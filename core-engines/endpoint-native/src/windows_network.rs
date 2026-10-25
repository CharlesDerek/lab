//! Direct socket confinement for the staged scanner image. Policies are committed
//! before launch and persist after owner death. Dropping a session never removes
//! them; removal requires proof that the scanner can no longer execute.
//! This is not protection from a privileged WFP administrator or IPC proxies.
use crate::{windows_scanner, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    ptr::{null, null_mut},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        Storage::FileSystem::VOLUME_NAME_DOS,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

const DOMAIN: &[u8] = b"athernex.windows.scanner.network.v1\0";
const SUBLAYER_WEIGHT: u16 = 0xfffe;
const RULES: [(GUID, bool); 10] = [
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, false),
    (FWPM_LAYER_ALE_AUTH_LISTEN_V4, false),
    (FWPM_LAYER_ALE_AUTH_LISTEN_V6, false),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, false),
    (FWPM_LAYER_ALE_AUTH_LISTEN_V4, true),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, true),
    // Original application identity is preserved by WFP socket redirection.
    // Separate rules also cover the original scanner when a proxy owns the
    // redirected socket; explicit IPC requests to other services remain out of scope.
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, false),
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: u32,
    pub id: String,
    pub application: String,
    pub app_id: Vec<u8>,
    pub port: u16,
}
fn guid_equal(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn check(code: u32) -> Result<()> {
    if code != 0 {
        return Err(format!("Windows scanner network policy failed: 0x{code:08x}").into());
    }
    Ok(())
}
struct Allocation<T>(*mut T);
impl<T> Drop for Allocation<T> {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0((&mut self.0 as *mut *mut T).cast());
        }
    }
}
fn blob(bytes: &[u8]) -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: bytes.len() as u32,
        data: bytes.as_ptr().cast_mut(),
    }
}
fn equal_blob(value: &FWP_BYTE_BLOB, expected: &[u8]) -> bool {
    value.size as usize == expected.len()
        && !value.data.is_null()
        && unsafe { std::slice::from_raw_parts(value.data, expected.len()) } == expected
}
impl Policy {
    /// Caller retains this handle and its pinned directory ancestry until the
    /// scanner stops. WFP application identity comes from the actual staged file.
    pub fn new(image: &File, port: u16) -> Result<Self> {
        let path = crate::windows_state::name(image, VOLUME_NAME_DOS)?;
        let application = path
            .strip_prefix("\\\\?\\")
            .ok_or("Scanner image is not a local DOS path")?
            .to_owned();
        let wide: Vec<u16> = application.encode_utf16().chain([0]).collect();
        let mut raw = null_mut();
        check(unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut raw) })?;
        if raw.is_null() {
            return Err("Windows returned no scanner application identity".into());
        }
        let owned = Allocation(raw);
        let value = unsafe { &*owned.0 };
        if value.size == 0 || value.size > 4096 || value.data.is_null() {
            return Err("Scanner application identity exceeds its budget".into());
        }
        let app_id =
            unsafe { std::slice::from_raw_parts(value.data, value.size as usize) }.to_vec();
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)?;
        let id = random.iter().map(|v| format!("{v:02x}")).collect();
        let result = Self {
            schema: 1,
            id,
            application,
            app_id,
            port,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        let bytes = self.application.as_bytes();
        if self.schema != 1
            || self.port == 0
            || self.id.len() != 64
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || bytes.len() < 4
            || bytes.len() > 4096
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1..3] != *b":\\"
            || self.application.contains(char::is_control)
            || self.app_id.len() < 20
            || self.app_id.len() > 4096
            || !self.app_id.len().is_multiple_of(2)
        {
            return Err("Invalid Windows scanner network policy".into());
        }
        let units: Vec<u16> = self
            .app_id
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let units = if units.last() == Some(&0) {
            &units[..units.len() - 1]
        } else {
            &units[..]
        };
        let name = String::from_utf16(units)?;
        if !name.to_ascii_lowercase().starts_with("\\device\\") || name.contains(char::is_control) {
            return Err(
                "Scanner network application identity is not a canonical device path".into(),
            );
        }
        Ok(())
    }
    fn digest(&self) -> Vec<u8> {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(self.id.as_bytes());
        hash.update(self.port.to_le_bytes());
        hash.update((self.application.len() as u32).to_le_bytes());
        hash.update(self.application.as_bytes());
        hash.update(&self.app_id);
        hash.finalize().to_vec()
    }
    fn key(&self, ordinal: u8) -> GUID {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(self.id.as_bytes());
        hash.update([ordinal]);
        GUID::from_u128(u128::from_be_bytes(
            hash.finalize()[..16].try_into().unwrap(),
        ))
    }
}

pub struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
struct Transaction<'a>(&'a Engine, bool);
impl<'a> Transaction<'a> {
    fn new(engine: &'a Engine, flags: u32) -> Result<Self> {
        check(unsafe { FwpmTransactionBegin0(engine.0, flags) })?;
        Ok(Self(engine, false))
    }
    fn commit(mut self) -> Result<()> {
        check(unsafe { FwpmTransactionCommit0(self.0 .0) })?;
        self.1 = true;
        Ok(())
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.1 {
            unsafe {
                FwpmTransactionAbort0(self.0 .0);
            }
        }
    }
}
impl Engine {
    pub fn open() -> Result<Self> {
        crate::windows_state::require_local_system()?;
        let session = FWPM_SESSION0 {
            txnWaitTimeoutInMSec: 1000,
            ..Default::default()
        };
        let mut handle = null_mut();
        check(unsafe {
            FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle)
        })?;
        if handle.is_null() {
            return Err("Windows returned no filtering engine session".into());
        }
        Ok(Self(handle))
    }
    pub fn install(&self, policy: &Policy) -> Result<()> {
        policy.validate()?;
        let transaction = Transaction::new(self, 0)?;
        let security = windows_scanner::descriptor("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
        let digest = policy.digest();
        let mut name: Vec<u16> = "Athernex scanner network confinement"
            .encode_utf16()
            .chain([0])
            .collect();
        // No provider object: provider-associated filters can be disabled at BFE
        // restart if that provider lacks an auto-start Windows service. These
        // persistent objects belong to our private persistent sublayer instead.
        let layer = FWPM_SUBLAYER0 {
            subLayerKey: policy.key(0),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerData: blob(&digest),
            weight: SUBLAYER_WEIGHT,
            ..Default::default()
        };
        // A collision never adopts an existing object or commits a partial set.
        check(unsafe { FwpmSubLayerAdd0(self.0, &layer, security.0) })
            .map_err(|error| format!("Scanner network sublayer installation: {error}"))?;
        for ordinal in 0..RULES.len() {
            with_filter(policy, ordinal, |filter| {
                check(unsafe { FwpmFilterAdd0(self.0, filter, security.0, null_mut()) }).map_err(
                    |error| {
                        format!("Scanner network filter {ordinal} installation: {error}").into()
                    },
                )
            })?;
        }
        transaction.commit()?;
        self.verify(policy)
    }
    pub fn verify(&self, policy: &Policy) -> Result<()> {
        policy.validate()?;
        let transaction = Transaction::new(self, FWPM_TXN_READ_ONLY)?;
        self.verify_inner(policy)?;
        transaction.commit()
    }
    fn verify_inner(&self, policy: &Policy) -> Result<()> {
        let mut raw = null_mut();
        check(unsafe { FwpmSubLayerGetByKey0(self.0, &policy.key(0), &mut raw) })?;
        if raw.is_null() {
            return Err("Scanner network sublayer is missing".into());
        }
        let layer = Allocation(raw);
        let layer = unsafe { &*layer.0 };
        if !guid_equal(&layer.subLayerKey, &policy.key(0))
            || layer.flags != FWPM_SUBLAYER_FLAG_PERSISTENT
            || !layer.providerKey.is_null()
            || layer.weight != SUBLAYER_WEIGHT
            || !equal_blob(&layer.providerData, &policy.digest())
        {
            return Err("Scanner network sublayer changed".into());
        }
        for ordinal in 0..RULES.len() {
            let mut raw = null_mut();
            check(unsafe {
                FwpmFilterGetByKey0(self.0, &policy.key(ordinal as u8 + 1), &mut raw)
            })?;
            if raw.is_null() {
                return Err("Scanner network filter is missing".into());
            }
            let owned = Allocation(raw);
            let actual = unsafe { &*owned.0 };
            with_filter(policy, ordinal, |expected| {
                if let Some(reason) = filter_mismatch(actual, expected) {
                    return Err(format!(
                        "Scanner network filter {ordinal} changed or is disabled: {reason}"
                    )
                    .into());
                }
                Ok(())
            })?;
        }
        Ok(())
    }
    /// Only call after the original owned process and its entire job have ended.
    /// A mismatch or partial set leaves all rules intact. An entirely absent
    /// set is accepted for replay after a committed deletion or aborted install.
    /// Drop never calls this operation.
    pub fn remove_after_job_exit(&self, policy: &Policy) -> Result<()> {
        self.remove_inactive(policy)
    }
    /// Recovery-only alternative: the durable launch record proves no scanner
    /// was ever resumed, and the caller holds the dead launch owner's exclusive
    /// service leases. A possibly suspended child cannot be resumed afterward.
    pub fn remove_before_first_resume(&self, policy: &Policy) -> Result<()> {
        self.remove_inactive(policy)
    }
    fn remove_inactive(&self, policy: &Policy) -> Result<()> {
        policy.validate()?;
        let transaction = Transaction::new(self, 0)?;
        if self.entirely_absent(policy)? {
            return transaction.commit();
        }
        self.verify_inner(policy)?;
        for ordinal in 0..RULES.len() {
            check(unsafe { FwpmFilterDeleteByKey0(self.0, &policy.key(ordinal as u8 + 1)) })?;
        }
        check(unsafe { FwpmSubLayerDeleteByKey0(self.0, &policy.key(0)) })?;
        transaction.commit()
    }
    fn entirely_absent(&self, policy: &Policy) -> Result<bool> {
        let mut raw = null_mut();
        let code = unsafe { FwpmSubLayerGetByKey0(self.0, &policy.key(0), &mut raw) };
        if code == 0 {
            if raw.is_null() {
                return Err("Windows returned no scanner network sublayer".into());
            }
            drop(Allocation(raw));
            return Ok(false);
        }
        if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            check(code)?;
        }
        for ordinal in 0..RULES.len() {
            let mut raw = null_mut();
            let code =
                unsafe { FwpmFilterGetByKey0(self.0, &policy.key(ordinal as u8 + 1), &mut raw) };
            if code == 0 {
                if !raw.is_null() {
                    drop(Allocation(raw));
                }
                return Err("Orphaned scanner network filter; recovery retained".into());
            }
            if code != FWP_E_FILTER_NOT_FOUND as u32 {
                check(code)?;
            }
        }
        Ok(true)
    }
}
fn condition(key: GUID, kind: i32, value: FWP_CONDITION_VALUE0_0) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}
fn with_filter<T>(
    policy: &Policy,
    ordinal: usize,
    work: impl FnOnce(&FWPM_FILTER0) -> Result<T>,
) -> Result<T> {
    let (layer, allow) = RULES[ordinal];
    let mut app = blob(&policy.app_id);
    // Application identity alone scopes blocks. Adding a token/user condition
    // would let a compromised process evade a rule by disabling a group.
    let mut conditions = vec![condition(
        if ordinal >= 8 {
            FWPM_CONDITION_ALE_ORIGINAL_APP_ID
        } else {
            FWPM_CONDITION_ALE_APP_ID
        },
        FWP_BYTE_BLOB_TYPE,
        FWP_CONDITION_VALUE0_0 { byteBlob: &mut app },
    )];
    if allow {
        conditions.extend([
            condition(
                FWPM_CONDITION_IP_LOCAL_PORT,
                FWP_UINT16,
                FWP_CONDITION_VALUE0_0 {
                    uint16: policy.port,
                },
            ),
            condition(
                FWPM_CONDITION_IP_LOCAL_ADDRESS,
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 { uint32: 0x7f000001 },
            ),
        ]);
        if guid_equal(&layer, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
            // AUTH_LISTEN is TCP-only and does not expose IP_PROTOCOL. At
            // RECV_ACCEPT, an explicit TCP condition excludes UDP/raw traffic.
            conditions.push(condition(
                FWPM_CONDITION_IP_PROTOCOL,
                FWP_UINT8,
                FWP_CONDITION_VALUE0_0 { uint8: 6 },
            ));
            conditions.push(condition(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 { uint32: 0x7f000001 },
            ));
        }
    }
    let digest = policy.digest();
    let mut weight = if allow { 2u64 } else { 1u64 };
    let mut name: Vec<u16> = "Athernex scanner network confinement"
        .encode_utf16()
        .chain([0])
        .collect();
    let filter = FWPM_FILTER0 {
        filterKey: policy.key(ordinal as u8 + 1),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerData: blob(&digest),
        layerKey: layer,
        subLayerKey: policy.key(0),
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: &mut weight,
            },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: if allow {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            },
            ..Default::default()
        },
        ..Default::default()
    };
    // Soft permits preserve blocking decisions from other security providers.
    work(&filter)
}
fn filter_mismatch(actual: &FWPM_FILTER0, expected: &FWPM_FILTER0) -> Option<String> {
    // Report only field names/types and numeric policy metadata, never app IDs,
    // private file paths, provider data or filter keys. Every mismatch still
    // refuses startup and removal. BFE may add INDEXED as lookup metadata;
    // every other flag remains exact, especially DISABLED and action overrides.
    if !guid_equal(&actual.filterKey, &expected.filterKey) {
        return Some("filter key".into());
    }
    if !guid_equal(&actual.layerKey, &expected.layerKey) {
        return Some("layer key".into());
    }
    if !guid_equal(&actual.subLayerKey, &expected.subLayerKey) {
        return Some("sublayer key".into());
    }
    if actual.flags & !FWPM_FILTER_FLAG_INDEXED != expected.flags & !FWPM_FILTER_FLAG_INDEXED {
        return Some(format!(
            "flags 0x{:x}, expected 0x{:x}",
            actual.flags, expected.flags
        ));
    }
    if !actual.providerKey.is_null() {
        return Some("unexpected provider".into());
    }
    if actual.action.r#type != expected.action.r#type {
        return Some(format!(
            "action {}, expected {}",
            actual.action.r#type, expected.action.r#type
        ));
    }
    if actual.weight.r#type != FWP_UINT64 {
        return Some(format!(
            "weight type {}, expected {FWP_UINT64}",
            actual.weight.r#type
        ));
    }
    if unsafe { actual.weight.Anonymous.uint64.is_null() } {
        return Some("missing weight".into());
    }
    if actual.numFilterConditions != expected.numFilterConditions {
        return Some(format!(
            "condition count {}, expected {}",
            actual.numFilterConditions, expected.numFilterConditions
        ));
    }
    if actual.filterCondition.is_null() {
        return Some("missing conditions".into());
    }
    unsafe {
        if *actual.weight.Anonymous.uint64 != *expected.weight.Anonymous.uint64 {
            return Some(format!(
                "weight {}, expected {}",
                *actual.weight.Anonymous.uint64, *expected.weight.Anonymous.uint64
            ));
        }
        if !equal_blob(
            &actual.providerData,
            std::slice::from_raw_parts(
                expected.providerData.data,
                expected.providerData.size as usize,
            ),
        ) {
            return Some("provider data".into());
        }
        let actual =
            std::slice::from_raw_parts(actual.filterCondition, actual.numFilterConditions as usize);
        let expected = std::slice::from_raw_parts(
            expected.filterCondition,
            expected.numFilterConditions as usize,
        );
        for (index, condition) in expected.iter().enumerate() {
            let matching: Vec<_> = actual
                .iter()
                .filter(|v| guid_equal(&v.fieldKey, &condition.fieldKey))
                .collect();
            if matching.len() != 1 {
                return Some(format!("condition {index} missing or duplicated"));
            }
            if !same_condition(matching[0], condition) {
                return Some(format!(
                    "condition {index} differs: match/type {}/{}, expected {}/{}",
                    matching[0].matchType,
                    matching[0].conditionValue.r#type,
                    condition.matchType,
                    condition.conditionValue.r#type
                ));
            }
        }
        None
    }
}
fn same_condition(a: &FWPM_FILTER_CONDITION0, b: &FWPM_FILTER_CONDITION0) -> bool {
    if a.matchType != b.matchType || a.conditionValue.r#type != b.conditionValue.r#type {
        return false;
    }
    unsafe {
        match b.conditionValue.r#type {
            FWP_UINT8 => a.conditionValue.Anonymous.uint8 == b.conditionValue.Anonymous.uint8,
            FWP_UINT16 => a.conditionValue.Anonymous.uint16 == b.conditionValue.Anonymous.uint16,
            FWP_UINT32 => a.conditionValue.Anonymous.uint32 == b.conditionValue.Anonymous.uint32,
            FWP_BYTE_BLOB_TYPE => {
                let (a, b) = (
                    a.conditionValue.Anonymous.byteBlob,
                    b.conditionValue.Anonymous.byteBlob,
                );
                !a.is_null()
                    && equal_blob(
                        &*a,
                        std::slice::from_raw_parts((*b).data, (*b).size as usize),
                    )
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_metadata_never_masks_disabled_or_other_changed_flags() {
        let policy = Policy {
            schema: 1,
            id: "a".repeat(64),
            application: r"C:\fixture\scanner.exe".into(),
            app_id: "\\Device\\Fixture\\scanner.exe"
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
            port: 3310,
        };
        for ordinal in 0..RULES.len() {
            with_filter(&policy, ordinal, |expected| {
                for indexing in [0, FWPM_FILTER_FLAG_INDEXED] {
                    let mut returned = *expected;
                    returned.flags |= indexing;
                    assert_eq!(filter_mismatch(&returned, expected), None);
                    // Every bit other than the documented indexing metadata
                    // must still reject a changed filter, including removal of
                    // PERSISTENT, DISABLED, hard permits and unknown flags.
                    for bit in 0..32 {
                        let changed = 1u32 << bit;
                        if changed == FWPM_FILTER_FLAG_INDEXED {
                            continue;
                        }
                        let mut altered = returned;
                        altered.flags ^= changed;
                        assert!(
                            filter_mismatch(&altered, expected).is_some(),
                            "filter {ordinal} accepted changed flag 0x{changed:x}"
                        );
                    }
                }
                Ok(())
            })
            .unwrap();
        }
    }
}
