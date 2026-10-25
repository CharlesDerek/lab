//! Mutations are confined to this explicitly opted-in disposable-host fixture.
use super::super::native::privilege::SecurityPrivilege;
use super::super::native::setup_test::SourceBarrier;
use std::ptr::{null, null_mut};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError},
    NetworkManagement::NetManagement::*,
    Security::{Authentication::Identity::*, *},
    System::RemoteDesktop::ProcessIdToSessionId,
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
pub(super) fn require_disposable() {
    assert!(
        std::env::var("ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST").as_deref() == Ok("1"),
        "Disposable authentication fixture was not explicitly enabled"
    );
    assert!(
        athernex_endpoint_native::windows_state::require_local_system().is_ok(),
        "Authentication fixture requires LocalSystem"
    );
    let mut session = u32::MAX;
    assert!(
        unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } != 0 && session == 0,
        "Authentication fixture requires session zero"
    );
}
struct AuditAllocation(*mut std::ffi::c_void);
impl Drop for AuditAllocation {
    fn drop(&mut self) {
        unsafe {
            AuditFree(self.0);
        }
    }
}
fn policies() -> Option<Vec<AUDIT_POLICY_INFORMATION>> {
    let _security = security_privilege()?;
    let ids = [Audit_Logon_Logon, Audit_Logon_AccountLockout];
    let mut raw = null_mut();
    let ok = unsafe { AuditQuerySystemPolicy(ids.as_ptr(), 2, &mut raw) };
    let code = unsafe { GetLastError() };
    let _allocation = AuditAllocation(raw.cast());
    if !ok {
        println!("\nATHERNEX_AUTH_DIAGNOSTIC=policy_query:{code}");
        return None;
    }
    if raw.is_null() {
        return None;
    }
    let result = unsafe { std::slice::from_raw_parts(raw, 2) }.to_vec();
    result
        .iter()
        .zip(ids)
        .all(|(p, id)| same_guid(p.AuditSubCategoryGuid, id))
        .then_some(result)
}
fn security_privilege() -> Option<SecurityPrivilege> {
    match SecurityPrivilege::acquire() {
        Ok(guard) => Some(guard),
        Err(error) => {
            if let Some(code) = error.raw_os_error() {
                println!(
                    "\nATHERNEX_AUTH_DIAGNOSTIC=privilege_acquire:{}",
                    code as u32
                );
            }
            None
        }
    }
}
pub(super) fn verify_privilege_scope() {
    println!("\nATHERNEX_AUTH_STAGE=security_privilege_starting");
    if let Err(error) = super::super::native::privilege::verify_scope() {
        if let Some(code) = error.raw_os_error() {
            println!(
                "\nATHERNEX_AUTH_DIAGNOSTIC=privilege_acquire:{}",
                code as u32
            );
        }
        panic!("Thread-scoped Security privilege proof failed");
    }
    println!("\nATHERNEX_AUTH_STAGE=security_privilege_verified");
}
fn same_guid(a: windows_sys::core::GUID, b: windows_sys::core::GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn same_policy(a: &[AUDIT_POLICY_INFORMATION], b: &[AUDIT_POLICY_INFORMATION]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            same_guid(a.AuditSubCategoryGuid, b.AuditSubCategoryGuid)
                && same_guid(a.AuditCategoryGuid, b.AuditCategoryGuid)
                && a.AuditingInformation == b.AuditingInformation
        })
}
fn set_policy_exact(desired: &[AUDIT_POLICY_INFORMATION]) -> bool {
    let Some(_security) = security_privilege() else {
        return false;
    };
    // A query can report disabled auditing as zero, but zero in a set request
    // means UNCHANGED. Keep normalization separate from the saved original.
    let mut request = desired.to_vec();
    for policy in &mut request {
        if policy.AuditingInformation == POLICY_AUDIT_EVENT_UNCHANGED as u32 {
            policy.AuditingInformation = POLICY_AUDIT_EVENT_NONE as u32;
        }
    }
    // Microsoft's AuditBuddy clears before setting to remove prior success or
    // failure bits reliably. This fixture touches only its two captured scopes:
    // https://github.com/microsoft/AuditBuddy/blob/main/AuditBuddy.Library/NativeInterface.cs#L293-L328
    let mut cleared = request.clone();
    for policy in &mut cleared {
        policy.AuditingInformation = POLICY_AUDIT_EVENT_NONE as u32;
    }
    println!("\nATHERNEX_AUTH_STAGE=policy_clear_starting");
    let reset = unsafe { AuditSetSystemPolicy(cleared.as_ptr(), cleared.len() as u32) };
    let code = unsafe { GetLastError() };
    if reset {
        println!("\nATHERNEX_AUTH_STAGE=policy_cleared");
    } else {
        println!("\nATHERNEX_AUTH_DIAGNOSTIC=policy_clear:{code}");
    }
    // Attempt the target even if reset failed, so a partially applied reset
    // cannot prevent the restoration attempt. Both operations must succeed.
    println!("\nATHERNEX_AUTH_STAGE=policy_apply_starting");
    let applied = unsafe { AuditSetSystemPolicy(request.as_ptr(), request.len() as u32) };
    let code = unsafe { GetLastError() };
    if applied {
        println!("\nATHERNEX_AUTH_STAGE=policy_applied");
    } else {
        println!("\nATHERNEX_AUTH_DIAGNOSTIC=policy_apply:{code}");
    }
    reset && applied
}
fn set_setup_step(desired: &[AUDIT_POLICY_INFORMATION], clear: bool) -> bool {
    let Some(_security) = security_privilege() else {
        return false;
    };
    if clear {
        println!("\nATHERNEX_AUTH_STAGE=policy_clear_starting");
    } else {
        println!("\nATHERNEX_AUTH_STAGE=policy_apply_starting");
    }
    let ok = unsafe { AuditSetSystemPolicy(desired.as_ptr(), desired.len() as u32) };
    let code = unsafe { GetLastError() };
    match (clear, ok) {
        (true, true) => println!("\nATHERNEX_AUTH_STAGE=policy_cleared"),
        (false, true) => println!("\nATHERNEX_AUTH_STAGE=policy_applied"),
        (true, false) => println!("\nATHERNEX_AUTH_DIAGNOSTIC=policy_clear:{code}"),
        (false, false) => println!("\nATHERNEX_AUTH_DIAGNOSTIC=policy_apply:{code}"),
    }
    ok
}
pub(super) struct Policy {
    original: Vec<AUDIT_POLICY_INFORMATION>,
    restored: bool,
}
impl Policy {
    pub fn start() -> Self {
        require_disposable();
        println!("\nATHERNEX_AUTH_STAGE=policy_capture_starting");
        let mut guard = Self {
            original: policies().expect("Cannot capture original audit policy"),
            restored: false,
        };
        println!("\nATHERNEX_AUTH_STAGE=policy_captured");
        if let Err(error) = guard.initialize() {
            super::super::diagnostics::classify(error.as_ref());
            assert!(
                guard.restore(),
                "Original audit policy restoration after setup failure was not verified"
            );
            println!("\nATHERNEX_AUTH_STAGE=setup_cleanup_verified");
            panic!("Native audit policy setup source barrier was not verified");
        }
        guard
    }
    fn initialize(&self) -> crate::Result<()> {
        // Establish the private source boundary before either policy mutation.
        // Every expected clear/addition notification is acknowledged before the
        // independent production Collector establishes its collection window.
        let mut source = SourceBarrier::capture()?;
        if self
            .original
            .iter()
            .any(|value| !matches!(value.AuditingInformation, 0..=4))
            || !policies().is_some_and(|actual| same_policy(&actual, &self.original))
        {
            return Err("Native audit setup original policy is uncertain".into());
        }
        let removed = [
            self.original[0].AuditingInformation & 3,
            self.original[1].AuditingInformation & 3,
        ];
        let mut cleared = self.original.clone();
        for value in &mut cleared {
            value.AuditingInformation = POLICY_AUDIT_EVENT_NONE as u32;
        }
        if !set_setup_step(&cleared, true) {
            return Err("Native audit setup clear failed".into());
        }
        let mut actual = policies().ok_or("Native audit setup clear readback failed")?;
        // A query can encode disabled auditing as zero or explicit NONE. This
        // semantic check is only for this intermediate disabled setup state;
        // final restoration still compares the exact captured representation.
        for value in &mut actual {
            if !matches!(value.AuditingInformation, 0 | 4) {
                return Err("Native audit setup clear readback was not disabled".into());
            }
            value.AuditingInformation = POLICY_AUDIT_EVENT_NONE as u32;
        }
        if !same_policy(&actual, &cleared) {
            return Err("Native audit setup clear readback changed scope".into());
        }
        println!("\nATHERNEX_AUTH_STAGE=setup_clear_verified");
        source.observe(removed, [0, 0])?;
        println!("\nATHERNEX_AUTH_STAGE=setup_clear_observed");
        let mut desired = self.original.clone();
        desired[0].AuditingInformation = 3;
        desired[1].AuditingInformation = 2;
        if !set_setup_step(&desired, false)
            || !policies().is_some_and(|actual| same_policy(&actual, &desired))
        {
            return Err("Native audit setup application readback failed".into());
        }
        println!("\nATHERNEX_AUTH_STAGE=policy_readback_verified");
        source.observe([0, 0], [3, 2])?;
        println!("\nATHERNEX_AUTH_STAGE=setup_apply_observed");
        Ok(())
    }
    pub fn set_logon(&self, flags: u32) {
        require_disposable();
        let mut desired = self.original.clone();
        desired[0].AuditingInformation = flags;
        desired[1].AuditingInformation = 2;
        assert!(
            set_policy_exact(&desired),
            "Disposable audit policy update failed"
        );
        assert!(
            policies().is_some_and(|actual| same_policy(&actual, &desired)),
            "Disposable audit policy update was not verified"
        );
        println!("\nATHERNEX_AUTH_STAGE=policy_readback_verified");
    }
    pub fn restore(&mut self) -> bool {
        if self.restored {
            return true;
        }
        // Preserve the original representation for strict readback comparison.
        let ok = set_policy_exact(&self.original)
            && policies().is_some_and(|actual| same_policy(&actual, &self.original));
        self.restored = ok;
        ok
    }
}
impl Drop for Policy {
    fn drop(&mut self) {
        if !self.restore() {
            eprintln!("Authentication fixture audit policy restoration failed");
        }
    }
}

struct NetAllocation(*mut u8);
impl Drop for NetAllocation {
    fn drop(&mut self) {
        unsafe {
            NetApiBufferFree(self.0.cast());
        }
    }
}
pub(super) struct Account {
    pub name: String,
    password: Vec<u16>,
    marker: Vec<u16>,
    sid: Vec<u8>,
    removed: bool,
}
impl Account {
    pub fn create() -> Self {
        require_disposable();
        // Account names and comments can be queried by other local users. Their
        // random values must disclose no material used to derive the password.
        let account_suffix = crate::secret().expect("Fixture randomness unavailable");
        let ownership_marker = crate::secret().expect("Fixture randomness unavailable");
        let password_secret = crate::secret().expect("Fixture randomness unavailable");
        let mut account = Self {
            name: format!("axauth{}", &account_suffix[..12]),
            password: wide(&format!("Ax!2{password_secret}")),
            marker: wide(&ownership_marker),
            sid: Vec::new(),
            removed: false,
        };
        let mut name = wide(&account.name);
        let user = USER_INFO_1 {
            usri1_name: name.as_mut_ptr(),
            usri1_password: account.password.as_mut_ptr(),
            usri1_priv: USER_PRIV_USER,
            usri1_comment: account.marker.as_mut_ptr(),
            usri1_flags: UF_SCRIPT | UF_NORMAL_ACCOUNT,
            ..Default::default()
        };
        let mut parameter = 0;
        let code = unsafe {
            NetUserAdd(
                null(),
                1,
                (&user as *const USER_INFO_1).cast(),
                &mut parameter,
            )
        };
        if code != 0 {
            account.removed = true;
            panic!("Ephemeral authentication account creation failed with code {code}, parameter {parameter}");
        }
        account.sid = account
            .identity()
            .expect("Ephemeral authentication account identity was not verified");
        account
    }
    fn identity(&self) -> Option<Vec<u8>> {
        let name = wide(&self.name);
        let mut raw = null_mut();
        let code = unsafe { NetUserGetInfo(null(), name.as_ptr(), 4, &mut raw) };
        let _allocation = NetAllocation(raw);
        if code != 0 || raw.is_null() {
            return None;
        }
        let user = unsafe { &*raw.cast::<USER_INFO_4>() };
        if user.usri4_comment.is_null() {
            return None;
        }
        // NetUserGetInfo owns a terminated API string. Compare only through the
        // first NUL, with a fixed marker bound; do not log any account property.
        for (offset, word) in self.marker.iter().enumerate() {
            let actual = unsafe { *user.usri4_comment.add(offset) };
            if actual != *word {
                return None;
            }
            if actual == 0 {
                break;
            }
        }
        if user.usri4_user_sid.is_null() || unsafe { IsValidSid(user.usri4_user_sid) } == 0 {
            return None;
        }
        let size = unsafe { GetLengthSid(user.usri4_user_sid) } as usize;
        if size == 0 || size > SECURITY_MAX_SID_SIZE as usize {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(user.usri4_user_sid.cast::<u8>(), size) }.to_vec())
    }
    pub fn attempt(&self, allowed: bool) {
        let name = wide(&self.name);
        let wrong = wide("Wrong!2-Disposable-Authentication-Password");
        let mut token = null_mut();
        let ok = unsafe {
            LogonUserW(
                name.as_ptr(),
                windows_sys::core::w!("."),
                if allowed {
                    self.password.as_ptr()
                } else {
                    wrong.as_ptr()
                },
                LOGON32_LOGON_NETWORK,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        } != 0;
        if !token.is_null() {
            unsafe {
                CloseHandle(token);
            }
        }
        assert!(
            ok == allowed,
            "Native LogonUser result did not match the controlled attempt"
        );
    }
    pub fn remove(&mut self) -> bool {
        if self.removed {
            return true;
        }
        let Some(sid) = self.identity() else {
            return false;
        };
        if !self.sid.is_empty() && self.sid != sid {
            return false;
        }
        let name = wide(&self.name);
        if unsafe { NetUserDel(null(), name.as_ptr()) } != 0 {
            return false;
        }
        let mut raw = null_mut();
        let code = unsafe { NetUserGetInfo(null(), name.as_ptr(), 4, &mut raw) };
        let _allocation = NetAllocation(raw);
        self.removed = code == NERR_UserNotFound;
        self.removed
    }
}
impl Drop for Account {
    fn drop(&mut self) {
        if !self.remove() {
            eprintln!("Authentication fixture account cleanup failed");
        }
        self.password.fill(0);
    }
}
