//! Mutations are confined to this explicitly opted-in disposable-host fixture.
use std::ptr::{null, null_mut};
use windows_sys::Win32::{
    Foundation::CloseHandle,
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
    let ids = [Audit_Logon_Logon, Audit_Logon_AccountLockout];
    let mut raw = null_mut();
    let ok = unsafe { AuditQuerySystemPolicy(ids.as_ptr(), 2, &mut raw) };
    let _allocation = AuditAllocation(raw.cast());
    if !ok || raw.is_null() {
        return None;
    }
    let result = unsafe { std::slice::from_raw_parts(raw, 2) }.to_vec();
    result
        .iter()
        .zip(ids)
        .all(|(p, id)| same_guid(p.AuditSubCategoryGuid, id))
        .then_some(result)
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
    let reset = unsafe { AuditSetSystemPolicy(cleared.as_ptr(), cleared.len() as u32) };
    // Attempt the target even if reset failed, so a partially applied reset
    // cannot prevent the restoration attempt. Both operations must succeed.
    let applied = unsafe { AuditSetSystemPolicy(request.as_ptr(), request.len() as u32) };
    reset && applied
}
pub(super) struct Policy {
    original: Vec<AUDIT_POLICY_INFORMATION>,
    restored: bool,
}
impl Policy {
    pub fn start() -> Self {
        require_disposable();
        let guard = Self {
            original: policies().expect("Cannot capture original audit policy"),
            restored: false,
        };
        guard.set_logon(3);
        guard
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
