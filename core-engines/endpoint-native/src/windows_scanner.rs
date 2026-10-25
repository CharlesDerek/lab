//! A reduced LocalService token for the scanner. This is not a network sandbox:
//! Everyone/BuiltinUsers-readable objects remain readable; low-integrity public
//! objects may remain writable. Private service state grants neither group access.
use crate::Result;
use std::{
    mem::{offset_of, size_of},
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{LocalFree, HANDLE, LUID},
    Security::{
        AllocateLocallyUniqueId,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW, SDDL_REVISION_1,
        },
        CreateRestrictedToken, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation,
        IsWellKnownSid, LookupPrivilegeValueW, SetTokenInformation, TokenDefaultDacl, TokenGroups,
        TokenIntegrityLevel, TokenMandatoryPolicy, TokenOwner, TokenPrivileges,
        TokenRestrictedSids, TokenSessionId, TokenUser, WinBuiltinUsersSid, WinLocalServiceSid,
        WinLowLabelSid, WinWorldSid, ACL, DISABLE_MAX_PRIVILEGE, LOGON32_LOGON_SERVICE,
        LOGON32_PROVIDER_DEFAULT, LUID_AND_ATTRIBUTES, PSID, SECURITY_ATTRIBUTES,
        SE_CHANGE_NOTIFY_NAME, SID_AND_ATTRIBUTES, TOKEN_DEFAULT_DACL, TOKEN_GROUPS,
        TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_MANDATORY_POLICY,
        TOKEN_MANDATORY_POLICY_NO_WRITE_UP, TOKEN_OWNER, TOKEN_PRIVILEGES, TOKEN_USER,
    },
    System::SystemServices::{
        SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_INTEGRITY, SE_GROUP_LOGON_ID,
        SE_GROUP_MANDATORY, SE_GROUP_OWNER, SE_GROUP_USE_FOR_DENY_ONLY,
    },
};

pub(crate) struct Allocation(pub(crate) *mut std::ffi::c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub(crate) fn descriptor(text: &str) -> Result<Allocation> {
    let text: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let mut raw = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Allocation(raw))
}
pub(crate) fn dacl(descriptor: &Allocation) -> Result<*mut ACL> {
    let (mut present, mut defaulted, mut acl) = (0, 0, null_mut());
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
        || acl.is_null()
    {
        return Err("Scanner security descriptor has no DACL".into());
    }
    Ok(acl)
}
fn sid(text: &str) -> Result<Allocation> {
    let text: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let mut raw = null_mut();
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Allocation(raw))
}
fn sid_text(sid: PSID) -> Result<String> {
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let _owned = Allocation(text.cast());
    let n = (0..256)
        .find(|&n| unsafe { *text.add(n) == 0 })
        .ok_or("Scanner SID exceeds its budget")?;
    Ok(String::from_utf16(unsafe {
        std::slice::from_raw_parts(text, n)
    })?)
}
fn query(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
    let mut bytes = 0;
    unsafe {
        GetTokenInformation(token, class, null_mut(), 0, &mut bytes);
    }
    if bytes == 0 || bytes > 65536 {
        return Err("Invalid scanner token information size".into());
    }
    let capacity = bytes;
    let mut data = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    if unsafe { GetTokenInformation(token, class, data.as_mut_ptr().cast(), capacity, &mut bytes) }
        == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if bytes == 0 || bytes > capacity {
        return Err("Scanner token information changed size".into());
    }
    Ok(data)
}
fn value<T: Copy>(data: &[usize]) -> Result<T> {
    if std::mem::size_of_val(data) < size_of::<T>() {
        return Err("Truncated scanner token information".into());
    }
    Ok(unsafe { data.as_ptr().cast::<T>().read() })
}
fn groups(data: &[usize]) -> Result<&[SID_AND_ATTRIBUTES]> {
    let count = *data.first().ok_or("Missing scanner groups")? as u32 as usize;
    if count > 1024
        || offset_of!(TOKEN_GROUPS, Groups) + count * size_of::<SID_AND_ATTRIBUTES>()
            > std::mem::size_of_val(data)
    {
        return Err("Scanner token group budget exceeded".into());
    }
    Ok(unsafe {
        std::slice::from_raw_parts(
            data.as_ptr()
                .cast::<u8>()
                .add(offset_of!(TOKEN_GROUPS, Groups))
                .cast(),
            count,
        )
    })
}
fn is_logon(group: &SID_AND_ATTRIBUTES) -> bool {
    group.Attributes & SE_GROUP_LOGON_ID as u32 == SE_GROUP_LOGON_ID as u32
}
fn retained(group: &SID_AND_ATTRIBUTES) -> bool {
    is_logon(group)
        || group.Attributes & SE_GROUP_INTEGRITY as u32 != 0
        || unsafe { IsWellKnownSid(group.Sid, WinWorldSid) != 0 }
        || unsafe { IsWellKnownSid(group.Sid, WinBuiltinUsersSid) != 0 }
}

/// Built-in service accounts can share logon contexts. Supply our own globally
/// allocated logon SID instead of assuming LogonUser creates an exclusive one.
/// Microsoft documents this entry point but provides no import library.
fn logon() -> Result<(OwnedHandle, String)> {
    use windows_sys::Win32::{
        Security::QUOTA_LIMITS,
        System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
    };
    type Logon = unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const u16,
        u32,
        u32,
        *const TOKEN_GROUPS,
        *mut HANDLE,
        *mut PSID,
        *mut *mut std::ffi::c_void,
        *mut u32,
        *mut QUOTA_LIMITS,
    ) -> i32;
    let module = unsafe { GetModuleHandleW(windows_sys::core::w!("advapi32.dll")) };
    if module.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let address = unsafe { GetProcAddress(module, windows_sys::core::s!("LogonUserExExW")) }
        .ok_or("Windows scanner logon API is unavailable")?;
    // advapi32 is also a static import of this module and remains loaded. The
    // signature is the documented LogonUserExExW ABI; no search-path load occurs.
    let function: Logon = unsafe { std::mem::transmute(address) };
    let mut luid = LUID::default();
    if unsafe { AllocateLocallyUniqueId(&mut luid) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let name = format!("S-1-5-5-{}-{}", luid.HighPart as u32, luid.LowPart);
    let unique = sid(&name)?;
    let groups = TOKEN_GROUPS {
        GroupCount: 1,
        Groups: [SID_AND_ATTRIBUTES {
            Sid: unique.0,
            Attributes: (SE_GROUP_LOGON_ID
                | SE_GROUP_ENABLED
                | SE_GROUP_ENABLED_BY_DEFAULT
                | SE_GROUP_MANDATORY
                | SE_GROUP_OWNER) as u32,
        }],
    };
    let mut raw = null_mut();
    if unsafe {
        function(
            windows_sys::core::w!("LocalService"),
            windows_sys::core::w!("NT AUTHORITY"),
            null(),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &groups,
            &mut raw,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((unsafe { OwnedHandle::from_raw_handle(raw) }, name))
}

/// The original LocalService token is closed before returning. No caller can
/// accidentally launch with it. The only exported handle is the checked token.
pub struct Token {
    handle: OwnedHandle,
    logon: String,
}
pub struct ProcessSecurity(Allocation);
impl ProcessSecurity {
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: 0,
        }
    }
}
impl Token {
    pub fn new() -> Result<Self> {
        crate::windows_state::require_local_system()?;
        let (original, allocated_logon) = logon()?;
        let user = query(original.as_raw_handle(), TokenUser)?;
        if unsafe { IsWellKnownSid(value::<TOKEN_USER>(&user)?.User.Sid, WinLocalServiceSid) } == 0
        {
            return Err("Scanner logon did not return LocalService".into());
        }
        let data = query(original.as_raw_handle(), TokenGroups)?;
        let entries = groups(&data)?;
        let logons: Vec<_> = entries.iter().filter(|g| is_logon(g)).collect();
        if logons.len() != 1 || logons[0].Attributes & SE_GROUP_ENABLED as u32 == 0 {
            return Err("Scanner logon must have exactly one enabled logon SID".into());
        }
        let logon = sid_text(logons[0].Sid)?;
        if logon != allocated_logon {
            return Err("Scanner logon did not retain its exclusive SID".into());
        }
        let disabled: Vec<_> = entries.iter().filter(|g| !retained(g)).copied().collect();
        let world = sid("S-1-1-0")?;
        let users = sid("S-1-5-32-545")?;
        let restricted = [
            SID_AND_ATTRIBUTES {
                Sid: world.0,
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: users.0,
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: logons[0].Sid,
                Attributes: 0,
            },
        ];
        let mut raw = null_mut();
        // Full restriction, never WRITE_RESTRICTED or SANDBOX_INERT. Both ACL
        // checks must permit standard-user-readable runtime DLLs. Retain only
        // the original BuiltinUsers membership; never add an account/group.
        if unsafe {
            CreateRestrictedToken(
                original.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                disabled.len() as u32,
                disabled.as_ptr(),
                0,
                null(),
                restricted.len() as u32,
                restricted.as_ptr(),
                &mut raw,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        drop(original);
        let low = sid("S-1-16-4096")?;
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: low.0,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };
        if unsafe {
            SetTokenInformation(
                handle.as_raw_handle(),
                TokenIntegrityLevel,
                (&label as *const TOKEN_MANDATORY_LABEL).cast(),
                size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low.0),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // New objects are usable by this logon, not every LocalService process.
        // A private DACL alone does not remove the shared user's implicit owner
        // WRITE_DAC. Give newly created scratch objects this logon's owner SID.
        let owner_sid = sid(&logon)?;
        let owner = TOKEN_OWNER { Owner: owner_sid.0 };
        if unsafe {
            SetTokenInformation(
                handle.as_raw_handle(),
                TokenOwner,
                (&owner as *const TOKEN_OWNER).cast(),
                size_of::<TOKEN_OWNER>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let security = descriptor(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{logon})"))?;
        let default = TOKEN_DEFAULT_DACL {
            DefaultDacl: dacl(&security)?,
        };
        if unsafe {
            SetTokenInformation(
                handle.as_raw_handle(),
                TokenDefaultDacl,
                (&default as *const TOKEN_DEFAULT_DACL).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = Self { handle, logon };
        result.verify()?;
        Ok(result)
    }
    pub fn logon_sid(&self) -> &str {
        &self.logon
    }
    pub fn handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }
    pub fn verify(&self) -> Result<()> {
        verify(self.handle.as_handle(), &self.logon)
    }
    pub fn process_security(&self) -> Result<ProcessSecurity> {
        // Explicit SYSTEM owner prevents the shared LocalService user SID from
        // receiving implicit owner WRITE_DAC on the scanner process/thread.
        Ok(ProcessSecurity(descriptor(&format!(
            "O:SYD:P(A;;GA;;;SY)(A;;GA;;;{})S:(ML;;NW;;;LW)",
            self.logon
        ))?))
    }
}

/// Recheck the launched process's token rather than trusting a plan or a flag.
pub fn verify(token: BorrowedHandle<'_>, expected_logon: &str) -> Result<()> {
    let token = token.as_raw_handle();
    let user = query(token, TokenUser)?;
    let level = query(token, TokenIntegrityLevel)?;
    let owner = query(token, TokenOwner)?;
    if sid_text(value::<TOKEN_OWNER>(&owner)?.Owner)? != expected_logon {
        return Err("Scanner token default owner is not its exclusive logon SID".into());
    }
    if unsafe { IsWellKnownSid(value::<TOKEN_USER>(&user)?.User.Sid, WinLocalServiceSid) } == 0
        || unsafe {
            IsWellKnownSid(
                value::<TOKEN_MANDATORY_LABEL>(&level)?.Label.Sid,
                WinLowLabelSid,
            )
        } == 0
    {
        return Err("Scanner must run as low-integrity LocalService".into());
    }
    let policy = value::<TOKEN_MANDATORY_POLICY>(&query(token, TokenMandatoryPolicy)?)?;
    if policy.Policy & TOKEN_MANDATORY_POLICY_NO_WRITE_UP == 0 {
        return Err("Scanner token permits write-up".into());
    }
    if value::<u32>(&query(token, TokenSessionId)?)? != 0 {
        return Err("Scanner must run in service session zero".into());
    }
    let data = query(token, TokenGroups)?;
    let mut logons = 0;
    let mut users = 0;
    for group in groups(&data)? {
        if is_logon(group) {
            if group.Attributes & SE_GROUP_ENABLED as u32 == 0
                || group.Attributes & SE_GROUP_OWNER as u32 == 0
                || sid_text(group.Sid)? != expected_logon
            {
                return Err("Scanner logon identity changed".into());
            }
            logons += 1;
        } else if unsafe { IsWellKnownSid(group.Sid, WinBuiltinUsersSid) != 0 } {
            if group.Attributes & SE_GROUP_ENABLED as u32 == 0
                || group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 != 0
            {
                return Err("Scanner lost its standard-user runtime access".into());
            }
            users += 1;
        } else if !retained(group) && group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0 {
            return Err("Scanner retained an unexpected group".into());
        }
    }
    if logons != 1 {
        return Err("Scanner token lost its logon identity".into());
    }
    if users != 1 {
        return Err("Scanner must retain exactly one BuiltinUsers group".into());
    }
    let data = query(token, TokenRestrictedSids)?;
    let restricted = groups(&data)?;
    if restricted.len() != 3
        || !restricted
            .iter()
            .any(|g| unsafe { IsWellKnownSid(g.Sid, WinWorldSid) } != 0)
        || !restricted
            .iter()
            .any(|g| unsafe { IsWellKnownSid(g.Sid, WinBuiltinUsersSid) } != 0)
        || !restricted
            .iter()
            .any(|g| sid_text(g.Sid).is_ok_and(|s| s == expected_logon))
    {
        return Err("Scanner restricting SIDs changed".into());
    }
    let data = query(token, TokenPrivileges)?;
    let count = value::<u32>(&data)? as usize;
    if count != 1
        || offset_of!(TOKEN_PRIVILEGES, Privileges) + size_of::<LUID_AND_ATTRIBUTES>()
            > std::mem::size_of_val(data.as_slice())
    {
        return Err("Scanner retained unexpected privileges".into());
    }
    let privilege = unsafe {
        data.as_ptr()
            .cast::<u8>()
            .add(offset_of!(TOKEN_PRIVILEGES, Privileges))
            .cast::<LUID_AND_ATTRIBUTES>()
            .read()
    };
    let mut change_notify = LUID::default();
    if unsafe { LookupPrivilegeValueW(null(), SE_CHANGE_NOTIFY_NAME, &mut change_notify) } == 0
        || privilege.Luid.LowPart != change_notify.LowPart
        || privilege.Luid.HighPart != change_notify.HighPart
    {
        return Err("Scanner retained a privileged capability".into());
    }
    Ok(())
}

pub fn verify_process(pid: u32, created: u64, logon: &str) -> Result<()> {
    use windows_sys::Win32::{
        Foundation::{FILETIME, WAIT_TIMEOUT},
        Security::TOKEN_QUERY,
        System::Threading::{
            GetProcessTimes, OpenProcess, OpenProcessToken, WaitForSingleObject,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    };
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let (mut birth, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut birth,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if (u64::from(birth.dwHighDateTime) << 32) | u64::from(birth.dwLowDateTime) != created {
        return Err("Scanner process creation identity changed".into());
    }
    let mut raw = null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    verify(token.as_handle(), logon)?;
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return Err("Scanner process is no longer running".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
