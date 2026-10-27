use super::*;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::{
            GetLastError, LocalFree, SetLastError, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS,
            GENERIC_ALL, GENERIC_WRITE,
        },
        Security::{Authorization::*, *},
        System::{
            Com::CoTaskMemFree,
            Registry::*,
            SystemInformation::OSVERSIONINFOW,
            SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
    },
};

const EPOCH_KEY: &str = "AthernexDriverLifecycleEpoch";
struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn status(code: u32) -> Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(code as i32).into())
    }
}
fn sid(text: &str) -> Result<Allocation> {
    let mut pointer = null_mut();
    bool_result(unsafe { ConvertStringSidToSidW(wide(text)?.as_ptr(), &mut pointer) })?;
    Ok(Allocation(pointer))
}
fn security() -> Result<Allocation> {
    let mut pointer = null_mut();
    let owner = if crate::windows_state::require_local_system().is_ok() {
        "SY"
    } else {
        "BA"
    };
    let text = wide(format!("O:{owner}D:P(A;;KA;;;SY)(A;;KA;;;BA)"))?;
    bool_result(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut pointer,
            null_mut(),
        )
    })?;
    Ok(Allocation(pointer))
}
fn open(parent: HKEY, name: &str, access: u32) -> Result<Option<Key>> {
    let mut key = null_mut();
    let code = unsafe {
        RegOpenKeyExW(
            parent,
            wide(name)?.as_ptr(),
            REG_OPTION_OPEN_LINK,
            access | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    status(code)?;
    let key = Key(key);
    let mut kind = 0;
    let mut bytes = 0;
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            wide("SymbolicLinkValue")?.as_ptr(),
            null(),
            &mut kind,
            null_mut(),
            &mut bytes,
        )
    };
    if code != ERROR_FILE_NOT_FOUND {
        return Err("Registry link or ambiguous epoch key refused".into());
    }
    Ok(Some(key))
}
fn protect(key: &Key, private: bool) -> Result<()> {
    let system = sid("S-1-5-18")?;
    let admins = sid("S-1-5-32-544")?;
    // The system Software parent may be maintained by Windows Modules Installer.
    let installer = sid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")?;
    let trusted = |p| unsafe {
        EqualSid(p, system.0) != 0
            || EqualSid(p, admins.0) != 0
            || (!private && EqualSid(p, installer.0) != 0)
    };
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut raw = null_mut();
    status(unsafe {
        GetSecurityInfo(
            key.0,
            SE_REGISTRY_KEY,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut raw,
        )
    })?;
    let _raw = Allocation(raw);
    if owner.is_null() || !trusted(owner) || dacl.is_null() {
        return Err("Registry owner/DACL refused".into());
    }
    if private {
        let mut control = 0;
        let mut revision = 0;
        bool_result(unsafe { GetSecurityDescriptorControl(raw, &mut control, &mut revision) })?;
        if control & SE_DACL_PROTECTED == 0 {
            return Err("Epoch DACL must be protected from inheritance".into());
        }
    }
    let count = unsafe { (*dacl).AceCount };
    if count == 0 || count > 128 {
        return Err("Registry DACL exceeds profile".into());
    }
    let mut grants = [0u32; 2];
    for i in 0..count {
        let mut ace = null_mut();
        bool_result(unsafe { GetAce(dacl, u32::from(i), &mut ace) })?;
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // An inheritance-only parent ACE does not grant access to SOFTWARE.
        // The separately created epoch has a protected explicit DACL.
        if !private && u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 && !private {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err("Registry DACL entry refused".into());
        }
        let allow = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let principal = std::ptr::addr_of!(allow.SidStart).cast_mut().cast();
        if !trusted(principal)
            && (private
                || allow.Mask
                    & (KEY_SET_VALUE
                        | KEY_CREATE_SUB_KEY
                        | 0x10000
                        | 0x40000
                        | 0x80000
                        | GENERIC_ALL
                        | GENERIC_WRITE)
                    != 0)
        {
            return Err("Registry allows untrusted modification".into());
        }
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE == 0 {
            for (index, known) in [system.0, admins.0].into_iter().enumerate() {
                if unsafe { EqualSid(principal, known) } != 0 {
                    grants[index] |= allow.Mask;
                }
            }
        }
    }
    if private
        && grants
            .iter()
            .any(|m| m & KEY_ALL_ACCESS != KEY_ALL_ACCESS && m & GENERIC_ALL == 0)
    {
        return Err("Epoch key does not preserve SYSTEM/admin access".into());
    }
    Ok(())
}
fn software() -> Result<Key> {
    let key = open(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE",
        KEY_READ | KEY_CREATE_SUB_KEY,
    )?
    .ok_or("System Software key missing")?;
    protect(&key, false)?;
    Ok(key)
}
fn binary(key: &Key, name: &str, max: u32) -> Result<Option<(u32, Vec<u8>)>> {
    let mut kind = 0;
    let mut count = 0;
    let name = wide(name)?;
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut kind,
            null_mut(),
            &mut count,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    status(code)?;
    if count > max {
        return Err("Registry value exceeds profile".into());
    }
    let mut bytes = vec![0u8; count as usize];
    let allocated = count;
    status(unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut kind,
            bytes.as_mut_ptr(),
            &mut count,
        )
    })?;
    if count > allocated {
        return Err("Registry value changed size".into());
    }
    bytes.truncate(count as usize);
    Ok(Some((kind, bytes)))
}
fn string(key: &Key, name: &str) -> Result<String> {
    let (kind, bytes) = binary(key, name, 2048)?.ok_or("Required instance string missing")?;
    if kind != REG_SZ || bytes.len() % 2 != 0 {
        return Err("Instance string type refused".into());
    }
    let words: Vec<_> = bytes
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .collect();
    let result = terminated(&words)?;
    if result.encode_utf16().count() + 1 != words.len() {
        return Err("Instance string has trailing data".into());
    }
    Ok(result)
}

/// Observe an already recorded protected kernel-lifetime token. Missing means
/// previous live observations are invalid; it does not prove reboot/completion.
pub fn epoch(expected: &str) -> Result<bool> {
    if !athernex_endpoint_protocol::hex_id(expected) {
        return Err("Invalid epoch receipt".into());
    }
    let parent = software()?;
    let Some(key) = open(parent.0, EPOCH_KEY, KEY_READ)? else {
        return Ok(false);
    };
    protect(&key, true)?;
    let (kind, value) =
        binary(&key, "Epoch", 64)?.ok_or("Unrecorded epoch creation requires recovery")?;
    if kind != REG_BINARY || value != expected.as_bytes() {
        return Err("Epoch ownership changed".into());
    }
    Ok(true)
}

/// Must follow a durable create intent. A lost successful-create receipt is
/// intentionally not recovered by adopting an existing matching key.
pub fn create_epoch(value: &str) -> Result<()> {
    crate::windows_state::require_administrator()?;
    if !athernex_endpoint_protocol::hex_id(value) {
        return Err("Invalid epoch value".into());
    }
    let parent = software()?;
    let descriptor = security()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut raw = null_mut();
    let mut disposition = 0;
    status(unsafe {
        RegCreateKeyExW(
            parent.0,
            wide(EPOCH_KEY)?.as_ptr(),
            0,
            null(),
            REG_OPTION_VOLATILE,
            KEY_ALL_ACCESS | KEY_WOW64_64KEY,
            &attributes,
            &mut raw,
            &mut disposition,
        )
    })?;
    let key = Key(raw);
    if disposition != REG_CREATED_NEW_KEY {
        return Err("Unowned existing epoch key refused".into());
    }
    protect(&key, true)?;
    status(unsafe {
        RegSetValueExW(
            key.0,
            wide("Epoch")?.as_ptr(),
            0,
            REG_BINARY,
            value.as_ptr(),
            value.len() as u32,
        )
    })?;
    if !epoch(value)? {
        return Err("Epoch creation could not be confirmed".into());
    }
    Ok(())
}

pub fn global_path() -> Result<PathBuf> {
    let mut raw = null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut raw) } < 0
        || raw.is_null()
    {
        return Err("System ProgramData location unavailable".into());
    }
    struct Memory(*mut u16);
    impl Drop for Memory {
        fn drop(&mut self) {
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
    let _memory = Memory(raw);
    let mut len = 0;
    while len < 1024 && unsafe { *raw.add(len) } != 0 {
        len += 1;
    }
    if len == 1024 {
        return Err("ProgramData path exceeds profile".into());
    }
    Ok(PathBuf::from(String::from_utf16(unsafe {
        std::slice::from_raw_parts(raw, len)
    })?)
    .join(GLOBAL_DIRECTORY))
}

pub(super) fn require_profile(expected: &Descriptor) -> Result<()> {
    use athernex_endpoint_protocol::windows_filter_package::{Deployment, LEGACY_PROFILE, PROFILE};
    expected.validate()?;
    if expected.deployment != Some(Deployment::InstallAndObserveDisarmedV1) {
        return Err("Native deployment was not requested".into());
    }
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    if unsafe { RtlGetVersion(&mut version) } != 0
        || version.dwMajorVersion != 10
        || version.dwBuildNumber < 19041
        || !cfg!(target_arch = "x86_64")
    {
        return Err("Native host does not match the supported AMD64 driver profile".into());
    }
    if (expected.profile == LEGACY_PROFILE && version.dwBuildNumber >= 26100)
        || (expected.profile == PROFILE && version.dwBuildNumber < 26100)
    {
        return Err("Native instance registry profile differs from this host".into());
    }
    Ok(())
}
pub(super) fn image_path(value: &str) -> Result<PathBuf> {
    if value.len() > 1023 || value.contains(['\0', '"']) {
        return Err("Driver image path refused".into());
    }
    let result = if let Some(suffix) = value.strip_prefix("\\SystemRoot\\") {
        windows_root()?.join(suffix)
    } else if let Some(path) = value.strip_prefix("\\??\\") {
        PathBuf::from(path)
    } else {
        PathBuf::from(value)
    };
    let text = result.to_str().ok_or("Driver image path is not Unicode")?;
    if text.as_bytes().get(1) != Some(&b':')
        || text.as_bytes().get(2) != Some(&b'\\')
        || text[3..].contains(':')
        || result
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("Driver image requires a local absolute path".into());
    }
    Ok(result)
}
pub(super) fn instance(expected: &Descriptor) -> Result<(String, String, u32)> {
    use athernex_endpoint_protocol::windows_filter_package::LEGACY_PROFILE;
    // CurrentControlSet is the documented OS-selected control-set alias; no
    // caller-supplied registry path is accepted here.
    let system =
        open(HKEY_LOCAL_MACHINE, "SYSTEM", KEY_READ)?.ok_or("System registry key missing")?;
    protect(&system, false)?;
    // Only this fixed OS-maintained alias may be followed; every subsequent
    // component is opened as a non-link under an already validated parent.
    let mut raw = null_mut();
    status(unsafe {
        RegOpenKeyExW(
            system.0,
            wide("CurrentControlSet")?.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut raw,
        )
    })?;
    let current = Key(raw);
    protect(&current, false)?;
    let services = open(current.0, "Services", KEY_READ)?.ok_or("Services registry key missing")?;
    protect(&services, false)?;
    let service = open(services.0, DRIVER, KEY_READ)?.ok_or("Driver registry key missing")?;
    protect(&service, false)?;
    let parameters = if expected.profile == LEGACY_PROFILE {
        None
    } else {
        let key = open(service.0, "Parameters", KEY_READ)?.ok_or("Driver parameters missing")?;
        protect(&key, false)?;
        Some(key)
    };
    let parent = parameters.as_ref().unwrap_or(&service);
    let root = open(parent.0, "Instances", KEY_READ)?.ok_or("Driver instances missing")?;
    protect(&root, false)?;

    let name = string(&root, "DefaultInstance")?;
    if name != DRIVER {
        return Err("Driver default instance differs".into());
    }
    let key = open(root.0, DRIVER, KEY_READ)?.ok_or("Driver instance missing")?;
    protect(&key, false)?;
    let altitude = string(&key, "Altitude")?;
    let (kind, bytes) = binary(&key, "Flags", 4)?.ok_or("Driver instance flags missing")?;
    if altitude != expected.altitude || kind != REG_DWORD || bytes.len() != 4 {
        return Err("Driver instance policy differs".into());
    }
    let flags = u32::from_le_bytes(bytes.try_into().map_err(|_| "Invalid flags")?);
    if flags != 0 {
        return Err("Driver instance flags differ".into());
    }
    Ok((name, altitude, flags))
}

pub(super) struct LoadPrivilege {
    token: OwnedHandle,
    previous: TOKEN_PRIVILEGES,
}
impl Drop for LoadPrivilege {
    fn drop(&mut self) {
        unsafe {
            AdjustTokenPrivileges(
                self.token.as_raw_handle(),
                0,
                &self.previous,
                0,
                null_mut(),
                null_mut(),
            );
        }
    }
}
pub(super) fn load_privilege() -> Result<LoadPrivilege> {
    let mut token = null_mut();
    bool_result(unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    })?;
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut luid = Default::default();
    bool_result(unsafe { LookupPrivilegeValueW(null(), SE_LOAD_DRIVER_NAME, &mut luid) })?;
    let requested = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let mut previous = TOKEN_PRIVILEGES::default();
    let mut bytes = 0;
    unsafe {
        SetLastError(0);
    }
    bool_result(unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            0,
            &requested,
            size_of::<TOKEN_PRIVILEGES>() as u32,
            &mut previous,
            &mut bytes,
        )
    })?;
    if unsafe { GetLastError() } != 0 {
        return Err("Required load-driver privilege is not assigned".into());
    }
    Ok(LoadPrivilege { token, previous })
}
