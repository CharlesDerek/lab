use crate::Result;
use std::{
    fs::File,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, GENERIC_ALL, HANDLE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        CheckTokenMembership, EqualSid, GetAce, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE,
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::FILE_ALL_ACCESS,
    System::{
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

pub(super) struct Allocation(pub *mut std::ffi::c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn user() -> Result<Vec<usize>> {
    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut bytes = 0;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut bytes);
    }
    if bytes == 0 || bytes > 65536 {
        return Err("Invalid Windows service identity size".into());
    }
    let mut data = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(data)
}
fn sid(data: &[usize]) -> PSID {
    unsafe { (*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid }
}
fn text_sid(sid: PSID) -> Result<String> {
    let mut raw = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let allocation = Allocation(raw.cast());
    let mut length = 0;
    while length < 256 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err("Invalid Windows service SID".into());
    }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })?;
    drop(allocation);
    Ok(result)
}
fn known_sid(text: &str) -> Result<Allocation> {
    let wide: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let mut raw = null_mut();
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Allocation(raw))
}
pub(super) fn descriptor() -> Result<Allocation> {
    let token = user()?;
    let service = text_sid(sid(&token))?;
    // Only the service identity, SYSTEM and administrators can access retained
    // bytes. The owner is explicit; no untrusted parent ACL is inherited.
    let text = format!("O:{service}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{service})");
    from_text(&text)
}
/// An elevated administrator and LocalSystem must be able to validate the same
/// newly created maintenance lease without trusting an individual user SID.
pub(super) fn maintenance_descriptor() -> Result<Allocation> {
    let token = user()?;
    let system = known_sid("S-1-5-18")?;
    if unsafe { EqualSid(sid(&token), system.0) } != 0 {
        return from_text("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    }
    let admins = known_sid("S-1-5-32-544")?;
    let mut member = 0;
    if unsafe { CheckTokenMembership(null_mut(), admins.0, &mut member) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if member != 0 {
        from_text("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    } else {
        // Per-user installations retain their ordinary private contract. This
        // does not grant authority to operate a LocalSystem endpoint.
        descriptor()
    }
}
pub(super) fn is_administrator() -> Result<bool> {
    let token = user()?;
    let system = known_sid("S-1-5-18")?;
    if unsafe { EqualSid(sid(&token), system.0) } != 0 {
        return Ok(true);
    }
    let admins = known_sid("S-1-5-32-544")?;
    let mut member = 0;
    if unsafe { CheckTokenMembership(null_mut(), admins.0, &mut member) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(member != 0)
}
pub(super) fn require_administrator() -> Result<()> {
    if !is_administrator()? {
        return Err(
            "Windows installation requires an elevated administrator or LocalSystem".into(),
        );
    }
    Ok(())
}
/// A distinct private user namespace is not a machine-service deployment state.
/// Do not infer this classification from a failed service ACL query.
pub(super) fn user_private(file: &File) -> Result<()> {
    if is_administrator()? {
        return Err("Expected a non-administrative private-user owner".into());
    }
    private_for(file, false)?;
    let token = user()?;
    let mut owner = null_mut();
    let mut raw = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut raw,
        )
    };
    let _raw = Allocation(raw);
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    if owner.is_null() || unsafe { EqualSid(owner, sid(&token)) } == 0 {
        return Err("Private-user state must be owned by this exact account".into());
    }
    Ok(())
}

fn from_text(text: &str) -> Result<Allocation> {
    let wide: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let mut raw: PSECURITY_DESCRIPTOR = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
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
pub(super) fn private(file: &File) -> Result<()> {
    private_for(file, false)
}
pub(super) fn service_private(file: &File) -> Result<()> {
    private_for(file, true)
}
fn private_for(file: &File, service: bool) -> Result<()> {
    let token = user()?;
    let system = known_sid("S-1-5-18")?;
    let admins = known_sid("S-1-5-32-544")?;
    let allowed = |candidate| {
        [system.0, admins.0]
            .into_iter()
            .any(|trusted| unsafe { EqualSid(candidate, trusted) } != 0)
            || (!service && unsafe { EqualSid(candidate, sid(&token)) } != 0)
    };
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32).into());
    }
    let _descriptor = Allocation(descriptor);
    if owner.is_null() || !allowed(owner) || dacl.is_null() {
        return Err("Mutation storage requires a trusted owner and a private DACL".into());
    }
    let count = unsafe { (*dacl).AceCount };
    if count == 0 || count > 32 {
        return Err("Unexpected mutation storage ACL".into());
    }
    let mut service_rights = [0u32; 2];
    for index in 0..count {
        let mut ace = null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // Conservative allow-only ACLs. Reject unknown/object/callback entries,
        // including inherited grants, rather than approximating access checks.
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err("Mutation storage ACL contains an unsupported entry".into());
        }
        let allowed_ace = ace.cast::<ACCESS_ALLOWED_ACE>();
        let candidate = unsafe { std::ptr::addr_of_mut!((*allowed_ace).SidStart).cast() };
        if !allowed(candidate) {
            return Err(
                "Mutation storage grants access outside the service and administrators".into(),
            );
        }
        if service && u32::from(header.AceFlags) & INHERIT_ONLY_ACE == 0 {
            for (index, principal) in [system.0, admins.0].into_iter().enumerate() {
                if unsafe { EqualSid(candidate, principal) } != 0 {
                    service_rights[index] |= unsafe { (*allowed_ace).Mask };
                }
            }
        }
    }
    if service
        && service_rights
            .iter()
            .any(|mask| mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS && mask & GENERIC_ALL == 0)
    {
        return Err("Installation directories require SYSTEM and Administrators ownership/access; repair permissions before installing".into());
    }
    Ok(())
}
