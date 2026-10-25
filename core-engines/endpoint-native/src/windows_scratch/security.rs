//! Explicit permissions apply only to the root of our freshly formatted volume
//! and the newly created scratch child. Existing host directories are not edited.
use super::*;
use windows_sys::Win32::Security::{
    Authorization::{GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT},
    EqualSid, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, GetSecurityDescriptorSacl, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
};
pub(super) fn root(logon: &str) -> Result<windows_scanner::Allocation> {
    validate_logon(logon)?;
    // Win32 opens also request READ_ATTRIBUTES and SYNCHRONIZE. Permit those
    // with traversal, never root listing or mutation. This ACE does not inherit.
    windows_scanner::descriptor(&format!(
        "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1000a0;;;{logon})S:(ML;;NW;;;ME)"
    ))
}
pub(super) fn scratch(logon: &str) -> Result<windows_scanner::Allocation> {
    validate_logon(logon)?;
    // The root itself grants create/list/traverse, but no delete, attribute or
    // ACL editing rights. Its separate share-read-only handle prevents a write
    // open for FSCTL_SET_REPARSE_POINT. Created descendants inherit Modify.
    windows_scanner::descriptor(&format!("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200af;;;{logon})(A;OICIIO;0x1301bf;;;{logon})S:(ML;OICI;NW;;;LW)"))
}
struct Parts {
    owner: *mut std::ffi::c_void,
    dacl: *mut ACL,
    sacl: *mut ACL,
}
fn parts(descriptor: &windows_scanner::Allocation) -> Result<Parts> {
    let (mut owner, mut dacl, mut sacl) = (null_mut(), null_mut(), null_mut());
    let (mut defaulted, mut dacl_present, mut sacl_present) = (0, 0, 0);
    if unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) } == 0
        || owner.is_null()
        || unsafe {
            GetSecurityDescriptorDacl(descriptor.0, &mut dacl_present, &mut dacl, &mut defaulted)
        } == 0
        || dacl_present == 0
        || dacl.is_null()
        || unsafe {
            GetSecurityDescriptorSacl(descriptor.0, &mut sacl_present, &mut sacl, &mut defaulted)
        } == 0
        || sacl_present == 0
        || sacl.is_null()
    {
        return Err("Incomplete scratch security descriptor".into());
    }
    Ok(Parts { owner, dacl, sacl })
}
fn same_acl(actual: *mut ACL, expected: *mut ACL) -> Result<bool> {
    if actual.is_null() || expected.is_null() {
        return Ok(false);
    }
    let count = unsafe { (*actual).AceCount };
    if count > 8 || count != unsafe { (*expected).AceCount } {
        return Ok(false);
    }
    for index in 0..count {
        let (mut a, mut b) = (null_mut(), null_mut());
        if unsafe { GetAce(actual, index as u32, &mut a) } == 0
            || unsafe { GetAce(expected, index as u32, &mut b) } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let (a_len, b_len) = unsafe {
            (
                (*a.cast::<ACE_HEADER>()).AceSize as usize,
                (*b.cast::<ACE_HEADER>()).AceSize as usize,
            )
        };
        if a_len < size_of::<ACE_HEADER>()
            || a_len > 256
            || a_len != b_len
            || unsafe {
                std::slice::from_raw_parts(a.cast::<u8>(), a_len)
                    != std::slice::from_raw_parts(b.cast::<u8>(), b_len)
            }
        {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(super) fn verify(file: &File, descriptor: &windows_scanner::Allocation) -> Result<()> {
    let expected = parts(descriptor)?;
    let (mut owner, mut dacl, mut sacl, mut raw) = (null_mut(), null_mut(), null_mut(), null_mut());
    check(unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            &mut sacl,
            &mut raw,
        )
    })?;
    let actual = windows_scanner::Allocation(raw);
    let (mut control, mut revision) = (0, 0);
    if unsafe { GetSecurityDescriptorControl(actual.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if owner.is_null()
        || unsafe { EqualSid(owner, expected.owner) } == 0
        || control & SE_DACL_PROTECTED == 0
        || !same_acl(dacl, expected.dacl)?
        || !same_acl(sacl, expected.sacl)?
    {
        return Err("Scratch owner, permissions or integrity label changed".into());
    }
    Ok(())
}
pub(super) fn set_root(file: &File, logon: &str) -> Result<()> {
    let descriptor = root(logon)?;
    let parts = parts(&descriptor)?;
    check(unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            parts.owner,
            null_mut(),
            parts.dacl,
            parts.sacl,
        )
    })?;
    verify(file, &descriptor)
}
