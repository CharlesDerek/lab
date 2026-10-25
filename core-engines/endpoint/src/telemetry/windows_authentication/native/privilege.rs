//! Enable an existing Security privilege on a duplicate of the effective token.
//! Process tokens and existing impersonation tokens are never modified.
use std::{
    io,
    marker::PhantomData,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    rc::Rc,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError, ERROR_NO_TOKEN, ERROR_SUCCESS},
    Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, RevertToSelf,
        SecurityImpersonation, TokenImpersonation, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
    },
};

fn previous_thread() -> io::Result<Option<OwnedHandle>> {
    let mut raw = null_mut();
    if unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            1,
            &mut raw,
        )
    } != 0
    {
        return Ok(Some(unsafe { OwnedHandle::from_raw_handle(raw) }));
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_NO_TOKEN {
        Ok(None)
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
fn process_token() -> io::Result<OwnedHandle> {
    let mut raw = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

pub(in super::super) struct SecurityPrivilege {
    _token: OwnedHandle,
    previous: Option<OwnedHandle>,
    _same_thread: PhantomData<Rc<()>>,
}
impl SecurityPrivilege {
    pub fn acquire() -> io::Result<Self> {
        let previous = previous_thread()?;
        // Never fall back to the process identity when a thread token exists,
        // including restricted tokens and lower impersonation levels.
        let process = if previous.is_none() {
            Some(process_token()?)
        } else {
            None
        };
        let effective = previous
            .as_ref()
            .or(process.as_ref())
            .expect("Effective token is present");
        let mut raw = null_mut();
        if unsafe {
            DuplicateTokenEx(
                effective.as_raw_handle(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut luid = Default::default();
        if unsafe { LookupPrivilegeValueW(null(), SE_SECURITY_NAME, &mut luid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe {
            SetLastError(ERROR_SUCCESS);
        }
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &privileges,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                null_mut(),
                null_mut(),
            )
        };
        let code = unsafe { GetLastError() };
        if adjusted == 0 || code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        if unsafe { SetThreadToken(null(), token.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _token: token,
            previous,
            _same_thread: PhantomData,
        })
    }
}
impl Drop for SecurityPrivilege {
    fn drop(&mut self) {
        let restored = match &self.previous {
            Some(previous) => unsafe { SetThreadToken(null(), previous.as_raw_handle()) },
            None => unsafe { RevertToSelf() },
        };
        if restored == 0 {
            // Microsoft requires terminating if reverting fails. Continuing
            // would leave the caller running under the wrong effective token.
            std::process::abort();
        }
    }
}

#[cfg(test)]
pub(in super::super) fn verify_scope() -> io::Result<()> {
    use windows_sys::Win32::Foundation::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED, HANDLE,
    };
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, GetTokenInformation, TokenPrivileges, TokenStatistics,
        DISABLE_MAX_PRIVILEGE, TOKEN_STATISTICS,
    };
    fn identity(token: HANDLE) -> io::Result<(u32, i32)> {
        let mut value = TOKEN_STATISTICS::default();
        let mut bytes = 0;
        if unsafe {
            GetTokenInformation(
                token,
                TokenStatistics,
                (&mut value as *mut TOKEN_STATISTICS).cast(),
                size_of::<TOKEN_STATISTICS>() as u32,
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((value.TokenId.LowPart, value.TokenId.HighPart))
    }
    fn thread_identity() -> io::Result<Option<(u32, i32)>> {
        previous_thread()?
            .as_ref()
            .map(|token| identity(token.as_raw_handle()))
            .transpose()
    }
    fn privileges(token: HANDLE) -> io::Result<Vec<(u32, i32, u32)>> {
        let mut bytes = 0;
        if unsafe { GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &mut bytes) } != 0
            || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
            || !(size_of::<TOKEN_PRIVILEGES>() as u32..=65536).contains(&bytes)
        {
            return Err(io::Error::other("Invalid fixture token privilege buffer"));
        }
        let capacity = bytes;
        let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                buffer.as_mut_ptr().cast(),
                capacity,
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if bytes > capacity {
            return Err(io::Error::other("Fixture token privilege buffer changed"));
        }
        let value = unsafe { &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>() };
        let count = value.PrivilegeCount as usize;
        let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
        if count > 1024 || offset + count * size_of::<LUID_AND_ATTRIBUTES>() > bytes as usize {
            return Err(io::Error::other("Invalid fixture token privilege count"));
        }
        let entries = unsafe { std::slice::from_raw_parts(value.Privileges.as_ptr(), count) };
        Ok(entries
            .iter()
            .map(|v| (v.Luid.LowPart, v.Luid.HighPart, v.Attributes))
            .collect())
    }
    fn require(ok: bool) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::other(
                "Thread-scoped Security privilege proof failed",
            ))
        }
    }
    let process = process_token()?;
    let original_flags = privileges(process.as_raw_handle())?;
    let initial = thread_identity()?;
    {
        let _outer = SecurityPrivilege::acquire()?;
        require(privileges(process.as_raw_handle())? == original_flags)?;
        let outer_id = thread_identity()?;
        require(outer_id.is_some())?;
        let active = previous_thread()?
            .ok_or_else(|| io::Error::other("Fixture thread token is missing"))?;
        let mut security = Default::default();
        if unsafe { LookupPrivilegeValueW(null(), SE_SECURITY_NAME, &mut security) } == 0 {
            return Err(io::Error::last_os_error());
        }
        require(
            privileges(active.as_raw_handle())?
                .iter()
                .any(|(low, high, flags)| {
                    *low == security.LowPart
                        && *high == security.HighPart
                        && flags & SE_PRIVILEGE_ENABLED != 0
                }),
        )?;
        {
            let _inner = SecurityPrivilege::acquire()?;
            require(thread_identity()? != outer_id)?;
        }
        require(thread_identity()? == outer_id)?;
        let previous = previous_thread()?;
        let mut raw = null_mut();
        let effective = previous
            .as_ref()
            .ok_or_else(|| io::Error::other("Fixture thread token is missing"))?;
        if unsafe {
            CreateRestrictedToken(
                effective.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                0,
                null(),
                0,
                null(),
                0,
                null(),
                &mut raw,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let restricted = unsafe { OwnedHandle::from_raw_handle(raw) };
        if unsafe { SetThreadToken(null(), restricted.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        {
            let _restricted_scope = SecurityPrivilege {
                _token: restricted,
                previous,
                _same_thread: PhantomData,
            };
            let restricted_id = thread_identity()?;
            let result = SecurityPrivilege::acquire();
            let refused = matches!(&result,Err(error) if error.raw_os_error()==Some(ERROR_NOT_ALL_ASSIGNED as i32));
            drop(result);
            require(refused && thread_identity()? == restricted_id)?;
        }
        require(thread_identity()? == outer_id)?;
    }
    require(thread_identity()? == initial && privileges(process.as_raw_handle())? == original_flags)
}
