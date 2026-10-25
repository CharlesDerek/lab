//! Privilege elevation stays on the calling thread, never the service process.
use crate::{windows_state::require_local_system, Result};
use std::{
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
        SecurityImpersonation, TokenImpersonation, LUID_AND_ATTRIBUTES, SE_MANAGE_VOLUME_NAME,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
    },
};
pub(super) struct ManageVolume {
    _token: OwnedHandle,
    _thread: PhantomData<Rc<()>>,
}
impl ManageVolume {
    pub fn acquire() -> Result<Self> {
        require_local_system()?;
        let mut raw = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
            drop(unsafe { OwnedHandle::from_raw_handle(raw) });
            return Err("Scratch disk operation refuses an existing thread impersonation".into());
        }
        if unsafe { GetLastError() } != ERROR_NO_TOKEN {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) }
            == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        if unsafe {
            DuplicateTokenEx(
                process.as_raw_handle(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut luid = Default::default();
        if unsafe { LookupPrivilegeValueW(null(), SE_MANAGE_VOLUME_NAME, &mut luid) } == 0 {
            return Err(std::io::Error::last_os_error().into());
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
        let error = unsafe { GetLastError() };
        if adjusted == 0 || error != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(error as i32).into());
        }
        if unsafe { SetThreadToken(null(), token.as_raw_handle()) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            _token: token,
            _thread: PhantomData,
        })
    }
}
impl Drop for ManageVolume {
    fn drop(&mut self) {
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}
