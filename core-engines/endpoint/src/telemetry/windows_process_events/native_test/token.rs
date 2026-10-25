//! Read-only snapshots prove the source fixture changes no token state.
use super::{api, require, Result};
use std::{
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, HANDLE},
    Security::*,
    System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
};
#[derive(PartialEq, Eq)]
struct Token {
    identity: (u32, i32),
    modified: (u32, i32),
    privileges: Vec<(u32, i32, u32)>,
}
#[derive(PartialEq, Eq)]
pub(super) struct Snapshot {
    process: Token,
    thread: Option<Token>,
}
impl Snapshot {
    pub fn unimpersonated(&self) -> bool {
        self.thread.is_none()
    }
}
fn read(handle: HANDLE) -> Result<Token> {
    let mut statistics = TOKEN_STATISTICS::default();
    let mut used = 0;
    if unsafe {
        GetTokenInformation(
            handle,
            TokenStatistics,
            (&mut statistics as *mut TOKEN_STATISTICS).cast(),
            size_of::<TOKEN_STATISTICS>() as u32,
            &mut used,
        )
    } == 0
    {
        api("token_query", unsafe { GetLastError() })?;
    }
    require(
        used as usize == size_of::<TOKEN_STATISTICS>(),
        "Token statistics size differs",
    )?;
    used = 0;
    let ok = unsafe { GetTokenInformation(handle, TokenPrivileges, null_mut(), 0, &mut used) };
    let code = unsafe { GetLastError() };
    require(
        ok == 0
            && code == ERROR_INSUFFICIENT_BUFFER
            && (size_of::<TOKEN_PRIVILEGES>() as u32..=65_536).contains(&used),
        "Token privilege size probe invalid",
    )?;
    let capacity = used;
    let mut buffer = vec![0u64; (capacity as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            handle,
            TokenPrivileges,
            buffer.as_mut_ptr().cast(),
            capacity,
            &mut used,
        )
    } == 0
    {
        api("token_query", unsafe { GetLastError() })?;
    }
    require(
        used <= capacity && used as usize >= size_of::<TOKEN_PRIVILEGES>(),
        "Token privilege result invalid",
    )?;
    let info = unsafe { &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let count = info.PrivilegeCount as usize;
    require(
        count <= 1024
            && offset_of!(TOKEN_PRIVILEGES, Privileges) + count * size_of::<LUID_AND_ATTRIBUTES>()
                <= used as usize,
        "Token privileges exceed buffer",
    )?;
    let entries = unsafe { std::slice::from_raw_parts(info.Privileges.as_ptr(), count) };
    let privileges = entries
        .iter()
        .map(|value| (value.Luid.LowPart, value.Luid.HighPart, value.Attributes))
        .collect();
    Ok(Token {
        identity: (statistics.TokenId.LowPart, statistics.TokenId.HighPart),
        modified: (
            statistics.ModifiedId.LowPart,
            statistics.ModifiedId.HighPart,
        ),
        privileges,
    })
}
pub(super) fn snapshot() -> Result<Snapshot> {
    let mut process = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process) } == 0 {
        api("token_query", unsafe { GetLastError() })?;
    }
    require(!process.is_null(), "Process token handle missing")?;
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut thread = null_mut();
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread) };
    let thread = if ok != 0 {
        require(!thread.is_null(), "Thread token handle missing")?;
        Some(unsafe { OwnedHandle::from_raw_handle(thread) })
    } else {
        let code = unsafe { GetLastError() };
        if code != ERROR_NO_TOKEN {
            api("token_query", code)?;
        }
        None
    };
    Ok(Snapshot {
        process: read(process.as_raw_handle())?,
        thread: thread
            .as_ref()
            .map(|value| read(value.as_raw_handle()))
            .transpose()?,
    })
}
