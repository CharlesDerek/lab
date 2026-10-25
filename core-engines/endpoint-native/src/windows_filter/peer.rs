//! Bind a loopback INSTREAM connection to the configured scanner process,
//! including its creation time. A listening port number is not authentication.
use super::engine::remaining;
use crate::Result;
use std::{
    io,
    mem::{offset_of, size_of},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_SUCCESS, FILETIME, WAIT_FAILED,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    },
    Networking::WinSock::AF_INET,
    System::Threading::{
        GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    },
};
pub struct EngineConnection {
    pub stream: TcpStream,
    process: OwnedHandle,
    created: u64,
}
fn creation(process: &OwnedHandle) -> Result<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}
pub fn identify(pid: u32) -> Result<u64> {
    if pid == 0 {
        return Err("Invalid Windows process identity".into());
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(handle) };
    let created = creation(&process)?;
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return Err("Windows process is no longer running".into());
    }
    Ok(created)
}
/// Observe an original process without terminating or trusting a recycled PID.
/// This alone says nothing about descendants. Recovery uses it only for scanner
/// jobs whose active-process limit is one, with no breakaway permission.
pub fn original_process_ended(pid: u32, created: u64) -> Result<bool> {
    if pid <= 4 || created == 0 {
        return Err("Invalid Windows recovery process identity".into());
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        // With valid access flags and a non-system PID, INVALID_PARAMETER means
        // the process ID no longer resolves. Access failures remain uncertain.
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(true);
        }
        return Err(error.into());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(handle) };
    if creation(&process)? != created {
        return Ok(true);
    }
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error().into()),
        _ => Err("Unexpected recovery process wait result".into()),
    }
}
fn address(ip: u32, port: u32) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(ip.to_ne_bytes()), u16::from_be(port as u16))
}
fn owns(stream: &TcpStream, pid: u32) -> Result<()> {
    let (SocketAddr::V4(client), SocketAddr::V4(server)) =
        (stream.local_addr()?, stream.peer_addr()?)
    else {
        return Err("Scanner requires IPv4 loopback".into());
    };
    let mut bytes = 0;
    for _ in 0..4 {
        if bytes > 4 * 1024 * 1024 {
            return Err("TCP ownership table exceeds its byte budget".into());
        }
        let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
        let pointer = if buffer.is_empty() {
            null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        let error = unsafe {
            GetExtendedTcpTable(
                pointer,
                &mut bytes,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if error == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if error != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(error as i32).into());
        }
        if bytes < 4 || bytes as usize > buffer.len() * 8 {
            return Err("Invalid TCP ownership table".into());
        }
        let data = buffer.as_ptr().cast::<u8>();
        let count = unsafe { data.cast::<u32>().read_unaligned() } as usize;
        let offset = offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        if count > 65536
            || offset
                .checked_add(
                    count
                        .checked_mul(size_of::<MIB_TCPROW_OWNER_PID>())
                        .ok_or("TCP table overflow")?,
                )
                .is_none_or(|end| end > bytes as usize)
        {
            return Err("Invalid TCP ownership row count".into());
        }
        for i in 0..count {
            let row = unsafe {
                data.add(offset + i * size_of::<MIB_TCPROW_OWNER_PID>())
                    .cast::<MIB_TCPROW_OWNER_PID>()
                    .read_unaligned()
            };
            if row.dwState == 5
                && row.dwOwningPid == pid
                && address(row.dwLocalAddr, row.dwLocalPort) == server
                && address(row.dwRemoteAddr, row.dwRemotePort) == client
            {
                return Ok(());
            }
        }
        return Err("Scanner connection belongs to a different process".into());
    }
    Err("TCP ownership table did not stabilize".into())
}
impl EngineConnection {
    pub fn connect(
        address: SocketAddrV4,
        pid: u32,
        created: u64,
        deadline: Instant,
    ) -> Result<Self> {
        if *address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 || pid == 0 || created == 0 {
            return Err("Scanner needs a pinned local process identity".into());
        }
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(handle) };
        if creation(&process)? != created
            || unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT
        {
            return Err("Scanner process identity changed".into());
        }
        let stream = TcpStream::connect_timeout(&SocketAddr::V4(address), remaining(deadline)?)?;
        owns(&stream, pid)?;
        let connection = Self {
            stream,
            process,
            created,
        };
        connection.alive()?;
        Ok(connection)
    }
    pub fn alive(&self) -> Result<()> {
        if creation(&self.process)? != self.created
            || unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_TIMEOUT
        {
            return Err("Scanner process ended during verification".into());
        }
        Ok(())
    }
}
