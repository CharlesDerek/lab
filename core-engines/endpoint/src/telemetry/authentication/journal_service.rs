//! Bounded read-only GetInfo request: retained files alone do not prove that
//! the native journal writer can still accept and process authentication logs.
use crate::Result;
use std::{
    io::{Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    time::{Duration, Instant},
};
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "Native journal service probe timed out".into())
}
pub(super) fn probe() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last = "Native journal control socket is unavailable".to_owned();
    for path in [
        "/run/systemd/journal/io.systemd.journal",
        "/run/systemd/journal/io.systemd.Journal",
    ] {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err("Native journal control socket has an unexpected owner or type".into());
        }
        let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        if let Err(error) =
            socket.connect_timeout(&socket2::SockAddr::unix(path)?, remaining(deadline)?)
        {
            last = error.to_string();
            continue;
        }
        let fd: OwnedFd = socket.into();
        let mut stream = UnixStream::from(fd);
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&credentials)
            || credentials.uid != 0
            || credentials.pid <= 0
        {
            return Err("Native journal control peer is not a root-owned service".into());
        }
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        stream.write_all(b"{\"method\":\"org.varlink.service.GetInfo\"}\0")?;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            stream.set_read_timeout(Some(remaining(deadline)?))?;
            let read = stream.read(&mut chunk)?;
            if read == 0 || bytes.len() + read > 8192 {
                return Err(
                    "Native journal service returned an empty or excessive response".into(),
                );
            }
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(end) = bytes.iter().position(|b| *b == 0) {
                if end != bytes.len() - 1 {
                    return Err("Unexpected extra native journal service response".into());
                }
                let value: serde_json::Value = serde_json::from_slice(&bytes[..end])?;
                if value.get("error").is_some()
                    || !value["parameters"]["interfaces"]
                        .as_array()
                        .is_some_and(|values| values.iter().any(|v| v == "io.systemd.Journal"))
                {
                    return Err(
                        "Native journal service did not identify its journal interface".into(),
                    );
                }
                return Ok(());
            }
        }
    }
    Err(format!("Native journal writer is unavailable: {last}").into())
}
