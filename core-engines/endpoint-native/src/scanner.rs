//! Read through descriptors, bind the ES vnode identity, and hash exactly the
//! INSTREAM bytes. Native authorization owns the deadline even if file I/O stalls.
use crate::{Identity, Result, Scan, Verdict, MAX_FILE};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, Metadata},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, net::UnixStream},
    },
    path::Path,
    time::{Duration, Instant},
};

pub fn identity(metadata: &Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_sec: metadata.mtime(),
        modified_nsec: metadata.mtime_nsec(),
        changed_sec: metadata.ctime(),
        changed_nsec: metadata.ctime_nsec(),
    }
}
pub fn open_file(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err("Native scan requires an absolute path".into());
    }
    let mut file = File::open("/")?;
    for part in path.components() {
        match part {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                file = unsafe { File::from_raw_fd(fd) };
            }
            _ => return Err("Native scan requires an absolute path without traversal".into()),
        }
    }
    if !file.metadata()?.is_file() {
        return Err("Native scan target is not a regular file".into());
    }
    Ok(file)
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "Native scan deadline elapsed".into())
}
fn bind(file: &File, expected: &Identity) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || &identity(&metadata) != expected {
        return Err("File identity or content metadata changed during authorization".into());
    }
    Ok(())
}
/// Exact-identity hashing for the excluded Linux reader. It returns no content
/// and does not claim a malware verdict. The approved response supplies the hash.
pub fn hash_bound(request: &Scan) -> Result<Verdict> {
    remaining(request.deadline)?;
    if request.identity.size > MAX_FILE {
        return Err("Native hash exceeds 128 MiB file budget".into());
    }
    let mut file = open_file(&request.path)?;
    bind(&file, &request.identity)?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        remaining(request.deadline)?;
        let bytes = file.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        count += bytes as u64;
        if count > request.identity.size || count > MAX_FILE {
            return Err("File grew during approved hashing".into());
        }
        hash.update(&buffer[..bytes]);
    }
    bind(&file, &request.identity)?;
    if count != request.identity.size {
        return Err("File length changed during approved hashing".into());
    }
    bind(&open_file(&request.path)?, &request.identity)?;
    remaining(request.deadline)?;
    Ok(Verdict {
        sha256: format!("{:x}", hash.finalize()),
        bytes: count,
        detection: None,
    })
}
pub fn scan(request: &Scan, socket_path: &Path) -> Result<Verdict> {
    remaining(request.deadline)?;
    if request.identity.size > MAX_FILE {
        return Err("Native scan exceeds 128 MiB file budget".into());
    }
    let mut file = open_file(&request.path)?;
    bind(&file, &request.identity)?;
    // A blocked connect/read can occupy only one of the fixed worker slots.
    // The native response loop independently denies expired requests.
    let mut socket = UnixStream::connect(socket_path)?;
    socket.set_write_timeout(Some(remaining(request.deadline)?))?;
    socket.write_all(b"zINSTREAM\0")?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        remaining(request.deadline)?;
        let bytes = file.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        count += bytes as u64;
        if count > MAX_FILE || count > request.identity.size {
            return Err("File grew during authorization".into());
        }
        socket.set_write_timeout(Some(remaining(request.deadline)?))?;
        socket.write_all(&(bytes as u32).to_be_bytes())?;
        socket.write_all(&buffer[..bytes])?;
        hash.update(&buffer[..bytes]);
    }
    bind(&file, &request.identity)?;
    if count != request.identity.size {
        return Err("File length changed during authorization".into());
    }
    socket.set_write_timeout(Some(remaining(request.deadline)?))?;
    socket.write_all(&0u32.to_be_bytes())?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let count = crate::socket_read::read(&socket, &mut buffer, request.deadline)?;
        let available = &buffer[..count];
        if available.is_empty() {
            return Err("Scanner closed before completing its response".into());
        }
        let end = available.iter().position(|b| *b == 0).map(|n| n + 1);
        let bytes = end.unwrap_or(available.len());
        if response.len() + bytes > 1024 {
            return Err("Scanner response exceeded its byte budget".into());
        }
        response.extend_from_slice(&available[..bytes]);
        if end.is_some() {
            break;
        }
    }
    remaining(request.deadline)?;
    bind(&file, &request.identity)?;
    // Reopening the path also detects a rename/replacement while the original
    // descriptor remained valid. No result is cached for future authorizations.
    bind(&open_file(&request.path)?, &request.identity)?;
    let verdict = std::str::from_utf8(&response)?
        .strip_prefix("stream: ")
        .and_then(|s| s.strip_suffix('\0'))
        .ok_or("Invalid scanner verdict framing")?;
    let detection = if verdict == "OK" {
        None
    } else {
        let name = verdict
            .strip_suffix(" FOUND")
            .ok_or("Scanner rejected the stream")?;
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err("Invalid scanner detection name".into());
        }
        Some(name.into())
    };
    Ok(Verdict {
        sha256: format!("{:x}", hash.finalize()),
        detection,
        bytes: count,
    })
}
