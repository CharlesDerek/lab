use super::hex_id;
use crate::Result;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
const HELPER_LIMIT: u64 = 256 * 1024 * 1024;

pub(crate) fn pin_helper(path: &Path, expected: &str) -> Result<File> {
    if !hex_id(expected) || !path.is_absolute() || path.canonicalize()? != path {
        return Err("Invalid process helper identity".into());
    }
    for (index, ancestor) in path.ancestors().enumerate() {
        let m = fs::symlink_metadata(ancestor)?;
        if m.uid() != 0
            || m.file_type().is_symlink()
            || m.mode() & 0o022 != 0
            || (index > 0 && !m.is_dir())
        {
            return Err("Process helper requires a trusted root-owned path".into());
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.mode() & 0o111 == 0
        || before.len() == 0
        || before.len() > HELPER_LIMIT
    {
        return Err("Invalid process helper file".into());
    }
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    let mut total = 0_u64;
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or("Process helper size overflow")?;
        if total > HELPER_LIMIT {
            return Err("Process helper exceeds its size bound".into());
        }
        hash.update(&bytes[..n]);
    }
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if total != before.len()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
        || named.dev() != before.dev()
        || named.ino() != before.ino()
        || named.file_type().is_symlink()
        || format!("{:x}", hash.finalize()) != expected
    {
        return Err("Process helper hash or file identity changed".into());
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
pub(crate) fn launch(
    path: &Path,
    expected_sha256: &str,
    stream_id: &str,
    mode: &'static str,
) -> Result<(
    crate::child::Service,
    std::os::unix::net::UnixStream,
    File,
    String,
)> {
    use crate::child;
    use std::os::unix::net::UnixStream;
    use std::{
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::process::CommandExt,
        },
        process::Command as ProcessCommand,
    };
    if unsafe { libc::geteuid() } != 0 || !hex_id(stream_id) {
        return Err("Process collection requires root and a valid stream".into());
    }
    let image = pin_helper(path, expected_sha256)?;
    let (stream, child_stream) = UnixStream::pair()?;
    // Duplicate an independently owned descriptor; only the child copy
    // loses CLOEXEC, and Command drops the parent's duplicate after spawn.
    let raw = unsafe { libc::fcntl(child_stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err("Process helper socket duplication failed".into());
    }
    let inherited = unsafe { File::from_raw_fd(raw) };
    let mut command = ProcessCommand::new(path);
    command.env_clear();
    command
        .arg(mode)
        .arg(std::process::id().to_string())
        .arg(raw.to_string());
    unsafe {
        command.pre_exec(move || {
            let fd = inherited.as_raw_fd();
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let service = child::Service::start(&mut command, 4096)?;
    drop(command);
    drop(child_stream);
    let mut random = [0; 32];
    getrandom::fill(&mut random).map_err(|_| "Process source nonce failed")?;
    let nonce = random.iter().map(|b| format!("{b:02x}")).collect();

    Ok((service, stream, image, nonce))
}
