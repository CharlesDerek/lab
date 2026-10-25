//! Approved scanning/hash workers use the excluded scanner identity, with only
//! read/search capability. Root itself remains subject to on-access prevention.
use super::*;
use std::os::unix::fs::MetadataExt;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub(crate) fn prepare_reader(config: &Config, command: &mut Command) -> Result<()> {
    config.protection.validate()?;
    let uid = config.protection.engine_uid.ok_or("Missing scanner UID")?;
    let gid = config.protection.engine_gid.ok_or("Missing scanner GID")?;
    prepare_identity(uid, gid, command)
}
fn prepare_identity(uid: u32, gid: u32, command: &mut Command) -> Result<()> {
    if [0, u32::MAX].contains(&uid) || [0, u32::MAX].contains(&gid) {
        return Err("Invalid read-only scanner identity".into());
    }
    let parent = std::process::id();
    // pre_exec runs after fork: use only async-signal-safe operations and no
    // allocation or locks. Capability ABI v3 contains two 32-bit words.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            const READ_SEARCH: u32 = 1 << 2;
            let header = CapHeader {
                version: 0x20080522,
                pid: 0,
            };
            let data = [
                CapData {
                    effective: READ_SEARCH,
                    permitted: READ_SEARCH,
                    inheritable: READ_SEARCH,
                },
                CapData {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
                || libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, 2, 0, 0) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent as i32 {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HashRequest {
    path: PathBuf,
    identity: athernex_endpoint_native::Identity,
    timeout_ms: u64,
}

pub(crate) fn mutation_hash(
    uid: u32,
    gid: u32,
    path: &Path,
    identity: &athernex_endpoint_native::Identity,
    timeout: Duration,
    lease: &fs::File,
) -> Result<athernex_endpoint_native::Verdict> {
    use athernex_endpoint_native::child;
    if unsafe { libc::geteuid() } != 0 {
        return Err("Protected Linux mutations require the root service identity".into());
    }
    let timeout = timeout.min(Duration::from_secs(30));
    if timeout.is_zero() {
        return Err("Protected mutation hash deadline elapsed".into());
    }
    let request = HashRequest {
        path: path.into(),
        identity: identity.clone(),
        timeout_ms: timeout.as_millis().max(1) as u64,
    };
    let input = serde_json::to_vec(&request)?;
    if input.len() > 8192 {
        return Err("Protected hash request exceeds its byte budget".into());
    }
    let mut command = Command::new(std::env::current_exe()?);
    prepare_identity(uid, gid, &mut command)?;
    let fd = child::inherit_lease(&mut command, lease)?;
    command
        .arg("protection-mutation-hash")
        .arg(fd.to_string())
        .arg(std::process::id().to_string());
    let result = child::run_with_input(&mut command, timeout, 8192, &input);
    // The mutation context closes its descriptor without unlocking after this
    // handoff. A reader with pending cleanup keeps the shared lock description
    // alive, even if this supervisor exits. Recovery must acquire that lock.
    let (code, output) = result?;
    if code != 0 {
        return Err(format!(
            "Protected mutation reader failed ({code}): {}",
            String::from_utf8_lossy(&output)
                .chars()
                .take(512)
                .collect::<String>()
        )
        .into());
    }
    let verdict: athernex_endpoint_native::Verdict = serde_json::from_slice(&output)?;
    if !athernex_endpoint_protocol::hex_id(&verdict.sha256)
        || verdict.bytes != identity.size
        || verdict.detection.is_some()
    {
        return Err("Invalid protected mutation hash response".into());
    }
    Ok(verdict)
}

pub fn mutation_hash_worker(fd: i32, parent: u32) -> Result<athernex_endpoint_native::Verdict> {
    use std::{io::Read, os::fd::FromRawFd};
    athernex_endpoint_native::child::guard_parent(parent)?;
    if fd < 3 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err("Protected reader is missing its mutation lease".into());
    }
    let lease = unsafe { fs::File::from_raw_fd(fd) };
    let m = lease.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.len() != 0 || m.nlink() != 1 {
        return Err("Invalid protected mutation lease".into());
    }
    let mut input = Vec::new();
    std::io::stdin().take(8193).read_to_end(&mut input)?;
    if input.len() > 8192 {
        return Err("Protected hash request exceeds its byte budget".into());
    }
    let request: HashRequest = serde_json::from_slice(&input)?;
    if !(1..=30000).contains(&request.timeout_ms) {
        return Err("Invalid protected hash deadline".into());
    }
    let result = athernex_endpoint_native::scanner::hash_bound(&athernex_endpoint_native::Scan {
        path: request.path,
        identity: request.identity,
        deadline: Instant::now() + Duration::from_millis(request.timeout_ms),
    });
    drop(lease);
    result
}
