//! Small OS-operation probes. A denied syscall alone does not prove antivirus
//! blocking: callers must also match the exact native authorization receipt.
use crate::{
    child,
    receipt::{self, Actor, Receipt},
    scanner, Identity, Policy, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Open,
    Exec,
    Mmap,
}
impl Operation {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "open" => Ok(Self::Open),
            "exec" => Ok(Self::Exec),
            "mmap" => Ok(Self::Mmap),
            _ => Err("Invalid probe operation".into()),
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Exec => "exec",
            Self::Mmap => "mmap",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub schema: u32,
    pub nonce: String,
    pub operation: Operation,
    pub path: PathBuf,
    pub identity: Identity,
    pub actor: Actor,
    pub time_ms: u64,
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn actor() -> Result<Actor> {
    #[cfg(target_os = "macos")]
    {
        let token = endpoint_sec::AuditToken::from_pid(std::process::id() as i32)
            .map_err(|e| format!("Cannot identify probe process: {e}"))?;
        Ok(Actor {
            pid: token.pid() as u32,
            uid: token.euid(),
            pidversion: token.pidversion(),
        })
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Actor {
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
            pidversion: 0,
        })
    }
}
fn emit(value: &impl Serialize) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Validate evidence independently of the syscall's error code. In particular,
/// permission errors, stale receipts and scanner failures cannot prove blocking.
pub fn validate_denial(
    attempt: &Attempt,
    event: &Receipt,
    policy: &Policy,
    sha256: &str,
    detection: &str,
) -> Result<()> {
    validate_denial_at(attempt, event, policy, sha256, detection, now_ms())
}

/// Revalidate saved evidence at its original verification time. The caller must
/// separately enforce the age of that complete verification cycle.
pub(crate) fn validate_denial_at(
    attempt: &Attempt,
    event: &Receipt,
    policy: &Policy,
    sha256: &str,
    detection: &str,
    checked_ms: u64,
) -> Result<()> {
    event.validate_policy(policy, checked_ms)?;
    if attempt.schema != 1
        || !receipt::hex_id(&attempt.nonce)
        || !receipt::hex_id(sha256)
        || attempt.actor.pid == 0
        || attempt.actor.uid == policy.scanner_uid
        || attempt.time_ms == 0
        || attempt.time_ms > checked_ms.saturating_add(1000)
        || checked_ms.saturating_sub(attempt.time_ms) > 15000
        || event.time_ms > checked_ms.saturating_add(1000)
        || event.time_ms < attempt.time_ms
        || event.time_ms > attempt.time_ms.saturating_add(10000)
        || event.operation != attempt.operation.name()
        || event.path != attempt.path.to_string_lossy()
        || event.identity != attempt.identity
        || event.actor.pid != attempt.actor.pid
        || event.actor.uid != attempt.actor.uid
        || event.actor.pidversion != attempt.actor.pidversion
        || !event.response_delivered
        || !event.error.is_empty()
        || event
            .verdict
            .as_ref()
            .is_none_or(|v| v.sha256 != sha256 || v.detection.as_deref() != Some(detection))
    {
        return Err("Probe denial does not match delivered native detection evidence".into());
    }
    Ok(())
}

pub fn validate_saved(
    plan: &Path,
    attempt: &Path,
    event: &Path,
    sha256: &str,
    detection: &str,
) -> Result<()> {
    use std::io::Read;
    fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        crate::broker::trusted(path, true)?;
        let mut bytes = Vec::new();
        scanner::open_file(path)?
            .take(8193)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return Err("Probe evidence exceeds its byte budget".into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    let plan = crate::service::read_plan(plan)?;
    validate_denial(
        &read(attempt)?,
        &read(event)?,
        &plan.policy,
        sha256,
        detection,
    )
}

/// Run in an owned process group. mmap uses a read-only descriptor opened before
/// protection activation, so AUTH_OPEN cannot stand in for an AUTH_MMAP result.
/// Exec replaces this helper; a successful caller-chosen fixture must exit zero.
pub fn run(
    parent: u32,
    operation: Operation,
    path: &Path,
    descriptor: Option<i32>,
    nonce: &str,
) -> Result<i32> {
    child::guard_parent(parent)?;
    if !receipt::hex_id(nonce)
        || !path.is_absolute()
        || path.canonicalize()? != path
        || path.as_os_str().len() > 1024
        || path.to_str().is_none_or(|s| s.contains(char::is_control))
        || (operation == Operation::Mmap) != descriptor.is_some()
    {
        return Err("Invalid native probe request".into());
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 16 * 1024 * 1024 {
        return Err("Invalid native probe file".into());
    }
    let attempt = Attempt {
        schema: 1,
        nonce: nonce.into(),
        operation: operation.clone(),
        path: path.into(),
        identity: scanner::identity(&metadata),
        actor: actor()?,
        time_ms: now_ms(),
    };
    let inherited = if let Some(fd) = descriptor {
        if fd < 3 {
            return Err("Invalid probe descriptor".into());
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err("Probe descriptor must be read-only".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if scanner::identity(&file.metadata()?) != attempt.identity {
            return Err("Probe descriptor belongs to another file".into());
        }
        Some(file)
    } else {
        None
    };
    emit(&attempt)?;
    let result: std::io::Result<()> = match operation {
        Operation::Open => OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .and_then(|f| {
                if scanner::identity(&f.metadata()?) != attempt.identity {
                    return Err(std::io::Error::other("Probe file changed"));
                }
                Ok(())
            }),
        Operation::Exec => {
            // execve has no execvp shell fallback for malformed executable
            // bytes. Probe exactly this image, with no inherited environment.
            let image = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
            let arguments = [image.as_ptr(), std::ptr::null()];
            let environment = [std::ptr::null()];
            unsafe {
                libc::execve(image.as_ptr(), arguments.as_ptr(), environment.as_ptr());
            }
            Err(std::io::Error::last_os_error())
        }
        Operation::Mmap => {
            let file = inherited.as_ref().ok_or("Missing mapping descriptor")?;
            let length = (metadata.len() as usize).min(4096);
            let pointer = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    length,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                Err(std::io::Error::last_os_error())
            } else {
                unsafe {
                    std::ptr::read_volatile(pointer.cast::<u8>());
                    libc::munmap(pointer, length);
                }
                Ok(())
            }
        }
    };
    let (outcome, errno, code) = match result {
        Ok(()) => ("allowed", None, 0),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
            ("denied", e.raw_os_error(), 10)
        }
        Err(e) => ("error", e.raw_os_error(), 1),
    };
    emit(&serde_json::json!({"schema":1,"nonce":nonce,"outcome":outcome,"errno":errno}))?;
    Ok(code)
}

#[cfg(test)]
mod tests;
