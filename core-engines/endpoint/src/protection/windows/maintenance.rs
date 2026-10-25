//! Maintenance excludes native workers independently of the public protection
//! toggle. Recovery is explicit; an update never guesses that a journal is safe
//! to discard or changes persistent network policy as a side effect.
use super::{recovery, scratch, windows_job, workspaces, Directory, File, Path, Result};

#[cfg(test)]
mod tests;

struct Native {
    _supervisor: File,
    _client: File,
    _scratch: File,
    _directory: Directory,
}
pub(crate) struct Quiescent {
    _native: Option<Native>,
    _protection: File,
    _directory: Directory,
}

fn optional(path: &Path) -> Result<Option<Directory>> {
    match Directory::open(path) {
        Ok(directory) => Ok(Some(directory)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
fn protection(endpoint: &Path) -> Result<Directory> {
    // Absolute normalization does not resolve junctions or symlinks: Directory
    // checks and pins the original ancestry before accessing private state.
    Directory::open(&std::path::absolute(endpoint)?)?.maintenance_directory("protection")
}
fn empty(state: &Directory) -> Result<()> {
    for leaf in [
        "network",
        "scratch-journal",
        "scratch-runtime",
        "scratch-health",
        "workspaces",
        "runtime",
    ] {
        if let Some(directory) = optional(&state.path().join(leaf))? {
            if std::fs::read_dir(directory.path())?
                .next()
                .transpose()?
                .is_some()
            {
                return Err(format!(
                    "Windows preview {leaf} still requires recovery; run windows-protection-recover as LocalSystem before maintenance"
                )
                .into());
            }
        }
    }
    Ok(())
}

pub(crate) fn quiescent(endpoint: &Path) -> Result<Quiescent> {
    windows_job::cleanup_ready()?;
    let protection = protection(endpoint)?;
    // Always acquire this lease, including on a never-configured endpoint.
    // Absence checks alone would race the preview's first startup.
    let lease = protection
        .maintenance_lock("supervisor.lock")
        .map_err(|e| format!("Stop Windows preview protection before maintenance: {e}"))?;
    let native = if let Some(state) = optional(&protection.path().join("windows"))? {
        let supervisor = state.maintenance_lock("supervisor.lock")?;
        let client = state.maintenance_lock("client.lock")?;
        let scratch = state.maintenance_lock("scratch-worker.lock")?;
        empty(&state)?;
        Some(Native {
            _supervisor: supervisor,
            _client: client,
            _scratch: scratch,
            _directory: state,
        })
    } else {
        None
    };
    Ok(Quiescent {
        _native: native,
        _protection: lease,
        _directory: protection,
    })
}

/// The caller retains both standard protection and native supervisor leases.
/// A surviving client or scratch helper blocks recovery before any mutation.
pub(super) fn recover_retired(state: &Directory) -> Result<()> {
    windows_job::cleanup_ready()?;
    let _client = state.lock("client.lock")?;
    let scratch = state.lock("scratch-worker.lock")?;
    // The cleanup subprocess must acquire this same lease. The supervisor
    // leases still exclude all normal startup while it performs reclamation.
    drop(scratch);
    recovery::recover(&state.directory("network")?)?;
    scratch::reclaim(state)?;
    workspaces::reclaim(state)?;
    let _scratch = state.lock("scratch-worker.lock")?;
    empty(state)
}

/// Retire only recorded/empty abandoned state. This never starts a scanner,
/// loads a driver, adopts a disk, or terminates a PID from a journal.
pub fn recover(endpoint: &Path) -> Result<()> {
    athernex_endpoint_native::windows_state::require_local_system()?;
    let protection = protection(endpoint)?;
    let _lease = protection.lock("supervisor.lock")?;
    if let Some(state) = optional(&protection.path().join("windows"))? {
        let _supervisor = state.lock("supervisor.lock")?;
        recover_retired(&state)?;
    }
    Ok(())
}
