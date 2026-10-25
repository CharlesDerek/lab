//! Portable scanner text is only a candidate path. A separate private snapshot
//! scan binds the verdict to a hash before a response playbook may act on it.
use crate::{file_hash, run_bounded, Config, Result, Store};
use std::{fs, io::Write, path::Path};

pub(crate) fn verify_snapshot(
    config: &Config,
    store: &Store,
    path: &Path,
    timeout: u64,
) -> Result<(String, String)> {
    if timeout == 0 {
        return Err("Scan verification exceeded the action deadline".into());
    }
    const LIMIT: u64 = 100 * 1024 * 1024;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let source = options.open(path)?;
    if !source.metadata()?.is_file() || source.metadata()?.len() > LIMIT {
        return Err("Scan verification requires a regular file at most 100 MiB".into());
    }
    let mut snapshot = tempfile::NamedTempFile::new_in(&store.directory)?;
    if std::io::copy(&mut std::io::Read::take(source, LIMIT + 1), &mut snapshot)? > LIMIT {
        return Err("Scan snapshot exceeded its byte budget".into());
    }
    snapshot.flush()?;
    // Close the writer before launching Windows scanners with restrictive file
    // sharing modes. The private parent directory protects the retained path.
    let snapshot = snapshot.into_temp_path();
    let hash = file_hash(&snapshot)?;
    let mut command = crate::antivirus::command(config, &config.scanner)?;
    if let Some(database) = &config.signature_database {
        command.arg("--database").arg(database);
    }
    command
        .args([
            "--recursive=no",
            "--infected",
            "--no-summary",
            "--max-filesize=100M",
            "--max-scansize=200M",
            "--",
        ])
        .arg(&snapshot);
    let (code, output) = run_bounded(&mut command, timeout)?;
    if code != 1 {
        return Err("Scanner report did not verify against the current file snapshot".into());
    }
    let detection = output.lines().find_map(|line| {
        line.strip_suffix(" FOUND")
            .and_then(|line| line.rsplit_once(": "))
            .map(|(_, name)| name)
    });
    let detection = detection.ok_or("Snapshot scan returned no detection name")?;
    if detection.is_empty() || detection.len() > 256 || detection.chars().any(char::is_control) {
        return Err("Invalid snapshot detection name".into());
    }
    Ok((hash, detection.into()))
}
