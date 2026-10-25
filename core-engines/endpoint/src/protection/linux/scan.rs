//! Hash exactly the bytes streamed to clamd. Verdicts never come from log paths.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
};

const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
#[derive(Default, Serialize, Deserialize)]
struct Report {
    files: u64,
    bytes: u64,
    skipped_special: u64,
    detections: Vec<Detection>,
}
#[derive(Serialize, Deserialize)]
struct Detection {
    path: String,
    sha256: String,
    detection: String,
}

fn open_at(directory: &File, name: &std::ffi::OsStr) -> std::io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_path(path: &Path) -> Result<File> {
    let mut file = File::open("/")?;
    for part in path.components() {
        match part {
            std::path::Component::RootDir => (),
            std::path::Component::Normal(name) => {
                file = open_at(&file, name)?;
            }
            _ => return Err("Scan requires an absolute canonical path".into()),
        }
    }
    Ok(file)
}

fn stream_file(
    mut file: File,
    socket_path: &Path,
    report: &mut Report,
) -> Result<(String, Option<String>)> {
    if file.metadata()?.len() > MAX_FILE {
        return Err("Scan file exceeds 128 MiB budget".into());
    }
    let mut socket = UnixStream::connect(socket_path)?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    socket.set_write_timeout(Some(Duration::from_secs(15)))?;
    socket.write_all(b"zINSTREAM\0")?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        report.bytes += n as u64;
        if size > MAX_FILE || report.bytes > MAX_TOTAL {
            return Err("Scan byte budget exceeded".into());
        }
        socket.write_all(&(n as u32).to_be_bytes())?;
        socket.write_all(&buffer[..n])?;
        hash.update(&buffer[..n]);
    }
    socket.write_all(&0u32.to_be_bytes())?;
    let mut response = Vec::new();
    BufReader::new(socket.take(1024)).read_until(0, &mut response)?;
    let text = std::str::from_utf8(&response)?;
    let result = text
        .strip_prefix("stream: ")
        .and_then(|s| s.strip_suffix('\0'))
        .ok_or("Invalid daemon scan response")?;
    let detection = if result == "OK" {
        None
    } else {
        let name = result
            .strip_suffix(" FOUND")
            .ok_or("Daemon rejected file scan")?;
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err("Invalid daemon detection name".into());
        }
        Some(name.to_owned())
    };
    Ok((format!("{:x}", hash.finalize()), detection))
}

fn visit(
    file: File,
    path: &Path,
    socket: &Path,
    depth: usize,
    visited: &mut usize,
    report: &mut Report,
) -> Result<()> {
    *visited += 1;
    if *visited > 4096 || depth > 32 {
        return Err("Scan exceeds 4096 entries or 32 directory levels".into());
    }
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        // Enumerate the already-open directory, including across renames.
        for entry in fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if !kind.is_file() && !kind.is_dir() {
                report.skipped_special += 1;
                continue;
            }
            let child = match open_at(&file, &entry.file_name()) {
                Ok(child) => child,
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                    report.skipped_special += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            visit(
                child,
                &path.join(entry.file_name()),
                socket,
                depth + 1,
                visited,
                report,
            )?;
        }
    } else if metadata.is_file() {
        let name = path.to_str().ok_or("Scan path must be UTF-8")?;
        if name.len() > 2048 {
            return Err("Scan path exceeds evidence budget".into());
        }
        let (sha256, detection) = stream_file(file, socket, report)?;
        report.files += 1;
        if let Some(detection) = detection {
            if detection == format!("{SIGNATURE}.UNOFFICIAL") && sha256 == protocol::hash(PROBE) {
                return Ok(());
            }
            report.detections.push(Detection {
                path: name.into(),
                sha256,
                detection,
            });
            if serde_json::to_vec(report)?.len() > protocol::MAX_OUTPUT - 1024 {
                return Err("Scan detection output budget exceeded".into());
            }
        }
    } else {
        report.skipped_special += 1;
    }
    Ok(())
}

pub fn scan_worker(path: &Path, socket: &Path) -> Result<String> {
    if !path.is_absolute() || !socket.is_absolute() {
        return Err("Scan paths must be absolute".into());
    }
    let mut report = Report::default();
    visit(open_path(path)?, path, socket, 0, &mut 0, &mut report)?;
    Ok(serde_json::to_string(&report)?)
}

pub(crate) fn execute_scan(
    config: &Config,
    store: &Store,
    path: &Path,
    timeout: u64,
) -> Result<String> {
    let mut command = Command::new(std::env::current_exe()?);
    command.arg("protection-scan").arg(path).arg(
        config
            .protection
            .runtime
            .as_ref()
            .ok_or("Missing protection socket")?
            .join("clamd.sock"),
    );
    prepare_reader(config, &mut command)?;
    let (code, output) = run_bounded(&mut command, timeout)?;
    if code != 0 {
        return Err(format!("Native scan failed: {}", crate::bounded(&output)).into());
    }
    let report: Report = serde_json::from_str(&output)?;
    let mut events = Vec::new();
    for detection in &report.detections {
        events.push(EndpointEvent { telemetry: None, id: crate::secret()?, time_ms: now_ms(), kind: "malware".into(), path: detection.path.clone(), sha256: detection.sha256.clone(), detection: detection.detection.clone(), detail: "ClamAV matched the exact byte stream identified by this SHA-256. Quarantine verifies the current file against that hash.".into() });
    }
    let summary = format!(
        "Native scan: {} files, {} bytes, {} detections, {} symlinks/special entries skipped.\n{}",
        report.files,
        report.bytes,
        report.detections.len(),
        report.skipped_special,
        report
            .detections
            .iter()
            .map(|d| format!("{}: {} FOUND", d.path, d.detection))
            .collect::<Vec<_>>()
            .join("\n")
    );
    events.push(EndpointEvent {
        telemetry: None,
        id: crate::secret()?,
        time_ms: now_ms(),
        kind: "scan".into(),
        path: path.to_string_lossy().into(),
        sha256: String::new(),
        detection: String::new(),
        detail: summary.chars().take(4000).collect(),
    });
    // Atomic admission prevents receipts claiming complete evidence delivery
    // after only some detections fit in the outbox.
    let tx = store.connection.unchecked_transaction()?;
    for event in &events {
        store.enqueue(event)?;
    }
    tx.commit()?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{fs::symlink, net::UnixListener};

    #[test]
    fn stream_digest_binds_the_open_file_and_rejects_malformed_verdicts() {
        for reply in [
            "stream: Fixture FOUND\0",
            "stream: OK\0",
            "untrusted: Fixture FOUND\0",
            "stream: Bad\nName FOUND\0",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let source = directory.path().join("source");
            fs::write(&source, b"original opened bytes").unwrap();
            let file = open_path(&source).unwrap();
            fs::rename(&source, directory.path().join("moved")).unwrap();
            fs::write(&source, b"different replacement").unwrap();
            let socket = directory.path().join("clamd.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut command = [0u8; 10];
                socket.read_exact(&mut command).unwrap();
                assert_eq!(&command, b"zINSTREAM\0");
                let mut data = Vec::new();
                loop {
                    let mut size = [0u8; 4];
                    socket.read_exact(&mut size).unwrap();
                    let size = u32::from_be_bytes(size) as usize;
                    if size == 0 {
                        break;
                    }
                    assert!(size <= 65536);
                    let offset = data.len();
                    data.resize(offset + size, 0);
                    socket.read_exact(&mut data[offset..]).unwrap();
                }
                assert_eq!(data, b"original opened bytes");
                socket.write_all(reply.as_bytes()).unwrap();
            });
            let result = stream_file(file, &socket, &mut Report::default());
            server.join().unwrap();
            if reply == "stream: OK\0" || reply == "stream: Fixture FOUND\0" {
                let (hash, detection) = result.unwrap();
                assert_eq!(hash, protocol::hash(b"original opened bytes"));
                assert_eq!(detection.is_some(), reply.contains("FOUND"));
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn scan_walk_skips_symlinks_and_special_files_without_following_them() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("watch");
        fs::create_dir(&root).unwrap();
        let outside = directory.path().join("private");
        fs::write(&outside, b"outside scope").unwrap();
        symlink(&outside, root.join("link")).unwrap();
        let fifo = CString::new(root.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let socket = directory.path().join("absent.sock");
        let report: Report = serde_json::from_str(&scan_worker(&root, &socket).unwrap()).unwrap();
        assert_eq!(report.skipped_special, 2);
        assert_eq!(report.files, 0);
        assert!(open_path(&root.join("link")).is_err());
        symlink(&root, directory.path().join("alias")).unwrap();
        assert!(open_path(&directory.path().join("alias/fifo")).is_err());
    }
}
