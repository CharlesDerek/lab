//! Keep atomic state replacement intact while a Windows reader briefly denies
//! delete sharing. Persistent access errors still fail within the retry budget.
use crate::Result;
use std::{
    path::Path,
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
};

pub(super) fn persist(mut file: NamedTempFile, path: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match file.persist(path) {
            Ok(_) => return Ok(()),
            Err(error) => {
                let retryable = matches!(
                    error.error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_ACCESS_DENIED | ERROR_LOCK_VIOLATION | ERROR_SHARING_VIOLATION)
                );
                if !retryable || Instant::now() >= deadline {
                    return Err(error.into());
                }
                // Retry the same already-written, synchronized temporary file.
                // Never unlink the old destination or change its permissions.
                file = error.file;
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::windows::fs::OpenOptionsExt, sync::mpsc};
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    fn pin(path: &Path) -> fs::File {
        fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .unwrap()
    }

    #[test]
    fn state_replacement_waits_for_reader_then_publishes_complete_contents() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.json");
        crate::private_write(&path, b"old state").unwrap();
        let reader = pin(&path);
        let target = path.clone();
        let (sender, receiver) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            sender
                .send(crate::private_write(&target, b"complete new state"))
                .unwrap();
        });
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"old state");
        drop(reader);
        receiver
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        writer.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"complete new state");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn persistent_reader_denial_preserves_state_and_removes_the_temporary_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.json");
        crate::private_write(&path, b"old state").unwrap();
        let reader = pin(&path);
        let started = Instant::now();
        assert!(crate::private_write(&path, b"new state").is_err());
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert_eq!(fs::read(&path).unwrap(), b"old state");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        drop(reader);
        crate::private_write(&path, b"later state").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"later state");
    }
}
