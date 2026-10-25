use super::*;

#[test]
fn native_policy_rejects_unbounded_or_recursive_scanner_scope() {
    let policy = Policy {
        roots: vec!["/Users".into()],
        socket: "/private/runtime/clamd.sock".into(),
        state: "/private/state".into(),
        scanner_uid: 82,
        scan_timeout_ms: 1000,
    };
    policy.validate().unwrap();
    assert!(policy.contains_observed_path(std::path::Path::new("/Users/file"), false));
    assert!(!policy.contains_observed_path(std::path::Path::new("/Users-other/file"), false));
    // An ambiguous truncated prefix must enter the denial path, while malformed
    // unrelated paths must not broaden protection beyond the configured roots.
    assert!(policy.contains_observed_path(std::path::Path::new("/Us"), true));
    assert!(!policy.contains_observed_path(std::path::Path::new("/private/unrelated"), true));
    for field in 0..6 {
        let mut bad = policy.clone();
        match field {
            0 => bad.roots = vec!["/".into()],
            1 => bad.state = "/Users/state".into(),
            2 => bad.socket = "/Users/socket".into(),
            3 => bad.scanner_uid = 0,
            4 => bad.scan_timeout_ms = 10000,
            _ => bad.roots = vec!["relative".into()],
        }
        assert!(bad.validate().is_err());
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{fs::symlink, net::UnixListener},
        path::Path,
        sync::Arc,
        thread,
        time::Duration,
    };

    fn request(path: &Path) -> Scan {
        Scan {
            path: path.into(),
            identity: scanner::identity(&fs::metadata(path).unwrap()),
            deadline: Instant::now() + Duration::from_secs(2),
        }
    }
    fn daemon(
        socket: &Path,
        response: Vec<u8>,
        hook: impl FnOnce(Vec<u8>) + Send + 'static,
    ) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(socket).unwrap();
        thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut header = [0u8; 10];
            client.read_exact(&mut header).unwrap();
            assert_eq!(&header, b"zINSTREAM\0");
            let mut data = Vec::new();
            loop {
                let mut count = [0u8; 4];
                client.read_exact(&mut count).unwrap();
                let count = u32::from_be_bytes(count) as usize;
                if count == 0 {
                    break;
                }
                assert!(count <= 65536);
                let mut part = vec![0u8; count];
                client.read_exact(&mut part).unwrap();
                data.extend(part);
            }
            hook(data);
            let _ = client.write_all(&response);
        })
    }
    #[test]
    fn scanner_hashes_the_exact_stream_and_accepts_only_framed_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let data = Arc::new(vec![13; 200000]);
        let path = root.join("sample");
        fs::write(&path, &*data).unwrap();
        for (index, response) in [
            b"stream: OK\0".to_vec(),
            b"stream: Test.Detection FOUND\0".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let socket = root.join(format!("scan-{index}.sock"));
            let expected = data.clone();
            let daemon = daemon(&socket, response, move |bytes| assert_eq!(bytes, *expected));
            let verdict = scanner::scan(&request(&path), &socket).unwrap();
            daemon.join().unwrap();
            assert_eq!(verdict.sha256, format!("{:x}", Sha256::digest(&*data)));
            assert_eq!(verdict.bytes, data.len() as u64);
            assert_eq!(
                verdict.detection,
                if index == 0 {
                    None
                } else {
                    Some("Test.Detection".into())
                }
            );
        }
    }
    #[test]
    fn malformed_scanner_responses_never_authorize_clean_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("sample");
        fs::write(&path, b"clean fixture").unwrap();
        for (index, response) in [
            b"OK\0".to_vec(),
            b"stream: OK".to_vec(),
            b"stream: size limit ERROR\0".to_vec(),
            b"stream: \nforged FOUND\0".to_vec(),
            vec![b'x'; 2048],
        ]
        .into_iter()
        .enumerate()
        {
            let socket = root.join(format!("bad-{index}.sock"));
            let daemon = daemon(&socket, response, |_| {});
            assert!(scanner::scan(&request(&path), &socket).is_err());
            daemon.join().unwrap();
        }
    }
    #[test]
    fn mutation_during_scanning_invalidates_a_clean_daemon_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("sample");
        fs::write(&path, b"original").unwrap();
        let change = path.clone();
        let socket = root.join("mutate.sock");
        let daemon = daemon(&socket, b"stream: OK\0".to_vec(), move |_| {
            fs::write(change, b"changed content").unwrap();
        });
        assert!(scanner::scan(&request(&path), &socket).is_err());
        daemon.join().unwrap();
    }
    #[test]
    fn replacing_the_path_cannot_reuse_the_original_descriptors_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("sample");
        fs::write(&path, b"same bytes").unwrap();
        let change = path.clone();
        let socket = root.join("replace.sock");
        let daemon = daemon(&socket, b"stream: OK\0".to_vec(), move |_| {
            fs::rename(&change, change.with_extension("original")).unwrap();
            fs::write(change, b"same bytes").unwrap();
        });
        assert!(scanner::scan(&request(&path), &socket).is_err());
        daemon.join().unwrap();
    }
    #[test]
    fn symlinks_directories_and_relative_paths_are_not_scanner_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let file = root.join("file");
        fs::write(&file, b"data").unwrap();
        symlink(&file, root.join("alias")).unwrap();
        symlink(&root, root.join("parent")).unwrap();
        assert!(scanner::open_file(&root.join("alias")).is_err());
        assert!(scanner::open_file(&root.join("parent/file")).is_err());
        assert!(scanner::open_file(&root).is_err());
        assert!(scanner::open_file(Path::new("relative")).is_err());
    }
    #[test]
    fn expired_or_slow_scans_cannot_return_a_late_allow() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("sample");
        fs::write(&path, b"test").unwrap();
        let socket = root.join("slow.sock");
        let daemon = daemon(&socket, b"stream: OK\0".to_vec(), |_| {
            thread::sleep(Duration::from_millis(150))
        });
        let mut scan = request(&path);
        scan.deadline = Instant::now() + Duration::from_millis(40);
        assert!(scanner::scan(&scan, &socket).is_err());
        daemon.join().unwrap();
        assert!(scanner::scan(&scan, &socket).is_err());
    }
    #[test]
    fn mismatched_identity_and_file_budget_are_rejected_before_transport() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("sample");
        fs::write(&path, b"test").unwrap();
        let mut scan = request(&path);
        scan.identity.inode += 1;
        assert!(scanner::scan(&scan, &root.join("missing.sock"))
            .unwrap_err()
            .to_string()
            .contains("identity"));
        scan.identity.size = MAX_FILE + 1;
        assert!(scanner::scan(&scan, &root.join("missing.sock"))
            .unwrap_err()
            .to_string()
            .contains("128 MiB"));
    }
}

#[test]
fn approved_hashing_binds_the_exact_file_and_rejects_stale_identity() {
    use sha2::{Digest, Sha256};
    use std::{fs, time::Duration};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("sample");
    let bytes = vec![42u8; 200000];
    fs::write(&path, &bytes).unwrap();
    let request = Scan {
        path: path.clone(),
        identity: scanner::identity(&fs::metadata(&path).unwrap()),
        deadline: Instant::now() + Duration::from_secs(2),
    };
    let verdict = scanner::hash_bound(&request).unwrap();
    assert_eq!(verdict.sha256, format!("{:x}", Sha256::digest(&bytes)));
    assert_eq!(verdict.bytes, bytes.len() as u64);
    assert!(verdict.detection.is_none());
    fs::rename(&path, path.with_extension("old")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    assert!(scanner::hash_bound(&request).is_err());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(path.with_extension("old"), &path).unwrap();
    assert!(scanner::hash_bound(&request).is_err());
}
