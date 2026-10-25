use super::*;
use sha2::{Digest, Sha256};

struct Fixture {
    _temp: tempfile::TempDir,
    policy: Policy,
    file: PathBuf,
    scope: Arc<AtomicBool>,
    broker: Option<Broker>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("native");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let watched = root.join("watched");
        fs::create_dir(&watched).unwrap();
        let file = watched.join("sample");
        fs::write(&file, b"public fixture").unwrap();
        let policy = Policy {
            roots: vec![watched],
            socket: root.join("clamd.sock"),
            state,
            scanner_uid: 1234,
            scan_timeout_ms: 1000,
        };
        let scope = Arc::new(AtomicBool::new(true));
        let broker = Broker::start(policy.clone(), scope.clone()).unwrap();
        Self {
            _temp: temp,
            policy,
            file,
            scope,
            broker: Some(broker),
        }
    }
    fn daemon(&self, response: &'static [u8], delay: Duration) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(&self.policy.socket).unwrap();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut header = [0; 10];
            socket.read_exact(&mut header).unwrap();
            assert_eq!(&header, b"zINSTREAM\0");
            let mut bytes = Vec::new();
            loop {
                let mut count = [0; 4];
                socket.read_exact(&mut count).unwrap();
                let count = u32::from_be_bytes(count) as usize;
                if count == 0 {
                    break;
                }
                let mut part = vec![0; count];
                socket.read_exact(&mut part).unwrap();
                bytes.extend(part);
            }
            assert_eq!(&bytes, b"public fixture");
            thread::sleep(delay);
            let _ = socket.write_all(response);
        })
    }
}

#[test]
fn private_broker_returns_exact_verified_bytes_and_preserves_malware_verdict() {
    let f = Fixture::new();
    let daemon = f.daemon(b"stream: PublicFixture FOUND\0", Duration::ZERO);
    let verdict = query(&f.policy.state, &f.file, Duration::from_secs(2)).unwrap();
    daemon.join().unwrap();
    assert_eq!(
        verdict.sha256,
        format!("{:x}", Sha256::digest(b"public fixture"))
    );
    assert_eq!(verdict.detection.as_deref(), Some("PublicFixture"));
    assert_eq!(verdict.bytes, 14);
    assert!(Broker::start(f.policy.clone(), f.scope.clone()).is_err());
    assert_eq!(
        fs::metadata(f.policy.state.join(SOCKET)).unwrap().mode() & 0o777,
        0o600
    );
}

#[test]
fn unavailable_or_changed_scope_cannot_return_a_hash() {
    let mut f = Fixture::new();
    let outside = f.policy.state.join("outside");
    fs::write(&outside, b"outside").unwrap();
    assert!(query(&f.policy.state, &outside, Duration::from_secs(1))
        .unwrap_err()
        .to_string()
        .contains("scope"));
    f.scope.store(false, Ordering::Relaxed);
    assert!(query(&f.policy.state, &f.file, Duration::from_secs(1))
        .unwrap_err()
        .to_string()
        .contains("scope"));
    f.scope.store(true, Ordering::Relaxed);
    fs::rename(&f.policy.roots[0], f.policy.state.join("old-root")).unwrap();
    fs::create_dir(&f.policy.roots[0]).unwrap();
    fs::write(&f.file, b"public fixture").unwrap();
    assert!(query(&f.policy.state, &f.file, Duration::from_secs(1))
        .unwrap_err()
        .to_string()
        .contains("scope"));
    drop(f.broker.take());
    assert!(configured(&f.policy.state).unwrap());
    assert!(query(&f.policy.state, &f.file, Duration::from_secs(1)).is_err());
}

#[test]
fn broker_deadline_and_invalid_verdict_never_yield_authoritative_hashes() {
    let f = Fixture::new();
    let daemon = f.daemon(b"stream: OK\0", Duration::from_millis(250));
    let start = Instant::now();
    assert!(query(&f.policy.state, &f.file, Duration::from_millis(60)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    daemon.join().unwrap();
    fs::remove_file(&f.policy.socket).unwrap();
    let daemon = f.daemon(b"stream: broken\0", Duration::ZERO);
    assert!(query(&f.policy.state, &f.file, Duration::from_secs(2)).is_err());
    daemon.join().unwrap();
}

#[test]
fn broker_rejects_wrong_policy_and_bad_frames_then_recovers() {
    let f = Fixture::new();
    let mut stream = UnixStream::connect(f.policy.state.join(SOCKET)).unwrap();
    stream
        .write_all(&((FRAME + 1) as u32).to_be_bytes())
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut byte = [0];
    assert!(stream.read(&mut byte).is_ok_and(|n| n == 0));
    let mut stream = UnixStream::connect(f.policy.state.join(SOCKET)).unwrap();
    let request = Request {
        schema: 1,
        nonce: "a".repeat(64),
        policy_sha256: "b".repeat(64),
        path: f.file.clone(),
        max_bytes: MAX_FILE,
        timeout_ms: 1000,
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    write_frame(&mut stream, &request, deadline).unwrap();
    let response: Reply = read_frame(&mut stream, deadline).unwrap();
    assert!(response.verdict.is_none());
    assert!(response.error.contains("scope"));
    let daemon = f.daemon(b"stream: OK\0", Duration::ZERO);
    assert!(query(&f.policy.state, &f.file, Duration::from_secs(2))
        .unwrap()
        .detection
        .is_none());
    daemon.join().unwrap();
}

#[test]
fn response_client_refuses_symlink_and_shared_binding() {
    let f = Fixture::new();
    let binding = f.policy.state.join(BINDING);
    fs::set_permissions(&binding, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(configured(&f.policy.state).is_err());
    fs::set_permissions(&binding, fs::Permissions::from_mode(0o600)).unwrap();
    let original = f.policy.state.join("original");
    fs::rename(&binding, &original).unwrap();
    std::os::unix::fs::symlink(original, &binding).unwrap();
    assert!(configured(&f.policy.state).is_err());
}

#[test]
fn response_client_rejects_cross_request_and_invalid_success_replies() {
    for variant in 0..3 {
        let mut f = Fixture::new();
        drop(f.broker.take());
        let socket = f.policy.state.join(SOCKET);
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let request: Request = read_frame(&mut stream, deadline).unwrap();
            let mut reply = Reply {
                schema: 1,
                nonce: request.nonce,
                policy_sha256: request.policy_sha256,
                verdict: Some(Verdict {
                    sha256: "a".repeat(64),
                    detection: None,
                    bytes: 14,
                }),
                error: String::new(),
            };
            match variant {
                0 => reply.nonce = "b".repeat(64),
                1 => reply.policy_sha256 = "b".repeat(64),
                _ => reply.error = "contradictory failure".into(),
            };
            write_frame(&mut stream, &reply, deadline).unwrap();
        });
        assert!(query(&f.policy.state, &f.file, Duration::from_secs(2)).is_err());
        server.join().unwrap();
    }
}
