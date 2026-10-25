use super::*;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

fn bootstrap(server: &str) -> Bootstrap {
    Bootstrap {
        protocol: PROTOCOL,
        server: server.into(),
        enrollment_token: "a".repeat(64),
        platform: Platform::current(),
        antivirus: vec![],
    }
}
fn state(temp: &tempfile::TempDir) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        athernex_endpoint_native::windows_state::Directory::maintenance_under(
            &std::path::absolute(temp.path()).unwrap(),
            "state",
        )
        .unwrap()
        .path()
        .into()
    }
    #[cfg(not(windows))]
    temp.path().join("state")
}
#[test]
fn enrollment_retry_preserves_identity_and_token_until_server_acceptance() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let bootstrap = bootstrap(&format!("http://{}/", listener.local_addr().unwrap()));
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut requests = Vec::new();
        for status in ["500 Internal Server Error", "200 OK"] {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "Enrollment request never arrived"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 2048];
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
                assert!(request.len() <= 65536);
                if let Some(end) = request.windows(4).position(|b| b == b"\r\n\r\n") {
                    let header = std::str::from_utf8(&request[..end]).unwrap();
                    assert!(header.starts_with("POST /api/endpoint/enroll HTTP/1.1\r\n"));
                    let length = header
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        requests.push(
                            serde_json::from_slice::<protocol::Enrollment>(
                                &request[end + 4..end + 4 + length],
                            )
                            .unwrap(),
                        );
                        break;
                    }
                }
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
        requests
    });
    let temp = tempfile::tempdir().unwrap();
    let directory = state(&temp);
    let store = open_store(&directory).unwrap();
    assert!(enroll(&bootstrap, &store).is_err());
    let pending = configuration(&bootstrap, &directory).unwrap();
    assert_eq!(
        pending.enrollment_token.as_deref(),
        Some(bootstrap.enrollment_token.as_str())
    );
    let enrolled = enroll(&bootstrap, &store).unwrap();
    assert_eq!(enrolled.endpoint_id, pending.endpoint_id);
    assert_eq!(enrolled.credential, pending.credential);
    assert!(enrolled.enrollment_token.is_none());
    assert!(
        Store::open(&directory).is_err(),
        "Shared setup must retain the caller's state lease"
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.endpoint_id, enrolled.endpoint_id);
        assert_eq!(request.credential, enrolled.credential);
        assert_eq!(request.enrollment_token, bootstrap.enrollment_token);
    }
    // A repeated completed setup performs no enrollment request and preserves
    // local policy, even if the supplied bundle has a fresh enrollment token.
    let mut next = bootstrap.clone();
    next.enrollment_token = "b".repeat(64);
    assert_eq!(
        enroll(&next, &store).unwrap().endpoint_id,
        enrolled.endpoint_id
    );
}
#[test]
fn setup_refuses_foreign_origin_and_corrupt_config_without_overwriting_identity() {
    let temp = tempfile::tempdir().unwrap();
    let directory = state(&temp);
    let _store = Store::open(&directory).unwrap();
    let mut bootstrap = bootstrap("https://example.com/");
    let config = configuration(&bootstrap, &directory).unwrap();
    save(&directory, &config).unwrap();
    let before = fs::read(directory.join("config.json")).unwrap();
    bootstrap.server = "https://different.example.com/".into();
    assert!(configuration(&bootstrap, &directory).is_err());
    assert!(provision(&bootstrap, &directory).is_err());
    assert_eq!(fs::read(directory.join("config.json")).unwrap(), before);
    fs::write(directory.join("config.json"), b"incomplete").unwrap();
    assert!(configuration(&bootstrap, &directory).is_err());
    assert_eq!(
        fs::read(directory.join("config.json")).unwrap(),
        b"incomplete"
    );
}
