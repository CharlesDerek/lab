//! Real endpoint subprocess, durable command receipts and native broker transport.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use athernex_endpoint::{now_ms, private_write, secret, Config, Store};
use athernex_endpoint_native::{broker::Broker, Policy};
use athernex_endpoint_protocol::EndpointEvent;
use athernex_endpoint_protocol::{hash, Action, Command};
use std::{fs, time::Duration};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        net::UnixListener,
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

struct TestState {
    directory: std::path::PathBuf,
    connection: rusqlite::Connection,
}
struct Fixture {
    _temp: tempfile::TempDir,
    store: TestState,
    config: Config,
    received: Arc<Mutex<Vec<serde_json::Value>>>,
    broker: Option<Broker>,
    stopped: Arc<AtomicBool>,
    stall_after_first: Arc<AtomicBool>,
    daemon: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn portable() -> Self {
        let mut fixture = Self::new(false);
        drop(fixture.broker.take());
        fs::remove_file(
            fixture
                .store
                .directory
                .join("protection/native/response.json"),
        )
        .unwrap();
        fixture
    }
    fn new(fail_after_first: bool) -> Self {
        // macOS's per-user temporary directory can exceed sockaddr_un's path
        // budget after adding the private state and response socket suffixes.
        let temp = tempfile::Builder::new()
            .prefix("ax-response-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(&root.join("state")).unwrap();
        let native = store.directory.join("protection/native");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&native)
            .unwrap();
        let watched = root.join("watched");
        fs::create_dir(&watched).unwrap();
        let socket = root.join("clamd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let stall_after_first = Arc::new(AtomicBool::new(false));
        let stall = stall_after_first.clone();
        let daemon = thread::spawn(move || {
            let mut count = 0;
            while !stop.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut header = [0; 10];
                stream.read_exact(&mut header).unwrap();
                assert_eq!(&header, b"zINSTREAM\0");
                let mut bytes = Vec::new();
                loop {
                    let mut size = [0; 4];
                    stream.read_exact(&mut size).unwrap();
                    let size = u32::from_be_bytes(size) as usize;
                    if size == 0 {
                        break;
                    }
                    let mut part = vec![0; size];
                    stream.read_exact(&mut part).unwrap();
                    bytes.extend(part);
                }
                count += 1;
                if count > 1 && stall.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                let verdict: &[u8] = if fail_after_first && count > 1 {
                    b"stream: fixture failure ERROR\0"
                } else if bytes.starts_with(b"detected") {
                    b"stream: PublicFixture FOUND\0"
                } else {
                    b"stream: OK\0"
                };
                stream.write_all(verdict).unwrap();
            }
        });
        let policy = Policy {
            roots: vec![watched.clone()],
            socket,
            state: native,
            scanner_uid: 1234,
            scan_timeout_ms: 1000,
        };
        let broker = Broker::start(policy, Arc::new(AtomicBool::new(true))).unwrap();
        let config = Config {
            engine_updates: Default::default(),
            updates: Default::default(),
            protection: Default::default(),
            telemetry: Default::default(),
            server: "http://127.0.0.1:1/".into(),
            endpoint_id: "a".repeat(64),
            credential: "b".repeat(64),
            enrollment_token: None,
            scanner: root.join("missing-scanner"),
            updater: root.join("missing-updater"),
            scan_roots: vec![watched],
            allow_scripts: false,
            ca_file: None,
            signature_database: None,
            signature_config: None,
            maintenance: Default::default(),
        };
        let directory = store.directory.clone();
        drop(store);
        let store = TestState {
            connection: rusqlite::Connection::open(directory.join("endpoint.sqlite3")).unwrap(),
            directory,
        };
        Self {
            _temp: temp,
            store,
            config,
            received: Arc::new(Mutex::new(Vec::new())),
            broker: Some(broker),
            stopped,
            stall_after_first,
            daemon: Some(daemon),
        }
    }
    fn execute(&self, command: &Command) -> Result<String, String> {
        self.execute_expect(command, 0)
    }
    fn execute_expect(&self, command: &Command, expected_exit: i32) -> Result<String, String> {
        use std::{
            io::{BufRead, BufReader},
            net::TcpListener,
            process::Command as Process,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut config = self.config.clone();
        config.server = format!("http://{}/", listener.local_addr().unwrap());
        private_write(
            &self.store.directory.join("config.json"),
            &serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let pending = command.clone();
        let received = self.received.clone();
        let server = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let path = line.split_whitespace().nth(1).unwrap().to_string();
                let mut size = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            size = v.trim().parse::<usize>().unwrap();
                        }
                    }
                }
                assert!(size <= 1024 * 1024);
                let mut body = vec![0; size];
                reader.read_exact(&mut body).unwrap();
                let reply = if path.ends_with("/poll") {
                    serde_json::json!([pending])
                } else if path.ends_with("/start") {
                    serde_json::to_value(&pending).unwrap()
                } else if path.ends_with("/events") {
                    let events: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
                    let count = events.len();
                    received.lock().unwrap().extend(events);
                    serde_json::json!({"durability":"committed","acknowledged":count})
                } else if path.ends_with("/receipt") {
                    serde_json::json!({"committed":true})
                } else if path.ends_with("/heartbeat") {
                    serde_json::json!({})
                } else {
                    panic!("Unexpected request {path}")
                };
                let bytes = serde_json::to_vec(&reply).unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        let result = athernex_endpoint_native::child::run(
            Process::new(env!("CARGO_BIN_EXE_athernex-endpoint"))
                .arg("run")
                .arg(&self.store.directory)
                .arg("--once"),
            Duration::from_secs(20),
            65536,
        );
        done.store(true, Ordering::Relaxed);
        server.join().unwrap();
        let (code, output) = result.unwrap();
        assert_eq!(code, expected_exit, "{}", String::from_utf8_lossy(&output));
        if expected_exit != 0 {
            return Ok(String::new());
        }
        let raw: String = self
            .store
            .connection
            .query_row("SELECT receipt FROM work WHERE id=?1", [&command.id], |r| {
                r.get(0)
            })
            .unwrap();
        let receipt: athernex_endpoint_protocol::Receipt = serde_json::from_str(&raw).unwrap();
        if receipt.outcome == "succeeded" {
            Ok(receipt.output)
        } else {
            Err(receipt.output)
        }
    }
    fn command(&self, action: Action) -> Command {
        Command {
            id: secret().unwrap(),
            endpoint_id: self.config.endpoint_id.clone(),
            action_hash: hash(&serde_json::to_vec(&action).unwrap()),
            action,
            case_id: 1,
            created_ms: now_ms(),
            expires_ms: now_ms() + 60000,
            timeout_secs: 10,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.broker.take());
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(daemon) = self.daemon.take() {
            daemon.join().unwrap();
        }
    }
}

#[test]
fn approved_scan_and_hash_bound_quarantine_use_the_broker() {
    let mut f = Fixture::new(false);
    let watched = &f.config.scan_roots[0];
    let sample = watched.join("sample");
    let clean = watched.join("clean");
    fs::write(&sample, b"detected public fixture").unwrap();
    fs::write(&clean, b"ordinary text").unwrap();
    let command = f.command(Action::Scan {
        path: watched.display().to_string(),
    });
    let result = f.execute(&command).unwrap();
    let result: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["files"], 2);
    assert_eq!(result["detections"], 1);
    let raw: String = f
        .store
        .connection
        .query_row(
            "SELECT payload FROM outbox WHERE json_extract(payload,'$.kind')='malware'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let event: EndpointEvent = serde_json::from_str(&raw).unwrap();
    assert_eq!(event.sha256, hash(b"detected public fixture"));
    let stale = f.command(Action::Quarantine {
        path: sample.display().to_string(),
        sha256: hash(b"old bytes"),
    });
    assert!(f.execute(&stale).is_err());
    assert!(sample.exists());
    let command = f.command(Action::Quarantine {
        path: sample.display().to_string(),
        sha256: event.sha256,
    });
    f.execute(&command).unwrap();
    assert!(!sample.exists());
    assert_eq!(
        fs::read(f.store.directory.join("quarantine").join(&command.id)).unwrap(),
        b"detected public fixture"
    );
    drop(f.broker.take());
    let command = f.command(Action::Quarantine {
        path: clean.display().to_string(),
        sha256: hash(b"ordinary text"),
    });
    assert!(
        f.execute(&command).is_err(),
        "A persistent binding must prohibit direct-read fallback after broker death"
    );
    assert!(clean.exists());
}

#[test]
fn native_scan_failure_never_commits_partial_detections() {
    let f = Fixture::new(true);
    let watched = &f.config.scan_roots[0];
    fs::write(watched.join("one"), b"detected one").unwrap();
    fs::write(watched.join("two"), b"detected two").unwrap();
    let command = f.command(Action::Scan {
        path: watched.display().to_string(),
    });
    assert!(f.execute(&command).is_err());
    assert_eq!(
        f.store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn timed_out_native_scan_discards_the_earlier_detection() {
    let f = Fixture::new(false);
    let watched = &f.config.scan_roots[0];
    fs::write(watched.join("one"), b"detected one").unwrap();
    fs::write(watched.join("two"), b"detected two").unwrap();
    f.stall_after_first.store(true, Ordering::Relaxed);
    let mut command = f.command(Action::Scan {
        path: watched.display().to_string(),
    });
    command.timeout_secs = 1;
    let start = std::time::Instant::now();
    let error = f.execute(&command).unwrap_err();
    assert!(
        error.contains("time budget") || error.contains("deadline") || error.contains("timed out"),
        "{error}"
    );
    assert!(start.elapsed() < Duration::from_millis(1800));
    assert_eq!(
        f.store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn actual_worker_enforces_local_scope_and_skips_special_files() {
    let f = Fixture::new(false);
    let watched = &f.config.scan_roots[0];
    let outside = f._temp.path().join("outside");
    fs::write(&outside, b"ordinary outside").unwrap();
    let command = f.command(Action::Scan {
        path: outside.display().to_string(),
    });
    assert!(f
        .execute(&command)
        .unwrap_err()
        .contains("outside the current local action roots"));
    let link = watched.join("link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let command = f.command(Action::Scan {
        path: link.display().to_string(),
    });
    assert!(f.execute(&command).unwrap_err().contains("target symlink"));
    let fifo = std::ffi::CString::new(watched.join("fifo").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    fs::write(watched.join("clean"), b"ordinary").unwrap();
    let command = f.command(Action::Scan {
        path: watched.display().to_string(),
    });
    let summary: serde_json::Value = serde_json::from_str(&f.execute(&command).unwrap()).unwrap();
    assert_eq!(summary["files"], 1);
    assert_eq!(summary["skipped_special"], 2);
}

#[test]
fn native_restore_publishes_complete_bytes_and_never_overwrites_a_conflict() {
    let mut f = Fixture::new(false);
    let path = f.config.scan_roots[0].join("sample");
    fs::write(&path, b"detected restore fixture").unwrap();
    let q = f.command(Action::Quarantine {
        path: path.display().to_string(),
        sha256: hash(b"detected restore fixture"),
    });
    f.execute(&q).unwrap();
    drop(f.broker.take());
    fs::remove_file(f.store.directory.join("protection/native/response.json")).unwrap();
    fs::write(&path, b"unrelated").unwrap();
    let refused = f.command(Action::Restore {
        quarantine_id: q.id.clone(),
    });
    assert!(f.execute(&refused).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"unrelated");
    assert_eq!(
        fs::read(f.store.directory.join("quarantine").join(&q.id)).unwrap(),
        b"detected restore fixture"
    );
    fs::remove_file(&path).unwrap();
    let restore = f.command(Action::Restore {
        quarantine_id: q.id.clone(),
    });
    f.execute(&restore).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"detected restore fixture");
    assert!(!f.store.directory.join("quarantine").join(&q.id).exists());
    let state: String = f
        .store
        .connection
        .query_row("SELECT state FROM quarantine WHERE id=?1", [&q.id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(state, "restored");
}

#[test]
fn completed_worker_without_parent_admission_recovers_and_preserves_existing_receipts() {
    use athernex_endpoint_native::mutation::{Intent, Operation, Verifier};
    for (local, acknowledged_failure) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        let f = if local {
            Fixture::portable()
        } else {
            Fixture::new(false)
        };
        let path = f.config.scan_roots[0].join("sample");
        fs::write(&path, b"detected recovery fixture").unwrap();
        let command = f.command(Action::Quarantine {
            path: path.display().to_string(),
            sha256: hash(b"detected recovery fixture"),
        });
        let intent = Intent {
            verifier: local.then_some(Verifier::Local),
            schema: 1,
            command_id: command.id.clone(),
            quarantine_id: command.id.clone(),
            operation: Operation::Quarantine,
            state: f.store.directory.clone(),
            path: path.clone(),
            roots: f.config.scan_roots.clone(),
            sha256: hash(b"detected recovery fixture"),
        };
        let failed = athernex_endpoint_protocol::Receipt {
            command_id: command.id.clone(),
            action_hash: command.action_hash.clone(),
            outcome: "failed".into(),
            output: "worker deadline elapsed before acknowledgement".into(),
            finished_ms: now_ms(),
        };
        let prior = acknowledged_failure.then(|| serde_json::to_string(&failed).unwrap());
        f.store
            .connection
            .execute(
                "INSERT INTO work(id,payload,receipt,acknowledged) VALUES(?1,?2,?3,?4)",
                rusqlite::params![
                    command.id,
                    serde_json::to_string(&command).unwrap(),
                    prior,
                    acknowledged_failure
                ],
            )
            .unwrap();
        f.store
            .connection
            .execute(
                "INSERT INTO quarantine VALUES(?1,?2,?3,'preparing')",
                rusqlite::params![command.id, path.to_str().unwrap(), intent.sha256],
            )
            .unwrap();
        f.store.connection.execute("INSERT INTO native_mutations(command_id,quarantine_id,intent,state) VALUES(?1,?1,?2,'pending')",rusqlite::params![command.id,serde_json::to_string(&intent).unwrap()]).unwrap();
        let input=serde_json::to_vec(&serde_json::json!({"nonce":"d".repeat(64),"intent":intent,"recover":false,"timeout_secs":5})).unwrap();
        let (code, output) = athernex_endpoint_native::child::run_with_input(
            std::process::Command::new(env!("CARGO_BIN_EXE_athernex-endpoint"))
                .arg("native-mutation-worker")
                .arg(std::process::id().to_string()),
            Duration::from_secs(5),
            65536,
            &input,
        )
        .unwrap();
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&output));
        // Intentionally discard the completed worker response. The next real
        // agent process must recover from its durable files and pending intent.
        f.execute(&f.command(Action::Inventory)).unwrap();
        let state: String = f
            .store
            .connection
            .query_row(
                "SELECT state FROM quarantine WHERE id=?1",
                [&command.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "quarantined");
        let raw: String = f
            .store
            .connection
            .query_row("SELECT receipt FROM work WHERE id=?1", [&command.id], |r| {
                r.get(0)
            })
            .unwrap();
        let receipt: athernex_endpoint_protocol::Receipt = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            receipt.outcome,
            if acknowledged_failure {
                "failed"
            } else {
                "succeeded"
            }
        );
        if acknowledged_failure {
            assert_eq!(raw, serde_json::to_string(&failed).unwrap());
            assert!(f
                .received
                .lock()
                .unwrap()
                .iter()
                .any(|e| e["kind"] == "agent_error"
                    && e["detail"].as_str().unwrap().contains(&command.id)));
        }
    }
}

#[test]
fn portable_quarantine_and_restore_use_verified_independent_bytes_and_journals() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::portable();
    let path = f.config.scan_roots[0].join("portable-sample");
    let contents = b"approved portable fixture";
    fs::write(&path, contents).unwrap();
    let mut old_writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let old_inode = old_writer.metadata().unwrap().ino();
    let rejected = f.command(Action::Quarantine {
        path: path.display().to_string(),
        sha256: "0".repeat(64),
    });
    assert!(f
        .execute(&rejected)
        .unwrap_err()
        .contains("changed since approval"));
    assert_eq!(fs::read(&path).unwrap(), contents);
    let q = f.command(Action::Quarantine {
        path: path.display().to_string(),
        sha256: hash(contents),
    });
    f.execute(&q).unwrap();
    assert!(!path.exists());
    let retained = f.store.directory.join("quarantine").join(&q.id);
    assert_ne!(fs::metadata(&retained).unwrap().ino(), old_inode);
    old_writer.write_all(b"changed through old handle").unwrap();
    old_writer.sync_all().unwrap();
    assert_eq!(fs::read(&retained).unwrap(), contents);
    let raw: String = f
        .store
        .connection
        .query_row(
            "SELECT intent FROM native_mutations WHERE command_id=?1 AND state='finished'",
            [&q.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw).unwrap()["verifier"]["kind"],
        "local"
    );
    fs::write(&path, b"unrelated destination").unwrap();
    assert!(f
        .execute(&f.command(Action::Restore {
            quarantine_id: q.id.clone()
        }))
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), b"unrelated destination");
    assert_eq!(fs::read(&retained).unwrap(), contents);
    fs::remove_file(&path).unwrap();
    let restore = f.command(Action::Restore {
        quarantine_id: q.id.clone(),
    });
    f.execute(&restore).unwrap();
    assert_eq!(fs::read(&path).unwrap(), contents);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert!(!retained.exists());
    for id in [&q.id, &restore.id] {
        let journal: serde_json::Value = serde_json::from_slice(
            &fs::read(
                f.store
                    .directory
                    .join("quarantine/operations")
                    .join(format!("{id}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(journal["record"]["phase"], "complete");
    }
}

#[test]
fn portable_restore_adopts_legacy_quarantine_without_an_original_operation_journal() {
    let f = Fixture::portable();
    let path = f.config.scan_roots[0].join("legacy-sample");
    let contents = b"legacy retained fixture";
    let id = secret().unwrap();
    let retained = f.store.directory.join("quarantine").join(&id);
    private_write(&retained, contents).unwrap();
    f.store
        .connection
        .execute(
            "INSERT INTO quarantine VALUES(?1,?2,?3,'quarantined')",
            rusqlite::params![id, path.to_str().unwrap(), hash(contents)],
        )
        .unwrap();
    let restore = f.command(Action::Restore {
        quarantine_id: id.clone(),
    });
    f.execute(&restore).unwrap();
    assert_eq!(fs::read(&path).unwrap(), contents);
    assert!(!retained.exists());
    let state: String = f
        .store
        .connection
        .query_row("SELECT state FROM quarantine WHERE id=?1", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(state, "restored");
}

#[test]
fn portable_worker_refuses_out_of_scope_and_symlink_sources_before_capture() {
    let f = Fixture::portable();
    let outside = f._temp.path().join("outside");
    let bytes = b"must remain in place";
    fs::write(&outside, bytes).unwrap();
    let link = f.config.scan_roots[0].join("link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    for path in [&outside, &link] {
        let command = f.command(Action::Quarantine {
            path: path.display().to_string(),
            sha256: hash(bytes),
        });
        assert!(f.execute(&command).is_err());
        assert_eq!(fs::read(&outside).unwrap(), bytes);
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!f
            .store
            .directory
            .join("quarantine")
            .join(&command.id)
            .exists());
    }
}

fn wait_for_fixture_exit(pid: u32) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if unsafe { libc::kill(pid as i32, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Fixture process {pid} remained alive"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn approved_automation_cleans_background_children_before_receipt() {
    let mut f = Fixture::portable();
    f.config.allow_scripts = true;
    let script = "sleep 30 & printf '%s\\n' \"$!\"".to_string();
    let command = f.command(Action::Script {
        interpreter: "sh".into(),
        sha256: hash(script.as_bytes()),
        script,
    });
    let output = f.execute(&command).unwrap();
    let pid: u32 = output.trim().parse().unwrap();
    wait_for_fixture_exit(pid);
}

#[test]
fn agent_death_stops_automation_and_descendants_without_replaying_the_script() {
    let mut f = Fixture::portable();
    f.config.allow_scripts = true;
    let marker = f.config.scan_roots[0].join("automation-pids");
    let launches = f.config.scan_roots[0].join("automation-launches");
    let quote = |p: &std::path::Path| format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"));
    let script = format!("printf 'started\\n' >> {}; trap '' TERM; sleep 30 & printf '%s %s %s\\n' \"$PPID\" \"$$\" \"$!\" > {}; wait",quote(&launches),quote(&marker));
    let command = f.command(Action::Script {
        interpreter: "sh".into(),
        sha256: hash(script.as_bytes()),
        script,
    });
    let killer = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(raw) = fs::read_to_string(&marker) {
                let pids: Vec<u32> = raw.split_whitespace().map(|p| p.parse().unwrap()).collect();
                if pids.len() == 3 {
                    assert!(pids.iter().all(|p| *p > 1));
                    assert_eq!(unsafe { libc::getpgid(pids[0] as i32) }, pids[0] as i32);
                    assert_eq!(unsafe { libc::getpgid(pids[1] as i32) }, pids[1] as i32);
                    assert_eq!(unsafe { libc::getpgid(pids[2] as i32) }, pids[1] as i32);
                    assert_eq!(unsafe { libc::kill(pids[0] as i32, libc::SIGKILL) }, 0);
                    return pids;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "Automation did not start"
            );
            thread::sleep(Duration::from_millis(10));
        }
    });
    f.execute_expect(&command, -1).unwrap();
    for pid in killer.join().unwrap() {
        wait_for_fixture_exit(pid);
    }
    f.execute(&f.command(Action::Inventory)).unwrap();
    let raw: String = f
        .store
        .connection
        .query_row("SELECT receipt FROM work WHERE id=?1", [&command.id], |r| {
            r.get(0)
        })
        .unwrap();
    let receipt: athernex_endpoint_protocol::Receipt = serde_json::from_str(&raw).unwrap();
    assert_eq!(receipt.outcome, "interrupted");
    assert_eq!(fs::read_to_string(launches).unwrap(), "started\n");
}
