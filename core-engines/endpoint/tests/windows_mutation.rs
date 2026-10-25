//! Actual Windows agent/worker, SQLite intent admission and immutable receipts.
//! A successful cross-build does not execute this native fixture.
#![cfg(windows)]
use athernex_endpoint::{now_ms, private_write, run_bounded, secret, Config, Process, Store};
use athernex_endpoint_native::mutation::{self, Intent, Operation, Verifier};
use athernex_endpoint_protocol::{hash, Action, Command, Receipt};
use rusqlite::{params, Connection};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

struct Fixture {
    _temp: Option<tempfile::TempDir>,
    agent: PathBuf,
    state: PathBuf,
    config: Config,
    events: Arc<Mutex<Vec<serde_json::Value>>>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = std::path::absolute(temp.path()).unwrap();
        let state = root.join("state");
        let watched = root.join("watched");
        let private =
            athernex_endpoint_native::windows_state::Directory::create_under(&root, "state")
                .unwrap();
        fs::create_dir(&watched).unwrap();
        // Use the actual private-directory primitive; fixture ACLs must not
        // depend on the runner shell's PowerShell module search path.
        drop(private);
        drop(Store::open(&state).unwrap());
        let config = Config {
            engine_updates: Default::default(),
            updates: Default::default(),
            protection: Default::default(),
            telemetry: Default::default(),
            server: "http://127.0.0.1:1/".into(),
            endpoint_id: "a".repeat(64),
            credential: "b".repeat(64),
            enrollment_token: None,
            scanner: root.join("missing-scanner.exe"),
            updater: root.join("missing-updater.exe"),
            scan_roots: vec![watched],
            allow_scripts: false,
            ca_file: None,
            signature_database: None,
            signature_config: None,
            maintenance: Default::default(),
        };
        Self {
            _temp: Some(temp),
            agent: env!("CARGO_BIN_EXE_athernex-endpoint").into(),
            state,
            config,
            events: Arc::new(Mutex::new(Vec::new())),
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
    fn connection(&self) -> Connection {
        Connection::open(self.state.join("endpoint.sqlite3")).unwrap()
    }
    fn execute(&self, command: &Command) -> Receipt {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut config = self.config.clone();
        config.server = format!("http://{}/", listener.local_addr().unwrap());
        private_write(
            &self.state.join("config.json"),
            &serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let pending = command.clone();
        let events = self.events.clone();
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
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let path = line.split_whitespace().nth(1).unwrap().to_owned();
                let mut length = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            length = v.trim().parse::<usize>().unwrap();
                        }
                    }
                }
                assert!(length <= 1024 * 1024);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let reply = if path.ends_with("/poll") {
                    serde_json::json!([pending])
                } else if path.ends_with("/start") {
                    serde_json::to_value(&pending).unwrap()
                } else if path.ends_with("/events") {
                    let batch: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
                    let count = batch.len();
                    events.lock().unwrap().extend(batch);
                    serde_json::json!({"durability":"committed","acknowledged":count})
                } else if path.ends_with("/receipt") {
                    serde_json::json!({"committed":true})
                } else if path.ends_with("/heartbeat") {
                    serde_json::json!({})
                } else {
                    panic!("Unexpected fixture request {path}")
                };
                let bytes = serde_json::to_vec(&reply).unwrap();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        let result = run_bounded(
            Process::new(&self.agent)
                .arg("run")
                .arg(&self.state)
                .arg("--once"),
            command.timeout_secs + 15,
        );
        stopped.store(true, Ordering::Relaxed);
        server.join().unwrap();
        let (code, output) = result.unwrap();
        assert_eq!(code, 0, "{output}");
        let raw: String = self
            .connection()
            .query_row("SELECT receipt FROM work WHERE id=?1", [&command.id], |r| {
                r.get(0)
            })
            .unwrap();
        serde_json::from_str(&raw).unwrap()
    }
    fn retained(&self, id: &str) -> PathBuf {
        self.state.join("quarantine").join(id)
    }
}

#[path = "windows_mutation/native.rs"]
mod native;

#[test]
fn actual_windows_worker_quarantines_restores_and_preserves_conflicts() {
    let f = Fixture::new();
    let path = f.config.scan_roots[0].join("sample.txt");
    let bytes = b"actual Windows worker fixture";
    fs::write(&path, bytes).unwrap();
    let mut writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let wrong = f.command(Action::Quarantine {
        path: path.display().to_string(),
        sha256: "0".repeat(64),
    });
    assert_eq!(f.execute(&wrong).outcome, "failed");
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let command = f.command(Action::Quarantine {
        path: path.display().to_string(),
        sha256: hash(bytes),
    });
    let receipt = f.execute(&command);
    assert_eq!(receipt.outcome, "succeeded", "{}", receipt.output);
    assert!(!path.exists());
    writer.write_all(b"changed after quarantine").unwrap();
    writer.sync_all().unwrap();
    drop(writer);
    assert_eq!(fs::read(f.retained(&command.id)).unwrap(), bytes);
    fs::write(&path, b"unrelated destination").unwrap();
    let conflict = f.command(Action::Restore {
        quarantine_id: command.id.clone(),
    });
    assert_eq!(f.execute(&conflict).outcome, "failed");
    assert_eq!(fs::read(&path).unwrap(), b"unrelated destination");
    assert_eq!(fs::read(f.retained(&command.id)).unwrap(), bytes);
    fs::remove_file(&path).unwrap();
    let restore = f.command(Action::Restore {
        quarantine_id: command.id.clone(),
    });
    let receipt = f.execute(&restore);
    assert_eq!(receipt.outcome, "succeeded", "{}", receipt.output);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(!f.retained(&command.id).exists());
    for id in [&command.id, &restore.id] {
        let phase: String = f
            .connection()
            .query_row(
                "SELECT state FROM native_mutations WHERE command_id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(phase, "finished");
        let record: serde_json::Value = serde_json::from_slice(
            &fs::read(
                f.state
                    .join("quarantine/operations")
                    .join(format!("{id}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(record["record"]["phase"], "complete");
    }
}

#[test]
fn actual_windows_recovery_adopts_committed_work_without_replay_or_rewriting_receipts() {
    for acknowledged in [false, true] {
        let f = Fixture::new();
        let path = f.config.scan_roots[0].join("recover.txt");
        let bytes = b"committed before acknowledgement";
        fs::write(&path, bytes).unwrap();
        let command = f.command(Action::Quarantine {
            path: path.display().to_string(),
            sha256: hash(bytes),
        });
        let intent = Intent {
            verifier: Some(Verifier::Local),
            schema: 1,
            command_id: command.id.clone(),
            quarantine_id: command.id.clone(),
            operation: Operation::Quarantine,
            state: f.state.canonicalize().unwrap(),
            path: Path::new(&path).into(),
            roots: f.config.scan_roots.clone(),
            sha256: hash(bytes),
        };
        let store = Store::open(&f.state).unwrap();
        assert!(store.claim(&command).unwrap());
        store
            .connection
            .execute(
                "INSERT INTO quarantine VALUES(?1,?2,?3,'preparing')",
                params![command.id, path.to_str().unwrap(), hash(bytes)],
            )
            .unwrap();
        store.connection.execute("INSERT INTO native_mutations(command_id,quarantine_id,intent,state) VALUES(?1,?1,?2,'pending')",params![command.id,serde_json::to_string(&intent).unwrap()]).unwrap();
        let prior = Receipt {
            command_id: command.id.clone(),
            action_hash: command.action_hash.clone(),
            outcome: "failed".into(),
            output: "Worker acknowledgement was lost".into(),
            finished_ms: now_ms(),
        };
        if acknowledged {
            store.save_receipt(&prior).unwrap();
        }
        drop(store);
        // Inject the filesystem/SQLite acknowledgement boundary. Subsequent
        // recovery executes through the actual endpoint's owned worker.
        mutation::apply(&intent, false, Duration::from_secs(10)).unwrap();
        fs::write(&path, b"replacement must remain untouched").unwrap();
        let recovered = f.execute(&command);
        assert_eq!(
            recovered.outcome,
            if acknowledged { "failed" } else { "succeeded" }
        );
        if acknowledged {
            assert_eq!(
                serde_json::to_value(&recovered).unwrap(),
                serde_json::to_value(&prior).unwrap()
            );
        }
        assert_eq!(
            fs::read(&path).unwrap(),
            b"replacement must remain untouched"
        );
        assert_eq!(fs::read(f.retained(&command.id)).unwrap(), bytes);
        assert_eq!(
            f.connection()
                .query_row(
                    "SELECT state FROM quarantine WHERE id=?1",
                    [&command.id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "quarantined"
        );
        if acknowledged {
            assert!(f.events.lock().unwrap().iter().any(|v| {
                v["detail"]
                    .as_str()
                    .is_some_and(|s| s.contains("native_mutation_recovery"))
            }));
        }
    }
}
