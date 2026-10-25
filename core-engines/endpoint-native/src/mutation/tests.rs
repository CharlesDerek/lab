use super::*;
use crate::{broker::Broker, Policy};
use std::{
    fs as stdfs,
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        net::UnixListener,
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};
struct Fixture {
    _temp: tempfile::TempDir,
    intent: Intent,
    broker: Option<Broker>,
    stop: Arc<AtomicBool>,
    daemon: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        stdfs::set_permissions(&root, stdfs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("state");
        let native = state.join("protection/native");
        stdfs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&native)
            .unwrap();
        let watched = root.join("watched");
        stdfs::create_dir(&watched).unwrap();
        let path = watched.join("sample");
        stdfs::write(&path, b"approved contents").unwrap();
        let socket = root.join("clamd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let daemon = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
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
                loop {
                    let mut size = [0; 4];
                    stream.read_exact(&mut size).unwrap();
                    let n = u32::from_be_bytes(size) as usize;
                    if n == 0 {
                        break;
                    }
                    let mut bytes = vec![0; n];
                    stream.read_exact(&mut bytes).unwrap();
                }
                stream.write_all(b"stream: PublicFixture FOUND\0").unwrap();
            }
        });
        let broker = Broker::start(
            Policy {
                roots: vec![watched.clone()],
                socket,
                state: native,
                scanner_uid: 1234,
                scan_timeout_ms: 1000,
            },
            Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
        let intent = Intent {
            verifier: None,
            schema: 1,
            command_id: "a".repeat(64),
            quarantine_id: "a".repeat(64),
            operation: Operation::Quarantine,
            state,
            path,
            roots: vec![watched],
            sha256: format!("{:x}", Sha256::digest(b"approved contents")),
        };
        Self {
            _temp: temp,
            intent,
            broker: Some(broker),
            stop,
            daemon: Some(daemon),
        }
    }
    fn restore(&self) -> Intent {
        Intent {
            command_id: "b".repeat(64),
            operation: Operation::Restore,
            ..self.intent.clone()
        }
    }
    fn cut(&self, intent: &Intent, stage: &str) {
        let error = apply_inner(intent, false, Duration::from_secs(3), &mut |at| {
            if at == stage {
                Err("simulated interruption".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "simulated interruption");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.broker.take());
        self.stop.store(true, Ordering::Relaxed);
        self.daemon.take().unwrap().join().unwrap();
    }
}
#[test]
fn quarantine_recovers_every_durable_boundary_without_replaying_source_move() {
    for stage in ["prepared", "captured", "ready", "retained", "complete"] {
        let f = Fixture::new();
        f.cut(&f.intent, stage);
        let report = apply(&f.intent, true, Duration::from_secs(3)).unwrap();
        if stage == "prepared" {
            assert_eq!(report.outcome, Outcome::Unconfirmed);
            assert!(f.intent.path.exists());
        } else {
            assert_eq!(report.outcome, Outcome::Completed);
            assert!(!f.intent.path.exists());
            assert_eq!(
                stdfs::read(
                    f.intent
                        .state
                        .join("quarantine")
                        .join(&f.intent.quarantine_id)
                )
                .unwrap(),
                b"approved contents"
            );
        }
        assert_eq!(
            apply(&f.intent, true, Duration::from_secs(3))
                .unwrap()
                .outcome,
            report.outcome
        );
    }
}
#[test]
fn restore_recovers_published_bytes_but_never_replays_unpublished_work() {
    for stage in ["prepared", "ready", "published", "complete"] {
        let f = Fixture::new();
        apply(&f.intent, false, Duration::from_secs(3)).unwrap();
        let restore = f.restore();
        f.cut(&restore, stage);
        let report = apply(&restore, true, Duration::from_secs(3)).unwrap();
        if ["prepared", "ready"].contains(&stage) {
            assert_eq!(report.outcome, Outcome::Unconfirmed);
            assert!(!f.intent.path.exists());
            assert!(f
                .intent
                .state
                .join("quarantine")
                .join(&f.intent.quarantine_id)
                .exists());
        } else {
            assert_eq!(report.outcome, Outcome::Completed);
            assert_eq!(stdfs::read(&f.intent.path).unwrap(), b"approved contents");
        }
        assert_eq!(
            apply(&restore, true, Duration::from_secs(3))
                .unwrap()
                .outcome,
            report.outcome
        );
    }
}
#[test]
fn open_writers_and_hardlinks_cannot_change_retained_quarantine_bytes() {
    let f = Fixture::new();
    let alias = f.intent.roots[0].join("alias");
    stdfs::hard_link(&f.intent.path, &alias).unwrap();
    let mut writer = stdfs::OpenOptions::new()
        .write(true)
        .open(&f.intent.path)
        .unwrap();
    apply(&f.intent, false, Duration::from_secs(3)).unwrap();
    writer.write_all(b"changed original!").unwrap();
    writer.sync_all().unwrap();
    assert_ne!(stdfs::read(&alias).unwrap(), b"approved contents");
    assert_eq!(
        stdfs::read(
            f.intent
                .state
                .join("quarantine")
                .join(&f.intent.quarantine_id)
        )
        .unwrap(),
        b"approved contents"
    );
}
#[test]
fn replacement_during_capture_is_retained_for_review_and_not_reported_as_success() {
    let f = Fixture::new();
    let result = apply_inner(&f.intent, false, Duration::from_secs(3), &mut |at| {
        if at == "prepared" {
            stdfs::remove_file(&f.intent.path)?;
            stdfs::write(&f.intent.path, b"unrelated replacement")?;
        }
        Ok(())
    });
    assert!(result.is_err());
    assert!(!f
        .intent
        .state
        .join("quarantine")
        .join(&f.intent.quarantine_id)
        .exists());
    assert!(apply(&f.intent, true, Duration::from_secs(3)).is_err());
    let captured = f
        .intent
        .state
        .join("quarantine")
        .join(format!(".capture-{}", f.intent.quarantine_id));
    assert_eq!(stdfs::read(captured).unwrap(), b"unrelated replacement");
}
#[test]
fn restore_conflict_preserves_existing_destination_and_retained_original() {
    let f = Fixture::new();
    apply(&f.intent, false, Duration::from_secs(3)).unwrap();
    let restore = f.restore();
    let result = apply_inner(&restore, false, Duration::from_secs(3), &mut |at| {
        if at == "ready" {
            stdfs::write(&f.intent.path, b"unrelated destination")?;
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(
        stdfs::read(&f.intent.path).unwrap(),
        b"unrelated destination"
    );
    assert_eq!(
        apply(&restore, true, Duration::from_secs(3))
            .unwrap()
            .outcome,
        Outcome::Unconfirmed
    );
    assert_eq!(
        stdfs::read(
            f.intent
                .state
                .join("quarantine")
                .join(&f.intent.quarantine_id)
        )
        .unwrap(),
        b"approved contents"
    );
}
#[test]
fn damaged_journal_and_changed_parent_never_authorize_recovery() {
    let f = Fixture::new();
    f.cut(&f.intent, "captured");
    let old = f.intent.roots[0].with_extension("old");
    stdfs::rename(&f.intent.roots[0], &old).unwrap();
    stdfs::create_dir(&f.intent.roots[0]).unwrap();
    let error = apply(&f.intent, true, Duration::from_secs(3))
        .unwrap_err()
        .to_string();
    assert!(error.contains("directory changed"), "{error}");
    let journal = f
        .intent
        .state
        .join("quarantine/operations")
        .join(format!("{}.json", f.intent.command_id));
    let mut value: serde_json::Value =
        serde_json::from_slice(&stdfs::read(&journal).unwrap()).unwrap();
    value["record"]["intent_sha256"] = serde_json::json!("0".repeat(64));
    stdfs::write(journal, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(apply(&f.intent, true, Duration::from_secs(3))
        .unwrap_err()
        .to_string()
        .contains("checksum mismatch"));
}
#[test]
fn worker_lock_and_private_paths_are_enforced() {
    let f = Fixture::new();
    let c = Context::open(&f.intent, Duration::from_secs(1)).unwrap();
    assert!(apply(&f.intent, false, Duration::from_secs(1))
        .unwrap_err()
        .to_string()
        .contains("still owns"));
    drop(c);
    let link = f.intent.roots[0].join("link");
    std::os::unix::fs::symlink(&f.intent.path, &link).unwrap();
    let mut bad = f.intent.clone();
    bad.path = link;
    assert!(apply(&bad, false, Duration::from_secs(1)).is_err());
    assert!(f.intent.path.exists());
}

#[test]
fn oversized_intent_is_rejected_before_any_filesystem_journal() {
    let f = Fixture::new();
    let mut oversized = f.intent.clone();
    oversized.roots = vec![PathBuf::from(format!("/{}", "x".repeat(4090))); 16];
    assert!(apply(&oversized, false, Duration::from_secs(1))
        .unwrap_err()
        .to_string()
        .contains("request budget"));
    assert!(!f.intent.state.join("quarantine").exists());
    assert!(f.intent.path.exists());
}

#[test]
fn approved_private_copy_survives_a_writer_changing_the_captured_inode() {
    let f = Fixture::new();
    let mut writer = stdfs::OpenOptions::new()
        .write(true)
        .open(&f.intent.path)
        .unwrap();
    f.cut(&f.intent, "ready");
    writer.write_all(b"changed original!").unwrap();
    writer.sync_all().unwrap();
    assert_eq!(
        apply(&f.intent, true, Duration::from_secs(3))
            .unwrap()
            .outcome,
        Outcome::Completed
    );
    assert_eq!(
        stdfs::read(
            f.intent
                .state
                .join("quarantine")
                .join(&f.intent.quarantine_id)
        )
        .unwrap(),
        b"approved contents"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn protected_reader_lease_blocks_recovery_after_supervisor_drops_its_context() {
    let f = Fixture::new();
    let mut intent = f.intent.clone();
    intent.verifier = Some(Verifier::LinuxProtected {
        uid: 1234,
        gid: 1234,
    });
    let mut held = None;
    let error = apply_with_verifier(&intent, false, Duration::from_secs(2), |_, _, _, lease| {
        held = Some(lease.try_clone()?);
        Err("simulated outstanding reader".into())
    })
    .unwrap_err();
    assert!(error.to_string().contains("outstanding reader"));
    assert!(apply(&intent, true, Duration::from_secs(1))
        .unwrap_err()
        .to_string()
        .contains("still owns"));
    assert!(f.intent.path.exists());
    drop(held);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match apply(&intent, true, Duration::from_secs(1)) {
            Ok(report) => {
                assert_eq!(report.outcome, Outcome::Unconfirmed);
                break;
            }
            Err(e) => {
                assert!(
                    e.to_string().contains("still owns") && Instant::now() < deadline,
                    "{e}"
                );
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[test]
fn original_broker_intents_keep_their_persisted_digest() {
    let raw=concat!("{\"schema\":1,\"command_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
    "\"quarantine_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"operation\":\"quarantine\",",
    "\"state\":\"/private/state\",\"path\":\"/watched/sample\",\"roots\":[\"/watched\"],",
    "\"sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}");
    let intent: Intent = serde_json::from_str(raw).unwrap();
    intent.validate().unwrap();
    assert!(intent.verifier.is_none());
    assert_eq!(
        intent.digest().unwrap(),
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    );
    assert_eq!(serde_json::to_string(&intent).unwrap(), raw);
}

#[test]
fn retained_verification_cannot_bypass_a_live_source_reader() {
    let f = Fixture::new();
    let mut intent = f.intent.clone();
    intent.verifier = Some(Verifier::Retained);
    assert!(apply(&intent, false, Duration::from_secs(1))
        .unwrap_err()
        .to_string()
        .contains("restricted to restore"));
    assert!(intent.path.exists());
    assert!(!intent.state.join("quarantine").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn protected_verifier_rejects_root_and_unavailable_reader_implementations() {
    let f = Fixture::new();
    let mut intent = f.intent.clone();
    for (uid, gid) in [(0, 1234), (1234, 0), (u32::MAX, 1234), (1234, u32::MAX)] {
        intent.verifier = Some(Verifier::LinuxProtected { uid, gid });
        assert!(intent.validate().is_err());
    }
    intent.verifier = Some(Verifier::LinuxProtected {
        uid: 1234,
        gid: 1234,
    });
    assert!(apply(&intent, false, Duration::from_secs(1))
        .unwrap_err()
        .to_string()
        .contains("implementation is unavailable"));
    assert!(intent.path.exists());
}

#[test]
fn local_verification_never_bypasses_a_persistent_broker_binding() {
    let mut f = Fixture::new();
    f.intent.verifier = Some(Verifier::Local);
    for running in [true, false] {
        if !running {
            drop(f.broker.take());
        }
        assert!(apply(&f.intent, false, Duration::from_secs(2))
            .unwrap_err()
            .to_string()
            .contains("cannot bypass"));
        assert_eq!(stdfs::read(&f.intent.path).unwrap(), b"approved contents");
        assert!(!f
            .intent
            .state
            .join("quarantine")
            .join(&f.intent.quarantine_id)
            .exists());
    }
}

#[test]
fn local_source_verification_recovers_each_boundary_without_a_scanner() {
    for stage in ["prepared", "captured", "ready", "retained", "complete"] {
        let mut f = Fixture::new();
        drop(f.broker.take());
        stdfs::remove_file(f.intent.state.join("protection/native/response.json")).unwrap();
        f.intent.verifier = Some(Verifier::Local);
        f.cut(&f.intent, stage);
        let report = apply(&f.intent, true, Duration::from_secs(3)).unwrap();
        if stage == "prepared" {
            assert_eq!(report.outcome, Outcome::Unconfirmed);
            assert_eq!(stdfs::read(&f.intent.path).unwrap(), b"approved contents");
        } else {
            assert_eq!(report.outcome, Outcome::Completed);
            assert!(!f.intent.path.exists());
            assert_eq!(
                stdfs::read(
                    f.intent
                        .state
                        .join("quarantine")
                        .join(&f.intent.quarantine_id)
                )
                .unwrap(),
                b"approved contents"
            );
        }
    }
}
