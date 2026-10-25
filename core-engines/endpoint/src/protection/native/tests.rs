use super::*;
use athernex_endpoint_native::{receipt::Actor, Identity, Verdict};
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};

pub(super) struct Fixture {
    _temp: tempfile::TempDir,
    pub(super) store: Store,
    pub(super) policy: Policy,
    receipt: Receipt,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(&root.join("state")).unwrap();
        let native = store.directory.join("protection/native");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(native.join("verdicts"))
            .unwrap();
        fs::set_permissions(native.join("verdicts"), fs::Permissions::from_mode(0o700)).unwrap();
        let policy = Policy {
            roots: vec![root.join("watched")],
            socket: root.join("scanner.sock"),
            state: native,
            scanner_uid: 1234,
            scan_timeout_ms: 1000,
        };
        let receipt = Receipt {
            schema: 1,
            id: "a".repeat(64),
            policy_sha256: receipt::policy_hash(&policy).unwrap(),
            time_ms: now_ms(),
            operation: "open".into(),
            response_delivered: true,
            actor: Actor {
                pid: 120,
                uid: 1000,
                pidversion: 4,
            },
            path: policy.roots[0].join("fixture").display().to_string(),
            identity: Identity {
                device: 1,
                inode: 2,
                size: 4,
                modified_sec: 3,
                modified_nsec: 4,
                changed_sec: 5,
                changed_nsec: 6,
            },
            verdict: Some(Verdict {
                sha256: protocol::hash(b"test"),
                detection: Some("PublicFixture.UNOFFICIAL".into()),
                bytes: 4,
            }),
            error: String::new(),
        };
        crate::private_write(
            &policy
                .state
                .join("policies")
                .join(format!("{}.json", receipt.policy_sha256)),
            &serde_json::to_vec(&policy).unwrap(),
        )
        .unwrap();
        let f = Self {
            _temp: temp,
            store,
            policy,
            receipt,
        };
        f.write(&f.receipt);
        f
    }
    pub(super) fn path(&self) -> PathBuf {
        self.policy
            .state
            .join("verdicts")
            .join(format!("{}.json", self.receipt.id))
    }
    fn write(&self, r: &Receipt) {
        crate::private_write(
            &self
                .policy
                .state
                .join("verdicts")
                .join(format!("{}.json", r.id)),
            &serde_json::to_vec(r).unwrap(),
        )
        .unwrap();
    }
    fn count(&self) -> usize {
        self.store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap()
    }
    fn transferred(&self) {
        self.store.connection.execute_batch("CREATE TABLE IF NOT EXISTS native_receipt_transfers(id TEXT PRIMARY KEY,sha256 TEXT NOT NULL);").unwrap();
        self.store
            .connection
            .execute(
                "INSERT INTO native_receipt_transfers VALUES(?1,?2)",
                params![
                    self.receipt.id,
                    protocol::hash(&fs::read(self.path()).unwrap())
                ],
            )
            .unwrap();
    }
}

#[test]
fn source_survives_outbox_pressure_then_commits_full_receipt() {
    let f = Fixture::new();
    f.store.connection.execute_batch("CREATE TRIGGER fixture_full BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture capacity'); END;").unwrap();
    assert!(collect(&f.store).is_err());
    assert!(f.path().exists());
    assert_eq!(f.count(), 0);
    f.store
        .connection
        .execute_batch("DROP TRIGGER fixture_full")
        .unwrap();
    collect(&f.store).unwrap();
    assert!(!f.path().exists());
    assert_eq!(f.count(), 1);
    let raw: String = f
        .store
        .connection
        .query_row("SELECT payload FROM outbox", [], |r| r.get(0))
        .unwrap();
    let event: EndpointEvent = serde_json::from_str(&raw).unwrap();
    assert_eq!(event.sha256, protocol::hash(b"test"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&event.detail).unwrap(),
        serde_json::to_value(&f.receipt).unwrap()
    );
    f.write(&f.receipt); // interrupted source removal with an existing outbox row
    collect(&f.store).unwrap();
    assert_eq!(f.count(), 1);
}

#[test]
fn durable_transfer_survives_restart_and_server_ack_before_unlink() {
    let f = Fixture::new();
    f.transferred(); // The durable outbox row was already ACKed by the server.
    let state = f.store.directory.clone();
    let path = f.path();
    drop(f.store);
    let store = Store::open(&state).unwrap();
    collect(&store).unwrap();
    assert!(!path.exists());
    assert_eq!(
        store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT count(*) FROM native_receipt_transfers", [], |r| r
                .get::<_, u64>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn committed_transfer_rejects_changed_content_and_recovers_unlinked_source() {
    let mut f = Fixture::new();
    f.transferred();
    f.receipt.actor.pid += 1;
    f.write(&f.receipt);
    assert!(collect(&f.store)
        .unwrap_err()
        .to_string()
        .contains("changed after"));
    assert!(f.path().exists());
    assert_eq!(f.count(), 0);
    fs::remove_file(f.path()).unwrap(); // crash after unlink, before ledger cleanup
    collect(&f.store).unwrap();
    assert_eq!(
        f.store
            .connection
            .query_row("SELECT count(*) FROM native_receipt_transfers", [], |r| r
                .get::<_, u64>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn invalid_native_claims_never_authorize_malware_actions() {
    let f = Fixture::new();
    for variant in 0..8 {
        let mut receipt = f.receipt.clone();
        match variant {
            0 => receipt.path = "/outside/scope".into(),
            1 => receipt.verdict.as_mut().unwrap().sha256 = "unverified".into(),
            2 => receipt.verdict.as_mut().unwrap().bytes = 5,
            3 => receipt.verdict.as_mut().unwrap().detection = None,
            4 => receipt.error = "contradictory error".into(),
            5 => receipt.time_ms = now_ms() + 120000,
            6 => receipt.policy_sha256 = "b".repeat(64),
            _ => receipt.id = "b".repeat(64),
        }
        crate::private_write(&f.path(), &serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(collect(&f.store).is_err(), "variant {variant}");
        assert!(f.path().exists());
        assert_eq!(f.count(), 0);
    }
    let mut error = f.receipt.clone();
    error.verdict = None;
    error.error = "Native scan deadline elapsed".into();
    f.write(&error);
    collect(&f.store).unwrap();
    let raw: String = f
        .store
        .connection
        .query_row("SELECT payload FROM outbox", [], |r| r.get(0))
        .unwrap();
    let event: EndpointEvent = serde_json::from_str(&raw).unwrap();
    assert_eq!(event.kind, "agent_error");
    assert!(event.sha256.is_empty());
    assert!(event.detection.is_empty());
}

#[test]
fn private_scope_history_and_regular_files_are_required() {
    let f = Fixture::new();
    fs::set_permissions(f.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(collect(&f.store).is_err());
    fs::set_permissions(f.path(), fs::Permissions::from_mode(0o600)).unwrap();
    let target = f.policy.state.join("original");
    fs::rename(f.path(), &target).unwrap();
    symlink(&target, f.path()).unwrap();
    assert!(collect(&f.store).is_err());
    assert!(target.exists());
    fs::remove_file(f.path()).unwrap();
    fs::rename(target, f.path()).unwrap();
    let history = f
        .policy
        .state
        .join("policies")
        .join(format!("{}.json", f.receipt.policy_sha256));
    let mut changed = f.policy.clone();
    changed.scanner_uid += 1;
    crate::private_write(&history, &serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(collect(&f.store).is_err());
    assert_eq!(f.count(), 0);
    crate::private_write(&history, &serde_json::to_vec(&f.policy).unwrap()).unwrap();
    collect(&f.store).unwrap();
    assert_eq!(f.count(), 1);
}

#[test]
fn batch_bound_keeps_untransferred_receipts_and_reclaims_transfer_rows() {
    let f = Fixture::new();
    for i in 1..70 {
        let mut r = f.receipt.clone();
        r.id = protocol::hash(format!("receipt-{i}").as_bytes());
        f.write(&r);
    }
    collect(&f.store).unwrap();
    assert_eq!(f.count(), 64);
    assert_eq!(
        fs::read_dir(f.policy.state.join("verdicts"))
            .unwrap()
            .count(),
        6
    );
    collect(&f.store).unwrap();
    assert_eq!(f.count(), 70);
    assert_eq!(
        f.store
            .connection
            .query_row("SELECT count(*) FROM native_receipt_transfers", [], |r| r
                .get::<_, u64>(
                0
            ))
            .unwrap(),
        0
    );
}
