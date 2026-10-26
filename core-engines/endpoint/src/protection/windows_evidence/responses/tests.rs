use super::*;
use crate::protection::windows_evidence::tests::{receipt, scope};
use athernex_endpoint_native::windows_filter::wire;

struct Fixture {
    temp: tempfile::TempDir,
    queue: Queue,
    probe: Probe,
    receipt: Receipt,
}
impl Fixture {
    fn new() -> Self {
        Self::with_storage(false)
    }
    fn with_storage(memory: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = if memory {
            Path::new(":memory:").to_path_buf()
        } else {
            temp.path().join("evidence.db")
        };
        let queue = Queue::open(&path).unwrap();
        let scope = scope();
        let receipt = receipt(&scope, 1);
        queue.register(&scope).unwrap();
        queue
            .begin_session(&receipt.session, &scope.digest().unwrap())
            .unwrap();
        queue
            .observe_kernel(
                &receipt.session,
                now_ms(),
                &wire::Status {
                    version: wire::VERSION,
                    armed: 1,
                    connected: 1,
                    pending: 0,
                    allowed: 0,
                    malware: 0,
                    errors: 0,
                    evidence_dropped: 0,
                    instance: [1; 16],
                    policy_sha256: scope.config().unwrap().policy_sha256,
                },
            )
            .unwrap();
        let now = now_ms();
        let probe = Probe {
            id: "d".repeat(64),
            session: receipt.session.clone(),
            policy: scope.digest().unwrap(),
            actor_pid: receipt.observation.actor_pid as u32,
            actor_created: receipt.observation.actor_created,
            path: scope.path(&receipt.observation.path).unwrap(),
            volume: receipt.observation.volume,
            file_id: receipt.observation.file_id.clone(),
            bytes: receipt.observation.bytes,
            started_ms: now,
            expires_ms: now + 10_000,
        };
        let mut receipt = receipt;
        receipt.observation.checked_ms = now;
        Self {
            temp,
            queue,
            probe,
            receipt,
        }
    }
    fn admit(&self) {
        self.queue.begin_response(&self.probe).unwrap();
    }
    fn refresh_kernel(&self) {
        self.queue
            .observe_kernel(
                &self.probe.session,
                now_ms(),
                &wire::Status {
                    version: wire::VERSION,
                    armed: 1,
                    connected: 1,
                    pending: 0,
                    allowed: 0,
                    malware: 0,
                    errors: 0,
                    evidence_dropped: 0,
                    instance: [1; 16],
                    policy_sha256: scope().config().unwrap().policy_sha256,
                },
            )
            .unwrap();
    }
    fn current_probe(&self) -> Probe {
        let mut probe = self.probe.clone();
        probe.started_ms = now_ms();
        probe.expires_ms = probe.started_ms + LIFETIME_MS;
        probe
    }
    fn live_ids(&self) -> Vec<String> {
        self.queue
            .connection
            .prepare("SELECT id FROM response_probes WHERE expires>?1 ORDER BY id")
            .unwrap()
            .query_map([now_ms()], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }
}

#[test]
fn denial_survives_management_transfer_and_restart_then_is_consumed_once() {
    let f = Fixture::new();
    f.admit();
    assert!(f.queue.take_response(&f.probe).unwrap().is_none());
    f.queue.record(&f.receipt).unwrap();
    f.queue.record(&f.receipt).unwrap();
    let store = Store::open(&f.temp.path().join("agent")).unwrap();
    f.queue.collect(&store).unwrap();
    assert_eq!(f.queue.counts().unwrap().0, 0);
    drop(f.queue);
    let queue = Queue::open(&f.temp.path().join("evidence.db")).unwrap();
    let verdict = queue.take_response(&f.probe).unwrap().unwrap();
    assert_eq!(verdict.sha256, f.receipt.observation.sha256);
    assert_eq!(verdict.detection, f.receipt.observation.detection);
    assert!(queue.take_response(&f.probe).is_err());
    assert!(
        store
            .connection
            .query_row(
                "SELECT count(*) FROM outbox WHERE id=?1",
                [f.receipt.id()],
                |r| r.get::<_, u64>(0)
            )
            .unwrap()
            == 1
    );
}

#[test]
fn mismatched_file_or_error_denial_never_verifies_a_source() {
    for mismatch in 0..7 {
        let mut f = Fixture::new();
        f.admit();
        match mismatch {
            0 => f.receipt.observation.file_id = "e".repeat(32),
            1 => f.receipt.observation.volume += 1,
            2 => f.receipt.observation.bytes += 1,
            3 => f.receipt.observation.path.push('x'),
            4 => f.receipt.observation.checked_ms = f.probe.started_ms - 1,
            5 => f.receipt.observation.checked_ms = f.probe.expires_ms + 1,
            6 => {
                f.receipt.observation.outcome = "denied_error".into();
                f.receipt.observation.sha256.clear();
                f.receipt.observation.detection = None;
            }
            _ => unreachable!(),
        }
        f.queue.record(&f.receipt).unwrap();
        assert!(
            f.queue.take_response(&f.probe).is_err(),
            "mismatch {mismatch}"
        );
    }
}

#[test]
fn other_actor_session_and_prior_evidence_cannot_satisfy_probe() {
    for mismatch in 0..3 {
        let mut f = Fixture::new();
        // Evidence already in the delivery queue is never searched as a source
        // of hashes when registering a new read attempt.
        f.queue.record(&f.receipt).unwrap();
        f.admit();
        assert!(f.queue.take_response(&f.probe).unwrap().is_none());
        f.receipt.observation.request_id += 1;
        match mismatch {
            0 => f.receipt.observation.actor_pid += 1,
            1 => f.receipt.observation.actor_created += 1,
            2 => f.receipt.session = "f".repeat(64),
            _ => unreachable!(),
        }
        f.queue.record(&f.receipt).unwrap();
        assert!(f.queue.take_response(&f.probe).unwrap().is_none());
    }
}

#[test]
fn probe_admission_requires_live_session_scope_and_unique_actor() {
    let f = Fixture::new();
    for mismatch in 0..5 {
        let mut probe = f.probe.clone();
        match mismatch {
            0 => probe.session = "e".repeat(64),
            1 => probe.path = "C:\\Outside\\sample.bin".into(),
            2 => probe.expires_ms = probe.started_ms,
            3 => probe.expires_ms += 1,
            4 => probe.actor_created = 0,
            _ => unreachable!(),
        }
        assert!(
            f.queue.begin_response(&probe).is_err(),
            "mismatch {mismatch}"
        );
    }
    f.admit();
    assert!(f.queue.begin_response(&f.probe).is_err());
    let mut other = f.probe.clone();
    other.id = "e".repeat(64);
    assert!(f.queue.begin_response(&other).is_err());
    let mut altered = f.probe.clone();
    altered.bytes += 1;
    assert!(f.queue.take_response(&altered).is_err());
    f.queue
        .end_session(&f.probe.session, "fixture stopped")
        .unwrap();
    assert!(f.queue.take_response(&f.probe).is_err());
}

#[test]
fn expiry_capacity_and_cancel_preserve_unrelated_pending_probes() {
    // Exercise admission/capacity, not 64 disk-sync latencies. Reopen and
    // durability tests above retain their file-backed queues. Model a live
    // source without extending or rewriting any already-admitted probe.
    let f = Fixture::with_storage(true);
    for i in 0..LIMIT {
        f.refresh_kernel();
        let mut probe = f.current_probe();
        probe.id = format!("{i:064x}");
        probe.actor_pid += i as u32 + 1;
        f.queue.begin_response(&probe).unwrap();
    }
    let expected = (0..LIMIT).map(|i| format!("{i:064x}")).collect::<Vec<_>>();
    assert_eq!(f.live_ids(), expected);
    f.refresh_kernel();
    let probe = f.current_probe();
    assert!(matches!(f.queue.begin_response(&probe), Err(error)
        if error.to_string() == "Windows response probe capacity exhausted"));
    assert_eq!(f.live_ids(), expected);
    f.queue
        .connection
        .execute(
            "UPDATE response_probes SET expires=1 WHERE id=?1",
            [format!("{:064x}", 0)],
        )
        .unwrap();
    f.refresh_kernel();
    let probe = f.current_probe();
    f.queue.begin_response(&probe).unwrap();
    f.queue.cancel_response(&probe).unwrap();
    f.queue.cancel_response(&probe).unwrap();
    assert!(f.queue.take_response(&probe).is_err());
    assert_eq!(f.live_ids(), expected[1..]);
    assert_eq!(
        f.queue
            .connection
            .query_row("SELECT count(*) FROM response_probes", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        LIMIT - 1
    );
}

#[test]
fn stale_coverage_or_kernel_checkpoint_refuses_admission_and_response() {
    for stale_kernel in [false, true] {
        let f = Fixture::new();
        f.refresh_kernel();
        let probe = f.current_probe();
        f.queue.begin_response(&probe).unwrap();
        let mut coverage = f.queue.coverage().unwrap().unwrap();
        let now = now_ms();
        coverage.checked_ms = now;
        coverage.kernel.as_mut().unwrap().checked_ms = now;
        let stale = now - 5001;
        if stale_kernel {
            coverage.kernel.as_mut().unwrap().checked_ms = stale;
        } else {
            coverage.checked_ms = stale;
        }
        coverage.validate().unwrap();
        f.queue
            .connection
            .execute(
                "UPDATE coverage_state SET payload=?1 WHERE name='current'",
                [serde_json::to_string(&coverage).unwrap()],
            )
            .unwrap();
        let refused = "Windows response protection session is unavailable or changed";
        assert!(
            matches!(f.queue.begin_response(&f.current_probe()), Err(error) if error.to_string() == refused)
        );
        assert!(
            matches!(f.queue.take_response(&probe), Err(error) if error.to_string() == refused)
        );
        assert_eq!(f.live_ids(), vec![probe.id]);
    }
}

#[test]
fn response_and_delivery_evidence_commit_atomically() {
    let f = Fixture::new();
    f.admit();
    f.queue.connection.execute_batch("CREATE TRIGGER reject_response BEFORE UPDATE ON response_probes BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;").unwrap();
    assert!(f.queue.record(&f.receipt).is_err());
    assert!(f.queue.take_response(&f.probe).unwrap().is_none());
    assert_eq!(
        f.queue
            .connection
            .query_row("SELECT count(*) FROM decisions", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    f.queue
        .connection
        .execute_batch("DROP TRIGGER reject_response;")
        .unwrap();
    f.queue.record(&f.receipt).unwrap();
    assert!(f.queue.take_response(&f.probe).unwrap().is_some());
}

#[test]
fn conflicting_receipts_preserve_both_decisions_and_refuse_verification() {
    let mut f = Fixture::new();
    f.admit();
    f.queue.record(&f.receipt).unwrap();
    f.receipt.observation.request_id += 1;
    f.receipt.observation.sha256 = "e".repeat(64);
    f.queue.record(&f.receipt).unwrap();
    assert!(f.queue.take_response(&f.probe).is_err());
    assert_eq!(
        f.queue
            .connection
            .query_row("SELECT count(*) FROM decisions", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        2
    );
}
