use super::*;
pub(super) fn scope() -> Scope {
    Scope {
        roots: vec![Root {
            nt: "\\Device\\HarddiskVolume3\\Protected".into(),
            dos: "C:\\Protected".into(),
        }],
        timeout_ms: 1000,
    }
}
pub(super) fn receipt(scope: &Scope, request: u64) -> Receipt {
    Receipt {
        session: "a".repeat(64),
        observation: Observation {
            schema: 1,
            request_id: request,
            checked_ms: now_ms(),
            path: "\\Device\\HarddiskVolume3\\Protected\\sample.bin".into(),
            volume: 1234,
            file_id: "b".repeat(32),
            actor_pid: 12,
            actor_created: 12345678,
            bytes: 7,
            sha256: "c".repeat(64),
            detection: Some("Fixture.Signature".into()),
            policy_sha256: scope.digest().unwrap(),
            outcome: "denied_malware".into(),
        },
    }
}
#[test]
fn transfer_survives_server_ack_before_source_ack_and_process_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("agent");
    let path = dir.path().join("windows-evidence.sqlite3");
    let scope = scope();
    let value = receipt(&scope, 1);
    {
        let queue = Queue::open(&path).unwrap();
        let store = Store::open(&state).unwrap();
        queue.register(&scope).unwrap();
        queue.collect(&store).unwrap();
        queue.record(&value).unwrap();
        queue
            .admit(
                &store,
                &value.event(&scope).unwrap(),
                &serde_json::to_string(&value).unwrap(),
            )
            .unwrap();
        // The server ACK removes the management event. Source receipt deletion
        // has not happened yet when both processes die.
        store.connection.execute("DELETE FROM outbox", []).unwrap();
    }
    let queue = Queue::open(&path).unwrap();
    let store = Store::open(&state).unwrap();
    queue.collect(&store).unwrap();
    assert_eq!(queue.counts().unwrap(), (0, 0));
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
            .query_row("SELECT count(*) FROM windows_receipt_transfers", [], |r| {
                r.get::<_, u64>(0)
            })
            .unwrap(),
        0
    );
}

#[test]
fn retained_transfers_do_not_hide_retired_entries_or_starve_coverage_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state")).unwrap();
    let queue = Queue::open(&dir.path().join("evidence.db")).unwrap();
    let scope = scope();
    queue.register(&scope).unwrap();
    queue.collect(&store).unwrap(); // Initialize management transfer schema.
    for n in 1..=64 {
        let value = receipt(&scope, n);
        queue.record(&value).unwrap();
        queue
            .admit(
                &store,
                &value.event(&scope).unwrap(),
                &serde_json::to_string(&value).unwrap(),
            )
            .unwrap();
    }
    // ACKed events retain their source records; later journal entries survived
    // source deletion. A LIMIT 64 scan would encounter only the live records.
    store
        .connection
        .execute_batch(
            "DELETE FROM outbox;
        WITH RECURSIVE n(x) AS (SELECT 65 UNION ALL SELECT x+1 FROM n WHERE x<2112)
        INSERT INTO windows_receipt_transfers SELECT printf('z%063x',x),'retired' FROM n;",
        )
        .unwrap();
    queue
        .begin_session(&"f".repeat(64), &scope.digest().unwrap())
        .unwrap();
    queue.collect(&store).unwrap();
    assert_eq!(queue.counts().unwrap().0, 0);
    assert_eq!(
        store
            .connection
            .query_row("SELECT count(*) FROM windows_receipt_transfers", [], |r| {
                r.get::<_, u64>(0)
            })
            .unwrap(),
        0
    );
    let raw: String = store
        .connection
        .query_row("SELECT payload FROM outbox", [], |r| r.get(0))
        .unwrap();
    assert!(serde_json::from_str::<EndpointEvent>(&raw)
        .unwrap()
        .detail
        .contains("windows_evidence_coverage"));
}
#[test]
fn changed_replay_is_refused_and_session_restart_has_a_distinct_identity() {
    let queue = Queue::open(Path::new(":memory:")).unwrap();
    let scope = scope();
    queue.register(&scope).unwrap();
    let mut first = receipt(&scope, 1);
    queue.record(&first).unwrap();
    queue.record(&first).unwrap();
    first.observation.sha256 = "d".repeat(64);
    assert!(queue.record(&first).is_err());
    first.session = "e".repeat(64);
    queue.record(&first).unwrap();
    assert_eq!(queue.counts().unwrap(), (2, 0));
    let mut remapped = scope.clone();
    remapped.roots[0].dos = "D:\\Different".into();
    assert!(queue.register(&remapped).is_err());
}
#[test]
fn evidence_preserves_windows_identity_and_rejects_path_or_verdict_confusion() {
    let scope = scope();
    let mut receipt = receipt(&scope, 9);
    let event = receipt.event(&scope).unwrap();
    assert_eq!(event.path, "C:\\Protected\\sample.bin");
    assert_eq!(event.kind, "malware");
    let decoded: Receipt = serde_json::from_str(&event.detail).unwrap();
    assert_eq!(decoded.observation.file_id, "b".repeat(32));
    assert_eq!(decoded.observation.actor_created, 12345678);
    receipt.observation.path = "\\Device\\HarddiskVolume3\\ProtectedSibling\\sample.bin".into();
    assert!(receipt.event(&scope).is_err());
    receipt.observation.path = "\\Device\\HarddiskVolume3\\Protected\\..\\sample.bin".into();
    assert!(receipt.event(&scope).is_err());
    receipt.observation.path = "\\Device\\HarddiskVolume3\\Protected\\sample.bin:stream".into();
    assert!(receipt.event(&scope).is_err());
    receipt.observation.path = "\\Device\\HarddiskVolume3\\Protected\\sample.bin".into();
    receipt.observation.outcome = "denied_error".into();
    assert!(receipt.event(&scope).is_err());
    receipt.observation.sha256.clear();
    receipt.observation.detection = None;
    assert_eq!(receipt.event(&scope).unwrap().kind, "agent_error");
}
#[test]
fn finite_spool_preserves_old_evidence_and_persists_loss_counters() {
    let queue = Queue::open(Path::new(":memory:")).unwrap();
    let scope = scope();
    queue.register(&scope).unwrap();
    for id in 1..=LIMIT {
        queue.record(&receipt(&scope, id)).unwrap();
    }
    assert!(queue.record(&receipt(&scope, LIMIT + 1)).is_err());
    assert_eq!(queue.counts().unwrap(), (LIMIT, 0));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evidence.sqlite3");
    {
        let queue = Queue::open(&path).unwrap();
        queue.lost(12).unwrap();
        queue.lost(i64::MAX as u64).unwrap();
    }
    assert_eq!(
        Queue::open(&path).unwrap().counts().unwrap(),
        (0, i64::MAX as u64)
    );
}
