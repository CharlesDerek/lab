use super::*;
fn fixture() -> (tempfile::TempDir, Queue, String, String) {
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(&directory.path().join("evidence.db")).unwrap();
    let scope = Scope {
        roots: vec![Root {
            nt: "\\Device\\HarddiskVolume3\\Protected".into(),
            dos: "C:\\Protected".into(),
        }],
        timeout_ms: 1000,
    };
    queue.register(&scope).unwrap();
    (directory, queue, "a".repeat(64), scope.digest().unwrap())
}
fn status(policy: &str, instance: u8, dropped: u64) -> wire::Status {
    let mut digest = [0; 32];
    for (out, hex) in digest.iter_mut().zip(policy.as_bytes().chunks_exact(2)) {
        *out = u8::from_str_radix(std::str::from_utf8(hex).unwrap(), 16).unwrap();
    }
    wire::Status {
        version: wire::VERSION,
        armed: 1,
        connected: 1,
        instance: [instance; 16],
        policy_sha256: digest,
        evidence_dropped: dropped,
        ..Default::default()
    }
}
#[test]
fn driver_drops_are_counted_once_across_client_restart_and_reload_preserves_unknown_tail() {
    let (dir, queue, session, policy) = fixture();
    queue.begin_session(&session, &policy).unwrap();
    let s = status(&policy, 1, 7);
    let c = queue.observe_kernel(&session, now_ms(), &s).unwrap();
    assert_eq!(c.kernel_dropped, 7);
    queue.observe_kernel(&session, now_ms(), &s).unwrap();
    assert_eq!(queue.coverage().unwrap().unwrap().kernel_dropped, 7);
    drop(queue);
    let queue = Queue::open(&dir.path().join("evidence.db")).unwrap();
    let session = "b".repeat(64);
    let c = queue.begin_session(&session, &policy).unwrap();
    assert_eq!(c.gaps, 1);
    assert!(c.incomplete());
    let c = queue
        .observe_kernel(&session, now_ms(), &status(&policy, 1, 11))
        .unwrap();
    assert_eq!(c.kernel_dropped, 11);
    let c = queue
        .observe_kernel(&session, now_ms(), &status(&policy, 2, 3))
        .unwrap();
    assert_eq!(c.kernel_dropped, 14);
    assert_eq!(c.gaps, 2);
    queue.end_session(&session, "controlled stop").unwrap();
    let stopped = queue.coverage().unwrap().unwrap();
    assert_eq!(stopped.gaps, 3);
    queue.end_session(&session, "duplicate stop").unwrap();
    assert_eq!(queue.coverage().unwrap().unwrap(), stopped);
    let c = queue.begin_session(&"c".repeat(64), &policy).unwrap();
    assert_eq!(c.gaps, 3);
    assert_eq!(c.kernel_dropped, 14);
}
#[test]
fn counter_regression_retains_baseline_and_cannot_be_reinterpreted_as_a_new_driver() {
    let (_directory, queue, session, policy) = fixture();
    queue.begin_session(&session, &policy).unwrap();
    let mut s = status(&policy, 1, 10);
    s.allowed = 30;
    let good = queue.observe_kernel(&session, now_ms(), &s).unwrap();
    s.allowed = 29;
    let failed = queue.observe_kernel(&session, now_ms(), &s).unwrap();
    assert_eq!(failed.state, "failed");
    assert_eq!(failed.kernel, good.kernel);
    assert_eq!(failed.kernel_dropped, 10);
    assert_eq!(failed.gaps, 1);
    assert!(queue.observe_kernel(&session, now_ms(), &s).is_err());
    assert!(queue.observe_kernel(&"b".repeat(64), now_ms(), &s).is_err());
    assert_eq!(queue.coverage().unwrap().unwrap(), failed);
    queue.end_session(&session, &"🦀\n".repeat(600)).unwrap();
    let stopped = queue.coverage().unwrap().unwrap();
    stopped.validate().unwrap();
    assert_eq!(stopped.reason.len(), 512);
    assert_eq!(stopped.gaps, failed.gaps);
}
#[test]
fn notice_and_checkpoint_commit_together_and_full_notice_queue_preserves_history() {
    let (_directory, queue, session, policy) = fixture();
    queue.begin_session(&session, &policy).unwrap();
    let before = queue.coverage().unwrap().unwrap();
    queue.connection.execute_batch("CREATE TRIGGER reject_notice BEFORE INSERT ON coverage_events BEGIN SELECT RAISE(ABORT,'controlled'); END;").unwrap();
    assert!(queue
        .observe_kernel(&session, now_ms(), &status(&policy, 1, 9))
        .is_err());
    assert_eq!(queue.coverage().unwrap().unwrap(), before);
    assert!(queue.lost(2).is_err());
    assert_eq!(queue.counts().unwrap().1, 0);
    queue
        .connection
        .execute_batch("DROP TRIGGER reject_notice;")
        .unwrap();
    for n in 1..NOTICES {
        queue
            .observe_kernel(&session, now_ms(), &status(&policy, 1, n))
            .unwrap();
    }
    let retained = queue.coverage().unwrap().unwrap();
    assert_eq!(retained.kernel_dropped, NOTICES - 1);
    assert!(queue
        .observe_kernel(&session, now_ms(), &status(&policy, 1, NOTICES))
        .is_err());
    assert_eq!(queue.coverage().unwrap().unwrap(), retained);
    assert_eq!(
        queue
            .connection
            .query_row("SELECT count(*) FROM coverage_events", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        NOTICES
    );
}
#[test]
fn coverage_transfer_survives_server_ack_before_source_ack_and_keeps_local_loss_separate() {
    let (dir, queue, session, policy) = fixture();
    let state = dir.path().join("state");
    let store = Store::open(&state).unwrap();
    queue.begin_session(&session, &policy).unwrap();
    queue
        .observe_kernel(&session, now_ms(), &status(&policy, 1, 5))
        .unwrap();
    queue.lost(3).unwrap();
    let c = queue.coverage().unwrap().unwrap();
    assert_eq!((c.kernel_dropped, c.local_dropped), (5, 3));
    queue.collect(&store).unwrap();
    let events = store
        .connection
        .prepare("SELECT payload FROM outbox")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(events.len(), 3);
    assert!(events.iter().any(|s| {
        let e: EndpointEvent = serde_json::from_str(s).unwrap();
        e.kind == "agent_error" && e.detail.contains("\"local_dropped\":3")
    }));
    queue
        .observe_kernel(&session, now_ms(), &status(&policy, 1, 7))
        .unwrap();
    let raw: String = queue
        .connection
        .query_row("SELECT payload FROM coverage_events", [], |r| r.get(0))
        .unwrap();
    let c: Coverage = serde_json::from_str(&raw).unwrap();
    let e = c.event().unwrap();
    queue.admit(&store, &e, &raw).unwrap();
    store.connection.execute("DELETE FROM outbox", []).unwrap();
    drop(store);
    drop(queue);
    let queue = Queue::open(&dir.path().join("evidence.db")).unwrap();
    let store = Store::open(&state).unwrap();
    queue.collect(&store).unwrap();
    assert_eq!(queue.counts().unwrap(), (0, 3));
    assert_eq!(
        store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    let c = queue.coverage().unwrap().unwrap();
    assert_eq!((c.kernel_dropped, c.local_dropped), (7, 3));
}
#[test]
fn old_spools_do_not_gain_a_false_complete_history_when_coverage_is_added() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);INSERT INTO counters VALUES('lost',4);").unwrap();
    drop(db);
    let queue = Queue::open(&path).unwrap();
    let session = "a".repeat(64);
    let policy = "b".repeat(64);
    queue.begin_session(&session, &policy).unwrap();
    let c = queue
        .observe_kernel(&session, now_ms(), &status(&policy, 1, 0))
        .unwrap();
    assert!(c.legacy_history_unknown);
    assert!(c.incomplete());
    assert_eq!(c.local_dropped, 4);
    drop(queue);
    let queue = Queue::open(&path).unwrap();
    assert!(queue.coverage().unwrap().unwrap().legacy_history_unknown);
}
