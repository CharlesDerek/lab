use super::*;
use protocol::macos_network_events::*;
fn event(stream: &str, receipt: u64) -> MacosNetworkEvent {
    MacosNetworkEvent::from_original(MacosNetworkOriginal {
        projection_version: 1,
        stream_id: stream.into(),
        receipt_sequence: receipt,
        callback: MacosNetworkCallback::NewFlow,
        receipt_time: MacosNetworkReceiptTime {
            seconds: (crate::now_ms() / 1000) as i64,
            nanoseconds: 0,
        },
        flow_id: "00000000-0000-0000-0000-000000000001".into(),
        direction: 0,
        socket_family: 2,
        socket_type: 1,
        socket_protocol: 0,
        local: None,
        remote: None,
        source_app_audit_token_hex: None,
        source_process_audit_token_hex: None,
    })
    .unwrap()
}
fn delivery(stream: &str, receipt: u64, batch: u64) -> Delivery {
    let events = vec![event(stream, receipt)];
    let health = MacosNetworkEventHealth {
        stream_id: stream.into(),
        state: "active".into(),
        source_policy_sha256: source_policy_sha256(),
        started_ms: 1,
        checked_ms: crate::now_ms(),
        received_records: receipt,
        pending_records: 1,
        pending_bytes: 500,
        ..Default::default()
    };
    Delivery {
        batch_id: batch,
        batch_sha256: protocol::hash(&serde_json::to_vec(&events).unwrap()),
        events,
        status: Status {
            health,
            last_acked_batch_id: batch - 1,
        },
    }
}
fn count(store: &Store) -> u64 {
    store
        .connection
        .query_row(
            "SELECT (SELECT count(*) FROM outbox)+(SELECT count(*) FROM telemetry_pending)",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
fn saved(store: &Store) -> (serde_json::Value, serde_json::Value) {
    (
        metadata(store, "macos_network_health").unwrap().unwrap(),
        metadata(store, "macos_network_session").unwrap().unwrap(),
    )
}
#[test]
fn reconnect_replays_committed_exact_batch_after_ack_loss_without_duplicate() {
    let temp = tempfile::tempdir().unwrap();
    let d = delivery(&"a".repeat(64), 3, 1);
    {
        let store = Store::open(temp.path()).unwrap();
        let (mut h, mut s) = prepare(&store, &d.status.health).unwrap();
        assert!(persist(&store, &mut h, &mut s, &d).unwrap());
        assert_eq!(h.admitted_records, 1);
        assert_eq!(count(&store), 1);
        let raw: String = store
            .connection
            .query_row(
                "SELECT payload FROM outbox WHERE id=?1",
                [d.events[0].event_id()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
            serde_json::to_value(envelope(&d.events[0])).unwrap()
        );
        store.connection.execute("DELETE FROM outbox", []).unwrap();
    }
    let store = Store::open(temp.path()).unwrap();
    let (mut h, mut s) = prepare(&store, &d.status.health).unwrap();
    assert!(persist(&store, &mut h, &mut s, &d).unwrap());
    assert_eq!(count(&store), 0);
    assert_eq!(h.admitted_records, 1);
    assert_eq!(s.last_receipt, 3);
    let before = saved(&store);
    let mut changed = d.clone();
    changed.events[0] = event(&d.status.health.stream_id, 2);
    assert!(persist(&store, &mut h, &mut s, &changed).is_err());
    assert_eq!(saved(&store), before);
    let mut changed = d.clone();
    changed.batch_sha256 = "b".repeat(64);
    assert!(persist(&store, &mut h, &mut s, &changed).is_err());
    assert_eq!(saved(&store), before);
}
#[test]
fn reset_database_and_missing_inflight_or_receipt_markers_cannot_claim_complete_history() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut d = delivery(&"a".repeat(64), 4, 2);
    let (mut h, mut s) = prepare(&store, &d.status.health).unwrap();
    assert!(persist(&store, &mut h, &mut s, &d).is_err());
    d.batch_id = 1;
    d.status.last_acked_batch_id = 0;
    assert!(persist(&store, &mut h, &mut s, &d).unwrap());
    assert!(persist(&store, &mut h, &mut s, &status_delivery(d.status.clone())).is_err());
    s.last_receipt = 3;
    assert!(persist(&store, &mut h, &mut s, &d).is_err());
}
#[test]
fn new_provider_preserves_originals_and_records_unknown_interval_not_exact_drops() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let d = delivery(&"a".repeat(64), 1, 1);
    let (mut h, mut s) = prepare(&store, &d.status.health).unwrap();
    persist(&store, &mut h, &mut s, &d).unwrap();
    let other = delivery(&"b".repeat(64), 1, 1);
    let (mut h, mut s) = prepare(&store, &other.status.health).unwrap();
    assert_eq!(
        (
            h.restarts,
            h.loss_signals,
            h.admitted_records,
            h.queue_drops
        ),
        (1, 1, 0, 0)
    );
    persist(&store, &mut h, &mut s, &other).unwrap();
    assert_eq!(count(&store), 2);
    assert!(!h.healthy(crate::now_ms()));
    assert_eq!(h.admitted_records, 1);
    finish(&store, &mut h, &mut s, false).unwrap();
    assert_eq!(h.queue_drops, 0);
    assert_eq!(h.pending_records, 1);
    assert!(h.error.contains("provider may still be active"));
}
#[test]
fn original_and_ack_commit_roll_back_together_on_database_failure() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut d = delivery(&"a".repeat(64), 2, 1);
    d.events = vec![
        event(&d.status.health.stream_id, 1),
        event(&d.status.health.stream_id, 2),
    ];
    d.status.health.pending_records = 2;
    d.status.health.pending_bytes = 1000;
    let (mut h, mut s) = prepare(&store, &d.status.health).unwrap();
    let before = saved(&store);
    store.connection.execute_batch(&format!("CREATE TRIGGER refuse_second BEFORE INSERT ON telemetry_pending WHEN NEW.id='{}' BEGIN SELECT RAISE(ABORT,'fixture'); END",d.events[1].event_id())).unwrap();
    assert!(persist(&store, &mut h, &mut s, &d).is_err());
    assert_eq!(count(&store), 0);
    assert_eq!(s.batch_id, 0);
    assert_eq!(saved(&store), before);
}
#[test]
fn exact_full_queue_and_replay_remain_backpressured_without_double_counting_loss() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let d = delivery(&"a".repeat(64), 1, 1);
    let (mut h, mut s) = prepare(&store, &d.status.health).unwrap();
    for (table, amount, base) in [
        ("outbox", 3072, 100000),
        ("telemetry_pending", 8191, 200000),
    ] {
        store.connection.execute(&format!("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO {table} SELECT printf('%064x',x+{base}),json_object('id',printf('%064x',x+{base}),'time_ms',?2,'kind','inventory','path','','sha256','','detection','','detail','queue fixture','telemetry',NULL) FROM n"),rusqlite::params![amount,crate::now_ms()]).unwrap();
    }
    assert!(persist(&store, &mut h, &mut s, &d).unwrap());
    assert!(h.backpressured);
    assert!(persist(&store, &mut h, &mut s, &d).unwrap());
    assert!(h.backpressured);
    assert_eq!(h.admitted_records, 1);
    let mut next = delivery(&d.status.health.stream_id, 2, 2);
    next.status.health.checked_ms = h.checked_ms;
    assert!(!persist(&store, &mut h, &mut s, &next).unwrap());
    assert_eq!((h.queue_drops, s.batch_id), (0, 1));
    store.connection.execute("DELETE FROM outbox", []).unwrap();
    store
        .connection
        .execute("DELETE FROM telemetry_pending", [])
        .unwrap();
    assert!(persist(&store, &mut h, &mut s, &next).unwrap());
    assert!(!h.backpressured);
    assert_eq!(h.admitted_records, 2);
}
#[test]
fn source_counter_regression_and_restart_transport_gap_are_sticky() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut d = delivery(&"a".repeat(64), 3, 1);
    d.status.health.callback_drops = 1;
    d.status.health.excluded_records = 1;
    let (mut h, mut s) = prepare(&store, &d.status.health).unwrap();
    persist(&store, &mut h, &mut s, &d).unwrap();
    assert!(!h.healthy(crate::now_ms()));
    finish(&store, &mut h, &mut s, true).unwrap();
    assert_eq!(
        (h.loss_signals, h.transport_errors, h.queue_drops),
        (1, 1, 0)
    );
    let (mut h, mut s) = prepare(&store, &d.status.health).unwrap();
    persist(&store, &mut h, &mut s, &d).unwrap();
    assert_eq!(h.loss_signals, 1);
    let before = saved(&store);
    d.status.health.callback_drops = 0;
    assert!(persist(&store, &mut h, &mut s, &d).is_err());
    assert_eq!(saved(&store), before);
}
