use super::*;
use protocol::macos_authentication::*;
use protocol::macos_process_events::{
    MacosEventTime, MacosExecutable, MacosMachTimebase, MacosNotifyResult, MacosProcessProjection,
};

fn event(stream: &str, receipt_sequence: u64) -> MacosAuthentication {
    MacosAuthentication::from_original(MacosAuthenticationOriginal {
        projection_version: 1,
        stream_id: stream.into(),
        receipt_sequence,
        message_version: 5,
        event_type: 111,
        action_type: 1,
        notify_result: MacosNotifyResult::Auth { result: 0 },
        time: MacosEventTime {
            seconds: (crate::now_ms() / 1000) as i64,
            nanoseconds: 123,
        },
        mach_time: 42,
        mach_timebase: MacosMachTimebase {
            numerator: 125,
            denominator: 3,
        },
        seq_num: receipt_sequence - 1,
        global_seq_num: receipt_sequence - 1,
        event_process: MacosProcessProjection {
            audit_token: [501, 501, 20, 501, 20, 42, 7, 9],
            parent_audit_token: [0; 8],
            responsible_audit_token: [0; 8],
            ppid: 1,
            original_ppid: 1,
            group_id: 42,
            session_id: 42,
            executable: MacosExecutable {
                path_bytes_hex: "2f666978747572652fff".into(),
                path_truncated: true,
            },
        },
        success: false,
        authentication_type: 3,
        authentication: MacosAuthenticationPayload::AutoUnlock {
            username_hex: "66697874757265ff".into(),
            purpose: 2,
        },
    })
    .unwrap()
}
fn source(health: &MacosAuthenticationHealth, received: u64) -> MacosAuthenticationHealth {
    MacosAuthenticationHealth {
        stream_id: health.stream_id.clone(),
        state: "active".into(),
        source_policy_sha256: source_policy_sha256(),
        started_ms: health.started_ms,
        checked_ms: crate::now_ms(),
        scope_checked_ms: crate::now_ms(),
        subscriptions: 1,
        received_records: received,
        mute_snapshot_sha256: "b".repeat(64),
        ..Default::default()
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
        metadata(store, "macos_authentication_health")
            .unwrap()
            .unwrap(),
        metadata(store, "macos_authentication_session")
            .unwrap()
            .unwrap(),
    )
}

#[test]
fn committed_batch_replays_idempotently_even_after_outbox_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = prepare(&store).unwrap();
    let event = event(&intent.stream_id, 1);
    let source = source(&health, 1);
    assert!(persist(
        &store,
        &mut health,
        &mut intent,
        1,
        std::slice::from_ref(&event),
        &source
    )
    .unwrap());
    assert_eq!(count(&store), 2); // Subscription boundary and one retained original.
    let raw: String = store
        .connection
        .query_row(
            "SELECT payload FROM outbox WHERE id=?1",
            [event.event_id()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
        serde_json::to_value(envelope(&event)).unwrap()
    );
    store.connection.execute("DELETE FROM outbox", []).unwrap();
    let before = saved(&store);
    assert!(persist(
        &store,
        &mut health,
        &mut intent,
        1,
        std::slice::from_ref(&event),
        &source
    )
    .unwrap());
    assert_eq!(count(&store), 0);
    assert_eq!(health.admitted_records, 1);
    assert_eq!(saved(&store), before);
    let mut changed = event.clone();
    changed.original.event_process.executable.path_bytes_hex = "2fff".into();
    assert!(persist(&store, &mut health, &mut intent, 1, &[changed], &source).is_err());
    assert_eq!(saved(&store), before);
}

#[test]
fn database_failure_rolls_back_originals_health_and_ack_identity_together() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = prepare(&store).unwrap();
    let events = [event(&intent.stream_id, 1), event(&intent.stream_id, 2)];
    let source = source(&health, 2);
    let before = saved(&store);
    store.connection.execute_batch(&format!("CREATE TRIGGER refuse_second BEFORE INSERT ON telemetry_pending WHEN NEW.id='{}' BEGIN SELECT RAISE(ABORT,'fixture admission failure'); END", events[1].event_id())).unwrap();
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &source).is_err());
    assert_eq!(count(&store), 1);
    assert_eq!(health.admitted_records, 0);
    assert_eq!(intent.batch_id, 0);
    assert_eq!(saved(&store), before);
    store
        .connection
        .execute_batch("DROP TRIGGER refuse_second")
        .unwrap();
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &source).unwrap());
    assert_eq!(count(&store), 3);
}

#[test]
fn full_queue_retains_batch_without_counting_it_as_dropped_and_recovers_once() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = prepare(&store).unwrap();
    store
        .connection
        .execute("DELETE FROM telemetry_pending", [])
        .unwrap();
    for (table, amount, base) in [
        ("outbox", 3072, 100000),
        ("telemetry_pending", 8191, 200000),
    ] {
        store.connection.execute(&format!("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO {table} SELECT printf('%064x',x+{base}),json_object('id',printf('%064x',x+{base}),'time_ms',?2,'kind','inventory','path','','sha256','','detection','','detail','queue fixture','telemetry',NULL) FROM n"), rusqlite::params![amount,crate::now_ms()]).unwrap();
    }
    let events = [event(&intent.stream_id, 1), event(&intent.stream_id, 2)];
    let mut source = source(&health, 2);
    assert!(!persist(&store, &mut health, &mut intent, 1, &events, &source).unwrap());
    assert!(health.backpressured);
    assert_eq!(
        (health.admitted_records, health.queue_drops, intent.batch_id),
        (0, 0, 0)
    );
    source.received_records = 3;
    source.callback_drops = 1;
    assert!(!persist(&store, &mut health, &mut intent, 1, &events, &source).unwrap());
    assert_eq!((health.received_records, health.callback_drops), (3, 1));
    store.connection.execute("DELETE FROM outbox", []).unwrap();
    store
        .connection
        .execute("DELETE FROM telemetry_pending", [])
        .unwrap();
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &source).unwrap());
    assert_eq!(
        (
            health.admitted_records,
            health.queue_drops,
            health.received_records
        ),
        (2, 0, 3)
    );
    assert!(!health.backpressured && !health.healthy(crate::now_ms()));
    assert_eq!(count(&store), 2);
}

#[test]
fn source_and_receipt_binding_refusals_do_not_advance_durable_ack() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = prepare(&store).unwrap();
    let events = [event(&intent.stream_id, 1)];
    let source = source(&health, 1);
    let before = saved(&store);
    for invalid in [0, 2, u64::MAX] {
        assert!(persist(&store, &mut health, &mut intent, invalid, &events, &source).is_err());
    }
    let mut other = source.clone();
    other.stream_id = "f".repeat(64);
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &other).is_err());
    let mut other = source.clone();
    other.received_records = 0;
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &other).is_err());
    assert_eq!(saved(&store), before);
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &source).unwrap());
    let before = saved(&store);
    let mut other = source.clone();
    other.received_records = 0;
    assert!(persist(&store, &mut health, &mut intent, 0, &[], &other).is_err());
    assert!(persist(&store, &mut health, &mut intent, 2, &events, &source).is_err());
    assert_eq!(saved(&store), before);
}

#[test]
fn exact_capacity_admits_whole_batch_and_stopped_source_cannot_look_healthy() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = prepare(&store).unwrap();
    store
        .connection
        .execute("DELETE FROM telemetry_pending", [])
        .unwrap();
    for (table, amount, base) in [
        ("outbox", 3072, 100000),
        ("telemetry_pending", 8191, 200000),
    ] {
        store.connection.execute(&format!("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO {table} SELECT printf('%064x',x+{base}),json_object('id',printf('%064x',x+{base}),'time_ms',?2,'kind','inventory','path','','sha256','','detection','','detail','queue fixture','telemetry',NULL) FROM n"), rusqlite::params![amount,crate::now_ms()]).unwrap();
    }
    let events = [event(&intent.stream_id, 1)];
    let mut source = source(&health, 1);
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &source).unwrap());
    assert_eq!(
        (health.admitted_records, health.queue_drops, intent.batch_id),
        (1, 0, 1)
    );
    assert!(health.backpressured && !health.healthy(crate::now_ms()));
    assert_eq!(count(&store), 3072 + 8192);
    store.connection.execute("DELETE FROM outbox", []).unwrap();
    assert!(persist(&store, &mut health, &mut intent, 0, &[], &source).unwrap());
    assert!(!health.backpressured && health.healthy(crate::now_ms()));
    source.state = "stopped".into();
    source.subscriptions = 0;
    assert!(persist(&store, &mut health, &mut intent, 0, &[], &source).unwrap());
    assert_eq!(health.state, "stopped");
    assert!(!health.healthy(crate::now_ms()));
}

#[test]
fn restart_changes_stream_retains_originals_and_keeps_overlapping_gaps_distinct() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = prepare(&store).unwrap();
    let events = [event(&intent.stream_id, 1)];
    let mut source = source(&health, 1);
    source.global_sequence_gaps = 7;
    source.event_sequence_gaps = 5;
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &source).unwrap());
    let previous = intent.stream_id.clone();
    drop(store);
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = prepare(&store).unwrap();
    assert_ne!(intent.stream_id, previous);
    assert_eq!(count(&store), 3);
    assert_eq!(
        (
            health.global_sequence_gaps,
            health.event_sequence_gaps,
            health.loss_signals
        ),
        (7, 5, 1)
    );
    let source = super::tests::source(&health, 0);
    assert!(persist(&store, &mut health, &mut intent, 0, &[], &source).unwrap());
    assert_eq!(health.admitted_records, 1);
    assert!(!health.healthy(crate::now_ms()));
    assert_eq!(super::health(&store).unwrap().unwrap().state, "stopped");
}

#[test]
fn helper_pin_is_default_off_and_source_never_enters_snapshot_cache() {
    let mut config = super::super::TelemetryConfig::default();
    assert!(config.validate().is_ok());
    let serialized = serde_json::to_value(&config).unwrap();
    assert!(serialized.get("macos_authentication").is_none());
    assert!(serialized.get("macos_authentication_adapter").is_none());
    let approved = tempfile::tempdir().unwrap();
    config.macos_authentication_adapter = Some(MacosAuthenticationAdapter {
        path: approved.path().join("athernex-endpoint-native"),
        sha256: "a".repeat(64),
    });
    assert!(config.validate().is_ok());
    assert!(!config.enabled && !config.macos_authentication);
    config.macos_authentication = true;
    assert!(config.validate().is_err());
    config.enabled = true;
    assert_eq!(config.validate().is_ok(), cfg!(target_os = "macos"));
    config.macos_authentication_adapter.as_mut().unwrap().sha256 = "not-a-release-hash".into();
    assert!(config.validate().is_err());
    let telemetry = envelope(&event(&"a".repeat(64), 1)).telemetry.unwrap();
    assert!(super::super::item_key(&telemetry).is_err());
    assert!(telemetry.process().is_none());
}

#[test]
fn process_policy_or_subscription_count_cannot_admit_authentication() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = prepare(&store).unwrap();
    let events = [event(&intent.stream_id, 1)];
    let expected = source(&health, 1);
    let before = saved(&store);
    let mut wrong = expected.clone();
    wrong.source_policy_sha256 = protocol::macos_process_events::source_policy_sha256();
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &wrong).is_err());
    wrong = expected.clone();
    wrong.subscriptions = 3;
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &wrong).is_err());
    assert_eq!(saved(&store), before);
    assert_eq!(count(&store), 1);
    assert!(
        metadata::<serde_json::Value>(&store, "macos_process_events_health")
            .unwrap()
            .is_none()
    );
    assert!(
        metadata::<serde_json::Value>(&store, "macos_process_events_session")
            .unwrap()
            .is_none()
    );
    assert!(persist(&store, &mut health, &mut intent, 1, &events, &expected).unwrap());
    assert_eq!(health.admitted_records, 1);
}

#[test]
fn authentication_configuration_is_independent_of_process_pin_and_enablement() {
    let approved = tempfile::tempdir().unwrap();
    let pin = MacosAuthenticationAdapter {
        path: approved.path().join("athernex-endpoint-native"),
        sha256: "a".repeat(64),
    };
    let mut config = super::super::TelemetryConfig {
        enabled: true,
        macos_authentication: true,
        macos_process_adapter: Some(pin.clone()),
        ..Default::default()
    };
    assert!(config.validate().is_err());
    config.macos_authentication_adapter = Some(pin);
    assert_eq!(config.validate().is_ok(), cfg!(target_os = "macos"));
    assert!(!config.macos_process_events);
    config.macos_authentication = false;
    config.macos_authentication_adapter.as_mut().unwrap().sha256 = "invalid".into();
    assert!(config.validate().is_err());
}
