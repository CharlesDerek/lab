use super::*;
use athernex_endpoint_protocol::windows_process_events::WindowsProcessOriginal;

fn event(sequence: u64) -> WindowsProcessEvent {
    let mut bytes = Vec::new();
    bytes.extend(123u64.to_le_bytes());
    for value in [42u32, 24, 0, 0] {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(0u64.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(0u32.to_le_bytes()); // Explicit absent WBEM SID.
    bytes.extend(b"fixture.exe\0");
    for value in ["fixture", "", ""] {
        bytes.extend(value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
    }
    let raw: WindowsProcessOriginal = serde_json::from_value(serde_json::json!({
        "stream_id":"a".repeat(64), "receipt_sequence":sequence,
        "clock":{"frequency_hz":10000000,"before_qpc":10000000,"after_qpc":10000020,
            "utc_filetime_100ns":116444736000000000u64+crate::now_ms()*10000},
        "header":{"size":80,"header_type":0,"flags":320,"event_property":0,
            "thread_id":11,"process_id":99,"timestamp_qpc":10000010,
            "provider_id":"{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}",
            "descriptor":{"id":0,"version":4,"channel":0,"level":0,"opcode":1,"task":0,"keyword":0},
            "processor_time":0,"activity_id":"{00000000-0000-0000-0000-000000000000}"},
        "buffer_context":{"processor_index":0,"logger_id":1},"extended_data":[],
        "user_data_hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>()
    }))
    .unwrap();
    WindowsProcessEvent::from_original(raw).unwrap()
}
fn state() -> (WindowsProcessEventHealth, SessionIntent) {
    let now = crate::now_ms();
    let intent = SessionIntent {
        stream_id: "a".repeat(64),
        session_name: "fixture".into(),
        session_guid: "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}".into(),
        owner_pid: 123,
        owner_created: 1,
        phase: "active".into(),
        started_ms: now,
        counters: Counters::default(),
    };
    let health = WindowsProcessEventHealth {
        stream_id: intent.stream_id.clone(),
        state: "active".into(),
        started_ms: now,
        checked_ms: now,
        subscriptions: 1,
        ..Default::default()
    };
    (health, intent)
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

#[test]
fn admission_and_health_rollback_together_on_duplicate_original() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = state();
    let value = event(1);
    persist(
        &store,
        &mut health,
        &mut intent,
        std::slice::from_ref(&value),
        0,
        Counters {
            received: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let before = serde_json::to_value(&health).unwrap();
    // Force a database admission failure after the first insert of this batch.
    let duplicate = event(2);
    assert!(persist(
        &store,
        &mut health,
        &mut intent,
        &[duplicate.clone(), duplicate],
        0,
        Counters {
            received: 3,
            ..Default::default()
        }
    )
    .is_err());
    assert_eq!(count(&store), 1);
    assert_eq!(serde_json::to_value(&health).unwrap(), before);
    let durable: WindowsProcessEventHealth = metadata(&store, "windows_process_events_health")
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(durable).unwrap(), before);
    assert_eq!(intent.counters.received, 1);
    let saved: String = store
        .connection
        .query_row("SELECT payload FROM outbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&saved).unwrap(),
        serde_json::to_value(envelope(&value)).unwrap()
    );
}

#[test]
fn full_delivery_queue_counts_unreplayable_drops_without_partial_admission() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = state();
    for (table, amount, base) in [
        ("outbox", 3072, 100000),
        ("telemetry_pending", 8191, 200000),
    ] {
        store.connection.execute(&format!("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO {table} SELECT printf('%064x',x+{base}),json_object('id',printf('%064x',x+{base}),'time_ms',?2,'kind','inventory','path','','sha256','','detection','','detail','queue fixture','telemetry',NULL) FROM n"),rusqlite::params![amount,crate::now_ms()]).unwrap();
    }
    persist(
        &store,
        &mut health,
        &mut intent,
        &[event(1), event(2)],
        0,
        Counters {
            received: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(health.queue_drops, 2);
    assert_eq!(health.admitted_records, 0);
    assert!(health.backpressured && !health.healthy(crate::now_ms()));
    assert_eq!(count(&store), 3072 + 8191);
    store.connection.execute("DELETE FROM outbox", []).unwrap();
    store
        .connection
        .execute("DELETE FROM telemetry_pending", [])
        .unwrap();
    persist(
        &store,
        &mut health,
        &mut intent,
        &[event(3)],
        0,
        Counters {
            received: 3,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(health.queue_drops, 2);
    assert_eq!(health.admitted_records, 1);
    assert!(!health.backpressured && !health.healthy(crate::now_ms()));
}

#[test]
fn counter_regressions_and_native_loss_remain_sticky_after_source_recovers() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = state();
    persist(
        &store,
        &mut health,
        &mut intent,
        &[],
        0,
        Counters {
            received: 10,
            events_lost: 2,
            ..Default::default()
        },
    )
    .unwrap();
    persist(
        &store,
        &mut health,
        &mut intent,
        &[],
        1,
        Counters {
            received: 1,
            events_lost: 0,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(health.loss_signals, 2);
    assert_eq!(health.events_lost, 2);
    assert_eq!(health.received_records, 11);
    assert_eq!(health.rejected_records, 1);
    persist(
        &store,
        &mut health,
        &mut intent,
        &[],
        0,
        Counters {
            received: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!health.healthy(crate::now_ms()));
    assert_eq!(health.loss_signals, 2);
}

#[test]
fn durable_health_cannot_claim_a_dead_collector_is_live() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (status, _) = state();
    set_metadata(&store, "windows_process_events_health", &status).unwrap();
    assert!(!health(&store).unwrap().unwrap().healthy(crate::now_ms()));
    store
        .windows_process_events_live
        .store(true, Ordering::Release);
    assert!(health(&store).unwrap().unwrap().healthy(crate::now_ms()));
}

#[test]
fn ownership_intent_rejects_path_guid_identity_and_phase_substitution() {
    let (_, original) = state();
    assert!(original.validate("fixture").is_ok());
    assert!(original.validate("other-state").is_err());
    for field in [
        "stream_id",
        "session_guid",
        "owner_pid",
        "owner_created",
        "phase",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = match field {
            "owner_pid" | "owner_created" => serde_json::json!(0),
            _ => serde_json::json!("invalid"),
        };
        let changed: SessionIntent = serde_json::from_value(value).unwrap();
        assert!(changed.validate("fixture").is_err());
    }
}

#[test]
fn malformed_normalized_record_never_advances_durable_receipt_counts() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = state();
    let mut value = event(1);
    value.pid += 1;
    assert!(persist(
        &store,
        &mut health,
        &mut intent,
        &[value],
        0,
        Counters {
            received: 1,
            ..Default::default()
        }
    )
    .is_err());
    assert_eq!(count(&store), 0);
    assert_eq!(health.received_records, 0);
    assert_eq!(intent.counters.received, 0);
}

#[test]
fn exact_fill_and_health_are_one_atomic_backpressure_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = state();
    for (table, amount, base) in [
        ("outbox", 3072, 300000),
        ("telemetry_pending", 8190, 400000),
    ] {
        store.connection.execute(&format!("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO {table} SELECT printf('%064x',x+{base}),json_object('id',printf('%064x',x+{base}),'time_ms',?2,'kind','inventory','path','','sha256','','detection','','detail','queue fixture','telemetry',NULL) FROM n"),rusqlite::params![amount,crate::now_ms()]).unwrap();
    }
    persist(
        &store,
        &mut health,
        &mut intent,
        &[event(1), event(2)],
        0,
        Counters {
            received: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(health.admitted_records, 2);
    assert_eq!(health.queue_drops, 0);
    assert_eq!(count(&store), 3072 + 8192);
    assert!(health.backpressured && !health.healthy(crate::now_ms()));
    let durable: WindowsProcessEventHealth = metadata(&store, "windows_process_events_health")
        .unwrap()
        .unwrap();
    assert!(durable.backpressured && !durable.healthy(crate::now_ms()));
}

#[test]
fn process_source_is_explicitly_opt_in_and_rejects_disabled_or_foreign_platforms() {
    let default = super::super::TelemetryConfig::default();
    assert!(!default.windows_process_events);
    let old: super::super::TelemetryConfig =
        serde_json::from_value(serde_json::json!({"enabled":true,"interval_secs":30})).unwrap();
    assert!(!old.windows_process_events);
    let mut configured = super::super::TelemetryConfig {
        windows_process_events: true,
        ..default
    };
    assert!(configured.validate().is_err());
    configured.enabled = true;
    assert_eq!(configured.validate().is_ok(), cfg!(windows));
}
