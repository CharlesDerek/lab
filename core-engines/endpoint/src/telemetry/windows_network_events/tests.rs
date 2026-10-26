mod transport;
use super::*;
use athernex_endpoint_protocol::windows_network_events::WindowsNetworkOriginal;

fn event(sequence: u64) -> WindowsNetworkEvent {
    // Proven v2 TCP/IPv4 receive layout: payload PID/size, network-order
    // addresses/ports, sequence and four-byte opaque connection token.
    let mut bytes = Vec::new();
    bytes.extend(42u32.to_le_bytes());
    bytes.extend(64u32.to_le_bytes());
    bytes.extend([127, 0, 0, 1]);
    bytes.extend([127, 0, 0, 1]);
    bytes.extend(80u16.to_be_bytes());
    bytes.extend(49152u16.to_be_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(123u32.to_le_bytes());
    let raw: WindowsNetworkOriginal = serde_json::from_value(serde_json::json!({
        "stream_id":"a".repeat(64), "receipt_sequence":sequence,
        "clock":{"frequency_hz":10000000,"before_qpc":10000000,"after_qpc":10000020,
            "utc_filetime_100ns":116444736000000000u64+crate::now_ms()*10000},
        "header":{"size":80,"header_type":0,"flags":320,"event_property":0,
            "thread_id":11,"process_id":99,"timestamp_qpc":10000010,
            "provider_id":"{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}",
            "descriptor":{"id":0,"version":2,"channel":0,"level":0,"opcode":11,"task":0,"keyword":0},
            "processor_time":0,"activity_id":"{00000000-0000-0000-0000-000000000000}"},
        "buffer_context":{"processor_index":0,"logger_id":1},"extended_data":[],
        "user_data_hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>()
    }))
    .unwrap();
    WindowsNetworkEvent::from_original(raw).unwrap()
}
fn state() -> (WindowsNetworkEventHealth, SessionIntent) {
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
        consumed_receipt: 0,
    };
    let health = WindowsNetworkEventHealth {
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
fn originals_health_and_receipts_rollback_together_after_database_failure() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = state();
    let original = event(1);
    persist(
        &store,
        &mut health,
        &mut intent,
        std::slice::from_ref(&original),
        0,
        1,
        Counters {
            received: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let before_health = serde_json::to_value(&health).unwrap();
    let before_intent = serde_json::to_value(&intent).unwrap();
    // Abort the last write after event insertion, queue drain and health update.
    store.connection.execute_batch("CREATE TRIGGER fixture_failure BEFORE INSERT ON telemetry_metadata WHEN NEW.key='windows_network_events_session' BEGIN SELECT RAISE(ABORT,'fixture admission failure'); END;").unwrap();
    assert!(persist(
        &store,
        &mut health,
        &mut intent,
        &[event(2)],
        0,
        2,
        Counters {
            received: 2,
            ..Default::default()
        }
    )
    .is_err());
    assert_eq!(count(&store), 1);
    assert_eq!(serde_json::to_value(&health).unwrap(), before_health);
    assert_eq!(serde_json::to_value(&intent).unwrap(), before_intent);
    let saved_health: WindowsNetworkEventHealth = metadata(&store, "windows_network_events_health")
        .unwrap()
        .unwrap();
    let saved_intent: SessionIntent = metadata(&store, "windows_network_events_session")
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(saved_health).unwrap(), before_health);
    assert_eq!(serde_json::to_value(saved_intent).unwrap(), before_intent);
    let before: String = store
        .connection
        .query_row("SELECT payload FROM outbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(before, serde_json::to_string(&envelope(&original)).unwrap());
    drop(store);
    let reopened = Store::open(temp.path()).unwrap();
    let after: String = reopened
        .connection
        .query_row("SELECT payload FROM outbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(before, after);
    assert!(!super::health(&reopened)
        .unwrap()
        .unwrap()
        .healthy(crate::now_ms()));
}

#[test]
fn repeated_conflicting_reordered_and_foreign_receipts_never_readmit() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = state();
    let original = event(1);
    persist(
        &store,
        &mut health,
        &mut intent,
        std::slice::from_ref(&original),
        0,
        1,
        Counters {
            received: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let mut conflict = original.original.clone();
    conflict.header.thread_id += 1;
    let conflict = WindowsNetworkEvent::from_original(conflict).unwrap();
    assert_ne!(original.event_id(), conflict.event_id());
    for value in [original, conflict] {
        assert!(persist(
            &store,
            &mut health,
            &mut intent,
            &[value],
            0,
            1,
            Counters {
                received: 1,
                ..Default::default()
            }
        )
        .is_err());
    }
    let mut foreign = event(2).original;
    foreign.stream_id = "b".repeat(64);
    assert!(persist(
        &store,
        &mut health,
        &mut intent,
        &[WindowsNetworkEvent::from_original(foreign).unwrap()],
        0,
        2,
        Counters {
            received: 2,
            ..Default::default()
        }
    )
    .is_err());
    assert!(persist(
        &store,
        &mut health,
        &mut intent,
        &[event(3), event(2)],
        0,
        3,
        Counters {
            received: 3,
            ..Default::default()
        }
    )
    .is_err());
    assert_eq!(intent.consumed_receipt, 1);
    assert_eq!(health.admitted_records, 1);
    assert_eq!(count(&store), 1);
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
        2,
        Counters {
            received: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(health.queue_drops, 2);
    assert_eq!(health.admitted_records, 0);
    assert_eq!(intent.consumed_receipt, 2);
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
        3,
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
        1,
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
    set_metadata(&store, "windows_network_events_health", &status).unwrap();
    assert!(!health(&store).unwrap().unwrap().healthy(crate::now_ms()));
    store
        .windows_network_events_live
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
    value.reported_pid += 1;
    assert!(persist(
        &store,
        &mut health,
        &mut intent,
        &[value],
        0,
        1,
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
        2,
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
    let durable: WindowsNetworkEventHealth = metadata(&store, "windows_network_events_health")
        .unwrap()
        .unwrap();
    assert!(durable.backpressured && !durable.healthy(crate::now_ms()));
}

#[test]
fn network_source_is_explicitly_opt_in_and_rejects_disabled_or_foreign_platforms() {
    let default = super::super::TelemetryConfig::default();
    assert!(!default.windows_network_events);
    let old: super::super::TelemetryConfig =
        serde_json::from_value(serde_json::json!({"enabled":true,"interval_secs":30})).unwrap();
    assert!(!old.windows_network_events);
    let mut configured = super::super::TelemetryConfig {
        windows_network_events: true,
        ..default
    };
    assert!(configured.validate().is_err());
    configured.enabled = true;
    assert_eq!(configured.validate().is_ok(), cfg!(windows));
}

#[test]
fn a_new_subscription_keeps_prior_losses_and_commits_its_boundary_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (_, mut first) = state();
    first.phase = "prepared".into();
    let (mut health, mut intent) = begin_subscription(&store, None, first).unwrap();
    intent.phase = "active".into();
    persist(
        &store,
        &mut health,
        &mut intent,
        &[event(1)],
        0,
        1,
        Counters {
            received: 2,
            callback_drops: 1,
            events_lost: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let mut next = intent.clone();
    next.stream_id = "b".repeat(64);
    next.session_guid = "{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}".into();
    next.phase = "prepared".into();
    next.consumed_receipt = 0;
    next.counters = Counters::default();
    let before = serde_json::to_value(&health).unwrap();
    store.connection.execute_batch("CREATE TRIGGER fixture_boundary_failure BEFORE INSERT ON telemetry_pending BEGIN SELECT RAISE(ABORT,'fixture boundary failure'); END;").unwrap();
    assert!(begin_subscription(&store, Some(health.clone()), next.clone()).is_err());
    let durable: WindowsNetworkEventHealth = metadata(&store, "windows_network_events_health")
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(durable).unwrap(), before);
    store
        .connection
        .execute_batch("DROP TRIGGER fixture_boundary_failure")
        .unwrap();
    let (health, intent) = begin_subscription(&store, Some(health), next).unwrap();
    assert_eq!(health.subscriptions, 2);
    assert_eq!(health.loss_signals, 1);
    assert_eq!(health.events_lost, 2);
    assert_eq!(health.callback_drops, 1);
    assert_eq!(health.admitted_records, 1);
    assert_eq!(health.stream_id, intent.stream_id);
    assert!(!health.healthy(crate::now_ms()));
    assert!(begin_subscription(&store, Some(health.clone()), intent).is_err());
}

#[test]
fn rejected_layouts_are_counted_without_admitting_or_reusing_their_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (mut health, mut intent) = state();
    persist(
        &store,
        &mut health,
        &mut intent,
        &[],
        1,
        1,
        Counters {
            received: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(health.rejected_records, 1);
    assert_eq!(count(&store), 0);
    assert_eq!(intent.consumed_receipt, 1);
    assert!(!health.healthy(crate::now_ms()));
    persist(
        &store,
        &mut health,
        &mut intent,
        &[event(2)],
        0,
        2,
        Counters {
            received: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(health.rejected_records, 1);
    assert_eq!(health.admitted_records, 1);
    assert!(!health.healthy(crate::now_ms()));
}
