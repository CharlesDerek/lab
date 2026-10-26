use super::*;
use crate::{telemetry::Telemetry, EndpointEvent};

fn process(pid: u32, version: u32) -> MacosProcessProjection {
    MacosProcessProjection {
        audit_token: [501, 501, 20, 501, 20, pid, 7, version],
        parent_audit_token: [0; 8],
        responsible_audit_token: [0; 8],
        ppid: 1,
        original_ppid: 1,
        group_id: 4,
        session_id: 4,
        executable: MacosExecutable {
            path_bytes_hex: "2f746d702fff".into(),
            path_truncated: true,
        },
    }
}
fn original(kind: u32) -> MacosProcessOriginal {
    MacosProcessOriginal {
        projection_version: 1,
        stream_id: "ab".repeat(32),
        receipt_sequence: 1,
        message_version: 5,
        event_type: kind,
        action_type: 1,
        notify_result: MacosNotifyResult::Auth { result: 0 },
        time: MacosEventTime {
            seconds: 1_700_000_000,
            nanoseconds: 123_456_789,
        },
        mach_time: 99,
        mach_timebase: MacosMachTimebase {
            numerator: 125,
            denominator: 3,
        },
        seq_num: 0,
        global_seq_num: 0,
        actor: process(42, 7),
        event: match kind {
            9 => MacosProcessPayload::Exec {
                target: process(42, 8),
            },
            11 => MacosProcessPayload::Fork {
                child: process(43, 1),
            },
            15 => MacosProcessPayload::Exit {
                raw_wait_status: 7 << 8,
            },
            _ => unreachable!(),
        },
    }
}
fn envelope(event: MacosProcessEvent) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "macos_process_event".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: String::new(),
        telemetry: Some(Telemetry::MacosProcessEvent { event }),
    }
}

#[test]
fn projections_preserve_roles_raw_bytes_time_and_zero_native_sequences() {
    for (kind, change, pid) in [
        (9, MacosProcessChange::Exec, 42),
        (11, MacosProcessChange::Fork, 43),
        (15, MacosProcessChange::Exit, 42),
    ] {
        let original = original(kind);
        let event = MacosProcessEvent::from_original(original.clone()).unwrap();
        assert_eq!(event.original, original);
        assert_eq!(
            (event.change, event.pid, event.actor_pid),
            (change, pid, 42)
        );
        assert_eq!(event.time_ms, 1_700_000_000_123);
        assert_eq!(event.subject().executable.path_bytes_hex, "2f746d702fff");
        if kind == 9 {
            assert_eq!((event.actor_pid_version, event.pid_version), (7, 8));
        }
        let wire = envelope(event);
        wire.validate(wire.time_ms).unwrap();
        assert!(wire.telemetry.as_ref().unwrap().process().is_none());
        assert_eq!(
            serde_json::to_value(&wire).unwrap(),
            serde_json::to_value(
                serde_json::from_slice::<EndpointEvent>(&serde_json::to_vec(&wire).unwrap())
                    .unwrap()
            )
            .unwrap()
        );
    }
}

#[test]
fn inconsistent_native_fields_and_unsupported_profiles_refuse() {
    for case in 0..17 {
        let mut o = original(9);
        match case {
            0 => o.projection_version = 2,
            1 => o.message_version = 4,
            2 => o.stream_id = "bad".into(),
            3 => o.receipt_sequence = 0,
            4 => o.event_type = 11,
            5 => o.action_type = 0,
            6 => o.notify_result = MacosNotifyResult::Auth { result: 2 },
            7 => o.time.seconds = -1,
            8 => o.time.nanoseconds = -1,
            9 => o.time.nanoseconds = 1_000_000_000,
            10 => o.time.seconds = i64::MAX,
            11 => o.mach_timebase.numerator = 0,
            12 => o.mach_timebase.denominator = 0,
            13 => o.actor.audit_token[5] = 0,
            14 => o.actor.audit_token[5] = u32::MAX,
            15 => o.actor.executable.path_bytes_hex = "FF".into(),
            16 => o.actor.executable.path_bytes_hex = "f".into(),
            _ => unreachable!(),
        }
        assert!(MacosProcessEvent::from_original(o).is_err(), "case {case}");
    }
    let mut o = original(9);
    o.notify_result = MacosNotifyResult::Flags { flags: u32::MAX };
    MacosProcessEvent::from_original(o).unwrap();
    let mut value = serde_json::to_value(original(9)).unwrap();
    value["argv"] = serde_json::json!(["excluded"]);
    assert!(serde_json::from_value::<MacosProcessOriginal>(value).is_err());
    let encoded = serde_json::to_string(&original(9)).unwrap();
    let duplicate = encoded.replacen(
        "\"message_version\":5",
        "\"message_version\":5,\"message_version\":6",
        1,
    );
    assert!(serde_json::from_str::<MacosProcessOriginal>(&duplicate).is_err());
    let mut wrong_token = serde_json::to_value(original(9)).unwrap();
    wrong_token["actor"]["audit_token"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<MacosProcessOriginal>(wrong_token).is_err());
}

#[test]
fn exact_projection_and_envelope_bind_normalization_and_observation_identity() {
    let event = MacosProcessEvent::from_original(original(9)).unwrap();
    for case in 0..5 {
        let mut forged = event.clone();
        match case {
            0 => forged.pid += 1,
            1 => forged.actor_pid_version += 1,
            2 => forged.change = MacosProcessChange::Fork,
            3 => forged.time_ms += 1,
            4 => forged.original.actor.executable.path_truncated = false,
            _ => unreachable!(),
        }
        if case == 4 {
            assert_ne!(forged.event_id(), event.event_id());
        } else {
            assert!(forged.validate(event.time_ms).is_err());
        }
    }
    for case in 0..7 {
        let mut forged = envelope(event.clone());
        match case {
            0 => forged.id = "00".repeat(32),
            1 => forged.time_ms += 1,
            2 => forged.path = "/not-verified".into(),
            3 => forged.sha256 = "00".repeat(32),
            4 => forged.detection = "not-a-verdict".into(),
            5 => forged.kind = "process".into(),
            6 => forged.telemetry = None,
            _ => unreachable!(),
        }
        assert!(forged.validate(event.time_ms).is_err());
    }
    for case in 0..3 {
        let mut changed = event.original.clone();
        match case {
            0 => changed.stream_id = "cd".repeat(32),
            1 => changed.receipt_sequence += 1,
            2 => changed.global_seq_num += 1,
            _ => unreachable!(),
        }
        assert_ne!(
            MacosProcessEvent::from_original(changed)
                .unwrap()
                .event_id(),
            event.event_id()
        );
    }
}

#[test]
fn serialized_original_and_path_budgets_are_independent_hard_limits() {
    let mut original = original(9);
    original.actor.executable.path_bytes_hex = "ff".repeat(MAX_PATH_BYTES);
    let MacosProcessPayload::Exec { target } = &mut original.event else {
        unreachable!()
    };
    target.executable.path_bytes_hex = "00".repeat(MAX_PATH_BYTES);
    assert!(serde_json::to_vec(&original).unwrap().len() > MAX_ORIGINAL_BYTES);
    assert!(MacosProcessEvent::from_original(original.clone()).is_err());

    let MacosProcessPayload::Exec { target } = &mut original.event else {
        unreachable!()
    };
    target.executable.path_bytes_hex.clear();
    let remaining = MAX_ORIGINAL_BYTES - serde_json::to_vec(&original).unwrap().len();
    let MacosProcessPayload::Exec { target } = &mut original.event else {
        unreachable!()
    };
    target.executable.path_bytes_hex = "00".repeat(remaining / 2);
    let size = serde_json::to_vec(&original).unwrap().len();
    assert!((MAX_ORIGINAL_BYTES - 1..=MAX_ORIGINAL_BYTES).contains(&size));
    let event = MacosProcessEvent::from_original(original.clone()).unwrap();
    let mut wire = envelope(event);
    wire.detail = "\u{0000}".repeat(4096);
    wire.validate(wire.time_ms).unwrap();
    assert!(serde_json::to_vec(&wire).unwrap().len() < MAX_SERIALIZED_EVENT_BYTES);
    let MacosProcessPayload::Exec { target } = &mut original.event else {
        unreachable!()
    };
    target.executable.path_bytes_hex.push_str("00");
    assert!(MacosProcessEvent::from_original(original).is_err());

    let mut too_long = super::tests::original(15);
    too_long.actor.executable.path_bytes_hex = "00".repeat(MAX_PATH_BYTES + 1);
    assert!(serde_json::to_vec(&too_long).unwrap().len() < MAX_ORIGINAL_BYTES);
    assert!(MacosProcessEvent::from_original(too_long).is_err());
}

#[test]
fn health_requires_fresh_scope_and_zero_sticky_loss_without_pinning_transient_mutes() {
    let health = MacosProcessEventHealth {
        stream_id: "ab".repeat(32),
        state: "active".into(),
        source_policy_sha256: source_policy_sha256(),
        started_ms: 1000,
        checked_ms: 2000,
        scope_checked_ms: 2000,
        mute_snapshot_sha256: "cd".repeat(32),
        subscriptions: 3,
        received_records: 1,
        admitted_records: 1,
        ..Default::default()
    };
    assert!(health.healthy(2000));
    for subscriptions in 0..3 {
        let mut partial = health.clone();
        partial.subscriptions = subscriptions;
        assert!(!partial.healthy(2000));
    }
    for name in [
        "loss_signals",
        "rejected_records",
        "callback_drops",
        "queue_drops",
        "transport_errors",
        "global_sequence_gaps",
        "event_sequence_gaps",
        "sequence_regressions",
        "subscribed_mute_count",
    ] {
        let mut value = serde_json::to_value(&health).unwrap();
        value[name] = 1.into();
        let changed: MacosProcessEventHealth = serde_json::from_value(value).unwrap();
        assert!(!changed.healthy(2000), "{name}");
    }
    let mut invalid_counts = health.clone();
    invalid_counts.rejected_records = 1;
    assert!(invalid_counts.validate().is_err());
    invalid_counts.received_records = u64::MAX;
    invalid_counts.admitted_records = u64::MAX;
    assert!(invalid_counts.validate().is_err());
    assert!(!health.healthy(40_000));
    let mut changed = health.clone();
    changed.scope_checked_ms = 0;
    assert!(!changed.healthy(2000));
    changed = health.clone();
    changed.source_policy_sha256 = "ef".repeat(32);
    assert!(!changed.healthy(2000));
    changed = health.clone();
    changed.mute_snapshot_sha256 = "ef".repeat(32);
    assert!(changed.healthy(2000));
    let mut legacy = serde_json::to_value(crate::telemetry::CollectorHealth::default()).unwrap();
    assert!(legacy.get("macos_process_events").is_none());
    legacy["macos_process_events"] = serde_json::to_value(health).unwrap();
    assert!(
        serde_json::from_value::<crate::telemetry::CollectorHealth>(legacy)
            .unwrap()
            .macos_process_events
            .is_some()
    );
}
