use super::*;
use crate::{telemetry::Telemetry, EndpointEvent};

fn process(pid: u32) -> MacosProcessProjection {
    MacosProcessProjection {
        audit_token: [501, 501, 20, 501, 20, pid, 7, 3],
        parent_audit_token: [0; 8],
        responsible_audit_token: [0; 8],
        ppid: 1,
        original_ppid: 1,
        group_id: 2,
        session_id: 2,
        executable: crate::macos_process_events::MacosExecutable {
            path_bytes_hex: "2f66697874757265ff".into(),
            path_truncated: true,
        },
    }
}
fn original(kind: u32) -> MacosAuthenticationOriginal {
    let instigator = Some(process(43));
    MacosAuthenticationOriginal {
        projection_version: 1,
        stream_id: "ab".repeat(32),
        receipt_sequence: 1,
        message_version: 5,
        event_type: 111,
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
        event_process: process(42),
        success: false,
        authentication_type: kind,
        authentication: match kind {
            0 => MacosAuthenticationPayload::OpenDirectory {
                instigator,
                record_type_hex: "5573657273".into(),
                record_name_hex: "0066ff".into(),
                node_name_hex: "2f4c6f63616c2f44656661756c74".into(),
                db_path_hex: None,
            },
            1 => MacosAuthenticationPayload::TouchId {
                instigator,
                mode: 1,
                has_uid: true,
                uid: Some(501),
            },
            2 => MacosAuthenticationPayload::Token {
                instigator,
                pubkey_hash_hex: "abcd".into(),
                token_id_hex: "746f6b656e".into(),
                kerberos_principal_hex: None,
            },
            3 => MacosAuthenticationPayload::AutoUnlock {
                username_hex: "75736572".into(),
                purpose: 2,
            },
            _ => unreachable!(),
        },
    }
}
fn envelope(event: MacosAuthentication) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "authentication".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: String::new(),
        telemetry: Some(Telemetry::MacosAuthentication { event }),
    }
}
#[test]
fn four_mechanisms_preserve_roles_bytes_time_and_report_only_result() {
    for kind in 0..4 {
        for success in [false, true] {
            let mut source = original(kind);
            source.success = success;
            let event = MacosAuthentication::from_original(source.clone()).unwrap();
            event.validate(event.time_ms).unwrap();
            assert_eq!(event.original, source);
            assert_eq!(event.reported_success, success);
            assert_eq!(event.service_outcome(), None);
            assert_eq!(event.time_ms, 1_700_000_000_123);
            assert_eq!(event.original.event_process.pid(), 42);
            if let Some(instigator) = event.original.authentication.instigator() {
                assert_eq!(instigator.pid(), 43);
            }
            let wire = envelope(event);
            wire.validate(wire.time_ms).unwrap();
            assert!(wire.telemetry.as_ref().unwrap().process().is_none());
            let roundtrip: EndpointEvent =
                serde_json::from_slice(&serde_json::to_vec(&wire).unwrap()).unwrap();
            assert_eq!(
                serde_json::to_value(roundtrip).unwrap(),
                serde_json::to_value(wire).unwrap()
            );
        }
    }
}
#[test]
fn touchid_presence_depends_only_on_has_uid_not_mode_or_result() {
    for success in [false, true] {
        for mode in [0, 1] {
            for uid in [None, Some(0), Some(501), Some(u32::MAX)] {
                let mut source = original(1);
                source.success = success;
                source.authentication = MacosAuthenticationPayload::TouchId {
                    instigator: None,
                    mode,
                    has_uid: uid.is_some(),
                    uid,
                };
                let accepted = MacosAuthentication::from_original(source.clone()).unwrap();
                assert_eq!(accepted.original, source);
                let MacosAuthenticationPayload::TouchId { has_uid, .. } =
                    &mut source.authentication
                else {
                    unreachable!()
                };
                *has_uid = !*has_uid;
                assert!(MacosAuthentication::from_original(source).is_err());
            }
        }
    }
    let mut source = original(1);
    let MacosAuthenticationPayload::TouchId { mode, .. } = &mut source.authentication else {
        unreachable!()
    };
    *mode = 2;
    assert!(MacosAuthentication::from_original(source).is_err());
}
#[test]
fn optional_null_empty_and_raw_non_utf8_tokens_remain_distinct() {
    for kind in [0, 2] {
        let absent = MacosAuthentication::from_original(original(kind)).unwrap();
        let mut source = absent.original.clone();
        let field = match &mut source.authentication {
            MacosAuthenticationPayload::OpenDirectory { db_path_hex, .. } => db_path_hex,
            MacosAuthenticationPayload::Token {
                kerberos_principal_hex,
                ..
            } => kerberos_principal_hex,
            _ => unreachable!(),
        };
        *field = Some(String::new());
        let empty = MacosAuthentication::from_original(source.clone()).unwrap();
        assert_ne!(absent.event_id(), empty.event_id());
        let field = match &mut source.authentication {
            MacosAuthenticationPayload::OpenDirectory { db_path_hex, .. } => db_path_hex,
            MacosAuthenticationPayload::Token {
                kerberos_principal_hex,
                ..
            } => kerberos_principal_hex,
            _ => unreachable!(),
        };
        *field = Some("00fffe".into());
        let bytes = MacosAuthentication::from_original(source).unwrap();
        assert_ne!(bytes.event_id(), empty.event_id());
        assert_eq!(
            serde_json::from_slice::<MacosAuthentication>(&serde_json::to_vec(&bytes).unwrap())
                .unwrap(),
            bytes
        );
    }
}
#[test]
fn unsupported_source_shapes_types_and_duplicate_fields_refuse() {
    let valid = serde_json::to_value(original(0)).unwrap();
    for (pointer, replacement) in [
        ("/projection_version", serde_json::json!(2)),
        ("/message_version", serde_json::json!(4)),
        ("/stream_id", serde_json::json!("not-a-stream")),
        ("/receipt_sequence", serde_json::json!(0)),
        ("/event_type", serde_json::json!(9)),
        ("/action_type", serde_json::json!(0)),
        ("/notify_result/result", serde_json::json!(2)),
        ("/time/seconds", serde_json::json!(-1)),
        ("/time/nanoseconds", serde_json::json!(1_000_000_000)),
        ("/mach_timebase/numerator", serde_json::json!(0)),
        ("/mach_timebase/denominator", serde_json::json!(0)),
        ("/authentication_type", serde_json::json!(4)),
        ("/event_process/audit_token/5", serde_json::json!(0)),
        (
            "/authentication/instigator/audit_token/5",
            serde_json::json!(0),
        ),
        ("/authentication/type", serde_json::json!("unknown")),
        ("/authentication/record_name_hex", serde_json::json!("FF")),
        ("/authentication/node_name_hex", serde_json::json!("0")),
        ("/event_process/audit_token", serde_json::json!([1, 2])),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            !serde_json::from_value::<MacosAuthenticationOriginal>(invalid)
                .map(MacosAuthentication::from_original)
                .is_ok_and(|r| r.is_ok()),
            "{pointer}"
        );
    }
    let mut unknown = valid.clone();
    unknown["authentication"]["password"] = serde_json::json!("excluded");
    assert!(serde_json::from_value::<MacosAuthenticationOriginal>(unknown).is_err());
    let raw = serde_json::to_string(&valid).unwrap().replace(
        "\"message_version\":5",
        "\"message_version\":5,\"message_version\":5",
    );
    assert!(serde_json::from_str::<MacosAuthenticationOriginal>(&raw).is_err());
    let mut invalid = original(3);
    let MacosAuthenticationPayload::AutoUnlock { purpose, .. } = &mut invalid.authentication else {
        unreachable!()
    };
    *purpose = 0;
    assert!(MacosAuthentication::from_original(invalid).is_err());
}
#[test]
fn normalized_fields_envelope_and_receipt_identity_are_bound() {
    let event = MacosAuthentication::from_original(original(0)).unwrap();
    for mutation in 0..4 {
        let mut invalid = event.clone();
        match mutation {
            0 => invalid.reported_success = !invalid.reported_success,
            1 => invalid.mechanism = MacosAuthenticationMechanism::Token,
            2 => invalid.time_ms += 1,
            _ => invalid.original.authentication_type = 1,
        }
        assert!(invalid.validate(event.time_ms).is_err());
    }
    let valid = envelope(event.clone());
    for mutation in 0..7 {
        let mut invalid = valid.clone();
        match mutation {
            0 => invalid.id = "f".repeat(64),
            1 => invalid.time_ms += 1,
            2 => invalid.path = "/not-verified".into(),
            3 => invalid.sha256 = "f".repeat(64),
            4 => invalid.detection = "not-a-verdict".into(),
            5 => invalid.kind = "process".into(),
            _ => invalid.telemetry = None,
        }
        assert!(invalid.validate(event.time_ms).is_err());
    }
    for mutation in 0..4 {
        let mut source = event.original.clone();
        match mutation {
            0 => source.stream_id = "cd".repeat(32),
            1 => source.receipt_sequence += 1,
            2 => source.success = !source.success,
            _ => source.seq_num += 1,
        }
        assert_ne!(
            MacosAuthentication::from_original(source)
                .unwrap()
                .event_id(),
            event.event_id()
        );
    }
}
#[test]
fn token_paths_and_serialized_original_have_independent_hard_limits() {
    let mut source = original(3);
    let MacosAuthenticationPayload::AutoUnlock { username_hex, .. } = &mut source.authentication
    else {
        unreachable!()
    };
    *username_hex = "ff".repeat(MAX_TOKEN_BYTES);
    MacosAuthentication::from_original(source.clone()).unwrap();
    let MacosAuthenticationPayload::AutoUnlock { username_hex, .. } = &mut source.authentication
    else {
        unreachable!()
    };
    username_hex.push_str("ff");
    assert!(MacosAuthentication::from_original(source).is_err());

    let mut source = original(0);
    source.event_process.executable.path_bytes_hex = "00".repeat(MAX_PATH_BYTES);
    let MacosAuthenticationPayload::OpenDirectory {
        instigator,
        db_path_hex,
        ..
    } = &mut source.authentication
    else {
        unreachable!()
    };
    instigator
        .as_mut()
        .unwrap()
        .executable
        .path_bytes_hex
        .clear();
    *db_path_hex = Some(String::new());
    let remaining = MAX_ORIGINAL_BYTES - serde_json::to_vec(&source).unwrap().len();
    let MacosAuthenticationPayload::OpenDirectory { db_path_hex, .. } = &mut source.authentication
    else {
        unreachable!()
    };
    *db_path_hex = Some("ff".repeat(remaining / 2));
    let size = serde_json::to_vec(&source).unwrap().len();
    assert!((MAX_ORIGINAL_BYTES - 1..=MAX_ORIGINAL_BYTES).contains(&size));
    let mut wire = envelope(MacosAuthentication::from_original(source.clone()).unwrap());
    wire.detail = "\u{0000}".repeat(4096);
    wire.validate(wire.time_ms).unwrap();
    assert!(serde_json::to_vec(&wire).unwrap().len() < MAX_SERIALIZED_EVENT_BYTES);
    let MacosAuthenticationPayload::OpenDirectory { db_path_hex, .. } = &mut source.authentication
    else {
        unreachable!()
    };
    db_path_hex.as_mut().unwrap().push_str("ff");
    assert!(MacosAuthentication::from_original(source).is_err());
    let mut source = original(0);
    let MacosAuthenticationPayload::OpenDirectory { db_path_hex, .. } = &mut source.authentication
    else {
        unreachable!()
    };
    *db_path_hex = Some("ff".repeat(MAX_PATH_BYTES + 1));
    assert!(MacosAuthentication::from_original(source).is_err());
}
#[test]
fn independent_health_requires_one_subscription_fresh_scope_and_zero_sticky_gaps() {
    let valid = MacosAuthenticationHealth {
        stream_id: "a".repeat(64),
        state: "active".into(),
        source_policy_sha256: source_policy_sha256(),
        started_ms: 1000,
        checked_ms: 2000,
        subscriptions: 1,
        received_records: 1,
        admitted_records: 1,
        scope_checked_ms: 2000,
        mute_snapshot_sha256: "b".repeat(64),
        ..Default::default()
    };
    assert!(valid.healthy(2000));
    for field in [
        "subscriptions",
        "callback_drops",
        "queue_drops",
        "transport_errors",
        "global_sequence_gaps",
        "event_sequence_gaps",
        "sequence_regressions",
        "loss_signals",
        "rejected_records",
        "subscribed_mute_count",
    ] {
        let mut value = serde_json::to_value(&valid).unwrap();
        value[field] = serde_json::json!(if field == "subscriptions" { 0 } else { 1 });
        let invalid: MacosAuthenticationHealth = serde_json::from_value(value).unwrap();
        assert!(!invalid.healthy(2000), "{field}");
    }
    let mut changed = valid.clone();
    changed.mute_snapshot_sha256 = "c".repeat(64);
    assert!(changed.healthy(2000));
    changed.source_policy_sha256 = crate::macos_process_events::source_policy_sha256();
    assert!(!changed.healthy(2000));
    let mut stale = valid.clone();
    stale.scope_checked_ms = 1000;
    assert!(!stale.healthy(31_001));
    let mut stopped = valid.clone();
    stopped.state = "stopped".into();
    stopped.subscriptions = 0;
    assert!(!stopped.healthy(2000));
    let mut invalid = valid.clone();
    invalid.rejected_records = 1;
    assert!(invalid.validate().is_err());
    invalid.received_records = u64::MAX;
    invalid.admitted_records = u64::MAX;
    assert!(invalid.validate().is_err());
    let mut restored = valid.clone();
    restored.loss_signals = 1;
    restored.error.clear();
    assert!(!restored.healthy(2000));
    let mut extra = valid;
    extra.subscriptions = 2;
    assert!(extra.validate().is_err());
}
#[test]
fn absent_authentication_health_keeps_legacy_wire_and_process_policy_independent() {
    let health = crate::telemetry::CollectorHealth::default();
    assert_eq!(serde_json::to_string(&health).unwrap(), "{\"mode\":\"\",\"last_attempt_ms\":0,\"last_success_ms\":0,\"process_count\":0,\"connection_count\":0,\"pending_changes\":0,\"incomplete\":false,\"error\":\"\"}");
    assert_ne!(
        source_policy_sha256(),
        crate::macos_process_events::source_policy_sha256()
    );
}
