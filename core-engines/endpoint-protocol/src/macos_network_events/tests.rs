use super::*;
use crate::{telemetry::Telemetry, EndpointEvent};
fn original() -> MacosNetworkOriginal {
    MacosNetworkOriginal {
        projection_version: 1,
        stream_id: "ab".repeat(32),
        receipt_sequence: 1,
        callback: MacosNetworkCallback::NewFlow,
        receipt_time: MacosNetworkReceiptTime {
            seconds: 1_800_000_000,
            nanoseconds: 123_456_789,
        },
        flow_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        direction: 0,
        socket_family: 2,
        socket_type: 1,
        socket_protocol: 6,
        local: Some(MacosNetworkEndpoint {
            address: "192.0.2.1".parse().unwrap(),
            port: 0,
            scope_id: None,
        }),
        remote: None,
        source_app_audit_token_hex: Some("01".repeat(32)),
        source_process_audit_token_hex: Some("02".repeat(32)),
    }
}
fn envelope(event: MacosNetworkEvent) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "macos_network_event".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: String::new(),
        telemetry: Some(Telemetry::MacosNetworkEvent { event }),
    }
}
#[test]
fn supported_numeric_optional_matrix_preserves_raw_roles_and_undetermined_protocol() {
    for family in [2, 30] {
        for (protocol, kind) in [(0, 1), (0, 2), (6, 1), (17, 2)] {
            for direction in 0..3 {
                for presence in 0..4 {
                    let mut o = original();
                    o.socket_family = family;
                    o.socket_protocol = protocol;
                    o.socket_type = kind;
                    o.direction = direction;
                    let endpoint = MacosNetworkEndpoint {
                        address: if family == 2 {
                            "192.0.2.1"
                        } else {
                            "2001:db8::1"
                        }
                        .parse()
                        .unwrap(),
                        port: 0,
                        scope_id: if family == 30 { Some(0) } else { None },
                    };
                    o.local = if presence & 1 != 0 {
                        Some(endpoint.clone())
                    } else {
                        None
                    };
                    o.remote = if presence & 2 != 0 {
                        Some(endpoint)
                    } else {
                        None
                    };
                    let event = MacosNetworkEvent::from_original(o.clone()).unwrap();
                    assert_eq!(event.original, o);
                    assert_eq!(event.time_ms, 1_800_000_000_123);
                    assert_eq!(
                        event.protocol == MacosNetworkProtocol::Undetermined,
                        protocol == 0
                    );
                    let wire = envelope(event);
                    wire.validate(wire.time_ms).unwrap();
                    assert!(wire.telemetry.as_ref().unwrap().process().is_none());
                    let back: EndpointEvent =
                        serde_json::from_slice(&serde_json::to_vec(&wire).unwrap()).unwrap();
                    assert_eq!(
                        serde_json::to_value(back).unwrap(),
                        serde_json::to_value(wire).unwrap()
                    );
                }
            }
        }
    }
}
#[test]
fn optional_tokens_and_scope_are_distinct_without_app_process_substitution() {
    let mut ids = std::collections::BTreeSet::new();
    for app in [None, Some("00".repeat(32)), Some("01".repeat(32))] {
        for process in [None, Some("00".repeat(32)), Some("02".repeat(32))] {
            let mut o = original();
            o.source_app_audit_token_hex = app.clone();
            o.source_process_audit_token_hex = process.clone();
            let e = MacosNetworkEvent::from_original(o.clone()).unwrap();
            assert_eq!(e.original, o);
            assert!(ids.insert(e.event_id()));
        }
    }
    let mut o = original();
    o.socket_family = 30;
    o.local.as_mut().unwrap().address = "fe80::1".parse().unwrap();
    let absent = MacosNetworkEvent::from_original(o.clone()).unwrap();
    o.local.as_mut().unwrap().scope_id = Some(0);
    let zero = MacosNetworkEvent::from_original(o.clone()).unwrap();
    o.local.as_mut().unwrap().scope_id = Some(7);
    let scoped = MacosNetworkEvent::from_original(o).unwrap();
    assert_ne!(absent.event_id(), zero.event_id());
    assert_ne!(zero.event_id(), scoped.event_id());
}
#[test]
fn unsupported_source_shapes_and_unselected_fields_refuse() {
    let valid = serde_json::to_value(original()).unwrap();
    for (pointer, value) in [
        ("/projection_version", serde_json::json!(2)),
        ("/receipt_sequence", serde_json::json!(0)),
        ("/stream_id", serde_json::json!("x")),
        (
            "/flow_id",
            serde_json::json!("01234567-89AB-cdef-0123-456789abcdef"),
        ),
        ("/direction", serde_json::json!(3)),
        ("/socket_family", serde_json::json!(1)),
        ("/socket_type", serde_json::json!(2)),
        ("/socket_protocol", serde_json::json!(1)),
        ("/receipt_time/seconds", serde_json::json!(-1)),
        ("/receipt_time/seconds", serde_json::json!(i64::MAX)),
        (
            "/receipt_time/nanoseconds",
            serde_json::json!(1_000_000_000),
        ),
        ("/receipt_time/nanoseconds", serde_json::json!(-1)),
        ("/local/address", serde_json::json!("hostname.invalid")),
        ("/local/address", serde_json::json!("2001:db8::1")),
        ("/local/scope_id", serde_json::json!(0)),
        ("/local/port", serde_json::json!(65536)),
        (
            "/source_app_audit_token_hex",
            serde_json::json!("AA".repeat(32)),
        ),
        (
            "/source_process_audit_token_hex",
            serde_json::json!("00".repeat(33)),
        ),
        ("/callback", serde_json::json!("flow_closed")),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(
            !serde_json::from_value::<MacosNetworkOriginal>(invalid)
                .map(MacosNetworkEvent::from_original)
                .is_ok_and(|r| r.is_ok()),
            "{pointer}"
        );
    }
    for field in [
        "url",
        "hostname",
        "packet_bytes",
        "bytes_inbound",
        "pid",
        "native_sequence",
    ] {
        let mut invalid = valid.clone();
        invalid[field] = serde_json::json!("excluded");
        assert!(serde_json::from_value::<MacosNetworkOriginal>(invalid).is_err());
    }
    let raw = serde_json::to_string(&valid)
        .unwrap()
        .replace("\"direction\":0", "\"direction\":0,\"direction\":0");
    assert!(serde_json::from_str::<MacosNetworkOriginal>(&raw).is_err());
}
#[test]
fn original_normalized_envelope_and_receipt_identity_are_bound() {
    let event = MacosNetworkEvent::from_original(original()).unwrap();
    for n in 0..6 {
        let mut e = event.clone();
        match n {
            0 => e.protocol = MacosNetworkProtocol::Udp,
            1 => e.family = MacosNetworkFamily::Ipv6,
            2 => e.direction = MacosNetworkDirection::Outbound,
            3 => e.local = None,
            4 => e.time_ms += 1,
            _ => e.original.socket_protocol = 17,
        };
        assert!(e.validate(event.time_ms).is_err());
    }
    let wire = envelope(event.clone());
    for n in 0..7 {
        let mut e = wire.clone();
        match n {
            0 => e.id = "f".repeat(64),
            1 => e.time_ms += 1,
            2 => e.path = "/unverified".into(),
            3 => e.sha256 = "f".repeat(64),
            4 => e.detection = "verdict".into(),
            5 => e.kind = "connection".into(),
            _ => e.telemetry = None,
        };
        assert!(e.validate(wire.time_ms).is_err());
    }
    for n in 0..4 {
        let mut o = event.original.clone();
        match n {
            0 => o.receipt_sequence += 1,
            1 => o.stream_id = "cd".repeat(32),
            2 => o.receipt_time.nanoseconds += 1,
            _ => o.flow_id = "00000000-0000-0000-0000-000000000001".into(),
        };
        assert_ne!(
            event.event_id(),
            MacosNetworkEvent::from_original(o).unwrap().event_id()
        );
    }
}
#[test]
fn aggregate_and_transport_budgets_remain_bounded() {
    let e = MacosNetworkEvent::from_original(original()).unwrap();
    assert!(serde_json::to_vec(&e.original).unwrap().len() < MAX_ORIGINAL_BYTES);
    assert!(serde_json::to_vec(&envelope(e)).unwrap().len() < MAX_SERIALIZED_EVENT_BYTES);
    let mut o = original();
    o.source_app_audit_token_hex = Some("00".repeat(MAX_ORIGINAL_BYTES));
    assert!(MacosNetworkEvent::from_original(o).is_err());
    assert_eq!(
        source_policy_sha256(),
        "faf8a5d37afe9cdc39b09b3562832b0db72b9c0b03281dd1ce701fc889f1dc64"
    );
}
#[test]
fn health_counts_local_loss_and_ack_overlap_without_inventing_kernel_counters() {
    let h = MacosNetworkEventHealth {
        stream_id: "a".repeat(64),
        state: "active".into(),
        source_policy_sha256: source_policy_sha256(),
        started_ms: 1000,
        checked_ms: 2000,
        received_records: 3,
        admitted_records: 2,
        excluded_records: 1,
        pending_records: 2,
        pending_bytes: 1000,
        ..Default::default()
    };
    h.validate().unwrap();
    assert!(h.healthy(2000));
    assert_eq!(
        serde_json::to_value(&h).unwrap()["kernel_loss_observability"],
        "unavailable"
    );
    for n in 0..11 {
        let mut bad = h.clone();
        match n {
            0 => bad.restarts = 1,
            1 => bad.loss_signals = 1,
            2 => bad.transport_errors = 1,
            3 => bad.backpressured = true,
            4 => bad.state = "stopped".into(),
            5 => bad.checked_ms = 0,
            6 => bad.source_policy_sha256 = "f".repeat(64),
            7 => {
                bad.received_records += 1;
                bad.rejected_records = 1
            }
            8 => {
                bad.received_records += 1;
                bad.callback_drops = 1
            }
            9 => {
                bad.received_records += 1;
                bad.queue_drops = 1
            }
            _ => bad.error = "fixed".into(),
        };
        assert!(!bad.healthy(2000));
    }
    for n in 0..5 {
        let mut bad = h.clone();
        match n {
            0 => bad.admitted_records = u64::MAX,
            1 => bad.rejected_records = 1,
            2 => bad.pending_records = MAX_PENDING_RECORDS + 1,
            3 => bad.pending_bytes = MAX_PENDING_BYTES + 1,
            _ => bad.pending_records = 0,
        };
        assert!(bad.validate().is_err());
    }
    let mut wrong = serde_json::to_value(h).unwrap();
    wrong["kernel_loss_observability"] = serde_json::json!("zero");
    assert!(serde_json::from_value::<MacosNetworkEventHealth>(wrong).is_err());
}
#[test]
fn omitted_health_preserves_legacy_wire() {
    let old = r#"{"mode":"disabled","last_attempt_ms":0,"last_success_ms":0,"process_count":0,"connection_count":0,"pending_changes":0,"incomplete":false,"error":""}"#;
    let health: crate::telemetry::CollectorHealth = serde_json::from_str(old).unwrap();
    assert!(health.macos_network_events.is_none());
    assert_eq!(serde_json::to_string(&health).unwrap(), old);
}
