use super::*;
use crate::{telemetry::Telemetry, EndpointEvent};

const NOW: u64 = 1_700_000_000_000;
const CASES: [(
    &str,
    u8,
    usize,
    WindowsNetworkOperation,
    WindowsNetworkFamily,
); 14] = [
    (
        TCP_PROVIDER,
        10,
        36,
        WindowsNetworkOperation::Send,
        WindowsNetworkFamily::Ipv4,
    ),
    (
        TCP_PROVIDER,
        11,
        28,
        WindowsNetworkOperation::Receive,
        WindowsNetworkFamily::Ipv4,
    ),
    (
        TCP_PROVIDER,
        12,
        44,
        WindowsNetworkOperation::Connect,
        WindowsNetworkFamily::Ipv4,
    ),
    (
        TCP_PROVIDER,
        13,
        28,
        WindowsNetworkOperation::Disconnect,
        WindowsNetworkFamily::Ipv4,
    ),
    (
        TCP_PROVIDER,
        15,
        44,
        WindowsNetworkOperation::Accept,
        WindowsNetworkFamily::Ipv4,
    ),
    (
        TCP_PROVIDER,
        26,
        60,
        WindowsNetworkOperation::Send,
        WindowsNetworkFamily::Ipv6,
    ),
    (
        TCP_PROVIDER,
        27,
        52,
        WindowsNetworkOperation::Receive,
        WindowsNetworkFamily::Ipv6,
    ),
    (
        TCP_PROVIDER,
        28,
        68,
        WindowsNetworkOperation::Connect,
        WindowsNetworkFamily::Ipv6,
    ),
    (
        TCP_PROVIDER,
        29,
        52,
        WindowsNetworkOperation::Disconnect,
        WindowsNetworkFamily::Ipv6,
    ),
    (
        TCP_PROVIDER,
        31,
        68,
        WindowsNetworkOperation::Accept,
        WindowsNetworkFamily::Ipv6,
    ),
    (
        UDP_PROVIDER,
        10,
        28,
        WindowsNetworkOperation::Send,
        WindowsNetworkFamily::Ipv4,
    ),
    (
        UDP_PROVIDER,
        11,
        28,
        WindowsNetworkOperation::Receive,
        WindowsNetworkFamily::Ipv4,
    ),
    (
        UDP_PROVIDER,
        26,
        52,
        WindowsNetworkOperation::Send,
        WindowsNetworkFamily::Ipv6,
    ),
    (
        UDP_PROVIDER,
        27,
        52,
        WindowsNetworkOperation::Receive,
        WindowsNetworkFamily::Ipv6,
    ),
];
fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn fixture(index: usize) -> WindowsNetworkOriginal {
    let (provider, opcode, length, _, family) = CASES[index];
    let mut bytes = vec![0x44, 0x33, 0x22, 0x11, 0x78, 0x56, 0x34, 0x12];
    if family == WindowsNetworkFamily::Ipv4 {
        bytes.extend([203, 0, 113, 8, 192, 0, 2, 9]);
    } else {
        bytes.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        bytes.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    }
    bytes.extend([0x01, 0xbb, 0xc3, 0x50]); // Destination443, source50000, network order.
    bytes.resize(length - 8, 0xa5); // Opaque native options remain original-only.
    bytes.extend([0xfe, 0xdc, 0xba, 0x98, 0x67, 0x45, 0x23, 0x01]);
    WindowsNetworkOriginal {
        stream_id: "a".repeat(64),
        receipt_sequence: 1,
        clock: QpcClock {
            frequency_hz: 1_000_000,
            before_qpc: 1_000_000,
            after_qpc: 1_000_000,
            utc_filetime_100ns: 116_444_736_000_000_000 + NOW * 10_000,
        },
        header: EventHeader {
            size: 80 + length as u16,
            header_type: 0,
            flags: 0x140,
            event_property: 0,
            thread_id: 91,
            process_id: 99,
            timestamp_qpc: 1_000_000,
            provider_id: provider.into(),
            descriptor: EventDescriptor {
                id: 0,
                version: 2,
                channel: 0,
                level: 0,
                opcode,
                task: 0,
                keyword: 0,
            },
            processor_time: 0,
            activity_id: "{00000000-0000-0000-0000-000000000000}".into(),
        },
        buffer_context: BufferContext {
            processor_index: 3,
            logger_id: 17,
        },
        extended_data: Vec::new(),
        user_data_hex: encode(&bytes),
    }
}
fn envelope(event: WindowsNetworkEvent) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "windows_network_event".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: "Controlled original network report".into(),
        telemetry: Some(Telemetry::WindowsNetworkEvent { event }),
    }
}

#[test]
fn fourteen_templates_preserve_reporting_scope_endianness_and_opaque_fields() {
    for (index, &(provider, _, _, operation, family)) in CASES.iter().enumerate() {
        let original = fixture(index);
        let event = WindowsNetworkEvent::from_original(original.clone()).unwrap();
        assert_eq!(event.original, original);
        assert_eq!(event.operation, operation);
        assert_eq!(event.family, family);
        assert_eq!(
            event.protocol,
            if provider == TCP_PROVIDER {
                WindowsNetworkProtocol::Tcp
            } else {
                WindowsNetworkProtocol::Udp
            }
        );
        assert_eq!(event.reported_pid, 0x11223344);
        assert_ne!(event.reported_pid, event.original.header.process_id);
        assert_eq!(event.reported_size, 0x12345678);
        assert_eq!(event.header_pointer_bits, 64);
        let (source, destination) = if family == WindowsNetworkFamily::Ipv4 {
            ("192.0.2.9:50000", "203.0.113.8:443")
        } else {
            ("[2001:db8::9]:50000", "[2001:db8::8]:443")
        };
        assert_eq!(event.source, source.parse().unwrap());
        assert_eq!(event.destination, destination.parse().unwrap());
        assert_eq!(event.time_ms, NOW);
        assert_eq!(event.time_uncertainty_ms, 1);
        assert!(event.validate(NOW).is_ok());
        let envelope = envelope(event);
        assert!(envelope.telemetry.as_ref().unwrap().process().is_none());
        assert!(envelope.validate(NOW).is_ok());
        let serialized = serde_json::to_string(&envelope).unwrap();
        assert!(!serialized.contains("connid"));
        assert!(!serialized.contains("process_start"));
        assert!(!serialized.contains("firewall"));
        let decoded: EndpointEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serde_json::to_string(&decoded).unwrap(), serialized);
    }
}

#[test]
fn exact_native_layout_refuses_every_truncation_tail_and_unverified_family() {
    for index in 0..CASES.len() {
        let original = fixture(index);
        for length in 0..original.user_data_hex.len() / 2 {
            let mut changed = original.clone();
            changed.user_data_hex.truncate(length * 2);
            assert!(WindowsNetworkEvent::from_original(changed).is_err());
        }
        for tail in ["0", "00", "00000000", "0000000000000000"] {
            let mut changed = original.clone();
            changed.user_data_hex.push_str(tail);
            assert!(WindowsNetworkEvent::from_original(changed).is_err());
        }
        for flags in [0, 0x40, 0x100, 0x120, 0x160, 0x144, 0x148] {
            let mut changed = original.clone();
            changed.header.flags = flags;
            assert!(WindowsNetworkEvent::from_original(changed).is_err());
        }
        for version in [0, 1, 3, 4, u8::MAX] {
            let mut changed = original.clone();
            changed.header.descriptor.version = version;
            assert!(WindowsNetworkEvent::from_original(changed).is_err());
        }
        for opcode in [0, 14, 16, 17, 18, 32, 255] {
            let mut changed = original.clone();
            changed.header.descriptor.opcode = opcode;
            assert!(WindowsNetworkEvent::from_original(changed).is_err());
        }
    }
    let mut failure = fixture(0);
    failure.header.descriptor.opcode = 17;
    failure.user_data_hex = "02000500".into();
    assert!(WindowsNetworkEvent::from_original(failure).is_err());
    let mut zero_context = fixture(0);
    zero_context
        .user_data_hex
        .replace_range(0..16, "0000000000000000");
    let event = WindowsNetworkEvent::from_original(zero_context).unwrap();
    assert_eq!((event.reported_pid, event.reported_size), (0, 0));
}

#[test]
fn normalized_forgery_and_original_identity_cannot_cross_envelope_boundary() {
    let event = WindowsNetworkEvent::from_original(fixture(0)).unwrap();
    let mut variants = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut v = event.clone();
            v.$field = $value;
            variants.push(v);
        }};
    }
    changed!(reported_pid, 99);
    changed!(reported_size, 0);
    changed!(source, "192.0.2.9:443".parse().unwrap());
    changed!(destination, "203.0.113.8:50000".parse().unwrap());
    changed!(operation, WindowsNetworkOperation::Receive);
    changed!(protocol, WindowsNetworkProtocol::Udp);
    changed!(family, WindowsNetworkFamily::Ipv6);
    changed!(header_pointer_bits, 32);
    changed!(time_ms, NOW + 1);
    changed!(time_uncertainty_ms, 100);
    for changed in variants {
        assert!(changed.validate(NOW).is_err());
    }
    let base = envelope(event.clone());
    for field in [
        "id",
        "time_ms",
        "kind",
        "path",
        "sha256",
        "detection",
        "telemetry",
    ] {
        let mut v = serde_json::to_value(&base).unwrap();
        v[field] = match field {
            "time_ms" => serde_json::json!(NOW + 1),
            "kind" => serde_json::json!("network_event"),
            "telemetry" => serde_json::Value::Null,
            "id" | "sha256" => serde_json::json!("b".repeat(64)),
            _ => serde_json::json!("invented identity"),
        };
        assert!(serde_json::from_value::<EndpointEvent>(v)
            .unwrap()
            .validate(NOW)
            .is_err());
    }
    for n in 0..4 {
        let mut original = event.original.clone();
        match n {
            0 => original.stream_id = "b".repeat(64),
            1 => original.receipt_sequence += 1,
            2 => original.header.process_id += 1,
            _ => {
                let end = original.user_data_hex.len();
                original.user_data_hex.replace_range(end - 2..end, "02");
            }
        }
        let changed = WindowsNetworkEvent::from_original(original).unwrap();
        assert_ne!(changed.event_id(), event.event_id());
        let mut forged = base.clone();
        forged.telemetry = Some(Telemetry::WindowsNetworkEvent { event: changed });
        assert!(forged.validate(NOW).is_err());
    }
    let mut unknown = serde_json::to_value(&event).unwrap();
    unknown["verified_process"] = true.into();
    assert!(serde_json::from_value::<WindowsNetworkEvent>(unknown).is_err());
}

#[test]
fn provenance_clock_and_combined_original_limits_are_checked_before_acceptance() {
    let original = fixture(0);
    for n in 0..10 {
        let mut v = original.clone();
        match n {
            0 => v.stream_id = "A".repeat(64),
            1 => v.receipt_sequence = 0,
            2 => v.header.provider_id = crate::windows_process_events::PROCESS_PROVIDER.into(),
            3 => v.header.activity_id = "invalid".into(),
            4 => v.clock.frequency_hz = 0,
            5 => v.clock.after_qpc = v.clock.before_qpc - 1,
            6 => v.header.timestamp_qpc += 300 * v.clock.frequency_hz as i64 + 1,
            7 => v.header.timestamp_qpc = 0,
            8 => v.user_data_hex.replace_range(0..2, "GG"),
            _ => v.user_data_hex = v.user_data_hex.to_uppercase(),
        }
        assert!(WindowsNetworkEvent::from_original(v).is_err(), "case {n}");
    }
    let mut full = original.clone();
    full.extended_data.push(ExtendedData {
        reserved1: 0,
        ext_type: 1,
        linkage: 0,
        data_hex: "ab".repeat(MAX_ORIGINAL_BYTES - original.user_data_hex.len() / 2),
    });
    let event = WindowsNetworkEvent::from_original(full.clone()).unwrap();
    let mut envelope = envelope(event);
    envelope.detail = "\u{0001}".repeat(4096);
    assert!(envelope.validate(NOW).is_ok());
    assert!(serde_json::to_vec(&envelope).unwrap().len() <= MAX_SERIALIZED_EVENT_BYTES);
    full.extended_data[0].data_hex.push_str("00");
    assert!(WindowsNetworkEvent::from_original(full).is_err());
    let mut many = original;
    many.extended_data = vec![
        ExtendedData {
            reserved1: 0,
            ext_type: 1,
            linkage: 0,
            data_hex: String::new()
        };
        MAX_EXTENDED_ITEMS + 1
    ];
    assert!(WindowsNetworkEvent::from_original(many).is_err());
}

#[test]
fn independent_health_requires_fresh_complete_coverage_and_preserves_legacy_wire() {
    let health = WindowsNetworkEventHealth {
        stream_id: "a".repeat(64),
        state: "active".into(),
        started_ms: NOW - 1000,
        checked_ms: NOW,
        subscriptions: 1,
        received_records: 10,
        admitted_records: 10,
        ..Default::default()
    };
    assert!(health.healthy(NOW));
    for field in [
        "loss_signals",
        "rejected_records",
        "callback_drops",
        "queue_drops",
        "events_lost",
        "log_buffers_lost",
        "realtime_buffers_lost",
        "backpressured",
        "error",
        "state",
        "checked_ms",
        "subscriptions",
    ] {
        let mut value = serde_json::to_value(&health).unwrap();
        value[field] = match field {
            "backpressured" => true.into(),
            "error" => "Coverage requires review".into(),
            "state" => "stopped".into(),
            "checked_ms" => (NOW - 30_001).into(),
            "subscriptions" => 0.into(),
            _ => 1.into(),
        };
        let changed: WindowsNetworkEventHealth = serde_json::from_value(value).unwrap();
        assert!(!changed.healthy(NOW), "{field}");
    }
    let mut invalid = health.clone();
    invalid.admitted_records = u64::MAX;
    invalid.rejected_records = 1;
    assert!(invalid.validate().is_err());
    let mut future = health;
    future.checked_ms = NOW + 1001;
    assert!(!future.healthy(NOW));
    let legacy = r#"{"mode":"disabled","last_attempt_ms":0,"last_success_ms":0,"process_count":0,"connection_count":0,"pending_changes":0,"incomplete":false,"error":""}"#;
    let decoded: crate::telemetry::CollectorHealth = serde_json::from_str(legacy).unwrap();
    assert!(decoded.windows_network_events.is_none());
    assert_eq!(serde_json::to_string(&decoded).unwrap(), legacy);
}
