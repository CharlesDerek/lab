use super::*;
use crate::{
    telemetry::{CollectorHealth, Telemetry},
    EndpointEvent,
};

const NOW: u64 = 1_800_000_000_000;
fn unicode(bytes: &mut Vec<u8>, value: &str) {
    for unit in value.encode_utf16().chain([0]) {
        bytes.extend(unit.to_le_bytes());
    }
}
fn payload(version: u8, width: usize, sid: bool, image: &[u8], command: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&0x1234u64.to_le_bytes()[..width]);
    for value in [42u32, 24, 7, 0xffff_fffe] {
        bytes.extend(value.to_le_bytes());
    }
    if version >= 3 {
        bytes.extend(&0x5678u64.to_le_bytes()[..width]);
    }
    if version >= 4 {
        bytes.extend(3u32.to_le_bytes());
    }
    if sid {
        // WBEM TOKEN_USER is two pointer-width words, followed by binary SID.
        bytes.extend(&0x4321u64.to_le_bytes()[..width]);
        bytes.extend(&0u64.to_le_bytes()[..width]);
        bytes.extend([1, 2, 0, 0, 0, 0, 0, 5]);
        bytes.extend(21u32.to_le_bytes());
        bytes.extend(1000u32.to_le_bytes());
    } else {
        bytes.extend(0u32.to_le_bytes());
    }
    bytes.extend(image);
    bytes.push(0);
    unicode(&mut bytes, command);
    if version >= 4 {
        unicode(&mut bytes, "fixture-package");
        unicode(&mut bytes, "fixture-app");
    }
    bytes
}
fn original(version: u8, width: usize, opcode: u8, sid: bool) -> WindowsProcessOriginal {
    WindowsProcessOriginal {
        stream_id: "a".repeat(64),
        receipt_sequence: 1,
        clock: QpcClock {
            frequency_hz: 10_000_000,
            before_qpc: 10_000_000,
            after_qpc: 10_000_020,
            utc_filetime_100ns: 116_444_736_000_000_000 + NOW * 10_000,
        },
        header: EventHeader {
            size: 80,
            header_type: 0,
            flags: 0x100 | if width == 8 { 0x40 } else { 0x20 },
            event_property: 0,
            thread_id: 11,
            process_id: 99,
            timestamp_qpc: 10_000_010,
            provider_id: PROCESS_PROVIDER.into(),
            descriptor: EventDescriptor {
                id: 0,
                version,
                channel: 0,
                level: 0,
                opcode,
                task: 0,
                keyword: 0,
            },
            processor_time: 7,
            activity_id: "{00000000-0000-0000-0000-000000000000}".into(),
        },
        buffer_context: BufferContext {
            processor_index: 1,
            logger_id: 3,
        },
        extended_data: vec![ExtendedData {
            reserved1: 0,
            ext_type: 13,
            linkage: 0,
            data_hex: "0100000000000000".into(),
        }],
        user_data_hex: parse::encode(&payload(
            version,
            width,
            sid,
            b"fixture\xff.exe",
            "fixture --value=\"\u{1f680}\"",
        )),
    }
}
fn envelope(event: WindowsProcessEvent) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "windows_process_event".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: String::new(),
        telemetry: Some(Telemetry::WindowsProcessEvent { event }),
    }
}

#[test]
fn documented_layouts_preserve_reported_facts_and_distinct_lifecycle_semantics() {
    for version in 2..=4 {
        for width in [4, 8] {
            for sid in [false, true] {
                for (opcode, change) in [
                    (1, WindowsProcessChange::Start),
                    (2, WindowsProcessChange::End),
                    (3, WindowsProcessChange::RundownStart),
                    (4, WindowsProcessChange::RundownEnd),
                    (39, WindowsProcessChange::Defunct),
                ] {
                    let raw = original(version, width, opcode, sid);
                    let event = WindowsProcessEvent::from_original(raw.clone()).unwrap();
                    assert_eq!(event.original, raw);
                    assert_eq!(event.change, change);
                    assert_eq!(event.pointer_bits, (width * 8) as u8);
                    assert_eq!(
                        (
                            event.pid,
                            event.parent_pid,
                            event.session_id,
                            event.exit_status
                        ),
                        (42, Some(24), Some(7), Some(-2))
                    );
                    assert_eq!(event.original.header.process_id, 99); // Never rewrite reporting PID.
                    assert_eq!(event.unique_process_key, Some(0x1234));
                    assert_eq!(event.process_flags, (version == 4).then_some(3));
                    assert_eq!(event.user_sid.as_deref(), sid.then_some("S-1-5-21-1000"));
                    assert_eq!(
                        event.image_name_bytes_hex.as_deref(),
                        Some("66697874757265ff2e657865")
                    );
                    assert_eq!(
                        event.command_line.as_deref(),
                        Some("fixture --value=\"\u{1f680}\"")
                    );
                    assert_eq!(
                        event.package_full_name.as_deref(),
                        (version == 4).then_some("fixture-package")
                    );
                    assert_eq!(
                        event.application_id.as_deref(),
                        (version == 4).then_some("fixture-app")
                    );
                    assert_eq!(event.time_ms, NOW);
                    assert_eq!(
                        event.time_basis,
                        WindowsProcessTimeBasis::CollectorQpcEstimate
                    );
                    envelope(event).validate(NOW).unwrap();
                }
            }
        }
    }
}

#[test]
fn optional_lifecycle_fields_preserve_exact_legacy_wire_bytes() {
    for version in 2..=4 {
        for width in [4, 8] {
            for sid in [false, true] {
                for (opcode, change) in [
                    (1, "start"),
                    (2, "end"),
                    (3, "rundown_start"),
                    (4, "rundown_end"),
                    (39, "defunct"),
                ] {
                    let raw = original(version, width, opcode, sid);
                    // The prior wire contract had six required scalar/string
                    // fields. Compare its literal JSON, including field order,
                    // rather than serializing the new Options as the oracle.
                    let expected = format!(
                        concat!(
                            "{{\"original\":{},\"change\":\"{}\",\"pointer_bits\":{},",
                            "\"pid\":42,\"parent_pid\":24,\"session_id\":7,\"exit_status\":-2,",
                            "\"unique_process_key\":4660,\"process_flags\":{},\"user_sid\":{},",
                            "\"image_name_bytes_hex\":\"66697874757265ff2e657865\",",
                            "\"command_line\":\"fixture --value=\\\"🚀\\\"\",",
                            "\"package_full_name\":{},\"application_id\":{},",
                            "\"time_ms\":1800000000000,\"time_uncertainty_ms\":2,",
                            "\"time_basis\":\"collector_qpc_estimate\"}}"
                        ),
                        serde_json::to_string(&raw).unwrap(),
                        change,
                        width * 8,
                        if version == 4 { "3" } else { "null" },
                        if sid { "\"S-1-5-21-1000\"" } else { "null" },
                        if version == 4 {
                            "\"fixture-package\""
                        } else {
                            "null"
                        },
                        if version == 4 {
                            "\"fixture-app\""
                        } else {
                            "null"
                        },
                    );
                    let event = WindowsProcessEvent::from_original(raw).unwrap();
                    assert_eq!(serde_json::to_vec(&event).unwrap(), expected.as_bytes());
                    let restored: WindowsProcessEvent = serde_json::from_str(&expected).unwrap();
                    restored.validate(NOW).unwrap();
                    assert_eq!(restored.event_id(), event.event_id());
                }
            }
        }
    }
}

fn terminate(width: usize) -> WindowsProcessOriginal {
    let mut raw = original(2, width, 11, false);
    raw.user_data_hex = parse::encode(&42u32.to_le_bytes());
    raw
}

#[test]
fn termination_preserves_only_reported_pid_and_exact_original() {
    for width in [4, 8] {
        let raw = terminate(width);
        let event = WindowsProcessEvent::from_original(raw.clone()).unwrap();
        assert_eq!(event.original, raw);
        assert_eq!(event.change, WindowsProcessChange::Terminate);
        assert_eq!(event.pid, 42);
        assert_eq!(event.original.header.process_id, 99);
        assert_eq!(event.pointer_bits, (width * 8) as u8);
        let value = serde_json::to_value(&event).unwrap();
        for field in [
            "parent_pid",
            "session_id",
            "exit_status",
            "unique_process_key",
            "process_flags",
            "user_sid",
            "image_name_bytes_hex",
            "command_line",
            "package_full_name",
            "application_id",
        ] {
            assert!(value.get(field).unwrap().is_null());
        }
        let restored: WindowsProcessEvent = serde_json::from_value(value).unwrap();
        assert_eq!(event, restored);
        let id = event.event_id();
        let wrapper = envelope(restored);
        wrapper.validate(NOW).unwrap();
        assert!(wrapper.telemetry.as_ref().unwrap().process().is_none());

        let mut reused = raw.clone();
        reused.receipt_sequence += 1;
        assert_ne!(
            id,
            WindowsProcessEvent::from_original(reused)
                .unwrap()
                .event_id()
        );
        let mut changed = raw;
        changed.user_data_hex = parse::encode(&43u32.to_le_bytes());
        let changed = WindowsProcessEvent::from_original(changed).unwrap();
        assert_ne!(id, changed.event_id());
        let mut forged = event;
        forged.original = changed.original;
        assert!(forged.validate(NOW).is_err());
    }
}

#[test]
fn termination_and_lifecycle_fact_presence_cannot_be_forged() {
    let termination = WindowsProcessEvent::from_original(terminate(8)).unwrap();
    for (field, value) in [
        ("parent_pid", serde_json::json!(24)),
        ("session_id", serde_json::json!(7)),
        ("exit_status", serde_json::json!(0)),
        ("unique_process_key", serde_json::json!(4660)),
        ("process_flags", serde_json::json!(0)),
        ("user_sid", serde_json::json!("S-1-5-18")),
        ("image_name_bytes_hex", serde_json::json!("")),
        ("command_line", serde_json::json!("")),
        ("package_full_name", serde_json::json!("")),
        ("application_id", serde_json::json!("")),
        ("change", serde_json::json!("end")),
        ("pid", serde_json::json!(43)),
    ] {
        let mut forged = serde_json::to_value(&termination).unwrap();
        forged[field] = value;
        let forged: WindowsProcessEvent = serde_json::from_value(forged).unwrap();
        assert!(forged.validate(NOW).is_err());
    }
    for opcode in [1, 2, 3, 4, 39] {
        let event = WindowsProcessEvent::from_original(original(4, 8, opcode, true)).unwrap();
        for field in [
            "parent_pid",
            "session_id",
            "exit_status",
            "unique_process_key",
            "image_name_bytes_hex",
            "command_line",
        ] {
            let mut forged = serde_json::to_value(&event).unwrap();
            forged[field] = serde_json::Value::Null;
            let forged: WindowsProcessEvent = serde_json::from_value(forged).unwrap();
            assert!(forged.validate(NOW).is_err());
        }
    }
}

#[test]
fn termination_requires_exact_version_two_four_byte_layout() {
    for width in [4, 8] {
        for version in [0, 1, 3, 4, 5, 255] {
            let mut raw = terminate(width);
            raw.header.descriptor.version = version;
            assert!(WindowsProcessEvent::from_original(raw).is_err());
        }
        for length in [0, 1, 2, 3, 5, 8, 16] {
            let mut raw = terminate(width);
            raw.user_data_hex = "00".repeat(length);
            assert!(WindowsProcessEvent::from_original(raw).is_err());
        }
        assert!(WindowsProcessEvent::from_original(original(2, width, 11, false)).is_err());
        for opcode in [1, 2, 3, 4, 39] {
            let mut raw = terminate(width);
            raw.header.descriptor.opcode = opcode;
            assert!(WindowsProcessEvent::from_original(raw).is_err());
        }
    }
}

#[test]
fn unknown_versions_opcodes_provenance_and_truncated_records_are_refused() {
    for version in [0, 1, 5, 255] {
        assert!(WindowsProcessEvent::from_original(original(version, 8, 1, false)).is_err());
    }
    for opcode in [0, 5, 10, 40, 255] {
        assert!(WindowsProcessEvent::from_original(original(4, 8, opcode, false)).is_err());
    }
    for version in 2..=4 {
        for width in [4, 8] {
            for sid in [false, true] {
                let raw = original(version, width, 1, sid);
                for end in (0..raw.user_data_hex.len()).step_by(2) {
                    let mut truncated = raw.clone();
                    truncated.user_data_hex.truncate(end);
                    assert!(WindowsProcessEvent::from_original(truncated).is_err());
                }
                let mut extra = raw;
                extra.user_data_hex.push_str("00");
                assert!(WindowsProcessEvent::from_original(extra).is_err());
            }
        }
    }
    let raw = original(4, 8, 1, false);
    for flags in [0, 0x100, 0x160, 0x140 | 4, 0x140 | 8] {
        let mut bad = raw.clone();
        bad.header.flags = flags;
        assert!(WindowsProcessEvent::from_original(bad).is_err());
    }
    let mut bad = raw.clone();
    bad.header.provider_id.replace_range(1..2, "0");
    assert!(WindowsProcessEvent::from_original(bad).is_err());
    let mut bad = raw.clone();
    bad.header.activity_id = "not-a-guid".into();
    assert!(WindowsProcessEvent::from_original(bad).is_err());
    let mut bad = raw.clone();
    bad.receipt_sequence = 0;
    assert!(WindowsProcessEvent::from_original(bad).is_err());
    for malformed in ["a", "FF", "0g"] {
        let mut bad = raw.clone();
        bad.user_data_hex = malformed.into();
        assert!(WindowsProcessEvent::from_original(bad).is_err());
    }
}

#[test]
fn malformed_sid_and_text_never_become_lossy_normalized_identity() {
    for width in [4, 8] {
        let mut raw = original(2, width, 1, true);
        let mut bytes = payload(2, width, true, b"image", "command");
        let sid = width + 16 + width * 2;
        bytes[sid] = 2;
        raw.user_data_hex = parse::encode(&bytes);
        assert!(WindowsProcessEvent::from_original(raw.clone()).is_err());
        bytes[sid] = 1;
        bytes[sid + 1] = 16;
        raw.user_data_hex = parse::encode(&bytes);
        assert!(WindowsProcessEvent::from_original(raw).is_err());
    }
    let mut raw = original(2, 8, 1, false);
    let mut bytes = payload(2, 8, false, b"a", "");
    bytes.truncate(bytes.len() - 2);
    bytes.extend([0x00, 0xd8, 0, 0]); // Unpaired high surrogate is refused.
    raw.user_data_hex = parse::encode(&bytes);
    assert!(WindowsProcessEvent::from_original(raw.clone()).is_err());
    raw.user_data_hex = parse::encode(&payload(2, 8, false, &vec![b'a'; 4097], ""));
    assert!(WindowsProcessEvent::from_original(raw).is_err());
}

#[test]
fn originals_and_normalized_fields_are_bound_to_immutable_envelope_identity() {
    let event = WindowsProcessEvent::from_original(original(4, 8, 1, true)).unwrap();
    let json = serde_json::to_vec(&event).unwrap();
    let restored: WindowsProcessEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(event.event_id(), restored.event_id());
    let mut changed = event.clone();
    changed.pid += 1;
    assert!(changed.validate(NOW).is_err());
    let mut changed = event.clone();
    changed.time_ms += 1;
    assert!(changed.validate(NOW).is_err());
    let mut changed = event.clone();
    changed.time_uncertainty_ms += 1;
    assert!(changed.validate(NOW).is_err());
    let mut changed = event.clone();
    changed.change = WindowsProcessChange::RundownStart;
    assert!(changed.validate(NOW).is_err());
    let mut changed = event.clone();
    changed.command_line.as_mut().unwrap().push('x');
    assert!(changed.validate(NOW).is_err());
    let mut changed = event.clone();
    changed.original.user_data_hex.replace_range(16..18, "ff");
    assert!(changed.validate(NOW).is_err());
    // Opaque original metadata/bytes also bind ID, even when facts are unchanged.
    for part in 0..5 {
        let mut raw = event.original.clone();
        match part {
            0 => raw.extended_data[0].data_hex.replace_range(0..2, "02"),
            1 => raw.header.processor_time += 1,
            2 => raw.buffer_context.logger_id += 1,
            3 => raw.receipt_sequence += 1,
            _ => raw.stream_id = "b".repeat(64),
        }
        let changed = WindowsProcessEvent::from_original(raw).unwrap();
        assert_ne!(event.event_id(), changed.event_id());
        let mut wrapper = envelope(changed);
        wrapper.id = event.event_id();
        assert!(wrapper.validate(NOW).is_err());
    }
    let mut wrapper = envelope(event);
    assert!(wrapper.telemetry.as_ref().unwrap().process().is_none());
    for field in ["path", "sha256", "detection", "kind", "time"] {
        let mut bad = wrapper.clone();
        match field {
            "path" => bad.path = "unverified.exe".into(),
            "sha256" => bad.sha256 = "a".repeat(64),
            "detection" => bad.detection = "invented".into(),
            "kind" => bad.kind = "process_event".into(),
            _ => bad.time_ms += 1,
        }
        assert!(bad.validate(NOW).is_err());
    }
    wrapper.telemetry = None;
    assert!(wrapper.validate(NOW).is_err());
}

#[test]
fn reused_pid_or_key_cannot_alias_receipt_identity_or_claim_execution() {
    let start = WindowsProcessEvent::from_original(original(4, 8, 1, false)).unwrap();
    let mut raw = start.original.clone();
    raw.receipt_sequence = 2;
    let reused = WindowsProcessEvent::from_original(raw).unwrap();
    assert_eq!(
        (start.pid, start.unique_process_key),
        (reused.pid, reused.unique_process_key)
    );
    assert_ne!(start.event_id(), reused.event_id());
    let mut raw = start.original.clone();
    raw.stream_id = "b".repeat(64);
    assert_ne!(
        start.event_id(),
        WindowsProcessEvent::from_original(raw).unwrap().event_id()
    );
    for opcode in [2, 3, 4, 39] {
        let other = WindowsProcessEvent::from_original(original(4, 8, opcode, false)).unwrap();
        assert_ne!(start.event_id(), other.event_id());
        assert_ne!(other.change, WindowsProcessChange::Start);
        assert!(Telemetry::WindowsProcessEvent { event: other }
            .process()
            .is_none());
    }
}

#[test]
fn clock_mapping_is_bracketed_bounded_and_explicitly_estimated() {
    let raw = original(4, 8, 1, false);
    assert_eq!(raw.clock.estimate(20_000_010).unwrap().0, NOW + 1000);
    assert_eq!(raw.clock.estimate(10).unwrap().0, NOW - 1000);
    for case in 0..8 {
        let mut clock = raw.clock.clone();
        match case {
            0 => clock.frequency_hz = 0,
            1 => clock.frequency_hz = u64::MAX,
            2 => clock.before_qpc = -1,
            3 => clock.after_qpc = clock.before_qpc - 1,
            4 => clock.after_qpc = clock.before_qpc + 1_000_001,
            5 => clock.utc_filetime_100ns = 0,
            6 => clock.after_qpc = i64::MAX,
            _ => clock.before_qpc = i64::MIN,
        }
        assert!(clock.estimate(raw.header.timestamp_qpc).is_err());
    }
    assert!(raw.clock.estimate(i64::MAX).is_err());
    assert!(raw.clock.estimate(0).is_err());
    let event = WindowsProcessEvent::from_original(raw).unwrap();
    assert!(event.validate(NOW - 60_001).is_err());
}

#[test]
fn original_and_serialized_transport_budgets_are_hard_refusals() {
    let mut raw = original(4, 8, 1, false);
    raw.extended_data[0].data_hex = "00".repeat(MAX_ORIGINAL_BYTES);
    assert!(WindowsProcessEvent::from_original(raw).is_err());
    let mut raw = original(4, 8, 1, false);
    raw.extended_data = vec![raw.extended_data[0].clone(); MAX_EXTENDED_ITEMS + 1];
    assert!(WindowsProcessEvent::from_original(raw).is_err());
    let mut raw = original(2, 8, 1, false);
    raw.user_data_hex = parse::encode(&payload(2, 8, false, b"fixture", &"\u{1}".repeat(16_384)));
    // Hex raw plus escaped normalized control characters exceeds the HTTP budget.
    assert!(WindowsProcessEvent::from_original(raw).is_err());
    let event = WindowsProcessEvent::from_original(original(4, 8, 1, false)).unwrap();
    let wrapper = envelope(event);
    assert!(serde_json::to_vec(&wrapper).unwrap().len() < 192 * 1024);
}

#[test]
fn health_gaps_are_sticky_and_old_optional_wire_shape_is_unchanged() {
    let healthy = WindowsProcessEventHealth {
        stream_id: "a".repeat(64),
        state: "active".into(),
        started_ms: NOW - 1000,
        checked_ms: NOW,
        subscriptions: 1,
        received_records: 2,
        admitted_records: 2,
        ..Default::default()
    };
    assert!(healthy.healthy(NOW));
    for case in 0..12 {
        let mut bad = healthy.clone();
        match case {
            0 => bad.loss_signals = 1,
            1 => bad.rejected_records = 1,
            2 => bad.callback_drops = 1,
            3 => bad.queue_drops = 1,
            4 => bad.events_lost = 1,
            5 => bad.log_buffers_lost = 1,
            6 => bad.realtime_buffers_lost = 1,
            7 => bad.backpressured = true,
            8 => bad.error = "gap".into(),
            9 => bad.state = "starting".into(),
            10 => bad.checked_ms = NOW + 1001,
            _ => bad.subscriptions = 0,
        }
        assert!(!bad.healthy(NOW));
        let replay: WindowsProcessEventHealth =
            serde_json::from_slice(&serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(!replay.healthy(NOW));
    }
    assert!(!healthy.healthy(NOW + 30_001));
    let collector = CollectorHealth::default();
    let bytes = serde_json::to_vec(&collector).unwrap();
    assert!(!String::from_utf8(bytes.clone())
        .unwrap()
        .contains("windows_process_events"));
    let restored: CollectorHealth = serde_json::from_slice(&bytes).unwrap();
    assert!(restored.windows_process_events.is_none());
    assert_eq!(bytes, serde_json::to_vec(&restored).unwrap());
    let mut value = serde_json::to_value(original(4, 8, 1, false)).unwrap();
    value["kernel_sequence"] = 99.into();
    assert!(serde_json::from_value::<WindowsProcessOriginal>(value).is_err());
}
