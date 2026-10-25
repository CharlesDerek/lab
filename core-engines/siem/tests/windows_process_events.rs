use athernex_endpoint_protocol::{
    self as p,
    telemetry::Telemetry,
    windows_process_events::{
        BufferContext, EventDescriptor, EventHeader, ExtendedData, QpcClock, WindowsProcessEvent,
        WindowsProcessOriginal, PROCESS_PROVIDER,
    },
    EndpointEvent, Enrollment, Platform,
};
use athernex_siem::{
    engine::Engine,
    model::{Kind, Outcome},
};
use std::collections::BTreeSet;

const NOW: u64 = 1_800_000_000_000;

fn enroll(engine: &Engine, id: char) -> Enrollment {
    let endpoint = Enrollment {
        protocol: p::PROTOCOL,
        enrollment_token: engine.create_enrollment(Platform::Windows, NOW).unwrap(),
        endpoint_id: id.to_string().repeat(64),
        credential: "d".repeat(64),
        hostname: "controlled-windows-fixture".into(),
        platform: Platform::Windows,
        arch: "x86_64".into(),
        version: "fixture".into(),
    };
    engine.enroll_endpoint(&endpoint, NOW).unwrap();
    endpoint
}

fn report(stream: char, receipt: u64, opcode: u8) -> EndpointEvent {
    // Synthetic v4/64-bit lifecycle bytes, including TOKEN_USER + a reported
    // SID, or the v2 termination report's sole PID. None of these controlled
    // constants are native host identities or addresses.
    let mut bytes = Vec::new();
    if opcode == 11 {
        bytes.extend(77u32.to_le_bytes());
    } else {
        bytes.extend(0x1234u64.to_le_bytes());
        for value in [77u32, 12, 0, 23] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(0u64.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(1u64.to_le_bytes());
        bytes.extend(0u64.to_le_bytes());
        bytes.extend([1, 1, 0, 0, 0, 0, 0, 5]);
        bytes.extend(18u32.to_le_bytes());
        bytes.extend(b"fixture<&>.exe\0");
        for text in [
            "<script>controlled</script>",
            "fixture.package",
            "fixture.app",
        ] {
            bytes.extend(text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        }
    }
    let event = WindowsProcessEvent::from_original(WindowsProcessOriginal {
        stream_id: stream.to_string().repeat(64),
        receipt_sequence: receipt,
        clock: QpcClock {
            frequency_hz: 1000,
            before_qpc: 1000,
            after_qpc: 1002,
            utc_filetime_100ns: 116_444_736_000_000_000 + NOW * 10_000,
        },
        header: EventHeader {
            size: 80,
            header_type: 0,
            flags: 0x140,
            event_property: 0,
            thread_id: 8,
            process_id: 4,
            timestamp_qpc: 1001,
            provider_id: PROCESS_PROVIDER.into(),
            descriptor: EventDescriptor {
                id: 0,
                version: if opcode == 11 { 2 } else { 4 },
                channel: 0,
                level: 0,
                opcode,
                task: 0,
                keyword: 0,
            },
            processor_time: 19,
            activity_id: "{00000000-0000-0000-0000-000000000000}".into(),
        },
        buffer_context: BufferContext {
            processor_index: 2,
            logger_id: 3,
        },
        extended_data: vec![ExtendedData {
            reserved1: 0,
            ext_type: 1,
            linkage: 0,
            data_hex: "010203".into(),
        }],
        user_data_hex: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    })
    .unwrap();
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
fn original_windows_events_remain_distinct_from_lifetime_identity_across_replay_streams_and_devices(
) {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("events.db");
    let mut engine = Engine::open(&database).unwrap();
    engine.configure_mode(false).unwrap();
    let first = enroll(&engine, 'a');
    let second = enroll(&engine, 'b');
    let mut reports: Vec<_> = [1, 2, 3, 4, 39, 11]
        .into_iter()
        .enumerate()
        .map(|(index, opcode)| report('c', index as u64 + 1, opcode))
        .collect();
    reports.push(report('d', 1, 1));
    reports.push(report('d', 2, 11));
    let cross_device = [reports[0].clone(), reports[5].clone()];
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        8
    );
    assert_eq!(
        engine
            .endpoint_events(&second.endpoint_id, &cross_device, NOW)
            .unwrap(),
        2
    );
    let mut objects = BTreeSet::new();
    let mut changes = BTreeSet::new();
    for (endpoint, expected) in [(&first, &reports[..]), (&second, &cross_device[..])] {
        let saved = engine
            .endpoint_observations(&endpoint.endpoint_id, u64::MAX, 32)
            .unwrap();
        assert_eq!(saved.len(), expected.len());
        for original in expected {
            assert!(original.telemetry.as_ref().unwrap().process().is_none());
            let row = saved
                .iter()
                .find(|row| row.event.id == original.id)
                .unwrap();
            assert!(
                serde_json::to_value(&row.event).unwrap()
                    == serde_json::to_value(original).unwrap()
            );
            let evidence = engine.reconstruct(row.evidence_id).unwrap();
            assert_eq!(evidence.event.kind, Kind::Process);
            assert_eq!(evidence.event.outcome, Outcome::Observe);
            assert!(
                objects.insert(evidence.event.object),
                "Observations merged by reported PID/key"
            );
            let context = evidence.context.unwrap();
            assert_eq!(context.host, endpoint.endpoint_id);
            assert_eq!(context.program, "Windows kernel ETW");
            assert_eq!(context.pid, Some(77));
            assert_eq!(context.parent_pid, None);
            assert_eq!(context.uid, None);
            assert_eq!(context.process_start_ms, None);
            assert_eq!(context.parent_start_ms, None);
            assert!(context.journal_cursor.is_empty());
            assert!(context.summary.contains("collector QPC estimate"));
            changes.insert(context.summary);
        }
    }
    assert_eq!(changes.len(), 6);
    assert!(changes
        .iter()
        .any(|summary| summary.contains("rundown start (existing process)")));
    assert!(changes
        .iter()
        .any(|summary| summary.contains("rundown end (existing process)")));
    assert!(changes
        .iter()
        .any(|summary| summary.contains("defunct (source-specific report)")));
    assert!(changes
        .iter()
        .any(|summary| summary.contains("termination report (PID only)")));
    let connection = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let verified_links: u64 = connection.query_row(
        "SELECT count(*) FROM graph_links WHERE entity LIKE 'endpoint-process:%' OR entity LIKE 'children:endpoint-process:%'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(verified_links, 0);
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|finding| ["AX-006", "AX-007", "AX-008"].contains(&finding.rule.as_str())));
    drop(connection);
    drop(engine);
    let engine = Engine::open(&database).unwrap();
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        0
    );
    for index in [0, 5] {
        let mut changed = reports[index].clone();
        changed.detail = "Conflicting original envelope".into();
        assert!(engine
            .endpoint_events(&first.endpoint_id, &[report('c', 10, 1), changed], NOW)
            .is_err());
    }
    assert_eq!(
        engine
            .endpoint_observations(&first.endpoint_id, u64::MAX, 32)
            .unwrap()
            .len(),
        8
    );
}

#[tokio::test]
async fn operator_export_retains_exact_records_and_portal_qualifies_and_escapes_windows_reports() {
    use athernex_siem::web::{router, App};
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(false).unwrap();
    let endpoint = enroll(&engine, 'a');
    let mut termination = report('c', 2, 11);
    termination.detail = "<strong>controlled termination</strong>".into();
    let observations = [report('c', 1, 3), termination];
    engine
        .endpoint_events(&endpoint.endpoint_id, &observations, NOW)
        .unwrap();
    engine
        .endpoint_heartbeat(
            &endpoint.endpoint_id,
            &p::Heartbeat {
                version: "fixture".into(),
                capabilities: vec![],
                scanner: String::new(),
                realtime: false,
                signature_version: String::new(),
                spool_events: 0,
                error: String::new(),
                protection: None,
                updates: None,
                controller_updates: None,
                collector: Some(p::telemetry::CollectorHealth {
                    mode: "snapshot".into(),
                    last_attempt_ms: NOW,
                    last_success_ms: NOW,
                    windows_process_events: Some(
                        p::windows_process_events::WindowsProcessEventHealth {
                            stream_id: "d".repeat(64),
                            state: "active".into(),
                            started_ms: NOW - 60_000,
                            checked_ms: NOW,
                            subscriptions: 2,
                            loss_signals: 1,
                            error: "Source <gap>".into(),
                            ..Default::default()
                        },
                    ),
                    ..Default::default()
                }),
            },
            NOW,
        )
        .unwrap();
    let token = "w".repeat(32);
    let app = router(App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(athernex_siem::auth::OperatorAuth::new(&token).unwrap()),
    });
    let export = format!("/api/endpoints/{}/events", endpoint.endpoint_id);
    for credential in [
        None,
        Some(endpoint.credential.as_str()),
        Some("incorrect-operator"),
    ] {
        let mut request = Request::builder().uri(&export);
        if let Some(value) = credential {
            request = request.header("Authorization", format!("Bearer {value}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for path in [
        export.clone(),
        "/endpoints".into(),
        format!("/endpoints/{}", endpoint.endpoint_id),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&path)
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        if path == export {
            let rows: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let rows = rows.as_array().unwrap();
            assert_eq!(rows.len(), observations.len());
            for observation in &observations {
                let row = rows
                    .iter()
                    .find(|row| row["event"]["id"] == observation.id)
                    .unwrap();
                assert!(row["event"] == serde_json::to_value(observation).unwrap());
            }
            let termination = &rows
                .iter()
                .find(|row| row["event"]["id"] == observations[1].id)
                .unwrap()["event"]["telemetry"]["event"];
            assert_eq!(termination["change"], "terminate");
            assert_eq!(termination["pid"], 77);
            assert_eq!(termination["original"]["user_data_hex"], "4d000000");
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
                assert_eq!(termination.get(field), Some(&serde_json::Value::Null));
            }
        } else {
            let html = std::str::from_utf8(&bytes).unwrap();
            if path == "/endpoints" {
                assert!(html.contains("Windows ETW process events: coverage incomplete"));
                assert!(html.contains("Source &lt;gap&gt;"));
                assert!(html.contains("no ETW source replay"));
            } else {
                assert!(html.contains("rundown start (existing process)"));
                assert!(html.contains("Original EVENT_RECORD"));
                assert!(html.contains("Collector QPC estimate"));
                assert!(html.contains("excluding wall-clock changes or drift"));
                assert!(html.contains("Reported parent PID"));
                assert!(html.contains("Reported image bytes (hex)"));
                assert!(html.contains("&lt;script&gt;controlled&lt;/script&gt;"));
                assert!(!html.contains("<script>controlled</script>"));
                let termination = html
                    .split("<section class='panel controls-panel fleet-panel'>")
                    .filter_map(|section| section.split("</section>").next())
                    .find(|section| section.contains("termination report (PID only)"))
                    .unwrap();
                assert!(termination.contains("<dt>Reported PID</dt><dd>77</dd>"));
                for label in [
                    "Reported parent PID",
                    "Reported session",
                    "Reported process key",
                    "Reported exit status",
                    "Reported SID",
                    "Reported image bytes (hex)",
                    "Reported command line",
                ] {
                    assert!(termination.contains(&format!("<dt>{label}</dt><dd>Not reported</dd>")));
                }
                assert!(termination.contains("&lt;strong&gt;controlled termination&lt;/strong&gt;"));
                assert!(!html.contains("<strong>controlled termination</strong>"));
            }
        }
    }
}
