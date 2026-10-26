//! Portable synthetic fixtures; no host addresses, records or identities.
use athernex_endpoint_protocol::{
    self as p,
    telemetry::Telemetry,
    windows_network_events::{
        BufferContext, EventDescriptor, EventHeader, ExtendedData, QpcClock, WindowsNetworkEvent,
        WindowsNetworkEventHealth, WindowsNetworkOriginal, MAX_ORIGINAL_BYTES, TCP_PROVIDER,
        UDP_PROVIDER,
    },
    EndpointEvent, Enrollment, Platform,
};
use athernex_siem::{
    engine::Engine,
    model::{InputEvent, Kind, Outcome},
    web::{router, App},
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
const NOW: u64 = 1_800_000_000_000;
const OPERATOR: &str = "public-windows-network-operator-fixture-32";
const KINDS: [(bool, u8); 14] = [
    (true, 10),
    (true, 11),
    (true, 12),
    (true, 13),
    (true, 15),
    (true, 26),
    (true, 27),
    (true, 28),
    (true, 29),
    (true, 31),
    (false, 10),
    (false, 11),
    (false, 26),
    (false, 27),
];
fn enroll(engine: &Engine, id: char, now: u64) -> Enrollment {
    let endpoint = Enrollment {
        protocol: p::PROTOCOL,
        enrollment_token: engine.create_enrollment(Platform::Windows, now).unwrap(),
        endpoint_id: id.to_string().repeat(64),
        credential: if id == 'a' { "d" } else { "e" }.repeat(64),
        hostname: "controlled-windows-network-fixture".into(),
        platform: Platform::Windows,
        arch: "x86_64".into(),
        version: "fixture".into(),
    };
    engine.enroll_endpoint(&endpoint, now).unwrap();
    endpoint
}
fn report(tcp: bool, opcode: u8, stream: char, receipt: u64, now: u64) -> EndpointEvent {
    let ipv6 = opcode >= 26;
    let mut bytes = Vec::new();
    bytes.extend(77u32.to_le_bytes());
    bytes.extend(u32::MAX.to_le_bytes());
    if ipv6 {
        bytes.extend("2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
        bytes.extend("2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
    } else {
        bytes.extend(Ipv4Addr::new(198, 51, 100, 20).octets());
        bytes.extend(Ipv4Addr::new(192, 0, 2, 10).octets());
    }
    bytes.extend(443u16.to_be_bytes());
    bytes.extend(54321u16.to_be_bytes());
    if tcp && [10, 26].contains(&opcode) {
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
    }
    if tcp && [12, 15, 28, 31].contains(&opcode) {
        for n in [1460u16, 1, 1, 1] {
            bytes.extend(n.to_le_bytes());
        }
        bytes.extend(65535u32.to_le_bytes());
        bytes.extend(1i16.to_le_bytes());
        bytes.extend(1i16.to_le_bytes());
    }
    bytes.extend(5u32.to_le_bytes());
    bytes.extend(0x1234u32.to_le_bytes());
    let event = WindowsNetworkEvent::from_original(WindowsNetworkOriginal {
        stream_id: stream.to_string().repeat(64),
        receipt_sequence: receipt,
        clock: QpcClock {
            frequency_hz: 1000,
            before_qpc: 1000,
            after_qpc: 1002,
            utc_filetime_100ns: 116_444_736_000_000_000 + now * 10_000,
        },
        header: EventHeader {
            size: 80,
            header_type: 0,
            flags: 0x140,
            event_property: 0,
            thread_id: 8,
            process_id: 4,
            timestamp_qpc: 1001,
            provider_id: if tcp { TCP_PROVIDER } else { UDP_PROVIDER }.into(),
            descriptor: EventDescriptor {
                id: 0,
                version: 2,
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
        extended_data: vec![],
        user_data_hex: bytes.iter().map(|n| format!("{n:02x}")).collect(),
    })
    .unwrap();
    envelope(event)
}
fn envelope(event: WindowsNetworkEvent) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "windows_network_event".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: String::new(),
        telemetry: Some(Telemetry::WindowsNetworkEvent { event }),
    }
}
fn network(event: &mut EndpointEvent) -> &mut WindowsNetworkEvent {
    match event.telemetry.as_mut().unwrap() {
        Telemetry::WindowsNetworkEvent { event } => event,
        _ => panic!("network fixture"),
    }
}
fn larger(mut event: EndpointEvent, extension_bytes: usize) -> EndpointEvent {
    let mut original = network(&mut event).original.clone();
    original.extended_data = vec![ExtendedData {
        reserved1: 0,
        ext_type: 1,
        linkage: 0,
        data_hex: "ab".repeat(extension_bytes),
    }];
    envelope(WindowsNetworkEvent::from_original(original).unwrap())
}
fn service(engine: Engine) -> (Router, Arc<Mutex<Engine>>) {
    let engine = Arc::new(Mutex::new(engine));
    (
        router(App {
            engine: engine.clone(),
            csrf: "fixture-csrf".into(),
            ingest_token: None,
            operator: Arc::new(athernex_siem::auth::OperatorAuth::new(OPERATOR).unwrap()),
        }),
        engine,
    )
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    bytes: Vec<u8>,
) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(credential) = credential {
        builder = builder.header("Authorization", format!("Bearer {credential}"));
    }
    app.clone()
        .oneshot(builder.body(Body::from(bytes)).unwrap())
        .await
        .unwrap()
}
async fn json(response: Response) -> serde_json::Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}
#[test]
fn all_network_operations_preserve_originals_without_process_connection_or_delivery_identity() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("events.db");
    let mut engine = Engine::open(&database).unwrap();
    engine.configure_mode(false).unwrap();
    let first = enroll(&engine, 'a', NOW);
    let second = enroll(&engine, 'b', NOW);
    let mut reports: Vec<_> = KINDS
        .into_iter()
        .enumerate()
        .map(|(i, (tcp, op))| report(tcp, op, 'c', i as u64 + 1, NOW))
        .collect();
    reports.push(report(true, 12, 'd', 1, NOW)); // Reused PID, tuple and opaque connid in another subscription.
    engine
        .ingest(
            &[InputEvent {
                time_ms: NOW - 1,
                source: "controlled-prior".into(),
                subject: first.endpoint_id.clone(),
                object: "controlled-process".into(),
                kind: Kind::Process,
                outcome: Outcome::Allow,
                severity: 5,
                bytes: 0,
                trace: 0,
                idempotency_key: p::hash(b"controlled-prior-process"),
                context: None,
            }],
            NOW,
        )
        .unwrap();
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        15
    );
    assert_eq!(
        engine
            .endpoint_events(&second.endpoint_id, &reports[..1], NOW)
            .unwrap(),
        1
    );
    let mut objects = BTreeSet::new();
    let mut summaries = BTreeSet::new();
    for (device, expected) in [(&first, &reports[..]), (&second, &reports[..1])] {
        let saved = engine
            .endpoint_observations(&device.endpoint_id, u64::MAX, 32)
            .unwrap();
        assert_eq!(saved.len(), expected.len());
        for original in expected {
            assert!(original.telemetry.as_ref().unwrap().process().is_none());
            let row = saved.iter().find(|r| r.event.id == original.id).unwrap();
            assert_eq!(
                serde_json::to_value(&row.event).unwrap(),
                serde_json::to_value(original).unwrap()
            );
            let evidence = engine.reconstruct(row.evidence_id).unwrap();
            assert_eq!(evidence.event.kind, Kind::Network);
            assert_eq!(evidence.event.outcome, Outcome::Observe);
            assert_eq!(evidence.event.bytes, 0);
            assert_eq!(evidence.event.severity, 1);
            assert!(
                objects.insert(evidence.event.object),
                "Observations merged by PID/tuple/connid"
            );
            let c = evidence.context.unwrap();
            assert_eq!(c.host, device.endpoint_id);
            assert_eq!(c.program, "Windows kernel network ETW");
            assert_eq!(c.pid, Some(77));
            assert_eq!(c.parent_pid, None);
            assert_eq!(c.process_start_ms, None);
            assert_eq!(c.parent_start_ms, None);
            assert_eq!(c.uid, None);
            assert!(c.journal_cursor.is_empty());
            assert!(c.summary.contains("collector QPC estimate"));
            assert!(c.summary.contains("do not verify"));
            assert!(c.summary.len() <= 160);
            summaries.insert(c.summary);
        }
    }
    assert_eq!(summaries.len(), 14);
    // Even a maximum native size after an allowed high-severity execution is
    // not the allowed/transferred-byte evidence required by the base AX-003 rule.
    assert!(engine.snapshot().unwrap().findings.is_empty());
    let db = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let count:u64=db.query_row("SELECT count(*) FROM graph_links WHERE entity LIKE 'endpoint-process:%' OR entity LIKE 'children:endpoint-process:%' OR entity LIKE 'file-path:%'",[],|r|r.get(0)).unwrap();
    assert_eq!(count, 0);
    drop(db);
    drop(engine);
    let engine = Engine::open(&database).unwrap();
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        0
    );
    let mut changed = reports[0].clone();
    changed.detail = "Conflicting replay".into();
    assert!(engine
        .endpoint_events(
            &first.endpoint_id,
            &[report(true, 12, 'c', 99, NOW), changed],
            NOW
        )
        .is_err());
    assert_eq!(
        engine
            .endpoint_observations(&first.endpoint_id, u64::MAX, 32)
            .unwrap()
            .len(),
        15
    );
}
#[test]
fn forged_normalized_fields_originals_and_generic_identity_are_refused_atomically() {
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(false).unwrap();
    let device = enroll(&engine, 'a', NOW);
    let valid = report(true, 12, 'c', 1, NOW);
    for mutation in 0..11 {
        let mut forged = valid.clone();
        match mutation {
            0 => network(&mut forged).reported_pid += 1,
            1 => network(&mut forged).reported_size = 1,
            2 => network(&mut forged).source = "203.0.113.9:123".parse().unwrap(),
            3 => network(&mut forged).original.header.timestamp_qpc += 1,
            4 => network(&mut forged)
                .original
                .user_data_hex
                .replace_range(..2, "ff"),
            5 => forged.time_ms += 1,
            6 => forged.id = "f".repeat(64),
            7 => forged.path = "controlled.exe".into(),
            8 => forged.sha256 = "e".repeat(64),
            9 => forged.detection = "unverified-malware".into(),
            _ => forged.kind = "network_event".into(),
        }
        assert!(
            engine
                .endpoint_events(
                    &device.endpoint_id,
                    &[report(false, 10, 'd', mutation + 1, NOW), forged],
                    NOW
                )
                .is_err(),
            "mutation {mutation}"
        );
        assert!(engine
            .endpoint_observations(&device.endpoint_id, u64::MAX, 32)
            .unwrap()
            .is_empty());
    }
}
#[tokio::test]
async fn authenticated_http_originals_replay_conflicts_device_isolation_and_restart_are_exact() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    let first = enroll(&engine, 'a', now);
    let second = enroll(&engine, 'b', now);
    let (app, shared) = service(engine);
    let observation = report(true, 12, 'c', 1, now);
    let bytes = serde_json::to_vec(&[&observation]).unwrap();
    let ingest = format!("/api/endpoint/{}/events", first.endpoint_id);
    let export = format!("/api/endpoints/{}/events", first.endpoint_id);
    for credential in [None, Some(second.credential.as_str())] {
        assert_eq!(
            request(&app, "POST", &ingest, credential, bytes.clone())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let response = request(
        &app,
        "POST",
        &ingest,
        Some(&first.credential),
        bytes.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let ack = json(response).await;
    assert_eq!(ack["durability"], "committed");
    assert_eq!(ack["accepted"], 1);
    assert_eq!(ack["acknowledged"], 1);
    for credential in [
        None,
        Some(first.credential.as_str()),
        Some("incorrect-operator"),
    ] {
        assert_eq!(
            request(&app, "GET", &export, credential, vec![])
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let before = json(request(&app, "GET", &export, Some(OPERATOR), vec![]).await).await;
    assert_eq!(
        before[0]["event"],
        serde_json::to_value(&observation).unwrap()
    );
    let replay = json(
        request(
            &app,
            "POST",
            &ingest,
            Some(&first.credential),
            bytes.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(replay["accepted"], 0);
    assert_eq!(replay["acknowledged"], 1);
    let mut changed = observation.clone();
    changed.detail = "conflicting envelope".into();
    let fresh = report(false, 26, 'e', 99, now);
    assert_eq!(
        request(
            &app,
            "POST",
            &ingest,
            Some(&first.credential),
            serde_json::to_vec(&[fresh, changed]).unwrap()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        json(request(&app, "GET", &export, Some(OPERATOR), vec![]).await).await,
        before
    );
    let other_ingest = format!("/api/endpoint/{}/events", second.endpoint_id);
    let other_export = format!("/api/endpoints/{}/events", second.endpoint_id);
    assert_eq!(
        request(
            &app,
            "POST",
            &other_ingest,
            Some(&first.credential),
            bytes.clone()
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &other_ingest,
            Some(&second.credential),
            bytes.clone()
        )
        .await
        .status(),
        StatusCode::OK
    );
    let other = json(request(&app, "GET", &other_export, Some(OPERATOR), vec![]).await).await;
    assert_eq!(other[0]["event"], before[0]["event"]);
    assert_ne!(other[0]["evidence_id"], before[0]["evidence_id"]);
    drop(app);
    drop(shared);
    let (app, _shared) = service(Engine::open(&path).unwrap());
    assert_eq!(
        json(request(&app, "GET", &export, Some(OPERATOR), vec![]).await).await,
        before
    );
    let ack = json(request(&app, "POST", &ingest, Some(&first.credential), bytes).await).await;
    assert_eq!(ack["accepted"], 0);
    assert_eq!(ack["acknowledged"], 1);
}
#[tokio::test]
async fn portal_escapes_originals_and_reports_separate_windows_network_coverage() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(false).unwrap();
    let device = enroll(&engine, 'a', now);
    let mut event = report(false, 26, 'c', 1, now);
    event.detail = "<script>controlled-original</script>".into();
    engine
        .endpoint_events(&device.endpoint_id, &[event.clone()], now)
        .unwrap();
    engine
        .endpoint_heartbeat(
            &device.endpoint_id,
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
                    last_attempt_ms: now,
                    last_success_ms: now,
                    windows_network_events: Some(WindowsNetworkEventHealth {
                        stream_id: "d".repeat(64),
                        state: "active".into(),
                        started_ms: now - 60_000,
                        checked_ms: now,
                        subscriptions: 2,
                        loss_signals: 1,
                        error: "Source <gap>".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            },
            now,
        )
        .unwrap();
    let (app, _) = service(engine);
    for path in [
        "/endpoints".into(),
        format!("/endpoints/{}", device.endpoint_id),
    ] {
        let response = request(&app, "GET", &path, Some(OPERATOR), vec![]).await;
        assert_eq!(response.status(), StatusCode::OK);
        let html = String::from_utf8(
            to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        if path == "/endpoints" {
            assert!(html.contains("Windows ETW network events: coverage incomplete"));
            assert!(html.contains("Source &lt;gap&gt;"));
            assert!(html.contains("no ETW source replay"));
        } else {
            for label in [
                "Windows ETW operation",
                "Reported PID",
                "Reported source",
                "Reported destination",
                "Reported operation size",
                "Original EVENT_RECORD",
                "Collector QPC estimate",
                "excluding wall-clock changes or drift",
                "no firewall decision",
            ] {
                assert!(html.contains(label), "missing {label}");
            }
            assert!(html.contains("&lt;script&gt;controlled-original&lt;/script&gt;"));
            assert!(!html.contains("<script>controlled-original</script>"));
            assert!(!html.contains("<dt>Process</dt>"));
            assert!(!html.contains("<dt>File path</dt>"));
        }
    }
}
#[tokio::test]
async fn maximal_originals_fit_real_event_and_request_budgets_without_relaxing_server_limit() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let base = report(false, 10, 'c', 1, now);
    let first = larger(base, MAX_ORIGINAL_BYTES - 28);
    let event_bytes = serde_json::to_vec(&first).unwrap().len();
    assert!((96 * 1024..128 * 1024).contains(&event_bytes));
    first.validate(now).unwrap();
    let mut lo = 0;
    let mut hi = MAX_ORIGINAL_BYTES - 28;
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let second = larger(report(false, 10, 'c', 2, now), mid);
        if serde_json::to_vec(&[&first, &second]).unwrap().len() <= 192 * 1024 {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let second = larger(report(false, 10, 'c', 2, now), lo);
    let body = serde_json::to_vec(&[&first, &second]).unwrap();
    assert!((192 * 1024 - 2..=192 * 1024).contains(&body.len()));
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(false).unwrap();
    let device = enroll(&engine, 'a', now);
    let (app, _) = service(engine);
    let path = format!("/api/endpoint/{}/events", device.endpoint_id);
    let response = request(&app, "POST", &path, Some(&device.credential), body).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["acknowledged"], 2);
    let oversized = serde_json::to_vec(&[&first, &first, &first]).unwrap();
    assert!(oversized.len() > 256 * 1024);
    assert_eq!(
        request(&app, "POST", &path, Some(&device.credential), oversized)
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
