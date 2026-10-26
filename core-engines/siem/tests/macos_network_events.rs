use athernex_endpoint_protocol::{
    self as p, macos_network_events::*, telemetry::Telemetry, EndpointEvent, Enrollment, Platform,
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
        enrollment_token: engine.create_enrollment(Platform::Macos, NOW).unwrap(),
        endpoint_id: id.to_string().repeat(64),
        credential: if id == 'a' { "d" } else { "e" }.repeat(64),
        hostname: "controlled-macos-fixture".into(),
        platform: Platform::Macos,
        arch: "aarch64".into(),
        version: "fixture".into(),
    };
    engine.enroll_endpoint(&endpoint, NOW).unwrap();
    endpoint
}
fn report_at(stream: char, receipt: u64, kind: u32, now: u64) -> EndpointEvent {
    let ipv6 = kind >= 2;
    let event = MacosNetworkEvent::from_original(MacosNetworkOriginal {
        projection_version: 1,
        stream_id: stream.to_string().repeat(64),
        receipt_sequence: receipt,
        callback: MacosNetworkCallback::NewFlow,
        receipt_time: MacosNetworkReceiptTime {
            seconds: (now / 1000) as i64,
            nanoseconds: ((now % 1000) * 1_000_000 + 123) as i64,
        },
        flow_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        direction: (kind % 3) as i32,
        socket_family: if ipv6 { 30 } else { 2 },
        socket_type: if kind == 1 { 2 } else { 1 },
        socket_protocol: match kind {
            1 => 17,
            2 => 0,
            _ => 6,
        },
        local: if kind == 0 {
            None
        } else {
            Some(MacosNetworkEndpoint {
                address: if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
                    .parse()
                    .unwrap(),
                port: 42,
                scope_id: if ipv6 { Some(0) } else { None },
            })
        },
        remote: None,
        source_app_audit_token_hex: Some("01".repeat(32)),
        source_process_audit_token_hex: if kind == 0 {
            None
        } else {
            Some("02".repeat(32))
        },
    })
    .unwrap();
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "macos_network_event".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: "<script>controlled</script>".into(),
        telemetry: Some(Telemetry::MacosNetworkEvent { event }),
    }
}
#[test]
fn new_flow_metadata_preserves_exact_originals_without_lifetime_or_process_joins() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("events.db");
    let mut engine = Engine::open(&db).unwrap();
    engine.configure_mode(false).unwrap();
    let first = enroll(&engine, 'a');
    let second = enroll(&engine, 'b');
    let reports = [
        report_at('c', 1, 0, NOW),
        report_at('c', 2, 1, NOW),
        report_at('c', 3, 2, NOW),
        report_at('c', 4, 3, NOW),
        report_at('d', 1, 0, NOW),
    ];
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        5
    );
    assert_eq!(
        engine
            .endpoint_events(&second.endpoint_id, &reports[..1], NOW)
            .unwrap(),
        1
    );
    let mut objects = BTreeSet::new();
    let mut subjects = BTreeSet::new();
    for (endpoint, expected) in [(&first, &reports[..]), (&second, &reports[..1])] {
        let rows = engine
            .endpoint_observations(&endpoint.endpoint_id, u64::MAX, 32)
            .unwrap();
        assert_eq!(rows.len(), expected.len());
        for original in expected {
            let row = rows.iter().find(|r| r.event.id == original.id).unwrap();
            assert_eq!(
                serde_json::to_value(&row.event).unwrap(),
                serde_json::to_value(original).unwrap()
            );
            assert!(row.event.telemetry.as_ref().unwrap().process().is_none());
            let evidence = engine.reconstruct(row.evidence_id).unwrap();
            assert_eq!(evidence.event.kind, Kind::Network);
            assert_eq!(evidence.event.outcome, Outcome::Observe);
            assert!(objects.insert(evidence.event.object));
            assert!(subjects.insert(evidence.event.subject));
            let context = evidence.context.unwrap();
            assert_eq!(context.host, endpoint.endpoint_id);
            assert_eq!(context.program, "macOS NetworkExtension metadata");
            assert_eq!(context.pid, None);
            assert_eq!(context.uid, None);
            assert_eq!(context.parent_pid, None);
            assert_eq!(context.process_start_ms, None);
            assert_eq!(context.parent_start_ms, None);
            assert!(context.journal_cursor.is_empty());
            assert!(context
                .summary
                .contains("Upstream OS loss accounting is unavailable"));
        }
    }
    let sql =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let links:u64=sql.query_row("SELECT count(*) FROM graph_links WHERE entity LIKE 'endpoint-process:%' OR entity LIKE 'children:endpoint-process:%'",[],|r|r.get(0)).unwrap();
    assert_eq!(links, 0);
    drop(sql);
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|f| ["AX-001", "AX-002", "AX-006", "AX-007", "AX-008"].contains(&f.rule.as_str())));
    drop(engine);
    let engine = Engine::open(&db).unwrap();
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        0
    );
    let mut conflict = reports[0].clone();
    conflict.detail = "conflicting envelope".into();
    assert!(engine
        .endpoint_events(
            &first.endpoint_id,
            &[report_at('c', 50, 0, NOW), conflict],
            NOW
        )
        .is_err());
    assert_eq!(
        engine
            .endpoint_observations(&first.endpoint_id, u64::MAX, 32)
            .unwrap()
            .len(),
        5
    );
}

#[tokio::test]
async fn authenticated_http_retains_network_metadata_with_qualified_private_exports() {
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
    let other = enroll(&engine, 'b');
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let observations = [
        report_at('c', 1, 0, now),
        report_at('c', 2, 1, now),
        report_at('c', 3, 2, now),
        report_at('c', 4, 3, now),
    ];
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
                    macos_network_events: Some(MacosNetworkEventHealth {
                        stream_id: "d".repeat(64),
                        state: "active".into(),
                        source_policy_sha256: source_policy_sha256(),
                        started_ms: NOW - 60_000,
                        checked_ms: NOW,
                        loss_signals: 1,
                        error: "Source <gap>".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            },
            NOW,
        )
        .unwrap();
    let token = "m".repeat(32);
    let app = router(App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(athernex_siem::auth::OperatorAuth::new(&token).unwrap()),
    });
    let ingest = format!("/api/endpoint/{}/events", endpoint.endpoint_id);
    let body = serde_json::to_vec(&observations).unwrap();
    for credential in [None, Some(other.credential.as_str()), Some(token.as_str())] {
        let mut request = Request::builder()
            .method("POST")
            .uri(&ingest)
            .header("Content-Type", "application/json");
        if let Some(value) = credential {
            request = request.header("Authorization", format!("Bearer {value}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body.clone())).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for accepted in [4, 0] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&ingest)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", endpoint.credential))
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let ack: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            ack,
            serde_json::json!({"accepted": accepted, "acknowledged":4, "durability":"committed"})
        );
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/endpoint/{}/events", other.endpoint_id))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", endpoint.credential))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let mut conflict = observations[0].clone();
    conflict.detail = "Conflicting retained envelope".into();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&ingest)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", endpoint.credential))
                .body(Body::from(
                    serde_json::to_vec(&[report_at('c', 50, 0, now), conflict]).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
                    .find(|r| r["event"]["id"] == observation.id)
                    .unwrap();
                assert!(row["event"] == serde_json::to_value(observation).unwrap());
            }
        } else {
            let html = std::str::from_utf8(&bytes).unwrap();
            if path == "/endpoints" {
                assert!(html.contains("macOS NetworkExtension metadata: coverage incomplete"));
                assert!(html.contains("Source &lt;gap&gt;"));
                assert!(html.contains("kernel loss accounting is unavailable"));
            } else {
                assert!(html.contains("Original network projection"));
                assert!(html.contains("Undetermined (reported protocol 0)"));
                assert!(html.contains("Source application audit token (hex)"));
                assert!(html.contains("Creator process audit token (hex)"));
                assert!(html.contains("Not reported"));
                assert!(html.contains("Collector admission ordinal"));
                assert!(html.contains("&lt;script&gt;controlled&lt;/script&gt;"));
                assert!(!html.contains("<script>controlled</script>"));
            }
        }
    }
}
