use athernex_endpoint_protocol::{
    self as p,
    macos_authentication::*,
    macos_process_events::{
        MacosEventTime, MacosExecutable, MacosMachTimebase, MacosNotifyResult,
        MacosProcessProjection,
    },
    telemetry::Telemetry,
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
fn process(pid: u32, version: u32) -> MacosProcessProjection {
    MacosProcessProjection {
        audit_token: [501, 501, 20, 501, 20, pid, 7, version],
        parent_audit_token: [0; 8],
        responsible_audit_token: [0; 8],
        ppid: 12,
        original_ppid: 12,
        group_id: 8,
        session_id: 8,
        executable: MacosExecutable {
            path_bytes_hex: b"/fixture/<script>controlled</script>"
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            path_truncated: true,
        },
    }
}
fn report(stream: char, receipt: u64, kind: u32) -> EndpointEvent {
    report_at(stream, receipt, kind, NOW)
}
fn report_at(stream: char, receipt: u64, kind: u32, now: u64) -> EndpointEvent {
    let hex = |text: &str| {
        text.as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let event = MacosAuthentication::from_original(MacosAuthenticationOriginal {
        projection_version: 1,
        stream_id: stream.to_string().repeat(64),
        receipt_sequence: receipt,
        message_version: 5,
        event_type: EVENT_TYPE,
        action_type: 1,
        notify_result: MacosNotifyResult::Auth { result: 0 },
        time: MacosEventTime {
            seconds: (now / 1000) as i64,
            nanoseconds: ((now % 1000) * 1_000_000 + 123) as i64,
        },
        mach_time: 100,
        mach_timebase: MacosMachTimebase {
            numerator: 1,
            denominator: 1,
        },
        seq_num: receipt - 1,
        global_seq_num: receipt - 1,
        event_process: process(77, 1),
        success: false,
        authentication_type: kind,
        authentication: match kind {
            0 => MacosAuthenticationPayload::OpenDirectory {
                instigator: Some(process(78, 2)),
                record_type_hex: hex("Users"),
                record_name_hex: hex("<script>controlled</script>"),
                node_name_hex: hex("/controlled/node"),
                db_path_hex: None,
            },
            1 => MacosAuthenticationPayload::TouchId {
                instigator: None,
                mode: 1,
                has_uid: true,
                uid: Some(501),
            },
            2 => MacosAuthenticationPayload::Token {
                instigator: Some(process(78, 2)),
                pubkey_hash_hex: hex("controlled-public-key-id"),
                token_id_hex: "00ff".into(),
                kerberos_principal_hex: Some(String::new()),
            },
            3 => MacosAuthenticationPayload::AutoUnlock {
                username_hex: hex("<script>controlled</script>"),
                purpose: 2,
            },
            _ => unreachable!(),
        },
    })
    .unwrap();
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
fn factors_preserve_exact_originals_without_bursts_accounts_or_process_identity() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("events.db");
    let mut engine = Engine::open(&database).unwrap();
    engine.configure_mode(false).unwrap();
    let first = enroll(&engine, 'a');
    let second = enroll(&engine, 'b');
    let mut reports = vec![
        report('c', 1, 0),
        report('c', 2, 1),
        report('c', 3, 2),
        report('c', 4, 3),
        report('d', 1, 0),
    ];
    // Eight failed OD mechanism reports with the same names do not establish
    // eight complete login failures; a later successful factor is not a login.
    reports.extend((5..12).map(|receipt| report('c', receipt, 0)));
    let mut success = report('c', 12, 0);
    let Some(Telemetry::MacosAuthentication { event }) = &mut success.telemetry else {
        unreachable!()
    };
    event.original.success = true;
    *event = MacosAuthentication::from_original(event.original.clone()).unwrap();
    success.id = event.event_id();
    reports.push(success);
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        reports.len()
    );
    assert_eq!(
        engine
            .endpoint_events(&second.endpoint_id, &reports[..1], NOW)
            .unwrap(),
        1
    );
    let mut objects = BTreeSet::new();
    let mut subjects = BTreeSet::new();
    let mut changes = BTreeSet::new();
    for (endpoint, expected) in [(&first, &reports[..]), (&second, &reports[..1])] {
        let saved = engine
            .endpoint_observations(&endpoint.endpoint_id, u64::MAX, 32)
            .unwrap();
        assert_eq!(saved.len(), expected.len());
        for original in expected {
            assert!(original.telemetry.as_ref().unwrap().process().is_none());
            let row = saved.iter().find(|r| r.event.id == original.id).unwrap();
            assert!(
                serde_json::to_value(&row.event).unwrap()
                    == serde_json::to_value(original).unwrap()
            );
            let evidence = engine.reconstruct(row.evidence_id).unwrap();
            assert_eq!(evidence.event.kind, Kind::Authentication);
            assert_eq!(evidence.event.outcome, Outcome::Observe);
            assert!(
                objects.insert(evidence.event.object),
                "Reported tokens merged observations"
            );
            assert!(
                subjects.insert(evidence.event.subject),
                "Reports merged account identities"
            );
            let context = evidence.context.unwrap();
            assert_eq!(context.host, endpoint.endpoint_id);
            assert_eq!(context.program, "macOS Endpoint Security authentication");
            assert_eq!(context.parent_pid, None);
            assert_eq!(context.uid, None);
            assert_eq!(context.process_start_ms, None);
            assert_eq!(context.parent_start_ms, None);
            assert!(context.journal_cursor.is_empty());
            assert!(context.summary.contains("retained projection only"));
            changes.insert(context.summary);
        }
    }
    assert_eq!(changes.len(), 4);
    let db = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let links: u64 = db.query_row("SELECT count(*) FROM graph_links WHERE entity LIKE 'endpoint-process:%' OR entity LIKE 'children:endpoint-process:%'", [], |r| r.get(0)).unwrap();
    assert_eq!(links, 0);
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|f| ["AX-001", "AX-002", "AX-006", "AX-007", "AX-008"].contains(&f.rule.as_str())));
    drop(db);
    drop(engine);
    let engine = Engine::open(&database).unwrap();
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        0
    );
    let mut conflict = reports[0].clone();
    conflict.detail = "Changed preserved envelope".into();
    assert!(engine
        .endpoint_events(&first.endpoint_id, &[report('c', 50, 0), conflict], NOW)
        .is_err());
    assert_eq!(
        engine
            .endpoint_observations(&first.endpoint_id, u64::MAX, 32)
            .unwrap()
            .len(),
        reports.len()
    );
}

#[tokio::test]
async fn authenticated_http_retains_factor_reports_with_qualified_private_exports() {
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
                    macos_authentication: Some(MacosAuthenticationHealth {
                        stream_id: "d".repeat(64),
                        state: "active".into(),
                        source_policy_sha256: source_policy_sha256(),
                        started_ms: NOW - 60_000,
                        checked_ms: NOW,
                        scope_checked_ms: NOW,
                        mute_snapshot_sha256: "e".repeat(64),
                        subscriptions: 1,
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
                assert!(html.contains(
                    "macOS Endpoint Security authentication reports: coverage incomplete"
                ));
                assert!(html.contains("Source &lt;gap&gt;"));
                assert!(html.contains("gaps have no source replay"));
            } else {
                assert!(html.contains("Retained authentication projection"));
                assert!(html.contains("not the full native message"));
                assert!(html.contains("Reported event process PID / version"));
                assert!(html.contains("Reported instigator PID / version"));
                assert!(html.contains("Not reported"));
                assert!(html.contains("Empty token"));
                assert!(html.contains("Bytes (hex): 00ff"));
                assert!(html.contains("Reported factor UID"));
                assert!(html.contains("not necessarily a username"));
                assert!(html.contains("not a completed login"));
                assert!(html.contains("&lt;script&gt;controlled&lt;/script&gt;"));
                assert!(!html.contains("<script>controlled</script>"));
            }
        }
    }
}
