use athernex_endpoint_protocol::{
    self as p, Action, Command, EndpointEvent, Enrollment, Heartbeat, Platform, Receipt,
};
use athernex_siem::{
    engine::Engine,
    web::{router, App},
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
const NOW: u64 = 1_800_000_000_000;

#[test]
fn tracker_updates_preserve_nat_tuples_without_inventing_owners_or_counting_cumulative_bytes() {
    use athernex_siem::model::{Kind, Outcome};
    use p::network_events::{Change, Counters, NetworkEvent, Protocol, Tuple};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("network.db");
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    let endpoint = enrollment(&engine);
    engine.enroll_endpoint(&endpoint, NOW).unwrap();
    let events = (1..=8)
        .map(|sequence| {
            let telemetry = p::telemetry::Telemetry::NetworkEvent {
                boot_id: "a".repeat(64),
                stream_id: "b".repeat(64),
                namespace: 42,
                sequence,
                monotonic_ns: sequence * 1000,
                event: NetworkEvent {
                    change: Change::Updated,
                    protocol: Protocol::Tcp,
                    tracker_id: 7,
                    status: 8,
                    original: Tuple {
                        source: "192.0.2.1:2000".parse().unwrap(),
                        destination: "198.51.100.2:443".parse().unwrap(),
                        zone: Some(3),
                    },
                    reply: Tuple {
                        source: "10.0.0.2:8443".parse().unwrap(),
                        destination: "192.0.2.1:2000".parse().unwrap(),
                        zone: None,
                    },
                    zone: Some(3),
                    mark: None,
                    timeout_seconds: Some(120),
                    tcp_state: Some(3),
                    original_counters: Some(Counters {
                        packets: 10_000,
                        bytes: 9_000_000_000,
                    }),
                    reply_counters: None,
                    started_ns: None,
                    stopped_ns: None,
                    origin_port: 4100,
                },
            };
            EndpointEvent {
                id: p::hash(&serde_json::to_vec(&telemetry).unwrap()),
                time_ms: NOW - 100,
                kind: "network_event".into(),
                path: String::new(),
                sha256: String::new(),
                detection: String::new(),
                detail: String::new(),
                telemetry: Some(telemetry),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        engine
            .endpoint_events(&endpoint.endpoint_id, &events, NOW)
            .unwrap(),
        8
    );
    for row in engine
        .endpoint_observations(&endpoint.endpoint_id, i64::MAX as u64, 32)
        .unwrap()
    {
        assert!(
            events
                .iter()
                .any(|e| serde_json::to_value(e).unwrap()
                    == serde_json::to_value(&row.event).unwrap())
        );
        let normal = engine.reconstruct(row.evidence_id).unwrap();
        assert_eq!(normal.event.kind, Kind::Network);
        assert_eq!(normal.event.outcome, Outcome::Observe);
        assert_eq!(normal.event.bytes, 0);
        let context = normal.context.unwrap();
        assert_eq!(context.pid, None);
        assert_eq!(context.process_start_ms, None);
        assert!(context.summary.contains("cumulative"));
        assert_eq!(normal.object_label, "tcp:198.51.100.2:443");
    }
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|f| f.rule == "AX-003"));
    drop(engine);
    let engine = Engine::open(&path).unwrap();
    assert_eq!(
        engine
            .endpoint_events(&endpoint.endpoint_id, &events, NOW)
            .unwrap(),
        0
    );
    let mut changed = events[0].clone();
    changed.detail = "altered replay".into();
    assert!(engine
        .endpoint_events(&endpoint.endpoint_id, &[changed], NOW)
        .is_err());
}

fn process_fixture() -> p::telemetry::ProcessObservation {
    p::telemetry::ProcessObservation {
        pid: 4100,
        parent_pid: Some(4099),
        started_ms: NOW - 1000,
        parent_started_ms: Some(NOW - 2000),
        name: "fixture<image>".into(),
        executable: Some("/public/fixture<image>".into()),
        user_id: Some("1000".into()),
    }
}
fn telemetry_fixture(connection: bool) -> EndpointEvent {
    let process = process_fixture();
    let telemetry = if connection {
        p::telemetry::Telemetry::Connection {
            boot_id: "1".repeat(64),
            connection: p::telemetry::ConnectionObservation {
                protocol: "tcp".into(),
                local: "192.0.2.7:41111".parse().unwrap(),
                remote: Some("203.0.113.10:443".parse().unwrap()),
                state: "ESTABLISHED".into(),
                owner_pid: Some(process.pid),
                process: Some(process.clone()),
            },
        }
    } else {
        p::telemetry::Telemetry::Process {
            boot_id: "1".repeat(64),
            process: process.clone(),
        }
    };
    EndpointEvent {
        id: p::hash(if connection { b"socket" } else { b"process" }),
        time_ms: NOW - 100,
        kind: telemetry.kind().into(),
        path: process.executable.unwrap(),
        telemetry: Some(telemetry),
        sha256: String::new(),
        detection: String::new(),
        detail: "Public snapshot fixture".into(),
    }
}
fn correlated_fixture(e: &mut Engine) -> (Enrollment, i64) {
    e.configure_mode(false).unwrap();
    let first = enrollment(e);
    e.enroll_endpoint(&first, NOW).unwrap();
    let mut second = enrollment(e);
    second.endpoint_id = "c".repeat(64);
    second.credential = "d".repeat(64);
    e.enroll_endpoint(&second, NOW).unwrap();
    let observations = [telemetry_fixture(false), telemetry_fixture(true)];
    e.endpoint_events(&second.endpoint_id, &observations, NOW)
        .unwrap();
    e.endpoint_events(&first.endpoint_id, &observations, NOW)
        .unwrap();
    let malware = EndpointEvent {
        id: "e".repeat(64),
        time_ms: NOW,
        kind: "malware".into(),
        path: process_fixture().executable.unwrap(),
        sha256: "f".repeat(64),
        detection: "Public fixture".into(),
        detail: String::new(),
        telemetry: None,
    };
    e.endpoint_events(&first.endpoint_id, &[malware], NOW)
        .unwrap();
    let case = e.cases().unwrap().remove(0);
    assert_eq!(case.evidence.len(), 3);
    assert!(case.notes[0].text.contains("do not prove execution"));
    for item in &case.evidence {
        assert_eq!(item.context.as_ref().unwrap().host, first.endpoint_id);
    }
    (first, case.id)
}

#[test]
fn typed_observations_correlate_per_device_and_survive_sealing() {
    use athernex_siem::{
        memory::DAY,
        model::{Kind, Outcome},
    };
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("fleet.db");
    let mut e = Engine::open(&db).unwrap();
    let (endpoint, case_id) = correlated_fixture(&mut e);
    let records = e
        .endpoint_observations(&endpoint.endpoint_id, u64::MAX, 2)
        .unwrap();
    assert_eq!(records.len(), 2);
    let connection = e.reconstruct(records[1].evidence_id).unwrap();
    assert_eq!(connection.event.kind, Kind::Network);
    assert_eq!(connection.event.outcome, Outcome::Observe);
    assert_eq!(connection.event.bytes, 0);
    assert_eq!(connection.object_label, "203.0.113.10");
    let context = connection.context.unwrap();
    assert_eq!(context.pid, Some(4100));
    assert_eq!(context.parent_pid, Some(4099));
    assert_eq!(context.process_start_ms, Some(NOW - 1000));
    assert_eq!(context.parent_start_ms, Some(NOW - 2000));
    assert_eq!(context.uid, Some(1000));
    let older = e
        .endpoint_observations(&endpoint.endpoint_id, records[1].evidence_id, 64)
        .unwrap();
    assert_eq!(older.len(), 1);
    assert_eq!(
        e.reconstruct(older[0].evidence_id).unwrap().event.kind,
        Kind::Process
    );
    e.tick(NOW + 3 * DAY).unwrap();
    assert_eq!(e.seal_evidence(NOW + 3 * DAY).unwrap(), Some(1));
    drop(e);
    let e = Engine::open(&db).unwrap();
    let restored = e
        .endpoint_observations(&endpoint.endpoint_id, u64::MAX, 64)
        .unwrap();
    assert_eq!(restored.len(), 3);
    assert_eq!(
        serde_json::to_value(&restored[1].event).unwrap(),
        serde_json::to_value(telemetry_fixture(true)).unwrap()
    );
    assert_eq!(
        e.endpoint_events(
            &endpoint.endpoint_id,
            &[telemetry_fixture(false), telemetry_fixture(true)],
            NOW + 3 * DAY
        )
        .unwrap(),
        0
    );
    let case = e
        .cases()
        .unwrap()
        .into_iter()
        .find(|c| c.id == case_id)
        .unwrap();
    for evidence in case.evidence {
        assert!(e.endpoint_observation(evidence.event.id).unwrap().is_some());
    }
}

#[tokio::test]
async fn endpoint_evidence_views_and_exports_require_operator_and_preserve_scope() {
    let mut engine = Engine::memory().unwrap();
    let (endpoint, case_id) = correlated_fixture(&mut engine);
    let app = router(App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "csrf-fixture".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("operator-fixture-32-characters-long").unwrap(),
        ),
    });
    for uri in [
        format!("/api/endpoints/{}/events", endpoint.endpoint_id),
        format!("/api/cases/{case_id}/export"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", format!("Bearer {}", endpoint.credential))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/endpoints/{}", endpoint.endpoint_id))
                .header(
                    "authorization",
                    "Bearer operator-fixture-32-characters-long",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("fixture&lt;image&gt;"));
    assert!(!html.contains("fixture<image>"));
    assert!(!html.contains(&endpoint.credential));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/endpoints/{}/events", endpoint.endpoint_id))
                .header(
                    "authorization",
                    "Bearer operator-fixture-32-characters-long",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let records: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(records.as_array().unwrap().len(), 3);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/cases/{case_id}/export"))
                .header(
                    "authorization",
                    "Bearer operator-fixture-32-characters-long",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let export: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(export["endpoint_observations"].as_array().unwrap().len(), 3);
    assert_eq!(export["evidence"].as_array().unwrap().len(), 3);
    assert!(export["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["context"]["host"] == endpoint.endpoint_id));
    assert!(export["endpoint_observations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["event"]["telemetry"]["connection"]["remote"] == "203.0.113.10:443"));
}

#[test]
fn malware_playbook_is_scoped_idempotent_and_revocable() {
    let (e, r) = setup();
    let mut h = health();
    h.capabilities.push("quarantine".into());
    e.endpoint_heartbeat(&r.endpoint_id, &h, NOW).unwrap();
    e.configure_malware_playbook(&r.endpoint_id, "automatic", NOW)
        .unwrap();
    let event = EndpointEvent {
        telemetry: None,
        id: "e".repeat(64),
        time_ms: NOW,
        kind: "malware".into(),
        path: "/home/fixture/test.txt".into(),
        sha256: "f".repeat(64),
        detection: "Fixture".into(),
        detail: String::new(),
    };
    e.endpoint_events(&r.endpoint_id, std::slice::from_ref(&event), NOW)
        .unwrap();
    e.endpoint_events(&r.endpoint_id, &[event], NOW).unwrap();
    let commands = e.poll_endpoint_commands(&r.endpoint_id, NOW).unwrap();
    assert_eq!(commands.len(), 1);
    assert!(matches!(commands[0].action, Action::Quarantine { .. }));
    e.configure_malware_playbook(&r.endpoint_id, "disabled", NOW)
        .unwrap();
    assert!(e
        .poll_endpoint_commands(&r.endpoint_id, NOW)
        .unwrap()
        .is_empty());
    assert!(e
        .start_endpoint_command(&r.endpoint_id, &commands[0].id, NOW)
        .is_err());
}
fn enrollment(e: &Engine) -> Enrollment {
    Enrollment {
        protocol: 1,
        enrollment_token: e.create_enrollment(Platform::Linux, NOW).unwrap(),
        endpoint_id: "a".repeat(64),
        credential: "b".repeat(64),
        hostname: "fixture-host".into(),
        platform: Platform::Linux,
        arch: "x86_64".into(),
        version: "0.1.0".into(),
    }
}
fn health() -> Heartbeat {
    Heartbeat {
        controller_updates: None,
        updates: None,
        protection: None,
        collector: None,
        version: "0.1.0".into(),
        capabilities: vec!["inventory".into(), "scan".into()],
        scanner: "fixture".into(),
        realtime: false,
        signature_version: String::new(),
        spool_events: 0,
        error: String::new(),
    }
}
fn setup() -> (Engine, Enrollment) {
    let mut e = Engine::memory().unwrap();
    e.configure_mode(false).unwrap();
    let request = enrollment(&e);
    e.enroll_endpoint(&request, NOW).unwrap();
    e.endpoint_heartbeat(&request.endpoint_id, &health(), NOW)
        .unwrap();
    (e, request)
}

#[test]
fn enrollment_is_single_device_scoped_and_retry_safe() {
    let (e, mut r) = setup();
    e.enroll_endpoint(&r, NOW + 1).unwrap();
    r.endpoint_id = "c".repeat(64);
    assert!(e.enroll_endpoint(&r, NOW).is_err());
    assert!(e
        .authenticate_endpoint(&"a".repeat(64), &"c".repeat(64))
        .is_err());
    let mut r = enrollment(&e);
    r.platform = Platform::Windows;
    assert!(e.enroll_endpoint(&r, NOW).is_err());
    let r = enrollment(&e);
    assert!(e.enroll_endpoint(&r, NOW + 900_000).is_err());
}

#[test]
fn approval_expiry_scope_and_receipts_are_enforced() {
    let (e, r) = setup();
    let case = e.create_case("Endpoint fixture", 3, NOW).unwrap();
    let id = e
        .queue_endpoint_action(&r.endpoint_id, Action::Inventory, case, NOW)
        .unwrap();
    assert!(e
        .poll_endpoint_commands(&r.endpoint_id, NOW)
        .unwrap()
        .is_empty());
    assert!(e.start_endpoint_command(&r.endpoint_id, &id, NOW).is_err());
    e.review_endpoint_action(&id, true, NOW).unwrap();
    assert!(e.start_endpoint_command(&"c".repeat(64), &id, NOW).is_err());
    let command = e.start_endpoint_command(&r.endpoint_id, &id, NOW).unwrap();
    assert!(e.start_endpoint_command(&r.endpoint_id, &id, NOW).is_err());
    let mut receipt = Receipt {
        command_id: id,
        action_hash: command.action_hash,
        outcome: "succeeded".into(),
        output: "fixture inventory".into(),
        finished_ms: NOW,
    };
    e.finish_endpoint_command(&r.endpoint_id, &receipt, NOW)
        .unwrap();
    e.finish_endpoint_command(&r.endpoint_id, &receipt, NOW)
        .unwrap();
    let exported = e.case_endpoint_commands(case).unwrap();
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].receipt.as_ref().unwrap().output, receipt.output);
    let unrelated = e.create_case("Separate investigation", 1, NOW).unwrap();
    assert!(e.case_endpoint_commands(unrelated).unwrap().is_empty());
    receipt.output = "different result".into();
    assert!(e
        .finish_endpoint_command(&r.endpoint_id, &receipt, NOW)
        .is_err());
    assert_eq!(
        e.cases()
            .unwrap()
            .iter()
            .find(|c| c.id == case)
            .unwrap()
            .notes
            .len(),
        1
    );
}

#[test]
fn revoke_and_closed_cases_block_queued_work() {
    let (e, r) = setup();
    let case = e.create_case("Endpoint fixture", 3, NOW).unwrap();
    let id = e
        .queue_endpoint_action(&r.endpoint_id, Action::Inventory, case, NOW)
        .unwrap();
    e.review_endpoint_action(&id, true, NOW).unwrap();
    e.endpoint_state(&r.endpoint_id, "revoked", NOW).unwrap();
    assert!(e
        .authenticate_endpoint(&r.endpoint_id, &r.credential)
        .is_err());
    e.endpoint_state(&r.endpoint_id, "active", NOW).unwrap();
    assert!(e
        .poll_endpoint_commands(&r.endpoint_id, NOW)
        .unwrap()
        .is_empty());
    let id = e
        .queue_endpoint_action(&r.endpoint_id, Action::Inventory, case, NOW)
        .unwrap();
    e.review_endpoint_action(&id, true, NOW).unwrap();
    e.update_case(
        case,
        1,
        athernex_siem::operations::CaseUpdate {
            owner: "analyst",
            status: "resolved",
            severity: 3,
            note: "closed",
        },
        NOW,
    )
    .unwrap();
    assert!(e.start_endpoint_command(&r.endpoint_id, &id, NOW).is_err());
}

#[test]
fn malware_roundtrip_retains_full_identity_hash_and_durable_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.db");
    let r;
    let event = EndpointEvent {
        telemetry: None,
        id: "c".repeat(64),
        time_ms: NOW,
        kind: "malware".into(),
        path: "/home/fixture/évidence.txt".into(),
        sha256: "d".repeat(64),
        detection: "Fixture.Test".into(),
        detail: "public test fixture".into(),
    };
    {
        let mut e = Engine::open(&path).unwrap();
        e.configure_mode(false).unwrap();
        r = enrollment(&e);
        e.enroll_endpoint(&r, NOW).unwrap();
        assert_eq!(
            e.endpoint_events(&r.endpoint_id, std::slice::from_ref(&event), NOW)
                .unwrap(),
            1
        );
    }
    let e = Engine::open(&path).unwrap();
    e.authenticate_endpoint(&r.endpoint_id, &r.credential)
        .unwrap();
    assert_eq!(
        e.endpoint_events(&r.endpoint_id, std::slice::from_ref(&event), NOW)
            .unwrap(),
        0
    );
    let mut conflict = event;
    conflict.detail = "conflict".into();
    assert!(e.endpoint_events(&r.endpoint_id, &[conflict], NOW).is_err());
    let cases = e.cases().unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].evidence[0].subject_label, r.endpoint_id);
    assert_eq!(cases[0].evidence[0].object_label, "d".repeat(64));
    assert!(cases[0].notes[0].text.contains("évidence"));
}

#[tokio::test]
async fn endpoint_http_boundary_and_receipt_loop() {
    let (e, r) = setup();
    let app = App {
        engine: Arc::new(Mutex::new(e)),
        csrf: "csrf-fixture".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("operator-fixture-32-characters-long").unwrap(),
        ),
    };
    let router = router(app.clone());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/endpoints")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/endpoints")
                .header("authorization", format!("Bearer {}", r.credential))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let uri = format!("/api/endpoint/{}/heartbeat", r.endpoint_id);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&health()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header("authorization", format!("Bearer {}", r.credential))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&health()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/endpoints")
                .header(
                    "authorization",
                    "Bearer operator-fixture-32-characters-long",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("fixture-host"));
    assert!(html.contains("not active"));
    assert!(!html.contains(&r.credential));
    let command: Command = {
        let e = app.engine.lock().unwrap();
        let now = athernex_siem::model::now_ms();
        let case = e.create_case("HTTP fixture", 3, now).unwrap();
        let id = e
            .queue_endpoint_action(&r.endpoint_id, Action::Inventory, case, now)
            .unwrap();
        e.review_endpoint_action(&id, true, now).unwrap();
        e.poll_endpoint_commands(&r.endpoint_id, now)
            .unwrap()
            .remove(0)
    };
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/endpoint/{}/command/{}/start",
                    r.endpoint_id, command.id
                ))
                .header("authorization", format!("Bearer {}", r.credential))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn installer_checks_artifact_integrity_and_contains_platform_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let binary = b"public nonexecutable fixture";
    std::fs::write(dir.path().join("athernex-endpoint-linux-x86_64"), binary).unwrap();
    let artifact = athernex_siem::fleet_web::Artifact {
        windows_filter: None,
        native_adapter: None,
        macos_network: None,
        target: "linux-x86_64".into(),
        version: "fixture".into(),
        sha256: p::hash(binary),
        signing: "development-unsigned".into(),
    };
    std::fs::write(
        dir.path().join("linux-x86_64.json"),
        serde_json::to_vec(&artifact).unwrap(),
    )
    .unwrap();
    let bootstrap = p::Bootstrap {
        protocol: 1,
        server: "https://example.test/".into(),
        enrollment_token: "a".repeat(64),
        platform: Platform::Linux,
        antivirus: vec![],
    };
    let bytes =
        athernex_siem::fleet_web::installer_bundle(dir.path(), "linux-x86_64", &bootstrap).unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    assert!(zip.by_name("install.sh").is_ok());
    assert!(zip.by_name("bootstrap.json").is_ok());
    std::fs::write(
        dir.path().join("athernex-endpoint-linux-x86_64"),
        b"tampered",
    )
    .unwrap();
    assert!(
        athernex_siem::fleet_web::installer_bundle(dir.path(), "linux-x86_64", &bootstrap).is_err()
    );
}

#[test]
fn macos_installer_binds_the_optional_native_adapter_to_architecture_and_catalog_hash() {
    use athernex_siem::fleet_web::{Artifact, NativeArtifact};
    use std::io::Read;
    for (target, machine) in [
        ("macos-x86_64", 0x1000007u32),
        ("macos-aarch64", 0x100000cu32),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let main = b"public management fixture";
        let mut adapter = vec![0u8; 64];
        adapter[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        adapter[4..8].copy_from_slice(&machine.to_le_bytes());
        std::fs::write(dir.path().join(format!("athernex-endpoint-{target}")), main).unwrap();
        let native_path = dir
            .path()
            .join(format!("athernex-endpoint-native-{target}"));
        std::fs::write(&native_path, &adapter).unwrap();
        let mut artifact = Artifact {
            windows_filter: None,
            target: target.into(),
            version: "fixture".into(),
            sha256: p::hash(main),
            signing: "native-signature-verified".into(),
            macos_network: None,
            native_adapter: Some(NativeArtifact {
                backend: "macos-endpoint-security".into(),
                sha256: p::hash(&adapter),
                signing: "native-signature-verified".into(),
            }),
        };
        let manifest = dir.path().join(format!("{target}.json"));
        std::fs::write(&manifest, serde_json::to_vec(&artifact).unwrap()).unwrap();
        let bootstrap = p::Bootstrap {
            protocol: 1,
            server: "https://example.test/".into(),
            enrollment_token: "a".repeat(64),
            platform: Platform::Macos,
            antivirus: vec![],
        };
        let bytes =
            athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut embedded = Vec::new();
        archive
            .by_name("athernex-endpoint-native")
            .unwrap()
            .read_to_end(&mut embedded)
            .unwrap();
        assert_eq!(embedded, adapter);
        let mut instructions = String::new();
        archive
            .by_name("native-adapter.txt")
            .unwrap()
            .read_to_string(&mut instructions)
            .unwrap();
        assert!(instructions.contains("dedicated scanner account and runtime"));
        assert!(
            instructions.contains("Protection remains unverified until live blocking is proven")
        );
        adapter[63] ^= 1;
        std::fs::write(&native_path, &adapter).unwrap();
        assert!(
            athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).is_err()
        );
        adapter[4..8].copy_from_slice(&(machine ^ 1).to_le_bytes());
        artifact.native_adapter.as_mut().unwrap().sha256 = p::hash(&adapter);
        std::fs::write(&manifest, serde_json::to_vec(&artifact).unwrap()).unwrap();
        std::fs::write(&native_path, &adapter).unwrap();
        assert!(
            athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).is_err(),
            "A matching checksum cannot authorize an adapter for another architecture"
        );
        std::fs::remove_file(&native_path).unwrap();
        assert!(
            athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).is_err()
        );
    }
}

#[test]
fn native_adapter_metadata_cannot_claim_unsigned_or_wrong_platform_components() {
    use athernex_siem::fleet_web::{Artifact, NativeArtifact};
    for (target, main_signing, native_signing, backend) in [
        (
            "linux-x86_64",
            "native-signature-verified",
            "native-signature-verified",
            "macos-endpoint-security",
        ),
        (
            "macos-aarch64",
            "development-unsigned",
            "native-signature-verified",
            "macos-endpoint-security",
        ),
        (
            "macos-aarch64",
            "native-signature-verified",
            "development-unsigned",
            "macos-endpoint-security",
        ),
        (
            "macos-aarch64",
            "native-signature-verified",
            "native-signature-verified",
            "unknown",
        ),
    ] {
        let artifact = Artifact {
            windows_filter: None,
            target: target.into(),
            version: "fixture".into(),
            sha256: "a".repeat(64),
            signing: main_signing.into(),
            macos_network: None,
            native_adapter: Some(NativeArtifact {
                backend: backend.into(),
                sha256: "b".repeat(64),
                signing: native_signing.into(),
            }),
        };
        assert!(artifact.native().is_err());
    }
}

#[test]
fn authentication_accounts_are_device_scoped_and_original_reports_survive_detection_and_replay() {
    use p::authentication::{from_journal, JournalRecord};
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("fleet.db");
    let mut engine = Engine::open(&db).unwrap();
    engine.configure_mode(false).unwrap();
    let first = enrollment(&engine);
    engine.enroll_endpoint(&first, NOW).unwrap();
    let mut second = enrollment(&engine);
    second.endpoint_id = "c".repeat(64);
    second.credential = "d".repeat(64);
    engine.enroll_endpoint(&second, NOW).unwrap();
    let event = |sequence: u64| {
        let record = JournalRecord {
            cursor: format!("s=fixture;i={sequence}"),
            sequence_id: "a".repeat(32),
            sequence,
            realtime_us: (NOW - 1000 + sequence) * 1000,
            machine_id: "b".repeat(32),
            boot_id: "c".repeat(32),
            executable: "/usr/sbin/sshd".into(),
            reporter_uid: 0,
            reporter_pid: 42,
            message: "Failed publickey for fixture from 192.0.2.7 port 2222 ssh2".into(),
        };
        let auth = from_journal(&record).unwrap().unwrap();
        EndpointEvent {
            id: auth.event_id(),
            time_ms: record.realtime_us / 1000,
            kind: "authentication".into(),
            path: String::new(),
            sha256: String::new(),
            detection: String::new(),
            detail: String::new(),
            telemetry: Some(p::telemetry::Telemetry::Authentication { event: auth }),
        }
    };
    let rows = (1..=8).map(event).collect::<Vec<_>>();
    engine
        .endpoint_events(&first.endpoint_id, &rows[..7], NOW)
        .unwrap();
    engine
        .endpoint_events(&second.endpoint_id, &rows[7..], NOW)
        .unwrap();
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|f| f.rule == "AX-001"));
    engine
        .endpoint_events(&first.endpoint_id, &rows[7..], NOW)
        .unwrap();
    let findings = engine.snapshot().unwrap().findings;
    let burst = findings.iter().find(|f| f.rule == "AX-001").unwrap();
    assert_eq!(burst.evidence.len(), 8);
    for evidence in &burst.evidence {
        assert_eq!(evidence.context.as_ref().unwrap().host, first.endpoint_id);
        assert_eq!(evidence.context.as_ref().unwrap().uid, Some(0));
        assert_eq!(
            evidence.event.kind,
            athernex_siem::model::Kind::Authentication
        );
        assert_eq!(evidence.event.outcome, athernex_siem::model::Outcome::Deny);
    }
    let original = engine
        .endpoint_observations(&first.endpoint_id, i64::MAX as u64, 32)
        .unwrap();
    assert_eq!(original.len(), 8);
    for row in &rows {
        assert!(original
            .iter()
            .any(|saved| serde_json::to_value(&saved.event).unwrap()
                == serde_json::to_value(row).unwrap()));
    }
    let count = findings.len();
    drop(engine);
    let reopened = Engine::open(&db).unwrap();
    assert_eq!(
        reopened
            .endpoint_events(&first.endpoint_id, &rows, NOW)
            .unwrap(),
        0
    );
    assert_eq!(reopened.snapshot().unwrap().findings.len(), count);
    let mut changed = rows[0].clone();
    changed.detail = "changed replay".into();
    assert!(reopened
        .endpoint_events(&first.endpoint_id, &[changed], NOW)
        .is_err());
}

#[tokio::test]
async fn pam_module_failures_remain_original_evidence_without_becoming_service_denials() {
    use athernex_siem::model::Outcome;
    use p::authentication::{from_journal, JournalRecord};
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(false).unwrap();
    let endpoint = enrollment(&engine);
    engine.enroll_endpoint(&endpoint, NOW).unwrap();
    let make = |sequence: u64, message: &str| {
        let report = from_journal(&JournalRecord {
            cursor: format!("pam-fixture-{sequence}"),
            sequence_id: "a".repeat(32),
            sequence,
            realtime_us: (NOW - 1000 + sequence) * 1000,
            machine_id: "b".repeat(32),
            boot_id: "c".repeat(32),
            executable: "/usr/sbin/sshd".into(),
            reporter_uid: 0,
            reporter_pid: sequence as u32,
            message: message.into(),
        })
        .unwrap()
        .unwrap();
        EndpointEvent {
            id: report.event_id(),
            time_ms: report.journal.realtime_us / 1000,
            kind: "authentication".into(),
            path: String::new(),
            sha256: String::new(),
            detection: String::new(),
            detail: String::new(),
            telemetry: Some(p::telemetry::Telemetry::Authentication { event: report }),
        }
    };
    let mut originals = Vec::new();
    for index in 0..8 {
        originals.push(make(2*index+1,"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.7 user=fixture"));
        originals.push(make(
            2 * index + 2,
            "Accepted password for fixture from 192.0.2.7 port 2222 ssh2",
        ));
    }
    engine
        .endpoint_events(&endpoint.endpoint_id, &originals, NOW)
        .unwrap();
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|f| f.rule == "AX-001"));
    for row in engine
        .endpoint_observations(&endpoint.endpoint_id, i64::MAX as u64, 64)
        .unwrap()
    {
        let Some(p::telemetry::Telemetry::Authentication { event }) = &row.event.telemetry else {
            panic!("Missing original")
        };
        let normalized = engine.reconstruct(row.evidence_id).unwrap();
        assert_eq!(
            normalized.event.outcome,
            if event.service_outcome().is_none() {
                Outcome::Observe
            } else {
                Outcome::Allow
            }
        );
        assert!(originals
            .iter()
            .any(|original| serde_json::to_value(original).unwrap()
                == serde_json::to_value(&row.event).unwrap()));
    }
    for index in 0..8 {
        let denied = make(
            100 + index,
            "Failed password for fixture from 192.0.2.7 port 2222 ssh2",
        );
        engine
            .endpoint_events(&endpoint.endpoint_id, &[denied], NOW)
            .unwrap();
        assert_eq!(
            engine
                .snapshot()
                .unwrap()
                .findings
                .iter()
                .any(|f| f.rule == "AX-001"),
            index == 7
        );
    }
    assert_eq!(
        engine
            .endpoint_events(&endpoint.endpoint_id, &originals, NOW)
            .unwrap(),
        0
    );
    let app = router(App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("public-pam-module-operator-fixture-32")
                .unwrap(),
        ),
    });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/endpoints/{}", endpoint.endpoint_id))
                .header(
                    "Authorization",
                    "Bearer public-pam-module-operator-fixture-32",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains("Module failure; service outcome not reported"));
    assert!(html.contains("pam_unix(sshd:auth): authentication failure;"));
}

#[test]
fn macos_network_bundle_binds_marker_hash_size_and_combined_component_budget() {
    use athernex_siem::fleet_web::{Artifact, NativeArtifact};
    use p::installer::MacosNetworkArtifact;
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let target = "macos-aarch64";
    let main = b"controlled management bytes";
    let archive = b"opaque archive fixture; target installer owns internal validation";
    let mut native = vec![0u8; 64];
    native[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    native[4..8].copy_from_slice(&0x100000cu32.to_le_bytes());
    std::fs::write(dir.path().join(format!("athernex-endpoint-{target}")), main).unwrap();
    std::fs::write(
        dir.path()
            .join(format!("athernex-endpoint-native-{target}")),
        &native,
    )
    .unwrap();
    let network_path = dir
        .path()
        .join(format!("athernex-macos-network-{target}.zip"));
    std::fs::write(&network_path, archive).unwrap();
    let descriptor = MacosNetworkArtifact {
        schema: 1,
        backend: "macos-network-extension".into(),
        signing: "native-signature-verified".into(),
        sha256: p::hash(archive),
        bytes: archive.len() as u64,
        tree_sha256: "a".repeat(64),
        container_sha256: "b".repeat(64),
        provider_sha256: "c".repeat(64),
        source_policy_sha256: p::macos_network_events::source_policy_sha256(),
        team_id: "ABCDEFGHIJ".into(),
        agent_identifier: "test.fixture.agent".into(),
        container_identifier: "test.fixture.container".into(),
        provider_identifier: "test.fixture.provider".into(),
        app_group: "group.test.fixture".into(),
        mach_service_name: "group.test.fixture.source".into(),
        provider_cdhashes: vec!["a".repeat(40)],
    };
    let mut artifact = Artifact {
        windows_filter: None,
        target: target.into(),
        version: "fixture".into(),
        sha256: p::hash(main),
        signing: "native-signature-verified".into(),
        native_adapter: Some(NativeArtifact {
            backend: "macos-endpoint-security".into(),
            sha256: p::hash(&native),
            signing: "native-signature-verified".into(),
        }),
        macos_network: Some(descriptor.clone()),
    };
    let manifest = dir.path().join(format!("{target}.json"));
    let save = |a: &Artifact| std::fs::write(&manifest, serde_json::to_vec(a).unwrap()).unwrap();
    save(&artifact);
    let bootstrap = p::Bootstrap {
        protocol: 1,
        server: "https://example.test/".into(),
        enrollment_token: "a".repeat(64),
        platform: Platform::Macos,
        antivirus: vec![],
    };
    let bytes = athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).unwrap();
    let mut bundle = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut embedded = Vec::new();
    bundle
        .by_name("macos-network.zip")
        .unwrap()
        .read_to_end(&mut embedded)
        .unwrap();
    assert_eq!(embedded, archive);
    let mut marker = String::new();
    bundle
        .by_name("macos-network.required")
        .unwrap()
        .read_to_string(&mut marker)
        .unwrap();
    assert_eq!(marker, "1\n");
    let mut instructions = String::new();
    bundle
        .by_name("macos-network.txt")
        .unwrap()
        .read_to_string(&mut instructions)
        .unwrap();
    assert!(instructions.contains("does not activate"));
    assert!(instructions.contains("does not stop or uninstall"));
    for invalid in 0..4 {
        let mut candidate = descriptor.clone();
        match invalid {
            0 => candidate.sha256 = "f".repeat(64),
            1 => candidate.bytes += 1,
            2 => candidate.source_policy_sha256 = "f".repeat(64),
            _ => candidate.signing = "development-unsigned".into(),
        };
        artifact.macos_network = Some(candidate);
        save(&artifact);
        assert!(
            athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).is_err()
        );
    }
    // Declared network bytes plus management fit alone; the native component
    // makes the combined budget exceed the cap before reading archive bytes.
    artifact.macos_network = Some(descriptor.clone());
    artifact.macos_network.as_mut().unwrap().bytes = 64 * 1024 * 1024 - main.len() as u64;
    save(&artifact);
    assert!(
        athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap)
            .unwrap_err()
            .to_string()
            .contains("Combined endpoint components")
    );
    artifact.macos_network = Some(descriptor);
    save(&artifact);
    std::fs::write(&network_path, b"tampered").unwrap();
    assert!(athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).is_err());
    std::fs::remove_file(&network_path).unwrap();
    assert!(athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).is_err());
    artifact.macos_network = None;
    save(&artifact);
    let bytes = athernex_siem::fleet_web::installer_bundle(dir.path(), target, &bootstrap).unwrap();
    let mut bundle = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    assert!(bundle.by_name("macos-network.required").is_err());
    assert!(bundle.by_name("macos-network.zip").is_err());
}

#[test]
fn windows_filter_package_delivery_requires_exact_bytes_and_marker() {
    use athernex_endpoint_protocol::windows_filter_package::{
        Descriptor, Member, MAGIC, PROFILE, TRUST,
    };
    let dir = tempfile::tempdir().unwrap();
    let binary = b"nonexecutable synthetic management fixture";
    let mut d = Descriptor {
        schema: 1,
        sha256: "a".repeat(64),
        bytes: 0,
        profile: PROFILE.into(),
        trust_policy: TRUST.into(),
        source_revision: "b".repeat(40),
        expected_abi: 2,
        deployment: None,
        driver_version: "1.2.3.4".into(),
        driver_date: "01/01/2025".into(),
        altitude: "325000.01".into(),
        sys: Member {
            bytes: 256,
            sha256: "a".repeat(64),
        },
        inf: Member {
            bytes: 1,
            sha256: "a".repeat(64),
        },
        cat: Member {
            bytes: 1,
            sha256: "a".repeat(64),
        },
    };
    let mut sys = vec![0; 256];
    sys[..2].copy_from_slice(b"MZ");
    sys[60..64].copy_from_slice(&64u32.to_le_bytes());
    sys[64..70].copy_from_slice(b"PE\0\0\x64\x86");
    sys[88..90].copy_from_slice(&[11, 2]);
    sys[156..158].copy_from_slice(&[1, 0]);
    let inf = d.inf_bytes();
    let cat = b"unsigned structural fixture".to_vec();
    for (member, bytes) in [&mut d.sys, &mut d.inf, &mut d.cat]
        .into_iter()
        .zip([&sys, &inf, &cat])
    {
        member.bytes = bytes.len() as u64;
        member.sha256 = p::hash(bytes);
    }
    let mut package = MAGIC.to_vec();
    for member in d.members() {
        package.extend(member.bytes.to_le_bytes());
    }
    for bytes in [&sys, &inf, &cat] {
        package.extend(bytes);
    }
    d.bytes = package.len() as u64;
    d.sha256 = p::hash(&package);
    let mut artifact = athernex_siem::fleet_web::Artifact {
        target: "windows-x86_64".into(),
        version: "fixture".into(),
        sha256: p::hash(binary),
        signing: "native-signature-verified".into(),
        native_adapter: None,
        macos_network: None,
        windows_filter: Some(d),
    };
    let manifest = dir.path().join("windows-x86_64.json");
    let component = dir
        .path()
        .join("athernex-windows-filter-windows-x86_64.axpkg");
    std::fs::write(
        dir.path().join("athernex-endpoint-windows-x86_64.exe"),
        binary,
    )
    .unwrap();
    std::fs::write(&component, &package).unwrap();
    std::fs::write(&manifest, serde_json::to_vec(&artifact).unwrap()).unwrap();
    let bootstrap = p::Bootstrap {
        protocol: 1,
        server: "https://example.test/".into(),
        enrollment_token: "a".repeat(64),
        platform: Platform::Windows,
        antivirus: vec![],
    };
    let bytes =
        athernex_siem::fleet_web::installer_bundle(dir.path(), "windows-x86_64", &bootstrap)
            .unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    use std::io::Read;
    let mut original = Vec::new();
    zip.by_name("windows-filter.axpkg")
        .unwrap()
        .read_to_end(&mut original)
        .unwrap();
    assert_eq!(original, package);
    let mut marker = Vec::new();
    zip.by_name("windows-filter.required")
        .unwrap()
        .read_to_end(&mut marker)
        .unwrap();
    assert_eq!(marker, b"1\n");
    artifact.windows_filter.as_mut().unwrap().deployment =
        Some(p::windows_filter_package::Deployment::InstallAndObserveDisarmedV1);
    std::fs::write(&manifest, serde_json::to_vec(&artifact).unwrap()).unwrap();
    let delivered =
        athernex_siem::fleet_web::installer_bundle(dir.path(), "windows-x86_64", &bootstrap)
            .unwrap();
    let mut deployed = zip::ZipArchive::new(std::io::Cursor::new(delivered)).unwrap();
    let mut approval = Vec::new();
    deployed
        .by_name("release.json")
        .unwrap()
        .read_to_end(&mut approval)
        .unwrap();
    let approval: p::installer::Artifact = serde_json::from_slice(&approval).unwrap();
    assert_eq!(
        approval.filter().unwrap().unwrap().deployment,
        artifact.windows_filter.as_ref().unwrap().deployment
    );
    assert_eq!(
        approval.filter().unwrap().unwrap().sha256,
        artifact.windows_filter.as_ref().unwrap().sha256
    );
    let mut instructions = String::new();
    deployed
        .by_name("windows-filter.txt")
        .unwrap()
        .read_to_string(&mut instructions)
        .unwrap();
    assert!(instructions.contains("owned LocalSystem coordinator"));
    assert!(instructions.contains("does not attest exact loaded-image bytes"));
    package.push(0);
    std::fs::write(&component, &package).unwrap();
    assert!(
        athernex_siem::fleet_web::installer_bundle(dir.path(), "windows-x86_64", &bootstrap)
            .is_err()
    );
    artifact.signing = "development-unsigned".into();
    std::fs::write(&manifest, serde_json::to_vec(&artifact).unwrap()).unwrap();
    assert!(
        athernex_siem::fleet_web::installer_bundle(dir.path(), "windows-x86_64", &bootstrap)
            .is_err()
    );
}
