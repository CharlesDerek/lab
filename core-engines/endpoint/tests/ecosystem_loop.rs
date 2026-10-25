#![cfg(target_os = "linux")]
//! Actual HTTP and endpoint filesystem mutation using a benign file and an
//! explicitly supplied malware observation. This does not measure AV efficacy.
use athernex_endpoint::{Client, Config, Store};
use athernex_endpoint_protocol::{self as p, EndpointEvent, Platform};
use athernex_siem::{
    ecosystem::IncidentRequest,
    engine::Engine,
    model::now_ms,
    web::{self, App},
};
use orchestrator::governor::{Class, Request, Resources};
use std::{
    future::IntoFuture,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn benign_incident_quarantines_real_file_and_recovers_placement_with_durable_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let watched = root.join("watched");
    std::fs::create_dir(&watched).unwrap();
    std::fs::set_permissions(&watched, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sample = watched.join("benign-fixture");
    std::fs::write(&sample, b"public benign fixture").unwrap();
    let scanner = root.join("scanner-fixture");
    std::fs::write(
        &scanner,
        b"#!/bin/sh\nprintf 'ClamAV controlled-version-fixture\\n'\n",
    )
    .unwrap();
    std::fs::set_permissions(&scanner, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut engine = Engine::open(&root.join("server.db")).unwrap();
    engine.configure_mode(false).unwrap();
    let token = engine.create_enrollment(Platform::Linux, now_ms()).unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("fixture-operator-key-long-enough").unwrap(),
        ),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, web::router(app.clone())).into_future());
    let config:Config=serde_json::from_value(serde_json::json!({"server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":token,"scanner":scanner,"updater":root.join("updater-unavailable"),"scan_roots":[watched],"allow_scripts":false})).unwrap();
    let state = root.join("agent");
    athernex_endpoint::private_write(
        &state.join("config.json"),
        &serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    let cycle = |enroll: bool| {
        let config = config.clone();
        let state = state.clone();
        tokio::task::spawn_blocking(move || {
            if enroll {
                let store = Store::open(&state).unwrap();
                let client = Client::new(config).unwrap();
                client.enroll().unwrap();
                client.cycle(&store).unwrap();
            } else {
                let (code, output) = athernex_endpoint::run_bounded(
                    athernex_endpoint::Process::new(env!("CARGO_BIN_EXE_athernex-endpoint"))
                        .arg("run")
                        .arg(&state)
                        .arg("--once"),
                    20,
                )
                .unwrap();
                assert_eq!(code, 0, "actual endpoint process: {output}");
            }
        })
    };
    cycle(true).await.unwrap();
    let budget = Resources {
        cpu_millis: 1000,
        memory_mib: 256,
        ..Default::default()
    };
    let proposal = {
        let e = app.engine.lock().unwrap();
        let now = now_ms();
        e.configure_pool("affected", budget, Resources::default(), now)
            .unwrap();
        e.configure_pool("replacement", budget, Resources::default(), now)
            .unwrap();
        e.bind_endpoint_pool(&config.endpoint_id, "affected", now)
            .unwrap();
        e.endpoint_events(
            &config.endpoint_id,
            &[EndpointEvent {
                telemetry: None,
                id: "c".repeat(64),
                time_ms: now,
                kind: "malware".into(),
                path: sample.to_string_lossy().into(),
                sha256: p::hash(b"public benign fixture"),
                detection: "Controlled.Positive.Fixture".into(),
                detail: "Injected public observation; no malicious file".into(),
            }],
            now,
        )
        .unwrap();
        let observation = e
            .endpoint_observations(&config.endpoint_id, u64::MAX, 1)
            .unwrap()
            .remove(0);
        let p = e
            .propose_incident(
                &IncidentRequest {
                    id: "end-to-end".into(),
                    endpoint: config.endpoint_id.clone(),
                    evidence_id: observation.evidence_id,
                    replacement_pool: "replacement".into(),
                    resources: budget,
                    expires_ms: now + 60000,
                },
                now,
            )
            .unwrap();
        e.approve_incident("end-to-end", &p.plan_hash, "operator", now)
            .unwrap();
        p
    };
    cycle(false).await.unwrap();
    cycle(false).await.unwrap();
    cycle(false).await.unwrap();
    {
        let e = app.engine.lock().unwrap();
        let incident = e.incident("end-to-end").unwrap();
        assert!(
            !sample.exists(),
            "real endpoint moved the approved directory entry: {:?}",
            incident.receipt
        );
        assert_eq!(incident.response_state, "succeeded");
        assert_eq!(incident.receipt.as_ref().unwrap().outcome, "succeeded");
        assert!(e
            .reserve_resources(
                &Request {
                    id: "held-work".into(),
                    pool: "affected".into(),
                    class: Class::Batch,
                    resources: budget,
                    expires_ms: now_ms() + 10000
                },
                now_ms()
            )
            .is_err());
        e.recover_incident(
            "end-to-end",
            &proposal.plan_hash,
            "operator",
            "Verified exact benign fixture quarantine and subsequent device health",
            now_ms(),
        )
        .unwrap();
        e.reserve_resources(
            &Request {
                id: "recovered-work".into(),
                pool: "affected".into(),
                class: Class::Batch,
                resources: budget,
                expires_ms: now_ms() + 10000,
            },
            now_ms(),
        )
        .unwrap();
        let receipts = e.case_endpoint_commands(proposal.plan.case_id).unwrap();
        assert_eq!(receipts.len(), 1);
    }
    server.abort();
}
