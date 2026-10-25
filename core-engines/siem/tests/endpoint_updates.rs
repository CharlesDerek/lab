use athernex_endpoint::{Client, Config, Store};
use athernex_endpoint_protocol::{
    self as p,
    update::{self as wire, DeploymentReceipt, SignedRelease},
    Enrollment, Platform,
};
use athernex_siem::{
    engine::Engine,
    model::now_ms,
    web::{router_with_release_catalog, App},
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::future::IntoFuture;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
static DOWNLOAD_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[test]
fn installation_requires_separate_approval_live_policy_and_exact_staging() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, config, release, _) = fixture(dir.path());
    assert!(engine
        .propose_endpoint_release(
            &config.endpoint_id,
            &release,
            &config.updates.public_key,
            true,
            now_ms()
        )
        .is_err());
    let mut health = athernex_endpoint::health(&config, 0);
    health.updates = athernex_endpoint::managed_update::health(&config, &dir.path().join("state"));
    health.updates.as_mut().unwrap().automatic = true;
    health.updates.as_mut().unwrap().supervised = true;
    engine
        .endpoint_heartbeat(&config.endpoint_id, &health, now_ms())
        .unwrap();
    let id = engine
        .propose_endpoint_release(
            &config.endpoint_id,
            &release,
            &config.updates.public_key,
            true,
            now_ms(),
        )
        .unwrap();
    assert!(engine
        .start_endpoint_installation(&config.endpoint_id, &id, now_ms())
        .is_err());
    engine.review_endpoint_update(&id, true, now_ms()).unwrap();
    assert!(engine
        .start_endpoint_installation(&config.endpoint_id, &id, now_ms())
        .is_err());
    let receipt = DeploymentReceipt {
        deployment_id: id.clone(),
        release_id: release.id().unwrap(),
        outcome: "staged".into(),
        detail: "Verified fixture staged".into(),
        finished_ms: now_ms(),
    };
    engine
        .endpoint_update_receipt(&config.endpoint_id, &receipt, now_ms())
        .unwrap();
    assert!(engine
        .start_endpoint_installation(&config.endpoint_id, &id, now_ms())
        .is_err());
    health.updates.as_mut().unwrap().staged_release = Some(release.id().unwrap());
    health.updates.as_mut().unwrap().highwater = 1;
    engine
        .endpoint_heartbeat(&config.endpoint_id, &health, now_ms())
        .unwrap();
    assert!(
        engine
            .start_endpoint_installation(&config.endpoint_id, &id, now_ms())
            .unwrap()
            .install
    );
    engine
        .start_endpoint_installation(&config.endpoint_id, &id, now_ms())
        .unwrap();
    assert!(engine.review_endpoint_update(&id, false, now_ms()).is_err());
    assert!(engine
        .propose_endpoint_release(
            &config.endpoint_id,
            &release,
            &config.updates.public_key,
            true,
            now_ms()
        )
        .is_err());
    let mut installed = wire::InstallationReceipt {
        deployment_id: id,
        release_id: release.id().unwrap(),
        outcome: "installed".into(),
        detail: "Runtime health confirmed".into(),
        finished_ms: now_ms(),
    };
    engine
        .endpoint_installation_receipt(&config.endpoint_id, &installed, now_ms())
        .unwrap();
    engine
        .endpoint_installation_receipt(&config.endpoint_id, &installed, now_ms())
        .unwrap();
    installed.outcome = "rolled_back".into();
    assert!(engine
        .endpoint_installation_receipt(&config.endpoint_id, &installed, now_ms())
        .is_err());
    drop(engine);
    let engine = Engine::open(&dir.path().join("ledger.db")).unwrap();
    let records = engine.endpoint_deployments(u64::MAX, now_ms()).unwrap();
    assert_eq!(records[0].state, "installed");
    assert_eq!(records[0].receipt, Some(receipt));
    assert_eq!(
        records[0].installation.as_ref().unwrap().outcome,
        "installed"
    );
}

fn fixture(root: &Path) -> (Engine, Config, SignedRelease, PathBuf) {
    let mut engine = Engine::open(&root.join("ledger.db")).unwrap();
    engine.configure_mode(false).unwrap();
    let (private, public) = wire::generate_key().unwrap();
    let config:Config=serde_json::from_value(serde_json::json!({
        "updates":{"managed":true,"public_key":public,"channel":"stable","install_path":root.join("installed"),"allow_unsigned_native":true},
        "server":"http://127.0.0.1:1/","endpoint_id":"a".repeat(64),"credential":"b".repeat(64),
        "scanner":root.join("no-scanner"),"updater":root.join("no-updater"),"scan_roots":[root],"allow_scripts":false
    })).unwrap();
    let token = engine
        .create_enrollment(Platform::current(), now_ms())
        .unwrap();
    engine
        .enroll_endpoint(
            &Enrollment {
                protocol: p::PROTOCOL,
                enrollment_token: token,
                endpoint_id: config.endpoint_id.clone(),
                credential: config.credential.clone(),
                hostname: "release<fixture>".into(),
                platform: Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    let mut health = athernex_endpoint::health(&config, 0);
    health.updates = athernex_endpoint::managed_update::health(&config, &root.join("state"));
    engine
        .endpoint_heartbeat(&config.endpoint_id, &health, now_ms())
        .unwrap();
    let mut bytes = vec![13; 2 * wire::CHUNK_BYTES as usize + 100];
    #[cfg(target_os = "linux")]
    {
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18..20].copy_from_slice(
            &(if cfg!(target_arch = "aarch64") {
                183u16
            } else {
                62u16
            })
            .to_le_bytes(),
        );
    }
    #[cfg(windows)]
    {
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..70].copy_from_slice(b"PE\0\0\x64\x86");
    }
    #[cfg(target_os = "macos")]
    {
        bytes[..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        bytes[4..8].copy_from_slice(
            &(if cfg!(target_arch = "aarch64") {
                0x100000cu32
            } else {
                0x1000007u32
            })
            .to_le_bytes(),
        );
    }
    let release = SignedRelease::sign(
        wire::Release {
            schema: 1,
            target: wire::target(),
            version: "fixture".into(),
            channel: "stable".into(),
            sequence: 1,
            issued_ms: now_ms(),
            expires_ms: now_ms() + 900_000,
            protocol: p::PROTOCOL,
            sha256: p::hash(&bytes),
            bytes: bytes.len() as u64,
        },
        &private,
    )
    .unwrap();
    let binary = root.join("release.bin");
    std::fs::write(&binary, bytes).unwrap();
    let manifest = root.join("release.json");
    std::fs::write(&manifest, serde_json::to_vec(&release).unwrap()).unwrap();
    let catalog = root.join("catalog");
    assert_eq!(
        athernex_endpoint::update::publish(
            &manifest,
            &binary,
            &config.updates.public_key,
            &catalog
        )
        .unwrap(),
        release.id().unwrap()
    );
    (engine, config, release, catalog)
}
fn app(engine: Engine) -> App {
    App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "update-fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("update-fixture-operator-key-long-enough")
                .unwrap(),
        ),
    }
}

#[test]
fn reviewed_delivery_is_scoped_replay_safe_and_retains_late_cancelled_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, config, release, _) = fixture(dir.path());
    assert!(engine
        .propose_endpoint_update(
            &config.endpoint_id,
            &release,
            &wire::generate_key().unwrap().1,
            now_ms()
        )
        .is_err());
    let id = engine
        .propose_endpoint_update(
            &config.endpoint_id,
            &release,
            &config.updates.public_key,
            now_ms(),
        )
        .unwrap();
    assert!(engine
        .propose_endpoint_update(
            &config.endpoint_id,
            &release,
            &config.updates.public_key,
            now_ms()
        )
        .is_err());
    assert!(engine
        .poll_endpoint_update(&config.endpoint_id, now_ms())
        .unwrap()
        .is_none());
    let mut receipt = DeploymentReceipt {
        deployment_id: id.clone(),
        release_id: release.id().unwrap(),
        outcome: "staged".into(),
        detail: "Public receipt".into(),
        finished_ms: now_ms(),
    };
    assert!(engine
        .endpoint_update_receipt(&config.endpoint_id, &receipt, now_ms())
        .is_err());
    engine.review_endpoint_update(&id, true, now_ms()).unwrap();
    receipt.finished_ms = now_ms();
    assert!(engine
        .authorized_endpoint_update(&"c".repeat(64), &id, now_ms())
        .is_err());
    engine.review_endpoint_update(&id, false, now_ms()).unwrap();
    assert!(engine
        .authorized_endpoint_update(&config.endpoint_id, &id, now_ms())
        .is_err());
    engine
        .endpoint_update_receipt(&config.endpoint_id, &receipt, now_ms())
        .unwrap();
    engine
        .endpoint_update_receipt(&config.endpoint_id, &receipt, now_ms())
        .unwrap();
    receipt.detail = "Altered replay".into();
    assert!(engine
        .endpoint_update_receipt(&config.endpoint_id, &receipt, now_ms())
        .is_err());
    drop(engine);
    let engine = Engine::open(&dir.path().join("ledger.db")).unwrap();
    let records = engine.endpoint_deployments(u64::MAX, now_ms()).unwrap();
    assert_eq!(records[0].state, "cancelled");
    assert_eq!(
        records[0].receipt.as_ref().unwrap().detail,
        "Public receipt"
    );
    assert!(engine
        .endpoint_deployments(records[0].row, now_ms())
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn update_portal_requires_operator_csrf_and_endpoint_download_authorization() {
    let _downloads = DOWNLOAD_TESTS.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let (engine, config, release, catalog) = fixture(dir.path());
    let app = app(engine);
    let id = app
        .engine
        .lock()
        .unwrap()
        .propose_endpoint_update(
            &config.endpoint_id,
            &release,
            &config.updates.public_key,
            now_ms(),
        )
        .unwrap();
    let router = router_with_release_catalog(app.clone(), catalog);
    for path in [
        "/api/endpoint-updates".into(),
        format!(
            "/api/endpoint/{}/updates/{id}/binary?offset=0",
            config.endpoint_id
        ),
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for csrf in ["wrong", "update-fixture-csrf"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/endpoints/updates/action")
                    .header(
                        "authorization",
                        "Bearer update-fixture-operator-key-long-enough",
                    )
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("csrf={csrf}&op=approve&id={id}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if csrf == "wrong" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::SEE_OTHER
            }
        );
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/endpoint/{}/updates/{id}/binary?offset=0",
                    config.endpoint_id
                ))
                .header("authorization", format!("Bearer {}", config.credential))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), wire::CHUNK_BYTES as usize)
            .await
            .unwrap()
            .len(),
        wire::CHUNK_BYTES as usize
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/endpoint-updates")
                .header(
                    "authorization",
                    "Bearer update-fixture-operator-key-long-enough",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("release&lt;fixture&gt;"));
    assert!(html.contains("Signed endpoint updates"));
    let mut held = Vec::new();
    for _ in 0..8 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/endpoint/{}/updates/{id}/binary?offset=0",
                        config.endpoint_id
                    ))
                    .header("authorization", format!("Bearer {}", config.credential))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response);
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/endpoint/{}/updates/{id}/binary?offset=0",
                    config.endpoint_id
                ))
                .header("authorization", format!("Bearer {}", config.credential))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(held.pop());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/endpoint/{}/updates/{id}/binary?offset=0",
                    config.endpoint_id
                ))
                .header("authorization", format!("Bearer {}", config.credential))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    drop(held);
    app.engine
        .lock()
        .unwrap()
        .endpoint_state(&config.endpoint_id, "revoked", now_ms())
        .unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/endpoint/{}/updates/{id}/binary?offset=0",
                    config.endpoint_id
                ))
                .header("authorization", format!("Bearer {}", config.credential))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

async fn cycle(config: Config, state: PathBuf) -> bool {
    tokio::task::spawn_blocking(move || {
        let client = Client::new(config).unwrap();
        let store = Store::open(&state).unwrap();
        client.cycle(&store).is_ok()
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_transport_stages_exact_bytes_and_recovers_a_lost_receipt() {
    delivery(false, false, wire::Component::Agent).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_catalog_bytes_exhaust_bounded_retries_without_advancing_sequence() {
    delivery(true, false, wire::Component::Agent).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staged_receipt_survives_cancellation_before_receipt_recovery() {
    delivery(false, true, wire::Component::Agent).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_transport_preserves_agent_history_and_recovers_lost_receipt() {
    delivery(false, false, wire::Component::Controller).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_transfer_rejects_altered_bytes_with_bounded_retries() {
    delivery(true, false, wire::Component::Controller).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_staging_receipt_survives_cancellation() {
    delivery(false, true, wire::Component::Controller).await;
}
async fn delivery(tamper: bool, cancel: bool, component: wire::Component) {
    let _downloads = DOWNLOAD_TESTS.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let (engine, mut config, release, catalog) = fixture(dir.path());
    if component == wire::Component::Controller {
        config.updates.controller_managed = true;
        config.updates.controller_path = Some(dir.path().join("controller"));
        config.updates.managed = false;
        let mut health = athernex_endpoint::health(&config, 0);
        health.controller_updates = athernex_endpoint::managed_update::component_health(
            &config,
            &dir.path().join("state"),
            component,
        );
        engine
            .endpoint_heartbeat(&config.endpoint_id, &health, now_ms())
            .unwrap();
    }
    let component_state = if component == wire::Component::Agent {
        "updates"
    } else {
        "updates/controller"
    };
    let app = app(engine);
    let id = app
        .engine
        .lock()
        .unwrap()
        .propose_component_release(
            &config.endpoint_id,
            &release,
            &config.updates.public_key,
            component,
            false,
            now_ms(),
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.server = format!("http://{}/", listener.local_addr().unwrap());
    let state = dir.path().join("state");
    athernex_endpoint::private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    if tamper {
        let path = catalog.join(format!("{}.bin", release.release.sha256));
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(path, bytes).unwrap();
    }
    let server = tokio::spawn(
        axum::serve(listener, router_with_release_catalog(app.clone(), catalog)).into_future(),
    );
    assert!(cycle(config.clone(), state.clone()).await);
    assert_eq!(
        athernex_endpoint::update::status_component(&state, component.into())
            .unwrap()
            .highwater,
        0
    );
    app.engine
        .lock()
        .unwrap()
        .review_endpoint_update(&id, true, now_ms())
        .unwrap();
    if tamper {
        assert!(!cycle(config.clone(), state.clone()).await);
        assert!(!cycle(config.clone(), state.clone()).await);
        assert!(cycle(config.clone(), state.clone()).await);
        assert_eq!(
            athernex_endpoint::update::status_component(&state, component.into())
                .unwrap()
                .highwater,
            0
        );
    } else {
        assert!(cycle(config.clone(), state.clone()).await);
        assert_eq!(
            athernex_endpoint::update::status_component(&state, component.into())
                .unwrap()
                .staged,
            Some(release.clone())
        );
        // Simulate a crash after staging but before receipt persistence.
        let path = state.join(component_state).join("delivery.json");
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["receipt"] = serde_json::Value::Null;
        std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        if cancel {
            app.engine
                .lock()
                .unwrap()
                .review_endpoint_update(&id, false, now_ms())
                .unwrap();
        }
        assert!(cycle(config.clone(), state.clone()).await);
        assert_eq!(
            p::hash(&std::fs::read(state.join(component_state).join("candidate.bin")).unwrap()),
            release.release.sha256
        );
    }
    assert!(cycle(config, state.clone()).await);
    let records = app
        .engine
        .lock()
        .unwrap()
        .endpoint_deployments(u64::MAX, now_ms())
        .unwrap();
    assert_eq!(
        records[0].state,
        if tamper {
            "failed"
        } else if cancel {
            "cancelled"
        } else {
            "staged"
        }
    );
    if !tamper {
        assert_eq!(
            records[0].receipt.as_ref().unwrap().finished_ms,
            athernex_endpoint::update::status_component(&state, component.into())
                .unwrap()
                .updated_ms
        );
    }
    assert_eq!(
        records[0].receipt.as_ref().unwrap().release_id,
        release.id().unwrap()
    );
    assert_eq!(records[0].deployment.component, component);
    if component == wire::Component::Controller {
        let agent = athernex_endpoint::update::status(&state).unwrap();
        assert_eq!(agent.highwater, 0);
        assert!(agent.staged.is_none() && agent.installed.is_none());
    }
    server.abort();
}

#[test]
fn controller_approval_uses_independent_policy_staging_and_launcher_health() {
    use wire::Component;
    let dir = tempfile::tempdir().unwrap();
    let (engine, config, release, _) = fixture(dir.path());
    let endpoint = &config.endpoint_id;
    let propose = |install| {
        engine.propose_component_release(
            endpoint,
            &release,
            &config.updates.public_key,
            Component::Controller,
            install,
            now_ms(),
        )
    };
    assert!(propose(false).is_err());
    let mut health = athernex_endpoint::health(&config, 0);
    let mut controller =
        athernex_endpoint::managed_update::health(&config, &dir.path().join("state")).unwrap();
    controller.managed = false;
    controller.automatic = true;
    controller.supervised = true;
    health.controller_updates = Some(controller.clone());
    let mut agent = controller.clone();
    agent.managed = true;
    agent.highwater = 100;
    agent.staged_release = Some(release.id().unwrap());
    health.updates = Some(agent);
    engine
        .endpoint_heartbeat(endpoint, &health, now_ms())
        .unwrap();
    assert!(propose(false).is_err());
    controller.managed = true;
    controller.supervised = false;
    health.controller_updates = Some(controller.clone());
    engine
        .endpoint_heartbeat(endpoint, &health, now_ms())
        .unwrap();
    assert!(propose(true).is_err());
    controller.supervised = true;
    controller.automatic = false;
    health.controller_updates = Some(controller.clone());
    engine
        .endpoint_heartbeat(endpoint, &health, now_ms())
        .unwrap();
    assert!(propose(true).is_err());
    controller.automatic = true;
    health.controller_updates = Some(controller.clone());
    engine
        .endpoint_heartbeat(endpoint, &health, now_ms())
        .unwrap();
    let id = propose(true).unwrap();
    // An agent approval cannot inherit the controller's lower sequence floor.
    assert!(engine
        .propose_endpoint_release(
            endpoint,
            &release,
            &config.updates.public_key,
            true,
            now_ms()
        )
        .is_err());
    health.controller_updates.as_mut().unwrap().managed = false;
    engine
        .endpoint_heartbeat(endpoint, &health, now_ms())
        .unwrap();
    assert!(engine.review_endpoint_update(&id, true, now_ms()).is_err());
    health.controller_updates = Some(controller.clone());
    engine
        .endpoint_heartbeat(endpoint, &health, now_ms())
        .unwrap();
    engine.review_endpoint_update(&id, true, now_ms()).unwrap();
    assert_eq!(
        engine
            .poll_endpoint_update(endpoint, now_ms())
            .unwrap()
            .unwrap()
            .component,
        Component::Controller
    );
    let staged = DeploymentReceipt {
        deployment_id: id.clone(),
        release_id: release.id().unwrap(),
        outcome: "staged".into(),
        detail: "Exact controller staged".into(),
        finished_ms: now_ms(),
    };
    engine
        .endpoint_update_receipt(endpoint, &staged, now_ms())
        .unwrap();
    // A staged agent report with the same release ID cannot authorize controller installation.
    assert!(engine
        .start_endpoint_installation(endpoint, &id, now_ms())
        .is_err());
    controller.staged_release = Some(release.id().unwrap());
    controller.highwater = 1;
    health.controller_updates = Some(controller.clone());
    engine
        .endpoint_heartbeat(endpoint, &health, now_ms())
        .unwrap();
    assert!(engine
        .start_endpoint_installation(endpoint, &id, now_ms() + 121_000)
        .is_err());
    let approved = engine
        .start_endpoint_installation(endpoint, &id, now_ms())
        .unwrap();
    assert_eq!(approved.component, Component::Controller);
    assert!(engine.review_endpoint_update(&id, false, now_ms()).is_err());
    let mut installed = wire::InstallationReceipt {
        deployment_id: id.clone(),
        release_id: release.id().unwrap(),
        outcome: "installed".into(),
        detail: "Controller runtime confirmed".into(),
        finished_ms: now_ms(),
    };
    engine
        .endpoint_installation_receipt(endpoint, &installed, now_ms())
        .unwrap();
    engine
        .endpoint_installation_receipt(endpoint, &installed, now_ms())
        .unwrap();
    installed.outcome = "rolled_back".into();
    assert!(engine
        .endpoint_installation_receipt(endpoint, &installed, now_ms())
        .is_err());
    drop(engine);
    let engine = Engine::open(&dir.path().join("ledger.db")).unwrap();
    let records = engine.endpoint_deployments(u64::MAX, now_ms()).unwrap();
    assert_eq!(records[0].deployment.component, Component::Controller);
    assert_eq!(records[0].state, "installed");
    assert_eq!(records[0].receipt, Some(staged));
    assert_eq!(
        records[0].installation.as_ref().unwrap().outcome,
        "installed"
    );
}
