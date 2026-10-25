//! Runs the portable Windows spool and real endpoint/server transport on Unix.
//! This does not simulate or validate Filter Manager or Windows service startup.
#![cfg(unix)]
use athernex_endpoint::{
    now_ms, private_write,
    protection::windows_evidence::{Queue, Root, Scope},
    Client, Config, Store,
};
use athernex_endpoint_native::windows_filter::wire;
use athernex_endpoint_protocol::{self as protocol, EndpointEvent};
use athernex_siem::{
    engine::Engine,
    web::{router, App},
};
use std::{
    future::IntoFuture,
    sync::{Arc, Mutex},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn windows_loss_notices_survive_offline_delivery_export_and_server_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("agent");
    let database = dir.path().join("server.db");
    let engine = Engine::open(&database).unwrap();
    let token = engine
        .create_enrollment(protocol::Platform::current(), now_ms())
        .unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "windows-coverage-fixture".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("windows-coverage-fixture-operator-32").unwrap(),
        ),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config:Config=serde_json::from_value(serde_json::json!({"server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":Some(token),
        "scanner":dir.path().join("absent-scanner"),"updater":dir.path().join("absent-updater"),"scan_roots":[dir.path()],"allow_scripts":false})).unwrap();
    app.engine
        .lock()
        .unwrap()
        .enroll_endpoint(
            &protocol::Enrollment {
                protocol: protocol::PROTOCOL,
                enrollment_token: config.enrollment_token.clone().unwrap(),
                endpoint_id: config.endpoint_id.clone(),
                credential: config.credential.clone(),
                hostname: "Portable Windows coverage fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    // Close the bound port while preparing and attempting offline delivery.
    drop(listener);
    let local = state.clone();
    let c = config.clone();
    let evidence = dir.path().join("evidence.db");
    let originals = tokio::task::spawn_blocking(move || {
        let store = Store::open(&local).unwrap();
        private_write(&local.join("config.json"), &serde_json::to_vec(&c).unwrap()).unwrap();
        let queue = Queue::open(&evidence).unwrap();
        let scope = Scope {
            roots: vec![Root {
                nt: "\\Device\\HarddiskVolume3\\Protected".into(),
                dos: "C:\\Protected".into(),
            }],
            timeout_ms: 1000,
        };
        queue.register(&scope).unwrap();
        let session = "d".repeat(64);
        queue
            .begin_session(&session, &scope.digest().unwrap())
            .unwrap();
        let mut status = wire::Status {
            version: wire::VERSION,
            armed: 1,
            connected: 1,
            instance: [1; 16],
            policy_sha256: scope.config().unwrap().policy_sha256,
            evidence_dropped: 6,
            ..Default::default()
        };
        queue.observe_kernel(&session, now_ms(), &status).unwrap();
        queue.lost(2).unwrap();
        status.instance = [2; 16];
        status.evidence_dropped = 1;
        queue.observe_kernel(&session, now_ms(), &status).unwrap();
        queue.collect(&store).unwrap();
        assert_eq!(queue.counts().unwrap().0, 0);
        let rows = store
            .connection
            .prepare("SELECT payload FROM outbox ORDER BY rowid")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows.len(), 4);
        assert!(Client::new(c).unwrap().cycle(&store).is_err());
        rows
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        axum::serve(listener, router(app.clone()))
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .into_future(),
    );
    let local = state.clone();
    let c = config.clone();
    tokio::task::spawn_blocking(move || {
        let store = Store::open(&local).unwrap();
        Client::new(c).unwrap().cycle(&store).unwrap();
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            0
        );
    })
    .await
    .unwrap();
    let http = reqwest::Client::new();
    let url = format!(
        "http://{address}/api/endpoints/{}/events",
        config.endpoint_id
    );
    assert!(!http.get(&url).send().await.unwrap().status().is_success());
    let rows: Vec<serde_json::Value> = http
        .get(&url)
        .bearer_auth("windows-coverage-fixture-operator-32")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rows.len(), 4);
    for raw in &originals {
        let event: EndpointEvent = serde_json::from_str(raw).unwrap();
        assert!(rows
            .iter()
            .any(|r| r["event"] == serde_json::to_value(&event).unwrap()));
        assert!(event.path.is_empty() && event.detection.is_empty());
    }
    let last: EndpointEvent = serde_json::from_str(originals.last().unwrap()).unwrap();
    let detail: serde_json::Value = serde_json::from_str(&last.detail).unwrap();
    let c = &detail["windows_evidence_coverage"];
    assert_eq!(c["kernel_dropped"], 7);
    assert_eq!(c["local_dropped"], 2);
    assert_eq!(c["gaps"], 1);
    drop(http);
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The server's connection tasks can release their state just after the
    // graceful-shutdown future completes. Wait for that ownership transfer
    // before testing a fresh process's exclusive ledger acquisition.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while Arc::strong_count(&app.engine) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server connection tasks retained the ledger after shutdown");
    drop(app);
    let engine = Engine::open(&database).unwrap();
    let events = originals
        .iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect::<Vec<EndpointEvent>>();
    assert_eq!(
        engine
            .endpoint_events(&config.endpoint_id, &events, now_ms())
            .unwrap(),
        0
    );
    let mut changed = events[1].clone();
    changed.detail.push_str(" changed");
    assert!(engine
        .endpoint_events(&config.endpoint_id, &[changed], now_ms())
        .is_err());
    assert!(
        engine.cases().unwrap().is_empty(),
        "Coverage gaps must not create fabricated malware cases"
    );
}
