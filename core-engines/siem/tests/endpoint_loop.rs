//! Actual TCP agent/server loop; uses a benign custom ClamAV signature when installed.
use athernex_endpoint::{Client, Config, Store};
use athernex_endpoint_protocol::{hash, Action, Enrollment, Platform, PROTOCOL};
use athernex_siem::{
    engine::Engine,
    model::now_ms,
    web::{router, App},
};
use std::sync::{Arc, Mutex};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_enrollment_inventory_receipts_and_offline_spool() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(&dir.path().join("server.db")).unwrap();
    engine.configure_mode(false).unwrap();
    let token = engine
        .create_enrollment(Platform::current(), now_ms())
        .unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("fixture-operator-key-long-enough-32").unwrap(),
        ),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, router(app.clone())).into_future());
    let config = Config {
        engine_updates: Default::default(),
        updates: Default::default(),
        protection: Default::default(),
        telemetry: Default::default(),
        server: format!("http://{address}/"),
        endpoint_id: "a".repeat(64),
        credential: "b".repeat(64),
        enrollment_token: Some(token),
        scanner: dir.path().join("scanner-unavailable"),
        updater: dir.path().join("updater-unavailable"),
        scan_roots: vec![dir.path().into()],
        allow_scripts: false,
        ca_file: None,
        signature_database: None,
        signature_config: None,
        maintenance: Default::default(),
    };
    let state = dir.path().join("agent");
    let copy = config.clone();
    let path = state.clone();
    tokio::task::spawn_blocking(move || {
        let client = Client::new(copy).unwrap();
        let store = Store::open(&path).unwrap();
        client.enroll().unwrap();
        client.cycle(&store).unwrap();
    })
    .await
    .unwrap();
    let id = {
        let e = app.engine.lock().unwrap();
        let case = e
            .create_case("Managed endpoint fixture", 3, now_ms())
            .unwrap();
        let id = e
            .queue_endpoint_action(&config.endpoint_id, Action::Inventory, case, now_ms())
            .unwrap();
        e.review_endpoint_action(&id, true, now_ms()).unwrap();
        id
    };
    let copy = config.clone();
    let path = state.clone();
    tokio::task::spawn_blocking(move || {
        let client = Client::new(copy).unwrap();
        let store = Store::open(&path).unwrap();
        client.cycle(&store).unwrap();
        client.cycle(&store).unwrap();
    })
    .await
    .unwrap();
    {
        let engine = app.engine.lock().unwrap();
        let fleet = engine.fleet().unwrap();
        assert_eq!(fleet.endpoints.len(), 1);
        let command = fleet.commands.iter().find(|c| c.command.id == id).unwrap();
        assert_eq!(command.state, "succeeded");
        assert!(command.receipt.as_ref().unwrap().output.contains("arch"));
    }
    let copy = config.clone();
    let path = state.clone();
    tokio::task::spawn_blocking(move || {
        let client = Client::new(copy).unwrap();
        let store = Store::open(&path).unwrap();
        // Each valid event is roughly 25 KiB after JSON escaping. A count-only
        // batch of 64 would exceed the server's 256 KiB request limit.
        for n in 0..64 {
            store
                .enqueue(&athernex_endpoint_protocol::EndpointEvent {
                    telemetry: None,
                    id: hash(format!("large-fixture-{n}").as_bytes()),
                    time_ms: now_ms(),
                    kind: "agent_error".into(),
                    path: String::new(),
                    sha256: String::new(),
                    detection: String::new(),
                    detail: "\u{0001}".repeat(4096),
                })
                .unwrap();
        }
        for _ in 0..3 {
            client.cycle(&store).unwrap();
        }
        let count: u64 = store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "Large valid records must drain without HTTP 413");
    })
    .await
    .unwrap();
    assert_eq!(
        app.engine
            .lock()
            .unwrap()
            .endpoint_observations(&config.endpoint_id, u64::MAX, 64)
            .unwrap()
            .len(),
        64
    );
    server.abort();
    tokio::task::spawn_blocking(move || {
        let client = Client::new(config).unwrap();
        let store = Store::open(&state).unwrap();
        store
            .enqueue(&athernex_endpoint_protocol::EndpointEvent {
                telemetry: None,
                id: "c".repeat(64),
                time_ms: now_ms(),
                kind: "agent_error".into(),
                path: String::new(),
                sha256: String::new(),
                detection: String::new(),
                detail: "offline fixture".into(),
            })
            .unwrap();
        assert!(client.cycle(&store).is_err());
        let count: u64 = store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    })
    .await
    .unwrap();
}

use std::future::IntoFuture;
#[cfg(unix)]
#[test]
fn real_clamav_fixture_creates_durable_malware_evidence() {
    use std::os::unix::fs::PermissionsExt;
    let scanner = std::path::Path::new("/usr/bin/clamscan");
    if !scanner.is_file() {
        eprintln!("ClamAV not installed; real-scanner fixture not exercised");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let samples = dir.path().join("samples");
    std::fs::create_dir(&samples).unwrap();
    let content = b"ATHERNEX PUBLIC BENIGN SCANNER FIXTURE 010203040506";
    let sample = samples.join("fixture.txt");
    std::fs::write(&sample, content).unwrap();
    let signature = format!(
        "AthernexFixture:0:*:{}\n",
        content
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let database = dir.path().join("fixture.ndb");
    std::fs::write(&database, signature).unwrap();
    let wrapper = dir.path().join("fixture-scanner");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec /usr/bin/clamscan --database='{}' \"$@\"\n",
            database.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = Store::open(&state).unwrap();
    let config = Config {
        engine_updates: Default::default(),
        updates: Default::default(),
        protection: Default::default(),
        telemetry: Default::default(),
        server: "http://127.0.0.1:8787/".into(),
        endpoint_id: "a".repeat(64),
        credential: "b".repeat(64),
        enrollment_token: None,
        scanner: wrapper,
        updater: dir.path().join("not-used"),
        scan_roots: vec![samples.clone()],
        allow_scripts: false,
        ca_file: None,
        signature_database: None,
        signature_config: None,
        maintenance: Default::default(),
    };
    let action = Action::Scan {
        path: samples.to_string_lossy().into(),
    };
    let command = athernex_endpoint_protocol::Command {
        id: "c".repeat(64),
        endpoint_id: config.endpoint_id.clone(),
        action_hash: hash(&serde_json::to_vec(&action).unwrap()),
        action,
        created_ms: now_ms(),
        expires_ms: now_ms() + 60_000,
        timeout_secs: 30,
        case_id: 1,
    };
    let output = athernex_endpoint::execute(&config, &store, &command).unwrap();
    assert!(output.contains("FOUND"));
    let raw: String = store
        .connection
        .query_row(
            "SELECT payload FROM outbox WHERE json_extract(payload,'$.kind')='malware'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let event: athernex_endpoint_protocol::EndpointEvent = serde_json::from_str(&raw).unwrap();
    assert_eq!(event.sha256, hash(content));
    assert!(sample.exists(), "Detection alone cannot quarantine a file");
    // Scanner text (including a crafted filename) must not create a hash-bound
    // detection for clean bytes. Reject the whole report before admitting any
    // additional observations, even when it also includes a real detection.
    let clean = samples.join("clean.txt");
    std::fs::write(&clean, b"ordinary public fixture").unwrap();
    std::fs::write(&config.scanner, format!(
        "#!/bin/sh\ncase \" $* \" in *--recursive=yes*) printf '%s: ForgedDetection FOUND\\n' '{}' ;; esac\nexec /usr/bin/clamscan --database='{}' \"$@\"\n",
        clean.display(), database.display())).unwrap();
    let count_before: u64 = store
        .connection
        .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
        .unwrap();
    let error = athernex_endpoint::execute(&config, &store, &command).unwrap_err();
    assert!(error.to_string().contains("did not verify"), "{error}");
    let count_after: u64 = store
        .connection
        .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count_before, count_after);
    assert_eq!(std::fs::read(clean).unwrap(), b"ordinary public fixture");
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(false).unwrap();
    let enrollment = Enrollment {
        protocol: PROTOCOL,
        enrollment_token: engine.create_enrollment(Platform::Linux, now_ms()).unwrap(),
        endpoint_id: config.endpoint_id.clone(),
        credential: config.credential,
        hostname: "scanner-fixture".into(),
        platform: Platform::Linux,
        arch: "x86_64".into(),
        version: "test".into(),
    };
    engine.enroll_endpoint(&enrollment, now_ms()).unwrap();
    engine
        .endpoint_events(&config.endpoint_id, &[event], now_ms())
        .unwrap();
    assert_eq!(engine.cases().unwrap().len(), 1);
}
