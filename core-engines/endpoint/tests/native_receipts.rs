//! Actual agent/server transport for a controlled native receipt fixture.
//! This tests evidence/SOAR integration, not execution of Apple's authorization API.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use athernex_endpoint::{private_write, Client, Config, Store};
use athernex_endpoint_native::{
    coverage::{Loss, Snapshot},
    receipt::{policy_hash, Actor, Receipt},
    scanner, Policy, Verdict,
};
use athernex_endpoint_protocol::{hash, Platform};
use athernex_siem::{
    engine::Engine,
    model::now_ms,
    web::{router, App},
};
use std::{
    fs,
    future::IntoFuture,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    sync::{Arc, Mutex},
};

fn app(engine: Engine) -> App {
    App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "native-fixture".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("native-fixture-operator-key-32-characters")
                .unwrap(),
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_receipt_recovers_offline_then_preserves_hash_in_automation_and_export() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let database = root.join("server.db");
    let mut engine = Engine::open(&database).unwrap();
    engine.configure_mode(false).unwrap();
    let token = engine
        .create_enrollment(Platform::current(), now_ms())
        .unwrap();
    let first = app(engine);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, router(first.clone())).into_future());
    let state = root.join("state");
    let watched = root.join("watched");
    fs::create_dir(&watched).unwrap();
    let path = watched.join("public-fixture.txt");
    let content = b"Public native receipt fixture";
    fs::write(&path, content).unwrap();
    let config = Config {
        engine_updates: Default::default(),
        updates: Default::default(),
        protection: Default::default(),
        telemetry: Default::default(),
        server: format!("http://{address}/"),
        endpoint_id: "a".repeat(64),
        credential: "b".repeat(64),
        enrollment_token: Some(token),
        scanner: root.join("scanner-unavailable"),
        updater: root.join("updater-unavailable"),
        scan_roots: vec![watched.clone()],
        allow_scripts: false,
        ca_file: None,
        signature_database: None,
        signature_config: None,
        maintenance: Default::default(),
    };
    let c = config.clone();
    let s = state.clone();
    tokio::task::spawn_blocking(move || {
        let client = Client::new(c.clone()).unwrap();
        let _store = Store::open(&s).unwrap();
        client.enroll().unwrap();
        private_write(&s.join("config.json"), &serde_json::to_vec(&c).unwrap()).unwrap();
    })
    .await
    .unwrap();
    first
        .engine
        .lock()
        .unwrap()
        .configure_malware_playbook(&config.endpoint_id, "automatic", now_ms())
        .unwrap();
    server.abort();
    let _ = server.await;
    drop(first);

    let native = state.join("protection/native");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(native.join("verdicts"))
        .unwrap();
    let policy = Policy {
        roots: vec![watched],
        socket: root.join("scanner.sock"),
        state: native.clone(),
        scanner_uid: 1234,
        scan_timeout_ms: 1000,
    };
    let receipt = Receipt {
        schema: 1,
        id: "c".repeat(64),
        policy_sha256: policy_hash(&policy).unwrap(),
        time_ms: now_ms(),
        operation: "open".into(),
        response_delivered: true,
        actor: Actor {
            pid: 120,
            uid: 1000,
            pidversion: 5,
        },
        path: path.display().to_string(),
        identity: scanner::identity(&fs::metadata(&path).unwrap()),
        verdict: Some(Verdict {
            sha256: hash(content),
            detection: Some("Public.NativeFixture".into()),
            bytes: content.len() as u64,
        }),
        error: String::new(),
    };
    private_write(
        &native
            .join("policies")
            .join(format!("{}.json", receipt.policy_sha256)),
        &serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let source = native.join("verdicts").join(format!("{}.json", receipt.id));
    private_write(&source, &serde_json::to_vec(&receipt).unwrap()).unwrap();
    let coverage = Snapshot::begin(None, &policy, 42, 7, false, now_ms())
        .unwrap()
        .observe(
            Loss {
                evidence_dropped: 5,
                event_gaps: 3,
                response_errors: 2,
            },
            true,
            true,
            now_ms(),
        )
        .unwrap();
    let coverage = Snapshot::begin(Some(&coverage), &policy, 43, 8, false, now_ms())
        .unwrap()
        .observe(
            Loss {
                evidence_dropped: 2,
                ..Default::default()
            },
            true,
            true,
            now_ms(),
        )
        .unwrap();
    coverage.save(&native).unwrap();
    let s = state.clone();
    let coverage_original = tokio::task::spawn_blocking(move || {
        assert_ne!(run_agent(&s), 0);
        let store = Store::open(&s).unwrap();
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            2
        );
        store
            .connection
            .query_row(
                "SELECT payload FROM outbox WHERE json_extract(payload,'$.kind')='agent_error'",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!source.exists());
    assert!(path.exists());

    let mut engine = Engine::open(&database).unwrap();
    engine.configure_mode(false).unwrap();
    let second = app(engine);
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let server = tokio::spawn(axum::serve(listener, router(second.clone())).into_future());
    let s = state.clone();
    tokio::task::spawn_blocking(move || {
        assert_eq!(run_agent(&s), 0);
        assert_eq!(run_agent(&s), 0);
        let store = Store::open(&s).unwrap();
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
    assert!(
        !path.exists(),
        "The reviewed automatic playbook must quarantine the exact approved bytes"
    );
    let (case_id, command_id) = {
        let e = second.engine.lock().unwrap();
        let fleet = e.fleet().unwrap();
        assert_eq!(fleet.commands.len(), 1);
        assert_eq!(fleet.commands[0].state, "succeeded");
        let cases = e.cases().unwrap();
        assert_eq!(cases.len(), 1);
        assert!(!fleet.endpoints[0].health.realtime);
        let observations = e
            .endpoint_observations(&config.endpoint_id, u64::MAX, 64)
            .unwrap();
        let coverage_events = observations
            .iter()
            .filter(|o| o.event.detail.contains("native_authorization_coverage"))
            .collect::<Vec<_>>();
        assert_eq!(coverage_events.len(), 1);
        assert!(coverage_events[0].case_id.is_none());
        assert_eq!(
            serde_json::to_string(&coverage_events[0].event).unwrap(),
            coverage_original
        );
        let detail: serde_json::Value =
            serde_json::from_str(&coverage_events[0].event.detail).unwrap();
        assert_eq!(
            detail["native_authorization_coverage"],
            serde_json::to_value(&coverage.evidence).unwrap()
        );
        assert_eq!(
            detail["native_authorization_coverage"]["totals"]["evidence_dropped"],
            7
        );
        assert_eq!(
            detail["native_authorization_coverage"]["unobserved_intervals"],
            1
        );
        (cases[0].id, fleet.commands[0].command.id.clone())
    };
    assert_eq!(
        fs::read(state.join("quarantine").join(&command_id)).unwrap(),
        content
    );
    let export_url = format!("http://{address}/api/cases/{case_id}/export");
    let export = tokio::task::spawn_blocking(move || fetch_export(&export_url))
        .await
        .unwrap();
    let observations = export["endpoint_observations"].as_array().unwrap();
    let original = observations
        .iter()
        .find(|r| r["event"]["kind"] == "malware")
        .unwrap();
    assert_eq!(original["event"]["sha256"], hash(content));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(original["event"]["detail"].as_str().unwrap())
            .unwrap(),
        serde_json::to_value(&receipt).unwrap()
    );
    assert!(export.to_string().contains(&command_id));
    let observation_url = format!(
        "http://{address}/api/endpoints/{}/events",
        config.endpoint_id
    );
    let exported = tokio::task::spawn_blocking(move || fetch_export(&observation_url))
        .await
        .unwrap();
    let original: serde_json::Value = serde_json::from_str(&coverage_original).unwrap();
    assert_eq!(
        exported
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["event"] == original)
            .count(),
        1
    );
    server.abort();
    let _ = server.await;
}

fn fetch_export(url: &str) -> serde_json::Value {
    // Use the standard library HTTP path to keep this fixture's dependencies small.
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };
    let (authority, path) = url
        .strip_prefix("http://")
        .unwrap()
        .split_once('/')
        .unwrap();
    let mut stream = TcpStream::connect(authority).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    write!(stream,"GET /{path} HTTP/1.0\r\nHost: {authority}\r\nAuthorization: Bearer native-fixture-operator-key-32-characters\r\nConnection: close\r\n\r\n").unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    assert!(std::str::from_utf8(&bytes[..split])
        .unwrap()
        .contains("200 OK"));
    serde_json::from_slice(&bytes[split + 4..]).unwrap()
}

fn run_agent(state: &std::path::Path) -> i32 {
    let (code, output) = athernex_endpoint_native::child::run(
        std::process::Command::new(env!("CARGO_BIN_EXE_athernex-endpoint"))
            .arg("run")
            .arg(state)
            .arg("--once"),
        std::time::Duration::from_secs(20),
        65536,
    )
    .unwrap();
    if code != 0 {
        eprintln!("{}", String::from_utf8_lossy(&output));
    }
    code
}
