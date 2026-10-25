//! Requires the private SSH/journald fixture; never starts or alters host services.
use super::*;
use crate::{Client, Config};
use athernex_siem::{
    engine::Engine,
    web::{router, App},
};
use std::{
    collections::BTreeMap,
    net::TcpListener,
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
fn attempt(allowed: bool) {
    assert_eq!(
        std::env::var("ATHERNEX_AUTH_FIXTURE").as_deref(),
        Ok("private-container")
    );
    let result = Command::new("/usr/bin/ssh")
        .args([
            "-F",
            "/dev/null",
            "-p",
            "2222",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "-i",
            if allowed {
                "/fixture/client"
            } else {
                "/fixture/wrong"
            },
            "fixture@127.0.0.1",
            "true",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.success(), allowed);
}
pub(super) fn queued(path: &std::path::Path) -> Vec<EndpointEvent> {
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    db.busy_timeout(Duration::from_secs(2)).unwrap();
    let values = db
        .prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    values
        .into_iter()
        .map(|raw| serde_json::from_str::<EndpointEvent>(&raw).unwrap())
        .filter(|e| matches!(e.telemetry, Some(Telemetry::Authentication { .. })))
        .collect()
}
#[track_caller]
pub(super) fn until(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !check() {
        assert!(
            Instant::now() < deadline,
            "Native authentication condition timed out"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
#[test]
#[ignore = "Requires private native SSH/journald fixture, root and libsystemd >= 254"]
fn native_authentication_survives_stalled_delivery_restart_and_journal_retention_loss() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("endpoint");
    let db = state.join("endpoint.sqlite3");
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config:Config=serde_json::from_value(serde_json::json!({"server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":null,"scanner":temp.path().join("absent-scanner"),"updater":temp.path().join("absent-updater"),"scan_roots":[temp.path()],"allow_scripts":false,"telemetry":{"enabled":true,"interval_secs":30,"linux_authentication":true}})).unwrap();
    let client = Client::new(config.clone()).unwrap();
    let queue = db.clone();
    let controlled = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let request = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => panic!("Heartbeat failed: {error}"),
            }
        };
        for _ in 0..8 {
            attempt(false);
        }
        attempt(true);
        until(|| queued(&queue).len() == 9);
        drop(request);
        listener
    });
    assert!(client.cycle(&store).is_err());
    let listener = controlled.join().unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    println!(
        "Capture health: {}",
        serde_json::to_string(&health(&store).unwrap()).unwrap()
    );
    let preserved = queued(&db);
    assert_eq!(preserved.iter().filter(|e|matches!(&e.telemetry,Some(Telemetry::Authentication {event}) if event.outcome==protocol::authentication::AuthenticationOutcome::Allowed)).count(),1);
    drop(collector);
    drop(store);
    attempt(false); // Written by native journald while the endpoint is stopped.
    let store = Store::open(&state).unwrap();
    let restarted = Collector::start(&store).unwrap();
    until(|| queued(&db).len() == 10 && health(&store).unwrap().unwrap().healthy(now_ms()));
    for expected in &preserved {
        assert!(queued(&db)
            .iter()
            .any(|actual| serde_json::to_value(actual).unwrap()
                == serde_json::to_value(expected).unwrap()));
    }
    drop(restarted);
    drop(store);
    // Only the private fixture supplies this rotation helper. It rotates its own
    // journal, removes its closed archives and leaves the active journal intact.
    assert!(Command::new("/usr/bin/python3")
        .arg("/fixture/rotate-journal.py")
        .status()
        .unwrap()
        .success());
    attempt(false);
    let store = Store::open(&state).unwrap();
    let restarted = Collector::start(&store).unwrap();
    until(|| queued(&db).len() == 11 && health(&store).unwrap().unwrap().loss_signals > 0);
    assert!(!health(&store).unwrap().unwrap().healthy(now_ms()));
    drop(restarted);
    let selected = queued(&db);
    let server_db = temp.path().join("server.db");
    let engine = Engine::open(&server_db).unwrap();
    let token = engine
        .create_enrollment(protocol::Platform::current(), now_ms())
        .unwrap();
    engine
        .enroll_endpoint(
            &protocol::Enrollment {
                protocol: protocol::PROTOCOL,
                enrollment_token: token,
                endpoint_id: config.endpoint_id.clone(),
                credential: config.credential.clone(),
                hostname: "Controlled native process fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "public-native-process-fixture".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("public-native-event-operator-fixture-32")
                .unwrap(),
        ),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serve = app.clone();
    let server = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, router(serve))
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
    });
    struct Server(
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<thread::JoinHandle<()>>,
    );
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
            self.1.take().unwrap().join().unwrap();
        }
    }
    let server = Server(Some(stop), Some(server));
    for _ in 0..64 {
        super::super::drain_pending(&store).unwrap();
        client.cycle(&store).unwrap();
        let pending: u64 = store
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM outbox)+(SELECT count(*) FROM telemetry_pending)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if pending == 0 {
            break;
        }
    }
    assert_eq!(
        store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    {
        let engine = app.engine.lock().unwrap();
        for batch in selected.chunks(protocol::MAX_EVENTS) {
            assert_eq!(
                engine
                    .endpoint_events(&config.endpoint_id, batch, now_ms())
                    .unwrap(),
                0
            );
        }
        let mut changed = selected[0].clone();
        changed.detail.push_str(" changed");
        assert!(engine
            .endpoint_events(&config.endpoint_id, &[changed], now_ms())
            .is_err());
    }
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let export = format!(
        "http://{address}/api/endpoints/{}/events",
        config.endpoint_id
    );
    assert!(!http.get(&export).send().unwrap().status().is_success());
    for (path, expected) in [
        (
            "/endpoints".to_owned(),
            "Authentication journal: coverage incomplete / catching up",
        ),
        (
            format!("/endpoints/{}", config.endpoint_id),
            "Original report",
        ),
    ] {
        let page = http
            .get(format!("http://{address}{path}"))
            .bearer_auth("public-native-event-operator-fixture-32")
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        assert!(
            page.contains(expected),
            "Missing native evidence or coverage status in portal"
        );
    }
    {
        #[derive(serde::Deserialize)]
        struct Observation {
            evidence_id: u64,
            event: EndpointEvent,
        }
        let mut before = i64::MAX as u64;
        let mut found = BTreeMap::new();
        let mut inspected_original_link = false;
        loop {
            let page: Vec<Observation> = http
                .get(&export)
                .query(&[("before", before)])
                .bearer_auth("public-native-event-operator-fixture-32")
                .send()
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .unwrap();
            if page.is_empty() {
                break;
            }
            before = page.last().unwrap().evidence_id;
            for row in page {
                if selected.iter().any(|e| e.id == row.event.id) {
                    if !inspected_original_link {
                        let page = http
                            .get(format!("http://{address}/event/{}", row.evidence_id))
                            .bearer_auth("public-native-event-operator-fixture-32")
                            .send()
                            .unwrap()
                            .error_for_status()
                            .unwrap()
                            .text()
                            .unwrap();
                        assert!(page.contains("Open original device evidence"));
                        assert!(page.contains(&format!("href='/endpoints/{}'", config.endpoint_id)));
                        assert!(!page.contains("Retrieve original journal message"));
                        inspected_original_link = true;
                    }
                    found.insert(row.event.id.clone(), row.event);
                }
            }
        }
        assert!(inspected_original_link);
        for expected in &selected {
            assert_eq!(
                serde_json::to_value(found.get(&expected.id).unwrap()).unwrap(),
                serde_json::to_value(expected).unwrap()
            );
        }
    }
    drop(server);
    drop(app);
    let reopened = Engine::open(&server_db).unwrap();
    for batch in selected.chunks(protocol::MAX_EVENTS) {
        assert_eq!(
            reopened
                .endpoint_events(&config.endpoint_id, batch, now_ms())
                .unwrap(),
            0
        );
    }
    assert!(reopened
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|finding| finding.rule == "AX-001"));
    let probe_store = Store::open(&temp.path().join("writer-health")).unwrap();
    let probe_collector = Collector::start(&probe_store).unwrap();
    until(|| health(&probe_store).unwrap().unwrap().healthy(now_ms()));
    struct ResumeJournal;
    impl Drop for ResumeJournal {
        fn drop(&mut self) {
            let _ = Command::new("/usr/bin/python3")
                .args(["/fixture/journal-signal.py", "resume"])
                .status();
        }
    }
    let resume = ResumeJournal;
    assert!(Command::new("/usr/bin/python3")
        .args(["/fixture/journal-signal.py", "pause"])
        .status()
        .unwrap()
        .success());
    until(|| health(&probe_store).unwrap().unwrap().loss_signals > 0);
    assert!(!health(&probe_store).unwrap().unwrap().healthy(now_ms()));
    drop(resume);
    drop(probe_collector);
    println!("Verified native SSH allow/deny reports during stalled HTTP, exact journal replay after restart, visible retention gaps, stalled journal writer detection, authenticated exports, replay and the authentication-burst detection");
}
