//! Explicit native test: requires CN_PROC access in the initial namespaces.
//! Only controlled child records are asserted/reported. Temporary stores are private.
use super::*;
use crate::{Client, Config};
use athernex_siem::{
    engine::Engine,
    web::{router, App},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::TcpListener,
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn queued(path: &std::path::Path, pids: &BTreeSet<u32>) -> Vec<EndpointEvent> {
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    db.busy_timeout(Duration::from_secs(2)).unwrap();
    let raw = db
        .prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    raw.into_iter().map(|s|serde_json::from_str::<EndpointEvent>(&s).unwrap())
        .filter(|e|matches!(&e.telemetry,Some(Telemetry::ProcessEvent{event,..}) if pids.contains(&event.pid))).collect()
}

#[test]
#[ignore = "Requires real Linux kernel process-connector access; run explicitly in the initial namespaces"]
fn short_lived_kernel_events_survive_stalled_transport_restart_and_exact_replay() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("endpoint");
    let db = state.join("endpoint.sqlite3");
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store)
        .expect("Kernel process connector must be available for this native gate");
    assert!(health(&store).unwrap().unwrap().healthy(now_ms()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config:Config=serde_json::from_value(serde_json::json!({
        "server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),
        "enrollment_token":null,"scanner":temp.path().join("absent-scanner"),"updater":temp.path().join("absent-updater"),
        "scan_roots":[temp.path()],"allow_scripts":false,"telemetry":{"enabled":true,"interval_secs":30,"linux_process_events":true}
    })).unwrap();
    let client = Client::new(config.clone()).unwrap();
    let controlled = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let request = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("Controlled heartbeat was not received: {e}"),
            }
        };
        let mut pids = BTreeSet::new();
        for _ in 0..24 {
            let mut child = Command::new("/bin/true").spawn().unwrap();
            pids.insert(child.id());
            assert!(child.wait().unwrap().success());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let selected = loop {
            let events = queued(&db, &pids);
            let mut kinds: BTreeMap<u32, BTreeSet<&str>> = BTreeMap::new();
            for e in &events {
                if let Some(Telemetry::ProcessEvent { event, .. }) = &e.telemetry {
                    kinds
                        .entry(event.pid)
                        .or_default()
                        .insert(event.change.name());
                }
            }
            if pids.iter().all(|pid| {
                kinds
                    .get(pid)
                    .is_some_and(|k| ["fork", "exec", "exit"].iter().all(|kind| k.contains(kind)))
            }) {
                break events;
            }
            assert!(
                Instant::now() < deadline,
                "Did not retain every controlled short-lived child's fork/exec/exit"
            );
            thread::sleep(Duration::from_millis(20));
        };
        drop(request); // No HTTP response: the endpoint must retain these observations.
        (listener, selected, pids)
    });
    assert!(client.cycle(&store).is_err());
    let (listener, selected, pids) = controlled.join().unwrap();
    assert!(health(&store).unwrap().unwrap().healthy(now_ms()));
    for pid in &pids {
        let mut ordered = selected
            .iter()
            .filter_map(|e| match &e.telemetry {
                Some(Telemetry::ProcessEvent { event, .. }) if event.pid == *pid => Some(event),
                _ => None,
            })
            .collect::<Vec<_>>();
        ordered.sort_by_key(|e| e.monotonic_ns);
        let fork = ordered
            .iter()
            .position(|e| matches!(e.change, protocol::process_events::Change::Fork { .. }))
            .unwrap();
        let exec = ordered
            .iter()
            .position(|e| matches!(e.change, protocol::process_events::Change::Exec))
            .unwrap();
        let exit = ordered
            .iter()
            .position(|e| matches!(e.change, protocol::process_events::Change::Exit { .. }))
            .unwrap();
        assert!(fork < exec && exec < exit);
        assert!(
            matches!(ordered[fork].change,protocol::process_events::Change::Fork { parent_pid,.. } if parent_pid==std::process::id())
        );
    }
    let prior_stream = health(&store).unwrap().unwrap().stream_id;
    drop(collector);
    drop(store);
    let store = Store::open(&state).unwrap();
    assert!(!health(&store).unwrap().unwrap().healthy(now_ms()));
    let retained = queued(&state.join("endpoint.sqlite3"), &pids);
    assert_eq!(
        serde_json::to_value(&selected).unwrap(),
        serde_json::to_value(&retained).unwrap()
    );
    let restarted = Collector::start(&store).unwrap();
    assert_ne!(health(&store).unwrap().unwrap().stream_id, prior_stream);
    assert_eq!(health(&store).unwrap().unwrap().subscriptions, 2);
    drop(restarted);

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
            "Kernel process events: coverage incomplete",
        ),
        (
            format!("/endpoints/{}", config.endpoint_id),
            "Kernel time (ns)",
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
                    found.insert(row.event.id.clone(), row.event);
                }
            }
        }
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
    println!("Verified {} short-lived children: native fork/exec/exit, stalled transport, collector/store restart, authenticated delivery, exact payload preservation and replay after server reopen",pids.len());
}
