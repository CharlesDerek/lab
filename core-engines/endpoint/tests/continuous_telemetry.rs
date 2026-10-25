//! Real agent process: a stalled control-plane request cannot stall collection.
use athernex_endpoint::{private_write, telemetry::TelemetryConfig, Config, Store};
use athernex_endpoint_protocol::{telemetry::Telemetry, EndpointEvent};
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "Requires real Linux process-connector access in the initial namespaces"]
fn native_events_continue_during_stalled_heartbeat_and_expose_agent_crash_gap() {
    use athernex_endpoint_protocol::process_events::ProcessEventHealth;
    use std::collections::{BTreeMap, BTreeSet};
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = serde_json::json!({"server":format!("http://{}/",listener.local_addr().unwrap()),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),
        "enrollment_token":null,"scanner":temp.path().join("no-scanner"),"updater":temp.path().join("no-updater"),"scan_roots":[temp.path()],"allow_scripts":false,
        "telemetry":{"enabled":true,"interval_secs":30,"linux_process_events":true}});
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let binary = std::env::var_os("ATHERNEX_NATIVE_EVENT_AGENT")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_athernex-endpoint").into());
    let start = || {
        Process(
            Command::new(&binary)
                .arg("run")
                .arg(&state)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    };
    let agent = start();
    let deadline = Instant::now() + Duration::from_secs(15);
    let connection = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(e) => panic!("Agent did not reach controlled heartbeat: {e}"),
        }
    };
    let mut pids = BTreeSet::new();
    for _ in 0..24 {
        let mut child = Command::new("/bin/true").spawn().unwrap();
        pids.insert(child.id());
        assert!(child.wait().unwrap().success());
    }
    let db = rusqlite::Connection::open_with_flags(
        state.join("endpoint.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(2)).unwrap();
    let records = || {
        db.prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap()
            .map(|r|serde_json::from_str::<EndpointEvent>(&r.unwrap()).unwrap()).filter(|e|matches!(&e.telemetry,Some(Telemetry::ProcessEvent {event,..}) if pids.contains(&event.pid))).collect::<Vec<_>>()
    };
    let native_health = || -> ProcessEventHealth {
        let raw: String = db
            .query_row(
                "SELECT value FROM telemetry_metadata WHERE key='process_events_health'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        serde_json::from_str(&raw).unwrap()
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let preserved = loop {
        let records = records();
        let mut kinds: BTreeMap<u32, BTreeSet<&str>> = BTreeMap::new();
        for e in &records {
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
                .is_some_and(|k| ["fork", "exec", "exit"].iter().all(|name| k.contains(name)))
        }) {
            break records;
        }
        assert!(
            Instant::now() < deadline,
            "Short-lived native events were not committed while heartbeat stalled"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let before = native_health();
    assert!(before.healthy(athernex_endpoint::now_ms()));
    drop(agent);
    drop(connection);
    let restarted = start();
    let deadline = Instant::now() + Duration::from_secs(15);
    let after = loop {
        let h = native_health();
        if h.stream_id != before.stream_id
            && h.subscriptions == 2
            && h.state == "degraded"
            && h.error.contains("loss")
        {
            break h;
        }
        assert!(
            Instant::now() < deadline,
            "Restart did not establish a new subscription"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(after.loss_signals > 0);
    assert!(!after.healthy(athernex_endpoint::now_ms()));
    let mut fresh = Command::new("/bin/true").spawn().unwrap();
    let fresh_pid = fresh.id();
    fresh.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let resumed=db.prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap()
            .filter_map(|r|serde_json::from_str::<EndpointEvent>(&r.unwrap()).ok())
            .any(|e|matches!(&e.telemetry,Some(Telemetry::ProcessEvent {stream_id,event,..}) if *stream_id==after.stream_id && event.pid==fresh_pid && matches!(event.change,athernex_endpoint_protocol::process_events::Change::Exit {..})));
        if resumed {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Restarted native stream did not capture a new controlled process"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let recovered = records();
    for e in preserved {
        assert!(recovered.iter().any(|r| r.id == e.id
            && serde_json::to_value(r).unwrap() == serde_json::to_value(&e).unwrap()));
    }
    drop(restarted);
    println!("Verified 24 short-lived processes through the actual agent during blocked HTTP; agent crash preserves original events and records a subscription gap after restart");
}

#[test]
#[ignore = "Child fixture invoked explicitly by collection_during_stalled_heartbeat"]
fn telemetry_fixture_process() {
    if std::env::var("ATHERNEX_TELEMETRY_TEST_CHILD").as_deref() == Ok("1") {
        thread::sleep(Duration::from_secs(30));
    }
}

#[test]
fn collection_during_stalled_heartbeat_preserves_new_process_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = Config {
        engine_updates: Default::default(),
        updates: Default::default(),
        protection: Default::default(),
        telemetry: TelemetryConfig {
            enabled: true,
            interval_secs: 1,
            ..Default::default()
        },
        server: format!("http://{}/", listener.local_addr().unwrap()),
        endpoint_id: "a".repeat(64),
        credential: "b".repeat(64),
        enrollment_token: None,
        scanner: temp.path().join("unavailable-scanner"),
        updater: temp.path().join("unavailable-updater"),
        scan_roots: vec![temp.path().to_path_buf()],
        allow_scripts: false,
        ca_file: None,
        signature_database: None,
        signature_config: None,
        maintenance: Default::default(),
    };
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let agent = Process(
        Command::new(env!("CARGO_BIN_EXE_athernex-endpoint"))
            .arg("run")
            .arg(&state)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let _stalled_request = loop {
        match listener.accept() {
            Ok((connection, _)) => break connection,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(25))
            }
            Err(e) => panic!("Agent did not connect to the controlled server: {e}"),
        }
    };
    // Start after the network request began. The server sends no response.
    let child = Process(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "telemetry_fixture_process", "--ignored"])
            .env("ATHERNEX_TELEMETRY_TEST_CHILD", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    let db = rusqlite::Connection::open(state.join("endpoint.sqlite3")).unwrap();
    db.busy_timeout(Duration::from_secs(2)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let captured = loop {
        let rows = db
            .prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let event = rows.into_iter().filter_map(|s| serde_json::from_str::<EndpointEvent>(&s).ok())
            .find(|e| matches!(&e.telemetry, Some(Telemetry::Process { process, .. }) if process.pid == pid));
        if let Some(event) = event {
            break event;
        }
        if Instant::now() >= deadline {
            let health: String = db
                .query_row(
                    "SELECT value FROM telemetry_metadata WHERE key='health'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or_default();
            let pending: u64 = db
                .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))
                .unwrap();
            let outbox: u64 = db
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
                .unwrap();
            panic!("New process was not collected while the heartbeat response was withheld; pending={pending}, outbox={outbox}, health={health}");
        }
        thread::sleep(Duration::from_millis(50));
    };
    drop(agent);
    drop(db);
    let store = Store::open(&state).unwrap();
    let persisted: String = store
        .connection
        .query_row(
            "SELECT payload FROM outbox WHERE id=?1 UNION ALL SELECT payload FROM telemetry_pending WHERE id=?1",
            [&captured.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<EndpointEvent>(&persisted)
            .unwrap()
            .time_ms,
        captured.time_ms
    );
    drop(child);
}
