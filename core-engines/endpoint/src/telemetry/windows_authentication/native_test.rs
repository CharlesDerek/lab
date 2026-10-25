//! Actual Security provider → durable collector → Client HTTP → SIEM evidence.
//! This component fixture is not proof of the full SCM-hosted agent lifecycle.
use super::*;
use crate::{Client, Config};
use athernex_siem::{
    engine::Engine,
    web::{router, App},
};
use std::{
    collections::BTreeMap,
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
mod host;

#[track_caller]
fn until(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !check() {
        assert!(
            Instant::now() < deadline,
            "Native Security fixture condition timed out"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
fn queued(path: &Path, account: &str) -> Vec<EndpointEvent> {
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    db.busy_timeout(Duration::from_secs(2)).unwrap();
    let values = db
        .prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    values.into_iter().map(|s|serde_json::from_str::<EndpointEvent>(&s).expect("Invalid private queued envelope")).filter(|e|matches!(&e.telemetry,Some(Telemetry::WindowsAuthentication {event}) if event.target_user.as_deref()==Some(account))).collect()
}
fn checkpoint(store: &Store) -> Checkpoint {
    metadata(store, "windows_authentication_checkpoint")
        .unwrap()
        .unwrap()
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
#[ignore = "Internal disposable-host collector crash worker"]
fn security_collector_crash_worker() {
    host::require_disposable();
    let state =
        std::env::var_os("ATHERNEX_AUTHENTICATION_CRASH_STATE").expect("Crash worker state absent");
    let path = Path::new(&state);
    let store = Store::open(path).expect("Crash worker store could not open");
    let _collector = Collector::start(&store).expect("Crash worker collector could not start");
    std::fs::write(path.join("crash-worker-ready"), b"ready").unwrap();
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}

fn fill_queues(store: &Store) {
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )
    .unwrap();
    for (table, budget, base) in [
        ("outbox", 3072, 100_000),
        ("telemetry_pending", 8192, 200_000),
    ] {
        let count: usize = store
            .connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        let missing = budget - count;
        if missing == 0 {
            continue;
        }
        let sql=format!("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO {table} SELECT printf('%064x',x+{base}),json_object('id',printf('%064x',x+{base}),'time_ms',?2,'kind','inventory','path','','sha256','','detection','','detail','controlled authentication backpressure fixture','telemetry',NULL) FROM n");
        store
            .connection
            .execute(&sql, rusqlite::params![missing, now_ms()])
            .unwrap();
    }
    tx.commit().unwrap();
}
fn remove_fillers(store: &Store) {
    for table in ["outbox", "telemetry_pending"] {
        store.connection.execute(&format!("DELETE FROM {table} WHERE json_extract(payload,'$.detail')='controlled authentication backpressure fixture'"),[]).unwrap();
    }
}

#[test]
#[ignore = "Requires an explicitly disposable native Windows LocalSystem/session-zero host; temporarily changes audit policy and creates one owned local account"]
fn security_logon_delivery_replays_and_reports_policy_gaps() {
    host::require_disposable();
    println!("\nATHERNEX_AUTH_STAGE=guard_verified");
    host::verify_privilege_scope();
    let mut policy = host::Policy::start();
    println!("\nATHERNEX_AUTH_STAGE=policy_ready");
    let mut account = host::Account::create();
    println!("\nATHERNEX_AUTH_STAGE=account_ready");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&policy, &account)));
    // Run and verify both cleanups even when a fixture assertion failed. Real
    // source values never enter assertion diagnostics or uploaded artifacts.
    let removed = account.remove();
    let restored = policy.restore();
    assert!(
        removed,
        "Owned authentication fixture account deletion was not verified"
    );
    assert!(
        restored,
        "Original authentication audit policy restoration was not verified"
    );
    println!("\nATHERNEX_AUTH_STAGE=cleanup_verified");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    println!("Windows authentication fixture passed: original XML, bounded backpressure, crash replay, HTTP evidence, deduplication and sticky policy gap; account deleted and exact audit policy restored");
}
fn run(policy: &host::Policy, account: &host::Account) {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("endpoint");
    let db = state.join("endpoint.sqlite3");
    let store = Store::open(&state).unwrap();
    println!("\nATHERNEX_AUTH_STAGE=source_starting");
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    println!("\nATHERNEX_AUTH_STAGE=source_ready");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let config:Config=serde_json::from_value(serde_json::json!({"server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":null,"scanner":temp.path().join("absent-scanner"),"updater":temp.path().join("absent-updater"),"scan_roots":[temp.path()],"allow_scripts":false,"telemetry":{"enabled":true,"interval_secs":30,"windows_authentication":true}})).unwrap();
    let client = Client::new(config.clone()).unwrap();
    let listener = thread::scope(|scope| {
        let queue = &db;
        let controlled = scope.spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let request = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => panic!("Controlled heartbeat did not arrive"),
                }
            };
            account.attempt(true);
            for _ in 0..8 {
                account.attempt(false);
            }
            until(|| queued(queue, &account.name).len() == 9);
            drop(request);
            listener
        });
        assert!(
            client.cycle(&store).is_err(),
            "Controlled stalled heartbeat unexpectedly succeeded"
        );
        controlled.join().unwrap()
    });
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    let preserved = queued(&db, &account.name);
    assert!(preserved.iter().filter(|e|matches!(&e.telemetry,Some(Telemetry::WindowsAuthentication {event}) if event.event_code==4624)).count()==1,"Native successful logon count differs");
    for event in &preserved {
        let Some(Telemetry::WindowsAuthentication { event }) = &event.telemetry else {
            unreachable!()
        };
        assert!(
            native::Reader::original(event.record_id).unwrap() == event.xml,
            "Queued original differs from native Security render"
        );
    }
    println!("\nATHERNEX_AUTH_STAGE=stalled_http_verified");
    // Freeze the collector while filling queues to establish an exact admission
    // boundary, then verify a real source report cannot advance that bookmark.
    drop(collector);
    fill_queues(&store);
    account.attempt(false);
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().backpressure);
    let before = checkpoint(&store);
    let received = metadata::<AuthenticationHealth>(&store, "windows_authentication_health")
        .unwrap()
        .unwrap()
        .received_records;
    thread::sleep(Duration::from_millis(500));
    assert!(
        health(&store).unwrap().unwrap().backpressure,
        "Backpressure unexpectedly cleared with full queues"
    );
    assert!(
        serde_json::to_vec(&before).unwrap() == serde_json::to_vec(&checkpoint(&store)).unwrap(),
        "Backpressure advanced the durable bookmark"
    );
    assert!(
        metadata::<AuthenticationHealth>(&store, "windows_authentication_health")
            .unwrap()
            .unwrap()
            .received_records
            == received,
        "Backpressure advanced received counters"
    );
    println!("\nATHERNEX_AUTH_STAGE=backpressure_verified");
    drop(collector);
    remove_fillers(&store);
    drop(store);

    // A separate process persists the blocked original, then is terminated
    // without a collector Drop. The parent reopens the database afterward.
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "telemetry::windows_authentication::native_test::security_collector_crash_worker",
            "--ignored",
            "--test-threads=1",
        ])
        .env("ATHERNEX_AUTHENTICATION_CRASH_STATE", &state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Collector crash worker could not start");
    let mut child = Child(child);
    until(|| state.join("crash-worker-ready").exists() && queued(&db, &account.name).len() == 10);
    child
        .0
        .kill()
        .expect("Collector crash worker termination failed");
    assert!(
        !child.0.wait().unwrap().success(),
        "Collector crash worker was not forcefully terminated"
    );
    account.attempt(false);
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| {
        queued(&db, &account.name).len() == 11 && health(&store).unwrap().unwrap().healthy(now_ms())
    });
    for expected in &preserved {
        assert!(
            queued(&db, &account.name)
                .iter()
                .any(|actual| serde_json::to_value(actual).unwrap()
                    == serde_json::to_value(expected).unwrap()),
            "Crash replay altered a queued original"
        );
    }
    println!("\nATHERNEX_AUTH_STAGE=crash_replay_verified");
    policy.set_logon(1);
    until(|| health(&store).unwrap().unwrap().loss_signals > 0);
    assert!(
        !health(&store).unwrap().unwrap().healthy(now_ms()),
        "Disabled failure audit policy reported healthy"
    );
    policy.set_logon(3);
    account.attempt(false);
    until(|| queued(&db, &account.name).len() == 12);
    assert!(
        !health(&store).unwrap().unwrap().healthy(now_ms()),
        "A later healthy source erased the observed policy gap"
    );
    println!("\nATHERNEX_AUTH_STAGE=policy_gap_verified");
    drop(collector);
    let selected = queued(&db, &account.name);
    let mut reader = native::Reader::open().unwrap();
    let (mut changed, _) = reader.baseline().unwrap();
    changed.anchor_sha256 = "0".repeat(64);
    assert!(
        reader.batch(&changed).unwrap().loss_signals > 0,
        "Strict bookmark anchor mismatch was not visible"
    );
    println!("\nATHERNEX_AUTH_STAGE=anchor_mismatch_verified");
    deliver(temp.path(), &store, listener, &config, &client, &selected);
    println!(
        "Native Security originals verified: count={}, aggregate_sha256={}",
        selected.len(),
        protocol::hash(
            selected
                .iter()
                .flat_map(|e| e.id.bytes())
                .collect::<Vec<_>>()
                .as_slice()
        )
    );
}

fn deliver(
    temp: &Path,
    store: &Store,
    listener: TcpListener,
    config: &Config,
    client: &Client,
    selected: &[EndpointEvent],
) {
    let address = listener.local_addr().unwrap();
    let server_db = temp.join("server.db");
    let mut engine = Engine::open(&server_db).unwrap();
    engine.configure_mode(false).unwrap();
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
                hostname: "Controlled native Windows authentication fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "public-native-authentication-fixture".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("public-native-event-operator-fixture-32")
                .unwrap(),
        ),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serve = app.clone();
    let thread = thread::spawn(move || {
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
            })
    });
    struct Server(
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<thread::JoinHandle<()>>,
    );
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
            let _ = self.1.take().unwrap().join();
        }
    }
    let server = Server(Some(stop), Some(thread));
    for _ in 0..128 {
        super::super::drain_pending(store).unwrap();
        client.cycle(store).unwrap();
        let count: u64 = store
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM outbox)+(SELECT count(*) FROM telemetry_pending)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if count == 0 {
            break;
        }
    }
    assert!(
        store
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM outbox)+(SELECT count(*) FROM telemetry_pending)",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap()
            == 0,
        "Native evidence did not finish HTTP delivery"
    );
    println!("\nATHERNEX_AUTH_STAGE=http_delivery_verified");
    {
        let engine = app.engine.lock().unwrap();
        for batch in selected.chunks(protocol::MAX_EVENTS) {
            assert!(
                engine
                    .endpoint_events(&config.endpoint_id, batch, now_ms())
                    .unwrap()
                    == 0,
                "Identical native evidence replay was not deduplicated"
            );
        }
        let mut changed = selected[0].clone();
        changed.detail.push_str(" changed");
        assert!(
            engine
                .endpoint_events(&config.endpoint_id, &[changed], now_ms())
                .is_err(),
            "Conflicting replay was accepted"
        );
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
    assert!(
        !http.get(&export).send().unwrap().status().is_success(),
        "Original evidence export did not require authentication"
    );
    #[derive(serde::Deserialize)]
    struct Observation {
        evidence_id: u64,
        event: EndpointEvent,
    }
    let mut found = BTreeMap::new();
    let mut before = i64::MAX as u64;
    let mut inspected = false;
    for _ in 0..128 {
        let rows: Vec<Observation> = http
            .get(&export)
            .query(&[("before", before)])
            .bearer_auth("public-native-event-operator-fixture-32")
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .unwrap();
        if rows.is_empty() {
            break;
        }
        before = rows.last().unwrap().evidence_id;
        for row in rows {
            if selected.iter().any(|e| e.id == row.event.id) {
                if !inspected {
                    let page = http
                        .get(format!("http://{address}/event/{}", row.evidence_id))
                        .bearer_auth("public-native-event-operator-fixture-32")
                        .send()
                        .unwrap()
                        .error_for_status()
                        .unwrap()
                        .text()
                        .unwrap();
                    assert!(
                        page.contains("Open original device evidence"),
                        "Native SIEM event lacks its original evidence link"
                    );
                    inspected = true;
                }
                found.insert(row.event.id.clone(), (row.evidence_id, row.event));
            }
        }
    }
    assert!(inspected, "No native evidence was exported");
    for expected in selected {
        assert!(
            found
                .get(&expected.id)
                .is_some_and(|(_, actual)| serde_json::to_value(actual).unwrap()
                    == serde_json::to_value(expected).unwrap()),
            "Authenticated export altered a native original"
        );
    }
    let page = http
        .get(format!("http://{address}/endpoints/{}", config.endpoint_id))
        .bearer_auth("public-native-event-operator-fixture-32")
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        page.contains("Windows Security logons: coverage incomplete / catching up"),
        "Portal hides Windows authentication coverage gap"
    );
    println!("\nATHERNEX_AUTH_STAGE=original_export_verified");
    drop(server);
    drop(app);
    let engine = Engine::open(&server_db).unwrap();
    for batch in selected.chunks(protocol::MAX_EVENTS) {
        assert!(
            engine
                .endpoint_events(&config.endpoint_id, batch, now_ms())
                .unwrap()
                == 0,
            "Server restart lost deduplication state"
        );
    }
    assert!(
        engine
            .snapshot()
            .unwrap()
            .findings
            .iter()
            .any(|f| f.rule == "AX-001"
                && f.evidence
                    .iter()
                    .filter(|evidence| {
                        found.values().any(|(id, original)| {
                            *id == evidence.event.id
                                && matches!(&original.telemetry,
                        Some(Telemetry::WindowsAuthentication {event}) if event.event_code == 4625
                            && evidence.context.as_ref().is_some_and(|context|
                                context.host == config.endpoint_id
                                && context.pid == event.caller_pid
                                && context.uid.is_none()
                                && context.process_start_ms.is_none()
                                && context.journal_cursor.is_empty()))
                        })
                    })
                    .count()
                    >= 8),
        "Controlled native denied originals did not supply the authentication finding evidence"
    );
    println!("\nATHERNEX_AUTH_STAGE=detection_verified");
}
