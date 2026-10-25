//! Private network namespace only; the runner proves isolation before enabling rules.
use super::*;
use crate::{now_ms, Client, Config};
use protocol::network_events::{Change, Protocol};
use std::{
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[path = "soak_test.rs"]
mod soak_test;

fn fixture() {
    assert_eq!(
        std::env::var("ATHERNEX_NETWORK_FIXTURE").as_deref(),
        Ok("private-container")
    );
    assert!(std::fs::read_to_string("/proc/1/comm")
        .unwrap()
        .contains("docker-init"));
    assert_eq!(std::fs::read_dir("/sys/class/net").unwrap().count(), 1);
    assert!(std::path::Path::new("/sys/class/net/lo").exists());
}
fn rules(add: bool) {
    fixture();
    for command in ["iptables", "ip6tables"] {
        assert!(Command::new(command)
            .args([
                if add { "-A" } else { "-D" },
                "OUTPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW,ESTABLISHED,RELATED",
                "-j",
                "ACCEPT"
            ])
            .status()
            .unwrap()
            .success());
    }
}
fn wait(mut predicate: impl FnMut() -> bool, description: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !predicate() {
        assert!(Instant::now() < deadline, "{description}");
        thread::sleep(Duration::from_millis(20));
    }
}
#[test]
#[ignore = "Requires the private network fixture; changes only its tracking rules"]
fn missing_or_removed_tracking_hooks_cannot_report_healthy_coverage() {
    fixture();
    assert!(hooks::source().unwrap().is_empty());
    assert!(linux::Reader::open().is_err());
    rules(true);
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let collector = Collector::start(&store).unwrap();
    assert!(health(&store).unwrap().unwrap().healthy(now_ms()));
    assert_eq!(health(&store).unwrap().unwrap().families, vec![4, 6]);
    rules(false);
    wait(
        || collector.check().is_err(),
        "Collector did not detect removal of tracking hooks",
    );
    let raw: NetworkEventHealth = metadata(&store, "network_events_health").unwrap().unwrap();
    assert!(raw.loss_signals > 0);
    assert!(!health(&store).unwrap().unwrap().healthy(now_ms()));
    println!("Verified subscription without tracking is refused; removing private tracking hooks stops the collector and records a coverage gap");
}
#[test]
#[ignore = "Requires the private network fixture and native netfilter delivery"]
fn real_socket_overflow_is_reported_as_a_coverage_gap() {
    fixture();
    rules(true);
    let mut reader = linux::Reader::with_capacity(1024).unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..512 {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"fixture", receiver.local_addr().unwrap())
            .unwrap();
    }
    wait(
        || {
            reader.batch().unwrap();
            reader.loss_signals > 0
        },
        "Kernel did not report socket overflow",
    );
    assert!(reader.loss_signals > 0);
    println!("Verified real ENOBUFS with a small private netlink receive buffer; loss is recorded rather than suppressed");
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn rows(db: &rusqlite::Connection) -> Vec<EndpointEvent> {
    db.prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| serde_json::from_str(&r.unwrap()).unwrap())
        .collect()
}
fn native_health(db: &rusqlite::Connection) -> NetworkEventHealth {
    let raw: String = db
        .query_row(
            "SELECT value FROM telemetry_metadata WHERE key='network_events_health'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}
fn flow(protocol: Protocol, v6: bool) -> (Protocol, SocketAddr, SocketAddr) {
    let bind = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
    let (source, destination) = if protocol == Protocol::Tcp {
        use std::io::{Read, Write};
        let listener = TcpListener::bind(bind).unwrap();
        let destination = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(destination).unwrap();
        let source = client.local_addr().unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"fixture").unwrap();
        let mut bytes = [0; 7];
        server.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"fixture");
        server.write_all(b"fixture").unwrap();
        client.read_exact(&mut bytes).unwrap();
        (source, destination)
    } else {
        let server = UdpSocket::bind(bind).unwrap();
        let client = UdpSocket::bind(bind).unwrap();
        for socket in [&server, &client] {
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
        }
        let destination = server.local_addr().unwrap();
        let source = client.local_addr().unwrap();
        client.send_to(b"fixture", destination).unwrap();
        let mut bytes = [0; 64];
        let (_, peer) = server.recv_from(&mut bytes).unwrap();
        server.send_to(b"reply", peer).unwrap();
        client.recv_from(&mut bytes).unwrap();
        (source, destination)
    };
    // Tracker deletion is explicit. It is not asserted to mean a socket closed.
    let result = Command::new("conntrack")
        .args([
            "-D",
            "-f",
            if v6 { "ipv6" } else { "ipv4" },
            "-p",
            protocol.label(),
            "--orig-src",
            &source.ip().to_string(),
            "--orig-dst",
            &destination.ip().to_string(),
            "--sport",
            &source.port().to_string(),
            "--dport",
            &destination.port().to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "Private tracker removal failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    (protocol, source, destination)
}
#[test]
#[ignore = "Requires private network fixture and ATHERNEX_NATIVE_EVENT_AGENT"]
fn native_flows_survive_stalled_agent_transport_crash_delivery_and_exact_replay() {
    fixture();
    rules(true);
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let config:Config=serde_json::from_value(serde_json::json!({"server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),
        "enrollment_token":null,"scanner":temp.path().join("absent-scanner"),"updater":temp.path().join("absent-updater"),"scan_roots":[temp.path()],"allow_scripts":false,
        "telemetry":{"enabled":true,"interval_secs":30,"linux_network_events":true}})).unwrap();
    crate::private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let binary =
        std::env::var_os("ATHERNEX_NATIVE_EVENT_AGENT").expect("Optimized agent is required");
    let start = || {
        Process(
            Command::new(&binary)
                .arg("run")
                .arg(&state)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        )
    };
    let agent = start();
    let mut connection = None;
    wait(
        || {
            connection = listener.accept().ok().map(|p| p.0);
            connection.is_some()
        },
        "Agent did not reach controlled heartbeat",
    );
    let db = rusqlite::Connection::open_with_flags(
        state.join("endpoint.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(2)).unwrap();
    wait(
        || native_health(&db).healthy(now_ms()),
        "Network collector did not become healthy",
    );
    let mut flows = Vec::new();
    for v6 in [false, true] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for _ in 0..4 {
                flows.push(flow(protocol, v6));
            }
        }
    }
    let selected = || {
        rows(&db).into_iter().filter(|e|matches!(&e.telemetry,Some(Telemetry::NetworkEvent{event,..}) if flows.iter().any(|(p,s,d)|*p==event.protocol&&*s==event.original.source&&*d==event.original.destination))).collect::<Vec<_>>()
    };
    wait(
        || {
            let records = selected();
            flows.iter().all(|(p,s,d)|[Change::Created,Change::Removed].iter().all(|change|records.iter().any(|r|matches!(&r.telemetry,Some(Telemetry::NetworkEvent{event,..}) if *p==event.protocol && *s==event.original.source && *d==event.original.destination && *change==event.change))))
        },
        "Missing created/removed tracker evidence during stalled heartbeat",
    );
    let preserved = selected();
    let before = native_health(&db);
    assert!(before.healthy(now_ms()));
    for row in &preserved {
        let Some(Telemetry::NetworkEvent {
            event, namespace, ..
        }) = &row.telemetry
        else {
            unreachable!()
        };
        assert_eq!(*namespace, before.namespace);
        assert!(row.telemetry.as_ref().unwrap().process().is_none());
        if event.change == Change::Removed {
            assert!(event.original_counters.as_ref().unwrap().bytes > 0);
            assert!(event.reply_counters.as_ref().unwrap().bytes > 0);
        }
    }
    drop(agent);
    drop(connection);
    let restarted = start();
    wait(
        || {
            let h = native_health(&db);
            h.stream_id != before.stream_id
                && h.subscriptions == 2
                && h.loss_signals > 0
                && h.state == "degraded"
        },
        "Crash gap was not retained on restart",
    );
    let fresh = flow(Protocol::Udp, false);
    wait(
        || {
            rows(&db).iter().any(|r|matches!(&r.telemetry,Some(Telemetry::NetworkEvent{event,stream_id,..}) if *stream_id!=before.stream_id && event.original.source==fresh.1 && event.original.destination==fresh.2 && event.change==Change::Removed))
        },
        "Restarted stream did not capture a new flow",
    );
    drop(restarted);
    let recovered = selected();
    for row in &preserved {
        assert!(recovered
            .iter()
            .any(|r| serde_json::to_value(r).unwrap() == serde_json::to_value(row).unwrap()));
    }
    drop(db);
    deliver_and_verify(&temp, &state, listener, config, &preserved);
    println!("Verified 16 short-lived TCP/UDP IPv4/IPv6 flows during stalled actual-agent HTTP, explicit tracker removal/counters, crash/restart gaps, authenticated delivery, exact export and replay");
}

fn deliver_and_verify(
    temp: &tempfile::TempDir,
    state: &std::path::Path,
    listener: TcpListener,
    config: Config,
    selected: &[EndpointEvent],
) {
    use athernex_siem::{
        engine::Engine,
        model::{Kind, Outcome},
        web::{router, App},
    };
    use std::sync::{Arc, Mutex};
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
                hostname: "Private network fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "network-fixture".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("public-native-event-operator-fixture-32")
                .unwrap(),
        ),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serve = app.clone();
    let worker = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                axum::serve(
                    tokio::net::TcpListener::from_std(listener).unwrap(),
                    router(serve),
                )
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
            self.1.take().unwrap().join().unwrap();
        }
    }
    let server = Server(Some(stop), Some(worker));
    let store = Store::open(state).unwrap();
    let client = Client::new(config.clone()).unwrap();
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
            .query_row(
                "SELECT (SELECT count(*) FROM outbox)+(SELECT count(*) FROM telemetry_pending)",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let export = format!(
        "{}api/endpoints/{}/events",
        config.server, config.endpoint_id
    );
    assert!(!http.get(&export).send().unwrap().status().is_success());
    let mut before = i64::MAX as u64;
    let mut found = std::collections::BTreeMap::new();
    loop {
        let page: Vec<serde_json::Value> = http
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
        before = page.last().unwrap()["evidence_id"].as_u64().unwrap();
        for row in page {
            let id = row["event"]["id"].as_str().unwrap().to_owned();
            if selected.iter().any(|e| e.id == id) {
                found.insert(id, row);
            }
        }
    }
    let engine = app.engine.lock().unwrap();
    for event in selected {
        let row = found.get(&event.id).unwrap();
        assert_eq!(row["event"], serde_json::to_value(event).unwrap());
        let normal = engine
            .reconstruct(row["evidence_id"].as_u64().unwrap())
            .unwrap();
        assert_eq!(normal.event.kind, Kind::Network);
        assert_eq!(normal.event.outcome, Outcome::Observe);
        assert_eq!(normal.event.bytes, 0);
        assert_eq!(normal.context.as_ref().unwrap().pid, None);
        assert!(normal
            .context
            .as_ref()
            .unwrap()
            .summary
            .contains("cumulative"));
    }
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|f| f.rule == "AX-003"));
    drop(engine);
    for (path, label) in [
        (
            "endpoints".to_owned(),
            "Network tracker events: coverage incomplete",
        ),
        (
            format!("endpoints/{}", config.endpoint_id),
            "Original tuple",
        ),
    ] {
        assert!(http
            .get(format!("{}{path}", config.server))
            .bearer_auth("public-native-event-operator-fixture-32")
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap()
            .contains(label));
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
    let mut changed = selected[0].clone();
    changed.detail.push_str(" changed");
    assert!(reopened
        .endpoint_events(&config.endpoint_id, &[changed], now_ms())
        .is_err());
}
