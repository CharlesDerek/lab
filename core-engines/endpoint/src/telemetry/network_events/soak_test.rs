//! Opt-in, measured native load; no host network policy is modified.
use super::*;
use athernex_siem::{
    engine::Engine,
    fleet::EndpointObservation,
    model::{Kind, Outcome},
    web::{router, App},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{atomic::AtomicBool, Arc, Mutex},
};

struct Server {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.worker.take().unwrap().join().unwrap();
    }
}
fn serve(listener: TcpListener, app: App, available: Arc<AtomicBool>) -> Server {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let worker = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let service = router(app).layer(axum::middleware::from_fn(
                    move |request: axum::extract::Request, next: axum::middleware::Next| {
                        let available = available.clone();
                        async move {
                            use axum::response::IntoResponse;
                            if available.load(Ordering::Acquire) {
                                next.run(request).await
                            } else {
                                axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                            }
                        }
                    },
                ));
                axum::serve(
                    tokio::net::TcpListener::from_std(listener).unwrap(),
                    service,
                )
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
            });
    });
    Server {
        stop: Some(stop),
        worker: Some(worker),
    }
}

fn key(protocol: Protocol, source: SocketAddr, destination: SocketAddr) -> String {
    format!("{} {source} {destination}", protocol.label())
}
fn event_key(event: &EndpointEvent) -> Option<String> {
    match &event.telemetry {
        Some(Telemetry::NetworkEvent { event, .. }) => Some(key(
            event.protocol,
            event.original.source,
            event.original.destination,
        )),
        _ => None,
    }
}
struct Expected {
    phase: &'static str,
    started: Instant,
    created: bool,
    removed: bool,
    latency_ms: Option<u128>,
}
struct Measurement {
    db: rusqlite::Connection,
    app: App,
    endpoint: String,
    expected: BTreeMap<String, Expected>,
    captured: BTreeMap<String, EndpointEvent>,
    delivered: BTreeMap<String, EndpointObservation>,
    delivered_keys: BTreeSet<String>,
    last_evidence: u64,
    max_pending: u64,
    max_outbox: u64,
    max_rss_kib: u64,
    phases: Vec<serde_json::Value>,
}
impl Measurement {
    fn poll(&mut self, pid: u32) {
        let counts: (u64, u64) = self
            .db
            .query_row(
                "SELECT (SELECT count(*) FROM telemetry_pending),(SELECT count(*) FROM outbox)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(
            counts.0 <= 8192 && counts.1 <= 4096,
            "Queue exceeded its bound"
        );
        self.max_pending = self.max_pending.max(counts.0);
        self.max_outbox = self.max_outbox.max(counts.1);
        for event in rows(&self.db) {
            if event_key(&event).is_some_and(|k| self.expected.contains_key(&k)) {
                self.captured.insert(event.id.clone(), event);
            }
        }
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            if let Some(rss) = status.lines().find_map(|line| {
                line.strip_prefix("VmHWM:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            }) {
                self.max_rss_kib = self.max_rss_kib.max(rss);
            }
        }
        let engine = self.app.engine.lock().unwrap();
        let mut before = i64::MAX as u64;
        let mut highest = self.last_evidence;
        loop {
            let page = engine
                .endpoint_observations(&self.endpoint, before, 64)
                .unwrap();
            if page.is_empty() {
                break;
            }
            before = page.last().unwrap().evidence_id;
            for row in page {
                if row.evidence_id <= self.last_evidence {
                    continue;
                }
                highest = highest.max(row.evidence_id);
                let Some(k) = event_key(&row.event) else {
                    continue;
                };
                self.delivered_keys.insert(k.clone());
                let Some(expected) = self.expected.get_mut(&k) else {
                    continue;
                };
                let Some(Telemetry::NetworkEvent { event, .. }) = &row.event.telemetry else {
                    unreachable!()
                };
                expected.created |= event.change == Change::Created;
                expected.removed |= event.change == Change::Removed;
                if expected.created && expected.removed && expected.latency_ms.is_none() {
                    expected.latency_ms = Some(expected.started.elapsed().as_millis());
                }
                self.delivered.insert(row.event.id.clone(), row);
            }
            if before <= self.last_evidence {
                break;
            }
        }
        self.last_evidence = highest;
    }
    fn generate(&mut self, phase: &'static str, seconds: u64, rate: u64, pid: u32) {
        let began = Instant::now();
        let mut next_poll = Instant::now();
        for i in 0..seconds * rate {
            let target = began + Duration::from_secs_f64(i as f64 / rate as f64);
            thread::sleep(target.saturating_duration_since(Instant::now()));
            let started = Instant::now();
            let (p, s, d) = flow(
                if i % 2 == 0 {
                    Protocol::Tcp
                } else {
                    Protocol::Udp
                },
                i % 4 >= 2,
            );
            assert!(
                self.expected
                    .insert(
                        key(p, s, d),
                        Expected {
                            phase,
                            started,
                            created: false,
                            removed: false,
                            latency_ms: None,
                        }
                    )
                    .is_none(),
                "Repeated fixture tuple makes the sample ambiguous"
            );
            if Instant::now() >= next_poll {
                self.poll(pid);
                next_poll = Instant::now() + Duration::from_secs(1);
            }
        }
        thread::sleep(
            (began + Duration::from_secs(seconds)).saturating_duration_since(Instant::now()),
        );
        self.poll(pid);
        self.phases.push(serde_json::json!({"phase":phase,"flows":seconds*rate,
            "elapsed_ms":began.elapsed().as_millis(),"target_flows_per_second":rate,
            "delivered_complete_at_phase_end":self.expected.values().filter(|e|e.phase==phase&&e.latency_ms.is_some()).count()}));
        println!(
            "Network soak phase {phase}: {} flows in {:.1}s",
            seconds * rate,
            began.elapsed().as_secs_f64()
        );
    }
}
fn setting(name: &str, default: u64, min: u64, max: u64) -> u64 {
    let value = std::env::var(name).map_or(default, |s| s.parse().expect("Invalid soak setting"));
    assert!(
        (min..=max).contains(&value),
        "Out-of-range soak setting {name}"
    );
    value
}

#[test]
#[ignore = "Requires private network fixture, optimized agent and several minutes"]
fn native_sustained_delivery_outage_and_restart_are_measured() {
    fixture();
    rules(true);
    let seconds = setting("ATHERNEX_NETWORK_SOAK_SECONDS", 60, 60, 600);
    let rate = setting("ATHERNEX_NETWORK_SOAK_RATE", 8, 1, 16);
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let server_db = temp.path().join("server.db");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "server":format!("http://{}/",listener.local_addr().unwrap()),
        "endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":null,
        "scanner":temp.path().join("absent-scanner"),"updater":temp.path().join("absent-updater"),
        "scan_roots":[temp.path()],"allow_scripts":false,
        "telemetry":{"enabled":true,"interval_secs":30,"linux_network_events":true}
    }))
    .unwrap();
    crate::private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
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
                hostname: "Private native network load fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "network-soak".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("public-network-soak-operator-fixture-32")
                .unwrap(),
        ),
    };
    let available = Arc::new(AtomicBool::new(true));
    let server = serve(listener, app.clone(), available.clone());
    let binary = std::env::var_os("ATHERNEX_NATIVE_EVENT_AGENT").expect("Optimized agent required");
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
    wait(
        || state.join("endpoint.sqlite3").exists(),
        "Agent database did not appear",
    );
    let db = rusqlite::Connection::open_with_flags(
        state.join("endpoint.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    wait(
        || {
            db.query_row(
                "SELECT value FROM telemetry_metadata WHERE key='network_events_health'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|s| serde_json::from_str::<NetworkEventHealth>(&s).ok())
            .is_some_and(|h| h.healthy(now_ms()))
        },
        "Network collector did not become healthy",
    );
    let began = Instant::now();
    let mut measured = Measurement {
        db,
        app: app.clone(),
        endpoint: config.endpoint_id.clone(),
        expected: BTreeMap::new(),
        captured: BTreeMap::new(),
        delivered: BTreeMap::new(),
        delivered_keys: BTreeSet::new(),
        last_evidence: 0,
        max_pending: 0,
        max_outbox: 0,
        max_rss_kib: 0,
        phases: Vec::new(),
    };
    measured.generate("online", seconds, rate, agent.0.id());
    assert!(
        measured.expected.values().any(|e| e.latency_ms.is_some()),
        "No online delivery during load"
    );
    available.store(false, Ordering::Release);
    // Let any already accepted request finish before attributing outage delivery.
    thread::sleep(Duration::from_secs(1));
    measured.generate("server_unavailable", 30, rate, agent.0.id());
    assert!(measured
        .expected
        .values()
        .filter(|e| e.phase == "server_unavailable")
        .all(|e| e.latency_ms.is_none()));
    wait(
        || {
            measured.poll(agent.0.id());
            let mut boundaries: BTreeMap<_, u8> = measured
                .expected
                .iter()
                .map(|(k, e)| (k.clone(), u8::from(e.created) | (u8::from(e.removed) << 1)))
                .collect();
            for row in rows(&measured.db) {
                if let Some(Telemetry::NetworkEvent { event, .. }) = &row.telemetry {
                    if let Some(bits) = boundaries.get_mut(&event_key(&row).unwrap()) {
                        *bits |= match event.change {
                            Change::Created => 1,
                            Change::Removed => 2,
                            Change::Updated => 0,
                        };
                    }
                }
            }
            boundaries.values().all(|bits| *bits == 3)
        },
        "Pre-crash flow boundaries did not reach durable storage",
    );
    measured.poll(agent.0.id());
    let outage_originals: Vec<_> = measured
        .captured
        .values()
        .filter(|e| {
            event_key(e).is_some_and(|k| measured.expected[&k].phase == "server_unavailable")
        })
        .cloned()
        .collect();
    let before = native_health(&measured.db);
    assert!(
        before.healthy(now_ms()),
        "Unexpected pre-crash coverage loss: {before:?}"
    );
    drop(agent);
    let gap: Vec<_> = (0..8)
        .map(|i| {
            let (p, s, d) = flow(
                if i % 2 == 0 {
                    Protocol::Tcp
                } else {
                    Protocol::Udp
                },
                i % 4 >= 2,
            );
            key(p, s, d)
        })
        .collect();
    let restarted = start();
    wait(
        || {
            let h = native_health(&measured.db);
            h.stream_id != before.stream_id
                && h.subscriptions == 2
                && h.loss_signals == 1
                && h.state == "degraded"
        },
        "Agent restart did not record the expected interrupted subscription",
    );
    available.store(true, Ordering::Release);
    measured.generate("recovery", seconds, rate, restarted.0.id());
    let drain = Instant::now();
    loop {
        measured.poll(restarted.0.id());
        if measured.expected.values().all(|e| e.latency_ms.is_some()) {
            break;
        }
        assert!(
            drain.elapsed() < Duration::from_secs(90),
            "Missing flow boundaries after recovery: {}",
            measured
                .expected
                .values()
                .filter(|e| e.latency_ms.is_none())
                .count()
        );
        thread::sleep(Duration::from_millis(200));
    }
    let after = native_health(&measured.db);
    assert_eq!(
        after.dropped_events, 0,
        "Queue dropped observations during measured load"
    );
    assert_eq!(
        after.loss_signals, 1,
        "Unexpected kernel loss in addition to deliberate crash"
    );
    assert!(
        !after.healthy(now_ms()),
        "Crash gap must remain visible after recovery"
    );
    drop(restarted);
    measured.poll(0);
    assert!(
        gap.iter().all(|k| !measured.delivered_keys.contains(k)),
        "Events generated while the collector was dead must not be invented"
    );
    let drain_ms = drain.elapsed().as_millis();
    let mut latencies = serde_json::Map::new();
    for phase in ["online", "server_unavailable", "recovery"] {
        let mut samples: Vec<_> = measured
            .expected
            .values()
            .filter(|e| e.phase == phase)
            .map(|e| e.latency_ms.unwrap())
            .collect();
        samples.sort_unstable();
        latencies.insert(phase.into(), serde_json::json!({"samples":samples.len(),
            "p50_ms":samples[(samples.len()-1)/2],"p95_ms":samples[(samples.len()-1)*95/100],"max_ms":samples.last()}));
    }
    let engine = app.engine.lock().unwrap();
    for row in measured.delivered.values() {
        assert!(!gap.contains(&event_key(&row.event).unwrap()));
        assert!(
            row.case_id.is_none(),
            "Unexpected investigation for benign tracker observation"
        );
        let normalized = engine.reconstruct(row.evidence_id).unwrap();
        assert_eq!(normalized.event.kind, Kind::Network);
        assert_eq!(normalized.event.outcome, Outcome::Observe);
        assert_eq!(normalized.event.bytes, 0);
        assert_eq!(normalized.context.unwrap().pid, None);
    }
    for event in measured.captured.values().chain(outage_originals.iter()) {
        let delivered = &measured
            .delivered
            .get(&event.id)
            .expect("Locally retained event was not delivered")
            .event;
        assert_eq!(
            serde_json::to_value(event).unwrap(),
            serde_json::to_value(delivered).unwrap()
        );
    }
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|f| f.rule == "AX-003"));
    drop(engine);
    drop(server);
    drop(app);
    let Measurement {
        app,
        delivered,
        expected,
        captured,
        max_pending,
        max_outbox,
        max_rss_kib,
        phases,
        ..
    } = measured;
    drop(app);
    let reopened = Engine::open(&server_db).unwrap();
    let replay: Vec<_> = delivered.values().map(|r| r.event.clone()).collect();
    for batch in replay.chunks(protocol::MAX_EVENTS) {
        assert_eq!(
            reopened
                .endpoint_events(&config.endpoint_id, batch, now_ms())
                .unwrap(),
            0
        );
    }
    let report = serde_json::json!({"schema":1,"passed":true,"elapsed_ms":began.elapsed().as_millis(),
        "phases":phases,"expected_flows":expected.len(),"complete_flows":expected.values().filter(|e|e.latency_ms.is_some()).count(),
        "delivered_tracker_records":delivered.len(),"exact_local_originals_verified":captured.len(),
        "outage_originals_verified":outage_originals.len(),"intentional_unobserved_gap_flows":gap.len(),
        "queue_high_water":{"pending":max_pending,"outbox":max_outbox},"agent_peak_rss_kib":max_rss_kib,
        "completion_latency_observed_upper_bound":latencies,"drain_after_generation_ms":drain_ms,
        "coverage_before_crash":before,"coverage_after_recovery":after,"unexpected_network_investigations":0,
        "replayed_records_without_duplicates":replay.len(),"native_windows_or_macos":false,
        "limits":["One Linux kernel and one endpoint; synthetic benign loopback workload, not a production false-positive rate",
            "Created/removed boundaries are checked; optional intermediate kernel updates have no independent expected count",
            "Delivery latency includes periodic fixture observation; RSS is the maximum sampled per-process high-water value",
            "Deliberate crash interval is unobservable and remains degraded; no arbitrary-load or lossless claim"]});
    println!("ATHERNEX_NETWORK_SOAK_REPORT={report}");
}
