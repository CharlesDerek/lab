//! Native decoder differential and actual-agent delivery acceptance. Raw records stay private.
use super::{native, *};
use crate::Config;
use rusqlite::OptionalExtension;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Read,
    net::{SocketAddr, TcpListener, TcpStream},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
mod coexist;
mod flows;
mod rollout;
mod schema;
mod token;
mod transport;
use flows::kind_header;
type Result<T> = std::result::Result<T, &'static str>;
fn require(ok: bool, category: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(category)
    }
}
fn api(operation: &'static str, code: u32) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    let category = match operation {
        "tdh_information" => "tdh_schema",
        "tdh_format_property" => "tdh_property",
        "token_query" => "token",
        "query_trace" => "ownership",
        _ => return Err("guard"),
    };
    println!("\nATHERNEX_NETWORK_EVENTS_DIAGNOSTIC={operation}:{code}");
    Err(category)
}
fn qpc() -> Result<i64> {
    native::clock()
        .map(|clock| clock.after_qpc)
        .map_err(|_| "guard")
}
fn safe<T, E>(value: std::result::Result<T, E>, category: &'static str) -> T {
    match value {
        Ok(value) => value,
        Err(_) => fail(category),
    }
}
#[track_caller]
fn ensure(ok: bool, category: &'static str) {
    if !ok {
        fail(category);
    }
}
#[track_caller]
fn fail(category: &'static str) -> ! {
    // Every caller supplies a closed category; no underlying error is printed.
    println!("\nATHERNEX_NETWORK_EVENTS_FAILURE={category}");
    panic!("Native network acceptance gate failed");
}
#[track_caller]
fn until(mut condition: impl FnMut() -> bool, category: &'static str) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !condition() {
        ensure(Instant::now() < deadline, category);
        thread::sleep(Duration::from_millis(25));
    }
}
fn guard() {
    ensure(
        std::env::var("ATHERNEX_WINDOWS_NETWORK_EVENTS_DISPOSABLE_HOST").as_deref() == Ok("1"),
        "configuration",
    );
    safe(
        athernex_endpoint_native::windows_state::require_local_system(),
        "configuration",
    );
    let mut session = u32::MAX;
    ensure(
        unsafe {
            windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                std::process::id(),
                &mut session,
            )
        } != 0
            && session == 0,
        "configuration",
    );
    safe(native::require_unimpersonated(), "configuration");
}
struct Child(std::process::Child);
impl Child {
    fn reaped(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return self.0.wait().is_ok(),
                Err(_) => return false,
                Ok(None) => (),
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn kill(&mut self) {
        match safe(self.0.try_wait(), "cleanup") {
            Some(_) => {
                safe(self.0.wait(), "cleanup");
            }
            None => {
                safe(self.0.kill(), "cleanup");
                ensure(self.reaped(), "cleanup");
            }
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.0.kill();
        if !self.reaped() {
            eprintln!("Controlled process cleanup exceeded its bounded interval");
            std::process::abort();
        }
    }
}
fn read_metadata<T: serde::de::DeserializeOwned>(state: &Path, key: &str) -> Option<T> {
    let db = safe(
        rusqlite::Connection::open_with_flags(
            state.join("endpoint.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ),
        "durable_admission",
    );
    safe(db.busy_timeout(Duration::from_secs(5)), "durable_admission");
    let raw: Option<String> = safe(
        db.query_row(
            "SELECT value FROM telemetry_metadata WHERE key=?1",
            [key],
            |r| r.get(0),
        )
        .optional(),
        "durable_admission",
    );
    raw.map(|s| safe(serde_json::from_str(&s), "durable_admission"))
}
fn status(state: &Path) -> Option<WindowsNetworkEventHealth> {
    read_metadata(state, "windows_network_events_health")
}
fn intent(state: &Path) -> SessionIntent {
    read_metadata(state, "windows_network_events_session").unwrap_or_else(|| fail("ownership"))
}
fn queued(state: &Path) -> Vec<EndpointEvent> {
    let db = safe(
        rusqlite::Connection::open_with_flags(
            state.join("endpoint.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ),
        "durable_admission",
    );
    safe(db.busy_timeout(Duration::from_secs(5)), "durable_admission");
    let mut query = safe(
        db.prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending"),
        "durable_admission",
    );
    let rows = safe(
        query.query_map([], |r| r.get::<_, String>(0)),
        "durable_admission",
    );
    rows.map(|row| {
        safe(
            serde_json::from_str(&safe(row, "durable_admission")),
            "durable_admission",
        )
    })
    .collect()
}
struct Agent {
    child: Option<Child>,
    state: PathBuf,
}
impl Agent {
    fn start(exe: &Path, state: &Path) -> Self {
        let child = safe(
            Command::new(exe)
                .arg("run")
                .arg(state)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn(),
            "source_start",
        );
        Self {
            child: Some(Child(child)),
            state: state.into(),
        }
    }
    fn restart(&mut self, exe: &Path) {
        ensure(self.child.is_none(), "ownership");
        // Retain this guard: dropping it here would let fixture cleanup reclaim
        // the orphan before the production agent can prove recovery itself.
        self.child = Some(Child(safe(
            Command::new(exe)
                .arg("run")
                .arg(&self.state)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn(),
            "source_start",
        )));
    }
    fn alive(&mut self) {
        ensure(
            safe(
                self.child.as_mut().expect("Agent absent").0.try_wait(),
                "source_stopped",
            )
            .is_none(),
            "source_stopped",
        );
    }
    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill();
        }
    }
    fn cleanup(&mut self) -> bool {
        if let Some(mut child) = self.child.take() {
            match child.0.try_wait() {
                Ok(Some(_)) => (),
                Ok(None) => {
                    if child.0.kill().is_err() || !child.reaped() {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        let recovered = (|| -> crate::Result<bool> {
            let db = rusqlite::Connection::open_with_flags(
                self.state.join("endpoint.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            db.busy_timeout(Duration::from_secs(5))?;
            let raw:Option<String>=db.query_row("SELECT value FROM telemetry_metadata WHERE key='windows_network_events_session'",[],|r|r.get(0)).optional()?;
            if let Some(raw) = raw {
                let owned: SessionIntent = serde_json::from_str(&raw)?;
                native::recover(&owned)?;
                return native::absent(&owned);
            }
            Ok(true)
        })();
        recovered.unwrap_or(false)
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn write_connection(state: &Path) -> rusqlite::Connection {
    let db = safe(
        rusqlite::Connection::open(state.join("endpoint.sqlite3")),
        "durable_admission",
    );
    safe(db.busy_timeout(Duration::from_secs(5)), "durable_admission");
    db
}
struct Fillers(Vec<(&'static str, String, String)>);
impl Fillers {
    fn insert(state: &Path) -> Self {
        let mut db = write_connection(state);
        let tx = safe(
            db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
            "durable_admission",
        );
        let nonce = safe(crate::secret(), "durable_admission");
        let mut rows = Vec::new();
        for (table, budget) in [("outbox", 3072usize), ("telemetry_pending", 8192)] {
            let count: usize = safe(
                tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)),
                "durable_admission",
            );
            ensure(count <= budget, "durable_admission");
            for index in count..budget {
                let id = protocol::hash(format!("{nonce}:{table}:{index}").as_bytes());
                let event = EndpointEvent {
                    id: id.clone(),
                    time_ms: crate::now_ms(),
                    kind: "inventory".into(),
                    path: String::new(),
                    sha256: String::new(),
                    detection: String::new(),
                    detail: "Controlled network agent queue fixture".into(),
                    telemetry: None,
                };
                let payload = safe(serde_json::to_string(&event), "durable_admission");
                safe(
                    tx.execute(
                        &format!("INSERT INTO {table}(id,payload) VALUES(?1,?2)"),
                        rusqlite::params![id, payload],
                    ),
                    "durable_admission",
                );
                rows.push((table, id, payload));
            }
        }
        safe(tx.commit(), "durable_admission");
        Self(rows)
    }
    fn remove(self, state: &Path) {
        let mut db = write_connection(state);
        let tx = safe(
            db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
            "durable_admission",
        );
        for (table, id, payload) in self.0 {
            ensure(
                safe(
                    tx.execute(
                        &format!("DELETE FROM {table} WHERE id=?1 AND payload=?2"),
                        rusqlite::params![id, payload],
                    ),
                    "durable_admission",
                ) == 1,
                "durable_admission",
            );
        }
        safe(tx.commit(), "durable_admission");
    }
}

fn schema_identity(label: &str) -> (u32, &'static str) {
    match label {
        "tcp4_connect" => (
            15,
            "5254d11d3ab0dacd7dd03cc71614a747927ff55f61d903bcae910fb923e909dc",
        ),
        "tcp4_accept" => (
            15,
            "eb21c45e4603de43fe8872a2ea0fa0637cbf91a6d49fe41fcdc15ffe1a0c2c5a",
        ),
        "tcp4_receive" | "udp4_receive" => (
            8,
            "59fffc969a1ed23b13a0cc437cfb886290360c3d65c7d79b2415a9bb20f5110c",
        ),
        "tcp4_send" => (
            10,
            "bf194bb2964bfc73d33ac287722f227a00d1f141eaf3ff3f272f9032c702f1ed",
        ),
        "tcp4_disconnect" => (
            8,
            "2e558a436c9a3e015c0985f13b4810c10612a41bb92b017a1e3f2d0b6a927295",
        ),
        "tcp6_connect" => (
            15,
            "5d4c432f1d9728df8431d23cedc7fa607f8f4fa669c490a2d232a15531551835",
        ),
        "tcp6_accept" => (
            15,
            "3b611b933f318c8d86820137f4ba7b60d8eab6768076b4ca67e862fee4ed3d1b",
        ),
        "tcp6_receive" | "udp6_receive" => (
            8,
            "e29ec558121045f5a59d4188a4edf5aaada207d87fb0e3a83fc680d2a266b71b",
        ),
        "tcp6_send" => (
            10,
            "ba1fd94cccbb5a7e5d6c6854c21d70a6039dd489f6c362317d5c2f721ae67888",
        ),
        "tcp6_disconnect" => (
            8,
            "c811fc4ecc3af52c5ded1dbb688049e6340f1ceb5691eef98d638ff5b2ea9059",
        ),
        "udp4_send" => (
            8,
            "42a070f09a58fd2e0c94f4372719f68ade2877c51657cf231cfe1214bec57ee1",
        ),
        "udp6_send" => (
            8,
            "926f87b094e22417b9f35e5b6310443c521e56b114ad34b4bf90d4c5316a3bc4",
        ),
        _ => fail("tdh_schema"),
    }
}
fn component(path: &Path) {
    native::copied_record_bounds_and_lifetime();
    let store = safe(Store::open(path), "durable_admission");
    let mut coexist = safe(coexist::Coexist::start(&store), "ownership");
    let (mut health, mut owned) = safe(prepare(&store), "ownership");
    let mut reader = safe(native::Reader::start(&owned), "source_start");
    ensure(native::recover(&owned).is_err(), "ownership");
    let mut foreign = owned.clone();
    foreign.stream_id = if owned.stream_id.starts_with('b') {
        "c".repeat(64)
    } else {
        "b".repeat(64)
    };
    let f = &foreign.stream_id;
    foreign.session_guid = format!(
        "{{{}-{}-{}-{}-{}}}",
        &f[..8],
        &f[8..12],
        &f[12..16],
        &f[16..20],
        &f[20..32]
    );
    foreign.owner_created = owned
        .owner_created
        .checked_add(1)
        .unwrap_or_else(|| fail("ownership"));
    safe(foreign.validate(&owned.session_name), "ownership");
    ensure(
        native::recover(&foreign).is_err() && !safe(native::absent(&owned), "ownership"),
        "ownership",
    );
    owned.phase = "active".into();
    safe(coexist.child(), "controlled_traffic");
    let flows = flows::flows();
    let mut matched = BTreeMap::new();
    until(
        || {
            safe(reader.check(), "source_stopped");
            safe(coexist.check(), "ownership");
            let records = reader.batch();
            let receipt = records
                .last()
                .map_or(owned.consumed_receipt, |record| record.sequence());
            let clock = safe(native::clock(), "tdh_schema");
            let mut events = Vec::new();
            let mut rejected = 0;
            for record in records {
                let original = record.clone().original(&owned.stream_id, clock.clone());
                match WindowsNetworkEvent::from_original(original.clone()) {
                    Ok(event) => {
                        let kind = flows::event_kind(&event);
                        let selected =
                            flows::select(vec![envelope(&event)], &flows, &owned.stream_id);
                        if selected.contains_key(kind.label) {
                            // TDH formats and checks every field of these exact owned bytes.
                            let report = safe(schema::decode(&record, kind.ipv6), "tdh_property");
                            let expected = schema_identity(kind.label);
                            ensure(
                                report.pid == event.reported_pid
                                    && report.source == event.source
                                    && report.destination == event.destination
                                    && report.size == event.reported_size
                                    && report.pointer_bits == event.header_pointer_bits
                                    && report.property_count == expected.0
                                    && report.schema_hash == expected.1
                                    && event.original == original,
                                "tdh_schema",
                            );
                            matched.insert(kind.label, event.event_id());
                        }
                        events.push(event);
                    }
                    Err(_) => rejected += 1,
                }
            }
            safe(
                persist(
                    &store,
                    &mut health,
                    &mut owned,
                    &events,
                    rejected,
                    receipt,
                    safe(reader.counters(), "native_loss"),
                ),
                "durable_admission",
            );
            ensure(health.healthy(crate::now_ms()), "native_loss");
            matched.len() == 14
        },
        "controlled_traffic",
    );
    safe(coexist.verify_child(), "controlled_traffic");
    let counters = safe(reader.close(), "cleanup");
    ensure(
        counters.events_lost == 0
            && counters.log_buffers_lost == 0
            && counters.realtime_buffers_lost == 0
            && counters.rejected == 0
            && counters.callback_drops == 0,
        "native_loss",
    );
    while safe(
        admit_batch(&store, &mut health, &mut owned, &reader),
        "durable_admission",
    ) != 0
    {}
    ensure(health.healthy(crate::now_ms()), "native_loss");
    ensure(safe(native::absent(&owned), "cleanup"), "cleanup");
    safe(coexist.close(), "cleanup");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=tdh_differential_verified");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=coexistence_verified");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=source_loss_verified");
}

#[test]
#[ignore = "Requires an explicitly disposable Windows LocalSystem/session-zero host and the exact staged release agent"]
fn network_reports_replay_with_visible_capture_gaps() {
    guard();
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=guard_verified");
    let token_before = safe(token::snapshot(), "token");
    ensure(token_before.unimpersonated(), "token");
    schema::property_names_and_scalar_metadata_are_bounded_and_typed();
    schema::failed_property_context_never_contains_private_values();
    schema::context_hypothesis_requires_exact_v2_template();
    schema::formatter_values_and_bounds_are_checked();
    let exe = PathBuf::from(
        std::env::var_os("ATHERNEX_NATIVE_NETWORK_EVENTS_AGENT")
            .unwrap_or_else(|| fail("configuration")),
    );
    ensure(exe.is_absolute() && exe.is_file(), "configuration");
    let exe = safe(exe.canonicalize(), "configuration");
    let test = safe(
        safe(std::env::current_exe(), "configuration").canonicalize(),
        "configuration",
    );
    ensure(
        exe.parent() == test.parent() && exe.file_name().is_some_and(|name| name == "agent.exe"),
        "configuration",
    );
    ensure(
        test.file_name()
            .is_some_and(|name| name == "endpoint-tests.exe"),
        "configuration",
    );
    let parent = exe.parent().unwrap_or_else(|| fail("configuration"));
    let directory = safe(
        athernex_endpoint_native::windows_state::Directory::open(parent),
        "configuration",
    );
    safe(directory.require_service_access(), "configuration");
    let _private_exe = safe(directory.read("agent.exe"), "configuration");
    let mut pinned_exe = safe(
        OpenOptions::new()
            .read(true)
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
            .open(&exe),
        "configuration",
    );
    let length = safe(pinned_exe.metadata(), "configuration").len();
    ensure(length > 0 && length <= 128 * 1024 * 1024, "configuration");
    let mut executable = Vec::new();
    safe(
        (&mut pinned_exe)
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut executable),
        "configuration",
    );
    ensure(executable.len() as u64 == length, "configuration");
    let manifest: serde_json::Value = safe(directory.read_json("inputs.json"), "configuration");
    ensure(
        manifest["suite"] == "NetworkEvents"
            && manifest["sha256"]["agent.exe"].as_str()
                == Some(protocol::hash(&executable).as_str()),
        "configuration",
    );
    drop(executable);
    let temp = safe(
        tempfile::Builder::new()
            .prefix("network-events-private-")
            .tempdir_in(exe.parent().unwrap_or_else(|| fail("configuration"))),
        "configuration",
    );
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(temp.path(), &exe)));
    ensure(safe(token::snapshot(), "token") == token_before, "token");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=token_verified");
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=cleanup_verified");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=passed");
}
fn run(temp: &Path, exe: &Path) {
    component(&temp.join("component"));
    let state = temp.join("agent");
    drop(safe(Store::open(&state), "configuration"));
    let listener = safe(TcpListener::bind("127.0.0.1:0"), "transport");
    safe(listener.set_nonblocking(true), "transport");
    let address = safe(listener.local_addr(), "transport");
    let config: Config = safe(
        serde_json::from_value(
            serde_json::json!({"server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":null,"scanner":temp.join("absent-scanner"),"updater":temp.join("absent-updater"),"scan_roots":[temp],"allow_scripts":false,"telemetry":{"enabled":true,"interval_secs":30,"windows_network_events":true}}),
        ),
        "configuration",
    );
    safe(
        std::fs::write(
            state.join("config.json"),
            safe(serde_json::to_vec(&config), "configuration"),
        ),
        "configuration",
    );
    let mut once = Child(safe(
        Command::new(exe)
            .arg("run")
            .arg(&state)
            .arg("--once")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn(),
        "configuration",
    ));
    until(
        || safe(once.0.try_wait(), "configuration").is_some(),
        "configuration",
    );
    ensure(
        !safe(once.0.wait(), "configuration").success()
            && read_metadata::<SessionIntent>(&state, "windows_network_events_session").is_none(),
        "configuration",
    );
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=agent_config_verified");
    let mut agent = Agent::start(exe, &state);
    until(
        || {
            agent.alive();
            status(&state).is_some_and(|health| health.healthy(crate::now_ms()))
        },
        "source_start",
    );
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=source_ready");
    let held = stalled(&listener, &mut agent, &config);
    let owned = intent(&state);
    let flows = flows::flows();
    until(
        || {
            agent.alive();
            flows::select(queued(&state), &flows, &owned.stream_id).len() == 14
        },
        "controlled_traffic",
    );
    let selected: Vec<_> = flows::select(queued(&state), &flows, &owned.stream_id)
        .into_values()
        .collect();
    ensure(selected.len() == 14, "controlled_traffic");
    let healthy = status(&state).unwrap_or_else(|| fail("native_loss"));
    ensure(healthy.healthy(crate::now_ms()), "native_loss");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=tcp4_verified");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=tcp6_verified");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=udp4_verified");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=udp6_verified");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=stalled_http_verified");
    let fillers = Fillers::insert(&state);
    let before_pressure = status(&state).unwrap_or_else(|| fail("durable_admission"));
    let pressure = flows::flows();
    until(
        || {
            agent.alive();
            status(&state).is_some_and(|health| {
                health.queue_drops >= before_pressure.queue_drops.saturating_add(14)
                    && health.received_records
                        >= before_pressure.received_records.saturating_add(14)
                    && health.rejected_records == before_pressure.rejected_records
                    && health.callback_drops == before_pressure.callback_drops
                    && health.events_lost == before_pressure.events_lost
                    && health.log_buffers_lost == before_pressure.log_buffers_lost
                    && health.realtime_buffers_lost == before_pressure.realtime_buffers_lost
                    && health.backpressured
                    && !health.healthy(crate::now_ms())
            })
        },
        "durable_admission",
    );
    ensure(
        flows::select(queued(&state), &pressure, &owned.stream_id).is_empty(),
        "durable_admission",
    );
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=queue_loss_verified");
    agent.kill();
    ensure(!safe(native::absent(&owned), "ownership"), "ownership");
    fillers.remove(&state);
    agent.restart(exe);
    until(
        || {
            agent.alive();
            status(&state).is_some_and(|health| {
                health.subscriptions >= 2
                    && health.loss_signals > 0
                    && !health.healthy(crate::now_ms())
            })
        },
        "ownership",
    );
    let recovered = intent(&state);
    ensure(
        recovered.stream_id != owned.stream_id
            && (recovered.owner_pid, recovered.owner_created)
                != (owned.owner_pid, owned.owner_created),
        "ownership",
    );
    let after = queued(&state);
    ensure(
        selected.iter().all(|event| {
            after
                .iter()
                .any(|actual| serde_json::to_vec(actual).ok() == serde_json::to_vec(event).ok())
        }),
        "replay",
    );
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=crash_replay_verified");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=orphan_recovered");
    let losses = status(&state)
        .unwrap_or_else(|| fail("native_loss"))
        .loss_signals;
    safe(native::stop_for_test(&recovered), "source_stopped");
    until(
        || {
            status(&state).is_some_and(|health| {
                health.loss_signals > losses
                    && health.state == "degraded"
                    && !health.healthy(crate::now_ms())
            })
        },
        "source_stopped",
    );
    let degraded = status(&state).unwrap_or_else(|| fail("native_loss"));
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=session_gap_verified");
    agent.kill();
    ensure(safe(native::absent(&recovered), "cleanup"), "cleanup");
    drop(held);
    safe(rollout::verify(temp, &healthy, &degraded), "rollout");
    println!("\nATHERNEX_NETWORK_EVENTS_STAGE=rollout_gates_verified");
    transport::deliver(temp, &state, listener, &config, exe, &selected, &degraded);
    ensure(agent.cleanup(), "cleanup");
}

fn stalled(listener: &TcpListener, agent: &mut Agent, config: &Config) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut stream = loop {
        agent.alive();
        ensure(Instant::now() < deadline, "timeout");
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => fail("transport"),
        }
    };
    safe(
        stream.set_read_timeout(Some(Duration::from_secs(5))),
        "transport",
    );
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        ensure(
            bytes.len() < 16384 && Instant::now() < deadline,
            "transport",
        );
        let mut byte = [0];
        safe(stream.read_exact(&mut byte), "transport");
        bytes.push(byte[0]);
    }
    let headers = safe(std::str::from_utf8(&bytes), "transport");
    let mut lines = headers.split("\r\n");
    ensure(
        lines.next()
            == Some(
                format!(
                    "POST /api/endpoint/{}/heartbeat HTTP/1.1",
                    config.endpoint_id
                )
                .as_str(),
            ),
        "transport",
    );
    let mut length = None;
    let mut authorized = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap_or_else(|| fail("transport"));
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            ensure(
                length.is_none() && !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "transport",
            );
            length = Some(safe(value.parse::<usize>(), "transport"));
        }
        if name.eq_ignore_ascii_case("authorization") {
            ensure(
                !authorized && value == format!("Bearer {}", config.credential),
                "transport",
            );
            authorized = true;
        }
        ensure(!name.eq_ignore_ascii_case("transfer-encoding"), "transport");
    }
    let length = length.unwrap_or_else(|| fail("transport"));
    ensure(
        authorized && length > 0 && length <= 192 * 1024,
        "transport",
    );
    let mut body = vec![0; length];
    safe(stream.read_exact(&mut body), "transport");
    let heartbeat: protocol::Heartbeat = safe(serde_json::from_slice(&body), "transport");
    safe(heartbeat.validate(), "transport");
    ensure(
        heartbeat
            .collector
            .as_ref()
            .and_then(|collector| collector.windows_network_events.as_ref())
            .is_some_and(|source| {
                source.stream_id == intent(&agent.state).stream_id && source.subscriptions == 1
            }),
        "transport",
    );
    stream
}
