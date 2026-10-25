//! Disposable native component and real-agent acceptance. Raw observations stay local.
use super::{native, *};
use crate::Config;
use athernex_endpoint_protocol::windows_process_events::WindowsProcessChange;
use rusqlite::OptionalExtension;
use std::{
    collections::BTreeMap,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
mod schema;
mod token;
mod transport;
type Result<T> = std::result::Result<T, &'static str>;
const CHILD: &str = "telemetry::windows_process_events::native_test::controlled_process_child";

fn require(ok: bool, message: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message)
    }
}
fn api(operation: &'static str, code: u32) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    if matches!(
        operation,
        "token_query" | "tdh_information" | "tdh_size" | "tdh_property"
    ) {
        println!("\nATHERNEX_PROCESS_EVENTS_DIAGNOSTIC={operation}:{code}");
    }
    Err("Native fixture API failed")
}
fn tdh_failure(error: &str) -> &'static str {
    match error {
        "TDH schema provenance differs" => "tdh_schema_provenance",
        "TDH schema event identity differs" => "tdh_schema_identity",
        "TDH metadata size probe invalid"
        | "TDH metadata exceeds bounds"
        | "TDH metadata result invalid"
        | "TDH property array exceeds buffer"
        | "Invalid schema property name offset"
        | "Schema property name empty"
        | "Schema property name encoding invalid"
        | "Schema property name invalid"
        | "Schema property name unterminated"
        | "Schema property name overlaps metadata array" => "tdh_schema_bounds",
        "TDH property count exceeds flat schema budget"
        | "Unsupported structured process schema"
        | "Duplicate process property"
        | "Schema fingerprint failed" => "tdh_schema_shape",
        "Required process schema property missing" => "tdh_property_missing",
        "Process schema property type differs" => "tdh_property_type",
        "Process schema property is not scalar" => "tdh_property_scalar",
        "TDH scalar property size differs"
        | "Invalid scalar bytes"
        | "Invalid pointer scalar bytes" => "tdh_property_size",
        "Invalid native process provenance" | "Native process pointer width is ambiguous" => {
            "tdh_record_provenance"
        }
        "Native fixture API failed" => "tdh_api",
        _ => "tdh_other",
    }
}
#[test]
fn tdh_rejections_export_only_closed_categories() {
    for (error, expected) in [
        ("TDH schema provenance differs", "tdh_schema_provenance"),
        ("TDH schema event identity differs", "tdh_schema_identity"),
        ("TDH metadata result invalid", "tdh_schema_bounds"),
        ("Duplicate process property", "tdh_schema_shape"),
        (
            "Required process schema property missing",
            "tdh_property_missing",
        ),
        ("Process schema property type differs", "tdh_property_type"),
        (
            "Process schema property is not scalar",
            "tdh_property_scalar",
        ),
        ("TDH scalar property size differs", "tdh_property_size"),
        (
            "Native process pointer width is ambiguous",
            "tdh_record_provenance",
        ),
        ("Native fixture API failed", "tdh_api"),
        ("unexpected\nprivate-value", "tdh_other"),
        ("TDH schema provenance differs appended text", "tdh_other"),
    ] {
        assert_eq!(tdh_failure(error), expected);
    }
}
fn differential(event: &WindowsProcessEvent, report: &schema::Report) {
    let scalar_matches = event.pid == report.pid
        && event.parent_pid == report.parent
        && event.session_id == report.session
        && event.exit_status == report.exit
        && event.unique_process_key == report.key
        && event.pointer_bits == report.pointer_bits;
    let shape_matches = if event.change == WindowsProcessChange::Terminate {
        event.original.header.descriptor.version == 2
            && event.pointer_bits == 64
            && report.property_count == 1
            && event.original.user_data_hex.len() == 8
            && report.schema_hash.len() == 64
    } else {
        event.original.header.descriptor.version == 4
            && event.pointer_bits == 64
            && report.property_count == 12
            && report.schema_hash.len() == 64
    };
    if !scalar_matches || !shape_matches {
        // Only bounded structural metadata is public. No payload values,
        // PID, key, SID, command line or raw original enters this marker.
        let descriptor = &event.original.header.descriptor;
        println!(
            "\nATHERNEX_PROCESS_EVENTS_SCHEMA={}:{}:{}:{}",
            descriptor.opcode, descriptor.version, event.pointer_bits, report.property_count
        );
        fail(if !scalar_matches {
            "tdh_scalar_mismatch"
        } else {
            "tdh_expected_shape"
        });
    }
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
    println!("\nATHERNEX_PROCESS_EVENTS_FAILURE={category}");
    panic!("Native process acceptance gate failed");
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
        std::env::var("ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST").as_deref() == Ok("1"),
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
    fn controlled() -> Self {
        let exe = safe(std::env::current_exe(), "controlled_lifecycle");
        Self(safe(
            Command::new(exe)
                .args(["--exact", CHILD, "--ignored", "--nocapture"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn(),
            "controlled_lifecycle",
        ))
    }
    fn finish(&mut self) {
        safe(
            self.0
                .stdin
                .take()
                .expect("Controlled stdin missing")
                .write_all(b"x"),
            "controlled_lifecycle",
        );
        until(
            || safe(self.0.try_wait(), "controlled_lifecycle").is_some(),
            "controlled_lifecycle",
        );
        ensure(
            safe(self.0.wait(), "controlled_lifecycle").code() == Some(23),
            "controlled_lifecycle",
        );
    }
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
        safe(self.0.kill(), "cleanup");
        ensure(self.reaped(), "cleanup");
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
#[test]
#[ignore = "Internal controlled native process child"]
fn controlled_process_child() {
    guard();
    use std::io::Read;
    let mut signal = [0];
    ensure(
        std::io::stdin().read_exact(&mut signal).is_ok(),
        "controlled_lifecycle",
    );
    std::process::exit(23);
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
fn status(state: &Path) -> Option<WindowsProcessEventHealth> {
    read_metadata(state, "windows_process_events_health")
}
fn intent(state: &Path) -> SessionIntent {
    read_metadata(state, "windows_process_events_session").unwrap_or_else(|| fail("ownership"))
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
fn process(e: &EndpointEvent) -> Option<&WindowsProcessEvent> {
    match &e.telemetry {
        Some(Telemetry::WindowsProcessEvent { event }) => Some(event),
        _ => None,
    }
}
fn controlled(state: &Path, pids: &[u32]) -> Vec<EndpointEvent> {
    queued(state)
        .into_iter()
        .filter(|e| process(e).is_some_and(|p| pids.contains(&p.pid)))
        .collect()
}
fn lifecycles(events: &[EndpointEvent], pids: &[u32]) -> bool {
    pids.iter().all(|pid| {
        [WindowsProcessChange::Start, WindowsProcessChange::End]
            .iter()
            .all(|change| {
                events
                    .iter()
                    .any(|e| process(e).is_some_and(|p| p.pid == *pid && &p.change == change))
            })
    })
}

fn termination(events: &[EndpointEvent], pid: u32, since_qpc: i64) -> bool {
    events.iter().filter_map(process).any(|event| {
        event.pid == pid
            && event.original.header.timestamp_qpc >= since_qpc
            && event.change == WindowsProcessChange::Terminate
            && event.original.header.descriptor.opcode == 11
            && event.original.header.descriptor.version == 2
            && event.pointer_bits == 64
            && event.original.user_data_hex.len() == 8
            && event.parent_pid.is_none()
            && event.session_id.is_none()
            && event.exit_status.is_none()
            && event.unique_process_key.is_none()
            && event.image_name_bytes_hex.is_none()
            && event.command_line.is_none()
            && event.process_flags.is_none()
            && event.user_sid.is_none()
            && event.package_full_name.is_none()
            && event.application_id.is_none()
    })
}

fn verify_controlled(events: &[EndpointEvent], pids: &[u32]) {
    ensure(
        pids.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == pids.len(),
        "controlled_lifecycle",
    );
    for pid in pids {
        let values: Vec<_> = events
            .iter()
            .filter_map(process)
            .filter(|event| event.pid == *pid)
            .collect();
        let starts: Vec<_> = values
            .iter()
            .filter(|event| event.change == WindowsProcessChange::Start)
            .collect();
        let ends: Vec<_> = values
            .iter()
            .filter(|event| event.change == WindowsProcessChange::End)
            .collect();
        ensure(starts.len() == 1 && ends.len() == 1, "controlled_lifecycle");
        let start = starts[0];
        let end = ends[0];
        ensure(
            start.parent_pid == Some(std::process::id())
                && end.parent_pid == start.parent_pid
                && start.session_id == Some(0)
                && end.session_id == Some(0)
                && end.exit_status == Some(23)
                && start.unique_process_key == end.unique_process_key
                && start.original.header.timestamp_qpc <= end.original.header.timestamp_qpc,
            "controlled_lifecycle",
        );
    }
}

fn component(path: &Path) {
    let mut preexisting = Child::controlled();
    let preexisting_pid = preexisting.0.id();
    let store = safe(Store::open(path), "durable_admission");
    let (_, owned) = safe(prepare(&store), "ownership");
    let mut reader = safe(native::Reader::start(&owned), "source_start");
    ensure(native::recover(&owned).is_err(), "ownership"); // Never reclaim a live owner.
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
    // The mismatched historical owner passes the dead-incarnation branch, but
    // the actual owned logger's different GUID must still prevent reclamation.
    ensure(native::recover(&foreign).is_err(), "ownership");
    ensure(!safe(native::absent(&owned), "ownership"), "ownership");
    let mut children: Vec<_> = (0..4).map(|_| Child::controlled()).collect();
    let pids: Vec<_> = children.iter().map(|child| child.0.id()).collect();
    for child in &mut children {
        child.finish();
    }
    let termination_since = safe(native::clock(), "controlled_lifecycle").after_qpc;
    let mut killed = Child::controlled();
    let killed_pid = killed.0.id();
    ensure(
        !pids.contains(&killed_pid) && killed_pid != preexisting_pid,
        "controlled_lifecycle",
    );
    ensure(
        safe(killed.0.try_wait(), "controlled_lifecycle").is_none(),
        "controlled_lifecycle",
    );
    killed.kill();
    let mut events = Vec::new();
    let mut rundown = false;
    until(
        || {
            safe(reader.check(), "source_stopped");
            for record in reader.batch() {
                // Differential checks use native TDH before portable normalization.
                let report =
                    schema::decode(&record).unwrap_or_else(|error| fail(tdh_failure(error)));
                if pids.contains(&report.pid)
                    || report.pid == preexisting_pid
                    || report.pid == killed_pid
                {
                    let event = safe(
                        WindowsProcessEvent::from_original(
                            record
                                .original(&owned.stream_id, safe(native::clock(), "normalization")),
                        ),
                        "normalization",
                    );
                    differential(&event, &report);
                    if event.pid == preexisting_pid
                        && event.change == WindowsProcessChange::RundownStart
                    {
                        rundown = true;
                    }
                    if pids.contains(&event.pid) && event.change == WindowsProcessChange::End {
                        ensure(event.exit_status == Some(23), "controlled_lifecycle");
                    }
                    events.push(envelope(&event));
                }
            }
            rundown
                && lifecycles(&events, &pids)
                && termination(&events, killed_pid, termination_since)
        },
        "controlled_lifecycle",
    );
    verify_controlled(&events, &pids);
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=rundown_verified");
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=tdh_differential_verified");
    let counters = safe(reader.close(), "cleanup");
    ensure(
        counters.events_lost == 0
            && counters.log_buffers_lost == 0
            && counters.realtime_buffers_lost == 0,
        "native_loss",
    );
    ensure(
        counters.rejected == 0 && counters.callback_drops == 0,
        "callback_loss",
    );
    ensure(safe(native::absent(&owned), "cleanup"), "cleanup");
    preexisting.finish();
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
            let raw:Option<String>=db.query_row("SELECT value FROM telemetry_metadata WHERE key='windows_process_events_session'",[],|r|r.get(0)).optional()?;
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

fn fill(state: &Path, remove: bool) {
    let db = safe(
        rusqlite::Connection::open(state.join("endpoint.sqlite3")),
        "durable_admission",
    );
    safe(db.busy_timeout(Duration::from_secs(5)), "durable_admission");
    let tx = safe(
        rusqlite::Transaction::new_unchecked(&db, rusqlite::TransactionBehavior::Immediate),
        "durable_admission",
    );
    for (table, budget, base) in [
        ("outbox", 3072, 100000),
        ("telemetry_pending", 8192, 200000),
    ] {
        if remove {
            safe(db.execute(&format!("DELETE FROM {table} WHERE json_extract(payload,'$.detail')='controlled process queue fixture'"),[]),"durable_admission");
            continue;
        }
        let count: usize = safe(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)),
            "durable_admission",
        );
        ensure(count <= budget, "durable_admission");
        let missing = budget - count;
        if missing > 0 {
            safe(db.execute(&format!("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO {table} SELECT printf('%064x',x+{base}),json_object('id',printf('%064x',x+{base}),'time_ms',?2,'kind','inventory','path','','sha256','','detection','','detail','controlled process queue fixture','telemetry',NULL) FROM n"),rusqlite::params![missing,crate::now_ms()]),"durable_admission");
        }
    }
    safe(tx.commit(), "durable_admission");
}

#[test]
#[ignore = "Requires an explicitly disposable Windows LocalSystem/session-zero host and the exact staged release agent"]
fn process_lifecycles_replay_with_visible_capture_gaps() {
    guard();
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=guard_verified");
    tdh_rejections_export_only_closed_categories();
    let token_before = safe(token::snapshot(), "ownership");
    ensure(token_before.unimpersonated(), "ownership");
    let exe = PathBuf::from(
        std::env::var_os("ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT")
            .unwrap_or_else(|| fail("configuration")),
    );
    ensure(exe.is_absolute() && exe.is_file(), "configuration");
    let parent = exe.parent().unwrap_or_else(|| fail("configuration"));
    // The runner stages this exact executable under its System/Admin-only ACL.
    // Keep raw records and private state inside that protected tree as well.
    let temp = safe(
        tempfile::Builder::new()
            .prefix("process-events-private-")
            .tempdir_in(parent),
        "configuration",
    );
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(temp.path(), &exe)));
    ensure(
        safe(token::snapshot(), "cleanup") == token_before,
        "cleanup",
    );
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=cleanup_verified");
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=passed");
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
            serde_json::json!({"server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":null,"scanner":temp.join("absent-scanner"),"updater":temp.join("absent-updater"),"scan_roots":[temp],"allow_scripts":false,"telemetry":{"enabled":true,"interval_secs":30,"windows_process_events":true}}),
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
            && read_metadata::<SessionIntent>(&state, "windows_process_events_session").is_none(),
        "configuration",
    );
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=agent_config_verified");
    let mut agent = Agent::start(exe, &state);
    until(
        || {
            agent.alive();
            status(&state).is_some_and(|h| h.healthy(crate::now_ms()))
        },
        "source_start",
    );
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=source_ready");
    let heartbeat_deadline = Instant::now() + Duration::from_secs(40);
    let held = loop {
        ensure(Instant::now() < heartbeat_deadline, "timeout");
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                agent.alive();
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => fail("transport"),
        }
    };
    // No HTTP response has been sent. The collector runs independently.
    let mut children: Vec<_> = (0..4).map(|_| Child::controlled()).collect();
    let pids: Vec<_> = children.iter().map(|c| c.0.id()).collect();
    for child in &mut children {
        child.finish();
    }
    let termination_since = safe(native::clock(), "controlled_lifecycle").after_qpc;
    let mut killed = Child::controlled();
    let killed_pid = killed.0.id();
    ensure(!pids.contains(&killed_pid), "controlled_lifecycle");
    ensure(
        safe(killed.0.try_wait(), "controlled_lifecycle").is_none(),
        "controlled_lifecycle",
    );
    killed.kill();
    let mut all_pids = pids.clone();
    all_pids.push(killed_pid);
    until(
        || {
            agent.alive();
            let records = controlled(&state, &all_pids);
            lifecycles(&records, &pids) && termination(&records, killed_pid, termination_since)
        },
        "controlled_lifecycle",
    );
    let selected = controlled(&state, &all_pids);
    verify_controlled(&selected, &pids);
    ensure(
        status(&state).is_some_and(|h| h.healthy(crate::now_ms())),
        "native_loss",
    );
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=lifecycle_verified");
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=termination_verified");
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=stalled_http_verified");
    fill(&state, false);
    let mut pressure = Child::controlled();
    pressure.finish();
    until(
        || {
            status(&state).is_some_and(|h| {
                h.queue_drops >= 2 && h.backpressured && !h.healthy(crate::now_ms())
            })
        },
        "durable_admission",
    );
    ensure(
        !lifecycles(&controlled(&state, &[pressure.0.id()]), &[pressure.0.id()]),
        "durable_admission",
    );
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=queue_loss_verified");
    let original = intent(&state);
    agent.kill();
    ensure(!safe(native::absent(&original), "ownership"), "ownership");
    fill(&state, true);
    agent.restart(exe);
    until(
        || {
            agent.alive();
            status(&state).is_some_and(|h| {
                h.subscriptions >= 2 && h.loss_signals > 0 && !h.healthy(crate::now_ms())
            })
        },
        "ownership",
    );
    let recovered = intent(&state);
    ensure(
        recovered.stream_id != original.stream_id && recovered.owner_pid != original.owner_pid,
        "ownership",
    );
    let after = controlled(&state, &all_pids);
    ensure(
        selected.iter().all(|e| {
            after
                .iter()
                .any(|actual| serde_json::to_value(actual).ok() == serde_json::to_value(e).ok())
        }),
        "replay",
    );
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=crash_replay_verified");
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=orphan_recovered");
    let losses = status(&state).expect("Process status absent").loss_signals;
    safe(native::stop_for_test(&recovered), "source_stopped");
    until(
        || {
            status(&state).is_some_and(|h| {
                h.loss_signals > losses && h.state == "degraded" && !h.healthy(crate::now_ms())
            })
        },
        "source_stopped",
    );
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=session_gap_verified");
    agent.kill();
    ensure(safe(native::absent(&recovered), "cleanup"), "cleanup");
    drop(held);
    transport::deliver(temp, &state, listener, &config, exe, &selected);
    ensure(agent.cleanup(), "cleanup");
}
