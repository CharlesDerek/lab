//! Real release-agent acceptance on a disposable host; originals remain private.
use super::super::{native, AuthenticationHealth, Checkpoint};
use super::host;
use crate::{Config, Store};
use athernex_endpoint_protocol::{self as protocol, telemetry::Telemetry, EndpointEvent};
use rusqlite::OptionalExtension;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Read,
    net::{TcpListener, TcpStream},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
mod token;
mod transport;
type Result<T> = std::result::Result<T, &'static str>;

fn require(value: bool, message: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(message)
    }
}
fn api(_: &'static str, code: u32) -> Result<()> {
    require(code == 0, "Native token query failed")
}
#[track_caller]
fn fail(category: &'static str) -> ! {
    let category = match category {
        "configuration" | "token" | "policy" | "account" | "source" | "transport" | "original"
        | "backpressure" | "replay" | "policy_gap" | "authorization" | "device_separation"
        | "detection" | "portal" | "cleanup" | "timeout" => category,
        _ => "other",
    };
    println!("\nATHERNEX_AUTH_AGENT_FAILURE={category}");
    panic!("Native authentication agent acceptance gate failed");
}
#[track_caller]
fn ensure(value: bool, category: &'static str) {
    if !value {
        fail(category);
    }
}
#[track_caller]
fn safe<T, E>(value: std::result::Result<T, E>, category: &'static str) -> T {
    value.unwrap_or_else(|_| fail(category))
}
#[track_caller]
fn until(mut condition: impl FnMut() -> bool, category: &'static str) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !condition() {
        ensure(Instant::now() < deadline, category);
        thread::sleep(Duration::from_millis(25));
    }
}
fn connection(state: &Path, writable: bool) -> rusqlite::Connection {
    let flags = if writable {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let db = safe(
        rusqlite::Connection::open_with_flags(state.join("endpoint.sqlite3"), flags),
        "source",
    );
    safe(db.busy_timeout(Duration::from_secs(5)), "source");
    db
}
fn metadata<T: serde::de::DeserializeOwned>(state: &Path, key: &str) -> Option<T> {
    let db = connection(state, false);
    let value: Option<String> = safe(
        db.query_row(
            "SELECT value FROM telemetry_metadata WHERE key=?1",
            [key],
            |r| r.get(0),
        )
        .optional(),
        "source",
    );
    value.map(|raw| safe(serde_json::from_str(&raw), "source"))
}
fn status(state: &Path) -> Option<AuthenticationHealth> {
    metadata(state, "windows_authentication_health")
}
fn checkpoint(state: &Path) -> Vec<u8> {
    let value: Checkpoint =
        metadata(state, "windows_authentication_checkpoint").unwrap_or_else(|| fail("source"));
    safe(serde_json::to_vec(&value), "source")
}
fn queued(state: &Path, account: &str) -> Vec<EndpointEvent> {
    let db = connection(state, false);
    let mut query = safe(
        db.prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending"),
        "source",
    );
    let rows = safe(query.query_map([], |row| row.get::<_, String>(0)), "source");
    let mut found = BTreeMap::new();
    for row in rows {
        let event: EndpointEvent = safe(serde_json::from_str(&safe(row, "source")), "source");
        if matches!(&event.telemetry, Some(Telemetry::WindowsAuthentication { event })
            if event.target_user.as_deref() == Some(account))
        {
            ensure(found.insert(event.id.clone(), event).is_none(), "replay");
        }
    }
    found.into_values().collect()
}
fn same_event(a: &EndpointEvent, b: &EndpointEvent) -> bool {
    safe(serde_json::to_vec(a), "original") == safe(serde_json::to_vec(b), "original")
}
fn verify_originals(events: &[EndpointEvent]) {
    for envelope in events {
        let Some(Telemetry::WindowsAuthentication { event }) = &envelope.telemetry else {
            fail("original")
        };
        ensure(
            safe(native::Reader::original(event.record_id), "original") == event.xml,
            "original",
        );
        ensure(envelope.validate(crate::now_ms()).is_ok(), "original");
    }
}

struct Agent {
    child: Option<std::process::Child>,
    state: PathBuf,
    exe: PathBuf,
    generation: u32,
    log_prefix: String,
    cleanup_ok: Arc<AtomicBool>,
}
impl Agent {
    fn start(exe: &Path, state: &Path, cleanup_ok: Arc<AtomicBool>) -> Self {
        let mut agent = Self {
            child: None,
            state: state.into(),
            exe: exe.into(),
            generation: 0,
            log_prefix: safe(crate::secret(), "configuration"),
            cleanup_ok,
        };
        agent.restart();
        agent
    }
    fn restart(&mut self) {
        ensure(self.child.is_none(), "configuration");
        let log = safe(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.state.join(format!(
                    "agent-{}-{}.private.log",
                    self.log_prefix, self.generation
                ))),
            "configuration",
        );
        self.generation += 1;
        self.child = Some(safe(
            Command::new(&self.exe)
                .arg("run")
                .arg(&self.state)
                .stdin(Stdio::null())
                .stdout(safe(log.try_clone(), "configuration"))
                .stderr(log)
                .spawn(),
            "source",
        ));
    }
    fn alive(&mut self) {
        ensure(
            safe(
                self.child
                    .as_mut()
                    .unwrap_or_else(|| fail("source"))
                    .try_wait(),
                "source",
            )
            .is_none(),
            "source",
        );
    }
    fn stop(&mut self, forced: bool) -> bool {
        let Some(child) = self.child.as_mut() else {
            return !forced;
        };
        match child.try_wait() {
            Ok(Some(_)) if !forced => {
                self.child.take();
                return true;
            }
            Ok(None) => (),
            _ => return false,
        }
        if child.kill().is_err() {
            return false;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let ok = (!forced || !status.success()) && child.wait().is_ok();
                    if ok {
                        self.child.take();
                    }
                    return ok;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                _ => return false,
            }
        }
    }
    fn kill(&mut self) {
        ensure(self.stop(true), "cleanup");
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        if !self.stop(false) {
            self.cleanup_ok.store(false, Ordering::SeqCst);
        }
    }
}

struct Fillers(Vec<(&'static str, String, String)>);
impl Fillers {
    fn insert(state: &Path) -> Self {
        let mut db = connection(state, true);
        let tx = safe(
            db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
            "backpressure",
        );
        let nonce = safe(crate::secret(), "backpressure");
        let mut rows = Vec::new();
        for (table, budget) in [("outbox", 3072usize), ("telemetry_pending", 8192)] {
            let count: usize = safe(
                tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)),
                "backpressure",
            );
            ensure(count <= budget, "backpressure");
            for index in count..budget {
                let id = protocol::hash(format!("{nonce}:{table}:{index}").as_bytes());
                let event = EndpointEvent {
                    id: id.clone(),
                    time_ms: crate::now_ms(),
                    kind: "inventory".into(),
                    path: String::new(),
                    sha256: String::new(),
                    detection: String::new(),
                    detail: "Controlled authentication agent queue fixture".into(),
                    telemetry: None,
                };
                let payload = safe(serde_json::to_string(&event), "backpressure");
                safe(
                    tx.execute(
                        &format!("INSERT INTO {table}(id,payload) VALUES(?1,?2)"),
                        rusqlite::params![id, payload],
                    ),
                    "backpressure",
                );
                rows.push((table, id, payload));
            }
        }
        safe(tx.commit(), "backpressure");
        Self(rows)
    }
    fn remove(self, state: &Path) {
        let mut db = connection(state, true);
        let tx = safe(
            db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
            "backpressure",
        );
        for (table, id, payload) in self.0 {
            ensure(
                safe(
                    tx.execute(
                        &format!("DELETE FROM {table} WHERE id=?1 AND payload=?2"),
                        rusqlite::params![id, payload],
                    ),
                    "backpressure",
                ) == 1,
                "backpressure",
            );
        }
        safe(tx.commit(), "backpressure");
    }
}

fn discard_stalled(listener: &TcpListener) {
    // Called only after the held agent is reaped; discard its unserved retries.
    for _ in 0..256 {
        match listener.accept() {
            Ok((stream, _)) => drop(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(_) => fail("transport"),
        }
    }
    fail("transport");
}
fn stalled(listener: &TcpListener, agent: &mut Agent, config: &Config) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut stream = loop {
        agent.alive();
        ensure(Instant::now() < deadline, "transport");
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
        ensure(bytes.len() < 16_384, "transport");
        let mut byte = [0];
        safe(stream.read_exact(&mut byte), "transport");
        bytes.push(byte[0]);
    }
    let headers = safe(std::str::from_utf8(&bytes), "transport");
    ensure(
        headers.starts_with(&format!(
            "POST /api/endpoint/{}/heartbeat ",
            config.endpoint_id
        )),
        "transport",
    );
    ensure(
        headers.lines().any(|line| {
            line.eq_ignore_ascii_case(&format!("authorization: Bearer {}", config.credential))
        }),
        "transport",
    );
    stream
}

#[test]
#[ignore = "Requires an explicitly disposable native LocalSystem/session-zero host and exact staged release agent; temporarily changes audit policy and creates one owned account"]
fn release_agent_logon_delivery_replays_and_reports_policy_gaps() {
    host::require_disposable_for(host::Suite::Agent);
    let before = safe(token::snapshot(), "token");
    ensure(before.unimpersonated(), "token");
    let current = safe(std::env::current_exe(), "configuration");
    let parent = current.parent().unwrap_or_else(|| fail("configuration"));
    ensure(
        current
            .file_name()
            .is_some_and(|name| name == "endpoint-tests.exe"),
        "configuration",
    );
    let directory = safe(
        athernex_endpoint_native::windows_state::Directory::open(parent),
        "configuration",
    );
    safe(directory.require_service_access(), "configuration");
    let exe = PathBuf::from(
        std::env::var_os("ATHERNEX_NATIVE_AUTHENTICATION_AGENT")
            .unwrap_or_else(|| fail("configuration")),
    );
    ensure(
        exe.is_absolute()
            && safe(std::fs::canonicalize(&exe), "configuration")
                == safe(
                    std::fs::canonicalize(parent.join("agent.exe")),
                    "configuration",
                ),
        "configuration",
    );
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
        manifest["suite"] == "AuthenticationAgent"
            && manifest["sha256"]["agent.exe"].as_str()
                == Some(protocol::hash(&executable).as_str()),
        "configuration",
    );
    drop(executable);
    let temp = safe(
        tempfile::Builder::new()
            .prefix("authentication-agent-private-")
            .tempdir_in(parent),
        "configuration",
    );
    let cleanup_ok = Arc::new(AtomicBool::new(true));
    println!("\nATHERNEX_AUTH_AGENT_STAGE=guard_verified");
    let mut policy = None;
    let mut account = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        host::verify_privilege_scope();
        policy = Some(host::Policy::start_for(host::Suite::Agent));
        println!("\nATHERNEX_AUTH_AGENT_STAGE=policy_ready");
        account = Some(host::Account::create_for(host::Suite::Agent));
        println!("\nATHERNEX_AUTH_AGENT_STAGE=account_ready");
        run(
            temp.path(),
            &exe,
            policy.as_ref().unwrap(),
            account.as_ref().unwrap(),
            cleanup_ok.clone(),
        );
    }));
    let removed = account.as_mut().is_none_or(|account| account.remove());
    let restored = policy.as_mut().is_none_or(|policy| policy.restore());
    let token_restored = token::snapshot().is_ok_and(|after| after == before);
    ensure(
        removed && restored && token_restored && cleanup_ok.load(Ordering::SeqCst),
        "cleanup",
    );
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    println!("\nATHERNEX_AUTH_AGENT_STAGE=cleanup_verified");
    println!("\nATHERNEX_AUTH_AGENT_STAGE=passed");
}

fn run(
    temp: &Path,
    exe: &Path,
    policy: &host::Policy,
    account: &host::Account,
    cleanup_ok: Arc<AtomicBool>,
) {
    let state = temp.join("agent");
    drop(safe(Store::open(&state), "configuration"));
    let listener = safe(TcpListener::bind("127.0.0.1:0"), "transport");
    safe(listener.set_nonblocking(true), "transport");
    let address = safe(listener.local_addr(), "transport");
    let config: Config = safe(
        serde_json::from_value(serde_json::json!({
        "server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":null,
        "scanner":temp.join("absent-scanner"),"updater":temp.join("absent-updater"),"scan_roots":[temp],"allow_scripts":false,
        "telemetry":{"enabled":true,"interval_secs":1,"windows_authentication":true}})),
        "configuration",
    );
    safe(config.validate(), "configuration");
    safe(
        crate::private_write(
            &state.join("config.json"),
            &safe(serde_json::to_vec(&config), "configuration"),
        ),
        "configuration",
    );
    println!("\nATHERNEX_AUTH_AGENT_STAGE=agent_config_verified");
    let mut agent = Agent::start(exe, &state, cleanup_ok.clone());
    let held = stalled(&listener, &mut agent, &config);
    until(
        || {
            agent.alive();
            status(&state).is_some_and(|h| h.healthy(crate::now_ms()))
        },
        "source",
    );
    println!("\nATHERNEX_AUTH_AGENT_STAGE=source_ready");
    account.attempt(true);
    for _ in 0..8 {
        account.attempt(false);
    }
    until(
        || {
            agent.alive();
            queued(&state, &account.name).len() == 9
        },
        "source",
    );
    let preserved = queued(&state, &account.name);
    ensure(preserved.iter().filter(|e| matches!(&e.telemetry, Some(Telemetry::WindowsAuthentication{event}) if event.event_code==4624)).count()==1, "source");
    ensure(
        preserved
            .iter()
            .filter(|envelope| {
                matches!(&envelope.telemetry,
        Some(Telemetry::WindowsAuthentication {event}) if event.event_code == 4625)
            })
            .count()
            == 8,
        "source",
    );
    verify_originals(&preserved);
    ensure(
        status(&state).is_some_and(|h| h.healthy(crate::now_ms())),
        "source",
    );
    println!("\nATHERNEX_AUTH_AGENT_STAGE=stalled_http_verified");
    println!("\nATHERNEX_AUTH_AGENT_STAGE=originals_verified");
    agent.kill();
    drop(held);
    discard_stalled(&listener);
    let fillers = Fillers::insert(&state);
    let blocked_checkpoint = checkpoint(&state);
    let received = status(&state)
        .unwrap_or_else(|| fail("source"))
        .received_records;
    account.attempt(false);
    agent.restart();
    let held = stalled(&listener, &mut agent, &config);
    until(
        || {
            agent.alive();
            status(&state).is_some_and(|h| h.backpressure)
        },
        "backpressure",
    );
    thread::sleep(Duration::from_millis(500));
    ensure(
        checkpoint(&state) == blocked_checkpoint
            && status(&state).is_some_and(|h| h.backpressure && h.received_records == received),
        "backpressure",
    );
    ensure(queued(&state, &account.name).len() == 9, "backpressure");
    println!("\nATHERNEX_AUTH_AGENT_STAGE=backpressure_verified");
    agent.kill();
    drop(held);
    discard_stalled(&listener);
    fillers.remove(&state);
    agent.restart();
    let held = stalled(&listener, &mut agent, &config);
    until(
        || {
            agent.alive();
            queued(&state, &account.name).len() == 10
                && status(&state).is_some_and(|h| h.healthy(crate::now_ms()))
        },
        "replay",
    );
    let before_crash = queued(&state, &account.name);
    ensure(
        preserved.iter().all(|expected| {
            before_crash
                .iter()
                .any(|actual| same_event(expected, actual))
        }),
        "backpressure",
    );
    agent.kill();
    drop(held);
    discard_stalled(&listener);
    account.attempt(false);
    agent.restart();
    let held = stalled(&listener, &mut agent, &config);
    until(
        || {
            agent.alive();
            queued(&state, &account.name).len() == 11
                && status(&state).is_some_and(|h| h.healthy(crate::now_ms()))
        },
        "replay",
    );
    let after = queued(&state, &account.name);
    ensure(
        before_crash
            .iter()
            .all(|expected| after.iter().any(|actual| same_event(expected, actual))),
        "replay",
    );
    verify_originals(&after);
    println!("\nATHERNEX_AUTH_AGENT_STAGE=crash_replay_verified");
    policy.set_logon(1);
    until(
        || {
            agent.alive();
            status(&state).is_some_and(|h| h.loss_signals > 0 && !h.healthy(crate::now_ms()))
        },
        "policy_gap",
    );
    policy.set_logon(3);
    account.attempt(false);
    until(
        || {
            agent.alive();
            queued(&state, &account.name).len() == 12
        },
        "policy_gap",
    );
    ensure(
        status(&state).is_some_and(|h| h.loss_signals > 0 && !h.healthy(crate::now_ms())),
        "policy_gap",
    );
    println!("\nATHERNEX_AUTH_AGENT_STAGE=policy_gap_verified");
    agent.kill();
    drop(held);
    discard_stalled(&listener);
    let selected = queued(&state, &account.name);
    ensure(
        selected.len() == 12
            && selected
                .iter()
                .filter(|envelope| {
                    matches!(&envelope.telemetry,
        Some(Telemetry::WindowsAuthentication {event}) if event.event_code == 4624)
                })
                .count()
                == 1
            && selected
                .iter()
                .filter(|envelope| {
                    matches!(&envelope.telemetry,
        Some(Telemetry::WindowsAuthentication {event}) if event.event_code == 4625)
                })
                .count()
                == 11,
        "source",
    );
    verify_originals(&selected);
    let mut reader = safe(native::Reader::open(), "original");
    let (mut altered, _) = safe(reader.baseline(), "original");
    altered.anchor_sha256 = "0".repeat(64);
    ensure(
        safe(reader.batch(&altered), "original").loss_signals > 0,
        "original",
    );
    println!("\nATHERNEX_AUTH_AGENT_STAGE=bookmark_anchor_verified");
    transport::deliver(temp, &state, listener, &config, exe, &selected, cleanup_ok);
}
