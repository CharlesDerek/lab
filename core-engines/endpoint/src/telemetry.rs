//! Bounded native OS snapshots, committed atomically with their durable outbox deltas.
mod authentication;
mod network_events;
mod process_events;
mod windows_authentication;
mod windows_process_events;
#[cfg(all(test, windows))]
mod windows_process_events_probe;
use crate::Process as Command;
use crate::{now_ms, secret, Client, Result, Store};
use athernex_endpoint_protocol::{self as protocol, telemetry::*, EndpointEvent};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::{marker::PhantomData, sync::mpsc, thread, time::Duration};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const MAX_ROWS: usize = 4096;
const MAX_CHANGES: usize = 128;
const TELEMETRY_SPOOL_LIMIT: usize = 3072; // Leave room for malware and action results.
const CAPTURE_HEALTH_MS: u64 = 30_000; // 15-second worker plus bounded database admission.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub linux_process_events: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub linux_authentication: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub windows_authentication: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub windows_process_events: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub linux_network_events: bool,
}
impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 30,
            linux_process_events: false,
            linux_authentication: false,
            windows_authentication: false,
            windows_process_events: false,
            linux_network_events: false,
        }
    }
}
impl TelemetryConfig {
    pub fn validate(&self) -> Result<()> {
        if self.windows_process_events && (!self.enabled || !cfg!(windows)) {
            return Err("Windows process collection requires enabled telemetry on Windows".into());
        }
        if self.windows_authentication && (!self.enabled || !cfg!(windows)) {
            return Err("Windows Security collection requires enabled telemetry on Windows".into());
        }
        if (self.linux_process_events || self.linux_authentication || self.linux_network_events)
            && (!self.enabled || !cfg!(target_os = "linux"))
        {
            return Err("Native event collectors require enabled telemetry on Linux".into());
        }
        if !(1..=3600).contains(&self.interval_secs) {
            return Err("Telemetry interval must be between 1 and 3600 seconds".into());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub observed_ms: u64,
    pub boot_time_secs: u64,
    pub uptime_secs: u64,
    pub processes: Vec<ProcessObservation>,
    pub connections: Vec<ConnectionObservation>,
    pub process_complete: bool,
    pub connection_complete: bool,
    pub error: String,
}

fn refresh(system: &mut System, only_pid: Option<u32>) {
    let ids = [Pid::from_u32(only_pid.unwrap_or_default())];
    let scope = if only_pid.is_some() {
        ProcessesToUpdate::Some(&ids)
    } else {
        ProcessesToUpdate::All
    };
    system.refresh_processes_specifics(
        scope,
        true,
        ProcessRefreshKind::nothing()
            .without_tasks()
            .with_exe(UpdateKind::Always)
            .with_user(UpdateKind::Always),
    );
}
fn observations(system: &System) -> BTreeMap<u32, ProcessObservation> {
    system
        .processes()
        .iter()
        .filter(|(pid, _)| pid.as_u32() != 0)
        .map(|(pid, p)| {
            let parent = p.parent();
            (
                pid.as_u32(),
                ProcessObservation {
                    pid: pid.as_u32(),
                    parent_pid: parent.map(|p| p.as_u32()),
                    started_ms: p.start_time().saturating_mul(1000),
                    parent_started_ms: parent
                        .and_then(|id| system.process(id))
                        .map(|p| p.start_time().saturating_mul(1000))
                        .filter(|s| *s != 0),
                    name: p.name().to_string_lossy().into_owned(),
                    executable: p.exe().map(|p| p.to_string_lossy().into_owned()),
                    user_id: p.user_id().map(|u| u.to_string()),
                },
            )
        })
        .collect()
}

/// The optional PID restriction is also used by native fixture tests; no host payload is logged.
pub fn capture_native(only_pid: Option<u32>) -> Result<Snapshot> {
    let observed_ms = now_ms();
    let mut system = System::new();
    refresh(&mut system, only_pid);
    let before = observations(&system);
    let mut process_complete = before.len() <= MAX_ROWS && !before.is_empty();
    let mut processes = Vec::new();
    for p in before.values().take(MAX_ROWS) {
        if p.validate(observed_ms).is_err() {
            process_complete = false;
            continue;
        }
        processes.push(p.clone());
    }
    let pids: Vec<u32> = before.keys().copied().collect();
    let (sockets, mut connection_complete) =
        crate::telemetry_sockets::capture(&pids, only_pid, MAX_ROWS);
    // Socket ownership is sampled between process snapshots. Do not attach metadata to a
    // PID whose observed start/image/owner changed or disappeared during collection.
    refresh(&mut system, only_pid);
    let after = observations(&system);
    let mut connections = Vec::new();
    for socket in sockets {
        if socket.owners.len() > 64 {
            connection_complete = false;
        }
        let owners: Vec<Option<u32>> = if socket.owners.is_empty() {
            vec![None]
        } else {
            socket
                .owners
                .into_iter()
                .filter(|id| only_pid.is_none_or(|p| p == *id))
                .take(64)
                .map(Some)
                .collect()
        };
        for owner_pid in owners {
            if connections.len() == MAX_ROWS {
                connection_complete = false;
                break;
            }
            let process = owner_pid
                .and_then(|id| before.get(&id).filter(|p| after.get(&id) == Some(*p)))
                .cloned()
                .filter(|p| p.started_ms != 0 && p.validate(observed_ms).is_ok());
            let mut connection = socket.connection.clone();
            connection.owner_pid = owner_pid;
            connection.process = process;
            if connection.validate(observed_ms).is_ok() {
                connections.push(connection);
            } else {
                connection_complete = false;
            }
        }
    }
    let error = if process_complete && connection_complete {
        String::new()
    } else {
        "Snapshot incomplete: native collection failed or exceeded record/field budgets".into()
    };
    Ok(Snapshot {
        observed_ms,
        boot_time_secs: System::boot_time(),
        uptime_secs: System::uptime(),
        processes,
        connections,
        process_complete,
        connection_complete,
        error,
    })
}

#[derive(Serialize, Deserialize)]
struct Boot {
    id: String,
    time: u64,
    uptime: u64,
}

fn metadata<T: for<'a> Deserialize<'a>>(store: &Store, key: &str) -> Result<Option<T>> {
    let raw: Option<String> = store
        .connection
        .query_row(
            "SELECT value FROM telemetry_metadata WHERE key=?1",
            [key],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|s| serde_json::from_str(&s)).transpose()?)
}
fn set_metadata<T: Serialize>(store: &Store, key: &str, value: &T) -> Result<()> {
    store.connection.execute("INSERT INTO telemetry_metadata VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,serde_json::to_string(value)?])?;
    Ok(())
}
pub fn health(store: &Store, config: &TelemetryConfig) -> Result<CollectorHealth> {
    // Keep the live marker stable while reading its durable record. Otherwise
    // completion between the SQLite read and a liveness check can look like a
    // crashed worker even though the new health already committed successfully.
    let live_capture = store
        .telemetry_capture
        .lock()
        .map_err(|_| "Native collector ownership unavailable")?;
    let pending_changes =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))?;
    if !config.enabled {
        return Ok(CollectorHealth {
            mode: "disabled".into(),
            pending_changes,
            ..Default::default()
        });
    }
    let mut status: CollectorHealth = metadata(store, "health")?.unwrap_or(CollectorHealth {
        mode: "snapshot".into(),
        incomplete: true,
        error: "Awaiting first collection".into(),
        ..Default::default()
    });
    status.pending_changes = pending_changes;
    if status.last_attempt_ms != 0
        && now_ms().saturating_sub(status.last_attempt_ms)
            > (config.interval_secs * 1000).saturating_add(30_000)
    {
        status.incomplete = true;
        status.error = "Native collection is stale; recent activity may be missing".into();
    }
    if let Some(started) = metadata::<u64>(store, "capture_in_progress")? {
        let live = *live_capture == started
            && started != 0
            && started <= now_ms()
            && now_ms().saturating_sub(started) <= CAPTURE_HEALTH_MS;
        status.last_attempt_ms = status.last_attempt_ms.max(started);
        if !live {
            status.incomplete = true;
            status.error =
                "Native collection was interrupted or exceeded its capture deadline".into();
        }
    }
    if status.pending_changes != 0 {
        status.incomplete = true;
        if status.error.is_empty() {
            status.error = if status.pending_changes >= (2 * MAX_ROWS) as u64 {
                "New collection paused: durable telemetry queue is full"
            } else {
                "Durable telemetry awaits delivery; sampling continues within queue capacity"
            }
            .into();
        }
    }
    status.process_events = if config.linux_process_events {
        process_events::health(store)?
    } else {
        None
    };
    if config.linux_process_events
        && !status
            .process_events
            .as_ref()
            .is_some_and(|h| h.healthy(now_ms()))
    {
        status.incomplete = true;
        status.error = status
            .process_events
            .as_ref()
            .map(|h| h.error.clone())
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| "Native process-event subscription is unavailable or stale".into());
    }
    status.authentication = if config.linux_authentication {
        authentication::health(store)?
    } else {
        None
    };
    if config.linux_authentication
        && !status
            .authentication
            .as_ref()
            .is_some_and(|h| h.healthy(now_ms()))
    {
        status.incomplete = true;
        status.error = status
            .authentication
            .as_ref()
            .map(|h| h.error.clone())
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| {
                "Authentication collector is unavailable, stale or catching up".into()
            });
    }
    status.windows_authentication = if config.windows_authentication {
        windows_authentication::health(store)?
    } else {
        None
    };
    if config.windows_authentication
        && !status
            .windows_authentication
            .as_ref()
            .is_some_and(|h| h.healthy(now_ms()))
    {
        status.incomplete = true;
        status.error = status
            .windows_authentication
            .as_ref()
            .map(|h| h.error.clone())
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| {
                "Windows Security collector is unavailable, stale or catching up".into()
            });
    }
    status.windows_process_events = if config.windows_process_events {
        windows_process_events::health(store)?
    } else {
        None
    };
    if config.windows_process_events
        && !status
            .windows_process_events
            .as_ref()
            .is_some_and(|h| h.healthy(now_ms()))
    {
        status.incomplete = true;
        status.error = status
            .windows_process_events
            .as_ref()
            .map(|h| h.error.clone())
            .filter(|error| !error.is_empty())
            .unwrap_or_else(|| {
                "Windows process collection is unavailable, stale or has a coverage gap".into()
            });
    }
    status.network_events = if config.linux_network_events {
        network_events::health(store)?
    } else {
        None
    };
    if config.linux_network_events
        && !status
            .network_events
            .as_ref()
            .is_some_and(|h| h.healthy(now_ms()))
    {
        status.incomplete = true;
        status.error = status
            .network_events
            .as_ref()
            .map(|h| h.error.clone())
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| {
                "Network-event subscription or tracking source is unavailable or stale".into()
            });
    }
    Ok(status)
}

fn item_key(item: &Telemetry) -> Result<String> {
    let identity = match item {
        Telemetry::NetworkEvent { .. }
        | Telemetry::ProcessEvent { .. }
        | Telemetry::WindowsAuthentication { .. }
        | Telemetry::WindowsProcessEvent { .. }
        | Telemetry::Authentication { .. } => {
            return Err("Kernel events must not enter the snapshot comparison cache".into())
        }
        Telemetry::Process { boot_id, process } => {
            serde_json::json!(["process", boot_id, process.pid, process.started_ms])
        }
        Telemetry::Connection {
            boot_id,
            connection,
        } => serde_json::json!([
            "connection",
            boot_id,
            connection.protocol,
            connection.local,
            connection.remote,
            connection.owner_pid,
            connection.process.as_ref().map(|p| p.started_ms)
        ]),
    };
    Ok(protocol::hash(&serde_json::to_vec(&identity)?))
}

/// Every admitted change is preserved with its original timestamp before its cursor advances.
/// Snapshot admission is atomic; delivery moves records into the outbound spool separately.
pub fn commit_snapshot(store: &Store, snapshot: &Snapshot) -> Result<CollectorHealth> {
    let now = now_ms();
    if snapshot.observed_ms > now.saturating_add(60_000)
        || snapshot.boot_time_secs == 0
        || snapshot.processes.len() > MAX_ROWS
        || snapshot.connections.len() > MAX_ROWS
        || snapshot.error.len() > 512
    {
        return Err("Invalid native snapshot".into());
    }
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    let previous: Option<Boot> = metadata(store, "boot")?;
    // Windows boot-time calculation can round across a second. Persist one identity
    // while uptime advances and the boot anchor stays within that tolerance.
    let boot = match previous {
        Some(mut p)
            if p.time.abs_diff(snapshot.boot_time_secs) <= 2
                && p.uptime <= snapshot.uptime_secs =>
        {
            p.uptime = snapshot.uptime_secs;
            p
        }
        _ => Boot {
            id: secret()?,
            time: snapshot.boot_time_secs,
            uptime: snapshot.uptime_secs,
        },
    };
    set_metadata(store, "boot", &boot)?;
    let mut rows = BTreeMap::new();
    for process in &snapshot.processes {
        let item = Telemetry::Process {
            boot_id: boot.id.clone(),
            process: process.clone(),
        };
        item.validate(snapshot.observed_ms)?;
        rows.insert(item_key(&item)?, item);
    }
    for connection in &snapshot.connections {
        let item = Telemetry::Connection {
            boot_id: boot.id.clone(),
            connection: connection.clone(),
        };
        item.validate(snapshot.observed_ms)?;
        rows.insert(item_key(&item)?, item);
    }
    let mut pending: usize =
        tx.query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))?;
    let existing: BTreeMap<String, (String, String)> = tx
        .prepare("SELECT key,domain,hash FROM telemetry_seen")?
        .query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?
        .collect::<std::result::Result<_, _>>()?;
    // This is a comparison cache, not an inventory of running processes. Evict
    // unseen keys even for partial samples so permission gaps cannot fill the
    // cache permanently. No exit/close event is inferred; a later reappearance
    // is simply another observed snapshot, with its own timestamp.
    for key in existing.keys() {
        if !rows.contains_key(key) {
            tx.execute("DELETE FROM telemetry_seen WHERE key=?1", [key])?;
        }
    }
    let mut cache_size: usize =
        tx.query_row("SELECT count(*) FROM telemetry_seen", [], |r| r.get(0))?;
    for (key, item) in rows {
        let digest = protocol::hash(&serde_json::to_vec(&item)?);
        if existing.get(&key).is_some_and(|(_, h)| *h == digest) {
            continue;
        }
        if pending >= 2 * MAX_ROWS || (cache_size >= 2 * MAX_ROWS && !existing.contains_key(&key)) {
            return Err(
                "Native snapshot admission capacity reached; no change cursor advanced".into(),
            );
        }
        let event = EndpointEvent {
            id: secret()?,
            time_ms: snapshot.observed_ms,
            kind: item.kind().into(),
            path: item
                .process()
                .and_then(|p| p.executable.clone())
                .unwrap_or_default(),
            sha256: String::new(),
            detection: String::new(),
            detail:
                "Native OS snapshot observation; short-lived activity between samples may be missed"
                    .into(),
            telemetry: Some(item.clone()),
        };
        event.validate(now)?;
        tx.execute(
            "INSERT INTO telemetry_pending VALUES(?1,?2)",
            params![event.id, serde_json::to_string(&event)?],
        )?;
        tx.execute("INSERT INTO telemetry_seen VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET hash=excluded.hash", params![key,item.kind(),digest])?;
        if !existing.contains_key(&key) {
            cache_size += 1;
        }
        pending += 1;
    }
    let previous: Option<CollectorHealth> = metadata(store, "health")?;
    let status = CollectorHealth {
        network_events: None,
        process_events: None,
        authentication: None,
        windows_authentication: None,
        windows_process_events: None,
        mode: "snapshot".into(),
        last_attempt_ms: now,
        last_success_ms: if snapshot.process_complete && snapshot.connection_complete {
            snapshot.observed_ms
        } else {
            previous.map_or(0, |p| p.last_success_ms)
        },
        process_count: snapshot.processes.len() as u64,
        connection_count: snapshot.connections.len() as u64,
        pending_changes: 0,
        incomplete: !snapshot.process_complete || !snapshot.connection_complete,
        error: snapshot.error.clone(),
    };
    set_metadata(store, "health", &status)?;
    store.connection.execute(
        "DELETE FROM telemetry_metadata WHERE key='capture_in_progress'",
        [],
    )?;
    // Publish health, cursors and the initial transfer together. A heartbeat
    // must not see a transient pending queue from an otherwise admitted sample.
    drain_pending_in_transaction(store)?;
    tx.commit()?;
    health(
        store,
        &TelemetryConfig {
            enabled: true,
            ..Default::default()
        },
    )
}

pub fn drain_pending(store: &Store) -> Result<usize> {
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    let count = drain_pending_in_transaction(store)?;
    tx.commit()?;
    Ok(count)
}

fn drain_pending_in_transaction(store: &Store) -> Result<usize> {
    let count: usize = store
        .connection
        .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))?;
    let capacity = TELEMETRY_SPOOL_LIMIT.saturating_sub(count).min(MAX_CHANGES);
    let rows = store
        .connection
        .prepare("SELECT id,payload FROM telemetry_pending ORDER BY rowid LIMIT ?1")?
        .query_map([capacity], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (id, raw) in &rows {
        let event: EndpointEvent = serde_json::from_str(raw)?;
        store.enqueue(&event)?;
        store
            .connection
            .execute("DELETE FROM telemetry_pending WHERE id=?1", [id])?;
    }
    Ok(rows.len())
}

impl Client {
    pub fn collect_telemetry(&self, store: &Store) -> Result<()> {
        collect(store, &self.config.telemetry, capture_worker)
    }
}

fn capture_worker() -> Result<Snapshot> {
    let (code, output) = crate::run_bounded_with_limit(
        Command::new(std::env::current_exe()?).arg("capture-telemetry"),
        15,
        8 * 1024 * 1024,
    )?;
    if code != 0 {
        return Err("Native telemetry worker failed".into());
    }
    Ok(serde_json::from_str(&output)?)
}

struct CaptureGuard<'a>(&'a Mutex<u64>);
impl Drop for CaptureGuard<'_> {
    fn drop(&mut self) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = 0;
    }
}

fn collect(
    store: &Store,
    policy: &TelemetryConfig,
    capture: impl FnOnce() -> Result<Snapshot>,
) -> Result<()> {
    // Disabling new collection must not strand observations already committed.
    drain_pending(store)?;
    if !policy.enabled {
        return Ok(());
    }
    let mut status = health(store, policy)?;
    // Retained changes do not stall fresh samples while the bounded pending
    // queue has room. Admission remains atomic: a sample that does not fit
    // cannot advance the comparison cursor or overwrite earlier observations.
    if status.pending_changes >= (2 * MAX_ROWS) as u64 {
        return Ok(());
    }
    if now_ms().saturating_sub(status.last_attempt_ms) < policy.interval_secs * 1000 {
        return Ok(());
    }
    status.last_attempt_ms = now_ms();
    {
        let mut live = store
            .telemetry_capture
            .lock()
            .map_err(|_| "Native collector ownership unavailable")?;
        if *live != 0 {
            return Err("A native capture is already running".into());
        }
        *live = status.last_attempt_ms;
    }
    let _capture_guard = CaptureGuard(&store.telemetry_capture);
    set_metadata(store, "capture_in_progress", &status.last_attempt_ms)?;
    let result = (|| -> Result<()> {
        let snapshot = capture()?;
        commit_snapshot(store, &snapshot)?;
        Ok(())
    })();
    if let Err(error) = &result {
        status.incomplete = true;
        status.error = error.to_string().chars().take(120).collect();
        let tx = rusqlite::Transaction::new_unchecked(
            &store.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        set_metadata(store, "health", &status)?;
        store.connection.execute(
            "DELETE FROM telemetry_metadata WHERE key='capture_in_progress'",
            [],
        )?;
        tx.commit()?;
    }
    result
}

/// Continuously schedules bounded samples independently of network calls and
/// endpoint actions. Samples remain snapshots, not lossless OS execution events.
/// The lifetime prevents releasing the process lock while the collector writes.
pub struct ContinuousCollector<'a> {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
    events: Option<process_events::Collector<'a>>,
    authentication: Option<authentication::Collector<'a>>,
    windows_authentication: Option<windows_authentication::Collector<'a>>,
    windows_process_events: Option<windows_process_events::Collector<'a>>,
    network: Option<network_events::Collector<'a>>,
    owner: PhantomData<&'a Store>,
}
impl<'a> ContinuousCollector<'a> {
    pub fn start(store: &'a Store, policy: &TelemetryConfig) -> Result<Self> {
        Self::start_with(store, policy, capture_worker)
    }

    fn start_with(
        store: &'a Store,
        policy: &TelemetryConfig,
        mut capture: impl FnMut() -> Result<Snapshot> + Send + 'static,
    ) -> Result<Self> {
        policy.validate()?;
        let network = if policy.linux_network_events {
            Some(network_events::Collector::start(store)?)
        } else {
            None
        };
        let authentication = if policy.linux_authentication {
            Some(authentication::Collector::start(store)?)
        } else {
            None
        };
        let windows_authentication = if policy.windows_authentication {
            Some(windows_authentication::Collector::start(store)?)
        } else {
            None
        };
        let windows_process_events = if policy.windows_process_events {
            Some(windows_process_events::Collector::start(store)?)
        } else {
            None
        };
        let events = if policy.linux_process_events {
            Some(process_events::Collector::start(store)?)
        } else {
            None
        };
        let store = store.collector_connection()?;
        let policy = policy.clone();
        let (stop, receive) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("endpoint-telemetry".into())
            .spawn(move || loop {
                if let Err(error) = collect(&store, &policy, &mut capture) {
                    eprintln!("Endpoint telemetry: {error}");
                }
                match receive.recv_timeout(Duration::from_secs(1)) {
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                    _ => break,
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            events,
            authentication,
            windows_authentication,
            windows_process_events,
            network,
            owner: PhantomData,
        })
    }

    pub fn check(&self) -> Result<()> {
        if let Some(network) = &self.network {
            network.check()?;
        }
        if let Some(authentication) = &self.authentication {
            authentication.check()?;
        }
        if let Some(authentication) = &self.windows_authentication {
            authentication.check()?;
        }
        if let Some(events) = &self.events {
            events.check()?;
        }
        if let Some(events) = &self.windows_process_events {
            events.check()?;
        }
        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
            return Err("Endpoint telemetry worker stopped unexpectedly".into());
        }
        Ok(())
    }
}
impl Drop for ContinuousCollector<'_> {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(count: u32) -> Snapshot {
        let now = now_ms();
        Snapshot {
            observed_ms: now,
            boot_time_secs: (now - 60_000) / 1000,
            uptime_secs: 60,
            processes: (1..=count)
                .map(|pid| ProcessObservation {
                    pid,
                    parent_pid: None,
                    started_ms: now - 30_000,
                    parent_started_ms: None,
                    name: "fixture".into(),
                    executable: Some("/public/fixture".into()),
                    user_id: Some("1000".into()),
                })
                .collect(),
            connections: vec![],
            process_complete: true,
            connection_complete: true,
            error: String::new(),
        }
    }
    #[test]
    fn live_capture_keeps_completed_health_until_atomic_admission() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let observer = store.collector_connection().unwrap();
        let policy = TelemetryConfig {
            enabled: true,
            interval_secs: 1,
            ..Default::default()
        };
        collect(&store, &policy, || {
            let first = health(&observer, &policy).unwrap();
            assert!(
                first.incomplete,
                "A first capture has no completed result yet"
            );
            assert_eq!(first.last_success_ms, 0);
            Ok(fixture(1))
        })
        .unwrap();
        let mut prior = health(&store, &policy).unwrap();
        prior.last_attempt_ms = now_ms() - 2000;
        set_metadata(&store, "health", &prior).unwrap();
        collect(&store, &policy, || {
            let during = health(&observer, &policy).unwrap();
            assert!(
                !during.incomplete,
                "A live sample is not a collection failure"
            );
            assert!(during.error.is_empty());
            assert_eq!(during.last_success_ms, prior.last_success_ms);
            assert_eq!(during.process_count, 1);
            Ok(fixture(2))
        })
        .unwrap();
        let completed = health(&observer, &policy).unwrap();
        assert!(!completed.incomplete);
        assert_eq!(completed.process_count, 2);
        assert_eq!(completed.pending_changes, 0);
        assert_eq!(*store.telemetry_capture.lock().unwrap(), 0);
        assert!(metadata::<u64>(&store, "capture_in_progress")
            .unwrap()
            .is_none());
    }

    #[test]
    fn stalled_panicked_and_reopened_captures_report_incomplete_health() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let policy = TelemetryConfig {
            enabled: true,
            interval_secs: 1,
            ..Default::default()
        };
        let mut prior = commit_snapshot(&store, &fixture(1)).unwrap();
        prior.last_attempt_ms = now_ms() - 2000;
        set_metadata(&store, "health", &prior).unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = collect(&store, &policy, || -> Result<Snapshot> {
                assert!(!health(&store, &policy).unwrap().incomplete);
                let expired = now_ms() - CAPTURE_HEALTH_MS - 1;
                *store.telemetry_capture.lock().unwrap() = expired;
                set_metadata(&store, "capture_in_progress", &expired).unwrap();
                let stalled = health(&store, &policy).unwrap();
                assert!(stalled.incomplete && stalled.error.contains("capture deadline"));
                // Even a recent durable attempt cannot survive loss of its live guard.
                let recent = now_ms();
                *store.telemetry_capture.lock().unwrap() = recent;
                set_metadata(&store, "capture_in_progress", &recent).unwrap();
                panic!("Controlled collector interruption");
            });
        }));
        assert!(panic.is_err());
        let interrupted = health(&store, &policy).unwrap();
        assert!(interrupted.incomplete && interrupted.error.contains("interrupted"));
        assert_eq!(interrupted.last_success_ms, prior.last_success_ms);
        drop(store);
        let reopened = Store::open(dir.path()).unwrap();
        let recovered = health(&reopened, &policy).unwrap();
        assert!(recovered.incomplete && recovered.error.contains("interrupted"));
        assert_eq!(recovered.last_success_ms, prior.last_success_ms);
        assert_eq!(
            reopened
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn failed_snapshot_transfer_preserves_cursor_and_reports_failure() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let policy = TelemetryConfig {
            enabled: true,
            interval_secs: 1,
            ..Default::default()
        };
        let mut prior = commit_snapshot(&store, &fixture(1)).unwrap();
        let previous: String = store
            .connection
            .query_row("SELECT hash FROM telemetry_seen", [], |r| r.get(0))
            .unwrap();
        prior.last_attempt_ms = now_ms() - 2000;
        set_metadata(&store, "health", &prior).unwrap();
        store.connection.execute_batch("CREATE TRIGGER fixture_full BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'controlled admission failure'); END;").unwrap();
        assert!(collect(&store, &policy, || Ok(fixture(2))).is_err());
        let failed = health(&store, &policy).unwrap();
        assert!(failed.incomplete && failed.error.contains("controlled admission failure"));
        assert_eq!(failed.last_success_ms, prior.last_success_ms);
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM telemetry_seen", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT hash FROM telemetry_seen", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            previous
        );
        assert_eq!(failed.pending_changes, 0);
        assert!(metadata::<u64>(&store, "capture_in_progress")
            .unwrap()
            .is_none());
    }

    #[test]
    fn collection_continues_without_management_and_joins_before_owner_release() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (sent, seen) = mpsc::channel();
        let mut generation = 0;
        let collector = ContinuousCollector::start_with(
            &store,
            &TelemetryConfig {
                enabled: true,
                interval_secs: 1,
                ..Default::default()
            },
            move || {
                generation += 1;
                let mut snapshot = fixture(1);
                snapshot.processes[0].pid = generation;
                sent.send(generation).unwrap();
                Ok(snapshot)
            },
        )
        .unwrap();
        assert_eq!(seen.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
        // No Client::cycle or collect_telemetry call occurs on the owner thread.
        assert_eq!(seen.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
        drop(collector);
        assert!(
            Store::open(dir.path()).is_err(),
            "Stopping telemetry must not release the owner lock"
        );
        let count: u64 = store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        drop(store);
        let reopened = Store::open(dir.path()).unwrap();
        let count: u64 = reopened
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2, "Background observations survive owner restart");
    }

    #[test]
    fn stale_collection_is_reported_and_concurrent_outbox_admission_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let config = TelemetryConfig {
            enabled: true,
            interval_secs: 1,
            ..Default::default()
        };
        set_metadata(
            &store,
            "health",
            &CollectorHealth {
                mode: "snapshot".into(),
                last_attempt_ms: now_ms() - 32_000,
                last_success_ms: now_ms() - 32_000,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(health(&store, &config).unwrap().incomplete);
        assert!(health(&store, &config).unwrap().error.contains("stale"));
        store.connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4095) INSERT INTO outbox SELECT printf('%064x',x),'{}' FROM n;").unwrap();
        let second = store.collector_connection().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let other_barrier = barrier.clone();
        let event = EndpointEvent {
            id: secret().unwrap(),
            time_ms: now_ms(),
            kind: "inventory".into(),
            path: String::new(),
            sha256: String::new(),
            detection: String::new(),
            detail: "Concurrent admission fixture".into(),
            telemetry: None,
        };
        let mut other = event.clone();
        other.id = secret().unwrap();
        let worker = thread::spawn(move || {
            other_barrier.wait();
            second.enqueue(&other).is_ok()
        });
        barrier.wait();
        let admitted = store.enqueue(&event).is_ok();
        assert_ne!(admitted, worker.join().unwrap());
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            4096
        );
    }
    #[test]
    fn native_process_and_loopback_socket_are_observed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(address).unwrap();
        let _server = listener.accept().unwrap();
        let pid = std::process::id();
        let snapshot = capture_native(Some(pid)).unwrap();
        assert!(snapshot
            .processes
            .iter()
            .any(|p| p.pid == pid && p.started_ms != 0));
        assert!(snapshot.connections.iter().any(|c| c.owner_pid == Some(pid)
            && c.remote == Some(address)
            && c.process.as_ref().is_some_and(|p| p.pid == pid)));
        assert!(snapshot.processes.iter().all(|p| p.pid == pid));
    }
    #[test]
    fn pending_observations_survive_restart_with_original_time_and_no_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = fixture(260);
        {
            let store = Store::open(dir.path()).unwrap();
            let status = commit_snapshot(&store, &snapshot).unwrap();
            assert_eq!(status.pending_changes, 132);
        }
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(drain_pending(&store).unwrap(), 128);
        assert_eq!(drain_pending(&store).unwrap(), 4);
        commit_snapshot(&store, &snapshot).unwrap();
        let rows: Vec<String> = store
            .connection
            .prepare("SELECT payload FROM outbox")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 260);
        for raw in rows {
            let event: EndpointEvent = serde_json::from_str(&raw).unwrap();
            assert_eq!(event.time_ms, snapshot.observed_ms);
            assert_eq!(event.kind, "process");
        }
    }
    #[test]
    fn delayed_delivery_keeps_collecting_new_processes_until_the_durable_queue_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<3072) INSERT INTO outbox SELECT printf('%064x',x),'{}' FROM n;").unwrap();
        let mut snapshot = fixture(260);
        commit_snapshot(&store, &snapshot).unwrap();
        let mut status: CollectorHealth = metadata(&store, "health").unwrap().unwrap();
        status.last_attempt_ms = now_ms() - 2000;
        set_metadata(&store, "health", &status).unwrap();
        let mut new_process = snapshot.processes[0].clone();
        new_process.pid = 261;
        snapshot.processes.push(new_process);
        collect(
            &store,
            &TelemetryConfig {
                enabled: true,
                interval_secs: 1,
                ..Default::default()
            },
            || Ok(snapshot),
        )
        .unwrap();
        let pending: Vec<String> = store
            .connection
            .prepare("SELECT payload FROM telemetry_pending")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(pending.len(), 261);
        assert!(pending.iter().any(|raw| matches!(serde_json::from_str::<EndpointEvent>(raw).unwrap().telemetry, Some(Telemetry::Process {process,..}) if process.pid==261)));
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            3072
        );
        store.connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 10000 UNION ALL SELECT x+1 FROM n WHERE x<17930) INSERT INTO telemetry_pending SELECT printf('%064x',x),'{}' FROM n;").unwrap();
        assert_eq!(
            health(
                &store,
                &TelemetryConfig {
                    enabled: true,
                    interval_secs: 1,
                    ..Default::default()
                }
            )
            .unwrap()
            .pending_changes,
            8192
        );
        collect(
            &store,
            &TelemetryConfig {
                enabled: true,
                interval_secs: 1,
                ..Default::default()
            },
            || panic!("A full durable queue must pause new capture"),
        )
        .unwrap();
    }
    #[test]
    fn failed_admission_never_advances_cursor_and_spool_reserves_malware_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let snapshot = fixture(1);
        store.connection.execute_batch("CREATE TRIGGER fixture_failure BEFORE INSERT ON telemetry_pending BEGIN SELECT RAISE(ABORT,'fixture disk failure'); END;").unwrap();
        assert!(commit_snapshot(&store, &snapshot).is_err());
        for table in [
            "telemetry_pending",
            "telemetry_seen",
            "telemetry_metadata",
            "outbox",
        ] {
            let count: u64 = store
                .connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0);
        }
        store.connection.execute_batch("DROP TRIGGER fixture_failure; WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<3072) INSERT INTO outbox SELECT printf('%064x',x),'{}' FROM n;").unwrap();
        assert_eq!(
            commit_snapshot(&store, &snapshot).unwrap().pending_changes,
            1
        );
        assert_eq!(drain_pending(&store).unwrap(), 0);
        store.connection.execute("DELETE FROM outbox", []).unwrap();
        assert_eq!(drain_pending(&store).unwrap(), 1);
        commit_snapshot(&store, &snapshot).unwrap();
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn boot_or_process_identity_change_is_a_new_observation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut snapshot = fixture(1);
        commit_snapshot(&store, &snapshot).unwrap();
        snapshot.processes[0].started_ms += 1000;
        commit_snapshot(&store, &snapshot).unwrap();
        snapshot.uptime_secs = 1;
        snapshot.boot_time_secs += 59;
        commit_snapshot(&store, &snapshot).unwrap();
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            3
        );
    }
    #[test]
    fn partial_samples_bound_comparison_cache_without_claiming_exits() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut snapshot = fixture(260);
        snapshot.process_complete = false;
        snapshot.connection_complete = false;
        snapshot.error = "Fixture permission gap".into();
        commit_snapshot(&store, &snapshot).unwrap();
        assert_eq!(
            health(&store, &TelemetryConfig::default())
                .unwrap()
                .pending_changes,
            132
        );
        drain_pending(&store).unwrap();
        drain_pending(&store).unwrap();
        for p in &mut snapshot.processes {
            p.pid += 260;
        }
        commit_snapshot(&store, &snapshot).unwrap();
        let cached: u64 = store
            .connection
            .query_row("SELECT count(*) FROM telemetry_seen", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            cached, 260,
            "Partial coverage cannot retain dead comparison keys forever"
        );
        drain_pending(&store).unwrap();
        drain_pending(&store).unwrap();
        let total: u64 = store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            total, 520,
            "All original observations survive cache eviction; no exit events are invented"
        );
    }
}
