//! Opt-in system journal authentication collection with transactional cursor admission.
#[cfg(all(test, target_os = "linux"))]
mod certificate_test;
#[cfg(target_os = "linux")]
mod journal_service;
#[cfg(all(test, target_os = "linux"))]
mod keyboard_interactive_test;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(test, target_os = "linux"))]
mod native_test;
#[cfg(all(test, target_os = "linux"))]
mod pam_test;
#[cfg(all(test, target_os = "linux"))]
mod sudo_test;
#[cfg(test)]
mod tests;
use super::metadata;
#[cfg(any(target_os = "linux", test))]
use super::{drain_pending_in_transaction, set_metadata, MAX_ROWS};
#[cfg(any(target_os = "linux", test))]
use crate::now_ms;
use crate::{Result, Store};
use athernex_endpoint_protocol::authentication::AuthenticationHealth;
#[cfg(any(target_os = "linux", test))]
use athernex_endpoint_protocol::{
    self as protocol, authentication::Authentication, telemetry::Telemetry, EndpointEvent,
};
#[cfg(any(target_os = "linux", test))]
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, mpsc},
    thread,
};

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    cursor: String,
    sequences: std::collections::BTreeMap<String, u64>,
    cursor_missing: bool,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
struct Batch {
    checkpoint: Checkpoint,
    events: Vec<Authentication>,
    received_records: u64,
    rejected_records: u64,
    loss_signals: u64,
    last_record_ms: u64,
    caught_up: bool,
}
pub(super) fn health(store: &Store) -> Result<Option<AuthenticationHealth>> {
    let mut result: Option<AuthenticationHealth> = metadata(store, "authentication_health")?;
    if let Some(health) = &mut result {
        if !store.authentication_live.load(Ordering::Acquire) {
            health.state = "stopped".into();
            health.error = "Authentication journal worker is not running".into();
        }
    }
    Ok(result)
}
/// A name/message hint can expose missing provenance, never establish a fact.
/// Only the reader's empty-_EXE branch uses this; a known unrelated executable
/// is not promoted by its comm or syslog identifier.
#[cfg(any(target_os = "linux", test))]
fn missing_provenance(comm: &str, message: &str) -> bool {
    if !["sshd", "sshd-session", "sudo", "login", "su"].contains(&comm) {
        return false;
    }
    (message.starts_with("pam_unix(") && message.contains(":auth): authentication failure;"))
        || (["sshd", "sshd-session"].contains(&comm)
            && (message.starts_with("Accepted ") || message.starts_with("Failed "))
            && message.contains(" for "))
        || (comm == "sudo"
            && protocol::authentication::sudo_report(message).is_some_and(|report| {
                matches!(
                    report.outcome,
                    protocol::authentication::SudoOutcome::PasswordDenied { .. }
                )
            }))
}
#[cfg(any(target_os = "linux", test))]
fn envelope(event: &Authentication) -> EndpointEvent {
    EndpointEvent {id:event.event_id(),time_ms:event.journal.realtime_us/1000,kind:"authentication".into(),path:String::new(),sha256:String::new(),detection:String::new(),
        detail:"Authentication reported by a supported journal producer. The claimed account is not an inferred OS UID; source journal provenance is retained.".into(),
        telemetry:Some(Telemetry::Authentication {event:event.clone()})}
}
/// False means the entire batch remains pending in the reader. Neither its
/// cursor nor counters may advance until every selected record is durable.
#[cfg(any(target_os = "linux", test))]
fn persist(store: &Store, health: &mut AuthenticationHealth, batch: &Batch) -> Result<bool> {
    if batch.received_records > 64 || batch.events.len() > 64 {
        return Err("Authentication batch exceeds budget".into());
    }
    let events = batch.events.iter().map(envelope).collect::<Vec<_>>();
    for event in &events {
        event.validate(now_ms())?;
    }
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    drain_pending_in_transaction(store)?;
    let pending: usize =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))?;
    let admitted = pending + events.len() <= 2 * MAX_ROWS;
    let mut next = health.clone();
    next.checked_ms = now_ms();
    next.backpressure = !admitted;
    if admitted {
        for event in events {
            store.connection.execute(
                "INSERT INTO telemetry_pending VALUES(?1,?2)",
                rusqlite::params![event.id, serde_json::to_string(&event)?],
            )?;
        }
        next.received_records = next.received_records.saturating_add(batch.received_records);
        next.authentication_events = next
            .authentication_events
            .saturating_add(batch.events.len() as u64);
        next.rejected_records = next.rejected_records.saturating_add(batch.rejected_records);
        next.loss_signals = next.loss_signals.saturating_add(batch.loss_signals);
        if batch.last_record_ms != 0 {
            next.last_record_ms = batch.last_record_ms;
        }
        next.caught_up = batch.caught_up;
        set_metadata(store, "authentication_checkpoint", &batch.checkpoint)?;
        drain_pending_in_transaction(store)?;
    }
    next.error=if next.loss_signals>0 || next.rejected_records>0 {"Journal retention, sequence loss or unsupported authentication reports require coverage review"}
        else if next.backpressure {"Authentication collection paused at its durable cursor: delivery queue is full"}
        else {""}.into();
    next.state = if next.error.is_empty() {
        "active"
    } else {
        "degraded"
    }
    .into();
    next.validate()?;
    set_metadata(store, "authentication_health", &next)?;
    tx.commit()?;
    *health = next;
    Ok(admitted)
}

#[cfg(any(target_os = "linux", test))]
fn load_state(store: &Store) -> Result<(AuthenticationHealth, Option<Checkpoint>)> {
    let previous: Option<AuthenticationHealth> = metadata(store, "authentication_health")?;
    let checkpoint: Option<Checkpoint> = metadata(store, "authentication_checkpoint")?;
    if let Some(h) = &previous {
        h.validate()?;
        if h.received_records != 0 && checkpoint.is_none() {
            return Err("Authentication cursor is missing from existing collection history".into());
        }
    } else if checkpoint.is_some() {
        return Err("Authentication health history is missing from its durable cursor".into());
    }
    if let Some(checkpoint) = &checkpoint {
        if checkpoint.cursor.is_empty()
            || checkpoint.cursor.len() > 512
            || checkpoint.cursor.chars().any(char::is_control)
            || checkpoint.sequences.is_empty()
            || checkpoint.sequences.len() > 16
            || checkpoint.sequences.iter().any(|(id, sequence)| {
                id.len() != 32
                    || *sequence == 0
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err("Invalid durable authentication cursor".into());
        }
    }
    let mut health = previous.unwrap_or_default();
    health.state = "starting".into();
    health.checked_ms = now_ms();
    health.caught_up = false;
    if health.started_ms == 0 {
        health.started_ms = now_ms();
    }
    Ok((health, checkpoint))
}

#[cfg(target_os = "linux")]
fn run_worker(
    connection: Store,
    live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    receive: mpsc::Receiver<()>,
    started: mpsc::Sender<std::result::Result<(), String>>,
) {
    struct Live(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Live {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let guard = Live(live);
    let (mut health, previous) = match load_state(&connection) {
        Ok(state) => state,
        Err(error) => {
            let _ = started.send(Err(error.to_string()));
            return;
        }
    };
    let prepare = (|| -> Result<(linux::Reader, Checkpoint)> {
        set_metadata(&connection, "authentication_health", &health)?;
        let mut reader = linux::Reader::open()?;
        let checkpoint = match previous {
            Some(checkpoint) => checkpoint,
            None => {
                let checkpoint = reader.baseline()?;
                health.started_ms = now_ms();
                let detail = serde_json::json!({
                    "authentication_collection": "started",
                    "baseline_cursor_sha256": protocol::hash(checkpoint.cursor.as_bytes()),
                    "coverage": "Earlier journal records are outside this collection window"
                })
                .to_string();
                let boundary = EndpointEvent {
                    id: crate::secret()?,
                    time_ms: health.started_ms,
                    kind: "inventory".into(),
                    path: String::new(),
                    sha256: String::new(),
                    detection: String::new(),
                    telemetry: None,
                    detail,
                };
                let tx = rusqlite::Transaction::new_unchecked(
                    &connection.connection,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                connection.enqueue(&boundary)?;
                set_metadata(&connection, "authentication_checkpoint", &checkpoint)?;
                set_metadata(&connection, "authentication_health", &health)?;
                tx.commit()?;
                checkpoint
            }
        };
        Ok((reader, checkpoint))
    })();
    let (mut reader, mut checkpoint) = match prepare {
        Ok(pair) => pair,
        Err(error) => {
            health.state = "degraded".into();
            health.error = error.to_string().chars().take(256).collect();
            let _ = set_metadata(&connection, "authentication_health", &health);
            let _ = started.send(Err(health.error));
            return;
        }
    };
    guard.0.store(true, Ordering::Release);
    let _ = started.send(Ok(()));
    let result = (|| -> Result<()> {
        let mut pending = None;
        loop {
            match receive.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => (),
            }
            let batch = match pending.take() {
                Some(batch) => batch,
                None => reader.batch(&checkpoint)?,
            };
            let idle = batch.caught_up;
            if persist(&connection, &mut health, &batch)? {
                checkpoint = batch.checkpoint;
            } else {
                pending = Some(batch);
            }
            if idle || pending.is_some() {
                match receive.recv_timeout(std::time::Duration::from_millis(200)) {
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                    _ => break,
                }
            }
        }
        Ok(())
    })();
    health.checked_ms = now_ms();
    match result {
        Ok(()) => health.state = "stopped".into(),
        Err(error) => {
            health.state = "degraded".into();
            health.loss_signals = health.loss_signals.saturating_add(1);
            health.error = error.to_string().chars().take(256).collect();
        }
    }
    if let Err(error) = set_metadata(&connection, "authentication_health", &health) {
        eprintln!("Authentication collector health persistence failed: {error}");
    }
}

pub(super) struct Collector<'a> {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
    owner: PhantomData<&'a Store>,
}
impl<'a> Collector<'a> {
    pub fn start(store: &'a Store) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = store;
            Err("Native authentication journal collection is available only on Linux".into())
        }
        #[cfg(target_os = "linux")]
        {
            let connection = store.collector_connection()?;
            let live = store.authentication_live.clone();
            let (stop, receive) = mpsc::channel();
            let (started, ready) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("endpoint-authentication".into())
                .spawn(move || run_worker(connection, live, receive, started))?;
            let collector = Self {
                stop,
                worker: Some(worker),
                owner: PhantomData,
            };
            ready
                .recv_timeout(std::time::Duration::from_secs(5))?
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(collector)
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
            return Err("Native authentication collector stopped".into());
        }
        Ok(())
    }
}
impl Drop for Collector<'_> {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
