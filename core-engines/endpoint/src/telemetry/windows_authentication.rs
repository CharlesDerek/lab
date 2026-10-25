//! Read-only Windows Security collection with atomic bookmark/outbox admission.
#[cfg(all(test, windows))]
mod diagnostics;
#[cfg(windows)]
mod native;
#[cfg(all(test, windows))]
mod native_test;
#[cfg(test)]
mod tests;
use super::metadata;
#[cfg(any(windows, test))]
use super::{drain_pending_in_transaction, set_metadata, MAX_ROWS};
#[cfg(any(windows, test))]
use crate::now_ms;
use crate::{Result, Store};
use athernex_endpoint_protocol::authentication::AuthenticationHealth;
#[cfg(any(windows, test))]
use athernex_endpoint_protocol::{
    self as protocol, telemetry::Telemetry, windows_authentication::WindowsAuthentication,
    EndpointEvent,
};
#[cfg(any(windows, test))]
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, mpsc},
    thread,
};

#[cfg(any(windows, test))]
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    bookmark: String,
    anchor_sha256: String,
    record_id: u64,
    log_created_filetime: u64,
    policy_healthy: bool,
    cursor_missing: bool,
}
#[cfg(any(windows, test))]
impl Checkpoint {
    fn validate(&self) -> Result<()> {
        if self.bookmark.is_empty()
            || self.bookmark.len() > 4096
            || self.bookmark.contains('\0')
            || self.record_id == 0
            || self.log_created_filetime == 0
            || self.anchor_sha256.len() != 64
            || !self
                .anchor_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Invalid durable Windows Security bookmark".into());
        }
        Ok(())
    }
}
#[cfg(any(windows, test))]
#[derive(Default)]
struct Batch {
    checkpoint: Checkpoint,
    events: Vec<WindowsAuthentication>,
    received_records: u64,
    rejected_records: u64,
    loss_signals: u64,
    last_record_ms: u64,
    caught_up: bool,
    source_error: String,
}
pub(super) fn health(store: &Store) -> Result<Option<AuthenticationHealth>> {
    let mut result: Option<AuthenticationHealth> =
        metadata(store, "windows_authentication_health")?;
    if let Some(health) = &mut result {
        if !store.windows_authentication_live.load(Ordering::Acquire) {
            health.state = "stopped".into();
            health.error = "Windows Security collector is not running".into();
        }
    }
    Ok(result)
}
#[cfg(any(windows, test))]
fn envelope(event: &WindowsAuthentication) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "authentication".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: "Windows Security logon report; original event XML is retained. Reported accounts, caller PID and network fields are not inferred identities or process lineage.".into(),
        telemetry: Some(Telemetry::WindowsAuthentication {
            event: event.clone(),
        }),
    }
}
#[cfg(any(windows, test))]
fn persist(store: &Store, health: &mut AuthenticationHealth, batch: &Batch) -> Result<bool> {
    if batch.received_records > 64
        || (batch.events.len() as u64).saturating_add(batch.rejected_records)
            > batch.received_records
        || batch.source_error.len() > 256
    {
        return Err("Windows Security batch exceeds its record budget".into());
    }
    batch.checkpoint.validate()?;
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
            // Retention recovery may replay an original still waiting for delivery.
            // Accept only the identical envelope; never hide an ID collision.
            let payload = serde_json::to_string(&event)?;
            let existing: Vec<String> = store.connection.prepare(
                "SELECT payload FROM telemetry_pending WHERE id=?1 UNION ALL SELECT payload FROM outbox WHERE id=?1"
            )?.query_map([&event.id], |r| r.get(0))?.collect::<std::result::Result<_,_>>()?;
            if existing.iter().any(|stored| stored != &payload) {
                return Err("Windows Security event ID conflicts with queued evidence".into());
            }
            if !existing.is_empty() {
                continue;
            }
            store.connection.execute(
                "INSERT INTO telemetry_pending VALUES(?1,?2)",
                rusqlite::params![event.id, payload],
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
        set_metadata(
            store,
            "windows_authentication_checkpoint",
            &batch.checkpoint,
        )?;
        drain_pending_in_transaction(store)?;
    }
    next.error = if !batch.source_error.is_empty() {
        batch.source_error.clone()
    } else if next.loss_signals > 0 || next.rejected_records > 0 {
        "Windows Security retention, source-policy gaps or unsupported logon records require coverage review".into()
    } else if !admitted {
        "Windows Security collection paused at its durable bookmark: delivery queue is full".into()
    } else {
        String::new()
    };
    next.state = if next.error.is_empty() {
        "active"
    } else {
        "degraded"
    }
    .into();
    next.validate()?;
    set_metadata(store, "windows_authentication_health", &next)?;
    tx.commit()?;
    *health = next;
    Ok(admitted)
}
#[cfg(any(windows, test))]
fn load_state(store: &Store) -> Result<(AuthenticationHealth, Option<Checkpoint>)> {
    let previous: Option<AuthenticationHealth> = metadata(store, "windows_authentication_health")?;
    let checkpoint: Option<Checkpoint> = metadata(store, "windows_authentication_checkpoint")?;
    if let Some(h) = &previous {
        h.validate()?;
        if h.received_records != 0 && checkpoint.is_none() {
            return Err("Windows Security history has no durable bookmark".into());
        }
    } else if checkpoint.is_some() {
        return Err("Windows Security bookmark has no health history".into());
    }
    if let Some(checkpoint) = &checkpoint {
        checkpoint.validate()?;
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
#[cfg(windows)]
fn run_worker(
    connection: Store,
    live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    receive: mpsc::Receiver<()>,
    started: mpsc::Sender<std::result::Result<(), String>>,
) {
    #[cfg(test)]
    diagnostics::source("worker_entered");
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
            #[cfg(test)]
            {
                diagnostics::source("startup_failed");
                diagnostics::classify(error.as_ref());
            }
            let _ = started.send(Err(error.to_string()));
            return;
        }
    };
    #[cfg(test)]
    diagnostics::source("durable_state_ready");
    let prepared = (|| -> Result<(native::Reader, Checkpoint)> {
        set_metadata(&connection, "windows_authentication_health", &health)?;
        #[cfg(test)]
        diagnostics::source("initial_health_saved");
        let mut reader = native::Reader::open()?;
        #[cfg(test)]
        diagnostics::source("reader_opened");
        let checkpoint = match previous {
            Some(checkpoint) => checkpoint,
            None => {
                let (checkpoint, source_error) = reader.baseline()?;
                health.started_ms = now_ms();
                if !checkpoint.policy_healthy {
                    health.loss_signals = health.loss_signals.saturating_add(1);
                    health.error = source_error;
                }
                let boundary = EndpointEvent {
                    id: crate::secret()?,
                    time_ms: health.started_ms,
                    kind: "inventory".into(),
                    path: String::new(),
                    sha256: String::new(),
                    detection: String::new(),
                    telemetry: None,
                    detail: serde_json::json!({
                        "windows_authentication_collection": "started",
                        "baseline_bookmark_sha256": protocol::hash(checkpoint.bookmark.as_bytes()),
                        "coverage": "Retained Windows Security records after this baseline; earlier records are outside this collection window"
                    }).to_string(),
                };
                let tx = rusqlite::Transaction::new_unchecked(
                    &connection.connection,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                connection.enqueue(&boundary)?;
                set_metadata(
                    &connection,
                    "windows_authentication_checkpoint",
                    &checkpoint,
                )?;
                set_metadata(&connection, "windows_authentication_health", &health)?;
                tx.commit()?;
                #[cfg(test)]
                diagnostics::source("baseline_committed");
                checkpoint
            }
        };
        Ok((reader, checkpoint))
    })();
    let (mut reader, mut checkpoint) = match prepared {
        Ok(pair) => pair,
        Err(error) => {
            #[cfg(test)]
            {
                diagnostics::source("startup_failed");
                diagnostics::classify(error.as_ref());
            }
            health.state = "degraded".into();
            health.error = error.to_string().chars().take(256).collect();
            let _ = set_metadata(&connection, "windows_authentication_health", &health);
            let _ = started.send(Err(health.error));
            return;
        }
    };
    guard.0.store(true, Ordering::Release);
    #[cfg(test)]
    diagnostics::source("worker_ready");
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
            #[cfg(test)]
            {
                diagnostics::source("worker_failed");
                diagnostics::classify(error.as_ref());
            }
            health.state = "degraded".into();
            health.loss_signals = health.loss_signals.saturating_add(1);
            health.error = error.to_string().chars().take(256).collect();
        }
    }
    if let Err(error) = set_metadata(&connection, "windows_authentication_health", &health) {
        eprintln!("Windows Security collector health persistence failed: {error}");
    }
}

pub(super) struct Collector<'a> {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
    owner: PhantomData<&'a Store>,
}
impl<'a> Collector<'a> {
    pub fn start(store: &'a Store) -> Result<Self> {
        #[cfg(not(windows))]
        {
            let _ = store;
            Err("Windows Security collection is available only on Windows".into())
        }
        #[cfg(windows)]
        {
            let connection = store.collector_connection()?;
            #[cfg(test)]
            diagnostics::source("connection_ready");
            let live = store.windows_authentication_live.clone();
            let (stop, receive) = mpsc::channel();
            let (started, ready) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("endpoint-windows-authentication".into())
                .spawn(move || run_worker(connection, live, receive, started))?;
            let collector = Self {
                stop,
                worker: Some(worker),
                owner: PhantomData,
            };
            ready
                .recv_timeout(std::time::Duration::from_secs(5))
                .inspect_err(|error| {
                    #[cfg(test)]
                    diagnostics::source(match error {
                        mpsc::RecvTimeoutError::Timeout => "startup_timeout",
                        mpsc::RecvTimeoutError::Disconnected => "startup_disconnected",
                    });
                    #[cfg(not(test))]
                    let _ = error;
                })?
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(collector)
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
            return Err("Windows Security collector stopped".into());
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
