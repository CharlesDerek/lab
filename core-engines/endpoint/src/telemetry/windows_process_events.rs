//! Opt-in Windows ETW lifecycle reports with durable admission and visible gaps.
#[cfg(windows)]
mod native;
#[cfg(all(test, windows))]
mod native_test;
#[cfg(test)]
mod tests;
use super::metadata;
#[cfg(any(windows, test))]
use super::{drain_pending_in_transaction, set_metadata, MAX_ROWS};
use crate::{Result, Store};
#[cfg(windows)]
use athernex_endpoint_protocol as protocol;
use athernex_endpoint_protocol::windows_process_events::WindowsProcessEventHealth;
#[cfg(any(windows, test))]
use athernex_endpoint_protocol::{
    telemetry::Telemetry, windows_process_events::WindowsProcessEvent, EndpointEvent,
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
struct Counters {
    received: u64,
    rejected: u64,
    callback_drops: u64,
    events_lost: u64,
    log_buffers_lost: u64,
    realtime_buffers_lost: u64,
}
#[cfg(any(windows, test))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionIntent {
    stream_id: String,
    session_name: String,
    session_guid: String,
    owner_pid: u32,
    owner_created: u64,
    phase: String,
    started_ms: u64,
    counters: Counters,
}
#[cfg(any(windows, test))]
impl SessionIntent {
    fn validate(&self, expected_name: &str) -> Result<()> {
        if self.stream_id.len() != 64
            || !self
                .stream_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.session_name != expected_name
            || self.owner_pid <= 4
            || self.owner_created == 0
            || self.started_ms == 0
            || !["prepared", "active", "stopped"].contains(&self.phase.as_str())
        {
            return Err("Invalid durable Windows process session ownership".into());
        }
        let s = &self.stream_id;
        let guid = format!(
            "{{{}-{}-{}-{}-{}}}",
            &s[..8],
            &s[8..12],
            &s[12..16],
            &s[16..20],
            &s[20..32]
        );
        if self.session_guid != guid {
            return Err("Windows process session GUID differs from its intent".into());
        }
        Ok(())
    }
}
pub(super) fn health(store: &Store) -> Result<Option<WindowsProcessEventHealth>> {
    let mut result: Option<WindowsProcessEventHealth> =
        metadata(store, "windows_process_events_health")?;
    if let Some(health) = &mut result {
        if !store.windows_process_events_live.load(Ordering::Acquire) {
            health.state = "stopped".into();
            health.error = "Windows process-event collector is not running".into();
        }
    }
    Ok(result)
}
#[cfg(any(windows, test))]
fn envelope(event: &WindowsProcessEvent) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(), time_ms: event.time_ms, kind: "windows_process_event".into(),
        path: String::new(), sha256: String::new(), detection: String::new(),
        detail: "Windows ETW lifecycle report with exact admitted original bytes. Reported PID, parent PID and kernel object key do not establish verified executable identity, ancestry or a current process incarnation. Live source gaps cannot be replayed.".into(),
        telemetry: Some(Telemetry::WindowsProcessEvent { event: event.clone() }),
    }
}
#[cfg(any(windows, test))]
fn delta(current: u64, previous: u64, losses: &mut u64) -> u64 {
    match current.checked_sub(previous) {
        Some(delta) => delta,
        None => {
            *losses = losses.saturating_add(1);
            current
        }
    }
}
#[cfg(any(windows, test))]
fn persist(
    store: &Store,
    health: &mut WindowsProcessEventHealth,
    intent: &mut SessionIntent,
    events: &[WindowsProcessEvent],
    rejected: u64,
    counters: Counters,
) -> Result<()> {
    if events.len() > 64 || rejected > 64 {
        return Err("Windows process admission exceeds bounded batch size".into());
    }
    let envelopes: Vec<_> = events.iter().map(envelope).collect();
    for event in &envelopes {
        event.validate(crate::now_ms())?;
    }
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    drain_pending_in_transaction(store)?;
    let pending: usize =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |row| {
                row.get(0)
            })?;
    let mut next = health.clone();
    let mut next_intent = intent.clone();
    next.received_records = next.received_records.saturating_add(delta(
        counters.received,
        intent.counters.received,
        &mut next.loss_signals,
    ));
    next.rejected_records = next
        .rejected_records
        .saturating_add(rejected)
        .saturating_add(delta(
            counters.rejected,
            intent.counters.rejected,
            &mut next.loss_signals,
        ));
    next.callback_drops = next.callback_drops.saturating_add(delta(
        counters.callback_drops,
        intent.counters.callback_drops,
        &mut next.loss_signals,
    ));
    next.events_lost = next.events_lost.saturating_add(delta(
        counters.events_lost,
        intent.counters.events_lost,
        &mut next.loss_signals,
    ));
    next.log_buffers_lost = next.log_buffers_lost.saturating_add(delta(
        counters.log_buffers_lost,
        intent.counters.log_buffers_lost,
        &mut next.loss_signals,
    ));
    next.realtime_buffers_lost = next.realtime_buffers_lost.saturating_add(delta(
        counters.realtime_buffers_lost,
        intent.counters.realtime_buffers_lost,
        &mut next.loss_signals,
    ));
    let refused = pending + events.len() > 2 * MAX_ROWS;
    if refused {
        next.queue_drops = next.queue_drops.saturating_add(events.len() as u64);
    } else {
        for event in &envelopes {
            store.connection.execute(
                "INSERT INTO telemetry_pending VALUES(?1,?2)",
                rusqlite::params![event.id, serde_json::to_string(event)?],
            )?;
        }
        next.admitted_records = next.admitted_records.saturating_add(events.len() as u64);
        drain_pending_in_transaction(store)?;
    }
    let final_pending: usize =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |row| {
                row.get(0)
            })?;
    next.backpressured = refused || final_pending >= 2 * MAX_ROWS;
    next.checked_ms = crate::now_ms();
    next.error = if next.loss_signals != 0
        || next.rejected_records != 0
        || next.callback_drops != 0
        || next.queue_drops != 0
        || next.events_lost != 0
        || next.log_buffers_lost != 0
        || next.realtime_buffers_lost != 0
    {
        "Windows process capture has a persistent source, restart, decoding or queue gap; live ETW records cannot be replayed".into()
    } else if next.backpressured {
        "Windows process delivery queue is full".into()
    } else {
        String::new()
    };
    next.state = if next.error.is_empty() {
        "active"
    } else {
        "degraded"
    }
    .into();
    next_intent.counters = counters;
    next.validate()?;
    set_metadata(store, "windows_process_events_health", &next)?;
    set_metadata(store, "windows_process_events_session", &next_intent)?;
    tx.commit()?;
    *health = next;
    *intent = next_intent;
    Ok(())
}
#[cfg(windows)]
fn prepare(store: &Store) -> Result<(WindowsProcessEventHealth, SessionIntent)> {
    let name = native::session_name(&store.directory)?;
    let previous: Option<SessionIntent> = metadata(store, "windows_process_events_session")?;
    let prior: Option<WindowsProcessEventHealth> =
        metadata(store, "windows_process_events_health")?;
    if previous.is_some() != prior.is_some() {
        return Err("Windows process session and health history differ".into());
    }
    if let Some(previous) = &previous {
        previous.validate(&name)?;
        let health = prior
            .as_ref()
            .ok_or("Windows process health history missing")?;
        health.validate()?;
        if health.stream_id != previous.stream_id {
            return Err("Windows process stream history differs".into());
        }
        native::recover(previous)?;
    }
    let stream_id = crate::secret()?;
    let s = &stream_id;
    let session_guid = format!(
        "{{{}-{}-{}-{}-{}}}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    );
    let now = crate::now_ms();
    let intent = SessionIntent {
        stream_id: stream_id.clone(),
        session_name: name,
        session_guid,
        owner_pid: std::process::id(),
        owner_created: native::owner_created()?,
        phase: "prepared".into(),
        started_ms: now,
        counters: Counters::default(),
    };
    let mut health = prior.unwrap_or_default();
    if previous.is_some() {
        health.loss_signals = health.loss_signals.saturating_add(1);
    }
    health.stream_id = stream_id.clone();
    health.state = "starting".into();
    health.started_ms = now;
    health.checked_ms = now;
    health.subscriptions = health.subscriptions.saturating_add(1);
    health.backpressured = false;
    health.error = String::new();
    health.validate()?;
    let boundary = EndpointEvent { id: protocol::hash(format!("windows-process-boundary:{stream_id}").as_bytes()), time_ms: now, kind: "inventory".into(), path: String::new(), sha256: String::new(), detection: String::new(), telemetry: None,
        detail: serde_json::json!({"windows_process_subscription":stream_id,"started_ms":now,"coverage":"Events before and between live ETW subscriptions are not observed or replayable; rundown is not process creation"}).to_string() };
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    set_metadata(store, "windows_process_events_health", &health)?;
    set_metadata(store, "windows_process_events_session", &intent)?;
    let count: usize =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |row| {
                row.get(0)
            })?;
    if count < 2 * MAX_ROWS {
        store.connection.execute(
            "INSERT INTO telemetry_pending VALUES(?1,?2)",
            rusqlite::params![boundary.id, serde_json::to_string(&boundary)?],
        )?;
    } else {
        health.loss_signals = health.loss_signals.saturating_add(1);
        set_metadata(store, "windows_process_events_health", &health)?;
    }
    tx.commit()?;
    Ok((health, intent))
}
#[cfg(windows)]
fn run(
    store: Store,
    live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: mpsc::Receiver<()>,
    ready: mpsc::Sender<std::result::Result<(), String>>,
) {
    struct Live(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Live {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _live = Live(live);
    let (mut health, mut intent) = match prepare(&store) {
        Ok(value) => value,
        Err(_) => {
            let _ = ready.send(Err(
                "Windows process ownership/recovery initialization failed".into(),
            ));
            return;
        }
    };
    let mut reader = match native::Reader::start(&intent) {
        Ok(value) => value,
        Err(_) => {
            health.state = "degraded".into();
            health.loss_signals = health.loss_signals.saturating_add(1);
            health.error = "Windows process source initialization failed".into();
            let _ = set_metadata(&store, "windows_process_events_health", &health);
            let _ = ready.send(Err(health.error));
            return;
        }
    };
    intent.phase = "active".into();
    let initial = reader
        .counters()
        .and_then(|counters| persist(&store, &mut health, &mut intent, &[], 0, counters));
    if initial.is_err() {
        let _ = ready.send(Err("Windows process startup admission failed".into()));
    } else {
        let _ = ready.send(Ok(()));
    }
    let result = (|| -> Result<()> {
        initial?;
        loop {
            match stop.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => (),
            }
            reader.check()?;
            let records = reader.batch();
            let clock = native::clock()?;
            let mut events = Vec::new();
            let mut rejected = 0;
            for record in records {
                match WindowsProcessEvent::from_original(
                    record.original(&intent.stream_id, clock.clone()),
                ) {
                    Ok(event) => events.push(event),
                    Err(_) => rejected += 1,
                }
            }
            let counters = reader.counters()?;
            if let Err(error) = persist(
                &store,
                &mut health,
                &mut intent,
                &events,
                rejected,
                counters,
            ) {
                health.queue_drops = health.queue_drops.saturating_add(events.len() as u64);
                return Err(error);
            }
            match stop.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
        Ok(())
    })();
    let closed = reader.close();
    let mut final_failed = false;
    if let Ok(counters) = &closed {
        // Final callbacks may arrive during shutdown. Drain and durably admit
        // them before recording the confirmed closed session.
        loop {
            let records = reader.batch();
            if records.is_empty() {
                break;
            }
            let clock = match native::clock() {
                Ok(value) => value,
                Err(_) => {
                    final_failed = true;
                    break;
                }
            };
            let mut events = Vec::new();
            let mut rejected = 0;
            for record in records {
                match WindowsProcessEvent::from_original(
                    record.original(&intent.stream_id, clock.clone()),
                ) {
                    Ok(event) => events.push(event),
                    Err(_) => rejected += 1,
                }
            }
            if persist(
                &store,
                &mut health,
                &mut intent,
                &events,
                rejected,
                counters.clone(),
            )
            .is_err()
            {
                final_failed = true;
                break;
            }
        }
        if !final_failed
            && persist(&store, &mut health, &mut intent, &[], 0, counters.clone()).is_ok()
        {
            intent.phase = "stopped".into();
        } else {
            final_failed = true;
        }
    }
    if result.is_err() || closed.is_err() || final_failed {
        health.loss_signals = health.loss_signals.saturating_add(1);
        health.error =
            "Windows process source or durable admission stopped with a coverage gap".into();
        health.state = "degraded".into();
    } else {
        health.state = "stopped".into();
    }
    health.checked_ms = crate::now_ms();
    let _ = (|| -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &store.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        set_metadata(&store, "windows_process_events_health", &health)?;
        set_metadata(&store, "windows_process_events_session", &intent)?;
        tx.commit()?;
        Ok(())
    })();
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
            Err("Native Windows process collection requires Windows".into())
        }
        #[cfg(windows)]
        {
            native::require_unimpersonated()?;
            let connection = store.collector_connection()?;
            if store
                .windows_process_events_live
                .swap(true, Ordering::AcqRel)
            {
                return Err("Windows process collector is already running".into());
            }
            let live = store.windows_process_events_live.clone();
            let (stop, receiver) = mpsc::channel();
            let (ready, started) = mpsc::channel();
            let worker = match thread::Builder::new()
                .name("endpoint-windows-process-events".into())
                .spawn(move || run(connection, live, receiver, ready))
            {
                Ok(worker) => worker,
                Err(error) => {
                    store
                        .windows_process_events_live
                        .store(false, Ordering::Release);
                    return Err(error.into());
                }
            };
            let collector = Self {
                stop,
                worker: Some(worker),
                owner: PhantomData,
            };
            match started.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(Ok(())) => Ok(collector),
                Ok(Err(error)) => Err(error.into()),
                Err(_) => Err("Windows process collector startup did not complete".into()),
            }
        }
    }
    pub fn check(&self) -> Result<()> {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            return Err("Windows process collector stopped unexpectedly".into());
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
