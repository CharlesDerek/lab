//! Opt-in Windows ETW network reports with durable admission and visible gaps.
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
#[cfg(any(windows, test))]
use athernex_endpoint_protocol as protocol;
use athernex_endpoint_protocol::windows_network_events::WindowsNetworkEventHealth;
#[cfg(any(windows, test))]
use athernex_endpoint_protocol::{
    telemetry::Telemetry, windows_network_events::WindowsNetworkEvent, EndpointEvent,
};
#[cfg(any(windows, test))]
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, mpsc},
    thread,
};

#[cfg(any(windows, test))]
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    // Last callback record consumed, including rejected or queue-refused records.
    // The next subscription always has a new stream; ETW has no replay cursor.
    consumed_receipt: u64,
}
#[cfg(any(windows, test))]
impl SessionIntent {
    fn validate(&self, expected_name: &str) -> Result<()> {
        if self.stream_id.len() != 64
            || !self
                .stream_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.stream_id.bytes().all(|byte| byte == b'0')
            || self.consumed_receipt > self.counters.received
            || self.session_name != expected_name
            || self.owner_pid <= 4
            || self.owner_created == 0
            || self.started_ms == 0
            || !["prepared", "active", "stopped"].contains(&self.phase.as_str())
        {
            return Err("Invalid durable Windows network session ownership".into());
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
            return Err("Windows network session GUID differs from its intent".into());
        }
        Ok(())
    }
}
pub(super) fn health(store: &Store) -> Result<Option<WindowsNetworkEventHealth>> {
    let mut result: Option<WindowsNetworkEventHealth> =
        metadata(store, "windows_network_events_health")?;
    if let Some(health) = &mut result {
        if !store.windows_network_events_live.load(Ordering::Acquire) {
            health.state = "stopped".into();
            health.error = "Windows network-event collector is not running".into();
        }
    }
    Ok(result)
}
#[cfg(any(windows, test))]
fn envelope(event: &WindowsNetworkEvent) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(), time_ms: event.time_ms, kind: "windows_network_event".into(),
        path: String::new(), sha256: String::new(), detection: String::new(),
        detail: "Windows ETW network report with exact admitted original bytes. Reported PID and endpoints do not establish verified process identity, socket lifetime, packet delivery or firewall enforcement. Live source gaps cannot be replayed.".into(),
        telemetry: Some(Telemetry::WindowsNetworkEvent { event: event.clone() }),
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
    health: &mut WindowsNetworkEventHealth,
    intent: &mut SessionIntent,
    events: &[WindowsNetworkEvent],
    rejected: u64,
    consumed_receipt: u64,
    counters: Counters,
) -> Result<()> {
    if events.len() > 64 || rejected > 64 || events.len() as u64 + rejected > 64 {
        return Err("Windows network admission exceeds bounded batch size".into());
    }
    if consumed_receipt < intent.consumed_receipt
        || consumed_receipt > counters.received
        || (events.len() as u64 + rejected != 0 && consumed_receipt == intent.consumed_receipt)
        || events.len() as u64 + rejected > consumed_receipt.saturating_sub(intent.consumed_receipt)
        || health.stream_id != intent.stream_id
    {
        return Err("Windows network admission receipt or stream differs".into());
    }
    let mut previous = intent.consumed_receipt;
    for event in events {
        let original = &event.original;
        if original.stream_id != intent.stream_id
            || original.receipt_sequence <= previous
            || original.receipt_sequence > consumed_receipt
        {
            return Err("Windows network admission reuses or reorders a source receipt".into());
        }
        previous = original.receipt_sequence;
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
        "Windows network capture has a persistent source, restart, decoding or queue gap; live ETW records cannot be replayed".into()
    } else if next.backpressured {
        "Windows network delivery queue is full".into()
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
    next_intent.consumed_receipt = consumed_receipt;
    next.validate()?;
    next_intent.validate(&intent.session_name)?;
    set_metadata(store, "windows_network_events_health", &next)?;
    set_metadata(store, "windows_network_events_session", &next_intent)?;
    tx.commit()?;
    *health = next;
    *intent = next_intent;
    Ok(())
}
#[cfg(windows)]
fn prepare(store: &Store) -> Result<(WindowsNetworkEventHealth, SessionIntent)> {
    let name = native::session_name(&store.directory)?;
    let previous: Option<SessionIntent> = metadata(store, "windows_network_events_session")?;
    let prior: Option<WindowsNetworkEventHealth> =
        metadata(store, "windows_network_events_health")?;
    if previous.is_some() != prior.is_some() {
        return Err("Windows network session and health history differ".into());
    }
    if let Some(previous) = &previous {
        previous.validate(&name)?;
        let health = prior
            .as_ref()
            .ok_or("Windows network health history missing")?;
        health.validate()?;
        if health.stream_id != previous.stream_id {
            return Err("Windows network stream history differs".into());
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
        consumed_receipt: 0,
    };
    begin_subscription(store, prior, intent)
}
#[cfg(any(windows, test))]
fn begin_subscription(
    store: &Store,
    prior: Option<WindowsNetworkEventHealth>,
    intent: SessionIntent,
) -> Result<(WindowsNetworkEventHealth, SessionIntent)> {
    intent.validate(&intent.session_name)?;
    if intent.phase != "prepared"
        || intent.consumed_receipt != 0
        || intent.counters != Counters::default()
    {
        return Err("Windows network subscription must start with a fresh intent".into());
    }
    let resumed = prior.is_some();
    if let Some(health) = &prior {
        health.validate()?;
        if health.stream_id == intent.stream_id {
            return Err("Windows network subscription cannot reuse a prior stream".into());
        }
    }
    let stream_id = intent.stream_id.clone();
    let now = intent.started_ms;
    let mut health = prior.unwrap_or_default();
    if resumed {
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
    let boundary = EndpointEvent { id: protocol::hash(format!("windows-network-boundary:{stream_id}").as_bytes()), time_ms: now, kind: "inventory".into(), path: String::new(), sha256: String::new(), detection: String::new(), telemetry: None,
        detail: serde_json::json!({"windows_network_subscription":stream_id,"started_ms":now,"coverage":"Events before and between live ETW subscriptions are not observed or replayable; reports do not prove packet delivery or complete socket lifetimes"}).to_string() };
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    set_metadata(store, "windows_network_events_health", &health)?;
    set_metadata(store, "windows_network_events_session", &intent)?;
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
        set_metadata(store, "windows_network_events_health", &health)?;
    }
    tx.commit()?;
    Ok((health, intent))
}
#[cfg(windows)]
fn admit_batch(
    store: &Store,
    health: &mut WindowsNetworkEventHealth,
    intent: &mut SessionIntent,
    reader: &native::Reader,
) -> Result<usize> {
    let records = reader.batch();
    let count = records.len();
    let consumed_receipt = records
        .last()
        .map_or(intent.consumed_receipt, |record| record.sequence());
    let admitted = (|| -> Result<()> {
        // Refresh after dequeuing, including for delayed records. The portable
        // decoder enforces the 300-second calibration distance without changing
        // the event's native QPC timestamp or extrapolating an old sample forever.
        let clock = native::clock()?;
        let mut events = Vec::new();
        let mut rejected = 0;
        for record in records {
            match WindowsNetworkEvent::from_original(
                record.original(&intent.stream_id, clock.clone()),
            ) {
                Ok(event) => events.push(event),
                Err(_) => rejected += 1,
            }
        }
        persist(
            store,
            health,
            intent,
            &events,
            rejected,
            consumed_receipt,
            reader.counters()?,
        )
    })();
    if admitted.is_err() {
        // These callbacks have left the bounded channel and ETW cannot replay
        // them. A failed transaction cannot advance the durable receipt.
        health.queue_drops = health.queue_drops.saturating_add(count as u64);
    }
    admitted?;
    Ok(count)
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
                "Windows network ownership/recovery initialization failed".into(),
            ));
            return;
        }
    };
    let mut reader = match native::Reader::start(&intent) {
        Ok(value) => value,
        Err(_) => {
            health.state = "degraded".into();
            health.loss_signals = health.loss_signals.saturating_add(1);
            health.error = "Windows network source initialization failed".into();
            let _ = set_metadata(&store, "windows_network_events_health", &health);
            let _ = ready.send(Err(health.error));
            return;
        }
    };
    intent.phase = "active".into();
    let initial = reader
        .counters()
        .and_then(|counters| persist(&store, &mut health, &mut intent, &[], 0, 0, counters));
    if initial.is_err() {
        let _ = ready.send(Err("Windows network startup admission failed".into()));
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
            admit_batch(&store, &mut health, &mut intent, &reader)?;
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
            match admit_batch(&store, &mut health, &mut intent, &reader) {
                Ok(0) => break,
                Ok(_) => (),
                Err(_) => {
                    final_failed = true;
                    break;
                }
            }
        }
        let receipt = intent.consumed_receipt;
        if !final_failed
            && persist(
                &store,
                &mut health,
                &mut intent,
                &[],
                0,
                receipt,
                counters.clone(),
            )
            .is_ok()
        {
            intent.phase = "stopped".into();
        } else {
            final_failed = true;
        }
    }
    if result.is_err() || closed.is_err() || final_failed {
        health.loss_signals = health.loss_signals.saturating_add(1);
        health.error =
            "Windows network source or durable admission stopped with a coverage gap".into();
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
        set_metadata(&store, "windows_network_events_health", &health)?;
        set_metadata(&store, "windows_network_events_session", &intent)?;
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
            Err("Native Windows network collection requires Windows".into())
        }
        #[cfg(windows)]
        {
            native::require_unimpersonated()?;
            let connection = store.collector_connection()?;
            if store
                .windows_network_events_live
                .swap(true, Ordering::AcqRel)
            {
                return Err("Windows network collector is already running".into());
            }
            let live = store.windows_network_events_live.clone();
            let (stop, receiver) = mpsc::channel();
            let (ready, started) = mpsc::channel();
            let worker = match thread::Builder::new()
                .name("endpoint-windows-network-events".into())
                .spawn(move || run(connection, live, receiver, ready))
            {
                Ok(worker) => worker,
                Err(error) => {
                    store
                        .windows_network_events_live
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
                Err(_) => Err("Windows network collector startup did not complete".into()),
            }
        }
    }
    pub fn check(&self) -> Result<()> {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            return Err("Windows network collector stopped unexpectedly".into());
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
