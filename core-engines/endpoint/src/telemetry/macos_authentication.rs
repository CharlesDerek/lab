//! A private, owned ES helper with transactional admission before acknowledgement.
//! The source is not replayable. Only originals already committed here can replay.
#[cfg(test)]
mod tests;
#[cfg(any(target_os = "macos", test))]
use super::{drain_pending_in_transaction, set_metadata, MAX_ROWS};
use super::{metadata, MacosAuthenticationAdapter};
use crate::{Result, Store};
use athernex_endpoint_protocol::macos_authentication::MacosAuthenticationHealth;
#[cfg(any(target_os = "macos", test))]
use athernex_endpoint_protocol::{
    self as protocol, macos_authentication::MacosAuthentication, telemetry::Telemetry,
    EndpointEvent,
};
#[cfg(any(target_os = "macos", test))]
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, mpsc},
    thread,
};

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionIntent {
    stream_id: String,
    phase: String,
    source: Option<MacosAuthenticationHealth>,
    batch_id: u64,
    batch_sha256: String,
    last_receipt: u64,
}
#[cfg(any(target_os = "macos", test))]
impl SessionIntent {
    fn validate(&self) -> Result<()> {
        if !protocol::hex_id(&self.stream_id)
            || !["prepared", "active", "stopped"].contains(&self.phase.as_str())
            || (self.batch_id == 0 && (!self.batch_sha256.is_empty() || self.last_receipt != 0))
            || (self.batch_id != 0
                && (!protocol::hex_id(&self.batch_sha256) || self.last_receipt == 0))
        {
            return Err("Invalid durable Mac authentication session".into());
        }
        if let Some(source) = &self.source {
            validate_source(source, &self.stream_id)?;
            if self.last_receipt > source.received_records {
                return Err("Durable Mac authentication receipt exceeds its source".into());
            }
        } else if self.batch_id != 0 {
            return Err("Durable Mac authentication batch has no source counters".into());
        }
        Ok(())
    }
}

pub(super) fn health(store: &Store) -> Result<Option<MacosAuthenticationHealth>> {
    let mut value: Option<MacosAuthenticationHealth> =
        metadata(store, "macos_authentication_health")?;
    if let Some(health) = &mut value {
        if !store.macos_authentication_live.load(Ordering::Acquire) {
            health.state = "stopped".into();
            health.error = "Mac authentication-event collector is not running".into();
        }
    }
    Ok(value)
}

#[cfg(any(target_os = "macos", test))]
fn validate_source(source: &MacosAuthenticationHealth, stream: &str) -> Result<()> {
    source.validate()?;
    if source.stream_id != stream
        || source.source_policy_sha256 != protocol::macos_authentication::source_policy_sha256()
        || source.admitted_records != 0
        || source.queue_drops != 0
        || source.transport_errors != 0
        || (source.state == "active" && source.subscriptions != 1)
        || (source.state == "stopped" && source.subscriptions != 0)
    {
        return Err("Mac authentication source binding or counter ownership differs".into());
    }
    Ok(())
}
#[cfg(any(target_os = "macos", test))]
fn envelope(event: &MacosAuthentication) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(), time_ms: event.time_ms, kind: "authentication".into(),
        path: String::new(), sha256: String::new(), detection: String::new(),
        detail: "Endpoint Security authentication method report with an exact retained semantic projection. Reported success is not final login or session completion. Event process and optional instigator are distinct reported roles. Native source gaps cannot be replayed.".into(),
        telemetry: Some(Telemetry::MacosAuthentication { event: event.clone() }),
    }
}
#[cfg(any(target_os = "macos", test))]
fn counters(source: &MacosAuthenticationHealth) -> [u64; 7] {
    [
        source.received_records,
        source.rejected_records,
        source.callback_drops,
        source.global_sequence_gaps,
        source.event_sequence_gaps,
        source.sequence_regressions,
        source.loss_signals,
    ]
}

/// Returns true only when this exact immutable batch is durably admitted.
/// A full queue commits current health but keeps the batch unacknowledged.
#[cfg(any(target_os = "macos", test))]
fn persist(
    store: &Store,
    health: &mut MacosAuthenticationHealth,
    intent: &mut SessionIntent,
    batch_id: u64,
    events: &[MacosAuthentication],
    source: &MacosAuthenticationHealth,
) -> Result<bool> {
    intent.validate()?;
    validate_source(source, &intent.stream_id)?;
    if events.len() > 64
        || (batch_id == 0) != events.is_empty()
        || serde_json::to_vec(events)?.len() > 1024 * 1024
    {
        return Err("Mac authentication admission exceeds its batch contract".into());
    }
    let previous = intent.source.as_ref().map(counters).unwrap_or([0; 7]);
    let current = counters(source);
    if current.iter().zip(previous).any(|(now, old)| *now < old)
        || intent.source.as_ref().is_some_and(|old| {
            old.started_ms != source.started_ms
                || source.checked_ms < old.checked_ms
                || source.scope_checked_ms < old.scope_checked_ms
        })
    {
        return Err("Mac authentication source counters regressed".into());
    }
    let digest = if batch_id == 0 {
        String::new()
    } else {
        protocol::hash(&serde_json::to_vec(events)?)
    };
    let replay = batch_id != 0 && batch_id == intent.batch_id;
    if replay && digest != intent.batch_sha256 {
        return Err("Committed Mac authentication batch changed".into());
    }
    if batch_id != 0 && !replay && intent.batch_id.checked_add(1) != Some(batch_id) {
        return Err("Mac authentication batch sequence differs".into());
    }
    let mut receipt = if replay { 0 } else { intent.last_receipt };
    let mut envelopes = Vec::with_capacity(events.len());
    for event in events {
        if event.original.stream_id != intent.stream_id
            || event.original.receipt_sequence <= receipt
            || event.original.receipt_sequence > source.received_records
        {
            return Err("Mac authentication original receipt differs".into());
        }
        receipt = event.original.receipt_sequence;
        let value = envelope(event);
        value.validate(crate::now_ms())?;
        envelopes.push(value);
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
    let admitted = replay || pending + events.len() <= 2 * MAX_ROWS;
    let mut next = health.clone();
    let mut next_intent = intent.clone();
    // These counters measure different observations. In particular, global and
    // per-event gaps can overlap and must never be summed as unique lost events.
    let delta: Vec<_> = current
        .into_iter()
        .zip(previous)
        .map(|(now, old)| now - old)
        .collect();
    next.received_records = next.received_records.saturating_add(delta[0]);
    next.rejected_records = next.rejected_records.saturating_add(delta[1]);
    next.callback_drops = next.callback_drops.saturating_add(delta[2]);
    next.global_sequence_gaps = next.global_sequence_gaps.saturating_add(delta[3]);
    next.event_sequence_gaps = next.event_sequence_gaps.saturating_add(delta[4]);
    next.sequence_regressions = next.sequence_regressions.saturating_add(delta[5]);
    next.loss_signals = next.loss_signals.saturating_add(delta[6]);
    if admitted && batch_id != 0 && !replay {
        for event in &envelopes {
            store.connection.execute(
                "INSERT INTO telemetry_pending VALUES(?1,?2)",
                rusqlite::params![event.id, serde_json::to_string(event)?],
            )?;
        }
        next.admitted_records = next.admitted_records.saturating_add(events.len() as u64);
        next_intent.batch_id = batch_id;
        next_intent.batch_sha256 = digest;
        next_intent.last_receipt = receipt;
        drain_pending_in_transaction(store)?;
    }
    let remaining: usize =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))?;
    next.started_ms = source.started_ms;
    next.checked_ms = source.checked_ms;
    next.subscriptions = source.subscriptions;
    next.scope_checked_ms = source.scope_checked_ms;
    next.mute_snapshot_sha256
        .clone_from(&source.mute_snapshot_sha256);
    next.muted_process_count = source.muted_process_count;
    next.muted_path_count = source.muted_path_count;
    next.subscribed_mute_count = source.subscribed_mute_count;
    next.backpressured = !admitted || remaining >= 2 * MAX_ROWS || source.backpressured;
    next.error = if next.loss_signals != 0
        || next.rejected_records != 0
        || next.callback_drops != 0
        || next.queue_drops != 0
        || next.transport_errors != 0
        || next.global_sequence_gaps != 0
        || next.event_sequence_gaps != 0
        || next.sequence_regressions != 0
    {
        "Mac authentication capture has a persistent source, restart, decoding or queue gap; live ES records cannot be replayed".into()
    } else if !source.error.is_empty() || source.subscribed_mute_count != 0 {
        "Mac authentication source scope or collection is degraded".into()
    } else if next.backpressured {
        "Mac authentication delivery queue is full".into()
    } else {
        String::new()
    };
    next.state = if source.state == "stopped" {
        "stopped"
    } else if next.error.is_empty() {
        source.state.as_str()
    } else {
        "degraded"
    }
    .into();
    next_intent.source = Some(source.clone());
    next.validate()?;
    set_metadata(store, "macos_authentication_health", &next)?;
    set_metadata(store, "macos_authentication_session", &next_intent)?;
    tx.commit()?;
    *health = next;
    *intent = next_intent;
    Ok(admitted)
}

#[cfg(any(target_os = "macos", test))]
fn prepare(store: &Store) -> Result<(MacosAuthenticationHealth, SessionIntent)> {
    let previous: Option<SessionIntent> = metadata(store, "macos_authentication_session")?;
    let prior: Option<MacosAuthenticationHealth> = metadata(store, "macos_authentication_health")?;
    if previous.is_some() != prior.is_some() {
        return Err("Mac authentication session and health history differ".into());
    }
    if let (Some(previous), Some(health)) = (&previous, &prior) {
        previous.validate()?;
        health.validate()?;
        if previous.stream_id != health.stream_id
            || health.source_policy_sha256 != protocol::macos_authentication::source_policy_sha256()
        {
            return Err("Mac authentication history binding differs".into());
        }
    }
    let stream_id = crate::secret()?;
    let now = crate::now_ms();
    let intent = SessionIntent {
        stream_id: stream_id.clone(),
        phase: "prepared".into(),
        source: None,
        batch_id: 0,
        batch_sha256: String::new(),
        last_receipt: 0,
    };
    let mut health = prior.unwrap_or_default();
    if previous.is_some() {
        health.loss_signals = health.loss_signals.saturating_add(1);
    }
    health.stream_id = stream_id.clone();
    health.source_policy_sha256 = protocol::macos_authentication::source_policy_sha256();
    health.state = "starting".into();
    health.started_ms = now;
    health.checked_ms = now;
    health.subscriptions = 0;
    health.scope_checked_ms = 0;
    health.mute_snapshot_sha256.clear();
    health.muted_process_count = 0;
    health.muted_path_count = 0;
    health.subscribed_mute_count = 0;
    health.backpressured = false;
    health.error.clear();
    let boundary = EndpointEvent { id: protocol::hash(format!("macos-authentication-boundary:{stream_id}").as_bytes()),
        time_ms: now, kind: "inventory".into(), path: String::new(), sha256: String::new(),
        detection: String::new(), telemetry: None,
        detail: serde_json::json!({"macos_authentication_subscription":stream_id,"started_ms":now,
            "coverage":"Events before and between live Endpoint Security subscriptions are not observed or replayable; method reports are not final login or session completion"}).to_string() };
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    let count: usize =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))?;
    if count < 2 * MAX_ROWS {
        store.connection.execute(
            "INSERT INTO telemetry_pending VALUES(?1,?2)",
            rusqlite::params![boundary.id, serde_json::to_string(&boundary)?],
        )?;
    } else {
        health.loss_signals = health.loss_signals.saturating_add(1);
    }
    health.validate()?;
    set_metadata(store, "macos_authentication_health", &health)?;
    set_metadata(store, "macos_authentication_session", &intent)?;
    tx.commit()?;
    Ok((health, intent))
}

#[cfg(target_os = "macos")]
fn run(
    store: Store,
    adapter: MacosAuthenticationAdapter,
    live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: mpsc::Receiver<()>,
    ready: mpsc::Sender<std::result::Result<(), String>>,
) {
    use athernex_endpoint_native::macos_authentication::Client;
    use std::time::{Duration, Instant};
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
                "Mac authentication durable initialization failed".into()
            ));
            return;
        }
    };
    let mut uncommitted = 0;
    let mut sent_ready = false;
    let mut source_failed = false;
    let result = (|| -> Result<()> {
        let mut reader = Client::start(&adapter.path, &adapter.sha256, &intent.stream_id)
            .inspect_err(|_| source_failed = true)?;
        intent.phase = "active".into();
        loop {
            let delivery = reader.poll().inspect_err(|_| source_failed = true)?;
            uncommitted = delivery.status.pending_records;
            if persist(
                &store,
                &mut health,
                &mut intent,
                delivery.batch_id,
                &delivery.events,
                &delivery.status.health,
            )? && delivery.batch_id != 0
            {
                uncommitted = uncommitted.saturating_sub(delivery.events.len() as u64);
                reader
                    .commit(delivery.batch_id)
                    .inspect_err(|_| source_failed = true)?;
            }
            if !sent_ready {
                let _ = ready.send(Ok(()));
                sent_ready = true;
            }
            match stop.recv_timeout(Duration::from_millis(100)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
        // Stop callbacks before draining; final committable records are retained.
        // Each IPC operation and process reap also has an independent deadline.
        let deadline = Instant::now() + Duration::from_secs(30);
        let stopped = reader.stop_source().inspect_err(|_| source_failed = true)?;
        uncommitted = stopped.pending_records;
        persist(&store, &mut health, &mut intent, 0, &[], &stopped.health)?;
        loop {
            if Instant::now() >= deadline {
                return Err("Mac authentication shutdown admission timed out".into());
            }
            let delivery = reader.poll().inspect_err(|_| source_failed = true)?;
            uncommitted = delivery.status.pending_records;
            let admitted = persist(
                &store,
                &mut health,
                &mut intent,
                delivery.batch_id,
                &delivery.events,
                &delivery.status.health,
            )?;
            if delivery.batch_id == 0 {
                break;
            }
            if admitted {
                uncommitted = uncommitted.saturating_sub(delivery.events.len() as u64);
                reader
                    .commit(delivery.batch_id)
                    .inspect_err(|_| source_failed = true)?;
            } else {
                thread::sleep(Duration::from_millis(100));
            }
        }
        let final_status = reader.close().inspect_err(|_| source_failed = true)?;
        persist(
            &store,
            &mut health,
            &mut intent,
            0,
            &[],
            &final_status.health,
        )?;
        intent.phase = "stopped".into();
        Ok(())
    })();
    if result.is_err() {
        health.loss_signals = health.loss_signals.saturating_add(1);
        if source_failed {
            health.transport_errors = health.transport_errors.saturating_add(1);
        }
        // This is a known lower bound. An unavailable native tail is represented
        // by loss_signals, never asserted to contain exactly this many records.
        health.queue_drops = health.queue_drops.saturating_add(uncommitted);
        health.error =
            "Mac authentication source or durable admission stopped with a coverage gap".into();
        health.state = "degraded".into();
        if !sent_ready {
            let _ = ready.send(Err("Mac authentication source initialization failed".into()));
        }
    } else {
        health.state = "stopped".into();
    }
    health.checked_ms = crate::now_ms();
    let _ = (|| -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &store.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        set_metadata(&store, "macos_authentication_health", &health)?;
        set_metadata(&store, "macos_authentication_session", &intent)?;
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
    pub fn start(store: &'a Store, adapter: &MacosAuthenticationAdapter) -> Result<Self> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (store, adapter);
            Err("Native Mac authentication collection requires macOS".into())
        }
        #[cfg(target_os = "macos")]
        {
            adapter.validate()?;
            athernex_endpoint_native::macos_authentication::verify_helper(
                &adapter.path,
                &adapter.sha256,
            )?;
            let connection = store.collector_connection()?;
            if store.macos_authentication_live.swap(true, Ordering::AcqRel) {
                return Err("Mac authentication collector is already running".into());
            }
            let live = store.macos_authentication_live.clone();
            let adapter = adapter.clone();
            let (stop, receiver) = mpsc::channel();
            let (ready, started) = mpsc::channel();
            let worker = match thread::Builder::new()
                .name("endpoint-macos-authentication-events".into())
                .spawn(move || run(connection, adapter, live, receiver, ready))
            {
                Ok(worker) => worker,
                Err(error) => {
                    store
                        .macos_authentication_live
                        .store(false, Ordering::Release);
                    return Err(error.into());
                }
            };
            let collector = Self {
                stop,
                worker: Some(worker),
                owner: PhantomData,
            };
            match started.recv_timeout(std::time::Duration::from_secs(20)) {
                Ok(Ok(())) => Ok(collector),
                Ok(Err(error)) => Err(error.into()),
                Err(_) => Err("Mac authentication collector startup did not complete".into()),
            }
        }
    }
    pub fn check(&self) -> Result<()> {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            return Err("Mac authentication collector stopped unexpectedly".into());
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
