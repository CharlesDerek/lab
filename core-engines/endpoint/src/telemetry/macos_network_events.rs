//! Durable admission for an OS-managed source. Detaching never stops the provider.
#[cfg(test)]
mod tests;
use super::metadata;
#[cfg(any(target_os = "macos", test))]
use super::{drain_pending_in_transaction, set_metadata, MAX_ROWS};
use crate::{Result, Store};
use athernex_endpoint_protocol::macos_network_events::MacosNetworkEventHealth;
#[cfg(any(target_os = "macos", test))]
use athernex_endpoint_protocol::{
    self as protocol, macos_network_events::MacosNetworkEvent, telemetry::Telemetry, EndpointEvent,
};
#[cfg(any(target_os = "macos", test))]
use athernex_macos_network::{Delivery, Status};
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
struct Session {
    stream_id: String,
    source: Option<MacosNetworkEventHealth>,
    batch_id: u64,
    batch_sha256: String,
    events_sha256: String,
    last_receipt: u64,
    transport_failures: u64,
}
#[cfg(any(target_os = "macos", test))]
impl Session {
    fn validate(&self) -> Result<()> {
        if !protocol::hex_id(&self.stream_id)
            || (self.batch_id == 0
                && (!self.batch_sha256.is_empty()
                    || !self.events_sha256.is_empty()
                    || self.last_receipt != 0))
            || (self.batch_id != 0
                && (!protocol::hex_id(&self.batch_sha256)
                    || !protocol::hex_id(&self.events_sha256)
                    || self.last_receipt == 0))
        {
            return Err("Invalid durable Mac network session".into());
        }
        if let Some(source) = &self.source {
            validate_source(source)?;
            if source.stream_id != self.stream_id || self.last_receipt > source.received_records {
                return Err("Mac network durable receipt differs from source".into());
            }
        } else if self.batch_id != 0 {
            return Err("Mac network durable source is missing".into());
        }
        Ok(())
    }
}
pub(super) fn health(store: &Store) -> Result<Option<MacosNetworkEventHealth>> {
    let mut value: Option<MacosNetworkEventHealth> = metadata(store, "macos_network_health")?;
    if let Some(h) = &mut value {
        if !store.macos_network_events_live.load(Ordering::Acquire) {
            h.state = "stopped".into();
            h.error =
                "Mac network consumer is not running; this does not stop the OS provider".into();
        }
    }
    Ok(value)
}
#[cfg(any(target_os = "macos", test))]
fn validate_source(h: &MacosNetworkEventHealth) -> Result<()> {
    h.validate()?;
    if h.source_policy_sha256 != protocol::macos_network_events::source_policy_sha256()
        || h.admitted_records != 0
        || h.restarts != 0
        || h.loss_signals != 0
        || h.pending_records > h.received_records
    {
        return Err("Mac network source binding or counter ownership differs".into());
    }
    Ok(())
}
#[cfg(any(target_os = "macos", test))]
fn counters(h: &MacosNetworkEventHealth) -> [u64; 6] {
    [
        h.received_records,
        h.excluded_records,
        h.rejected_records,
        h.callback_drops,
        h.queue_drops,
        h.transport_errors,
    ]
}
#[cfg(any(target_os = "macos", test))]
fn envelope(event: &MacosNetworkEvent) -> EndpointEvent {
    EndpointEvent {
        id:event.event_id(), time_ms:event.time_ms,kind:"macos_network_event".into(),path:String::new(),sha256:String::new(),detection:String::new(),
        detail:"NetworkExtension new-flow metadata; collector receipt time/order, separate reported app/process tokens, and unavailable upstream loss accounting. No connection success or complete flow lifetime is implied.".into(),
        telemetry:Some(Telemetry::MacosNetworkEvent {event:event.clone()}),
    }
}
#[cfg(any(target_os = "macos", test))]
fn save(store: &Store, h: &MacosNetworkEventHealth, session: &Session) -> Result<()> {
    h.validate()?;
    session.validate()?;
    set_metadata(store, "macos_network_health", h)?;
    set_metadata(store, "macos_network_session", session)
}
#[cfg(any(target_os = "macos", test))]
fn increment(n: u64) -> Result<u64> {
    n.checked_add(1)
        .ok_or_else(|| "Mac network durable counter overflow".into())
}

/// Select the provider's stream, never invent or reset it on consumer startup.
#[cfg(any(target_os = "macos", test))]
fn prepare(
    store: &Store,
    source: &MacosNetworkEventHealth,
) -> Result<(MacosNetworkEventHealth, Session)> {
    validate_source(source)?;
    let prior: Option<MacosNetworkEventHealth> = metadata(store, "macos_network_health")?;
    let session: Option<Session> = metadata(store, "macos_network_session")?;
    if prior.is_some() != session.is_some() {
        return Err("Mac network durable session and health differ".into());
    }
    if let (Some(h), Some(s)) = (&prior, &session) {
        h.validate()?;
        s.validate()?;
        if h.stream_id != s.stream_id || h.source_policy_sha256 != source.source_policy_sha256 {
            return Err("Mac network durable history binding differs".into());
        }
        if s.stream_id == source.stream_id {
            return Ok((h.clone(), s.clone()));
        }
    }
    let mut h = source.clone();
    h.state = "starting".into();
    if let Some(prior) = prior {
        h.restarts = increment(prior.restarts)?;
        h.loss_signals = increment(prior.loss_signals)?;
        h.error =
            "Mac network provider changed; the intervening source interval cannot be replayed"
                .into();
    }
    let s = Session {
        stream_id: source.stream_id.clone(),
        source: None,
        batch_id: 0,
        batch_sha256: String::new(),
        events_sha256: String::new(),
        last_receipt: 0,
        transport_failures: 0,
    };
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    save(store, &h, &s)?;
    tx.commit()?;
    Ok((h, s))
}

/// Native transport already checked the exact immutable batch bytes/digest. Store
/// that digest and independently bind typed event content before acknowledging.
#[cfg(any(target_os = "macos", test))]
fn persist(
    store: &Store,
    h: &mut MacosNetworkEventHealth,
    s: &mut Session,
    d: &Delivery,
) -> Result<bool> {
    s.validate()?;
    validate_source(&d.status.health)?;
    let source = &d.status.health;
    if source.stream_id != s.stream_id
        || d.events.len() > 64
        || (d.batch_id == 0) != d.events.is_empty()
        || (d.batch_id == 0) != d.batch_sha256.is_empty()
        || (d.batch_id != 0 && !protocol::hex_id(&d.batch_sha256))
        || d.events.len() as u64 > source.pending_records
        || (d.batch_id == 0 && d.status.last_acked_batch_id != s.batch_id)
        || d.status.last_acked_batch_id > s.batch_id
        || d.status.last_acked_batch_id < s.batch_id.saturating_sub(1)
    {
        return Err(
            "Mac network batch or acknowledged frontier differs from durable history".into(),
        );
    }
    if let Some(old) = &s.source {
        if counters(source)
            .iter()
            .zip(counters(old))
            .any(|(a, b)| *a < b)
            || source.started_ms != old.started_ms
            || source.checked_ms < old.checked_ms
        {
            return Err("Mac network source counters regressed".into());
        }
    }
    let typed = serde_json::to_vec(&d.events)?;
    if typed.len() > 64 * protocol::macos_network_events::MAX_SERIALIZED_EVENT_BYTES {
        return Err("Mac network normalized batch exceeds budget".into());
    }
    let digest = protocol::hash(&typed);
    let replay = d.batch_id != 0 && d.batch_id == s.batch_id;
    if replay && (d.batch_sha256 != s.batch_sha256 || digest != s.events_sha256) {
        return Err("Mac network committed batch changed".into());
    }
    if d.batch_id != 0
        && (d.status.last_acked_batch_id.checked_add(1) != Some(d.batch_id)
            || (!replay && s.batch_id.checked_add(1) != Some(d.batch_id)))
    {
        return Err("Mac network batch sequence differs".into());
    }
    let mut receipt = if replay { 0 } else { s.last_receipt };
    let mut envelopes = Vec::with_capacity(d.events.len());
    for event in &d.events {
        if event.original.stream_id != s.stream_id
            || event.original.receipt_sequence <= receipt
            || event.original.receipt_sequence > source.received_records
        {
            return Err("Mac network original receipt differs".into());
        }
        receipt = event.original.receipt_sequence;
        let event = envelope(event);
        event.validate(crate::now_ms())?;
        envelopes.push(event);
    }
    if replay && receipt != s.last_receipt {
        return Err("Mac network durable receipt high-water differs".into());
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
    let admitted = replay || pending + envelopes.len() <= 2 * MAX_ROWS;
    let mut next = source.clone();
    let mut session = s.clone();
    next.admitted_records = h.admitted_records;
    next.restarts = h.restarts;
    next.loss_signals = h.loss_signals;
    next.transport_errors = source
        .transport_errors
        .checked_add(s.transport_failures)
        .ok_or("Mac network transport counter overflow")?;
    if admitted && d.batch_id != 0 && !replay {
        for event in &envelopes {
            store.connection.execute(
                "INSERT INTO telemetry_pending VALUES(?1,?2)",
                rusqlite::params![event.id, serde_json::to_string(event)?],
            )?;
        }
        next.admitted_records = next
            .admitted_records
            .checked_add(envelopes.len() as u64)
            .ok_or("Mac network admitted counter overflow")?;
        session.batch_id = d.batch_id;
        session.batch_sha256 = d.batch_sha256.clone();
        session.events_sha256 = digest;
        session.last_receipt = receipt;
        drain_pending_in_transaction(store)?;
    }
    let remaining: usize =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))?;
    next.backpressured = source.backpressured || !admitted || remaining >= 2 * MAX_ROWS;
    next.error = if next.restarts != 0
        || next.loss_signals != 0
        || next.rejected_records != 0
        || next.callback_drops != 0
        || next.queue_drops != 0
        || next.transport_errors != 0
    {
        "Mac network source has a persistent local loss or unknown interval; upstream loss accounting is unavailable".into()
    } else if next.backpressured {
        "Mac network durable delivery is backpressured".into()
    } else if !source.error.is_empty() {
        "Mac network provider configuration or collection is degraded".into()
    } else {
        String::new()
    };
    if !next.error.is_empty() && next.state != "stopped" {
        next.state = "degraded".into();
    }
    session.source = Some(source.clone());
    save(store, &next, &session)?;
    tx.commit()?;
    *h = next;
    *s = session;
    Ok(admitted)
}
#[cfg(any(target_os = "macos", test))]
fn status_delivery(status: Status) -> Delivery {
    Delivery {
        batch_id: 0,
        batch_sha256: String::new(),
        events: vec![],
        status,
    }
}
#[cfg(any(target_os = "macos", test))]
fn finish(
    store: &Store,
    h: &mut MacosNetworkEventHealth,
    s: &mut Session,
    failed: bool,
) -> Result<()> {
    if failed {
        h.loss_signals = increment(h.loss_signals)?;
        s.transport_failures = increment(s.transport_failures)?;
        h.transport_errors = increment(h.transport_errors)?;
        h.state = "degraded".into();
        h.error =
            "Mac network consumer stopped with an unknown interval; provider may still be active"
                .into();
    } else {
        h.state = "stopped".into();
        h.error = "Mac network consumer detached; OS provider may still be active".into();
    }
    h.checked_ms = crate::now_ms();
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    save(store, h, s)?;
    tx.commit()?;
    Ok(())
}
#[cfg(target_os = "macos")]
fn run(
    store: Store,
    config: athernex_macos_network::Config,
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
    let mut sent_ready = false;
    let mut history: Option<(MacosNetworkEventHealth, Session)> = None;
    let result = (|| -> Result<()> {
        let mut client = athernex_macos_network::Client::connect(&config)?;
        history = Some(prepare(&store, &client.status().health)?);
        loop {
            let d = client.poll()?;
            let (h, s) = history.as_mut().ok_or("Missing Mac network session")?;
            if persist(&store, h, s, &d)? && d.batch_id != 0 {
                let status = client.commit(d.batch_id, &d.batch_sha256)?;
                persist(&store, h, s, &status_delivery(status))?;
            }
            if !sent_ready {
                let _ = ready.send(Ok(()));
                sent_ready = true;
            }
            match stop.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
        // No drain/stop/kill: provider and its immutable inflight batch outlive us.
        let status = client.close()?;
        if let Some((h, s)) = &mut history {
            persist(&store, h, s, &status_delivery(status))?;
        }
        Ok(())
    })();
    if let Some((h, s)) = &mut history {
        let _ = finish(&store, h, s, result.is_err());
    }
    if !sent_ready {
        let _ = ready.send(Err("Mac network consumer initialization failed".into()));
    }
}
pub(super) struct Collector<'a> {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
    owner: PhantomData<&'a Store>,
}
impl<'a> Collector<'a> {
    pub fn start(
        store: &'a Store,
        deployment: &crate::macos_network_bundle::Deployment,
    ) -> Result<Self> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (store, deployment);
            Err("Mac network collection requires macOS13 or later".into())
        }
        #[cfg(target_os = "macos")]
        {
            deployment.verify_installed()?;
            let config = deployment.client_config();
            let connection = store.collector_connection()?;
            if store.macos_network_events_live.swap(true, Ordering::AcqRel) {
                return Err("Mac network consumer is already running".into());
            }
            let live = store.macos_network_events_live.clone();
            let (stop, receiver) = mpsc::channel();
            let (ready, started) = mpsc::channel();
            let worker = match thread::Builder::new()
                .name("endpoint-macos-network-events".into())
                .spawn(move || run(connection, config, live, receiver, ready))
            {
                Ok(w) => w,
                Err(e) => {
                    store
                        .macos_network_events_live
                        .store(false, Ordering::Release);
                    return Err(e.into());
                }
            };
            let collector = Self {
                stop,
                worker: Some(worker),
                owner: PhantomData,
            };
            match started.recv_timeout(std::time::Duration::from_secs(20)) {
                Ok(Ok(())) => Ok(collector),
                Ok(Err(e)) => Err(e.into()),
                Err(_) => Err("Mac network consumer startup did not complete".into()),
            }
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
            return Err("Mac network consumer stopped unexpectedly".into());
        }
        Ok(())
    }
}
// Join retains Store ownership. The five-second XPC deadline is per request;
// database/filesystem stalls and OS scheduling prevent a total shutdown deadline.
impl Drop for Collector<'_> {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
