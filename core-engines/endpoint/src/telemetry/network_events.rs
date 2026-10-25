//! Opt-in connection-tracker stream; no firewall rules or sysctls are changed.
#[cfg(target_os = "linux")]
mod hooks;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(test, target_os = "linux"))]
mod native_test;
#[cfg(test)]
mod tests;
#[cfg(target_os = "linux")]
mod wire;
use super::metadata;
#[cfg(any(target_os = "linux", test))]
use super::{drain_pending_in_transaction, set_metadata, MAX_ROWS};
use crate::{Result, Store};
use athernex_endpoint_protocol::network_events::NetworkEventHealth;
#[cfg(any(target_os = "linux", test))]
use athernex_endpoint_protocol::{
    self as protocol, network_events::NetworkEvent, telemetry::Telemetry, EndpointEvent,
};
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, mpsc},
    thread,
};

pub(super) fn health(store: &Store) -> Result<Option<NetworkEventHealth>> {
    let mut value: Option<NetworkEventHealth> = metadata(store, "network_events_health")?;
    if let Some(h) = &mut value {
        if !store.network_events_live.load(Ordering::Acquire) {
            h.state = "stopped".into();
            if h.error.is_empty() {
                h.error = "Native network-event worker is not running".into();
            }
        }
    }
    Ok(value)
}
#[cfg(any(target_os = "linux", test))]
fn persist(store: &Store, health: &mut NetworkEventHealth, events: &[EndpointEvent]) -> Result<()> {
    if events.len() > 128 {
        return Err("Network event admission exceeds batch limit".into());
    }
    for event in events {
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
            .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))?;
    let mut next = health.clone();
    if pending + events.len() > 2 * MAX_ROWS {
        next.dropped_events = next.dropped_events.saturating_add(events.len() as u64);
    } else {
        for event in events {
            store.connection.execute(
                "INSERT INTO telemetry_pending VALUES(?1,?2)",
                rusqlite::params![event.id, serde_json::to_string(event)?],
            )?;
        }
    }
    if next.loss_signals > 0 || next.dropped_events > 0 {
        next.state = "degraded".into();
        next.error =
            "Kernel tracker loss, interrupted subscription or full queue requires coverage review"
                .into();
    }
    drain_pending_in_transaction(store)?;
    next.validate()?;
    set_metadata(store, "network_events_health", &next)?;
    tx.commit()?;
    *health = next;
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn envelope(
    h: &NetworkEventHealth,
    event: NetworkEvent,
    sequence: u64,
    monotonic_ns: u64,
    wall_ms: u64,
) -> Result<EndpointEvent> {
    let telemetry = Telemetry::NetworkEvent {
        boot_id: h.boot_id.clone(),
        stream_id: h.stream_id.clone(),
        namespace: h.namespace,
        sequence,
        monotonic_ns,
        event,
    };
    Ok(EndpointEvent {id:protocol::hash(&serde_json::to_vec(&telemetry)?),time_ms:wall_ms,kind:"network_event".into(),path:String::new(),sha256:String::new(),detection:String::new(),
        detail:"Netfilter tracker observation in the reported network namespace. No process owner or firewall verdict is inferred. Tracker counters are cumulative; removal does not establish socket close. Events before/between subscriptions and traffic bypassing tracking are outside coverage.".into(),telemetry:Some(telemetry)})
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
            Err("Native network-event collection is available only on Linux".into())
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let connection = store.collector_connection()?;
            let previous: Option<NetworkEventHealth> =
                metadata(&connection, "network_events_health")?;
            if let Some(h) = &previous {
                h.validate()?;
            }
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
            let mut h = NetworkEventHealth {
                boot_id: protocol::hash(boot.trim().as_bytes()),
                stream_id: crate::secret()?,
                namespace: std::fs::metadata("/proc/thread-self/ns/net")?.ino(),
                families: Vec::new(),
                state: "starting".into(),
                started_ms: crate::now_ms(),
                checked_ms: crate::now_ms(),
                source_checked_ms: 0,
                received_events: previous.as_ref().map_or(0, |p| p.received_events),
                skipped_protocols: previous.as_ref().map_or(0, |p| p.skipped_protocols),
                dropped_events: previous.as_ref().map_or(0, |p| p.dropped_events),
                loss_signals: previous.as_ref().map_or(0, |p| {
                    p.loss_signals
                        .saturating_add(u64::from(p.state != "stopped" && !p.families.is_empty()))
                }),
                subscriptions: previous
                    .as_ref()
                    .map_or(1, |p| p.subscriptions.saturating_add(1)),
                error: String::new(),
            };
            set_metadata(&connection, "network_events_health", &h)?;
            let mut reader = match linux::Reader::open() {
                Ok(reader) => reader,
                Err(error) => {
                    h.state = "degraded".into();
                    h.error = error.to_string().chars().take(256).collect();
                    set_metadata(&connection, "network_events_health", &h)?;
                    return Err(error);
                }
            };
            h.families = reader.families.clone();
            h.source_checked_ms = reader.source_checked_ms;
            h.state = "active".into();
            let boundary=EndpointEvent {id:crate::secret()?,time_ms:h.started_ms,kind:"inventory".into(),path:String::new(),sha256:String::new(),detection:String::new(),telemetry:None,
                detail:serde_json::json!({"network_event_subscription":h.stream_id,"namespace":h.namespace,"families":h.families,"started_ms":h.started_ms,"previous_stream_last_checked_ms":previous.as_ref().map(|p|p.checked_ms),"coverage":"Only TCP/UDP tracker events in this namespace after subscription; policy bypasses, prior entries and subscription gaps are not observed"}).to_string()};
            {
                let tx = rusqlite::Transaction::new_unchecked(
                    &connection.connection,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                connection.enqueue(&boundary)?;
                h.validate()?;
                set_metadata(&connection, "network_events_health", &h)?;
                tx.commit()?;
            }
            let base_loss = h.loss_signals;
            let base_skipped = h.skipped_protocols;
            let live = store.network_events_live.clone();
            let (stop, receive) = mpsc::channel();
            let (started, ready) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("endpoint-network-events".into())
                .spawn(move || {
                    struct Live(std::sync::Arc<std::sync::atomic::AtomicBool>);
                    impl Drop for Live {
                        fn drop(&mut self) {
                            self.0.store(false, Ordering::Release);
                        }
                    }
                    let guard = Live(live);
                    guard.0.store(true, Ordering::Release);
                    let _ = started.send(());
                    let result = (|| -> Result<()> {
                        loop {
                            match receive.try_recv() {
                                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                                Err(mpsc::TryRecvError::Empty) => (),
                            }
                            let batch = reader.batch()?;
                            let now = crate::now_ms();
                            let loss = base_loss.saturating_add(reader.loss_signals);
                            let skipped = base_skipped.saturating_add(reader.skipped_protocols);
                            if batch.is_empty()
                                && now.saturating_sub(h.checked_ms) < 1000
                                && h.loss_signals == loss
                                && h.skipped_protocols == skipped
                            {
                                continue;
                            }
                            let mono = linux::monotonic_ns()?;
                            let events = batch
                                .into_iter()
                                .enumerate()
                                .map(|(index, event)| {
                                    let sequence = h
                                        .received_events
                                        .checked_add(index as u64 + 1)
                                        .ok_or("Network event sequence exhausted")?;
                                    envelope(&h, event, sequence, mono, now)
                                })
                                .collect::<Result<Vec<_>>>()?;
                            h.checked_ms = now;
                            h.source_checked_ms = reader.source_checked_ms;
                            h.loss_signals = loss;
                            h.skipped_protocols = skipped;
                            h.received_events = h
                                .received_events
                                .checked_add(events.len() as u64)
                                .ok_or("Network event counter exhausted")?;
                            persist(&connection, &mut h, &events)?;
                        }
                        Ok(())
                    })();
                    h.checked_ms = crate::now_ms();
                    match result {
                        Ok(()) => h.state = "stopped".into(),
                        Err(error) => {
                            h.state = "degraded".into();
                            h.loss_signals = h.loss_signals.saturating_add(1);
                            h.error = error.to_string().chars().take(256).collect();
                        }
                    }
                    if let Err(error) = set_metadata(&connection, "network_events_health", &h) {
                        eprintln!("Network-event health persistence failed: {error}");
                    }
                })?;
            let collector = Self {
                stop,
                worker: Some(worker),
                owner: PhantomData,
            };
            ready.recv_timeout(std::time::Duration::from_secs(3))?;
            Ok(collector)
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
            Err("Native network-event worker stopped".into())
        } else {
            Ok(())
        }
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
