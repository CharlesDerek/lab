//! Opt-in kernel lifecycle stream with bounded durable delivery and visible gaps.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(test, target_os = "linux"))]
mod native_test;
#[cfg(target_os = "linux")]
mod wire;
use super::metadata;
#[cfg(any(target_os = "linux", test))]
use super::{drain_pending_in_transaction, set_metadata, MAX_ROWS};
#[cfg(any(target_os = "linux", test))]
use crate::now_ms;
#[cfg(target_os = "linux")]
use crate::secret;
use crate::{Result, Store};
use athernex_endpoint_protocol::process_events::ProcessEventHealth;
#[cfg(any(target_os = "linux", test))]
use athernex_endpoint_protocol::{
    self as protocol, process_events::ProcessEvent, telemetry::Telemetry, EndpointEvent,
};
#[cfg(any(target_os = "linux", test))]
use rusqlite::params;
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, mpsc},
    thread,
};

pub(super) fn health(store: &Store) -> Result<Option<ProcessEventHealth>> {
    let mut h: Option<ProcessEventHealth> = metadata(store, "process_events_health")?;
    if let Some(h) = &mut h {
        if !store.process_events_live.load(Ordering::Acquire) {
            h.state = "stopped".into();
            h.error = "Native process-event worker is not running".into();
        }
    }
    Ok(h)
}
#[cfg(any(target_os = "linux", test))]
fn persist(store: &Store, health: &mut ProcessEventHealth, events: &[EndpointEvent]) -> Result<()> {
    if events.len() > 128 {
        return Err("Native event admission exceeds batch limit".into());
    }
    for event in events {
        event.validate(now_ms())?;
    }
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    let pending: usize =
        store
            .connection
            .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r.get(0))?;
    if pending + events.len() > 2 * MAX_ROWS {
        health.dropped_events = health.dropped_events.saturating_add(events.len() as u64);
        health.error =
            "Native process events exceeded durable queue capacity; coverage has a gap".into();
    } else {
        for event in events {
            store.connection.execute(
                "INSERT INTO telemetry_pending VALUES(?1,?2)",
                params![event.id, serde_json::to_string(event)?],
            )?;
        }
    }
    if (health.loss_signals > 0 || health.dropped_events > 0) && health.error.is_empty() {
        health.error =
            "Kernel process-event loss or an interrupted subscription requires coverage review"
                .into();
    }
    if !health.error.is_empty() {
        health.state = "degraded".into();
    }
    drain_pending_in_transaction(store)?;
    health.validate()?;
    set_metadata(store, "process_events_health", health)?;
    tx.commit()?;
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn envelope(
    health: &ProcessEventHealth,
    event: ProcessEvent,
    monotonic_ns: u64,
    wall_ms: u64,
) -> Result<EndpointEvent> {
    if event.monotonic_ns > monotonic_ns.saturating_add(1_000_000_000) {
        return Err("Kernel event timestamp is ahead of the local monotonic clock".into());
    }
    let elapsed = monotonic_ns.saturating_sub(event.monotonic_ns) / 1_000_000;
    let time_ms = wall_ms
        .checked_sub(elapsed)
        .ok_or("Kernel timestamp cannot be mapped to wall time")?;
    let telemetry = Telemetry::ProcessEvent {
        boot_id: health.boot_id.clone(),
        stream_id: health.stream_id.clone(),
        event,
    };
    let id = protocol::hash(&serde_json::to_vec(&telemetry)?);
    Ok(EndpointEvent { id,time_ms,kind:"process_event".into(),path:String::new(),sha256:String::new(),detection:String::new(),
        detail:"Linux kernel lifecycle notification. PID/TID and monotonic time are original kernel values; executable identity and command line are not inferred. Subscription gaps are reported separately.".into(),telemetry:Some(telemetry) })
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
            Err("Native process-event subscription is implemented only on Linux".into())
        }
        #[cfg(target_os = "linux")]
        {
            let connection = store.collector_connection()?;
            let previous: Option<ProcessEventHealth> =
                metadata(&connection, "process_events_health")?;
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
            let mut h = ProcessEventHealth {
                boot_id: protocol::hash(boot.trim().as_bytes()),
                stream_id: secret()?,
                state: "starting".into(),
                started_ms: now_ms(),
                checked_ms: now_ms(),
                received_events: previous.as_ref().map_or(0, |p| p.received_events),
                dropped_events: previous.as_ref().map_or(0, |p| p.dropped_events),
                loss_signals: previous.as_ref().map_or(0, |p| {
                    p.loss_signals
                        .saturating_add(u64::from(p.state != "stopped"))
                }),
                subscriptions: previous
                    .as_ref()
                    .map_or(1, |p| p.subscriptions.saturating_add(1)),
                error: String::new(),
            };
            set_metadata(&connection, "process_events_health", &h)?;
            let mut reader = match linux::Reader::open() {
                Ok(reader) => reader,
                Err(error) => {
                    h.state = "degraded".into();
                    h.error = error.to_string().chars().take(256).collect();
                    set_metadata(&connection, "process_events_health", &h)?;
                    return Err(error);
                }
            };
            h.state = "active".into();
            let boundary=EndpointEvent { id:secret()?,time_ms:h.started_ms,kind:"inventory".into(),path:String::new(),sha256:String::new(),detection:String::new(),telemetry:None,
                detail:serde_json::json!({"process_event_subscription":h.stream_id,"started_ms":h.started_ms,"previous_stream_last_checked_ms":previous.as_ref().map(|p|p.checked_ms),"coverage":"Events before subscription and between subscriptions are not observed"}).to_string() };
            persist(&connection, &mut h, &[boundary])?;
            let base_loss = h.loss_signals;
            let live = store.process_events_live.clone();
            let (stop, receive) = mpsc::channel();
            let (started, ready) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("endpoint-process-events".into())
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
                            let monotonic = linux::monotonic_ns()?;
                            let now = now_ms();
                            let events = batch
                                .into_iter()
                                .map(|e| envelope(&h, e, monotonic, now))
                                .collect::<Result<Vec<_>>>()?;
                            if events.is_empty()
                                && now.saturating_sub(h.checked_ms) < 1000
                                && h.loss_signals == base_loss.saturating_add(reader.loss_signals)
                            {
                                continue;
                            }
                            h.checked_ms = now;
                            h.received_events =
                                h.received_events.saturating_add(events.len() as u64);
                            h.loss_signals = base_loss.saturating_add(reader.loss_signals);
                            persist(&connection, &mut h, &events)?;
                        }
                        Ok(())
                    })();
                    h.checked_ms = now_ms();
                    match result {
                        Ok(()) => h.state = "stopped".into(),
                        Err(error) => {
                            h.state = "degraded".into();
                            h.error = error.to_string().chars().take(256).collect();
                        }
                    }
                    if let Err(error) = set_metadata(&connection, "process_events_health", &h) {
                        eprintln!("Process-event health persistence failed: {error}");
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
            return Err("Native process-event worker stopped".into());
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

#[cfg(test)]
mod tests {
    use super::*;
    fn status() -> ProcessEventHealth {
        ProcessEventHealth {
            boot_id: "a".repeat(64),
            stream_id: "b".repeat(64),
            state: "active".into(),
            started_ms: now_ms(),
            checked_ms: now_ms(),
            received_events: 0,
            dropped_events: 0,
            loss_signals: 0,
            subscriptions: 1,
            error: String::new(),
        }
    }
    fn event(h: &ProcessEventHealth, seq: u32) -> EndpointEvent {
        envelope(
            h,
            ProcessEvent {
                cpu: 1,
                sequence: seq,
                monotonic_ns: 1_000_000,
                pid: 42,
                tid: 42,
                change: protocol::process_events::Change::Exec,
            },
            2_000_000,
            now_ms(),
        )
        .unwrap()
    }
    #[test]
    fn durable_event_time_and_identity_survive_restart_without_pid_enrichment() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut h = status();
        let e = event(&h, 1);
        persist(&store, &mut h, std::slice::from_ref(&e)).unwrap();
        assert!(e.telemetry.as_ref().unwrap().process().is_none());
        assert!(e.path.is_empty());
        drop(store);
        let reopened = Store::open(dir.path()).unwrap();
        let raw: String = reopened
            .connection
            .query_row("SELECT payload FROM outbox WHERE id=?1", [&e.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(raw, serde_json::to_string(&e).unwrap());
        assert!(!health(&reopened).unwrap().unwrap().healthy(now_ms()));
    }
    #[test]
    fn full_durable_queue_records_dropped_events_and_never_overwrites_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut h = status();
        store.connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<8192) INSERT INTO telemetry_pending SELECT printf('%064x',x),'{}' FROM n;").unwrap();
        store.connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<3072) INSERT INTO outbox SELECT printf('%064x',x),'{}' FROM n;").unwrap();
        let e = event(&h, 2);
        persist(&store, &mut h, &[e]).unwrap();
        assert_eq!(h.dropped_events, 1);
        assert_eq!(h.state, "degraded");
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM telemetry_pending", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            8192
        );
        persist(&store, &mut h, &[]).unwrap();
        assert_eq!(h.dropped_events, 1);
        assert!(!h.healthy(now_ms()));
    }
}
