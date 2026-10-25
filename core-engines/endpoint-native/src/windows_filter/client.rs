//! Four bounded scanner workers. The embedding supervisor owns the process job,
//! durable evidence admission, health proofs and the scanner daemon lifetime.
pub use super::evidence::Observation;
use super::{
    engine,
    peer::EngineConnection,
    port::{Message, Port, Receiver},
    wire,
};
use crate::Result;
use std::{
    net::SocketAddrV4,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, SyncSender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[derive(Clone, Copy)]
pub struct Scanner {
    pub address: SocketAddrV4,
    pub pid: u32,
    pub created: u64,
}
struct StopOnExit(Arc<AtomicBool>);
impl Drop for StopOnExit {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn scan(
    port: &Port,
    file: &wire::Notification,
    scanner: Scanner,
    policy: &wire::Configuration,
) -> Result<wire::Reply> {
    file.validate()?;
    if file.policy_sha256 != policy.policy_sha256 {
        return Err("Windows scan belongs to another policy".into());
    }
    let deadline = Instant::now() + Duration::from_millis(policy.timeout_ms as u64);
    let section = port.mapping(file)?;
    let mut connection =
        EngineConnection::connect(scanner.address, scanner.pid, scanner.created, deadline)?;
    let verdict = engine::scan(
        &mut connection.stream,
        file.bytes,
        deadline,
        |offset, bytes| section.read(offset, bytes),
    )?;
    connection.alive()?;
    let reply = wire::Reply::verdict(file.request_id, &verdict)?;
    drop(section); // Release the user view before authorizing the kernel reply.
    Ok(reply)
}
pub struct Counters {
    pub dropped: AtomicU64,
    pub scan_errors: AtomicU64,
    pub reply_errors: AtomicU64,
    pub kernel: Mutex<Option<Snapshot>>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub checked_ms: u64,
    pub status: wire::Status,
}
impl Default for Counters {
    fn default() -> Self {
        Self {
            dropped: AtomicU64::new(0),
            scan_errors: AtomicU64::new(0),
            reply_errors: AtomicU64::new(0),
            kernel: Mutex::new(None),
        }
    }
}
pub fn run(
    policy: wire::Configuration,
    scanner: Scanner,
    events: SyncSender<Observation>,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
) -> Result<()> {
    policy.validate()?;
    // Prove the actual scanner identity before arming the driver.
    let probe = EngineConnection::connect(
        scanner.address,
        scanner.pid,
        scanner.created,
        Instant::now() + Duration::from_secs(2),
    )?;
    drop(probe);
    let port = Arc::new(Port::connect()?);
    let policy = Arc::new(policy);
    thread::scope(|scope| -> Result<()> {
        let (ready, initialized) = mpsc::sync_channel(4);
        let mut workers = Vec::new();
        for _ in 0..4 {
            let (port, policy, stop, counters, events, ready) = (
                port.clone(),
                policy.clone(),
                stop.clone(),
                counters.clone(),
                events.clone(),
                ready.clone(),
            );
            workers.push(scope.spawn(move || -> Result<()> {
                let _stop_on_panic_or_exit = StopOnExit(stop.clone());
                let result = (|| -> Result<()> {
                    let mut receive = Receiver::new(port.clone())?;
                    ready.send(())?;
                    while let Some(message) = receive.receive(&stop)? {
                        match message {
                            Message::Scan { id, file } => {
                                let reply =
                                    scan(&port, &file, scanner, &policy).unwrap_or_else(|_| {
                                        counters.scan_errors.fetch_add(1, Ordering::Relaxed);
                                        wire::Reply::error(file.request_id)
                                    });
                                // A late reply never starts a new scan or becomes
                                // a receipt: only the driver's APPLIED message does.
                                if port.reply(id, reply).is_err() {
                                    counters.reply_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Message::Applied(event) => {
                                let event = Observation::applied(
                                    *event,
                                    &policy.policy_sha256,
                                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
                                        as u64,
                                )?;
                                if events.try_send(event).is_err() {
                                    counters.dropped.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    Ok(())
                })();
                if result.is_err() {
                    stop.store(true, Ordering::Release);
                }
                result
            }));
        }
        drop(ready);
        let setup = (|| -> Result<()> {
            for _ in 0..4 {
                initialized.recv_timeout(Duration::from_secs(2))?;
            }
            if stop.load(Ordering::Acquire) {
                return Err("Windows scanner stopped before policy admission".into());
            }
            port.configure(&policy)?;
            Ok(())
        })();
        if setup.is_err() {
            stop.store(true, Ordering::Release);
        }
        let mut failure = setup.err();
        while failure.is_none() && !stop.load(Ordering::Acquire) {
            let observed = (|| -> Result<()> {
                let status = port.status()?;
                if status.armed != 1
                    || status.connected != 1
                    || status.policy_sha256 != policy.policy_sha256
                {
                    return Err("Windows filter lost its armed policy or scanner connection".into());
                }
                *counters
                    .kernel
                    .lock()
                    .map_err(|_| "Windows kernel snapshot lock poisoned")? = Some(Snapshot {
                    checked_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
                    status,
                });
                Ok(())
            })();
            if let Err(error) = observed {
                failure = Some(error);
                stop.store(true, Ordering::Release);
            } else {
                thread::sleep(Duration::from_millis(250));
            }
        }
        for worker in workers {
            match worker.join() {
                Ok(Ok(())) => (),
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(_) => {
                    stop.store(true, Ordering::Release);
                    failure.get_or_insert("Windows scanner worker panicked".into());
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    })
}
