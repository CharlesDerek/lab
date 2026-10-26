use super::{
    hex_id, now_ms,
    queue::Shared,
    transport::{self, Command, Reply, Request, Response},
    Status,
};
use athernex_endpoint_protocol::macos_process_events::*;
use endpoint_sec::{sys, Action, ActionResult, Event, Message, Process};
use std::{
    marker::PhantomData,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    ptr::NonNull,
    rc::Rc,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

mod scope;
#[cfg(test)]
mod tests;
const EVENTS: [sys::es_event_type_t; 3] = [
    sys::es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
    sys::es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
    sys::es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
];
type Handler = block2::RcBlock<dyn Fn(NonNull<sys::es_client_t>, NonNull<sys::es_message_t>)>;

#[derive(Clone, Copy)]
struct LifetimeApi {
    create: fn(&mut *mut sys::es_client_t, &Handler) -> sys::es_new_client_result_t,
    unsubscribe: fn(*mut sys::es_client_t) -> sys::es_return_t,
    delete: fn(*mut sys::es_client_t) -> sys::es_return_t,
}
impl LifetimeApi {
    fn native() -> Self {
        Self {
            create: |out, block| unsafe { sys::es_new_client(out, block) },
            unsubscribe: |client| unsafe { sys::es_unsubscribe_all(client) },
            delete: |client| unsafe { sys::es_delete_client(client) },
        }
    }
}

struct Owner {
    client: Option<NonNull<sys::es_client_t>>,
    block: Option<Handler>,
    shared: Arc<Shared>,
    api: LifetimeApi,
    failed: bool,
    _thread: PhantomData<Rc<()>>,
}
impl Owner {
    fn new(
        shared: Arc<Shared>,
        stream: String,
        timebase: MacosMachTimebase,
    ) -> crate::Result<Self> {
        Self::new_with_api(shared, stream, timebase, LifetimeApi::native())
    }
    fn new_with_api(
        shared: Arc<Shared>,
        stream: String,
        timebase: MacosMachTimebase,
        api: LifetimeApi,
    ) -> crate::Result<Self> {
        let callback = shared.clone();
        let block: Handler = block2::RcBlock::new(
            move |_client: NonNull<sys::es_client_t>, raw: NonNull<sys::es_message_t>| {
                callback.callback(|| {
                    let Some(receipt) = callback.counters.receive() else {
                        return;
                    };
                    // Balanced retain/release remains inside the caught callback.
                    // No native pointer or Message is placed in the application queue.
                    let message = unsafe { Message::from_raw(raw) };
                    if message.version() < MIN_MESSAGE_VERSION {
                        callback.counters.add(&callback.counters.rejected, 1);
                        return;
                    }
                    let (Some(seq), Some(global)) = (message.seq_num(), message.global_seq_num())
                    else {
                        callback.counters.add(&callback.counters.rejected, 1);
                        return;
                    };
                    let kind = match message.event_type().0 {
                        9 => 0,
                        11 => 1,
                        15 => 2,
                        _ => {
                            callback.counters.unknown_event_sequence(global);
                            callback.counters.add(&callback.counters.rejected, 1);
                            return;
                        }
                    };
                    callback.counters.sequences(kind, seq, global);
                    match projection(&message, &stream, receipt, &timebase) {
                        Ok(event) => callback.enqueue(event),
                        Err(_) => callback.counters.add(&callback.counters.rejected, 1),
                    }
                });
            },
        );
        let mut raw = std::ptr::null_mut();
        let code = (api.create)(&mut raw, &block);
        if code != sys::es_new_client_result_t::ES_NEW_CLIENT_RESULT_SUCCESS || raw.is_null() {
            // A contradictory pointer/result is uncertain native ownership. Keep
            // callback capture alive until this helper exits; never retry creation.
            if !raw.is_null() || code == sys::es_new_client_result_t::ES_NEW_CLIENT_RESULT_SUCCESS {
                shared.closing.store(true, Ordering::SeqCst);
                std::mem::forget(block);
            }
            return Err("Endpoint Security process client creation failed".into());
        }
        Ok(Self {
            client: NonNull::new(raw),
            block: Some(block),
            shared,
            api,
            failed: false,
            _thread: PhantomData,
        })
    }
    fn raw(&self) -> crate::Result<*mut sys::es_client_t> {
        self.client
            .map(NonNull::as_ptr)
            .ok_or_else(|| "Process source client is closed".into())
    }
    fn subscriptions(&self) -> crate::Result<()> {
        let (mut count, mut events) = (0_usize, std::ptr::null_mut());
        let code = unsafe { sys::es_subscriptions(self.raw()?, &mut count, &mut events) };
        struct List(*mut sys::es_event_type_t);
        impl Drop for List {
            fn drop(&mut self) {
                unsafe { libc::free(self.0.cast()) };
            }
        }
        let _list = List(events);
        if code != sys::es_return_t::ES_RETURN_SUCCESS || count != 3 || events.is_null() {
            return Err("Process source subscriptions could not be verified".into());
        }
        let mut actual = unsafe { std::slice::from_raw_parts(events, count) }
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>();
        actual.sort_unstable();
        if actual != [9, 11, 15] {
            return Err("Process source subscriptions changed".into());
        }
        Ok(())
    }
    fn stop(&mut self) -> crate::Result<()> {
        if self.failed {
            return Err("Process source shutdown is unconfirmed".into());
        }
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        let unsubscribe = (self.api.unsubscribe)(client.as_ptr());
        let deleted = (self.api.delete)(client.as_ptr());
        self.shared.closing.store(true, Ordering::SeqCst);
        if deleted != sys::es_return_t::ES_RETURN_SUCCESS {
            self.failed = true;
            self.shared.counters.failed.store(true, Ordering::SeqCst);
            // SDK documents leaked resources on failure. Keep the exact block
            // capture owned until process exit; do not retry or start a new client.
            if let Some(block) = self.block.take() {
                std::mem::forget(block);
            }
            return Err("Endpoint Security process client shutdown failed".into());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.shared.callbacks.load(Ordering::SeqCst) != 0 {
            if Instant::now() >= deadline {
                self.failed = true;
                if let Some(block) = self.block.take() {
                    std::mem::forget(block);
                }
                return Err("Process callback shutdown did not complete".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        self.block.take();
        if unsubscribe != sys::es_return_t::ES_RETURN_SUCCESS {
            self.failed = true;
            return Err("Process source unsubscribe failed".into());
        }
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn process(value: Process<'_>) -> crate::Result<MacosProcessProjection> {
    let executable = value.executable();
    let path = executable.path().as_bytes();
    if path.len() > MAX_PATH_BYTES {
        return Err("Process executable path exceeds bound".into());
    }
    Ok(MacosProcessProjection {
        audit_token: value.audit_token().raw_token().val,
        parent_audit_token: value
            .parent_audit_token()
            .ok_or("Missing parent audit token")?
            .raw_token()
            .val,
        responsible_audit_token: value
            .responsible_audit_token()
            .ok_or("Missing responsible audit token")?
            .raw_token()
            .val,
        ppid: value.ppid(),
        original_ppid: value.original_ppid(),
        group_id: value.group_id(),
        session_id: value.session_id(),
        executable: MacosExecutable {
            path_bytes_hex: path.iter().map(|b| format!("{b:02x}")).collect(),
            path_truncated: executable.path_truncated(),
        },
    })
}
fn projection(
    message: &Message,
    stream: &str,
    receipt: u64,
    timebase: &MacosMachTimebase,
) -> crate::Result<MacosProcessEvent> {
    let notify_result = match message.action() {
        Some(Action::Notify(ActionResult::Auth(result))) if result.0 <= 1 => {
            MacosNotifyResult::Auth { result: result.0 }
        }
        Some(Action::Notify(ActionResult::Flags(flags))) => MacosNotifyResult::Flags { flags },
        _ => return Err("Invalid process notification result".into()),
    };
    let event = match message.event() {
        Some(Event::NotifyExec(event)) => MacosProcessPayload::Exec {
            target: process(event.target())?,
        },
        Some(Event::NotifyFork(event)) => MacosProcessPayload::Fork {
            child: process(event.child())?,
        },
        Some(Event::NotifyExit(event)) => MacosProcessPayload::Exit {
            raw_wait_status: event.stat(),
        },
        _ => return Err("Unsupported process notification".into()),
    };
    let time = message.raw_time();
    MacosProcessEvent::from_original(MacosProcessOriginal {
        projection_version: PROJECTION_VERSION,
        stream_id: stream.into(),
        receipt_sequence: receipt,
        message_version: message.version(),
        event_type: message.event_type().0,
        action_type: message.action_type().0,
        notify_result,
        time: MacosEventTime {
            seconds: time.tv_sec,
            nanoseconds: time.tv_nsec,
        },
        mach_time: message.raw_mach_time(),
        mach_timebase: timebase.clone(),
        seq_num: message.seq_num().ok_or("Missing process sequence")?,
        global_seq_num: message
            .global_seq_num()
            .ok_or("Missing process global sequence")?,
        actor: process(message.process())?,
        event,
    })
    .map_err(|_| "Invalid process notification projection".into())
}

fn runtime() -> crate::Result<MacosMachTimebase> {
    let (code, output) = crate::child::run(
        std::process::Command::new("/usr/bin/sw_vers").arg("-productVersion"),
        Duration::from_secs(5),
        128,
    )?;
    if code != 0 {
        return Err("macOS version query failed".into());
    }
    let text = std::str::from_utf8(&output).map_err(|_| "Invalid macOS version")?;
    let values = text
        .trim()
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if values.is_empty() || values.len() > 3 || values[0] < 12 {
        return Err("Process notifications require macOS12 or later".into());
    }
    endpoint_sec::version::set_runtime_version(
        values[0],
        *values.get(1).unwrap_or(&0),
        *values.get(2).unwrap_or(&0),
    );
    let mut timebase = mach2::mach_time::mach_timebase_info { numer: 0, denom: 0 };
    if unsafe { mach2::mach_time::mach_timebase_info(&mut timebase) } != 0
        || timebase.numer == 0
        || timebase.denom == 0
    {
        return Err("Process source Mach clock query failed".into());
    }
    Ok(MacosMachTimebase {
        numerator: timebase.numer,
        denominator: timebase.denom,
    })
}

fn snapshot(shared: &Shared, status: &Status) -> crate::Result<Status> {
    let mut status = status.clone();
    status.health.checked_ms = now_ms();
    let queue = shared
        .queue
        .lock()
        .map_err(|_| "Process queue unavailable")?;
    queue.status(&mut status);
    shared.counters.apply(&mut status);
    Ok(status)
}

/// Entrypoint only for the root-owned helper spawned with a private socket.
pub fn run_owned(parent: u32, fd: i32) -> crate::Result<()> {
    // This helper is a separate process. The hook never projects panic payloads.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("Process notification helper failed")
    }));
    run(parent, fd).map_err(|_| "Process notification helper failed".into())
}
fn run(parent: u32, fd: i32) -> crate::Result<()> {
    if unsafe { libc::geteuid() } != 0 || fd < 3 {
        return Err("Invalid process helper owner".into());
    }
    crate::child::guard_parent(parent)?;
    let mut kind = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut length,
        )
    } != 0
        || kind != libc::SOCK_STREAM
        || length as usize != std::mem::size_of::<i32>()
    {
        return Err("Invalid process helper socket".into());
    }
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.local_addr()?;
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err("Process helper descriptor protection failed".into());
    }
    let initial: Request =
        transport::read(&mut stream, 4096, Instant::now() + Duration::from_secs(5))?;
    if initial.version != 1
        || !hex_id(&initial.nonce)
        || !hex_id(&initial.stream_id)
        || !matches!(initial.command, Command::Start)
    {
        return Err("Invalid process helper handshake".into());
    }
    let shared = Arc::new(Shared::default());
    let started = now_ms();
    let mut owner = Owner::new(shared.clone(), initial.stream_id.clone(), runtime()?)?;
    let inventory = scope::prepare(owner.raw()?)?;
    if unsafe { sys::es_subscribe(owner.raw()?, EVENTS.as_ptr(), EVENTS.len() as u32) }
        != sys::es_return_t::ES_RETURN_SUCCESS
    {
        return Err("Process source subscription failed".into());
    }
    owner.subscriptions()?;
    let checked = now_ms();
    let mut status = Status {
        health: MacosProcessEventHealth {
            stream_id: initial.stream_id.clone(),
            state: "active".into(),
            source_policy_sha256: source_policy_sha256(),
            started_ms: started,
            checked_ms: checked,
            subscriptions: 3,
            scope_checked_ms: checked,
            mute_snapshot_sha256: inventory.digest()?,
            muted_process_count: inventory.processes,
            muted_path_count: inventory.paths,
            ..Default::default()
        },
        pending_records: 0,
        pending_bytes: 0,
    };
    let respond = |stream: &mut UnixStream, reply| {
        transport::write(
            stream,
            &Response {
                version: 1,
                nonce: initial.nonce.clone(),
                stream_id: initial.stream_id.clone(),
                reply,
            },
            Instant::now() + Duration::from_secs(5),
        )
    };
    respond(
        &mut stream,
        Reply::Ready {
            status: snapshot(&shared, &status)?,
        },
    )?;
    loop {
        let request: Request =
            transport::read(&mut stream, 4096, Instant::now() + Duration::from_secs(30))?;
        if request.version != 1
            || request.nonce != initial.nonce
            || request.stream_id != initial.stream_id
        {
            return Err("Process source request binding failed".into());
        }
        if owner.client.is_some() {
            let verified: crate::Result<()> = (|| {
                owner.subscriptions()?;
                let current = scope::inspect(owner.raw()?)?;
                status.health.mute_snapshot_sha256 = current.digest()?;
                status.health.muted_process_count = current.processes;
                status.health.muted_path_count = current.paths;
                status.health.subscribed_mute_count = current.intersections();
                if current.intersections() != 0 {
                    return Err("Process source exclusions changed".into());
                }
                Ok(())
            })();
            status.health.scope_checked_ms = now_ms();
            if verified.is_err() {
                status.health.state = "degraded".into();
                status.health.loss_signals = 1;
                status.health.error = "Process notification scope changed".into();
            }
        }
        let reply = match request.command {
            Command::Start => return Err("Duplicate process source startup".into()),
            Command::Poll => {
                let mut queue = shared
                    .queue
                    .lock()
                    .map_err(|_| "Process queue unavailable")?;
                let mut current = status.clone();
                current.health.checked_ms = now_ms();
                let mut delivery = queue.delivery(current)?;
                // Select the batch before reading cumulative callback counters,
                // with no intervening enqueue: every selected receipt is covered.
                shared.counters.apply(&mut delivery.status);
                Reply::Batch { delivery }
            }
            Command::Ack { batch_id } => {
                shared
                    .queue
                    .lock()
                    .map_err(|_| "Process queue unavailable")?
                    .acknowledge(batch_id)?;
                Reply::Ack {
                    batch_id,
                    status: snapshot(&shared, &status)?,
                }
            }
            Command::StopSource => {
                owner.stop()?;
                status.health.state = "stopped".into();
                status.health.subscriptions = 0;
                Reply::SourceStopped {
                    status: snapshot(&shared, &status)?,
                }
            }
            Command::Close => {
                let final_status = snapshot(&shared, &status)?;
                if owner.client.is_some() || final_status.pending_records != 0 {
                    return Err("Process source must be drained before close".into());
                }
                respond(
                    &mut stream,
                    Reply::Closed {
                        status: final_status,
                    },
                )?;
                return Ok(());
            }
        };
        respond(&mut stream, reply)?;
    }
}
