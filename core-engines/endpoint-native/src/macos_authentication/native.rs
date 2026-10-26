use super::{
    hex_id, now_ms,
    queue::Shared,
    transport::{self, Command, Reply, Request, Response},
    Status,
};
use athernex_endpoint_protocol::macos_authentication::*;
use athernex_endpoint_protocol::macos_process_events::MacosMachTimebase;
use endpoint_sec::{sys, Message};
use std::{
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixStream,
    },
    ptr::NonNull,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::macos_notify::native::scope;
#[cfg(test)]
mod tests;
const EVENTS: [sys::es_event_type_t; 1] =
    [sys::es_event_type_t::ES_EVENT_TYPE_NOTIFY_AUTHENTICATION];
mod projection;
type Owner = crate::macos_notify::native::Owner<MacosAuthentication, 1>;
#[cfg(test)]
use crate::macos_notify::native::{Handler, LifetimeApi};
fn callback(
    shared: Arc<Shared>,
    stream: String,
    timebase: MacosMachTimebase,
) -> impl Fn(NonNull<sys::es_message_t>) + std::panic::RefUnwindSafe {
    move |raw| {
        let callback = &shared;
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
        let (Some(seq), Some(global)) = (message.seq_num(), message.global_seq_num()) else {
            callback.counters.add(&callback.counters.rejected, 1);
            return;
        };
        if message.event_type().0 != EVENT_TYPE {
            callback.counters.unknown_event_sequence(global);
            callback.counters.add(&callback.counters.rejected, 1);
            return;
        }
        callback.counters.sequences(0, seq, global);
        match unsafe { projection::project(raw.as_ref(), &stream, receipt, &timebase) } {
            Ok(event) => callback.enqueue(event),
            Err(_) => callback.counters.add(&callback.counters.rejected, 1),
        }
    }
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
    if values.is_empty() || values.len() > 3 || values[0] < 13 {
        return Err("Authentication notifications require macOS13 or later".into());
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
        return Err("Authentication source Mach clock query failed".into());
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
        .map_err(|_| "Authentication queue unavailable")?;
    queue.status(&mut status);
    shared.counters.apply(&mut status);
    Ok(status)
}

/// Entrypoint only for the root-owned helper spawned with a private socket.
pub fn run_owned(parent: u32, fd: i32) -> crate::Result<()> {
    // This helper is a separate process. The hook never projects panic payloads.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("Authentication notification helper failed")
    }));
    run(parent, fd).map_err(|_| "Authentication notification helper failed".into())
}
fn run(parent: u32, fd: i32) -> crate::Result<()> {
    if unsafe { libc::geteuid() } != 0 || fd < 3 {
        return Err("Invalid authentication helper owner".into());
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
        return Err("Invalid authentication helper socket".into());
    }
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.local_addr()?;
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err("Authentication helper descriptor protection failed".into());
    }
    let initial: Request =
        transport::read(&mut stream, 4096, Instant::now() + Duration::from_secs(5))?;
    if initial.version != 1
        || !hex_id(&initial.nonce)
        || !hex_id(&initial.stream_id)
        || !matches!(initial.command, Command::Start)
    {
        return Err("Invalid authentication helper handshake".into());
    }
    let shared = Arc::new(Shared::default());
    let started = now_ms();
    let mut owner = Owner::new(
        shared.clone(),
        callback(shared.clone(), initial.stream_id.clone(), runtime()?),
    )?;
    let inventory = scope::prepare(owner.raw()?, &[111])?;
    if unsafe { sys::es_subscribe(owner.raw()?, EVENTS.as_ptr(), EVENTS.len() as u32) }
        != sys::es_return_t::ES_RETURN_SUCCESS
    {
        return Err("Authentication source subscription failed".into());
    }
    owner.subscriptions(&[111])?;
    let checked = now_ms();
    let mut status = Status {
        health: MacosAuthenticationHealth {
            stream_id: initial.stream_id.clone(),
            state: "active".into(),
            source_policy_sha256: source_policy_sha256(),
            started_ms: started,
            checked_ms: checked,
            subscriptions: 1,
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
            return Err("Authentication source request binding failed".into());
        }
        if owner.client.is_some() {
            let verified: crate::Result<()> = (|| {
                owner.subscriptions(&[111])?;
                let current = scope::inspect(owner.raw()?, &[111])?;
                status.health.mute_snapshot_sha256 = current.digest()?;
                status.health.muted_process_count = current.processes;
                status.health.muted_path_count = current.paths;
                status.health.subscribed_mute_count = current.intersections();
                if current.intersections() != 0 {
                    return Err("Authentication source exclusions changed".into());
                }
                Ok(())
            })();
            status.health.scope_checked_ms = now_ms();
            if verified.is_err() {
                status.health.state = "degraded".into();
                status.health.loss_signals = 1;
                status.health.error = "Authentication notification scope changed".into();
            }
        }
        let reply = match request.command {
            Command::Start => return Err("Duplicate authentication source startup".into()),
            Command::Poll => {
                let mut queue = shared
                    .queue
                    .lock()
                    .map_err(|_| "Authentication queue unavailable")?;
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
                    .map_err(|_| "Authentication queue unavailable")?
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
                    return Err("Authentication source must be drained before close".into());
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
