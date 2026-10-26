//! Deadline-aware process execution with bounded output and asynchronous reaping.
//! Keep the leader waitable until its group has received termination, avoiding a
//! signal to a PID that could have been recycled after an earlier wait().
use crate::Result;
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};

const LIMIT: usize = 16;
const CLEANUP: Duration = Duration::from_millis(100);
mod watch;
/// Check required kernel primitives without launching a command or closing any
/// caller descriptor. Installers use this before stopping an existing service.
pub fn check_lifetime_support() -> crate::Result<()> {
    watch::check_support()
}
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

/// Intentionally carry a duplicate of a lock's open-file description across
/// exec. The caller must not unlock it until child work has actually stopped.
/// Only the child's duplicate loses CLOEXEC; unrelated children do not inherit it.
pub fn inherit_lease(command: &mut Command, lease: &File) -> Result<i32> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let duplicate = unsafe { File::from_raw_fd(fd) };
    unsafe {
        command.pre_exec(move || {
            let fd = duplicate.as_raw_fd();
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(fd)
}
struct Slot;
impl Slot {
    fn acquire() -> Result<Self> {
        ACTIVE
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < LIMIT).then_some(n + 1)
            })
            .map_err(|_| "Local child process budget exhausted; cleanup may still be pending")?;
        Ok(Self)
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Pending {
    child: Child,
    group: Option<u32>,
    completed: Arc<AtomicBool>,
    _slot: Slot,
}
struct Reaper {
    pending: Mutex<Vec<Pending>>,
    healthy: AtomicBool,
}
fn reaper() -> Result<Arc<Reaper>> {
    static REAPER: OnceLock<std::result::Result<Arc<Reaper>, String>> = OnceLock::new();
    let result = REAPER.get_or_init(|| {
        let r = Arc::new(Reaper {
            pending: Mutex::new(Vec::new()),
            healthy: AtomicBool::new(true),
        });
        let worker = r.clone();
        thread::Builder::new()
            .name("athernex-child-reaper".into())
            .spawn(move || loop {
                {
                    let mut pending = worker.pending.lock().unwrap_or_else(|p| p.into_inner());
                    let mut i = 0;
                    while i < pending.len() {
                        match pending[i].child.try_wait() {
                            Ok(Some(_)) => match pending[i].group.map(group_exists).transpose() {
                                Ok(None | Some(false)) => {
                                    let entry = pending.swap_remove(i);
                                    let completed = entry.completed.clone();
                                    // Capacity is released before anyone can accept completion.
                                    drop(entry);
                                    completed.store(true, Ordering::Release);
                                }
                                Ok(Some(true)) => {
                                    i += 1;
                                }
                                Err(_) => {
                                    worker.healthy.store(false, Ordering::SeqCst);
                                    i += 1;
                                }
                            },
                            Ok(None) => i += 1,
                            Err(_) => {
                                worker.healthy.store(false, Ordering::SeqCst);
                                i += 1;
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_millis(25));
            })
            .map_err(|e| e.to_string())?;
        Ok(r)
    });
    let r = result.as_ref().map_err(|e| e.clone())?;
    if !r.healthy.load(Ordering::SeqCst) {
        return Err("Child cleanup could not confirm ownership; restart requires review".into());
    }
    Ok(r.clone())
}
pub fn pending_cleanup() -> usize {
    reaper()
        .map(|r| r.pending.lock().unwrap_or_else(|p| p.into_inner()).len())
        .unwrap_or(LIMIT)
}

/// Owned long-running child with a bounded output tail and nonblocking polling.
/// The child must arrange parent-death cleanup on macOS (our service entrypoints
/// call guard_parent). A successful stop confirms the leader was reaped; service
/// recovery must additionally check its recorded group for remaining descendants.
pub struct Service {
    owned: Owned,
    pipes: [File; 2],
    output: Vec<u8>,
    output_limit: usize,
    dropped: u64,
    status: Option<i32>,
}
impl Service {
    pub fn start(command: &mut Command, output_limit: usize) -> Result<Self> {
        if !(256..=65536).contains(&output_limit) {
            return Err("Invalid service output budget".into());
        }
        let reaper = reaper()?;
        let slot = Slot::acquire()?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        #[cfg(target_os = "linux")]
        unsafe {
            let parent = std::process::id();
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent as i32 {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                Ok(())
            });
        }
        let mut owned = Owned {
            child: Some(command.spawn()?),
            slot: Some(slot),
            reaper,
            cleanup_pending: false,
            cleanup_completed: Arc::new(AtomicBool::new(false)),
        };
        let child = owned.child.as_mut().expect("owned service child");
        let stdout: OwnedFd = child.stdout.take().ok_or("Missing service output")?.into();
        let stderr: OwnedFd = child
            .stderr
            .take()
            .ok_or("Missing service error output")?
            .into();
        Ok(Self {
            owned,
            pipes: [
                nonblocking(File::from(stdout))?,
                nonblocking(File::from(stderr))?,
            ],
            output: Vec::new(),
            output_limit,
            dropped: 0,
            status: None,
        })
    }
    pub fn pid(&self) -> Option<u32> {
        self.owned.child.as_ref().map(Child::id)
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn dropped_output(&self) -> u64 {
        self.dropped
    }
    fn drain(&mut self) -> Result<()> {
        let mut buffer = [0u8; 4096];
        for pipe in &mut self.pipes {
            // A noisy service cannot monopolize a supervision tick.
            for _ in 0..4 {
                let n = match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                };
                self.output.extend_from_slice(&buffer[..n]);
                let excess = self.output.len().saturating_sub(self.output_limit);
                self.dropped = self.dropped.saturating_add(excess as u64);
                self.output.drain(..excess);
            }
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Option<i32>> {
        self.drain()?;
        if self.status.is_some() {
            return Ok(self.status);
        }
        if exited(
            self.owned
                .child
                .as_ref()
                .ok_or("Service cleanup is pending")?,
        )? {
            self.stop()?;
        }
        Ok(self.status)
    }
    pub fn stop(&mut self) -> Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        let status = self.owned.finish().ok_or("Service cleanup is pending")?;
        self.status = Some(status.code().unwrap_or(-1));
        Ok(())
    }
}
fn exited(child: &Child) -> Result<bool> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    #[cfg(target_os = "linux")]
    {
        Ok(unsafe { info.si_pid() } != 0)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(info.si_pid != 0)
    }
}
struct Owned {
    child: Option<Child>,
    slot: Option<Slot>,
    reaper: Arc<Reaper>,
    cleanup_pending: bool,
    cleanup_completed: Arc<AtomicBool>,
}
fn group_exists(pid: u32) -> std::io::Result<bool> {
    if unsafe { libc::kill(-(pid as i32), 0) } == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(std::io::Error::last_os_error()),
    }
}
impl Owned {
    // Only the normal-return path waits. Failure, Drop and service stop keep
    // their existing short cleanup policy; ownership remains with the reaper.
    fn await_cleanup(&mut self, start: Instant, timeout: Duration) -> Result<()> {
        while self.cleanup_pending {
            // Observe the receipt before checking health/time, so a waiter
            // descheduled here cannot accept it against an earlier allowance.
            let completed = self.cleanup_completed.load(Ordering::Acquire);
            if !self.reaper.healthy.load(Ordering::SeqCst) {
                return Err(
                    "Child cleanup could not confirm ownership; restart requires review".into(),
                );
            }
            let remaining = timeout.saturating_sub(start.elapsed());
            // A completion first observed after the original deadline cannot
            // turn a timed-out operation into success.
            if remaining.is_zero() {
                return Err(
                    "Action exceeded its time budget while awaiting child group cleanup".into(),
                );
            }
            if completed {
                self.cleanup_pending = false;
                break;
            }
            thread::sleep(remaining.min(Duration::from_millis(10)));
        }
        Ok(())
    }
    fn finish(&mut self) -> Option<ExitStatus> {
        let mut child = self.child.take()?;
        // A successful non-reaping wait confirms this is still our child. Do
        // not signal an unowned/recycled PID if another component reaped it.
        if exited(&child).is_ok() {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
        }
        let start = Instant::now();
        let group = child.id();
        let mut observed = None;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    observed = Some(status);
                    match group_exists(group) {
                        Ok(false) => {
                            drop(self.slot.take());
                            self.cleanup_completed.store(true, Ordering::Release);
                            return observed;
                        }
                        Ok(true) => {}
                        Err(_) => {
                            self.reaper.healthy.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    self.reaper.healthy.store(false, Ordering::SeqCst);
                    break;
                }
            }
            if start.elapsed() >= CLEANUP {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        self.reaper
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(Pending {
                child,
                group: Some(group),
                completed: self.cleanup_completed.clone(),
                _slot: self
                    .slot
                    .take()
                    .expect("owned child retains its capacity slot"),
            });
        self.cleanup_pending = true;
        observed
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        self.finish();
    }
}
fn nonblocking(file: File) -> Result<File> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}
fn drain(pipes: &mut [File], output: &mut Vec<u8>, limit: usize) -> Result<()> {
    let mut bytes = [0; 8192];
    for pipe in pipes {
        // The total output cap bounds this loop even for a continuously-writing
        // child. Pipes impose backpressure without an unbounded temporary file.
        loop {
            match pipe.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => {
                    if output.len().saturating_add(n) > limit {
                        return Err("Action exceeded its output budget".into());
                    }
                    output.extend_from_slice(&bytes[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}

pub fn run(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
) -> Result<(i32, Vec<u8>)> {
    run_with_input(command, timeout, output_limit, &[])
}

/// Deliver a bounded private request over stdin while draining both output
/// pipes. A child that never reads its request cannot block the caller.
pub fn run_with_input(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
    input: &[u8],
) -> Result<(i32, Vec<u8>)> {
    if timeout.is_zero() || output_limit == 0 || output_limit > 16 * 1024 * 1024 {
        return Err("Invalid child execution budget".into());
    }
    if input.len() > 65536 {
        return Err("Child request exceeds its input budget".into());
    }
    let reaper = reaper()?;
    let slot = Slot::acquire()?;
    command
        .stdin(if input.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    #[cfg(target_os = "linux")]
    unsafe {
        let parent = std::process::id();
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent as i32 {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let start = Instant::now();
    watch::attach(command)?;
    let mut owned = Owned {
        child: Some(command.spawn()?),
        slot: Some(slot),
        reaper,
        cleanup_pending: false,
        cleanup_completed: Arc::new(AtomicBool::new(false)),
    };
    let child = owned.child.as_mut().expect("spawned child is owned");
    let stdout: OwnedFd = child
        .stdout
        .take()
        .ok_or("Missing child stdout pipe")?
        .into();
    let stderr: OwnedFd = child
        .stderr
        .take()
        .ok_or("Missing child stderr pipe")?
        .into();
    let mut stdin = child
        .stdin
        .take()
        .map(|pipe| {
            let fd: OwnedFd = pipe.into();
            nonblocking(File::from(fd))
        })
        .transpose()?;
    let mut written = 0;
    let mut pipes = [
        nonblocking(File::from(stdout))?,
        nonblocking(File::from(stderr))?,
    ];
    let mut output = Vec::new();
    let result = (|| -> Result<i32> {
        loop {
            if start.elapsed() >= timeout {
                return Err("Action exceeded its time budget".into());
            }
            drain(&mut pipes, &mut output, output_limit)?;
            if let Some(pipe) = &mut stdin {
                match pipe.write(&input[written..]) {
                    Ok(0) => return Err("Child closed its request pipe".into()),
                    Ok(n) => written += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e.into()),
                }
                if written == input.len() {
                    drop(stdin.take());
                }
            }
            if exited(
                owned
                    .child
                    .as_ref()
                    .expect("child remains owned until finish"),
            )? {
                let status = owned.finish().ok_or("Child cleanup is still pending")?;
                owned.await_cleanup(start, timeout)?;
                drain(&mut pipes, &mut output, output_limit)?;
                return Ok(status.code().unwrap_or(-1));
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    match result {
        Ok(code) => Ok((code, output)),
        Err(error) => {
            owned.finish();
            Err(format!(
                "{error}; termination requested{}",
                if owned.cleanup_pending {
                    "; cleanup pending"
                } else {
                    ""
                }
            )
            .into())
        }
    }
}

/// The internal worker calls this before opening its request or target files.
/// Linux also binds parent death in pre_exec; macOS uses a PID-bound kqueue.
pub fn guard_parent(parent: u32) -> Result<()> {
    if parent == 0
        || unsafe { libc::getppid() } != parent as i32
        || unsafe { libc::getpgrp() } != std::process::id() as i32
    {
        return Err("Native worker is not owned by its expected process group and parent".into());
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::FromRawFd;
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let queue = unsafe { OwnedFd::from_raw_fd(raw) };
        let change = libc::kevent {
            ident: parent as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        if unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { libc::getppid() } != parent as i32 {
            return Err("Native worker parent exited during registration".into());
        }
        thread::Builder::new()
            .name("athernex-parent-watch".into())
            .spawn(move || {
                let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                loop {
                    let result = unsafe {
                        libc::kevent(
                            queue.as_raw_fd(),
                            std::ptr::null(),
                            0,
                            &mut event,
                            1,
                            std::ptr::null(),
                        )
                    };
                    if result < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    // Any monitoring failure ends the worker rather than allowing
                    // unowned work to continue. The parent observes an interruption.
                    unsafe {
                        libc::kill(-libc::getpgrp(), libc::SIGKILL);
                        libc::_exit(86);
                    }
                }
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
