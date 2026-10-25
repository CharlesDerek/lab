//! Owned Windows process trees. JOB_LIST assigns ownership atomically with
//! CreateProcessW; there is no running-child-before-AssignProcessToJobObject gap.
//! Closing the noninherited job handle on owner death kills its descendants.
//! This is lifecycle ownership, not a sandbox for privileged/delegated services.
mod command;
#[cfg(test)]
mod debug;
mod desktop;
mod environment;
mod handles;
pub use command::Command;
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        JobObjects::{
            CreateJobObjectW, JobObjectBasicAccountingInformation,
            JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
            TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::{
            CreateProcessAsUserW, CreateProcessW, GetExitCodeProcess, ResumeThread,
            WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW,
        },
    },
};
const MAX_TREES: usize = 16;
const CLEANUP_GRACE: Duration = Duration::from_millis(100);
#[cfg(test)]
pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

/// Check the process-creation attributes before an installer stops a service.
pub(crate) fn check_lifetime_support() -> io::Result<()> {
    let job = job()?;
    let stdio = handles::Stdio::inherit()?;
    let jobs = [job.as_raw_handle()];
    let handles = stdio.handles();
    let _attributes = handles::Attributes::new(&jobs, &handles)?;
    Ok(())
}

/// Pending/unobservable cleanup must also prevent replacement of executables.
pub(crate) fn cleanup_ready() -> io::Result<()> {
    let state = reaper()?;
    if !state.healthy.load(Ordering::SeqCst) || state.pending.load(Ordering::SeqCst) != 0 {
        return Err(io::Error::other(
            "Windows process cleanup is pending or uncertain",
        ));
    }
    Ok(())
}

struct Reaper {
    healthy: AtomicBool,
    active: AtomicUsize,
    pending: AtomicUsize,
    trees: Mutex<Vec<Tree>>,
}
fn reaper() -> io::Result<Arc<Reaper>> {
    static REAPER: OnceLock<Result<Arc<Reaper>, String>> = OnceLock::new();
    REAPER
        .get_or_init(|| {
            let state = Arc::new(Reaper {
                healthy: AtomicBool::new(true),
                active: AtomicUsize::new(0),
                pending: AtomicUsize::new(0),
                trees: Mutex::new(Vec::with_capacity(MAX_TREES)),
            });
            let owned = state.clone();
            thread::Builder::new()
                .name("athernex-windows-reaper".into())
                .spawn(move || {
                    struct Health(Arc<Reaper>);
                    impl Drop for Health {
                        fn drop(&mut self) {
                            self.0.healthy.store(false, Ordering::SeqCst);
                        }
                    }
                    let _health = Health(owned.clone());
                    loop {
                        {
                            let mut trees = owned.trees.lock().unwrap_or_else(|e| {
                                owned.healthy.store(false, Ordering::SeqCst);
                                e.into_inner()
                            });
                            let mut index = 0;
                            while index < trees.len() {
                                match trees[index].cleanup() {
                                    Ok(true) => {
                                        trees.swap_remove(index);
                                        owned.pending.fetch_sub(1, Ordering::SeqCst);
                                    }
                                    Ok(false) => index += 1,
                                    Err(_) => {
                                        owned.healthy.store(false, Ordering::SeqCst);
                                        index += 1;
                                    }
                                }
                            }
                        }
                        thread::sleep(Duration::from_millis(25));
                    }
                })
                .map_err(|e| e.to_string())?;
            Ok(state)
        })
        .as_ref()
        .cloned()
        .map_err(|e| io::Error::other(e.clone()))
}
struct Slot(Arc<Reaper>);
impl Slot {
    fn reserve() -> io::Result<Self> {
        let state = reaper()?;
        if !state.healthy.load(Ordering::SeqCst) || state.pending.load(Ordering::SeqCst) != 0 {
            return Err(io::Error::other(
                "Windows process cleanup is pending or uncertain",
            ));
        }
        state
            .active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_TREES).then_some(n + 1)
            })
            .map_err(|_| io::Error::other("Windows process tree capacity is full"))?;
        Ok(Self(state))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Tree {
    job: OwnedHandle,
    process: OwnedHandle,
    slot: Slot,
    exit: Option<i32>,
    _desktop: Option<desktop::Context>,
}
impl Tree {
    fn root_exit(&mut self) -> io::Result<Option<i32>> {
        if self.exit.is_some() {
            return Ok(self.exit);
        }
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                // 259 is a valid exit code when the handle is signaled.
                self.exit = Some(code as i32);
                Ok(self.exit)
            }
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("Unexpected Windows process wait result")),
        }
    }
    fn empty(&self) -> io::Result<bool> {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            QueryInformationJobObject(
                self.job.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info.ActiveProcesses == 0)
    }
    fn terminate(&self) -> io::Result<()> {
        if unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn cleanup(&mut self) -> io::Result<bool> {
        // Empty job plus signaled original process, never just root exit/PID.
        if self.empty()? && self.root_exit()?.is_some() {
            return Ok(true);
        }
        self.terminate()?;
        Ok(false)
    }
}
/// A managed child is observed exited only after its entire owned job is empty.
pub(crate) struct Child {
    tree: Option<Tree>,
    initial_thread: Option<OwnedHandle>,
    pid: u32,
    exit: Option<i32>,
}
impl Child {
    fn resume_scanner(&mut self) -> io::Result<()> {
        let thread = self
            .initial_thread
            .take()
            .ok_or_else(|| io::Error::other("Scanner has no suspended initial thread"))?;
        // Exactly one suspension was requested at creation. Never loop to undo
        // an unexpected suspension or silently accept an already running child.
        let previous = unsafe { ResumeThread(thread.as_raw_handle()) };
        if previous == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        if previous != 1 {
            return Err(io::Error::other("Unexpected scanner suspension count"));
        }
        Ok(())
    }
    pub fn id(&self) -> u32 {
        self.pid
    }
    pub(crate) fn creation_time(&self) -> io::Result<u64> {
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let process = &self
            .tree
            .as_ref()
            .ok_or_else(|| io::Error::other("Owned process already ended"))?
            .process;
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        if unsafe {
            GetProcessTimes(
                process.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
    pub fn poll(&mut self) -> io::Result<Option<i32>> {
        let Some(tree) = self.tree.as_mut() else {
            return Ok(self.exit);
        };
        let Some(code) = tree.root_exit()? else {
            return Ok(None);
        };
        if !tree.empty()? {
            tree.terminate()?;
            return Ok(None);
        }
        self.exit = Some(code);
        self.tree.take();
        Ok(self.exit)
    }
    pub fn stop(&mut self) -> io::Result<()> {
        let start = Instant::now();
        while let Some(tree) = self.tree.as_mut() {
            if tree.cleanup()? {
                self.exit = tree.exit;
                self.tree.take();
                return Ok(());
            }
            if start.elapsed() >= CLEANUP_GRACE {
                return Err(io::Error::other("Windows job cleanup remains pending"));
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
}
/// A long-lived owned process with continuously drained, bounded diagnostics.
/// The existing Child reaper retains ownership if synchronous cleanup stalls.
pub(crate) struct Service {
    child: Child,
    pipe: handles::Pipe,
    output: Vec<u8>,
    limit: usize,
}
impl Service {
    /// Returns only after the original process and its entire job have ended.
    /// On uncertainty callers must retain persistent confinement rules.
    pub(crate) fn stop(&mut self) -> io::Result<()> {
        self.child.stop()
    }
    pub(crate) fn start_scanner(
        command: &Command,
        token: &athernex_endpoint_native::windows_scanner::Token,
        limit: usize,
        before_resume: impl FnOnce(u32, u64) -> io::Result<()>,
    ) -> io::Result<Self> {
        let (stdio, pipe) = handles::Stdio::capture()?;
        let child = command.spawn_with_token(&stdio, Some(token))?;
        drop(stdio);
        let mut service = Self {
            child,
            pipe,
            output: Vec::new(),
            limit,
        };
        service.verify_scanner(token.logon_sid())?;
        // The caller durably records ownership before any scanner instruction
        // runs. Failure (including panic) drops the still-suspended owned job.
        before_resume(service.id(), service.creation_time()?)?;
        service.child.resume_scanner()?;
        Ok(service)
    }
    pub(crate) fn verify_scanner(&self, logon: &str) -> io::Result<()> {
        use std::os::windows::io::{AsHandle, FromRawHandle};
        use windows_sys::Win32::{Security::TOKEN_QUERY, System::Threading::OpenProcessToken};
        let tree = self
            .child
            .tree
            .as_ref()
            .ok_or_else(|| io::Error::other("Scanner process ended"))?;
        let mut raw = null_mut();
        if unsafe { OpenProcessToken(tree.process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        athernex_endpoint_native::windows_scanner::verify(token.as_handle(), logon)
            .map_err(io::Error::other)
    }
    pub(crate) fn start(command: &Command, input: Option<&[u8]>, limit: usize) -> io::Result<Self> {
        let (stdio, pipe) = match input {
            Some(input) => handles::Stdio::capture_with_input(input)?,
            None => handles::Stdio::capture()?,
        };
        let child = command.spawn_with(&stdio)?;
        drop(stdio);
        Ok(Self {
            child,
            pipe,
            output: Vec::new(),
            limit,
        })
    }
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }
    pub(crate) fn creation_time(&self) -> io::Result<u64> {
        self.child.creation_time()
    }
    pub(crate) fn output(&self) -> &[u8] {
        &self.output
    }
    pub(crate) fn poll(&mut self) -> io::Result<Option<i32>> {
        self.pipe.drain_diagnostics(&mut self.output, self.limit)?;
        self.child.poll()
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.stop().is_ok() {
            return;
        }
        if let Some(tree) = self.tree.take() {
            let state = tree.slot.0.clone();
            state.pending.fetch_add(1, Ordering::SeqCst);
            // Keep the process/job handles AND capacity slot until cleanup is
            // confirmed. API errors in the reaper permanently stop admission.
            let mut pending = state.trees.lock().unwrap_or_else(|e| {
                state.healthy.store(false, Ordering::SeqCst);
                e.into_inner()
            });
            pending.push(tree);
        }
    }
}
fn job() -> io::Result<OwnedHandle> {
    let handle = handles::owned(unsafe { CreateJobObjectW(null(), null()) })?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            handle.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}
fn spawn(
    application: &[u16],
    line: &mut [u16],
    directory: Option<&[u16]>,
    environment: &[u16],
    stdio: &handles::Stdio,
    token: Option<&athernex_endpoint_native::windows_scanner::Token>,
) -> io::Result<Child> {
    let mut desktop = token.map(desktop::Context::create).transpose()?;
    let slot = Slot::reserve()?;
    let job = job()?;
    if token.is_some() {
        use windows_sys::Win32::System::JobObjects::{
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.ProcessMemoryLimit = 2 * 1024 * 1024 * 1024;
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let jobs: [HANDLE; 1] = [job.as_raw_handle()];
    let handles = stdio.handles();
    let mut attributes = handles::Attributes::new(&jobs, &handles)?;
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.as_mut_ptr();
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // JOB_LIST is applied by the kernel during creation; failure never falls
    // back to spawning an unowned child. Only the three stdio handles inherit.
    let created = if let Some(token) = token {
        token.verify().map_err(io::Error::other)?;
        let security = token.process_security().map_err(io::Error::other)?;
        let attributes = security.attributes();
        // The creation worker has already exited with its job empty. Only this
        // restricted scanner connects to its private station and desktop.
        startup.StartupInfo.lpDesktop = desktop.as_mut().unwrap().startup.as_mut_ptr();
        let flags = EXTENDED_STARTUPINFO_PRESENT
            | CREATE_UNICODE_ENVIRONMENT
            | CREATE_NO_WINDOW
            | CREATE_SUSPENDED;
        #[cfg(test)]
        let flags = flags
            | if debug::enabled() {
                windows_sys::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS
            } else {
                0
            };
        unsafe {
            CreateProcessAsUserW(
                token.handle().as_raw_handle(),
                application.as_ptr(),
                line.as_mut_ptr(),
                &attributes,
                &attributes,
                1,
                flags,
                environment.as_ptr().cast(),
                directory.map_or(null(), |d| d.as_ptr()),
                &startup.StartupInfo,
                &mut info,
            )
        }
    } else {
        unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                directory.map_or(null(), |d| d.as_ptr()),
                &startup.StartupInfo,
                &mut info,
            )
        }
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    // Successful CreateProcessW returns two valid owned handles. Capture both
    // without a fallible operation between process creation and ownership.
    use std::os::windows::io::FromRawHandle;
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let initial_thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
    let initial_thread = token.is_some().then_some(initial_thread);
    Ok(Child {
        tree: Some(Tree {
            job,
            process,
            slot,
            exit: None,
            _desktop: desktop,
        }),
        initial_thread,
        pid: info.dwProcessId,
        exit: None,
    })
}

pub(crate) fn run(
    command: &Command,
    timeout: Duration,
    limit: usize,
) -> io::Result<(i32, Vec<u8>)> {
    let (stdio, mut pipe) = handles::Stdio::capture()?;
    let mut child = command.spawn_with(&stdio)?;
    drop(stdio); // Only children hold pipe write ends from this point onward.
    collect(&mut child, &mut pipe, timeout, limit)
}

pub(crate) fn run_with_input(
    command: &Command,
    timeout: Duration,
    limit: usize,
    input: &[u8],
) -> io::Result<(i32, Vec<u8>)> {
    let (stdio, mut pipe) = handles::Stdio::capture_with_input(input)?;
    let mut child = command.spawn_with(&stdio)?;
    drop(stdio);
    collect(&mut child, &mut pipe, timeout, limit)
}

fn collect(
    child: &mut Child,
    pipe: &mut handles::Pipe,
    timeout: Duration,
    limit: usize,
) -> io::Result<(i32, Vec<u8>)> {
    let start = Instant::now();
    let mut output = Vec::new();
    loop {
        pipe.drain(&mut output, limit)?;
        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Action exceeded its time budget",
            ));
        }
        if let Some(code) = child.poll()? {
            // No owned writer remains. Drain all buffered output, preserving
            // the original deadline even if the OS chose a larger pipe buffer.
            loop {
                let drained = pipe.drain(&mut output, limit)?;
                if start.elapsed() >= timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Output drain exceeded its time budget",
                    ));
                }
                if drained {
                    break;
                }
            }
            return Ok((code, output));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn guard_parent(parent: u32) -> io::Result<()> {
    use windows_sys::{
        Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
        Win32::{
            Foundation::RtlNtStatusToDosError,
            System::{
                JobObjects::IsProcessInJob,
                Threading::{
                    GetCurrentProcess, OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_SYNCHRONIZE,
                },
            },
        },
    };
    let mut info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessBasicInformation,
            (&mut info as *mut PROCESS_BASIC_INFORMATION).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    if parent == 0 || info.InheritedFromUniqueProcessId != parent as usize {
        return Err(io::Error::other(
            "Windows worker has a different creating parent",
        ));
    }
    let process = handles::owned(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, parent) })?;
    let mut member = 0;
    if unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut member) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if member == 0 || unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return Err(io::Error::other(
            "Windows worker needs a live parent and process-job ownership",
        ));
    }
    // An internal launch contract, not a privilege boundary. The creator uses
    // JOB_LIST for ownership before user code; job close enforces parent death.
    Ok(())
}

#[doc(hidden)]
pub fn desktop_worker(parent: u32) -> crate::Result<()> {
    desktop::worker_main(parent)
}

#[cfg(test)]
mod tests;
