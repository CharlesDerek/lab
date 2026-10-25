use super::{Lifecycle, Phase, LOCK, NAME};
use crate::{installer, now_ms, windows_job, Process, Result};
use athernex_endpoint_native::windows_state::{self, Directory};
use std::{
    fs::File,
    path::{Path, PathBuf},
    ptr::null_mut,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_EXCEPTION_IN_SERVICE, ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
        ERROR_SERVICE_SPECIFIC_ERROR,
    },
    System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS,
    },
};

const STOP_LIMIT: Duration = Duration::from_secs(15);
pub(crate) struct Lease {
    directory: Directory,
    _file: File,
}
pub(crate) fn lease(state: &Directory) -> Result<Lease> {
    let directory = Directory::open(state.path())?;
    let file = directory.maintenance_lock(LOCK)?;
    Ok(Lease {
        directory,
        _file: file,
    })
}
struct Request {
    state: PathBuf,
    controller: PathBuf,
    agent: PathBuf,
}
struct Context {
    request: Request,
    handle: AtomicPtr<std::ffi::c_void>,
    lifecycle: Mutex<Lifecycle>,
    failure: Mutex<Option<String>>,
}
static CONTEXT: OnceLock<Context> = OnceLock::new();

impl Context {
    // Caller holds lifecycle across the API call: callback and worker cannot
    // reorder RUNNING/STOP_PENDING/STOPPED publications.
    fn publish(&self, state: &Lifecycle) -> Result<()> {
        let pending = matches!(state.phase, Phase::Starting | Phase::Stopping);
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: match state.phase {
                Phase::Starting => SERVICE_START_PENDING,
                Phase::Running => SERVICE_RUNNING,
                Phase::Stopping => SERVICE_STOP_PENDING,
                Phase::Stopped => SERVICE_STOPPED,
            },
            dwControlsAccepted: if state.phase == Phase::Running {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: if state.exit_code == 0 {
                0
            } else {
                ERROR_SERVICE_SPECIFIC_ERROR
            },
            dwServiceSpecificExitCode: state.exit_code,
            // Never advance checkpoints merely because a timer elapsed.
            dwCheckPoint: u32::from(pending),
            dwWaitHint: if pending { 20_000 } else { 0 },
        };
        if unsafe { SetServiceStatus(self.handle.load(Ordering::Acquire), &status) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn stopping(&self) -> Result<()> {
        let mut state = self
            .lifecycle
            .lock()
            .map_err(|_| "Service lifecycle lock poisoned")?;
        if state.stopping()? {
            self.publish(&state)?;
        }
        Ok(())
    }
}

unsafe extern "system" fn control(
    code: u32,
    _: u32,
    _: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> u32 {
    let Some(context) = CONTEXT.get() else {
        return ERROR_EXCEPTION_IN_SERVICE;
    };
    // No disk access, process wait, or cleanup in the SCM dispatcher callback.
    let Ok(mut state) = context.lifecycle.lock() else {
        return ERROR_EXCEPTION_IN_SERVICE;
    };
    match code {
        SERVICE_CONTROL_INTERROGATE => 0,
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            if !state.request_stop() {
                return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
            }
            if context.publish(&state).is_err() {
                ERROR_EXCEPTION_IN_SERVICE
            } else {
                0
            }
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn observation(
    lease: &Lease,
    phase: &str,
    launcher: Option<u32>,
    error: &str,
    output: &[u8],
) -> Result<()> {
    lease.directory.maintenance_directory("supervisor")?.write_maintenance_json("windows-service.json", &serde_json::json!({
        "schema":1,"service":NAME,"host_pid":std::process::id(),"checked_ms":now_ms(),
        "phase":phase,"launcher_pid":launcher,"error":error.chars().take(2048).collect::<String>(),
        "output_tail":String::from_utf8_lossy(output),"runtime_protection_verified":false
    }))
}

fn work(context: &Context) -> Result<()> {
    windows_state::require_local_system()?;
    let state = Directory::open(&context.request.state)?;
    let lease = lease(&state)?;
    observation(&lease, "starting", None, "", &[])?;
    let mut child: Option<windows_job::Service> = None;
    let result = (|| -> Result<()> {
        installer::require_complete(state.path())?;
        let executable = std::env::current_exe()?;
        crate::update::check_destination(&executable)?;
        let mut command = Process::new(executable);
        command
            .arg("launch")
            .arg(state.path())
            .arg(&context.request.controller)
            .arg(&context.request.agent);
        child = Some(windows_job::Service::start(&command, None, 8192)?);
        let child = child.as_mut().ok_or("Owned launcher unavailable")?;
        observation(&lease, "running", Some(child.id()), "", &[])?;
        {
            let mut state = context
                .lifecycle
                .lock()
                .map_err(|_| "Service lifecycle lock poisoned")?;
            state.running()?;
            context.publish(&state)?;
        }
        loop {
            if context
                .lifecycle
                .lock()
                .map_err(|_| "Service lifecycle lock poisoned")?
                .phase
                == Phase::Stopping
            {
                return Ok(());
            }
            if let Some(code) = child.poll()? {
                return Err(format!("Owned Windows launcher exited unexpectedly ({code})").into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    })();
    // Retain the host lease during ALL cleanup, including a partially failed
    // process creation whose job has moved into the reaper. No terminal SCM
    // status or executable replacement may precede confirmed ownership release.
    let pending = context.stopping();
    let started = Instant::now();
    loop {
        let local = child.as_mut().is_none_or(|child| child.stop().is_ok());
        if local && windows_job::cleanup_ready().is_ok() {
            break;
        }
        if started.elapsed() >= STOP_LIMIT {
            let _ = observation(
                &lease,
                "cleanup-unconfirmed",
                child.as_ref().map(|c| c.id()),
                "Owned job cleanup exceeded its deadline",
                child.as_ref().map_or(&[], |c| c.output()),
            );
            // Deliberately fail without claiming STOPPED. Process exit closes
            // the kill-on-close jobs; durable endpoint journals still gate
            // recovery if the kernel has not completed descendant termination.
            std::process::exit(1);
        }
        thread::sleep(Duration::from_millis(25));
    }
    let result = result.and(pending);
    observation(
        &lease,
        if result.is_ok() { "stopped" } else { "failed" },
        child.as_ref().map(|c| c.id()),
        &result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default(),
        child.as_ref().map_or(&[], |c| c.output()),
    )?;
    result
}

unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let Some(context) = CONTEXT.get() else {
        std::process::exit(1);
    };
    let name: Vec<u16> = NAME.encode_utf16().chain([0]).collect();
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null_mut()) };
    if handle.is_null() {
        std::process::exit(1);
    }
    context.handle.store(handle, Ordering::Release);
    let run = std::panic::catch_unwind(|| -> Result<()> {
        context.publish(
            &*context
                .lifecycle
                .lock()
                .map_err(|_| "Service lifecycle lock poisoned")?,
        )?;
        let result = work(context);
        context.stopping()?;
        let cleanup_started = Instant::now();
        while windows_job::cleanup_ready().is_err() {
            if cleanup_started.elapsed() >= STOP_LIMIT {
                std::process::exit(1);
            }
            thread::sleep(Duration::from_millis(25));
        }
        // All job handles, state pins and the host lease have been released by
        // work before the terminal status. Save the result BEFORE that RPC.
        let code = u32::from(result.is_err());
        *context
            .failure
            .lock()
            .map_err(|_| "Service result lock poisoned")? = result.err().map(|e| e.to_string());
        let mut state = context
            .lifecycle
            .lock()
            .map_err(|_| "Service lifecycle lock poisoned")?;
        state.stopped(true, code)?;
        context.publish(&state)
    });
    if !matches!(run, Ok(Ok(()))) {
        std::process::exit(1);
    }
}

pub fn run(state: &Path, controller: &Path, agent: &Path) -> Result<()> {
    // Connect immediately. Trust checks and all filesystem initialization run
    // in ServiceMain, after registering the control handler.
    CONTEXT
        .set(Context {
            request: Request {
                state: state.into(),
                controller: controller.into(),
                agent: agent.into(),
            },
            handle: AtomicPtr::new(null_mut()),
            lifecycle: Mutex::new(Lifecycle::new()),
            failure: Mutex::new(None),
        })
        .map_err(|_| "Windows service dispatcher may only start once")?;
    let mut name: Vec<u16> = NAME.encode_utf16().chain([0]).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if let Some(error) = CONTEXT
        .get()
        .ok_or("Service context unavailable")?
        .failure
        .lock()
        .map_err(|_| "Service result lock poisoned")?
        .take()
    {
        return Err(error.into());
    }
    Ok(())
}
