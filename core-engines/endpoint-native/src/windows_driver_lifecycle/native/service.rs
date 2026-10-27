//! The fixed LocalSystem coordinator is distinct from the ordinary management
//! service. A caller may open it only using a durable successful-create receipt;
//! matching SCM configuration is never sufficient to adopt an unknown service.
use super::*;
use athernex_endpoint_protocol::{hex_id, windows_filter_package::Member};
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{
        atomic::{AtomicBool, AtomicPtr, Ordering},
        Arc, Mutex, OnceLock,
    },
};
use windows_sys::Win32::{
    Foundation::{
        LocalFree, ERROR_CALL_NOT_IMPLEMENTED, ERROR_EXCEPTION_IN_SERVICE,
        ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_SPECIFIC_ERROR, FILETIME, WAIT_TIMEOUT,
    },
    Security::{Authorization::*, *},
    System::{SystemServices::ACCESS_ALLOWED_ACE_TYPE, Threading::*},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperSpec {
    pub program: PathBuf,
    pub transaction: String,
    pub nonce: String,
    pub binary: Member,
    pub owner_system: bool,
}
impl HelperSpec {
    pub fn validate(&self) -> Result<()> {
        if self.binary.bytes == 0
            || self.binary.bytes > 64 * 1024 * 1024
            || !hex_id(&self.binary.sha256)
        {
            return Err("Invalid coordinator executable approval".into());
        }
        if !hex_id(&self.transaction)
            || !hex_id(&self.nonce)
            || !self.program.is_absolute()
            || self.program.file_name().and_then(|v| v.to_str()) != Some("management.exe")
        {
            return Err("Invalid fixed coordinator specification".into());
        }
        let value = self
            .program
            .to_str()
            .ok_or("Non-Unicode coordinator path")?;
        if value.contains(['"', '\0']) || value.chars().any(char::is_control) {
            return Err("Invalid coordinator command path".into());
        }
        Ok(())
    }
    fn command(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "\"{}\" windows-driver-coordinator {} {}",
            self.program.display(),
            self.transaction,
            self.nonce
        ))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperStatus {
    pub state: u32,
    pub pid: u32,
    pub created: Option<u64>,
    pub win32_exit_code: u32,
    pub service_exit_code: u32,
}
pub struct Helper {
    handle: ServiceHandle,
    spec: HelperSpec,
    _parent: PinnedDirectory,
    _binary: File,
}
struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn secure(handle: &ServiceHandle, owner_system: bool) -> Result<()> {
    let mut raw = null_mut();
    bool_result(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(if owner_system {
                "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"
            } else {
                "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"
            })?
            .as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            null_mut(),
        )
    })?;
    let _raw = Allocation(raw);
    let mut owner = null_mut();
    let mut defaulted = 0;
    let mut dacl = null_mut();
    let mut present = 0;
    bool_result(unsafe { GetSecurityDescriptorOwner(raw, &mut owner, &mut defaulted) })?;
    bool_result(unsafe {
        GetSecurityDescriptorDacl(raw, &mut present, &mut dacl, &mut defaulted)
    })?;
    if owner.is_null() || present == 0 || dacl.is_null() {
        return Err("Coordinator ACL construction failed".into());
    }
    let code = unsafe {
        SetSecurityInfo(
            handle.0,
            SE_SERVICE,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    security(handle, owner_system)
}
fn security(handle: &ServiceHandle, owner_system: bool) -> Result<()> {
    let mut needed = 0;
    unsafe {
        QueryServiceObjectSecurity(
            handle.0,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 || needed > 16384 {
        return Err("Coordinator security size refused".into());
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let allocated = needed;
    bool_result(unsafe {
        QueryServiceObjectSecurity(
            handle.0,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            buffer.as_mut_ptr().cast(),
            allocated,
            &mut needed,
        )
    })?;
    if needed > allocated {
        return Err("Coordinator security changed size".into());
    }
    let descriptor = buffer.as_mut_ptr().cast();
    let mut owner = null_mut();
    let mut defaulted = 0;
    bool_result(unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) })?;
    if owner.is_null()
        || unsafe {
            IsWellKnownSid(
                owner,
                if owner_system {
                    WinLocalSystemSid
                } else {
                    WinBuiltinAdministratorsSid
                },
            )
        } == 0
    {
        return Err("Coordinator owner differs from the recorded trusted creator".into());
    }
    let mut dacl = null_mut();
    let mut present = 0;
    bool_result(unsafe {
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
    })?;
    let mut control = 0;
    let mut revision = 0;
    bool_result(unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) })?;
    if present == 0
        || dacl.is_null()
        || control & SE_DACL_PROTECTED == 0
        || unsafe { (*dacl).AceCount } != 2
    {
        return Err("Coordinator must have an exact protected service ACL".into());
    }
    let mut found = [false; 2];
    for i in 0..2 {
        let mut ace = null_mut();
        bool_result(unsafe { GetAce(dacl, i, &mut ace) })?;
        let value = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if value.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || value.Header.AceFlags != 0
            || usize::from(value.Header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            || (value.Mask != windows_sys::Win32::Foundation::GENERIC_ALL
                && value.Mask != SERVICE_ALL_ACCESS)
        {
            return Err("Coordinator service grant differs".into());
        }
        let sid = std::ptr::addr_of!(value.SidStart).cast_mut().cast();
        let index = if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0 {
            0
        } else if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0 {
            1
        } else {
            return Err("Coordinator service grants an unapproved principal".into());
        };
        if found[index] {
            return Err("Duplicate coordinator service grant".into());
        }
        found[index] = true;
    }
    if found != [true, true] {
        return Err("Coordinator service ACL is incomplete".into());
    }
    Ok(())
}
impl Helper {
    fn pin(spec: &HelperSpec) -> Result<(PinnedDirectory, File)> {
        spec.validate()?;
        let parent =
            PinnedDirectory::open(spec.program.parent().ok_or("Coordinator parent missing")?)?;
        let binary = trust::pin(&spec.program, &spec.binary)?;
        Ok((parent, binary))
    }
    fn check(&self) -> Result<()> {
        security(&self.handle, self.spec.owner_system)?;
        let actual = configuration(&self.handle)?;
        if actual
            != (ServiceConfiguration {
                service_type: SERVICE_WIN32_OWN_PROCESS,
                start_type: SERVICE_DEMAND_START,
                error_control: SERVICE_ERROR_NORMAL,
                binary_path: self.spec.command()?,
                load_order_group: String::new(),
                dependencies: Vec::new(),
                account: "LocalSystem".into(),
            })
        {
            return Err("Coordinator registration differs from its ownership receipt".into());
        }
        Ok(())
    }
    /// A failed return after CreateService may leave a service. Never delete or
    /// adopt it automatically; the caller has persisted a creation intent.
    pub fn create(spec: &HelperSpec) -> Result<Self> {
        crate::windows_state::require_administrator()?;
        if spec.owner_system != crate::windows_state::require_local_system().is_ok() {
            return Err("Coordinator creator identity differs".into());
        }
        let (parent, binary) = Self::pin(spec)?;
        trust::verify_executable(&spec.program, &spec.binary)?;
        let manager = scm(SC_MANAGER_CREATE_SERVICE)?;
        let handle = unsafe {
            CreateServiceW(
                manager.0,
                wide(HELPER)?.as_ptr(),
                wide(HELPER)?.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                wide(spec.command()?)?.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
            )
        };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = Self {
            handle: ServiceHandle(handle),
            spec: spec.clone(),
            _parent: parent,
            _binary: binary,
        };
        secure(&result.handle, spec.owner_system)?;
        result.check()?;
        Ok(result)
    }
    /// Only the owner with a durable successful CreateService receipt may call.
    pub fn open_owned(spec: &HelperSpec) -> Result<Self> {
        let (parent, binary) = Self::pin(spec)?;
        let manager = scm(SC_MANAGER_CONNECT)?;
        let handle = open_service(
            &manager,
            HELPER,
            SERVICE_QUERY_CONFIG
                | SERVICE_QUERY_STATUS
                | SERVICE_START
                | SERVICE_STOP
                | 0x10000
                | 0x20000,
        )?
        .ok_or("Owned coordinator service is missing")?;
        let result = Self {
            handle,
            spec: spec.clone(),
            _parent: parent,
            _binary: binary,
        };
        result.check()?;
        Ok(result)
    }
    pub fn start(&self) -> Result<()> {
        self.check()?;
        trust::verify_executable(&self.spec.program, &self.spec.binary)?;
        if self.status()?.state != SERVICE_STOPPED {
            return Err("Coordinator is not stopped before its one start".into());
        }
        bool_result(unsafe { StartServiceW(self.handle.0, 0, null()) })
    }
    pub fn status(&self) -> Result<HelperStatus> {
        self.check()?;
        let value = service_observation(&self.handle)?;
        // SCM documents the PID as invalid in STOPPED and potentially invalid
        // in START/STOP_PENDING. Never open such a PID or infer owner liveness.
        let pid_valid = matches!(
            value.state,
            SERVICE_RUNNING | SERVICE_PAUSED | SERVICE_PAUSE_PENDING | SERVICE_CONTINUE_PENDING
        );
        let created = if !pid_valid || value.process_id == 0 {
            None
        } else {
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    value.process_id,
                )
            };
            if handle.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let process = unsafe { OwnedHandle::from_raw_handle(handle) };
            let mut image = [0u16; 1024];
            let mut length = image.len() as u32;
            bool_result(unsafe {
                QueryFullProcessImageNameW(
                    process.as_raw_handle(),
                    0,
                    image.as_mut_ptr(),
                    &mut length,
                )
            })?;
            if length == 0 || length as usize >= image.len() {
                return Err("Coordinator process image unavailable".into());
            }
            let image = PathBuf::from(String::from_utf16(&image[..length as usize])?);
            let _parent =
                PinnedDirectory::open(image.parent().ok_or("Process image parent missing")?)?;
            let actual = trust::pin(&image, &self.spec.binary)?;
            if identity(&actual)? != identity(&self._binary)? {
                return Err("Coordinator PID belongs to another image object".into());
            }
            let (mut created, mut exited, mut kernel, mut user) = (
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
            );
            bool_result(unsafe {
                GetProcessTimes(
                    process.as_raw_handle(),
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            })?;
            if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT {
                return Err("Coordinator ended during observation".into());
            }
            Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
        };
        Ok(HelperStatus {
            state: value.state,
            pid: if pid_valid { value.process_id } else { 0 },
            created,
            win32_exit_code: value.win32_exit_code,
            service_exit_code: value.service_exit_code,
        })
    }
    /// No automatic stop/kill is provided: a timed-out native operation retains
    /// ownership. Deletion is allowed only after the journal and SCM are terminal.
    pub fn delete_stopped(&self) -> Result<()> {
        if self.status()?.state != SERVICE_STOPPED {
            return Err("Coordinator is still active".into());
        }
        bool_result(unsafe { DeleteService(self.handle.0) })
    }
}

type Work = Box<dyn FnOnce(Arc<AtomicBool>) -> Result<()> + Send>;
struct Context {
    work: Mutex<Option<Work>>,
    stop: Arc<AtomicBool>,
    handle: AtomicPtr<c_void>,
    state: Mutex<u32>,
    failed: AtomicBool,
}
static CONTEXT: OnceLock<Context> = OnceLock::new();
impl Context {
    fn publish(&self, state: u32, failed: bool) -> Result<()> {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: if failed {
                ERROR_SERVICE_SPECIFIC_ERROR
            } else {
                0
            },
            dwServiceSpecificExitCode: u32::from(failed),
            dwCheckPoint: u32::from(
                state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING,
            ),
            dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
                20000
            } else {
                0
            },
        };
        bool_result(unsafe { SetServiceStatus(self.handle.load(Ordering::Acquire), &status) })
    }
}
unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    let Some(context) = CONTEXT.get() else {
        return ERROR_EXCEPTION_IN_SERVICE;
    };
    let Ok(mut state) = context.state.lock() else {
        return ERROR_EXCEPTION_IN_SERVICE;
    };
    match code {
        SERVICE_CONTROL_INTERROGATE => 0,
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            if *state != SERVICE_RUNNING {
                return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
            }
            context.stop.store(true, Ordering::Release);
            *state = SERVICE_STOP_PENDING;
            if context.publish(*state, false).is_ok() {
                0
            } else {
                ERROR_EXCEPTION_IN_SERVICE
            }
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
unsafe extern "system" fn main(_: u32, _: *mut *mut u16) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        crate::windows_state::require_local_system()?;
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(wide(HELPER)?.as_ptr(), Some(control), null_mut())
        };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        context.handle.store(handle, Ordering::Release);
        {
            let mut state = context
                .state
                .lock()
                .map_err(|_| "Coordinator lifecycle poisoned")?;
            context.publish(*state, false)?;
            *state = SERVICE_RUNNING;
            context.publish(*state, false)?;
        }
        let work = context
            .work
            .lock()
            .map_err(|_| "Coordinator work poisoned")?
            .take()
            .ok_or("Coordinator work already consumed")?;
        work(context.stop.clone())
    }));
    let failed = !matches!(result, Ok(Ok(())));
    context.failed.store(failed, Ordering::Release);
    if let Ok(mut state) = context.state.lock() {
        *state = SERVICE_STOPPED;
        if !context.handle.load(Ordering::Acquire).is_null()
            && context.publish(*state, failed).is_err()
        {
            context.failed.store(true, Ordering::Release);
        }
    }
}
pub fn serve(work: impl FnOnce(Arc<AtomicBool>) -> Result<()> + Send + 'static) -> Result<()> {
    crate::windows_state::require_local_system()?;
    CONTEXT
        .set(Context {
            work: Mutex::new(Some(Box::new(work))),
            stop: Arc::new(AtomicBool::new(false)),
            handle: AtomicPtr::new(null_mut()),
            state: Mutex::new(SERVICE_START_PENDING),
            failed: AtomicBool::new(false),
        })
        .map_err(|_| "Coordinator dispatcher already initialized")?;
    let mut name = wide(HELPER)?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    bool_result(unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) })?;
    if CONTEXT
        .get()
        .is_none_or(|c| c.failed.load(Ordering::Acquire))
    {
        return Err("Coordinator service failed; inspect its private transaction".into());
    }
    Ok(())
}

/// Read-only absence is used only after an owned deletion intent, never to
/// adopt an existing matching registration or infer a worker's termination.
pub fn helper_absent() -> Result<bool> {
    let manager = scm(SC_MANAGER_CONNECT)?;
    Ok(open_service(&manager, HELPER, SERVICE_QUERY_STATUS)?.is_none())
}
