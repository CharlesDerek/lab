//! A private, noninteractive station/desktop for one restricted scanner.
//! Only an owned, short-lived SYSTEM worker changes its process station. The
//! multithreaded supervisor never attaches to the scanner's USER objects.
use super::{handles, Command, Service};
use athernex_endpoint_native::windows_scanner::Token;
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read, Write},
    mem::{size_of, size_of_val},
    os::windows::io::AsRawHandle,
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, GetLastError, LocalFree, DUPLICATE_SAME_ACCESS, ERROR_ALREADY_EXISTS,
        GENERIC_ALL, HANDLE, WAIT_OBJECT_0,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    System::{
        RemoteDesktop::ProcessIdToSessionId,
        StationsAndDesktops::{
            CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
            GetProcessWindowStation, GetUserObjectInformationW, SetProcessWindowStation, HDESK,
            HWINSTA, UOI_NAME, UOI_TYPE, USER_OBJECT_INFORMATION_INDEX,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, OpenEventW, SetEvent, WaitForSingleObject,
            SYNCHRONIZATION_SYNCHRONIZE,
        },
    },
};

const READY: &[u8] = b"ATHERNEX_DESKTOP_READY ";
const TIMEOUT: Duration = Duration::from_secs(15);
const CWF_CREATE_ONLY: u32 = 1;
const DESKTOP_NAME: &str = "Scanner";

struct Descriptor(*mut std::ffi::c_void);
impl Descriptor {
    fn new(sddl: &str) -> io::Result<Self> {
        let mut raw = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(raw))
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Station(HWINSTA);
struct Desktop(HDESK);
// These handles only pin object lifetime in the supervisor, which never calls
// SetProcessWindowStation/SetThreadDesktop on them. The reaper may close them.
unsafe impl Send for Station {}
unsafe impl Send for Desktop {}
impl Drop for Station {
    fn drop(&mut self) {
        unsafe {
            CloseWindowStation(self.0);
        }
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        unsafe {
            CloseDesktop(self.0);
        }
    }
}
pub(super) struct Context {
    // Close the desktop before its station. Retain both through owned-job cleanup.
    _desktop: Desktop,
    _station: Station,
    #[cfg(test)]
    pub(super) name: String,
    pub(super) startup: Vec<u16>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    nonce: String,
    logon: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    station: usize,
    desktop: usize,
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn station_name(nonce: &str) -> String {
    format!("AthernexScanner-{nonce}")
}
fn event_name(nonce: &str) -> String {
    format!("Local\\AthernexScannerDesktop-{nonce}")
}
fn require_system_session() -> io::Result<()> {
    athernex_endpoint_native::windows_state::require_local_system().map_err(io::Error::other)?;
    let mut session = u32::MAX;
    if unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if session != 0 {
        return Err(io::Error::other("Scanner desktop requires session zero"));
    }
    Ok(())
}
pub(super) fn object_text(
    handle: HANDLE,
    field: USER_OBJECT_INFORMATION_INDEX,
) -> io::Result<String> {
    let mut data = [0u16; 256];
    let mut bytes = 0;
    if unsafe {
        GetUserObjectInformationW(
            handle,
            field,
            data.as_mut_ptr().cast(),
            size_of_val(&data) as u32,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let units = bytes as usize / 2;
    if bytes % 2 != 0 || units == 0 || units > data.len() || data[units - 1] != 0 {
        return Err(io::Error::other("Invalid scanner USER object information"));
    }
    String::from_utf16(&data[..units - 1]).map_err(io::Error::other)
}
fn duplicate(process: HANDLE, raw: usize) -> io::Result<HANDLE> {
    if raw == 0 || raw > isize::MAX as usize {
        return Err(io::Error::other("Invalid scanner desktop worker handle"));
    }
    let mut copy = null_mut();
    if unsafe {
        DuplicateHandle(
            process,
            raw as HANDLE,
            GetCurrentProcess(),
            &mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(copy)
}
fn worker_command() -> io::Result<Command> {
    #[cfg(not(test))]
    {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("windows-desktop-worker")
            .arg(std::process::id().to_string());
        Ok(command)
    }
    #[cfg(test)]
    {
        let mut command = super::tests::command("desktop-worker", std::path::Path::new("unused"));
        command.env(
            "ATHERNEX_WINDOWS_FIXTURE_PARENT",
            std::process::id().to_string(),
        );
        Ok(command)
    }
}
impl Context {
    pub(super) fn create(token: &Token) -> io::Result<Self> {
        require_system_session()?;
        token.verify().map_err(io::Error::other)?;
        let request = Request {
            nonce: crate::secret().map_err(io::Error::other)?,
            logon: token.logon_sid().into(),
        };
        let event_sd = Descriptor::new("O:SYG:SYD:P(A;;GA;;;SY)")?;
        let raw = unsafe {
            CreateEventW(
                &event_sd.attributes(),
                1,
                0,
                wide(&event_name(&request.nonce)).as_ptr(),
            )
        };
        let error = unsafe { GetLastError() };
        let event = handles::owned(raw)?;
        if error == ERROR_ALREADY_EXISTS {
            return Err(io::Error::other(
                "Scanner desktop handoff object already exists",
            ));
        }
        let mut worker = Service::start(
            &worker_command()?,
            Some(&serde_json::to_vec(&request)?),
            4096,
        )?;
        let deadline = Instant::now() + TIMEOUT;
        let reply: Reply = loop {
            if worker.poll()?.is_some() {
                return Err(io::Error::other(format!(
                    "Scanner desktop worker ended before handoff: {}",
                    String::from_utf8_lossy(worker.output())
                )));
            }
            if let Some(start) = worker
                .output()
                .windows(READY.len())
                .position(|s| s == READY)
            {
                let tail = &worker.output()[start + READY.len()..];
                if let Some(end) = tail.iter().position(|b| *b == b'\n') {
                    break serde_json::from_slice(&tail[..end])?;
                }
            }
            if worker.output().len() == 4096 || Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Scanner desktop handoff did not complete",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        };
        // Duplicate from our original owned process handle, never reopen a PID.
        let process = worker
            .child
            .tree
            .as_ref()
            .ok_or_else(|| io::Error::other("Scanner desktop worker ownership lost"))?
            .process
            .as_raw_handle();
        let station = Station(duplicate(process, reply.station)?);
        let desktop = Desktop(duplicate(process, reply.desktop)?);
        let name = station_name(&request.nonce);
        if object_text(station.0, UOI_TYPE)? != "WindowStation"
            || object_text(desktop.0, UOI_TYPE)? != "Desktop"
            || object_text(station.0, UOI_NAME)? != name
            || object_text(desktop.0, UOI_NAME)? != DESKTOP_NAME
        {
            return Err(io::Error::other(
                "Scanner desktop worker returned different USER objects",
            ));
        }
        if unsafe { SetEvent(event.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // No scanner code may run while any privileged worker remains in its
        // station. Service::poll proves root exit AND an empty owned job.
        loop {
            if let Some(code) = worker.poll()? {
                if code != 0 {
                    return Err(io::Error::other(
                        "Scanner desktop worker failed during handoff",
                    ));
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Scanner desktop worker did not exit",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(Self {
            _desktop: desktop,
            _station: station,
            startup: wide(&format!("{name}\\{DESKTOP_NAME}")),
            #[cfg(test)]
            name,
        })
    }
}

/// Internal owned-worker entry point. Must execute in a separate process.
pub(super) fn worker_main(parent: u32) -> crate::Result<()> {
    super::guard_parent(parent)?;
    require_system_session()?;
    let mut input = Vec::new();
    io::stdin().take(4097).read_to_end(&mut input)?;
    if input.len() > 4096 {
        return Err("Scanner desktop request exceeds byte budget".into());
    }
    let request: Request = serde_json::from_slice(&input)?;
    let sid = request
        .logon
        .strip_prefix("S-1-5-5-")
        .ok_or("Invalid scanner desktop logon SID")?;
    let parts: Vec<_> = sid.split('-').collect();
    if !athernex_endpoint_protocol::hex_id(&request.nonce)
        || parts.len() != 2
        || parts
            .iter()
            .any(|p| p.parse::<u32>().is_err() || p.parse::<u32>().unwrap().to_string() != *p)
    {
        return Err("Invalid scanner desktop request".into());
    }
    let event = handles::owned(unsafe {
        OpenEventW(
            SYNCHRONIZATION_SYNCHRONIZE,
            0,
            wide(&event_name(&request.nonce)).as_ptr(),
        )
    })?;
    // SYSTEM owns the objects. Scanner receives object-specific rights and
    // READ_CONTROL, never DELETE/WRITE_DAC/WRITE_OWNER or WINSTA_CREATEDESKTOP.
    // Native Windows USER32 initialization requires WINSTA_EXITWINDOWS even
    // here in session zero; grant it only on this new private station. The
    // scanner still has no shutdown privilege. No shared station ACL is changed.
    // The low label permits USER32 writes within this private station only.
    let station_sd = Descriptor::new(&format!(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;0x20377;;;{})S:(ML;;NW;;;LW)",
        request.logon
    ))?;
    let desktop_sd = Descriptor::new(&format!(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;0x201ff;;;{})S:(ML;;NW;;;LW)",
        request.logon
    ))?;
    let original = unsafe { GetProcessWindowStation() };
    if original.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let raw = unsafe {
        CreateWindowStationW(
            wide(&station_name(&request.nonce)).as_ptr(),
            CWF_CREATE_ONLY,
            GENERIC_ALL,
            &station_sd.attributes(),
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let station = Station(raw);
    struct Restore(HWINSTA);
    impl Drop for Restore {
        fn drop(&mut self) {
            if unsafe { SetProcessWindowStation(self.0) } == 0 {
                std::process::abort();
            }
        }
    }
    let _restore = Restore(original);
    if unsafe { SetProcessWindowStation(station.0) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    // This name cannot preexist: its containing station was created exclusively.
    let raw = unsafe {
        CreateDesktopW(
            wide(DESKTOP_NAME).as_ptr(),
            null(),
            null(),
            0,
            GENERIC_ALL,
            &desktop_sd.attributes(),
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let desktop = Desktop(raw);
    println!(
        "{}{}",
        std::str::from_utf8(READY)?,
        serde_json::to_string(&Reply {
            station: station.0 as usize,
            desktop: desktop.0 as usize
        })?
    );
    io::stdout().flush()?;
    if unsafe { WaitForSingleObject(event.as_raw_handle(), TIMEOUT.as_millis() as u32) }
        != WAIT_OBJECT_0
    {
        return Err("Scanner desktop handoff acknowledgment did not arrive".into());
    }
    Ok(())
}
