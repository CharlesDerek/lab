//! Opt-in native fixture diagnostics only. Never compiled into the endpoint.
//! Image-specific loader snaps apply only to a freshly named synthetic helper.
use super::Service;
use std::{
    cell::Cell,
    io,
    os::windows::io::AsRawHandle,
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_SEM_TIMEOUT,
        EXCEPTION_BREAKPOINT, HANDLE,
    },
    System::{
        Diagnostics::Debug::{
            ContinueDebugEvent, DebugActiveProcessStop, ReadProcessMemory, WaitForDebugEventEx,
            CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
            EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT,
        },
        Registry::{
            RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE,
            KEY_SET_VALUE, KEY_WOW64_64KEY, REG_CREATED_NEW_KEY, REG_DWORD,
            REG_OPTION_NON_VOLATILE,
        },
    },
};
thread_local! { static ENABLED: Cell<bool> = const { Cell::new(false) }; }
thread_local! { static UI_PROBE: Cell<u8> = const { Cell::new(0) }; }
pub(super) fn ui_probe() -> u8 {
    UI_PROBE.get()
}
pub(super) fn enabled() -> bool {
    ENABLED.get()
}
pub(super) fn launch(start: impl FnOnce() -> io::Result<Service>) -> io::Result<Service> {
    assert!(!ENABLED.replace(true));
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ENABLED.set(false);
        }
    }
    let _reset = Reset;
    start()
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
pub(super) struct LoaderSnaps {
    path: Vec<u16>,
}
impl LoaderSnaps {
    pub(super) fn enable(image: &str) -> io::Result<Self> {
        let nonce = image
            .strip_prefix("scanner-")
            .and_then(|s| s.strip_suffix(".exe"));
        if !nonce.is_some_and(athernex_endpoint_protocol::hex_id) {
            return Err(io::Error::other(
                "Loader snaps require a unique fixture image",
            ));
        }
        let path = wide(&format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{image}"));
        let (mut key, mut disposition) = (null_mut(), 0);
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                0,
                null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut key,
                &mut disposition,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if disposition != REG_CREATED_NEW_KEY {
            unsafe {
                RegCloseKey(key);
            }
            return Err(io::Error::other("Refusing an existing image-options key"));
        }
        let owned = Self { path };
        let flag = 2u32.to_le_bytes(); // FLG_SHOW_LDR_SNAPS, not a global registry flag.
        let status = unsafe {
            RegSetValueExW(
                key,
                wide("GlobalFlag").as_ptr(),
                0,
                REG_DWORD,
                flag.as_ptr(),
                flag.len() as u32,
            )
        };
        unsafe {
            RegCloseKey(key);
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(owned)
    }
}
impl Drop for LoaderSnaps {
    fn drop(&mut self) {
        let status =
            unsafe { RegDeleteKeyExW(HKEY_LOCAL_MACHINE, self.path.as_ptr(), KEY_WOW64_64KEY, 0) };
        if status != 0 {
            eprintln!("Fixture loader-snaps key cleanup failed: {status}");
        }
    }
}
struct Attached {
    pid: u32,
    exited: bool,
}
impl Drop for Attached {
    fn drop(&mut self) {
        if !self.exited && unsafe { DebugActiveProcessStop(self.pid) } == 0 {
            // Do not leave a debug-stopped process for the normal reaper, whose
            // thread cannot continue events belonging to this fixture thread.
            eprintln!("Cannot detach fixture debugger; terminating its owner");
            std::process::abort();
        }
    }
}
fn close_file(handle: HANDLE) {
    if !handle.is_null() {
        unsafe {
            CloseHandle(handle);
        }
    }
}
fn retain(trace: &mut Vec<u8>, bytes: &[u8]) {
    trace.extend_from_slice(bytes);
    if trace.len() > 12000 {
        trace.drain(..trace.len() - 12000);
    }
}
pub(super) fn capture_startup(service: &mut Service) -> io::Result<()> {
    let mut attached = Attached {
        pid: service.id(),
        exited: false,
    };
    let process = service.child.tree.as_ref().unwrap().process.as_raw_handle();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut trace = Vec::new();
    let result = (|| {
        loop {
            service
                .pipe
                .drain_diagnostics(&mut service.output, service.limit)?;
            if service
                .output()
                .windows(b"SCANNER_READY".len())
                .any(|s| s == b"SCANNER_READY")
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Fixture loader diagnostics timed out",
                ));
            }
            let mut event = DEBUG_EVENT::default();
            if unsafe { WaitForDebugEventEx(&mut event, 50) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32) {
                    continue;
                }
                return Err(error);
            }
            let mut status = DBG_CONTINUE;
            // DEBUG_ONLY_THIS_PROCESS plus original child identity: no system
            // process attachment and no arbitrary-process memory reads.
            assert_eq!(event.dwProcessId, service.id());
            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    close_file(unsafe { event.u.CreateProcessInfo.hFile })
                }
                LOAD_DLL_DEBUG_EVENT => close_file(unsafe { event.u.LoadDll.hFile }),
                OUTPUT_DEBUG_STRING_EVENT => {
                    let message = unsafe { event.u.DebugString };
                    let count = usize::from(message.nDebugStringLength)
                        .saturating_mul(if message.fUnicode == 0 { 1 } else { 2 })
                        .min(32768);
                    let mut data = vec![0u8; count];
                    let mut read = 0;
                    if count > 0
                        && unsafe {
                            ReadProcessMemory(
                                process,
                                message.lpDebugStringData.cast(),
                                data.as_mut_ptr().cast(),
                                count,
                                &mut read,
                            )
                        } != 0
                        && read <= data.len()
                    {
                        data.truncate(read);
                        if message.fUnicode != 0 {
                            let utf16: Vec<_> = data
                                .chunks_exact(2)
                                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                                .collect();
                            retain(
                                &mut trace,
                                String::from_utf16_lossy(&utf16)
                                    .trim_matches('\0')
                                    .as_bytes(),
                            );
                        } else {
                            retain(&mut trace, &data);
                        }
                    }
                }
                EXCEPTION_DEBUG_EVENT => {
                    let info = unsafe { event.u.Exception };
                    retain(
                        &mut trace,
                        format!(
                            "\nFixture loader exception 0x{:08x}, first chance {}\n",
                            info.ExceptionRecord.ExceptionCode as u32, info.dwFirstChance
                        )
                        .as_bytes(),
                    );
                    if info.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT {
                        status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                _ => {}
            }
            if unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                attached.exited = true;
                return Ok(());
            }
        }
    })();
    eprintln!(
        "Fixture loader trace (bounded tail):\n{}",
        String::from_utf8_lossy(&trace).replace('\0', "")
    );
    result
}

pub(super) fn compare_private_ui_access(
    command: &super::Command,
    token: &athernex_endpoint_native::windows_scanner::Token,
) {
    // Every candidate has its own fresh private station/desktop. The privileged
    // creation helper exits before the synthetic scanner is resumed. These
    // diagnostic launches cannot turn the original failing test into a pass.
    for mode in 1..=7 {
        UI_PROBE.set(mode);
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                UI_PROBE.set(0);
            }
        }
        let reset = Reset;
        let started = Service::start_scanner(command, token, 4096, |_, _| Ok(()));
        drop(reset);
        let result: io::Result<String> = (|| {
            let mut service = started?;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let exit = service.poll()?;
                if service
                    .output()
                    .windows(b"SCANNER_READY".len())
                    .any(|s| s == b"SCANNER_READY")
                {
                    service.stop()?;
                    return Ok("helper reached main; owned job stopped".into());
                }
                if let Some(code) = exit {
                    return Ok(format!("exit 0x{:08x}", code as u32));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "private UI comparison deadline",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })();
        eprintln!("Private USER object access candidate {mode}: {result:?}");
    }
}
