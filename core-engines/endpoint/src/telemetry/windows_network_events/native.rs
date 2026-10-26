mod record;
mod session;
use super::{Counters, SessionIntent};
use crate::Result;
use athernex_endpoint_protocol::windows_network_events::QpcClock;
pub(super) use record::Record;
#[cfg(test)]
pub(super) use record::{copied_record_bounds_and_lifetime, same_guid};
#[cfg(test)]
pub(super) use session::{absent, stop_for_test};
use std::{
    io,
    os::windows::io::{FromRawHandle, OwnedHandle},
    path::Path,
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_CTX_CLOSE_PENDING, ERROR_NO_TOKEN, FILETIME},
    Security::TOKEN_QUERY,
    System::{
        Diagnostics::Etw::*,
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        SystemInformation::GetSystemTimePreciseAsFileTime,
        Threading::{GetCurrentThread, OpenThreadToken},
    },
};

fn api(_operation: &'static str, code: u32) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    #[cfg(test)]
    eprintln!("\nATHERNEX_NETWORK_EVENTS_DIAGNOSTIC={_operation}:{code}");
    Err(io::Error::from_raw_os_error(code as i32).into())
}
pub(super) fn require_unimpersonated() -> Result<()> {
    let mut handle = null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut handle) } != 0 {
        let _token = unsafe { OwnedHandle::from_raw_handle(handle) };
        return Err("Windows network collection does not support an impersonated caller".into());
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_NO_TOKEN {
        Ok(())
    } else {
        api("token_query", code)
    }
}
pub(super) fn owner_created() -> Result<u64> {
    athernex_endpoint_native::windows_filter::peer::identify(std::process::id())
}
pub(super) fn session_name(path: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(path)?;
    use std::os::windows::ffi::OsStrExt;
    let bytes: Vec<u8> = canonical
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    Ok(format!(
        "Athernex Network Events {}",
        &athernex_endpoint_protocol::hash(&bytes)[..32]
    ))
}
pub(super) fn recover(intent: &SessionIntent) -> Result<()> {
    session::recover(intent)
}
pub(super) fn clock() -> Result<QpcClock> {
    let mut frequency = 0;
    let mut before = 0;
    let mut after = 0;
    let mut utc = FILETIME::default();
    if unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
        || unsafe { QueryPerformanceCounter(&mut before) } == 0
    {
        return Err("Windows network QPC clock query failed".into());
    }
    unsafe {
        GetSystemTimePreciseAsFileTime(&mut utc);
    }
    if unsafe { QueryPerformanceCounter(&mut after) } == 0 || frequency <= 0 {
        return Err("Windows network QPC calibration failed".into());
    }
    let clock = QpcClock {
        frequency_hz: frequency as u64,
        before_qpc: before,
        after_qpc: after,
        utc_filetime_100ns: (utc.dwHighDateTime as u64) << 32 | utc.dwLowDateTime as u64,
    };
    clock.estimate(after)?;
    Ok(clock)
}
pub(super) struct Reader {
    session: session::Session,
    state: Arc<record::State>,
    received: mpsc::Receiver<Record>,
    consumer: Option<PROCESSTRACE_HANDLE>,
    worker: Option<thread::JoinHandle<u32>>,
}
impl Reader {
    pub fn start(intent: &SessionIntent) -> Result<Self> {
        require_unimpersonated()?;
        let session = session::Session::start(intent)?;
        let (queue, received) = mpsc::sync_channel(record::QUEUE_RECORDS);
        let state = Arc::new(record::State {
            queue,
            bytes: AtomicUsize::new(0),
            received: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            fatal: AtomicU64::new(0),
        });
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: session.name.as_ptr().cast_mut(),
            Context: Arc::as_ptr(&state).cast_mut().cast(),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_REAL_TIME
            | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        logfile.Anonymous2.EventRecordCallback = Some(record::callback);
        let consumer = unsafe { OpenTraceW(&mut logfile) };
        if consumer.Value == u64::MAX {
            api("open_trace", unsafe { GetLastError() })?;
            return Err("Windows network consumer handle invalid".into());
        }
        let mut reader = Self {
            session,
            state,
            received,
            consumer: Some(consumer),
            worker: None,
        };
        let (ready, started) = mpsc::channel();
        reader.worker = Some(
            thread::Builder::new()
                .name("endpoint-windows-network-etw-consumer".into())
                .spawn(move || {
                    let _ = ready.send(());
                    unsafe { ProcessTrace(&consumer, 1, null(), null()) }
                })?,
        );
        started
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "Windows network consumer startup timeout")?;
        reader.check()?;
        Ok(reader)
    }
    pub fn check(&self) -> Result<()> {
        if self
            .worker
            .as_ref()
            .is_none_or(|worker| worker.is_finished())
            || self.state.fatal.load(Ordering::Acquire) != 0
        {
            return Err("Windows network consumer stopped or rejected its callback".into());
        }
        Ok(())
    }
    pub fn batch(&self) -> Vec<Record> {
        let values: Vec<_> = self.received.try_iter().take(64).collect();
        for value in &values {
            self.state.bytes.fetch_sub(value.bytes(), Ordering::AcqRel);
        }
        values
    }
    pub fn counters(&self) -> Result<Counters> {
        let mut counters = self.session.counters()?;
        // Receipt allocation precedes callback classification. Sample receipt
        // count last so a concurrent rejection cannot exceed received records.
        counters.rejected = self.state.rejected.load(Ordering::Acquire);
        counters.callback_drops = self.state.dropped.load(Ordering::Acquire);
        counters.received = self.state.received.load(Ordering::Acquire);
        Ok(counters)
    }
    pub fn close(&mut self) -> Result<Counters> {
        let stopped = self.session.close();
        let closed = if let Some(consumer) = self.consumer.take() {
            let code = unsafe { CloseTrace(consumer) };
            if code == ERROR_CTX_CLOSE_PENDING {
                Ok(())
            } else {
                api("close_trace", code)
            }
        } else {
            Ok(())
        };
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if !worker.is_finished() {
                eprintln!(
                    "Windows network consumer did not stop within its bounded shutdown interval"
                );
                std::process::abort();
            }
            api(
                "process_trace",
                worker
                    .join()
                    .map_err(|_| "Windows network consumer panicked")?,
            )?;
        }
        stopped?;
        closed?;
        if self.state.fatal.load(Ordering::Acquire) != 0 {
            return Err("Windows network callback failed".into());
        }
        self.counters()
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
