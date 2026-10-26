//! Test-only ownership and bounded copies for the actual Windows ETW source.
use super::{api, require, Result};
use athernex_endpoint_protocol::windows_process_events::QpcClock;
use std::{
    mem::{offset_of, size_of},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{
            GetLastError, ERROR_CTX_CLOSE_PENDING, ERROR_WMI_INSTANCE_NOT_FOUND, FILETIME,
        },
        System::{
            Diagnostics::Etw::*,
            Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
            SystemInformation::GetSystemTimePreciseAsFileTime,
        },
    },
};

const MAX_BYTES: usize = 48 * 1024;
const QUEUE_BYTES: usize = 8 * 1024 * 1024;
const QUEUE_RECORDS: usize = 2048;
pub(super) fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

pub(super) struct Extended {
    header: EVENT_HEADER_EXTENDED_DATA_ITEM,
    bytes: Vec<u8>,
}
pub(super) struct Original {
    pub header: EVENT_HEADER,
    clock: QpcClock,
    stream: GUID,
    context: ETW_BUFFER_CONTEXT,
    extended: Vec<Extended>,
    data: Vec<u8>,
}
impl Original {
    unsafe fn copy(record: &EVENT_RECORD, clock: &QpcClock, stream: GUID) -> Result<Self> {
        require(
            record.UserDataLength != 0
                && record.UserDataLength as usize <= MAX_BYTES
                && !record.UserData.is_null(),
            "Invalid network payload",
        )?;
        require(
            record.ExtendedDataCount <= 16
                && (record.ExtendedDataCount == 0 || !record.ExtendedData.is_null()),
            "Invalid network extended data",
        )?;
        let mut total = record.UserDataLength as usize;
        let mut extended = Vec::new();
        for index in 0..record.ExtendedDataCount as usize {
            let mut header = record.ExtendedData.add(index).read();
            let size = header.DataSize as usize;
            total = total
                .checked_add(size)
                .ok_or("Network record size overflow")?;
            require(
                total <= MAX_BYTES && (size == 0 || header.DataPtr != 0),
                "Network record exceeds copy budget",
            )?;
            let bytes = if size == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(header.DataPtr as *const u8, size).to_vec()
            };
            header.DataPtr = 0;
            extended.push(Extended { header, bytes });
        }
        Ok(Self {
            header: record.EventHeader,
            clock: clock.clone(),
            stream,
            context: record.BufferContext,
            extended,
            data: std::slice::from_raw_parts(
                record.UserData.cast::<u8>(),
                record.UserDataLength as usize,
            )
            .to_vec(),
        })
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    fn bytes(&self) -> usize {
        self.data.len()
            + self
                .extended
                .iter()
                .map(|item| item.bytes.len())
                .sum::<usize>()
    }
    pub fn with_record<T>(&self, consume: impl FnOnce(&EVENT_RECORD) -> Result<T>) -> Result<T> {
        let mut items: Vec<_> = self
            .extended
            .iter()
            .map(|item| {
                let mut header = item.header;
                header.DataPtr = item.bytes.as_ptr() as u64;
                header
            })
            .collect();
        let record = EVENT_RECORD {
            EventHeader: self.header,
            BufferContext: self.context,
            ExtendedDataCount: items.len() as u16,
            UserDataLength: self.data.len() as u16,
            ExtendedData: items.as_mut_ptr(),
            UserData: self.data.as_ptr().cast_mut().cast(),
            UserContext: null_mut(),
        };
        consume(&record)
    }
}
struct State {
    clock: QpcClock,
    stream: GUID,
    queue: mpsc::SyncSender<Original>,
    bytes: AtomicUsize,
    drops: AtomicU64,
    failures: AtomicU64,
}
unsafe extern "system" fn event(record: *mut EVENT_RECORD) {
    if record.is_null() || (*record).UserContext.is_null() {
        return;
    }
    let state = &*(*record).UserContext.cast::<State>();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        let record = &*record;
        if !same_guid(record.EventHeader.ProviderId, TcpIpGuid)
            && !same_guid(record.EventHeader.ProviderId, UdpIpGuid)
        {
            return Ok(());
        }
        let original = Original::copy(record, &state.clock, state.stream)?;
        let bytes = original.bytes();
        let previous = state.bytes.fetch_add(bytes, Ordering::AcqRel);
        if previous + bytes > QUEUE_BYTES {
            state.bytes.fetch_sub(bytes, Ordering::AcqRel);
            state.drops.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        if state.queue.try_send(original).is_err() {
            state.bytes.fetch_sub(bytes, Ordering::AcqRel);
            state.drops.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }));
    if !matches!(outcome, Ok(Ok(()))) {
        state.failures.fetch_add(1, Ordering::Relaxed);
    }
}

#[repr(C)]
struct Properties {
    value: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
    file: [u16; 1024],
}
impl Properties {
    fn new(guid: GUID) -> Self {
        let mut value = EVENT_TRACE_PROPERTIES::default();
        value.Wnode.BufferSize = size_of::<Self>() as u32;
        value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        value.Wnode.Guid = guid;
        value.Wnode.ClientContext = 1; // QPC; retained without ProcessTrace conversion.
        value.LoggerNameOffset = offset_of!(Self, name) as u32;
        value.LogFileNameOffset = offset_of!(Self, file) as u32;
        value.LogFileMode = EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE;
        Self {
            value,
            name: [0; 128],
            file: [0; 1024],
        }
    }
}
struct Session {
    handle: CONTROLTRACE_HANDLE,
    guid: GUID,
    name: Vec<u16>,
    stopped: bool,
}
impl Session {
    fn start() -> Result<Self> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| "Session identity unavailable")?;
        let guid = GUID::from_u128(u128::from_be_bytes(random));
        require(
            !same_guid(guid, SystemTraceControlGuid) && random != [0; 16],
            "session_ownership",
        )?;
        let label = format!(
            "Athernex Network Source Probe {:032x}",
            u128::from_be_bytes(random)
        );
        let name: Vec<u16> = label.encode_utf16().chain([0]).collect();
        let mut properties = Properties::new(guid);
        properties.value.BufferSize = 64;
        properties.value.MinimumBuffers = 8;
        properties.value.MaximumBuffers = 32;
        properties.value.FlushTimer = 1;
        properties.value.EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
        // No file logging: leave the file offset zero when starting a real-time session.
        properties.value.LogFileNameOffset = 0;
        let mut handle = CONTROLTRACE_HANDLE::default();
        api("start_trace", unsafe {
            StartTraceW(&mut handle, name.as_ptr(), &mut properties.value)
        })?;
        let session = Self {
            handle,
            guid,
            name,
            stopped: false,
        };
        session.check()?;
        Ok(session)
    }
    fn query(&self) -> Result<Properties> {
        let mut properties = Properties::new(self.guid);
        api("query_trace", unsafe {
            ControlTraceW(
                self.handle,
                null(),
                &mut properties.value,
                EVENT_TRACE_CONTROL_QUERY,
            )
        })?;
        require(
            same_guid(properties.value.Wnode.Guid, self.guid),
            "Session GUID ownership differs",
        )?;
        let length = properties
            .name
            .iter()
            .position(|unit| *unit == 0)
            .ok_or("Session name is unterminated")?;
        require(
            properties.name[..length] == self.name[..self.name.len() - 1],
            "Session name ownership differs",
        )?;
        require(
            properties.value.LogFileMode
                == EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE
                && properties.file[0] == 0
                && (properties.value.LogFileNameOffset == 0
                    || properties.value.LogFileNameOffset == offset_of!(Properties, file) as u32)
                && properties.value.EnableFlags == EVENT_TRACE_FLAG_NETWORK_TCPIP
                && properties.value.Wnode.ClientContext == 1,
            "Session source configuration differs",
        )?;
        require(
            unsafe { properties.value.Wnode.Anonymous1.HistoricalContext } == self.handle.Value
                && self.handle.Value != 0,
            "session_ownership",
        )?;
        Ok(properties)
    }
    fn check(&self) -> Result<()> {
        let properties = self.query()?;
        require(
            properties.value.EventsLost == 0
                && properties.value.LogBuffersLost == 0
                && properties.value.RealTimeBuffersLost == 0,
            "Native source reports lost records",
        )
    }
    fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        let mut properties = self.query()?;
        api("stop_trace", unsafe {
            ControlTraceW(
                self.handle,
                null(),
                &mut properties.value,
                EVENT_TRACE_CONTROL_STOP,
            )
        })?;
        self.stopped = true;
        let lost = properties.value.EventsLost != 0
            || properties.value.LogBuffersLost != 0
            || properties.value.RealTimeBuffersLost != 0;
        let mut absent = Properties::new(self.guid);
        let code = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                self.name.as_ptr(),
                &mut absent.value,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        require(
            code == ERROR_WMI_INSTANCE_NOT_FOUND,
            "Owned trace session removal was not verified",
        )?;
        require(!lost, "Native source lost records during shutdown")
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub(super) struct Source {
    session: Session,
    state: Arc<State>,
    received: mpsc::Receiver<Original>,
    consumer: Option<PROCESSTRACE_HANDLE>,
    worker: Option<thread::JoinHandle<u32>>,
}
impl Source {
    pub fn start() -> Result<Self> {
        let clock = clock()?;
        let session = Session::start()?;
        let (queue, received) = mpsc::sync_channel(QUEUE_RECORDS);
        let state = Arc::new(State {
            clock,
            stream: session.guid,
            queue,
            bytes: AtomicUsize::new(0),
            drops: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        });
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: session.name.as_ptr().cast_mut(),
            Context: Arc::as_ptr(&state).cast_mut().cast(),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_REAL_TIME
            | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        logfile.Anonymous2.EventRecordCallback = Some(event);
        let consumer = unsafe { OpenTraceW(&mut logfile) };
        if consumer.Value == u64::MAX {
            api("open_trace", unsafe { GetLastError() })?;
            return Err("Native network consumer handle invalid");
        }
        let mut source = Self {
            session,
            state,
            received,
            consumer: Some(consumer),
            worker: None,
        };
        let (ready, receiver) = mpsc::channel();
        source.worker = Some(
            thread::Builder::new()
                .name("windows-network-source-probe".into())
                .spawn(move || {
                    let _ = ready.send(());
                    unsafe { ProcessTrace(&consumer, 1, null(), null()) }
                })
                .map_err(|_| "Native consumer thread could not start")?,
        );
        receiver
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "Native consumer startup timeout")?;
        source.check()?;
        Ok(source)
    }
    pub fn check(&self) -> Result<()> {
        require(
            self.worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished()),
            "Native consumer exited unexpectedly",
        )?;
        require(
            self.state.drops.load(Ordering::Relaxed) == 0,
            "callback_overflow",
        )?;
        require(
            self.state.failures.load(Ordering::Relaxed) == 0,
            "callback_bounds",
        )?;
        self.session.check()
    }
    pub fn check_original(&self, original: &Original) -> Result<()> {
        require(
            same_guid(original.stream, self.session.guid)
                && original.header.TimeStamp >= original.clock.before_qpc,
            "controlled_match",
        )?;
        original
            .clock
            .estimate(original.header.TimeStamp)
            .map_err(|_| "controlled_match")?;
        Ok(())
    }
    pub fn drain(&self) -> Result<Vec<Original>> {
        let records: Vec<_> = self.received.try_iter().take(QUEUE_RECORDS).collect();
        for record in &records {
            self.state.bytes.fetch_sub(record.bytes(), Ordering::AcqRel);
        }
        Ok(records)
    }
    pub fn close(&mut self) -> Result<()> {
        let stopped = self.session.stop();
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
                // Never free callback storage while ProcessTrace can still use it.
                eprintln!("Native consumer did not stop within the bounded cleanup interval");
                std::process::abort();
            }
            let code = worker.join().map_err(|_| "Native consumer panicked")?;
            api("process_trace", code)?;
        }
        stopped?;
        closed?;
        require(
            self.state.drops.load(Ordering::Relaxed) == 0
                && self.state.failures.load(Ordering::Relaxed) == 0,
            "Native callback lost records before shutdown",
        )
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[test]
pub(super) fn callback_copies_relocatable_owned_payload_and_rejects_invalid_bounds() {
    let mut payload = vec![1u8, 2, 3, 4];
    let mut extra = vec![5u8; 8];
    let mut extension = EVENT_HEADER_EXTENDED_DATA_ITEM {
        ExtType: EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY as u16,
        DataSize: extra.len() as u16,
        DataPtr: extra.as_mut_ptr() as u64,
        ..Default::default()
    };
    let mut record = EVENT_RECORD {
        UserData: payload.as_mut_ptr().cast(),
        UserDataLength: payload.len() as u16,
        ExtendedData: &mut extension,
        ExtendedDataCount: 1,
        ..Default::default()
    };
    let clock = clock().expect("Synthetic clock unavailable");
    let stream = GUID::from_u128(1);
    let owned = unsafe { Original::copy(&record, &clock, stream) }.expect("Synthetic copy failed");
    payload.fill(0);
    extra.fill(0);
    drop(payload);
    drop(extra);
    assert!(owned
        .with_record(|copy| {
            let data = unsafe {
                std::slice::from_raw_parts(copy.UserData.cast::<u8>(), copy.UserDataLength as usize)
            };
            let extension = unsafe { &*copy.ExtendedData };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    extension.DataPtr as *const u8,
                    extension.DataSize as usize,
                )
            };
            require(
                data == [1, 2, 3, 4] && bytes == [5; 8],
                "Synthetic owned payload changed",
            )
        })
        .is_ok());
    record.UserData = null_mut();
    assert!(unsafe { Original::copy(&record, &clock, stream) }.is_err());
    record.UserData = std::ptr::dangling_mut::<u8>().cast();
    record.ExtendedDataCount = 17;
    assert!(unsafe { Original::copy(&record, &clock, stream) }.is_err());
}

// Query-only view of the existing production process collector. Never adopt,
// update or stop that session from the network probe.
pub(super) fn process_session(stream: &str, label: &str) -> Result<Option<u64>> {
    require(
        stream.len() == 64
            && stream
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && label.starts_with("Athernex Process Events ")
            && label.len() < 128,
        "session_ownership",
    )?;
    let id = u128::from_str_radix(&stream[..32], 16).map_err(|_| "session_ownership")?;
    let guid = GUID::from_u128(id);
    require(
        !same_guid(guid, SystemTraceControlGuid),
        "session_ownership",
    )?;
    let name: Vec<_> = label.encode_utf16().chain([0]).collect();
    let mut properties = Properties::new(guid);
    let code = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            name.as_ptr(),
            &mut properties.value,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if code == ERROR_WMI_INSTANCE_NOT_FOUND {
        return Ok(None);
    }
    api("query_trace", code)?;
    let length = properties
        .name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("session_ownership")?;
    require(
        same_guid(properties.value.Wnode.Guid, guid)
            && properties.name[..length] == name[..name.len() - 1]
            && properties.value.EnableFlags == EVENT_TRACE_FLAG_PROCESS
            && properties.value.LogFileMode
                == EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE
            && properties.file[0] == 0
            && (properties.value.LogFileNameOffset == 0
                || properties.value.LogFileNameOffset == offset_of!(Properties, file) as u32)
            && properties.value.Wnode.ClientContext == 1,
        "session_ownership",
    )?;
    require(
        properties.value.EventsLost == 0
            && properties.value.LogBuffersLost == 0
            && properties.value.RealTimeBuffersLost == 0,
        "source_loss",
    )?;
    let handle = unsafe { properties.value.Wnode.Anonymous1.HistoricalContext };
    require(handle != 0, "session_ownership")?;
    Ok(Some(handle))
}

fn clock() -> Result<QpcClock> {
    let mut frequency = 0;
    let mut before = 0;
    let mut after = 0;
    let mut utc = FILETIME::default();
    require(
        unsafe { QueryPerformanceFrequency(&mut frequency) } != 0 && frequency > 0,
        "guard",
    )?;
    require(
        unsafe { QueryPerformanceCounter(&mut before) } != 0,
        "guard",
    )?;
    unsafe {
        GetSystemTimePreciseAsFileTime(&mut utc);
    }
    require(unsafe { QueryPerformanceCounter(&mut after) } != 0, "guard")?;
    let sample = QpcClock {
        frequency_hz: frequency as u64,
        before_qpc: before,
        after_qpc: after,
        utc_filetime_100ns: (utc.dwHighDateTime as u64) << 32 | utc.dwLowDateTime as u64,
    };
    sample.estimate(after).map_err(|_| "guard")?;
    Ok(sample)
}
