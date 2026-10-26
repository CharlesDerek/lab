//! Actual production collector coexistence; no second mock process logger.
use super::super::super::windows_process_events::{health, Collector};
use super::{native, qpc, require, Result};
use crate::Store;
use athernex_endpoint_protocol::{
    telemetry::Telemetry, windows_process_events::WindowsProcessChange, EndpointEvent,
};
use serde::Deserialize;
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Deserialize, PartialEq, Eq)]
struct Identity {
    stream_id: String,
    session_name: String,
    session_guid: String,
    owner_pid: u32,
    owner_created: u64,
    started_ms: u64,
    phase: String,
}
impl Identity {
    fn read(store: &Store) -> Result<Self> {
        super::super::super::metadata(store, "windows_process_events_session")
            .map_err(|_| "ownership")?
            .ok_or("ownership")
    }
    fn same(&self, other: &Self) -> bool {
        self.stream_id == other.stream_id
            && self.session_name == other.session_name
            && self.session_guid == other.session_guid
            && self.owner_pid == other.owner_pid
            && self.owner_created == other.owner_created
            && self.started_ms == other.started_ms
    }
}
pub(super) struct Coexist<'a> {
    store: &'a Store,
    collector: Option<Collector<'a>>,
    identity: Identity,
    handle: u64,
    log_file_mode: u32,
    child: Option<Child>,
    child_bound: i64,
}
impl<'a> Coexist<'a> {
    pub fn start(store: &'a Store) -> Result<Self> {
        let collector = Collector::start(store).map_err(|_| "session_start")?;
        let identity = Identity::read(store)?;
        require(
            identity.phase == "active" && identity.owner_pid == std::process::id(),
            "session_ownership",
        )?;
        let (handle, log_file_mode) =
            process_session(&identity.stream_id, &identity.session_name, None)?
                .ok_or("ownership")?;
        let result = Self {
            store,
            collector: Some(collector),
            identity,
            handle,
            log_file_mode,
            child: None,
            child_bound: 0,
        };
        result.check()?;
        Ok(result)
    }
    pub fn check(&self) -> Result<()> {
        self.collector
            .as_ref()
            .ok_or("ownership")?
            .check()
            .map_err(|_| "consumer_start")?;
        let identity = Identity::read(self.store)?;
        require(
            self.identity.same(&identity) && identity.phase == "active",
            "session_ownership",
        )?;
        require(
            process_session(
                &identity.stream_id,
                &identity.session_name,
                Some(self.log_file_mode),
            )? == Some((self.handle, self.log_file_mode)),
            "session_ownership",
        )?;
        require(
            health(self.store)
                .map_err(|_| "source_loss")?
                .is_some_and(|value| {
                    value.stream_id == self.identity.stream_id && value.healthy(crate::now_ms())
                }),
            "source_loss",
        )
    }
    pub fn child(&mut self) -> Result<()> {
        let exe = std::env::current_exe().map_err(|_| "traffic")?;
        self.child_bound = qpc()?;
        // An exact nonexistent test filter only lists zero tests and exits 0.
        // No child helper, shell, network command, or external executable runs.
        self.child = Some(
            Command::new(exe)
                .args(["--exact", "athernex_network_source_no_test", "--list"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| "traffic")?,
        );
        Ok(())
    }
    pub fn verify_child(&mut self) -> Result<()> {
        let child = self.child.as_mut().ok_or("controlled_match")?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().map_err(|_| "traffic")? {
                require(status.code() == Some(0), "controlled_match")?;
                break;
            }
            require(Instant::now() < deadline, "timeout")?;
            std::thread::sleep(Duration::from_millis(20));
        }
        // Retain the Child handle through both source checks so the PID cannot
        // be reused. The QPC bound excludes an earlier incarnation in the queue.
        let pid = child.id();
        let mut starts = 0;
        let mut ends = 0;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            self.check()?;
            let mut query = self
                .store
                .connection
                .prepare(
                    "SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending",
                )
                .map_err(|_| "controlled_match")?;
            let rows = query
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|_| "controlled_match")?;
            starts = 0;
            ends = 0;
            for row in rows {
                let event: EndpointEvent =
                    serde_json::from_str(&row.map_err(|_| "controlled_match")?)
                        .map_err(|_| "controlled_match")?;
                let Some(Telemetry::WindowsProcessEvent { event }) = event.telemetry else {
                    continue;
                };
                if event.pid != pid
                    || event.original.stream_id != self.identity.stream_id
                    || event.original.header.timestamp_qpc < self.child_bound
                    || !matches!(
                        event.change,
                        WindowsProcessChange::Start | WindowsProcessChange::End
                    )
                {
                    continue;
                }
                require(
                    event.parent_pid == Some(std::process::id()) && event.session_id == Some(0),
                    "controlled_match",
                )?;
                match event.change {
                    WindowsProcessChange::Start => starts += 1,
                    WindowsProcessChange::End => {
                        require(event.exit_status == Some(0), "controlled_match")?;
                        ends += 1;
                    }
                    _ => (),
                }
            }
            if starts == 1 && ends == 1 {
                return Ok(());
            }
            require(starts <= 1 && ends <= 1, "controlled_match")?;
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = (starts, ends);
        Err("timeout")
    }
    pub fn close(&mut self) -> Result<()> {
        if let Some(child) = &mut self.child {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !matches!(child.try_wait(), Ok(Some(_))) {
                    if Instant::now() >= deadline {
                        eprintln!("\nATHERNEX_NETWORK_EVENTS_FAILURE=timeout");
                        std::process::abort();
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        if self.collector.is_none() {
            return Ok(());
        }
        let before = self.check();
        self.collector.take();
        let identity = Identity::read(self.store)?;
        require(
            self.identity.same(&identity) && identity.phase == "stopped",
            "session_cleanup",
        )?;
        require(
            process_session(
                &identity.stream_id,
                &identity.session_name,
                Some(self.log_file_mode),
            )?
            .is_none(),
            "session_cleanup",
        )?;
        before
    }
}
impl Drop for Coexist<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn process_session(stream: &str, label: &str, pinned: Option<u32>) -> Result<Option<(u64, u32)>> {
    use std::mem::{offset_of, size_of};
    use windows_sys::{
        core::GUID,
        Win32::{Foundation::ERROR_WMI_INSTANCE_NOT_FOUND, System::Diagnostics::Etw::*},
    };
    require(
        stream.len() == 64
            && stream
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && label.starts_with("Athernex Process Events ")
            && label.len() < 128,
        "ownership",
    )?;
    let guid = GUID::from_u128(u128::from_str_radix(&stream[..32], 16).map_err(|_| "ownership")?);
    require(
        !native::same_guid(guid, SystemTraceControlGuid),
        "ownership",
    )?;
    #[repr(C)]
    struct Properties {
        value: EVENT_TRACE_PROPERTIES,
        name: [u16; 128],
        file: [u16; 1024],
    }
    let mut properties = Properties {
        value: EVENT_TRACE_PROPERTIES::default(),
        name: [0; 128],
        file: [0; 1024],
    };
    properties.value.Wnode.BufferSize = size_of::<Properties>() as u32;
    properties.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.value.Wnode.Guid = guid;
    properties.value.LoggerNameOffset = offset_of!(Properties, name) as u32;
    properties.value.LogFileNameOffset = offset_of!(Properties, file) as u32;
    let name: Vec<u16> = label.encode_utf16().chain([0]).collect();
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
    super::api("query_trace", code)?;
    let end = properties
        .name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("ownership")?;
    require(
        native::same_guid(properties.value.Wnode.Guid, guid)
            && properties.name[..end] == name[..name.len() - 1],
        "ownership",
    )?;
    let base = EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE;
    let mode = properties.value.LogFileMode;
    require(
        [
            base | EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN,
            base | EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN,
        ]
        .contains(&mode)
            && pinned.is_none_or(|expected| expected == mode)
            && properties.value.EnableFlags == EVENT_TRACE_FLAG_PROCESS
            && properties.value.Wnode.ClientContext == 1
            && properties.file[0] == 0
            && [0, offset_of!(Properties, file) as u32]
                .contains(&properties.value.LogFileNameOffset),
        "ownership",
    )?;
    require(
        properties.value.EventsLost == 0
            && properties.value.LogBuffersLost == 0
            && properties.value.RealTimeBuffersLost == 0,
        "native_loss",
    )?;
    let handle = unsafe { properties.value.Wnode.Anonymous1.HistoricalContext };
    require(handle != 0, "ownership")?;
    Ok(Some((handle, mode)))
}
