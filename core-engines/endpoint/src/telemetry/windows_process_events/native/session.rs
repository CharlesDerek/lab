use super::super::{Counters, SessionIntent};
use super::api;
use super::record::{guid, same_guid};
use crate::Result;
use std::{
    mem::{offset_of, size_of},
    ptr::null,
};
use windows_sys::{
    core::GUID,
    Win32::{Foundation::ERROR_WMI_INSTANCE_NOT_FOUND, System::Diagnostics::Etw::*},
};

#[repr(C)]
struct Properties {
    value: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
    file: [u16; 1024],
}
impl Properties {
    fn new(id: GUID) -> Self {
        let mut value = EVENT_TRACE_PROPERTIES::default();
        value.Wnode.BufferSize = size_of::<Self>() as u32;
        value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        value.Wnode.Guid = id;
        value.Wnode.ClientContext = 1;
        value.LoggerNameOffset = offset_of!(Self, name) as u32;
        value.LogFileNameOffset = offset_of!(Self, file) as u32;
        value.LogFileMode = EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE;
        Self {
            value,
            name: [0; 128],
            file: [0; 1024],
        }
    }
    fn counters(&self) -> Counters {
        Counters {
            events_lost: self.value.EventsLost as u64,
            log_buffers_lost: self.value.LogBuffersLost as u64,
            realtime_buffers_lost: self.value.RealTimeBuffersLost as u64,
            ..Default::default()
        }
    }
}
fn identifier(intent: &SessionIntent) -> Result<GUID> {
    let value = u128::from_str_radix(&intent.stream_id[..32], 16)
        .map_err(|_| "Invalid Windows process session identity")?;
    let id = GUID::from_u128(value);
    if guid(id) != intent.session_guid || same_guid(id, SystemTraceControlGuid) {
        return Err("Windows process session identity is not private".into());
    }
    Ok(id)
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn query(
    intent: &SessionIntent,
    handle: Option<CONTROLTRACE_HANDLE>,
) -> Result<Option<(Properties, CONTROLTRACE_HANDLE)>> {
    let name = wide(&intent.session_name);
    let id = identifier(intent)?;
    let mut properties = Properties::new(id);
    let code = unsafe {
        ControlTraceW(
            handle.unwrap_or_default(),
            if handle.is_some() {
                null()
            } else {
                name.as_ptr()
            },
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
        .ok_or("Windows process session name is unterminated")?;
    if !same_guid(properties.value.Wnode.Guid, id)
        || properties.name[..length] != name[..name.len() - 1]
    {
        return Err("Windows process session ownership changed".into());
    }
    if properties.value.EnableFlags != EVENT_TRACE_FLAG_PROCESS
        || properties.value.LogFileMode
            & (EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE)
            != EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE
        || properties.value.Wnode.ClientContext != 1
    {
        return Err("Windows process session configuration changed".into());
    }
    // Microsoft SDK evntrace.h documents this as the controller handle returned
    // by ControlTrace(0, sessionName, ...), valid until the session stops.
    let observed = CONTROLTRACE_HANDLE {
        Value: unsafe { properties.value.Wnode.Anonymous1.HistoricalContext },
    };
    if observed.Value == 0 || handle.is_some_and(|expected| expected.Value != observed.Value) {
        return Err("Windows process session controller identity changed".into());
    }
    Ok(Some((properties, observed)))
}
fn stop(intent: &SessionIntent, handle: CONTROLTRACE_HANDLE) -> Result<Counters> {
    let (mut properties, _) =
        query(intent, Some(handle))?.ok_or("Windows process session disappeared")?;
    api("stop_trace", unsafe {
        ControlTraceW(
            handle,
            null(),
            &mut properties.value,
            EVENT_TRACE_CONTROL_STOP,
        )
    })?;
    let counters = properties.counters();
    if query(intent, None)?.is_some() {
        return Err("Windows process session removal was not verified".into());
    }
    Ok(counters)
}
pub(super) fn recover(intent: &SessionIntent) -> Result<()> {
    if intent.phase != "stopped"
        && !athernex_endpoint_native::windows_filter::peer::original_process_ended(
            intent.owner_pid,
            intent.owner_created,
        )?
    {
        return Err("Windows process session still has a live original owner".into());
    }
    if let Some((_, handle)) = query(intent, None)? {
        if intent.phase == "stopped" {
            return Err("A stopped Windows process session unexpectedly exists".into());
        }
        stop(intent, handle)?;
    }
    Ok(())
}
pub(super) struct Session {
    intent: SessionIntent,
    handle: CONTROLTRACE_HANDLE,
    stopped: Option<Counters>,
    pub name: Vec<u16>,
}
impl Session {
    pub fn start(intent: &SessionIntent) -> Result<Self> {
        if query(intent, None)?.is_some() {
            return Err("Windows process session already exists".into());
        }
        let id = identifier(intent)?;
        let name = wide(&intent.session_name);
        let mut properties = Properties::new(id);
        properties.value.BufferSize = 64;
        properties.value.MinimumBuffers = 8;
        properties.value.MaximumBuffers = 32;
        properties.value.FlushTimer = 1;
        properties.value.EnableFlags = EVENT_TRACE_FLAG_PROCESS;
        properties.value.LogFileNameOffset = 0;
        let mut handle = CONTROLTRACE_HANDLE::default();
        api("start_trace", unsafe {
            StartTraceW(&mut handle, name.as_ptr(), &mut properties.value)
        })?;
        let session = Self {
            intent: intent.clone(),
            handle,
            stopped: None,
            name,
        };
        session.counters()?;
        Ok(session)
    }
    pub fn counters(&self) -> Result<Counters> {
        if let Some(counters) = &self.stopped {
            return Ok(counters.clone());
        }
        Ok(query(&self.intent, Some(self.handle))?
            .ok_or("Windows process session disappeared")?
            .0
            .counters())
    }
    pub fn close(&mut self) -> Result<Counters> {
        if let Some(counters) = &self.stopped {
            return Ok(counters.clone());
        }
        let counters = stop(&self.intent, self.handle)?;
        self.stopped = Some(counters.clone());
        Ok(counters)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
#[cfg(test)]
pub(in super::super) fn stop_for_test(intent: &SessionIntent) -> Result<()> {
    let (_, handle) = query(intent, None)?.ok_or("Controlled session absent")?;
    stop(intent, handle)?;
    Ok(())
}
#[cfg(test)]
pub(in super::super) fn absent(intent: &SessionIntent) -> Result<bool> {
    Ok(query(intent, None)?.is_none())
}
