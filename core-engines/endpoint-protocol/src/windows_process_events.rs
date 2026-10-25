//! Classic Windows process reports, distinct from snapshots or verified image
//! identities. Receipt ordinals belong to a collector stream, not the kernel.
//! Raw payload bytes may contain addresses; EVENT_RECORD's native pointers and
//! padding are never serialized. Transport/export must retain its access checks.
use serde::{Deserialize, Serialize};

mod parse;
#[cfg(test)]
mod tests;

pub const PROCESS_PROVIDER: &str = "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}";
pub const MAX_ORIGINAL_BYTES: usize = 48 * 1024;
pub const MAX_SERIALIZED_EVENT_BYTES: usize = 128 * 1024;
pub const MAX_EXTENDED_ITEMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventDescriptor {
    pub id: u16,
    pub version: u8,
    pub channel: u8,
    pub level: u8,
    pub opcode: u8,
    pub task: u16,
    pub keyword: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventHeader {
    pub size: u16,
    pub header_type: u16,
    pub flags: u16,
    pub event_property: u16,
    pub thread_id: u32,
    /// The reporting header PID is not rewritten to the payload's target PID.
    pub process_id: u32,
    pub timestamp_qpc: i64,
    pub provider_id: String,
    pub descriptor: EventDescriptor,
    /// Exact bits of the documented processor/kernel+user-time union.
    pub processor_time: u64,
    pub activity_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BufferContext {
    /// Exact processor-index union value; interpretation also depends on flags.
    pub processor_index: u16,
    pub logger_id: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtendedData {
    pub reserved1: u16,
    pub ext_type: u16,
    /// Exact 16-bit linkage/reserved bitfield, not DataPtr.
    pub linkage: u16,
    pub data_hex: String,
}

/// Bracket one precise UTC FILETIME read with two QueryPerformanceCounter reads.
/// The estimate assumes the local wall clock follows QPC near this sample; the
/// bracket does not bound wall-clock corrections, drift or cross-host accuracy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QpcClock {
    pub frequency_hz: u64,
    pub before_qpc: i64,
    pub after_qpc: i64,
    pub utc_filetime_100ns: u64,
}
impl QpcClock {
    pub fn estimate(&self, timestamp_qpc: i64) -> Result<(u64, u64), String> {
        const UNIX_FILETIME: i128 = 116_444_736_000_000_000;
        let frequency = i128::from(self.frequency_hz);
        let width = i128::from(self.after_qpc) - i128::from(self.before_qpc);
        if !(1..=1_000_000_000_000).contains(&self.frequency_hz)
            || self.before_qpc <= 0
            || timestamp_qpc <= 0
            || width < 0
            || width * 10 > frequency
            || i128::from(self.utc_filetime_100ns) <= UNIX_FILETIME
        {
            return Err("Invalid Windows process clock sample".into());
        }
        let midpoint = i128::from(self.before_qpc) + width / 2;
        let delta = i128::from(timestamp_qpc) - midpoint;
        if delta.abs() > frequency * 300 {
            return Err("Windows process clock sample is too distant".into());
        }
        let utc =
            i128::from(self.utc_filetime_100ns) - UNIX_FILETIME + delta * 10_000_000 / frequency;
        let time_ms = u64::try_from(utc / 10_000)
            .ok()
            .filter(|value| *value != 0)
            .ok_or("Windows process clock mapping is out of range")?;
        // Rounded up for the sample bracket and millisecond/QPC quantization.
        let uncertainty = (width * 1000 + 2 * frequency - 1) / (2 * frequency) + 1;
        Ok((time_ms, uncertainty as u64))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProcessOriginal {
    pub stream_id: String,
    pub receipt_sequence: u64,
    pub clock: QpcClock,
    pub header: EventHeader,
    pub buffer_context: BufferContext,
    pub extended_data: Vec<ExtendedData>,
    pub user_data_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsProcessChange {
    Start,
    End,
    RundownStart,
    RundownEnd,
    Defunct,
    /// A separate PID-only termination report, not End or a verified lifetime.
    Terminate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsProcessTimeBasis {
    CollectorQpcEstimate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProcessEvent {
    pub original: WindowsProcessOriginal,
    pub change: WindowsProcessChange,
    pub pointer_bits: u8,
    /// Reported target fields, not a verified current PID/incarnation/ancestry.
    pub pid: u32,
    /// Lifecycle-only fields are absent from the PID-only Terminate layout.
    pub parent_pid: Option<u32>,
    pub session_id: Option<u32>,
    pub exit_status: Option<i32>,
    pub unique_process_key: Option<u64>,
    pub process_flags: Option<u32>,
    pub user_sid: Option<String>,
    /// The ANSI image field is bytes: no machine code page or path is guessed.
    pub image_name_bytes_hex: Option<String>,
    pub command_line: Option<String>,
    pub package_full_name: Option<String>,
    pub application_id: Option<String>,
    pub time_ms: u64,
    /// Sample-bracket/rounding allowance only, not a bound on wall-clock drift,
    /// corrections, suspend behavior or cross-host timestamp accuracy.
    pub time_uncertainty_ms: u64,
    pub time_basis: WindowsProcessTimeBasis,
}
impl WindowsProcessEvent {
    pub fn from_original(original: WindowsProcessOriginal) -> Result<Self, String> {
        let event = parse::decode(original)?;
        event.check_size()?;
        Ok(event)
    }
    pub fn event_id(&self) -> String {
        // Struct field order is fixed; no unordered maps or normalized display
        // fields enter identity. Replaying persisted originals keeps this ID.
        crate::hash(
            &serde_json::to_vec(&("windows-process-event-v1", &self.original))
                .expect("Windows process originals contain only JSON-serializable scalars"),
        )
    }
    fn check_size(&self) -> Result<(), String> {
        if serde_json::to_vec(self)
            .map_err(|_| "Windows process serialization failed")?
            .len()
            > MAX_SERIALIZED_EVENT_BYTES
        {
            return Err("Windows process event exceeds transport budget".into());
        }
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        self.check_size()?;
        if self.time_ms > now.saturating_add(60_000)
            || parse::decode(self.original.clone())? != *self
        {
            return Err("Windows process facts do not match their original record".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProcessEventHealth {
    pub stream_id: String,
    pub state: String,
    pub started_ms: u64,
    pub checked_ms: u64,
    pub subscriptions: u64,
    pub received_records: u64,
    pub admitted_records: u64,
    pub rejected_records: u64,
    pub callback_drops: u64,
    pub queue_drops: u64,
    pub events_lost: u64,
    pub log_buffers_lost: u64,
    pub realtime_buffers_lost: u64,
    /// Sticky gap signals include every restart interval; not an exact number
    /// of missing events and never a claim that real-time ETW can replay gaps.
    pub loss_signals: u64,
    pub backpressured: bool,
    pub error: String,
}
impl WindowsProcessEventHealth {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::hex_id(&self.stream_id)
            || !["starting", "active", "degraded", "stopped"].contains(&self.state.as_str())
            || self.started_ms == 0
            || self.error.len() > 512
            || self.admitted_records > self.received_records
            || (self.state == "active" && self.subscriptions == 0)
        {
            return Err("Invalid Windows process-event health".into());
        }
        Ok(())
    }
    pub fn healthy(&self, now: u64) -> bool {
        self.validate().is_ok()
            && self.state == "active"
            && self.error.is_empty()
            && !self.backpressured
            && self.loss_signals == 0
            && self.rejected_records == 0
            && self.callback_drops == 0
            && self.queue_drops == 0
            && self.events_lost == 0
            && self.log_buffers_lost == 0
            && self.realtime_buffers_lost == 0
            && self.checked_ms >= self.started_ms
            && self.checked_ms <= now.saturating_add(1000)
            && now.saturating_sub(self.checked_ms) <= 30_000
    }
}
