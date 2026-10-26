//! Windows kernel TCP/UDP reports preserve original bytes and reporting scope.
//! A payload PID is context, not a verified process incarnation. These reports
//! establish neither packet delivery, complete socket lifetimes nor firewall decisions.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// These are semantic ETW/clock structures, shared without process-event decoding.
pub use crate::windows_process_events::{
    BufferContext, EventDescriptor, EventHeader, ExtendedData, QpcClock,
};
mod parse;
#[cfg(test)]
mod tests;

pub const TCP_PROVIDER: &str = "{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}";
pub const UDP_PROVIDER: &str = "{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}";
pub const MAX_ORIGINAL_BYTES: usize = 48 * 1024;
pub const MAX_SERIALIZED_EVENT_BYTES: usize = 128 * 1024;
pub const MAX_EXTENDED_ITEMS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNetworkOriginal {
    pub stream_id: String,
    /// Collector receipt order; never the payload's seqnum or connid.
    pub receipt_sequence: u64,
    pub clock: QpcClock,
    pub header: EventHeader,
    pub buffer_context: BufferContext,
    pub extended_data: Vec<ExtendedData>,
    pub user_data_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsNetworkOperation {
    Connect,
    Accept,
    Send,
    Receive,
    Disconnect,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsNetworkProtocol {
    Tcp,
    Udp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsNetworkFamily {
    Ipv4,
    Ipv6,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsNetworkTimeBasis {
    CollectorQpcEstimate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNetworkEvent {
    pub original: WindowsNetworkOriginal,
    pub operation: WindowsNetworkOperation,
    pub protocol: WindowsNetworkProtocol,
    pub family: WindowsNetworkFamily,
    /// Original header architecture, separate from the connection field's width.
    pub header_pointer_bits: u8,
    pub reported_pid: u32,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    /// Native size field; not an independently observed delivery byte count.
    pub reported_size: u32,
    pub time_ms: u64,
    /// Calibration bracket/rounding only; does not bound wall-clock drift or changes.
    pub time_uncertainty_ms: u64,
    pub time_basis: WindowsNetworkTimeBasis,
}
impl WindowsNetworkEvent {
    pub fn from_original(original: WindowsNetworkOriginal) -> Result<Self, String> {
        let event = parse::decode(original)?;
        event.check_size()?;
        Ok(event)
    }
    pub fn event_id(&self) -> String {
        crate::hash(
            &serde_json::to_vec(&("windows-network-event-v1", &self.original))
                .expect("Windows network originals contain only JSON-serializable scalars"),
        )
    }
    fn check_size(&self) -> Result<(), String> {
        if serde_json::to_vec(self)
            .map_err(|_| "Windows network serialization failed")?
            .len()
            > MAX_SERIALIZED_EVENT_BYTES
        {
            return Err("Windows network event exceeds transport budget".into());
        }
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        self.check_size()?;
        if self.time_ms > now.saturating_add(60_000)
            || parse::decode(self.original.clone())? != *self
        {
            return Err("Windows network facts do not match their original record".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNetworkEventHealth {
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
    /// Sticky restart/coverage signals, not an exact missing-event count.
    pub loss_signals: u64,
    pub backpressured: bool,
    pub error: String,
}
impl WindowsNetworkEventHealth {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::hex_id(&self.stream_id)
            || !["starting", "active", "degraded", "stopped"].contains(&self.state.as_str())
            || self.started_ms == 0
            || self.error.len() > 512
            || self.error.contains('\0')
            || self
                .admitted_records
                .checked_add(self.rejected_records)
                .is_none_or(|count| count > self.received_records)
            || (self.state == "active" && self.subscriptions == 0)
        {
            return Err("Invalid Windows network-event health".into());
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
