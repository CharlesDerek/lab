//! Netfilter tracker observations, not socket ownership or firewall verdicts.
use crate::hex_id;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    Created,
    Updated,
    Removed,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}
impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tuple {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub zone: Option<u16>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkEvent {
    pub change: Change,
    pub protocol: Protocol,
    /// Kernel tracker IDs may be reused. They are not a durable flow identity.
    pub tracker_id: u32,
    pub status: u32,
    pub original: Tuple,
    pub reply: Tuple,
    pub zone: Option<u16>,
    pub mark: Option<u32>,
    pub timeout_seconds: Option<u32>,
    pub tcp_state: Option<u8>,
    /// Cumulative tracker counters, not deltas, application bytes or wire totals.
    pub original_counters: Option<Counters>,
    pub reply_counters: Option<Counters>,
    pub started_ns: Option<u64>,
    pub stopped_ns: Option<u64>,
    /// Originating netlink port for reported mutations; never interpreted as PID.
    pub origin_port: u32,
}
impl NetworkEvent {
    pub fn validate(&self) -> Result<(), String> {
        let ipv4 = self.original.source.is_ipv4();
        if [
            self.original.destination,
            self.reply.source,
            self.reply.destination,
        ]
        .iter()
        .any(|a| a.is_ipv4() != ipv4)
            || (self.protocol == Protocol::Udp && self.tcp_state.is_some())
        {
            return Err("Invalid kernel tracker observation".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEventHealth {
    pub boot_id: String,
    pub stream_id: String,
    pub namespace: u64,
    /// IP families with observed tracking and confirmation hooks (4 and/or 6).
    pub families: Vec<u8>,
    pub state: String,
    pub started_ms: u64,
    pub checked_ms: u64,
    pub source_checked_ms: u64,
    pub received_events: u64,
    pub skipped_protocols: u64,
    pub dropped_events: u64,
    pub loss_signals: u64,
    pub subscriptions: u64,
    pub error: String,
}
impl NetworkEventHealth {
    pub fn validate(&self) -> Result<(), String> {
        if !hex_id(&self.boot_id)
            || !hex_id(&self.stream_id)
            || self.namespace == 0
            || !matches!(self.families.as_slice(), [] | [4] | [6] | [4, 6])
            || !["starting", "active", "degraded", "stopped"].contains(&self.state.as_str())
            || self.started_ms == 0
            || self.subscriptions == 0
            || self.error.len() > 512
        {
            return Err("Invalid network-event collector health".into());
        }
        Ok(())
    }
    pub fn healthy(&self, now: u64) -> bool {
        self.state == "active"
            && !self.families.is_empty()
            && self.error.is_empty()
            && self.dropped_events == 0
            && self.loss_signals == 0
            && self.checked_ms <= now.saturating_add(1000)
            && now.saturating_sub(self.checked_ms) <= 30_000
            && self.source_checked_ms <= now.saturating_add(1000)
            && now.saturating_sub(self.source_checked_ms) <= 15_000
    }
}
