//! Owned, bounded transport for a separate Endpoint Security NOTIFY client.
//! The retained original is an explicit semantic projection, not native memory.
use athernex_endpoint_protocol::macos_authentication::{
    MacosAuthentication, MacosAuthenticationHealth,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

mod client;
#[cfg(target_os = "macos")]
mod native;
#[cfg(any(target_os = "macos", test))]
mod queue;
#[cfg(test)]
mod tests;
mod transport;

pub use client::{verify_helper, Client};
#[cfg(target_os = "macos")]
pub use native::run_owned;

pub const MAX_RECORDS: usize = crate::macos_notify::MAX_RECORDS;
pub const MAX_QUEUE_BYTES: usize = crate::macos_notify::MAX_QUEUE_BYTES;
pub const MAX_BATCH_RECORDS: usize = crate::macos_notify::MAX_BATCH_RECORDS;
pub const MAX_FRAME_BYTES: usize = crate::macos_notify::MAX_FRAME_BYTES;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Native source counters. Durable admission/queue/transport counters are
    /// added by the owning endpoint after its database transaction.
    pub health: MacosAuthenticationHealth,
    pub pending_records: u64,
    pub pending_bytes: u64,
}
impl Status {
    fn validate(&self, stream: &str) -> crate::Result<()> {
        self.health
            .validate()
            .map_err(|_| "Invalid authentication source status")?;
        if self.health.stream_id != stream
            || self.health.source_policy_sha256
                != athernex_endpoint_protocol::macos_authentication::source_policy_sha256()
            || self.pending_records > MAX_RECORDS as u64
            || self.pending_records > self.health.received_records
            || self.pending_bytes > MAX_QUEUE_BYTES as u64
            || self.health.subscriptions > 1
            || self.health.admitted_records != 0
            || self.health.queue_drops != 0
            || self.health.transport_errors != 0
            || ![
                "",
                "Authentication notification callback failed",
                "Authentication notification coverage is incomplete",
                "Authentication notification scope changed",
            ]
            .contains(&self.health.error.as_str())
        {
            return Err("Invalid authentication source status binding".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    /// Zero denotes an empty poll. Nonzero batches require explicit commit.
    pub batch_id: u64,
    pub events: Vec<MacosAuthentication>,
    pub status: Status,
}
impl Delivery {
    fn validate(&self, stream: &str) -> crate::Result<()> {
        self.status.validate(stream)?;
        if self.events.len() > MAX_BATCH_RECORDS
            || self.events.len() as u64 > self.status.pending_records
            || self.events.is_empty() != (self.batch_id == 0)
        {
            return Err("Invalid authentication source batch".into());
        }
        let mut previous = 0;
        for event in &self.events {
            event
                .validate(now_ms())
                .map_err(|_| "Invalid authentication source event")?;
            if event.original.stream_id != stream
                || event.original.receipt_sequence <= previous
                || event.original.receipt_sequence > self.status.health.received_records
            {
                return Err("Invalid authentication source receipt order".into());
            }
            previous = event.original.receipt_sequence;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |t| u64::try_from(t.as_millis()).unwrap_or(u64::MAX))
}
