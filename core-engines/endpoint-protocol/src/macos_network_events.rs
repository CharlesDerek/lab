//! Selected NetworkExtension new-flow metadata, not a packet trace or connection lifetime.
//! Receipt time/order are collector facts. Upstream OS loss accounting is unavailable.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[cfg(test)]
mod tests;

pub const PROJECTION_VERSION: u32 = 1;
pub const MAX_ORIGINAL_BYTES: usize = 48 * 1024;
pub const MAX_SERIALIZED_EVENT_BYTES: usize = 128 * 1024;
pub const MAX_PENDING_RECORDS: u64 = 2048;
pub const MAX_PENDING_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_BATCH_RECORDS: usize = 64;
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
pub const MAX_CONTROL_BYTES: usize = 4096;
pub fn source_policy_sha256() -> String {
    crate::hash(POLICY.as_bytes())
}
const POLICY: &str = "macos-network-metadata-v1;runtime=macos13+;callback=handleNewFlow;projection=1;filterSockets=true;filterBrowsers=false;rules=TCP:anynetwork:anydirection:filterData,UDP:anynetwork:anydirection:filterData;default=allow;callbackVerdict=allow;family=darwin2|30;type=stream1|dgram2;protocol=0:undetermined|6:stream1|17:dgram2;direction=0:unspecified|1:inbound|2:outbound;endpoints=optional-numeric-only-no-resolution;ipv6-scope=optional-numeric;tokens=optional-separate-app-and-process-exact32B;time=collector-receipt-timespec;sequence=collector-serialized-admission-attempt-ordinal;upstream-loss=unavailable;no-packets-urls-hostnames-app-strings-binary-ids-report-bytes-end-events;original-json=49152;event-and-envelope-json=131072;queue-records=2048;queue-original-bytes=8388608;batch-records=64;batch-frame-bytes=1048576;transport=root-euid-and-bidirectional-pre-resume-code-requirements;commit-before-ack;provider-owned-stream;one-consumer;one-inflight;epoch-bound;close=detach-only";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosNetworkEndpoint {
    pub address: IpAddr,
    pub port: u16,
    /// Numeric source scope only; no interface lookup or inferred scope.
    pub scope_id: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosNetworkReceiptTime {
    pub seconds: i64,
    pub nanoseconds: i64,
}
impl MacosNetworkReceiptTime {
    fn milliseconds(&self) -> Result<u64, String> {
        if !(0..1_000_000_000).contains(&self.nanoseconds) {
            return Err("Invalid macOS network receipt time".into());
        }
        u64::try_from(self.seconds)
            .ok()
            .and_then(|s| s.checked_mul(1000))
            .and_then(|s| s.checked_add(self.nanoseconds as u64 / 1_000_000))
            .ok_or_else(|| "Invalid macOS network receipt time".into())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkCallback {
    NewFlow,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosNetworkOriginal {
    pub projection_version: u32,
    pub stream_id: String,
    /// Allocated under the successful queue lock before projection/admission.
    /// Never kernel order, callback-arrival order or a source replay cursor.
    pub receipt_sequence: u64,
    pub callback: MacosNetworkCallback,
    pub receipt_time: MacosNetworkReceiptTime,
    pub flow_id: String,
    pub direction: i32,
    pub socket_family: i32,
    pub socket_type: i32,
    pub socket_protocol: i32,
    pub local: Option<MacosNetworkEndpoint>,
    pub remote: Option<MacosNetworkEndpoint>,
    pub source_app_audit_token_hex: Option<String>,
    pub source_process_audit_token_hex: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkProtocol {
    Undetermined,
    Tcp,
    Udp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkFamily {
    Ipv4,
    Ipv6,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkDirection {
    Unspecified,
    Inbound,
    Outbound,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkTimeBasis {
    CollectorReceiptTime,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosNetworkEvent {
    pub original: MacosNetworkOriginal,
    pub protocol: MacosNetworkProtocol,
    pub family: MacosNetworkFamily,
    pub direction: MacosNetworkDirection,
    pub local: Option<MacosNetworkEndpoint>,
    pub remote: Option<MacosNetworkEndpoint>,
    pub time_ms: u64,
    pub time_basis: MacosNetworkTimeBasis,
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
impl MacosNetworkEvent {
    pub fn from_original(original: MacosNetworkOriginal) -> Result<Self, String> {
        if original.projection_version != PROJECTION_VERSION
            || !crate::hex_id(&original.stream_id)
            || original.receipt_sequence == 0
            || !uuid(&original.flow_id)
            || [
                &original.source_app_audit_token_hex,
                &original.source_process_audit_token_hex,
            ]
            .iter()
            .any(|token| token.as_ref().is_some_and(|t| !crate::hex_id(t)))
        {
            return Err("Invalid macOS network source projection".into());
        }
        let family = match original.socket_family {
            2 => MacosNetworkFamily::Ipv4,
            30 => MacosNetworkFamily::Ipv6,
            _ => return Err("Unsupported macOS network socket family".into()),
        };
        let protocol = match (original.socket_protocol, original.socket_type) {
            (0, 1 | 2) => MacosNetworkProtocol::Undetermined,
            (6, 1) => MacosNetworkProtocol::Tcp,
            (17, 2) => MacosNetworkProtocol::Udp,
            _ => return Err("Unsupported macOS network socket protocol/type".into()),
        };
        let direction = match original.direction {
            0 => MacosNetworkDirection::Unspecified,
            1 => MacosNetworkDirection::Inbound,
            2 => MacosNetworkDirection::Outbound,
            _ => return Err("Unsupported macOS network initial direction".into()),
        };
        for endpoint in [&original.local, &original.remote].into_iter().flatten() {
            if endpoint.address.is_ipv4() != (family == MacosNetworkFamily::Ipv4)
                || (endpoint.address.is_ipv4() && endpoint.scope_id.is_some())
            {
                return Err("macOS network endpoint family/scope mismatch".into());
            }
        }
        if serde_json::to_vec(&original)
            .map_err(|_| "macOS network original serialization failed")?
            .len()
            > MAX_ORIGINAL_BYTES
        {
            return Err("macOS network original exceeds budget".into());
        }
        let event = Self {
            protocol,
            family,
            direction,
            local: original.local.clone(),
            remote: original.remote.clone(),
            time_ms: original.receipt_time.milliseconds()?,
            time_basis: MacosNetworkTimeBasis::CollectorReceiptTime,
            original,
        };
        event.check_size()?;
        Ok(event)
    }
    pub fn event_id(&self) -> String {
        crate::hash(
            &serde_json::to_vec(&("macos-network-projection-v1", &self.original))
                .expect("Network projections contain only serializable scalars"),
        )
    }
    fn check_size(&self) -> Result<(), String> {
        if serde_json::to_vec(self)
            .map_err(|_| "macOS network serialization failed")?
            .len()
            > MAX_SERIALIZED_EVENT_BYTES
        {
            return Err("macOS network event exceeds transport budget".into());
        }
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        self.check_size()?;
        if self.time_ms > now.saturating_add(60_000)
            || Self::from_original(self.original.clone())? != *self
        {
            return Err("macOS network facts do not match retained projection".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkLossObservability {
    #[default]
    Unavailable,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosNetworkEventHealth {
    pub stream_id: String,
    pub state: String,
    pub source_policy_sha256: String,
    pub started_ms: u64,
    pub checked_ms: u64,
    pub received_records: u64,
    pub admitted_records: u64,
    pub excluded_records: u64,
    pub rejected_records: u64,
    pub callback_drops: u64,
    pub queue_drops: u64,
    pub transport_errors: u64,
    pub pending_records: u64,
    /// Exact retained original JSON bytes; queue/inflight counted once.
    pub pending_bytes: u64,
    pub restarts: u64,
    /// Observed unknown intervals, never a count of missing OS events.
    pub loss_signals: u64,
    pub kernel_loss_observability: MacosNetworkLossObservability,
    pub backpressured: bool,
    pub error: String,
}
impl MacosNetworkEventHealth {
    pub fn validate(&self) -> Result<(), String> {
        let accounted = [
            self.admitted_records,
            self.excluded_records,
            self.rejected_records,
            self.callback_drops,
            self.queue_drops,
        ]
        .into_iter()
        .try_fold(0u64, |sum, n| sum.checked_add(n));
        if !crate::hex_id(&self.stream_id)
            || !crate::hex_id(&self.source_policy_sha256)
            || !["starting", "active", "degraded", "stopped"].contains(&self.state.as_str())
            || self.started_ms == 0
            || self.error.len() > 512
            || self.error.contains('\0')
            || accounted.is_none_or(|n| n > self.received_records)
            || self.pending_records > MAX_PENDING_RECORDS
            || self.pending_records > self.received_records
            || self.pending_bytes > MAX_PENDING_BYTES
            || (self.pending_records == 0) != (self.pending_bytes == 0)
            || self.pending_bytes < self.pending_records
        {
            return Err("Invalid macOS network health".into());
        }
        // Pending and admitted may overlap after commit and before ACK.
        Ok(())
    }
    /// Healthy local pipeline; upstream OS loss accounting remains unavailable.
    pub fn healthy(&self, now: u64) -> bool {
        self.validate().is_ok()
            && self.state == "active"
            && self.source_policy_sha256 == source_policy_sha256()
            && self.error.is_empty()
            && !self.backpressured
            && self.restarts == 0
            && self.loss_signals == 0
            && self.rejected_records == 0
            && self.callback_drops == 0
            && self.queue_drops == 0
            && self.transport_errors == 0
            && self.checked_ms >= self.started_ms
            && self.checked_ms <= now.saturating_add(1000)
            && now.saturating_sub(self.checked_ms) <= 30_000
    }
}
