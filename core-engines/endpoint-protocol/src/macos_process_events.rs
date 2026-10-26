//! A bounded owned projection of selected Endpoint Security NOTIFY fields.
//! This is not a complete `es_message_t`, process snapshot, or ancestry proof.
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

pub const PROJECTION_VERSION: u32 = 1;
pub const MIN_MESSAGE_VERSION: u32 = 5;
pub const MAX_PATH_BYTES: usize = 16 * 1024;
/// Maximum serialized JSON bytes of the exact owned original projection.
/// The whole event/envelope has a separate MAX_SERIALIZED_EVENT_BYTES limit.
pub const MAX_ORIGINAL_BYTES: usize = 48 * 1024;
pub const MAX_SERIALIZED_EVENT_BYTES: usize = 128 * 1024;

/// Stable configured policy, independent of transient observed mute tokens.
/// Runtime macOS 12+ and message >=5 are separate requirements; compatibility
/// of that profile with every macOS 12 release has not been established.
pub fn source_policy_sha256() -> String {
    crate::hash(b"macos-process-policy-v1;macos>=12;message>=5;notify=9,11,15;projection=1;path=16384;original-json=49152;envelope=131072;owned-client-unmute=only-subscribed-intersections;preserve-other-mutes;requery-scope;argv=excluded;env=excluded")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosEventTime {
    pub seconds: i64,
    pub nanoseconds: i64,
}
impl MacosEventTime {
    fn milliseconds(&self) -> Result<u64, String> {
        if self.seconds <= 0 || !(0..1_000_000_000).contains(&self.nanoseconds) {
            return Err("Invalid macOS event timestamp".into());
        }
        u64::try_from(i128::from(self.seconds) * 1000 + i128::from(self.nanoseconds) / 1_000_000)
            .map_err(|_| "macOS event timestamp exceeds range".into())
    }
}

/// Collector-captured clock metadata, not an additional field of the ES message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosMachTimebase {
    pub numerator: u32,
    pub denominator: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosExecutable {
    pub path_bytes_hex: String,
    pub path_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosProcessProjection {
    pub audit_token: [u32; 8],
    pub parent_audit_token: [u32; 8],
    pub responsible_audit_token: [u32; 8],
    pub ppid: i32,
    pub original_ppid: i32,
    pub group_id: i32,
    pub session_id: i32,
    pub executable: MacosExecutable,
}
impl MacosProcessProjection {
    /// Reported audit-token PID, not a lookup of a current process.
    pub fn pid(&self) -> u32 {
        self.audit_token[5]
    }
    /// An execution discriminator, not a process lifetime or cross-host key.
    pub fn pid_version(&self) -> u32 {
        self.audit_token[7]
    }
    fn validate(&self) -> Result<(), String> {
        let path = &self.executable.path_bytes_hex;
        if self.pid() == 0
            || self.pid() > i32::MAX as u32
            || path.len() > MAX_PATH_BYTES * 2
            || !path.len().is_multiple_of(2)
            || !path
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Invalid macOS process projection".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosNotifyResult {
    Auth { result: u32 },
    Flags { flags: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosProcessPayload {
    Exec { target: MacosProcessProjection },
    Fork { child: MacosProcessProjection },
    Exit { raw_wait_status: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosProcessOriginal {
    pub projection_version: u32,
    pub stream_id: String,
    pub receipt_sequence: u64,
    pub message_version: u32,
    pub event_type: u32,
    pub action_type: u32,
    pub notify_result: MacosNotifyResult,
    pub time: MacosEventTime,
    pub mach_time: u64,
    pub mach_timebase: MacosMachTimebase,
    pub seq_num: u64,
    pub global_seq_num: u64,
    pub actor: MacosProcessProjection,
    pub event: MacosProcessPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosProcessChange {
    Exec,
    Fork,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosProcessTimeBasis {
    EndpointSecurityEventTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosProcessEvent {
    pub original: MacosProcessOriginal,
    pub change: MacosProcessChange,
    pub actor_pid: u32,
    pub actor_pid_version: u32,
    pub pid: u32,
    pub pid_version: u32,
    pub time_ms: u64,
    pub time_basis: MacosProcessTimeBasis,
}
impl MacosProcessEvent {
    pub fn from_original(original: MacosProcessOriginal) -> Result<Self, String> {
        if original.projection_version != PROJECTION_VERSION
            || original.message_version < MIN_MESSAGE_VERSION
            || !crate::hex_id(&original.stream_id)
            || original.receipt_sequence == 0
            || original.action_type != 1
            || original.mach_timebase.numerator == 0
            || original.mach_timebase.denominator == 0
            || matches!(original.notify_result, MacosNotifyResult::Auth { result } if result > 1)
        {
            return Err("Invalid macOS process source projection".into());
        }
        let time_ms = original.time.milliseconds()?;
        original.actor.validate()?;
        let (event_type, change, subject) = match &original.event {
            MacosProcessPayload::Exec { target } => {
                target.validate()?;
                (9, MacosProcessChange::Exec, target)
            }
            MacosProcessPayload::Fork { child } => {
                child.validate()?;
                (11, MacosProcessChange::Fork, child)
            }
            MacosProcessPayload::Exit { .. } => (15, MacosProcessChange::Exit, &original.actor),
        };
        if original.event_type != event_type
            || serde_json::to_vec(&original)
                .map_err(|_| "macOS original serialization failed")?
                .len()
                > MAX_ORIGINAL_BYTES
        {
            return Err("macOS event payload or projection budget mismatch".into());
        }
        let event = Self {
            change,
            actor_pid: original.actor.pid(),
            actor_pid_version: original.actor.pid_version(),
            pid: subject.pid(),
            pid_version: subject.pid_version(),
            time_ms,
            time_basis: MacosProcessTimeBasis::EndpointSecurityEventTime,
            original,
        };
        event.check_size()?;
        Ok(event)
    }
    pub fn subject(&self) -> &MacosProcessProjection {
        match &self.original.event {
            MacosProcessPayload::Exec { target } => target,
            MacosProcessPayload::Fork { child } => child,
            MacosProcessPayload::Exit { .. } => &self.original.actor,
        }
    }
    pub fn event_id(&self) -> String {
        crate::hash(
            &serde_json::to_vec(&("macos-process-projection-v1", &self.original))
                .expect("macOS projections contain only JSON-serializable scalars"),
        )
    }
    fn check_size(&self) -> Result<(), String> {
        if serde_json::to_vec(self)
            .map_err(|_| "macOS event serialization failed")?
            .len()
            > MAX_SERIALIZED_EVENT_BYTES
        {
            return Err("macOS process event exceeds transport budget".into());
        }
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        self.check_size()?;
        if self.time_ms > now.saturating_add(60_000)
            || Self::from_original(self.original.clone())? != *self
        {
            return Err("macOS process facts do not match their retained projection".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosProcessEventHealth {
    pub stream_id: String,
    pub state: String,
    pub source_policy_sha256: String,
    pub started_ms: u64,
    pub checked_ms: u64,
    /// Current confirmed subscribed event kinds; healthy requires all three.
    pub subscriptions: u64,
    pub received_records: u64,
    pub admitted_records: u64,
    pub rejected_records: u64,
    pub callback_drops: u64,
    pub queue_drops: u64,
    pub transport_errors: u64,
    pub global_sequence_gaps: u64,
    pub event_sequence_gaps: u64,
    pub sequence_regressions: u64,
    pub loss_signals: u64,
    pub scope_checked_ms: u64,
    pub mute_snapshot_sha256: String,
    pub muted_process_count: u64,
    pub muted_path_count: u64,
    pub subscribed_mute_count: u64,
    pub backpressured: bool,
    pub error: String,
}
impl MacosProcessEventHealth {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::hex_id(&self.stream_id)
            || !crate::hex_id(&self.source_policy_sha256)
            || !["starting", "active", "degraded", "stopped"].contains(&self.state.as_str())
            || self.started_ms == 0
            || self.error.len() > 512
            || self
                .admitted_records
                .checked_add(self.rejected_records)
                .is_none_or(|count| count > self.received_records)
            || (!self.mute_snapshot_sha256.is_empty() && !crate::hex_id(&self.mute_snapshot_sha256))
            || self.subscriptions > 3
        {
            return Err("Invalid macOS process-event health".into());
        }
        Ok(())
    }
    pub fn healthy(&self, now: u64) -> bool {
        let fresh = |time| {
            time >= self.started_ms
                && time <= now.saturating_add(1000)
                && now.saturating_sub(time) <= 30_000
        };
        self.validate().is_ok()
            && self.state == "active"
            && self.subscriptions == 3
            && self.source_policy_sha256 == source_policy_sha256()
            && self.error.is_empty()
            && !self.backpressured
            && self.loss_signals == 0
            && self.rejected_records == 0
            && self.callback_drops == 0
            && self.queue_drops == 0
            && self.transport_errors == 0
            && self.global_sequence_gaps == 0
            && self.event_sequence_gaps == 0
            && self.sequence_regressions == 0
            && self.subscribed_mute_count == 0
            && crate::hex_id(&self.mute_snapshot_sha256)
            && fresh(self.checked_ms)
            && fresh(self.scope_checked_ms)
    }
}
