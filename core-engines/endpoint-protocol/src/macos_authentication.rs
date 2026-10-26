//! Selected owned ES authentication notification fields. A reported result is
//! neither login/session completion nor this product's prevention decision.
use crate::macos_process_events::{
    MacosEventTime, MacosMachTimebase, MacosNotifyResult, MacosProcessProjection,
    MacosProcessTimeBasis,
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

pub const PROJECTION_VERSION: u32 = 1;
pub const MIN_MESSAGE_VERSION: u32 = 5;
pub const EVENT_TYPE: u32 = 111;
pub const MAX_TOKEN_BYTES: usize = 4096;
pub const MAX_PATH_BYTES: usize = 16 * 1024;
pub const MAX_ORIGINAL_BYTES: usize = 48 * 1024;
pub const MAX_SERIALIZED_EVENT_BYTES: usize = 128 * 1024;

/// Configured scope, separate from observed per-session mute inventory.
pub fn source_policy_sha256() -> String {
    crate::hash(b"macos-authentication-policy-v1;macos>=13;message>=5;notify=111;authentication=0,1,2,3;projection=1;token=4096;path=16384;original-json=49152;envelope=131072;uid-presence=has_uid;optional-token-presence=retained;owned-client-unmute=only-subscribed-intersections;preserve-other-mutes;requery-scope;newer-instigator-token=excluded;argv=excluded;env=excluded")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosAuthenticationPayload {
    OpenDirectory {
        instigator: Option<MacosProcessProjection>,
        record_type_hex: String,
        record_name_hex: String,
        node_name_hex: String,
        db_path_hex: Option<String>,
    },
    TouchId {
        instigator: Option<MacosProcessProjection>,
        mode: u32,
        has_uid: bool,
        uid: Option<u32>,
    },
    Token {
        instigator: Option<MacosProcessProjection>,
        pubkey_hash_hex: String,
        token_id_hex: String,
        kerberos_principal_hex: Option<String>,
    },
    AutoUnlock {
        username_hex: String,
        purpose: u32,
    },
}
impl MacosAuthenticationPayload {
    pub fn instigator(&self) -> Option<&MacosProcessProjection> {
        match self {
            Self::OpenDirectory { instigator, .. }
            | Self::TouchId { instigator, .. }
            | Self::Token { instigator, .. } => instigator.as_ref(),
            Self::AutoUnlock { .. } => None,
        }
    }
    fn validate(&self) -> Result<(u32, MacosAuthenticationMechanism), String> {
        if let Some(process) = self.instigator() {
            process.validate()?;
        }
        match self {
            Self::OpenDirectory {
                record_type_hex,
                record_name_hex,
                node_name_hex,
                db_path_hex,
                ..
            } => {
                for field in [record_type_hex, record_name_hex, node_name_hex] {
                    token(field, MAX_TOKEN_BYTES)?;
                }
                if let Some(path) = db_path_hex {
                    token(path, MAX_PATH_BYTES)?;
                }
                Ok((0, MacosAuthenticationMechanism::OpenDirectory))
            }
            Self::TouchId {
                mode, has_uid, uid, ..
            } => {
                // has_uid alone controls union presence; success and mode do
                // not authorize reading otherwise absent native union bytes.
                if *mode > 1 || *has_uid != uid.is_some() {
                    return Err("Invalid macOS TouchID projection".into());
                }
                Ok((1, MacosAuthenticationMechanism::TouchId))
            }
            Self::Token {
                pubkey_hash_hex,
                token_id_hex,
                kerberos_principal_hex,
                ..
            } => {
                token(pubkey_hash_hex, MAX_TOKEN_BYTES)?;
                token(token_id_hex, MAX_TOKEN_BYTES)?;
                if let Some(principal) = kerberos_principal_hex {
                    token(principal, MAX_TOKEN_BYTES)?;
                }
                Ok((2, MacosAuthenticationMechanism::Token))
            }
            Self::AutoUnlock {
                username_hex,
                purpose,
            } => {
                token(username_hex, MAX_TOKEN_BYTES)?;
                if ![1, 2].contains(purpose) {
                    return Err("Invalid macOS Auto Unlock projection".into());
                }
                Ok((3, MacosAuthenticationMechanism::AutoUnlock))
            }
        }
    }
}
fn token(value: &str, max: usize) -> Result<(), String> {
    if value.len() > max * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid macOS authentication token bytes".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosAuthenticationOriginal {
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
    /// Native message.process; not a substitution for optional instigator.
    pub event_process: MacosProcessProjection,
    pub success: bool,
    pub authentication_type: u32,
    pub authentication: MacosAuthenticationPayload,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosAuthenticationMechanism {
    OpenDirectory,
    TouchId,
    Token,
    AutoUnlock,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosAuthentication {
    pub original: MacosAuthenticationOriginal,
    pub mechanism: MacosAuthenticationMechanism,
    pub reported_success: bool,
    pub time_ms: u64,
    pub time_basis: MacosProcessTimeBasis,
}
impl MacosAuthentication {
    pub fn from_original(original: MacosAuthenticationOriginal) -> Result<Self, String> {
        if original.projection_version != PROJECTION_VERSION
            || original.message_version < MIN_MESSAGE_VERSION
            || original.event_type != EVENT_TYPE
            || original.action_type != 1
            || !crate::hex_id(&original.stream_id)
            || original.receipt_sequence == 0
            || original.mach_timebase.numerator == 0
            || original.mach_timebase.denominator == 0
            || matches!(original.notify_result, MacosNotifyResult::Auth { result } if result > 1)
        {
            return Err("Invalid macOS authentication source projection".into());
        }
        let time_ms = original.time.milliseconds()?;
        original.event_process.validate()?;
        let (kind, mechanism) = original.authentication.validate()?;
        if original.authentication_type != kind
            || serde_json::to_vec(&original)
                .map_err(|_| "macOS authentication original serialization failed")?
                .len()
                > MAX_ORIGINAL_BYTES
        {
            return Err("macOS authentication payload or original budget mismatch".into());
        }
        let event = Self {
            mechanism,
            reported_success: original.success,
            time_ms,
            time_basis: MacosProcessTimeBasis::EndpointSecurityEventTime,
            original,
        };
        event.check_size()?;
        Ok(event)
    }
    /// This source reports authentication factors/mechanisms, not a complete
    /// service login. Do not feed generic failed-login or Allow correlations.
    pub fn service_outcome(&self) -> Option<crate::authentication::AuthenticationOutcome> {
        None
    }
    pub fn event_id(&self) -> String {
        crate::hash(
            &serde_json::to_vec(&("macos-authentication-projection-v1", &self.original))
                .expect("Authentication projections contain only serializable scalar fields"),
        )
    }
    fn check_size(&self) -> Result<(), String> {
        if serde_json::to_vec(self)
            .map_err(|_| "macOS authentication serialization failed")?
            .len()
            > MAX_SERIALIZED_EVENT_BYTES
        {
            return Err("macOS authentication exceeds transport budget".into());
        }
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        self.check_size()?;
        if self.time_ms > now.saturating_add(60_000)
            || Self::from_original(self.original.clone())? != *self
        {
            return Err("macOS authentication facts do not match retained projection".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosAuthenticationHealth {
    pub stream_id: String,
    pub state: String,
    pub source_policy_sha256: String,
    pub started_ms: u64,
    pub checked_ms: u64,
    /// Current confirmed subscribed event kinds; healthy requires the one authentication event kind.
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
impl MacosAuthenticationHealth {
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
            || self.subscriptions > 1
            || (self.state == "stopped" && self.subscriptions != 0)
        {
            return Err("Invalid macOS authentication health".into());
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
            && self.subscriptions == 1
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
