//! Kernel lifecycle notifications are distinct from sampled process metadata.
//! IDs are those reported by the initial Linux PID namespace. An event does not
//! establish an executable path, command line, or a PID's current incarnation.
use crate::hex_id;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Fork {
        parent_pid: u32,
        parent_tid: u32,
    },
    Exec,
    UserId {
        real: u32,
        effective: u32,
    },
    GroupId {
        real: u32,
        effective: u32,
    },
    Session,
    Ptrace {
        tracer_pid: u32,
        tracer_tid: u32,
    },
    Name {
        bytes_hex: String,
    },
    CoreDump {
        parent_pid: u32,
        parent_tid: u32,
    },
    Exit {
        parent_pid: u32,
        parent_tid: u32,
        code: u32,
        signal: u32,
    },
}
impl Change {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Fork { .. } => "fork",
            Self::Exec => "exec",
            Self::UserId { .. } => "user ID",
            Self::GroupId { .. } => "group ID",
            Self::Session => "session",
            Self::Ptrace { .. } => "ptrace",
            Self::Name { .. } => "name",
            Self::CoreDump { .. } => "core dump",
            Self::Exit { .. } => "exit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvent {
    pub cpu: u32,
    pub sequence: u32,
    /// CLOCK_MONOTONIC time from the kernel; unlike wall time it excludes suspend.
    pub monotonic_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub change: Change,
}
impl ProcessEvent {
    pub fn validate(&self) -> Result<(), String> {
        if self.cpu >= 8192 || self.monotonic_ns == 0 || self.pid == 0 || self.tid == 0 {
            return Err("Invalid kernel process event identity".into());
        }
        if let Change::Name { bytes_hex } = &self.change {
            if bytes_hex.len() != 32
                || !bytes_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("Kernel process name must preserve its 16 original bytes".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEventHealth {
    pub boot_id: String,
    pub stream_id: String,
    pub state: String,
    pub started_ms: u64,
    pub checked_ms: u64,
    pub received_events: u64,
    pub dropped_events: u64,
    /// Notifications of loss, not an exact count of missing kernel events.
    pub loss_signals: u64,
    pub subscriptions: u64,
    pub error: String,
}
impl ProcessEventHealth {
    pub fn validate(&self) -> Result<(), String> {
        if !hex_id(&self.boot_id)
            || !hex_id(&self.stream_id)
            || !["starting", "active", "degraded", "stopped"].contains(&self.state.as_str())
            || self.error.len() > 512
            || self.started_ms == 0
            || self.subscriptions == 0
        {
            return Err("Invalid native process-event health".into());
        }
        Ok(())
    }
    pub fn healthy(&self, now: u64) -> bool {
        self.state == "active"
            && self.error.is_empty()
            && self.loss_signals == 0
            && self.dropped_events == 0
            && self.checked_ms <= now.saturating_add(1000)
            && now.saturating_sub(self.checked_ms) <= 30_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{telemetry::Telemetry, EndpointEvent};
    #[test]
    fn kernel_events_cannot_claim_sampled_or_verified_image_identity() {
        let mut event = EndpointEvent {
            id: "a".repeat(64),
            time_ms: 1000,
            kind: "process_event".into(),
            path: String::new(),
            sha256: String::new(),
            detection: String::new(),
            detail: String::new(),
            telemetry: Some(Telemetry::ProcessEvent {
                boot_id: "b".repeat(64),
                stream_id: "c".repeat(64),
                event: ProcessEvent {
                    cpu: 0,
                    sequence: 4,
                    monotonic_ns: 100,
                    pid: 12,
                    tid: 13,
                    change: Change::Exec,
                },
            }),
        };
        event.validate(1000).unwrap();
        assert!(event.telemetry.as_ref().unwrap().process().is_none());
        event.path = "/unverified/image".into();
        assert!(event.validate(1000).is_err());
        event.path.clear();
        event.sha256 = "a".repeat(64);
        assert!(event.validate(1000).is_err());
        event.sha256.clear();
        event.kind = "process".into();
        assert!(event.validate(1000).is_err());
        event.kind = "process_event".into();
        event.telemetry = None;
        assert!(event.validate(1000).is_err());
        let bad = ProcessEvent {
            cpu: 0,
            sequence: 4,
            monotonic_ns: 100,
            pid: 12,
            tid: 13,
            change: Change::Name {
                bytes_hex: "not raw bytes".into(),
            },
        };
        assert!(bad.validate().is_err());
    }
}
