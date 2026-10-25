//! Observations preserve collection semantics: a snapshot is not an execution trace.
use crate::{hex_id, text};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub started_ms: u64,
    pub parent_started_ms: Option<u64>,
    pub name: String,
    pub executable: Option<String>,
    pub user_id: Option<String>,
}
impl ProcessObservation {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.pid == 0
            || !text(&self.name, 256)
            || self.started_ms > now.saturating_add(60_000)
            || self
                .parent_started_ms
                .is_some_and(|s| s > now.saturating_add(60_000))
            || self
                .executable
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 1024 || p.contains('\0'))
            || self.user_id.as_ref().is_some_and(|u| !text(u, 128))
        {
            return Err("Invalid process observation".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionObservation {
    pub protocol: String,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: String,
    pub owner_pid: Option<u32>,
    // Missing ownership is explicitly unknown, never attributed to an arbitrary PID.
    pub process: Option<ProcessObservation>,
}
impl ConnectionObservation {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if !["tcp", "udp"].contains(&self.protocol.as_str())
            || !text(&self.state, 32)
            || (self.protocol == "udp" && self.remote.is_some())
            || self.owner_pid == Some(0)
        {
            return Err("Invalid connection observation".into());
        }
        if let Some(p) = &self.process {
            p.validate(now)?;
        }
        if self
            .process
            .as_ref()
            .is_some_and(|p| Some(p.pid) != self.owner_pid)
        {
            return Err("Connection ownership does not match process".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Telemetry {
    NetworkEvent {
        boot_id: String,
        stream_id: String,
        namespace: u64,
        sequence: u64,
        monotonic_ns: u64,
        event: crate::network_events::NetworkEvent,
    },
    Authentication {
        event: crate::authentication::Authentication,
    },
    WindowsAuthentication {
        event: crate::windows_authentication::WindowsAuthentication,
    },
    WindowsProcessEvent {
        event: crate::windows_process_events::WindowsProcessEvent,
    },
    ProcessEvent {
        boot_id: String,
        stream_id: String,
        event: crate::process_events::ProcessEvent,
    },
    Process {
        boot_id: String,
        process: ProcessObservation,
    },
    Connection {
        boot_id: String,
        connection: ConnectionObservation,
    },
}
impl Telemetry {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NetworkEvent { .. } => "network_event",
            Self::Authentication { .. } | Self::WindowsAuthentication { .. } => "authentication",
            Self::WindowsProcessEvent { .. } => "windows_process_event",
            Self::ProcessEvent { .. } => "process_event",
            Self::Process { .. } => "process",
            Self::Connection { .. } => "connection",
        }
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        match self {
            Self::NetworkEvent {
                boot_id,
                stream_id,
                namespace,
                sequence,
                monotonic_ns,
                event,
            } => {
                if !hex_id(boot_id)
                    || !hex_id(stream_id)
                    || *namespace == 0
                    || *sequence == 0
                    || *monotonic_ns == 0
                {
                    return Err("Invalid network event stream identity".into());
                }
                event.validate()
            }
            Self::Authentication { event } => event.validate(now),
            Self::WindowsAuthentication { event } => event.validate(now),
            Self::WindowsProcessEvent { event } => event.validate(now),
            Self::ProcessEvent {
                boot_id,
                stream_id,
                event,
            } => {
                if !hex_id(boot_id) || !hex_id(stream_id) {
                    return Err("Invalid kernel event stream identity".into());
                }
                event.validate()
            }
            Self::Process { boot_id, process } => {
                if !hex_id(boot_id) {
                    return Err("Invalid telemetry boot identity".into());
                }
                process.validate(now)
            }
            Self::Connection {
                boot_id,
                connection,
            } => {
                if !hex_id(boot_id) {
                    return Err("Invalid telemetry boot identity".into());
                }
                connection.validate(now)
            }
        }
    }
    pub fn process(&self) -> Option<&ProcessObservation> {
        match self {
            Self::NetworkEvent { .. }
            | Self::Authentication { .. }
            | Self::WindowsAuthentication { .. } => None,
            Self::WindowsProcessEvent { .. } => None,
            Self::ProcessEvent { .. } => None,
            Self::Process { process, .. } => Some(process),
            Self::Connection { connection, .. } => connection.process.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorHealth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_events: Option<crate::network_events::NetworkEventHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<crate::authentication::AuthenticationHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_authentication: Option<crate::authentication::AuthenticationHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_process_events: Option<crate::windows_process_events::WindowsProcessEventHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_events: Option<crate::process_events::ProcessEventHealth>,
    pub mode: String,
    pub last_attempt_ms: u64,
    pub last_success_ms: u64,
    pub process_count: u64,
    pub connection_count: u64,
    pub pending_changes: u64,
    pub incomplete: bool,
    pub error: String,
}
impl CollectorHealth {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(events) = &self.network_events {
            events.validate()?;
        }
        if let Some(authentication) = &self.authentication {
            authentication.validate()?;
        }
        if let Some(authentication) = &self.windows_authentication {
            authentication.validate()?;
        }
        if let Some(events) = &self.windows_process_events {
            events.validate()?;
        }
        if let Some(events) = &self.process_events {
            events.validate()?;
        }
        if !["disabled", "snapshot"].contains(&self.mode.as_str())
            || self.error.len() > 512
            || self.process_count > 8192
            || self.connection_count > 8192
            || self.pending_changes > 16384
        {
            return Err("Invalid collector health".into());
        }
        Ok(())
    }
}
