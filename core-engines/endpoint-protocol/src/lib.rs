//! Versioned endpoint contracts shared by the server and the enforcement agent.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub mod authentication;
pub mod engine;
pub mod engine_fleet;
pub mod installer;
pub mod macos_authentication;
pub mod macos_process_events;
pub mod network_events;
pub mod process_events;
pub mod protection;
pub mod telemetry;
pub mod update;
pub mod windows_authentication;
pub mod windows_network_events;
pub mod windows_process_events;

pub const PROTOCOL: u32 = 1;
pub const MAX_EVENTS: usize = 64;
pub const MAX_OUTPUT: usize = 16_384;

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn hex_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
pub fn text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
pub fn server_url(s: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(s).map_err(|_| "Invalid server URL")?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(
            "Use an HTTPS server origin, or literal loopback HTTP for local testing".into(),
        );
    }
    Ok(url)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}
impl Platform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Linux
        }
    }
}

// Credentials deliberately do not implement Debug.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub protocol: u32,
    pub server: String,
    pub enrollment_token: String,
    pub platform: Platform,
    #[serde(default)]
    pub antivirus: Vec<AntivirusPackage>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntivirusPackage {
    pub platform: Platform,
    pub arch: String,
    pub format: String,
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub bytes: u64,
}
impl AntivirusPackage {
    pub fn validate(&self) -> Result<(), String> {
        let url = url::Url::parse(&self.url).map_err(|_| "Invalid antivirus package URL")?;
        if url.scheme() != "https"
            || url.host_str() != Some("github.com")
            || !url
                .path()
                .starts_with("/Cisco-Talos/clamav/releases/download/")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !hex_id(&self.sha256)
            || !(1..=400 * 1024 * 1024).contains(&self.bytes)
            || !["msi", "pkg", "deb", "rpm"].contains(&self.format.as_str())
            || !["x86_64", "aarch64", "universal"].contains(&self.arch.as_str())
        {
            return Err("Invalid pinned antivirus package".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub protocol: u32,
    pub enrollment_token: String,
    pub endpoint_id: String,
    pub credential: String,
    pub hostname: String,
    pub platform: Platform,
    pub arch: String,
    pub version: String,
}
impl Enrollment {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol != PROTOCOL
            || !hex_id(&self.endpoint_id)
            || !hex_id(&self.credential)
            || !hex_id(&self.enrollment_token)
            || !text(&self.hostname, 128)
            || !text(&self.arch, 32)
            || !text(&self.version, 32)
        {
            return Err("Invalid endpoint enrollment".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Inventory,
    Scan {
        path: String,
    },
    UpdateSignatures,
    Quarantine {
        path: String,
        sha256: String,
    },
    Restore {
        quarantine_id: String,
    },
    Script {
        interpreter: String,
        script: String,
        sha256: String,
    },
}
impl Action {
    pub fn capability(&self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Scan { .. } => "scan",
            Self::UpdateSignatures => "update_signatures",
            Self::Quarantine { .. } => "quarantine",
            Self::Restore { .. } => "restore",
            Self::Script { .. } => "script",
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        let valid = match self {
            Self::Inventory | Self::UpdateSignatures => true,
            Self::Scan { path } => text(path, 1024) && !path.starts_with('-'),
            Self::Quarantine { path, sha256 } => {
                text(path, 1024) && !path.starts_with('-') && hex_id(sha256)
            }
            Self::Restore { quarantine_id } => hex_id(quarantine_id),
            Self::Script {
                interpreter,
                script,
                sha256,
            } => {
                ["sh", "powershell"].contains(&interpreter.as_str())
                    && !script.is_empty()
                    && script.len() <= 8192
                    && !script.contains('\0')
                    && hash(script.as_bytes()) == *sha256
            }
        };
        if valid {
            Ok(())
        } else {
            Err("Invalid or unbound endpoint action".into())
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub id: String,
    pub endpoint_id: String,
    pub action: Action,
    pub action_hash: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub timeout_secs: u64,
    pub case_id: i64,
}
impl Command {
    pub fn validate(&self, endpoint: &str, now: u64) -> Result<(), String> {
        self.action.validate()?;
        if !hex_id(&self.id)
            || self.endpoint_id != endpoint
            || self.action_hash
                != hash(&serde_json::to_vec(&self.action).map_err(|e| e.to_string())?)
            || self.created_ms > now.saturating_add(60_000)
            || now >= self.expires_ms
            || !(1..=600).contains(&self.timeout_secs)
        {
            return Err("Expired, mismatched or invalid command".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub command_id: String,
    pub action_hash: String,
    pub outcome: String,
    pub output: String,
    pub finished_ms: u64,
}
impl Receipt {
    pub fn validate(&self) -> Result<(), String> {
        if !hex_id(&self.command_id)
            || !hex_id(&self.action_hash)
            || !["succeeded", "failed", "interrupted", "refused"].contains(&self.outcome.as_str())
            || self.output.len() > MAX_OUTPUT
            || self.finished_ms > i64::MAX as u64
        {
            return Err("Invalid execution receipt".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates: Option<update::UpdateHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_updates: Option<update::UpdateHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<protection::ProtectionHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<telemetry::CollectorHealth>,
    pub version: String,
    pub capabilities: Vec<String>,
    pub scanner: String,
    pub realtime: bool,
    pub signature_version: String,
    pub spool_events: u64,
    pub error: String,
}
impl Heartbeat {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(updates) = &self.updates {
            updates.validate()?;
        }
        if let Some(updates) = &self.controller_updates {
            updates.validate()?;
        }
        if let Some(protection) = &self.protection {
            protection.validate()?;
            if self.realtime != (protection.state == "active") {
                return Err("Protection state and real-time status disagree".into());
            }
        }
        if let Some(collector) = &self.collector {
            collector.validate()?;
        }
        if !text(&self.version, 32)
            || self.capabilities.len() > 8
            || self.capabilities.iter().any(|c| {
                ![
                    "inventory",
                    "scan",
                    "update_signatures",
                    "quarantine",
                    "restore",
                    "script",
                ]
                .contains(&c.as_str())
            })
            || self.scanner.len() > 64
            || self.signature_version.len() > 256
            || self.error.len() > 512
            || self.spool_events > 1_000_000
        {
            return Err("Invalid heartbeat".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<telemetry::Telemetry>,
    pub id: String,
    pub time_ms: u64,
    pub kind: String,
    pub path: String,
    pub sha256: String,
    pub detection: String,
    pub detail: String,
}
impl EndpointEvent {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if !hex_id(&self.id)
            || self.time_ms > now.saturating_add(60_000)
            || ![
                "malware",
                "scan",
                "inventory",
                "agent_error",
                "process",
                "connection",
                "process_event",
                "network_event",
                "authentication",
                "windows_process_event",
                "macos_process_event",
                "windows_network_event",
            ]
            .contains(&self.kind.as_str())
            || self.path.len() > 1024
            || (!self.sha256.is_empty() && !hex_id(&self.sha256))
            || self.detection.len() > 256
            || self.detail.len() > 4096
        {
            return Err("Invalid endpoint event".into());
        }
        if let Some(telemetry) = &self.telemetry {
            telemetry.validate(now)?;
            if let telemetry::Telemetry::Authentication { event } = telemetry {
                if self.id != event.event_id() || self.time_ms != event.journal.realtime_us / 1000 {
                    return Err(
                        "Authentication envelope does not match journal identity/time".into(),
                    );
                }
            }
            if let telemetry::Telemetry::WindowsAuthentication { event } = telemetry {
                if self.id != event.event_id() || self.time_ms != event.time_ms {
                    return Err(
                        "Windows authentication envelope does not match XML identity/time".into(),
                    );
                }
            }
            if let telemetry::Telemetry::MacosAuthentication { event } = telemetry {
                if self.id != event.event_id() || self.time_ms != event.time_ms {
                    return Err(
                        "macOS authentication envelope does not match projection identity/time"
                            .into(),
                    );
                }
                if serde_json::to_vec(self)
                    .map_err(|_| "macOS authentication envelope serialization failed")?
                    .len()
                    > macos_authentication::MAX_SERIALIZED_EVENT_BYTES
                {
                    return Err("macOS authentication envelope exceeds transport budget".into());
                }
            }
            if let telemetry::Telemetry::MacosProcessEvent { event } = telemetry {
                if self.id != event.event_id() || self.time_ms != event.time_ms {
                    return Err(
                        "macOS process envelope does not match projection identity/time".into(),
                    );
                }
                if serde_json::to_vec(self)
                    .map_err(|_| "macOS envelope serialization failed")?
                    .len()
                    > macos_process_events::MAX_SERIALIZED_EVENT_BYTES
                {
                    return Err("macOS process envelope exceeds transport budget".into());
                }
            }
            if let telemetry::Telemetry::WindowsProcessEvent { event } = telemetry {
                if self.id != event.event_id() || self.time_ms != event.time_ms {
                    return Err(
                        "Windows process envelope does not match original identity/time".into(),
                    );
                }
            }
            if let telemetry::Telemetry::WindowsNetworkEvent { event } = telemetry {
                if self.id != event.event_id() || self.time_ms != event.time_ms {
                    return Err(
                        "Windows network envelope does not match original identity/time".into(),
                    );
                }
                if serde_json::to_vec(self)
                    .map_err(|_| "Windows network envelope serialization failed")?
                    .len()
                    > windows_network_events::MAX_SERIALIZED_EVENT_BYTES
                {
                    return Err("Windows network envelope exceeds transport budget".into());
                }
            }
            if telemetry.kind() != self.kind {
                return Err("Telemetry kind does not match event".into());
            }
            let observed_path = telemetry
                .process()
                .and_then(|p| p.executable.as_deref())
                .unwrap_or_default();
            if self.path != observed_path || !self.sha256.is_empty() || !self.detection.is_empty() {
                return Err("Snapshot evidence does not match its typed observation".into());
            }
        } else if [
            "process",
            "connection",
            "process_event",
            "network_event",
            "authentication",
            "windows_process_event",
            "macos_process_event",
            "windows_network_event",
        ]
        .contains(&self.kind.as_str())
        {
            return Err("Typed telemetry is required".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_event_encoding_and_typed_observation_boundaries() {
        let legacy = format!(
            r#"{{"id":"{}","time_ms":10000,"kind":"inventory","path":"","sha256":"","detection":"","detail":"public fixture"}}"#,
            "a".repeat(64)
        );
        let mut event: EndpointEvent = serde_json::from_str(&legacy).unwrap();
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            legacy,
            "Existing durable replay hashes must not change"
        );
        event.kind = "process".into();
        assert!(event.validate(10000).is_err());
        let process = telemetry::ProcessObservation {
            pid: 10,
            parent_pid: None,
            started_ms: 1000,
            parent_started_ms: None,
            name: "public-fixture".into(),
            executable: Some("/public/fixture".into()),
            user_id: None,
        };
        event.telemetry = Some(telemetry::Telemetry::Process {
            boot_id: "b".repeat(64),
            process: process.clone(),
        });
        assert!(
            event.validate(10000).is_err(),
            "Path must agree with typed evidence"
        );
        event.path = "/public/fixture".into();
        assert!(event.validate(10000).is_ok());
        event.kind = "connection".into();
        assert!(event.validate(10000).is_err());
        let mut connection = telemetry::ConnectionObservation {
            protocol: "tcp".into(),
            local: "127.0.0.1:1234".parse().unwrap(),
            remote: None,
            state: "LISTEN".into(),
            owner_pid: Some(11),
            process: Some(process),
        };
        assert!(connection.validate(10000).is_err());
        connection.owner_pid = Some(10);
        assert!(connection.validate(10000).is_ok());
        connection.protocol = "udp".into();
        connection.remote = Some("127.0.0.1:4321".parse().unwrap());
        assert!(connection.validate(10000).is_err());
    }
    #[test]
    fn transport_and_action_boundaries() {
        assert!(server_url("https://fleet.example/").is_ok());
        assert!(server_url("http://127.0.0.1:8787/").is_ok());
        for bad in [
            "http://fleet.example/",
            "https://user:secret@fleet.example/",
            "https://fleet.example/path",
            "https://fleet.example/?token=abc",
        ] {
            assert!(server_url(bad).is_err());
        }
        assert!(Action::Script {
            interpreter: "sh".into(),
            script: "echo ok".into(),
            sha256: hash(b"echo bad")
        }
        .validate()
        .is_err());
    }
}
