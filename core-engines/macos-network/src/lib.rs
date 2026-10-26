//! Selected network metadata from an OS-managed provider. Closing this client
//! only detaches the consumer; it does not stop or delete the extension.
use athernex_endpoint_protocol::macos_network_events::{
    source_policy_sha256, MacosNetworkEvent, MacosNetworkEventHealth,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

mod client;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod tests;
mod transport;
pub use client::Client;
pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub team_id: String,
    pub agent_identifier: String,
    pub provider_identifier: String,
    pub mach_service_name: String,
    pub app_group: String,
    pub provider_cdhashes: Vec<String>,
    pub source_policy_sha256: String,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        identity(
            &self.team_id,
            &[
                &self.agent_identifier,
                &self.provider_identifier,
                &self.mach_service_name,
                &self.app_group,
            ],
        )?;
        if !self
            .mach_service_name
            .starts_with(&format!("{}.", self.app_group))
            || self.agent_identifier == self.provider_identifier
            || self.source_policy_sha256 != source_policy_sha256()
            || self.provider_cdhashes.is_empty()
            || self.provider_cdhashes.len() > 4
            || self.provider_cdhashes.iter().any(|h| !hex(h, 40))
            || self
                .provider_cdhashes
                .iter()
                .enumerate()
                .any(|(i, h)| self.provider_cdhashes[..i].contains(h))
        {
            return Err("Invalid network deployment identity".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleIdentity {
    pub team_id: String,
    pub agent_identifier: String,
    pub container_identifier: String,
    pub provider_identifier: String,
    pub app_group: String,
    pub mach_service_name: String,
}
impl BundleIdentity {
    pub fn validate(&self) -> Result<()> {
        identity(
            &self.team_id,
            &[
                &self.agent_identifier,
                &self.container_identifier,
                &self.provider_identifier,
                &self.app_group,
                &self.mach_service_name,
            ],
        )?;
        if !self
            .mach_service_name
            .starts_with(&format!("{}.", self.app_group))
            || self.agent_identifier == self.provider_identifier
            || self.container_identifier == self.provider_identifier
            || self.agent_identifier == self.container_identifier
        {
            return Err("Invalid network bundle identity".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleInspection {
    pub identity: BundleIdentity,
    pub provider_cdhashes: Vec<String>,
}
/// Inspect exact signed app/provider and current agent, including entitlement
/// compatibility. Root installation code separately verifies the immutable tree.
/// This does not activate the provider or establish native capture acceptance.
pub fn inspect_bundle(path: &Path, expected: &BundleIdentity) -> Result<BundleInspection> {
    expected.validate()?;
    #[cfg(target_os = "macos")]
    {
        macos::inspect_bundle(path, expected)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("Network bundle inspection requires macOS 13 or later".into())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub health: MacosNetworkEventHealth,
    pub last_acked_batch_id: u64,
}
impl Status {
    fn validate(&self, stream: &str) -> Result<()> {
        self.health
            .validate()
            .map_err(|_| "Invalid network source status")?;
        if self.health.stream_id != stream
            || self.health.source_policy_sha256 != source_policy_sha256()
            || self.health.pending_records > self.health.received_records
            || self.health.admitted_records != 0
            || self.health.restarts != 0
            || self.health.loss_signals != 0
            || ![
                "",
                "Network source is stopping",
                "Network source projection was rejected",
                "Network source callback lost records",
                "Network source queue lost records",
                "Network source transport failed",
                "Network source configuration failed",
                "Network source counters overflowed",
            ]
            .contains(&self.health.error.as_str())
        {
            return Err("Invalid network source status binding".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub batch_id: u64,
    pub batch_sha256: String,
    pub events: Vec<MacosNetworkEvent>,
    pub status: Status,
}
fn identity(team: &str, values: &[&str]) -> Result<()> {
    if team.len() != 10
        || !team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        || values.iter().any(|s| {
            s.len() > 255
                || !s.contains('.')
                || s.split('.').any(|p| {
                    p.is_empty()
                        || p.len() > 63
                        || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        })
    {
        return Err("Invalid network signing identity".into());
    }
    Ok(())
}
fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |t| u64::try_from(t.as_millis()).unwrap_or(u64::MAX))
}
