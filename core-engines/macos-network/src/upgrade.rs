//! A bounded lifecycle channel. The caller owns the durable journal and must
//! record the one-shot claim before replying with a permit. This channel neither
//! installs files nor treats an OS completion callback as live-source evidence.
use crate::{hex, BundleIdentity, Result};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

#[cfg(target_os = "macos")]
mod native;
#[cfg(test)]
mod tests;

pub const MAX_MESSAGE_BYTES: usize = 32_768;
pub const MAX_PROPERTIES: usize = 4;
pub const MAX_PERMIT_MS: u32 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeServerConfig {
    pub transaction_id: String,
    pub generation: u64,
    pub operator_uid: u32,
    pub identity: BundleIdentity,
    pub container_cdhashes: Vec<String>,
}
impl UpgradeServerConfig {
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        hashes(&self.container_cdhashes)?;
        if !hex(&self.transaction_id, 64)
            || self.generation == 0
            || self.service_name().len() >= 128
        {
            return Err("Invalid network upgrade listener binding".into());
        }
        Ok(())
    }
    pub fn service_name(&self) -> String {
        format!("{}.network-upgrade", self.identity.app_group)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeMode {
    Submit,
    Reconcile,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeCodePin {
    pub executable_sha256: String,
    pub cdhashes: Vec<String>,
    pub info_plist_sha256: String,
    pub bundle_version: String,
    pub short_version: String,
}
impl UpgradeCodePin {
    pub fn validate(&self) -> Result<()> {
        hashes(&self.cdhashes)?;
        if !hex(&self.executable_sha256, 64) || !hex(&self.info_plist_sha256, 64) {
            return Err("Invalid network upgrade code pin".into());
        }
        version(&self.bundle_version)?;
        version(&self.short_version)?;
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradePlan {
    pub mode: UpgradeMode,
    pub transaction_id: String,
    pub generation: u64,
    pub identity: BundleIdentity,
    pub source_policy_sha256: String,
    pub old: UpgradeCodePin,
    pub new: UpgradeCodePin,
    pub container_cdhashes: Vec<String>,
}
impl UpgradePlan {
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        self.old.validate()?;
        self.new.validate()?;
        hashes(&self.container_cdhashes)?;
        if !hex(&self.transaction_id, 64)
            || self.generation == 0
            || self.source_policy_sha256
                != athernex_endpoint_protocol::macos_network_events::source_policy_sha256()
            || version(&self.new.bundle_version)? <= version(&self.old.bundle_version)?
            || self.old.cdhashes == self.new.cdhashes
        {
            return Err("Invalid network upgrade plan".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionProperty {
    /// An SDK-reported file URL expressed as an absolute filesystem path.
    /// The native inspector independently checks its allowed location and code.
    pub url: String,
    pub bundle_identifier: String,
    pub bundle_version: String,
    pub bundle_short_version: String,
    pub is_enabled: bool,
    pub is_awaiting_user_approval: bool,
    pub is_uninstalling: bool,
}
impl ExtensionProperty {
    pub fn validate(&self) -> Result<()> {
        bounded_path(&self.url)?;
        crate::identity("AAAAAAAAAA", &[&self.bundle_identifier])?;
        version(&self.bundle_version)?;
        version(&self.bundle_short_version)?;
        Ok(())
    }
    pub fn matches(&self, identity: &BundleIdentity, pin: &UpgradeCodePin) -> bool {
        self.bundle_identifier == identity.provider_identifier
            && self.bundle_version == pin.bundle_version
            && self.bundle_short_version == pin.short_version
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FilterState {
    Absent,
    Owned { enabled: bool },
    Foreign,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradePermit {
    pub plan: UpgradePlan,
    pub old_property: ExtensionProperty,
    pub attempt_id: String,
    pub attempt_nonce: String,
    pub permit_ms: u32,
}
impl UpgradePermit {
    pub fn validate(&self) -> Result<()> {
        self.plan.validate()?;
        self.old_property.validate()?;
        if self.plan.mode != UpgradeMode::Submit
            || !self
                .old_property
                .matches(&self.plan.identity, &self.plan.old)
            || self.old_property.is_awaiting_user_approval
            || self.old_property.is_uninstalling
            || !hex(&self.attempt_id, 64)
            || !hex(&self.attempt_nonce, 64)
            || !(1..=MAX_PERMIT_MS).contains(&self.permit_ms)
        {
            return Err("Invalid network upgrade permit".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeOutcome {
    AwaitingApproval,
    ReplacementAllowed,
    ReplacementRefused,
    Completed,
    RebootRequired,
    Failed,
    Abandoned,
    UnexpectedCompleted,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpgradeRequest {
    Plan,
    Inspect {
        properties: Vec<ExtensionProperty>,
        filter: FilterState,
    },
    Claim {
        plan_sha256: String,
    },
    Report {
        attempt_id: String,
        attempt_nonce: String,
        sequence: u64,
        outcome: UpgradeOutcome,
    },
}
impl UpgradeRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Plan => (),
            Self::Inspect { properties, .. } => {
                if properties.len() > MAX_PROPERTIES {
                    return Err("Too many network extension properties".into());
                }
                for p in properties {
                    p.validate()?;
                }
            }
            Self::Claim { plan_sha256 } => {
                if !hex(plan_sha256, 64) {
                    return Err("Invalid network upgrade plan binding".into());
                }
            }
            Self::Report {
                attempt_id,
                attempt_nonce,
                sequence,
                ..
            } => {
                if !hex(attempt_id, 64) || !hex(attempt_nonce, 64) || *sequence == 0 {
                    return Err("Invalid network upgrade report binding".into());
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpgradeReply {
    Plan {
        plan: UpgradePlan,
        plan_sha256: String,
    },
    Inspected,
    Permit {
        permit: UpgradePermit,
    },
    Recorded,
    Refused,
}
impl UpgradeReply {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Plan { plan, plan_sha256 } => {
                plan.validate()?;
                if !hex(plan_sha256, 64) {
                    return Err("Invalid network upgrade plan digest".into());
                }
            }
            Self::Permit { permit } => permit.validate()?,
            Self::Inspected | Self::Recorded | Self::Refused => (),
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpgradeEvent {
    Request { request: UpgradeRequest },
    Disconnected,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeIncoming {
    pub connection_generation: u64,
    pub request_token: u64,
    pub peer_euid: u32,
    pub event: UpgradeEvent,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeBundleInspection {
    pub container_cdhashes: Vec<String>,
    pub provider: UpgradeCodePin,
}
impl UpgradeBundleInspection {
    pub fn validate(&self) -> Result<()> {
        hashes(&self.container_cdhashes)?;
        self.provider.validate()
    }
}

pub struct UpgradeServer {
    #[cfg(target_os = "macos")]
    native: native::Server,
}
impl UpgradeServer {
    pub fn start(config: &UpgradeServerConfig) -> Result<Self> {
        config.validate()?;
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                native: native::Server::start(config)?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        Err("Network upgrade listener requires macOS13 or later".into())
    }
    pub fn poll(&mut self, timeout: Duration) -> Result<Option<UpgradeIncoming>> {
        #[cfg(target_os = "macos")]
        {
            self.native.poll(timeout)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = timeout;
            Err("Network upgrade listener requires macOS13 or later".into())
        }
    }
    pub fn reply(&mut self, request_token: u64, reply: &UpgradeReply) -> Result<()> {
        reply.validate()?;
        #[cfg(target_os = "macos")]
        {
            self.native.reply(request_token, reply)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request_token;
            Err("Network upgrade listener requires macOS13 or later".into())
        }
    }
    pub fn close(self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.native.close()
        }
        #[cfg(not(target_os = "macos"))]
        Err("Network upgrade listener requires macOS13 or later".into())
    }
}
pub fn inspect_upgrade_bundle(
    path: &Path,
    identity: &BundleIdentity,
) -> Result<UpgradeBundleInspection> {
    identity.validate()?;
    #[cfg(target_os = "macos")]
    {
        native::inspect_bundle(path, identity)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("Network upgrade inspection requires macOS13 or later".into())
    }
}
pub fn inspect_upgrade_property(
    property: &ExtensionProperty,
    identity: &BundleIdentity,
    pin: &UpgradeCodePin,
) -> Result<()> {
    property.validate()?;
    identity.validate()?;
    pin.validate()?;
    if !property.matches(identity, pin) {
        return Err("Network extension properties differ from approved code".into());
    }
    #[cfg(target_os = "macos")]
    {
        native::inspect_property(property, identity, pin)
    }
    #[cfg(not(target_os = "macos"))]
    Err("Network upgrade inspection requires macOS13 or later".into())
}

fn hashes(values: &[String]) -> Result<()> {
    if !(1..=4).contains(&values.len())
        || values.iter().any(|v| !hex(v, 40))
        || values.windows(2).any(|v| v[0] >= v[1])
    {
        return Err("Invalid network upgrade code hashes".into());
    }
    Ok(())
}
fn version(value: &str) -> Result<[u32; 3]> {
    let parts: Vec<_> = value.split('.').collect();
    if value.len() > 64 || !(1..=3).contains(&parts.len()) {
        return Err("Invalid network bundle version".into());
    }
    let mut result = [0; 3];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty()
            || !part.bytes().all(|v| v.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return Err("Invalid network bundle version".into());
        }
        result[i] = part.parse().map_err(|_| "Invalid network bundle version")?;
    }
    Ok(result)
}
fn bounded_path(value: &str) -> Result<()> {
    if value.len() > 4096
        || !value.starts_with('/')
        || value.contains('\0')
        || Path::new(value).components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("Invalid network extension path".into());
    }
    Ok(())
}
