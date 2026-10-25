//! Portal transport for separately trusted, signed engine trees.
use crate::{engine::SignedRelease, hex_id};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub managed: bool,
    pub automatic: bool,
    pub supervised: bool,
    pub target: String,
    pub key_fingerprint: String,
    pub channel: String,
    pub highwater: u64,
    pub staged_release: Option<String>,
    pub installed_release: Option<String>,
    pub phase: String,
    pub error: String,
}
impl Health {
    pub fn validate(&self) -> Result<(), String> {
        if !hex_id(&self.key_fingerprint)
            || !["stable", "preview"].contains(&self.channel.as_str())
            || self.target.len() > 32
            || self.phase.len() > 64
            || self.error.len() > 512
            || self.highwater > i64::MAX as u64
            || self
                .staged_release
                .iter()
                .chain(self.installed_release.iter())
                .any(|s| !hex_id(s))
        {
            return Err("Invalid engine health".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub id: String,
    pub endpoint_id: String,
    pub release: SignedRelease,
    pub install: bool,
    pub created_ms: u64,
    pub expires_ms: u64,
}
impl Deployment {
    pub fn validate(&self, endpoint: &str, now: u64) -> Result<(), String> {
        self.release.release.validate()?;
        if !hex_id(&self.id)
            || !hex_id(&self.endpoint_id)
            || self.endpoint_id != endpoint
            || self.created_ms > now.saturating_add(60000)
            || self.expires_ms <= now
            || self.expires_ms > self.created_ms.saturating_add(900000)
            || self.expires_ms > self.release.release.expires_ms
        {
            return Err("Invalid or expired engine deployment".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub deployment_id: String,
    pub release_id: String,
    pub outcome: String,
    pub detail: String,
    pub finished_ms: u64,
}
impl Receipt {
    pub fn validate(&self) -> Result<(), String> {
        if !hex_id(&self.deployment_id)
            || !hex_id(&self.release_id)
            || !["staged", "installed", "rolled_back", "refused"].contains(&self.outcome.as_str())
            || self.detail.len() > 512
            || self.finished_ms > i64::MAX as u64
        {
            return Err("Invalid engine receipt".into());
        }
        Ok(())
    }
}
