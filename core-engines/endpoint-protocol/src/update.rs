//! Release signatures bind identity, freshness, target and exact executable
//! bytes. The public key comes from local policy, never from a release bundle.
use crate::{hex_id, text, PROTOCOL};
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

pub const MAX_BINARY: u64 = 64 * 1024 * 1024;
pub const MAX_MANIFEST: u64 = 8192;
pub const CHUNK_BYTES: u64 = 1024 * 1024;
const DAY: u64 = 86_400_000;
fn disabled(value: &bool) -> bool {
    !value
}

/// Existing deployment records without a component always target the agent.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    #[default]
    Agent,
    Controller,
}
impl Component {
    pub fn is_agent(&self) -> bool {
        *self == Self::Agent
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Agent => "Agent",
            Self::Controller => "Controller",
        }
    }
}

pub fn fingerprint(public_key: &str) -> Result<String, String> {
    Ok(crate::hash(&decode::<32>(public_key)?))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateHealth {
    #[serde(default, skip_serializing_if = "disabled")]
    pub automatic: bool,
    #[serde(default, skip_serializing_if = "disabled")]
    pub supervised: bool,
    pub managed: bool,
    pub key_fingerprint: String,
    pub channel: String,
    pub highwater: u64,
    pub staged_release: Option<String>,
    pub installed_release: Option<String>,
    pub state: String,
    pub error: String,
}
impl UpdateHealth {
    pub fn validate(&self) -> Result<(), String> {
        if !hex_id(&self.key_fingerprint)
            || !["stable", "preview"].contains(&self.channel.as_str())
            || self.highwater > i64::MAX as u64
            || self
                .staged_release
                .iter()
                .chain(self.installed_release.iter())
                .any(|s| !hex_id(s))
            || ![
                "ready",
                "staged",
                "installed",
                "rolled_back",
                "recovery_required",
                "verifying",
                "error",
            ]
            .contains(&self.state.as_str())
            || self.error.len() > 512
        {
            return Err("Invalid endpoint update health".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    #[serde(default, skip_serializing_if = "Component::is_agent")]
    pub component: Component,
    #[serde(default, skip_serializing_if = "disabled")]
    pub install: bool,
    pub id: String,
    pub endpoint_id: String,
    pub release_id: String,
    pub release: SignedRelease,
    pub created_ms: u64,
    pub expires_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationReceipt {
    pub deployment_id: String,
    pub release_id: String,
    pub outcome: String,
    pub detail: String,
    pub finished_ms: u64,
}
impl InstallationReceipt {
    pub fn validate(&self) -> Result<(), String> {
        if !hex_id(&self.deployment_id)
            || !hex_id(&self.release_id)
            || !["installed", "rolled_back", "refused"].contains(&self.outcome.as_str())
            || self.detail.len() > 512
            || self.finished_ms > i64::MAX as u64
        {
            return Err("Invalid installation receipt".into());
        }
        Ok(())
    }
}
impl Deployment {
    pub fn validate(&self, endpoint: &str, now: u64) -> Result<(), String> {
        self.release.release.validate()?;
        if !hex_id(&self.id)
            || !hex_id(&self.endpoint_id)
            || self.endpoint_id != endpoint
            || self.release_id != self.release.id()?
            || self.created_ms > now.saturating_add(60_000)
            || self.expires_ms <= now
            || self.expires_ms <= self.created_ms
            || self.expires_ms > self.created_ms.saturating_add(900_000)
            || self.expires_ms > self.release.release.expires_ms
        {
            return Err("Invalid, expired or mismatched update deployment".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentReceipt {
    pub deployment_id: String,
    pub release_id: String,
    pub outcome: String,
    pub detail: String,
    pub finished_ms: u64,
}
impl DeploymentReceipt {
    pub fn validate(&self) -> Result<(), String> {
        if !hex_id(&self.deployment_id)
            || !hex_id(&self.release_id)
            || !["staged", "failed"].contains(&self.outcome.as_str())
            || self.detail.len() > 512
            || self.finished_ms > i64::MAX as u64
        {
            return Err("Invalid update deployment receipt".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub schema: u32,
    pub target: String,
    pub version: String,
    pub channel: String,
    pub sequence: u64,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub protocol: u32,
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub release: Release,
    pub signature: String,
}

pub fn target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}
pub fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn decode<const N: usize>(raw: &str) -> Result<[u8; N], String> {
    if raw.len() != N * 2
        || !raw
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("Invalid release key or signature encoding".into());
    }
    let mut bytes = [0u8; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).map_err(|_| "Invalid hex")?;
    }
    Ok(bytes)
}
impl Release {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || self.protocol != PROTOCOL
            || ![
                "linux-x86_64",
                "linux-aarch64",
                "windows-x86_64",
                "macos-x86_64",
                "macos-aarch64",
            ]
            .contains(&self.target.as_str())
            || !text(&self.version, 32)
            || !["stable", "preview"].contains(&self.channel.as_str())
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.issued_ms == 0
            || self.expires_ms <= self.issued_ms
            || self.expires_ms > self.issued_ms.saturating_add(31 * DAY)
            || self.expires_ms > i64::MAX as u64
            || !hex_id(&self.sha256)
            || !(64..=MAX_BINARY).contains(&self.bytes)
        {
            return Err("Invalid endpoint release manifest".into());
        }
        Ok(())
    }
    fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = b"athernex.endpoint.release.v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(bytes)
    }
}
impl SignedRelease {
    pub fn id(&self) -> Result<String, String> {
        Ok(crate::hash(
            &serde_json::to_vec(self).map_err(|e| e.to_string())?,
        ))
    }
    pub fn sign(release: Release, private_pkcs8: &[u8]) -> Result<Self, String> {
        let key =
            Ed25519KeyPair::from_pkcs8(private_pkcs8).map_err(|_| "Invalid release signing key")?;
        let signature = encode(key.sign(&release.signing_bytes()?).as_ref());
        Ok(Self { release, signature })
    }
    /// Expiration limits admission of new releases, not continued use or
    /// recovery of an already installed version.
    pub fn authenticate(&self, public_key: &str) -> Result<(), String> {
        let public = decode::<32>(public_key)?;
        let signature = decode::<64>(&self.signature)?;
        UnparsedPublicKey::new(&signature::ED25519, public)
            .verify(&self.release.signing_bytes()?, &signature)
            .map_err(|_| "Endpoint release signature rejected".into())
    }
    pub fn admit(
        &self,
        public_key: &str,
        target: &str,
        channel: &str,
        highwater: u64,
        now: u64,
    ) -> Result<(), String> {
        self.authenticate(public_key)?;
        if self.release.target != target
            || self.release.channel != channel
            || self.release.sequence <= highwater
            || self.release.issued_ms > now.saturating_add(60_000)
            || self.release.expires_ms <= now
        {
            return Err("Release target, channel, sequence or validity window rejected".into());
        }
        Ok(())
    }
}
pub fn generate_key() -> Result<(Vec<u8>, String), String> {
    let document = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| "Release key generation failed")?;
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref())
        .map_err(|_| "Release key validation failed")?;
    Ok((
        document.as_ref().to_vec(),
        encode(key.public_key().as_ref()),
    ))
}
pub fn public_key(private_pkcs8: &[u8]) -> Result<String, String> {
    let key =
        Ed25519KeyPair::from_pkcs8(private_pkcs8).map_err(|_| "Invalid release signing key")?;
    Ok(encode(key.public_key().as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release() -> Release {
        Release {
            schema: 1,
            target: "linux-x86_64".into(),
            version: "0.1.0".into(),
            channel: "stable".into(),
            sequence: 2,
            issued_ms: 1000,
            expires_ms: 100000,
            protocol: PROTOCOL,
            sha256: "a".repeat(64),
            bytes: 1000,
        }
    }
    #[test]
    fn deployment_component_is_explicit_and_legacy_records_remain_agent_only() {
        let (key, _) = generate_key().unwrap();
        let signed = SignedRelease::sign(release(), &key).unwrap();
        let deployment = Deployment {
            component: Component::Agent,
            install: true,
            id: "b".repeat(64),
            endpoint_id: "c".repeat(64),
            release_id: signed.id().unwrap(),
            release: signed,
            created_ms: 2000,
            expires_ms: 90000,
        };
        let mut value = serde_json::to_value(&deployment).unwrap();
        assert!(value.get("component").is_none());
        assert_eq!(
            serde_json::from_value::<Deployment>(value.clone()).unwrap(),
            deployment
        );
        value["component"] = "controller".into();
        let controller: Deployment = serde_json::from_value(value.clone()).unwrap();
        controller.validate(&deployment.endpoint_id, 3000).unwrap();
        assert_eq!(controller.component, Component::Controller);
        assert_ne!(controller, deployment);
        value["component"] = "launcher".into();
        assert!(serde_json::from_value::<Deployment>(value).is_err());
    }
    #[test]
    fn signed_release_binds_every_execution_and_admission_field() {
        let (key, public) = generate_key().unwrap();
        let signed = SignedRelease::sign(release(), &key).unwrap();
        signed
            .admit(&public, "linux-x86_64", "stable", 1, 2000)
            .unwrap();
        for field in [
            "target",
            "version",
            "channel",
            "sequence",
            "issued_ms",
            "expires_ms",
            "sha256",
            "bytes",
            "protocol",
            "schema",
        ] {
            let mut changed = serde_json::to_value(&signed).unwrap();
            match changed["release"][field].clone() {
                serde_json::Value::String(value) => {
                    changed["release"][field] = format!("{value}x").into()
                }
                serde_json::Value::Number(value) => {
                    changed["release"][field] = (value.as_u64().unwrap() + 1).into()
                }
                _ => unreachable!(),
            }
            assert!(
                serde_json::from_value::<SignedRelease>(changed)
                    .unwrap()
                    .authenticate(&public)
                    .is_err(),
                "{field}"
            );
        }
        assert!(signed.authenticate(&generate_key().unwrap().1).is_err());
        for (target, channel, floor, now) in [
            ("windows-x86_64", "stable", 1, 2000),
            ("linux-x86_64", "preview", 1, 2000),
            ("linux-x86_64", "stable", 2, 2000),
            ("linux-x86_64", "stable", 1, 100000),
        ] {
            assert!(signed.admit(&public, target, channel, floor, now).is_err());
        }
        // Schema validation rejects unknown fields instead of verifying only a
        // subset of a future manifest with different execution semantics.
        let mut extended = serde_json::to_value(&signed).unwrap();
        extended["release"]["script"] = "untrusted".into();
        assert!(serde_json::from_value::<SignedRelease>(extended).is_err());
    }
}
