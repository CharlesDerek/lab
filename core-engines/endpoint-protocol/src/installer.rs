//! Private build-catalog metadata. Hashes bind bundle components; native
//! signatures must also be checked by the packaging host and target installer.
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub struct Artifact {
    pub target: String,
    pub version: String,
    pub sha256: String,
    pub signing: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_adapter: Option<NativeArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_network: Option<MacosNetworkArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_filter: Option<crate::windows_filter_package::Descriptor>,
}
/// Private release pin for a separately activated macOS network system extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosNetworkArtifact {
    pub schema: u32,
    pub backend: String,
    pub signing: String,
    pub sha256: String,
    pub bytes: u64,
    pub tree_sha256: String,
    pub container_sha256: String,
    pub provider_sha256: String,
    pub source_policy_sha256: String,
    pub team_id: String,
    pub agent_identifier: String,
    pub container_identifier: String,
    pub provider_identifier: String,
    pub app_group: String,
    pub mach_service_name: String,
    pub provider_cdhashes: Vec<String>,
}
impl MacosNetworkArtifact {
    pub fn validate(&self) -> Result<(), &'static str> {
        fn identifier(s: &str) -> bool {
            !s.is_empty()
                && s.contains('.')
                && s.len() <= 255
                && s.split('.').all(|part| {
                    !part.is_empty()
                        && part.len() <= 63
                        && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        }
        if self.schema != 1
            || self.backend != "macos-network-extension"
            || self.signing != "native-signature-verified"
            || !(1..=64 * 1024 * 1024).contains(&self.bytes)
            || [
                &self.sha256,
                &self.tree_sha256,
                &self.container_sha256,
                &self.provider_sha256,
                &self.source_policy_sha256,
            ]
            .iter()
            .any(|v| !crate::hex_id(v))
            || self.source_policy_sha256 != crate::macos_network_events::source_policy_sha256()
            || self.team_id.len() != 10
            || !self
                .team_id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            || [
                &self.agent_identifier,
                &self.container_identifier,
                &self.provider_identifier,
                &self.app_group,
                &self.mach_service_name,
            ]
            .iter()
            .any(|s| !identifier(s))
            || !self
                .mach_service_name
                .starts_with(&format!("{}.", self.app_group))
            || self.agent_identifier == self.container_identifier
            || self.agent_identifier == self.provider_identifier
            || self.container_identifier == self.provider_identifier
            || !(1..=4).contains(&self.provider_cdhashes.len())
            || self.provider_cdhashes.iter().any(|s| {
                s.len() != 40
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || self.provider_cdhashes.windows(2).any(|s| s[0] >= s[1])
        {
            return Err("Invalid macOS network release metadata");
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifact {
    pub backend: String,
    pub sha256: String,
    pub signing: String,
}
impl Artifact {
    pub fn filter(
        &self,
    ) -> Result<Option<&crate::windows_filter_package::Descriptor>, &'static str> {
        let Some(component) = &self.windows_filter else {
            return Ok(None);
        };
        component.validate()?;
        if self.target != "windows-x86_64"
            || self.signing != "native-signature-verified"
            || self.native_adapter.is_some()
            || self.macos_network.is_some()
        {
            return Err("Windows filter package requires a signed Windows endpoint");
        }
        Ok(Some(component))
    }
    pub fn network(&self) -> Result<Option<&MacosNetworkArtifact>, &'static str> {
        self.filter()?;
        let Some(component) = &self.macos_network else {
            return Ok(None);
        };
        component.validate()?;
        if !["macos-x86_64", "macos-aarch64"].contains(&self.target.as_str())
            || self.signing != "native-signature-verified"
        {
            return Err("macOS network release requires a signed macOS endpoint");
        }
        Ok(Some(component))
    }
    pub fn native(&self) -> Result<Option<&NativeArtifact>, &'static str> {
        self.filter()?;
        let Some(component) = &self.native_adapter else {
            return Ok(None);
        };
        if !["macos-x86_64", "macos-aarch64"].contains(&self.target.as_str())
            || self.signing != "native-signature-verified"
            || component.signing != "native-signature-verified"
            || component.backend != "macos-endpoint-security"
            || !crate::hex_id(&component.sha256)
        {
            return Err("Native adapter catalog metadata is invalid");
        }
        Ok(Some(component))
    }
}
