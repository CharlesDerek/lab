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
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifact {
    pub backend: String,
    pub sha256: String,
    pub signing: String,
}
impl Artifact {
    pub fn native(&self) -> Result<Option<&NativeArtifact>, &'static str> {
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
