//! Signed, bounded engine trees. Paths and libraries are part of the release
//! authorization; archives and installer scripts are never executed on admission.
use crate::{
    hash, hex_id,
    update::{decode, encode},
    PROTOCOL,
};
use ring::signature::{self, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_FILES: usize = 128;
pub const MAX_FILE: u64 = 128 * 1024 * 1024;
pub const MAX_TOTAL: u64 = 512 * 1024 * 1024;
pub const MAX_MANIFEST: u64 = 65536;

/// A common path grammar avoids platform-specific aliases and stream syntax.
pub fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 240
        && path.split('/').count() <= 8
        && path.split('/').all(|part| {
            !part.is_empty()
                && ![".", ".."].contains(&part)
                && !part.ends_with('.')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && !matches!(
                    part.split('.')
                        .next()
                        .unwrap()
                        .to_ascii_lowercase()
                        .as_str(),
                    "con"
                        | "prn"
                        | "aux"
                        | "nul"
                        | "com1"
                        | "com2"
                        | "com3"
                        | "com4"
                        | "com5"
                        | "com6"
                        | "com7"
                        | "com8"
                        | "com9"
                        | "lpt1"
                        | "lpt2"
                        | "lpt3"
                        | "lpt4"
                        | "lpt5"
                        | "lpt6"
                        | "lpt7"
                        | "lpt8"
                        | "lpt9"
                )
        })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub executable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Roles {
    pub scanner: String,
    pub updater: String,
    pub daemon: String,
    /// Linux clamonacc only. Windows/Mac retain their separately signed adapter.
    pub monitor: Option<String>,
    pub library_dirs: Vec<String>,
    pub certificates: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub schema: u32,
    pub protocol: u32,
    pub engine: String,
    pub target: String,
    pub version: String,
    pub channel: String,
    pub sequence: u64,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub roles: Roles,
    pub files: Vec<File>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub release: Release,
    pub signature: String,
}
impl Release {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || self.protocol != PROTOCOL
            || self.engine != "clamav"
            || ![
                "linux-x86_64",
                "linux-aarch64",
                "windows-x86_64",
                "macos-x86_64",
                "macos-aarch64",
            ]
            .contains(&self.target.as_str())
            || self.version.is_empty()
            || self.version.len() > 32
            || !self
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            || !["stable", "preview"].contains(&self.channel.as_str())
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.issued_ms == 0
            || self.expires_ms <= self.issued_ms
            || self.expires_ms > self.issued_ms.saturating_add(31 * 86_400_000)
            || self.expires_ms > i64::MAX as u64
            || self.files.is_empty()
            || self.files.len() > MAX_FILES
        {
            return Err("Invalid engine release metadata or budget".into());
        }
        let mut paths = BTreeSet::new();
        let mut total = 0u64;
        for file in &self.files {
            if !relative_path(&file.path)
                || !hex_id(&file.sha256)
                || file.bytes == 0
                || file.bytes > MAX_FILE
                || !paths.insert(file.path.to_ascii_lowercase())
            {
                return Err("Invalid, duplicate or oversized engine file".into());
            }
            total += file.bytes;
        }
        if total > MAX_TOTAL {
            return Err("Engine tree exceeds its byte budget".into());
        }
        for path in &paths {
            let mut parent = path.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                if paths.contains(prefix) {
                    return Err("Engine file shadows a directory".into());
                }
                parent = prefix;
            }
        }
        let mut roles = BTreeSet::new();
        for path in [&self.roles.scanner, &self.roles.updater, &self.roles.daemon]
            .into_iter()
            .chain(self.roles.monitor.iter())
        {
            if !roles.insert(path) || !self.files.iter().any(|f| &f.path == path && f.executable) {
                return Err("Engine roles must name distinct signed executables".into());
            }
        }
        if self.target.starts_with("linux-") != self.roles.monitor.is_some() {
            return Err("Only Linux engine releases contain the native on-access monitor".into());
        }
        if self.roles.library_dirs.len() > 4 {
            return Err("Too many engine library directories".into());
        }
        let mut libraries = BTreeSet::new();
        for path in &self.roles.library_dirs {
            if !relative_path(path)
                || !libraries.insert(path.to_ascii_lowercase())
                || !self
                    .files
                    .iter()
                    .any(|f| f.path.starts_with(&format!("{path}/")))
            {
                return Err(
                    "Engine libraries must name distinct populated bundle directories".into(),
                );
            }
        }
        if !relative_path(&self.roles.certificates)
            || !self
                .files
                .iter()
                .any(|f| f.path.starts_with(&format!("{}/", self.roles.certificates)))
        {
            return Err("Engine certificates must name a populated signed directory".into());
        }
        Ok(())
    }
    fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = b"athernex.endpoint.clamav-tree.v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(bytes)
    }
}
impl SignedRelease {
    pub fn id(&self) -> Result<String, String> {
        Ok(hash(&serde_json::to_vec(self).map_err(|e| e.to_string())?))
    }
    pub fn sign(release: Release, private: &[u8]) -> Result<Self, String> {
        let key = Ed25519KeyPair::from_pkcs8(private).map_err(|_| "Invalid engine signing key")?;
        let signature = encode(key.sign(&release.signing_bytes()?).as_ref());
        Ok(Self { release, signature })
    }
    pub fn authenticate(&self, public: &str) -> Result<(), String> {
        UnparsedPublicKey::new(&signature::ED25519, decode::<32>(public)?)
            .verify(
                &self.release.signing_bytes()?,
                &decode::<64>(&self.signature)?,
            )
            .map_err(|_| "Engine release signature rejected".into())
    }
    pub fn admit(
        &self,
        public: &str,
        target: &str,
        channel: &str,
        floor: u64,
        now: u64,
    ) -> Result<(), String> {
        self.authenticate(public)?;
        if self.release.target != target
            || self.release.channel != channel
            || self.release.sequence <= floor
            || self.release.issued_ms > now.saturating_add(60_000)
            || self.release.expires_ms <= now
        {
            return Err("Engine release is mismatched, expired or replayed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release() -> Release {
        Release {
            schema: 1,
            protocol: PROTOCOL,
            engine: "clamav".into(),
            target: "linux-x86_64".into(),
            version: "1.5.4".into(),
            channel: "stable".into(),
            sequence: 2,
            issued_ms: 1_800_000_000_000,
            expires_ms: 1_800_000_060_000,
            roles: Roles {
                scanner: "bin/clamscan".into(),
                updater: "bin/freshclam".into(),
                daemon: "sbin/clamd".into(),
                monitor: Some("sbin/clamonacc".into()),
                library_dirs: vec!["lib".into()],
                certificates: "etc/certs".into(),
            },
            files: [
                "bin/clamscan",
                "bin/freshclam",
                "sbin/clamd",
                "sbin/clamonacc",
                "lib/libclamav.so",
                "etc/certs/clamav.crt",
            ]
            .iter()
            .map(|p| File {
                path: p.to_string(),
                sha256: hash(p.as_bytes()),
                bytes: 64,
                executable: true,
            })
            .collect(),
        }
    }
    #[test]
    fn signature_binds_tree_roles_target_and_sequence() {
        let (key, public) = crate::update::generate_key().unwrap();
        let signed = SignedRelease::sign(release(), &key).unwrap();
        signed
            .admit(&public, "linux-x86_64", "stable", 1, 1_800_000_000_001)
            .unwrap();
        assert!(signed
            .admit(&public, "windows-x86_64", "stable", 1, 1_800_000_000_001)
            .is_err());
        assert!(signed
            .admit(&public, "linux-x86_64", "stable", 2, 1_800_000_000_001)
            .is_err());
        assert!(signed
            .admit(&public, "linux-x86_64", "stable", 1, 1_800_000_060_000)
            .is_err());
        let mut changed = signed.clone();
        changed.release.files[0].sha256 = hash(b"changed");
        assert!(changed.authenticate(&public).is_err());
        let mut changed = signed.clone();
        changed.release.roles.scanner = "bin/freshclam".into();
        assert!(changed.authenticate(&public).is_err());
        let mut changed = signed;
        changed.release.channel = "preview".into();
        assert!(changed.authenticate(&public).is_err());
    }
    #[test]
    fn paths_and_tree_budgets_refuse_aliases_streams_and_shadowing() {
        for path in [
            "../bin/scan",
            "/bin/scan",
            "bin/./scan",
            "bin//scan",
            "bin\\scan",
            "C:/scan",
            "bin/scan:stream",
            "bin/NUL.exe",
            "bin/com1",
            "bin/name.",
            "bin/scan ",
        ] {
            assert!(!relative_path(path), "{path}");
        }
        let mut r = release();
        r.files.push(r.files[0].clone());
        r.files.last_mut().unwrap().path = "BIN/CLAMSCAN".into();
        assert!(r.validate().is_err());
        let mut r = release();
        r.files[4].path = "bin".into();
        assert!(r.validate().is_err());
        let mut r = release();
        r.files[0].bytes = MAX_FILE + 1;
        assert!(r.validate().is_err());
        let mut r = release();
        for f in &mut r.files {
            f.bytes = MAX_FILE;
        }
        assert!(r.validate().is_err());
        let mut r = release();
        r.roles.library_dirs = vec!["outside".into()];
        assert!(r.validate().is_err());
        let mut r = release();
        r.target = "windows-x86_64".into();
        assert!(r.validate().is_err());
    }
}
