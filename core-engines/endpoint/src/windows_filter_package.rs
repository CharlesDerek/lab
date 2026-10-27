//! Private preparation of approved Windows driver packages. Prepared is only a
//! verified immutable snapshot: no Driver Store, SCM, registry or filter calls.
use crate::{update, Result};
use athernex_endpoint_protocol::{self as protocol, installer::Artifact};
#[cfg(any(windows, test))]
use protocol::windows_filter_package::Descriptor;
use std::path::Path;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{prepare, prepared_directory, require_prepared};
#[cfg(windows)]
pub fn verify_worker(path: &Path) -> Result<String> {
    windows::worker(path).map_err(|_| "Windows driver package verification refused".into())
}

pub fn installer_hash(manifest: &Path) -> Result<Option<String>> {
    installer_hash_inner(manifest).map_err(|_| "Windows driver component capability refused".into())
}
fn installer_hash_inner(manifest: &Path) -> Result<Option<String>> {
    let artifact: Artifact = serde_json::from_slice(&update::read_bounded(manifest, 16384)?)?;
    artifact.native()?;
    artifact.network()?;
    let Some(component) = artifact.filter()? else {
        return Ok(None);
    };
    if artifact.target != protocol::update::target()
        || !cfg!(windows)
        || crate::file_hash(&std::env::current_exe()?)? != artifact.sha256
    {
        return Err(
            "Windows filter component requires its exact Windows management executable".into(),
        );
    }
    Ok(Some(component.sha256.clone()))
}
/// Marker/metadata consistency is checked before any management service stop.
pub(crate) fn components(directory: &Path, artifact: &Artifact) -> Result<()> {
    let required = directory.join("windows-filter.required");
    let package = directory.join("windows-filter.axpkg");
    fn exists(path: &Path) -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn regular(path: &Path) -> Result<()> {
        let m = std::fs::symlink_metadata(path)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if m.file_attributes() & 0x400 != 0 {
                return Err("Reparse driver package input refused".into());
            }
        }
        if !m.is_file() || m.file_type().is_symlink() {
            return Err("Driver package input must be regular".into());
        }
        Ok(())
    }
    match artifact.filter()? {
        Some(component) => {
            if !cfg!(windows) {
                return Err("Driver package is unsupported on this platform".into());
            }
            regular(&required)?;
            regular(&package)?;
            if update::read_bounded(&required, 2)? != b"1\n" {
                return Err("Windows filter component marker is invalid".into());
            }
            #[cfg(windows)]
            {
                use protocol::windows_filter_package::Member;
                use std::io::Read;
                let _parent =
                    athernex_endpoint_native::windows_state::PinnedDirectory::open(directory)?;
                let file = athernex_endpoint_native::windows_filter_package::pin(
                    &package,
                    &Member {
                        bytes: component.bytes,
                        sha256: component.sha256.clone(),
                    },
                )?;
                let _marker = athernex_endpoint_native::windows_filter_package::pin(
                    &required,
                    &Member {
                        bytes: 2,
                        sha256: protocol::hash(b"1\n"),
                    },
                )?;
                let mut bytes = Vec::new();
                (&file).take(component.bytes + 1).read_to_end(&mut bytes)?;
                component.unpack(&bytes)?;
            }
            #[cfg(not(windows))]
            let _ = component;
        }
        None if exists(&required)? || exists(&package)? => {
            return Err("Undeclared Windows filter component".into())
        }
        None => {}
    }
    Ok(())
}
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preparation {
    schema: u32,
    transaction: String,
    source_sha256: String,
    descriptor: Descriptor,
    state_volume: u64,
    state_file_id: [u8; 16],
    directory: Option<(u64, [u8; 16])>,
    prepared: bool,
    members: [Option<(u64, [u8; 16])>; 4],
}
#[cfg(any(windows, test))]
impl Preparation {
    fn validate(&self) -> Result<()> {
        self.descriptor.validate()?;
        if self.schema != 1
            || !protocol::hex_id(&self.transaction)
            || !protocol::hex_id(&self.source_sha256)
            || (self.prepared
                && (self.directory.is_none() || self.members.iter().any(Option::is_none)))
            || (self.directory.is_none() && self.members.iter().any(Option::is_some))
        {
            return Err("Invalid Windows filter preparation receipt".into());
        }
        Ok(())
    }
    fn member_action(&self, index: usize, actual: Option<(u64, [u8; 16])>) -> Result<bool> {
        self.validate()?;
        match (
            self.members
                .get(index)
                .ok_or("Invalid preparation member")?,
            actual,
        ) {
            (None, None) if !self.prepared && self.directory.is_some() => Ok(true),
            (Some(expected), Some(actual)) if *expected == actual => Ok(false),
            _ => Err("Unconfirmed or replaced preparation member requires recovery".into()),
        }
    }
    fn matches(&self, source: &str, descriptor: &Descriptor) -> Result<()> {
        self.validate()?;
        if (!self.prepared && self.source_sha256 != source) || self.descriptor != *descriptor {
            return Err("Resume driver preparation with the original approved release".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;

#[cfg(windows)]
pub fn verify_package(directory: &Path) -> Result<String> {
    verify_package_inner(directory)
        .map_err(|_| "Windows driver package verification refused".into())
}
#[cfg(windows)]
fn verify_package_inner(directory: &Path) -> Result<String> {
    let d: Descriptor = serde_json::from_slice(&update::read_bounded(
        &directory.join("descriptor.json"),
        16384,
    )?)?;
    d.validate()?;
    let source = crate::file_hash(&std::env::current_exe()?)?;
    windows::verify_bounded(directory, &d, &source)
        .map_err(|_| "Windows driver package verification refused")?;
    Ok(d.sha256)
}

#[cfg(windows)]
pub fn publish_catalog(snapshot: &Path, output: &Path) -> Result<String> {
    windows::publish_catalog(snapshot, output)
        .map_err(|_| "Private Windows driver catalog publication refused".into())
}
