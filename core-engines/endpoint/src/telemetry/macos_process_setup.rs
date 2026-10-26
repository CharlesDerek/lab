//! Record a locally approved signed helper without enabling a collector.
use super::MacosNativeAdapter;
use crate::{private_write, update, Config, Result};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

/// The installer supplies the hash of its signature-verified release component.
/// Custom deployment must perform that release approval before invoking setup.
pub fn configure(state: &Path, helper: &Path, sha256: &str) -> Result<()> {
    configure_source(state, helper, sha256, false)
}

/// Records only the authentication pin; runtime13+ is checked when collection starts.
pub fn configure_authentication(state: &Path, helper: &Path, sha256: &str) -> Result<()> {
    configure_source(state, helper, sha256, true)
}

fn configure_source(state: &Path, helper: &Path, sha256: &str, authentication: bool) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Mac native helper setup requires root".into());
    }
    let adapter = MacosNativeAdapter {
        path: helper.into(),
        sha256: sha256.into(),
    };
    adapter.validate()?;
    if !state.is_absolute() || state.canonicalize()? != state {
        return Err("Mac native state must be an absolute canonical directory".into());
    }
    for (index, ancestor) in state.ancestors().enumerate() {
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != 0
            || m.mode() & 0o022 != 0
            || (index == 0 && m.mode() & 0o777 != 0o700)
        {
            return Err("Mac native state requires private root-owned storage".into());
        }
    }
    let path = state.join("config.json");
    update::check_destination(&path)?;
    let m = fs::symlink_metadata(&path)?;
    if m.nlink() != 1 || m.mode() & 0o077 != 0 {
        return Err("Mac native configuration must be private and singly linked".into());
    }
    athernex_endpoint_native::macos_process_events::verify_helper(helper, sha256)?;
    let original = update::read_bounded(&path, 65536)?;
    let mut config: Config = serde_json::from_slice(&original)?;
    config.validate()?;
    let _maintenance = update::offline_maintenance(state, &config)?;
    if update::read_bounded(&path, 65536)? != original {
        return Err("Endpoint policy changed while acquiring setup ownership".into());
    }
    // No source is launched and neither telemetry nor protection is enabled.
    if authentication {
        config.telemetry.macos_authentication_adapter = Some(adapter);
    } else {
        config.telemetry.macos_process_adapter = Some(adapter);
    }
    config.validate()?;
    private_write(&path, &serde_json::to_vec_pretty(&config)?)
}
