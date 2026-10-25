//! Native prevention is managed independently of remote actions and scan jobs.
use crate::{Config, Result, Store};
use athernex_endpoint_protocol::protection::ProtectionHealth;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod managed_native;
#[cfg(unix)]
pub mod native;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod native_response;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod native_setup;
#[cfg(windows)]
pub mod windows;
pub mod windows_evidence;
#[cfg(any(windows, test))]
mod windows_launch;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{configure, mutation_hash_worker, probe_read, scan_worker, supervise};
#[cfg(target_os = "linux")]
pub(crate) use linux::{execute_scan, mutation_hash};
#[cfg(target_os = "macos")]
pub use managed_native::supervise;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionConfig {
    pub enabled: bool,
    #[serde(default)]
    pub roots: Vec<PathBuf>,
    pub daemon: Option<PathBuf>,
    /// clamonacc on Linux; the separately signed authorization adapter on macOS.
    pub monitor: Option<PathBuf>,
    pub database: Option<PathBuf>,
    pub runtime: Option<PathBuf>,
    pub engine_uid: Option<u32>,
    pub engine_gid: Option<u32>,
}
impl ProtectionConfig {
    pub fn validate(&self) -> Result<()> {
        self.validate_platform(std::env::consts::OS)
    }
    fn validate_platform(&self, platform: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !["linux", "macos"].contains(&platform) {
            return Err("Native protection backend is not implemented on this platform".into());
        }
        if self.roots.is_empty()
            || self.roots.len() > 16
            || self.engine_uid.is_none_or(|u| [0, u32::MAX].contains(&u))
            || self.engine_gid.is_none_or(|g| [0, u32::MAX].contains(&g))
        {
            return Err(
                "Native protection needs 1–16 roots and a dedicated non-root scanner identity"
                    .into(),
            );
        }
        for path in self.roots.iter().chain(
            [&self.daemon, &self.monitor, &self.database, &self.runtime]
                .into_iter()
                .flatten(),
        ) {
            let raw = path.to_str().ok_or("Protection paths must be UTF-8")?;
            if !path.is_absolute()
                || raw.len() > 1024
                || raw.chars().any(char::is_control)
                || raw.contains('"')
                || path.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || path == Path::new("/")
            {
                return Err("Invalid native protection path".into());
            }
        }
        if [&self.daemon, &self.monitor, &self.database, &self.runtime]
            .iter()
            .any(|p| p.is_none())
        {
            return Err("Native protection paths are incomplete".into());
        }
        Ok(())
    }
}

pub fn health(config: &Config, state: &Path) -> ProtectionHealth {
    if !config.protection.enabled {
        return ProtectionHealth {
            state: "disabled".into(),
            backend: "none".into(),
            ..Default::default()
        };
    }
    #[cfg(target_os = "linux")]
    {
        linux::health(&config.protection, state)
    }
    #[cfg(target_os = "macos")]
    {
        managed_native::health(&config.protection, state)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = state;
        ProtectionHealth {
            state: "unsupported".into(),
            backend: "none".into(),
            error: "Native prevention backend is unavailable".into(),
            ..Default::default()
        }
    }
}
pub fn collect(store: &Store) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::collect(store)?;
    }
    #[cfg(unix)]
    {
        native::collect(store)?;
    }
    #[cfg(windows)]
    {
        windows::collect(store)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = store;
    }
    Ok(())
}
