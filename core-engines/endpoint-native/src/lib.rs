//! Native authorization is deliberately separate from portal commands. The
//! macOS adapter needs native signing/entitlement validation before deployment.
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const MAX_FILE: u64 = 128 * 1024 * 1024;
pub const WORKERS: usize = 4;
pub const CAPACITY: usize = 64;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod child;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod coverage;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod health;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod macos_authentication;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod macos_notify;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod macos_process_events;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod mutation;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod probe;
pub mod receipt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod service;
#[cfg(any(windows, test))]
mod windows_directory;
pub mod windows_filter;
#[cfg(windows)]
pub mod windows_filter_package;
#[cfg(windows)]
pub mod windows_network;
#[cfg(windows)]
pub mod windows_scanner;
#[cfg(windows)]
pub mod windows_scratch;
#[cfg(any(windows, test))]
mod windows_scratch_spec;
#[cfg(windows)]
pub mod windows_state;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub roots: Vec<PathBuf>,
    pub socket: PathBuf,
    pub state: PathBuf,
    pub scanner_uid: u32,
    pub scan_timeout_ms: u64,
}
impl Policy {
    pub fn contains_observed_path(&self, path: &Path, truncated: bool) -> bool {
        self.roots.iter().any(|root| {
            path.starts_with(root)
                || (truncated
                    && root
                        .as_os_str()
                        .as_encoded_bytes()
                        .starts_with(path.as_os_str().as_encoded_bytes()))
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.roots.is_empty()
            || self.roots.len() > 16
            || self.scanner_uid == 0
            || !(100..=5000).contains(&self.scan_timeout_ms)
        {
            return Err("Native policy requires 1–16 roots, a non-root scanner UID and a 100–5000 ms scan deadline".into());
        }
        for path in self.roots.iter().chain([&self.socket, &self.state]) {
            if !path.is_absolute()
                || path.parent().is_none()
                || path.as_os_str().len() > 1024
                || path
                    .to_str()
                    .is_none_or(|s| s.chars().any(char::is_control))
                || path.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err("Native paths must be bounded absolute paths without traversal".into());
            }
        }
        if self
            .roots
            .iter()
            .any(|p| self.state.starts_with(p) || self.socket.starts_with(p))
        {
            return Err("Native state and scanner socket must be outside monitored roots".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_sec: i64,
    pub modified_nsec: i64,
    pub changed_sec: i64,
    pub changed_nsec: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub sha256: String,
    pub detection: Option<String>,
    pub bytes: u64,
}
pub struct Scan {
    pub path: PathBuf,
    pub identity: Identity,
    pub deadline: Instant,
}

#[cfg(unix)]
pub mod broker;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(unix)]
pub mod scanner;
#[cfg(unix)]
mod socket_read;

#[cfg(all(test, unix))]
mod tests;
