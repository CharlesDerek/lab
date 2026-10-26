//! Controlled replacement of the installed, OS-managed network provider.
//! File placement, an SDK callback, and active-source verification are separate
//! durable facts. A lost request owner never creates another approval.
#[cfg(target_os = "macos")]
mod filesystem;
pub(super) mod inspection;
mod journal;
mod launchd;
#[cfg(target_os = "macos")]
mod macos;
mod owner;
#[cfg(any(target_os = "macos", test))]
mod retirement;
#[cfg(target_os = "macos")]
mod storage;
#[cfg(target_os = "macos")]
pub(crate) use filesystem::Lease;
#[cfg(target_os = "macos")]
pub use macos::{abort, finish, prepare, recover, require_settled, serve, status};
#[cfg(target_os = "macos")]
pub(super) fn prepare_guard_directory() -> crate::Result<()> {
    filesystem::prepare_guard_directory()
}
