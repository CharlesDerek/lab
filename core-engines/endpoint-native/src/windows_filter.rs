//! Windows minifilter transport. Native enforcement and installation must be
//! validated on Windows before this backend can report active protection.
#[cfg(windows)]
pub mod client;
pub mod engine;
pub mod evidence;
#[cfg(windows)]
pub mod peer;
#[cfg(windows)]
pub mod port;
#[cfg(test)]
mod tests;
pub mod wire;
