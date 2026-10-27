//! Native primitive-driver lifecycle. Registration and ABI observations are
//! deliberately separate from current-image attestation and prevention health.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DRIVER: &str = "AthernexFilter";
pub const HELPER: &str = "AthernexFilterLifecycle";
pub const GLOBAL_DIRECTORY: &str = "AthernexFilterDeployment";
pub const MAX_INVENTORY_CHARS: usize = 1024 * 1024;
pub const MAX_INVENTORY_FILES: usize = 16384;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub volume: u64,
    pub file_id: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfiguration {
    pub service_type: u32,
    pub start_type: u32,
    pub error_control: u32,
    pub binary_path: String,
    pub load_order_group: String,
    pub dependencies: Vec<String>,
    pub account: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceObservation {
    pub configuration: ServiceConfiguration,
    pub state: u32,
    pub process_id: u32,
    pub win32_exit_code: u32,
    pub service_exit_code: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub published_inf: PathBuf,
    pub store_inf: PathBuf,
    pub published_identity: ObjectIdentity,
    pub member_identities: [ObjectIdentity; 3],
    pub configuration: ServiceConfiguration,
    pub instance: String,
    pub altitude: String,
    pub instance_flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// Original INF/catalog names select candidates; the exact package is
    /// independently checked before an observation can become Registration.
    pub candidate_infs: Vec<PathBuf>,
    pub service: Option<ServiceObservation>,
    pub filter_present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadObserved {
    pub version: u32,
    pub instance: [u8; 16],
    pub armed: u32,
    pub connected: u32,
    pub pending: u32,
    pub policy_sha256: [u8; 32],
}

impl LoadObserved {
    /// This establishes the selected ABI's reported disarmed state only. In
    /// particular, pending==0 is not a retained-view/rundown or unload proof.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != crate::windows_filter::wire::VERSION
            || self.instance == [0; 16]
            || self.armed != 0
            || self.connected != 1
            || self.pending != 0
            || self.policy_sha256 != [0; 32]
        {
            return Err("Disarmed driver observation refused");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEffect {
    pub succeeded: bool,
    pub need_reboot: bool,
    pub code: u32,
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::*;
