use crate::text;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionHealth {
    pub state: String,
    pub backend: String,
    pub checked_ms: u64,
    pub roots: Vec<String>,
    pub excluded_uid: Option<u32>,
    pub pending_events: u64,
    pub dropped_events: u64,
    pub error: String,
}
impl ProtectionHealth {
    pub fn validate(&self) -> Result<(), String> {
        if !["disabled", "starting", "active", "degraded", "unsupported"]
            .contains(&self.state.as_str())
            || !text(&self.backend, 64)
            || self.roots.len() > 16
            || self
                .roots
                .iter()
                .any(|r| r.is_empty() || r.len() > 1024 || r.contains('\0'))
            || self.pending_events > 2048
            || self.error.len() > 512
            || self.checked_ms > i64::MAX as u64
            || (self.state == "active"
                && (self.checked_ms == 0
                    || self.roots.is_empty()
                    || self.excluded_uid.is_none_or(|u| u == 0)))
        {
            return Err("Invalid native protection health".into());
        }
        Ok(())
    }
}
