//! Durable Windows installation state. A partial installation is never normal
//! service readiness, including after its owning process has exited.
use crate::Result;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::Lease;
#[cfg(windows)]
pub use windows::{install, preflight, require_complete};

pub(crate) const RECORD: &str = "installer.json";
#[cfg(windows)]
pub(crate) const LOCK: &str = "installer.lock";
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Preparing,
    Installing,
    Complete,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub schema: u32,
    pub id: String,
    pub source_sha256: String,
    pub server: String,
    pub agent_directory: String,
    pub state_volume: u64,
    pub state_file_id: [u8; 16],
    pub phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_filter_sha256: Option<String>,
}
impl Record {
    pub(crate) fn require_filter_selection(&self, next: Option<&str>) -> Result<()> {
        if self
            .windows_filter_sha256
            .as_deref()
            .is_some_and(|old| Some(old) != next)
        {
            return Err(
                "Existing required driver package cannot be removed or replaced by reinstall"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || !athernex_endpoint_protocol::hex_id(&self.id)
            || self
                .windows_filter_sha256
                .as_ref()
                .is_some_and(|v| !athernex_endpoint_protocol::hex_id(v))
            || !athernex_endpoint_protocol::hex_id(&self.source_sha256)
            || !crate::protection::windows_evidence::drive_path(&self.agent_directory)
            || athernex_endpoint_protocol::server_url(&self.server)?.as_str() != self.server
        {
            return Err("Invalid Windows installation journal".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_install_cannot_drop_or_switch_required_driver_package() {
        let mut record = Record {
            schema: 1,
            id: "a".repeat(64),
            source_sha256: "b".repeat(64),
            server: "https://example.com/".into(),
            agent_directory: r"C:\Athernex".into(),
            state_volume: 1,
            state_file_id: [1; 16],
            phase: Phase::Complete,
            windows_filter_sha256: Some("c".repeat(64)),
        };
        assert!(record.require_filter_selection(None).is_err());
        assert!(record
            .require_filter_selection(Some(&"d".repeat(64)))
            .is_err());
        record
            .require_filter_selection(Some(&"c".repeat(64)))
            .unwrap();
        record.windows_filter_sha256 = None;
        record.require_filter_selection(None).unwrap();
        record
            .require_filter_selection(Some(&"c".repeat(64)))
            .unwrap();
    }
    #[test]
    fn installation_record_rejects_unknown_schema_source_origin_and_destination() {
        let record = Record {
            schema: 1,
            id: "a".repeat(64),
            source_sha256: "b".repeat(64),
            server: "https://example.com/".into(),
            agent_directory: r"C:\Program Files\Athernex Endpoint".into(),
            state_volume: 1,
            state_file_id: [1; 16],
            phase: Phase::Preparing,
            windows_filter_sha256: None,
        };
        record.validate().unwrap();
        for field in ["schema", "id", "source_sha256", "server", "agent_directory"] {
            let mut changed = record.clone();
            match field {
                "schema" => changed.schema = 2,
                "id" => changed.id = "x".into(),
                "source_sha256" => changed.source_sha256.clear(),
                "server" => changed.server = "https://example.com/path/".into(),
                _ => changed.agent_directory = r"C:\Program Files\..\Windows".into(),
            }
            assert!(changed.validate().is_err(), "{field}");
        }
        let mut value = serde_json::to_value(record).unwrap();
        value["phase"] = serde_json::json!("unknown");
        assert!(serde_json::from_value::<Record>(value).is_err());
        assert_eq!(RECORD, "installer.json");
    }
}
