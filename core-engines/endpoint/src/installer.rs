//! Durable Windows installation state. A partial installation is never normal
//! service readiness, including after its owning process has exited.
use crate::Result;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{
    deployment_preflight, install_owned, mark_driver_retired, require_completed_driver, Lease,
};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_filter_deployment:
        Option<athernex_endpoint_protocol::windows_filter_package::Deployment>,
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

    pub(crate) fn require_deployment_selection(
        &self,
        next: Option<athernex_endpoint_protocol::windows_filter_package::Deployment>,
    ) -> Result<()> {
        if self.windows_filter_deployment != next
            && (self.phase != Phase::Complete || self.windows_filter_deployment.is_some())
        {
            return Err("Required deployment differs from the original installation; explicit retirement is required".into());
        }
        Ok(())
    }
    pub(crate) fn require_resume(
        &self,
        source: &str,
        server: &str,
        agent: &str,
        package: Option<&str>,
        deployment: Option<athernex_endpoint_protocol::windows_filter_package::Deployment>,
    ) -> Result<()> {
        self.require_filter_selection(package)?;
        self.require_deployment_selection(deployment)?;
        if self.phase != Phase::Complete
            && (self.source_sha256 != source
                || self.server != server
                || self.windows_filter_sha256.as_deref() != package
                || !crate::protection::windows_evidence::prefix_equal(&self.agent_directory, agent))
        {
            return Err(
                "Interrupted installation must resume with the same source, server and destination"
                    .into(),
            );
        }
        Ok(())
    }
    pub(crate) fn driver_retired(&mut self, source: &str, package: &str) -> Result<()> {
        self.validate()?;
        if self.source_sha256 != source || self.windows_filter_sha256.as_deref() != Some(package) {
            return Err("Driver retirement differs from installer ownership".into());
        }
        // An unfinished installer must retain the same approved inputs for a
        // later new deployment. Retirement is never installer completion.
        if self.phase == Phase::Complete {
            self.windows_filter_deployment = None;
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
            || self.windows_filter_deployment.is_some() && self.windows_filter_sha256.is_none()
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
            windows_filter_deployment: None,
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
            windows_filter_deployment: None,
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
    #[test]
    fn failed_load_retirement_preserves_incomplete_same_input_resume() {
        use athernex_endpoint_protocol::windows_filter_package::Deployment;
        let deployment = Some(Deployment::InstallAndObserveDisarmedV1);
        for phase in [Phase::Preparing, Phase::Installing, Phase::Complete] {
            let mut r = Record {
                schema: 1,
                id: "a".repeat(64),
                source_sha256: "b".repeat(64),
                server: "https://example.com/".into(),
                agent_directory: r"C:\Athernex".into(),
                state_volume: 1,
                state_file_id: [1; 16],
                phase,
                windows_filter_sha256: Some("c".repeat(64)),
                windows_filter_deployment: deployment,
            };
            assert!(r.driver_retired(&"d".repeat(64), &"c".repeat(64)).is_err());
            r.driver_retired(&"b".repeat(64), &"c".repeat(64)).unwrap();
            assert!(r.phase == phase);
            r.require_deployment_selection(deployment).unwrap();
            if phase == Phase::Complete {
                assert!(r.windows_filter_deployment.is_none());
                r.require_deployment_selection(None).unwrap();
            } else {
                assert!(r.windows_filter_deployment == deployment);
                assert!(r.require_deployment_selection(None).is_err());
                r.require_resume(
                    &"b".repeat(64),
                    "https://example.com/",
                    r"C:\Athernex",
                    Some(&"c".repeat(64)),
                    deployment,
                )
                .unwrap();
                for (source, server, agent) in [
                    (&"d".repeat(64), "https://example.com/", r"C:\Athernex"),
                    (
                        &"b".repeat(64),
                        "https://other.example.com/",
                        r"C:\Athernex",
                    ),
                    (&"b".repeat(64), "https://example.com/", r"C:\Other"),
                ] {
                    assert!(r
                        .require_resume(source, server, agent, Some(&"c".repeat(64)), deployment)
                        .is_err());
                }
            }
            assert_eq!(r.windows_filter_sha256, Some("c".repeat(64)));
        }
    }
}
