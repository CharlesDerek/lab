//! Portal delivery is only a transport: local release policy authorizes bytes.
use crate::{now_ms, private_write, update, Client, Result, Store};
use athernex_endpoint_protocol::update::{
    self as wire, Component, Deployment, DeploymentReceipt, UpdateHealth,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    deployment: Deployment,
    attempts: u8,
    receipt: Option<DeploymentReceipt>,
    #[serde(default)]
    terminal: bool,
}
fn directory(state: &Path, component: Component) -> std::path::PathBuf {
    update::Component::from(component).directory(state)
}
fn delivery(state: &Path, component: Component) -> Result<Option<Delivery>> {
    match update::read_bounded(&directory(state, component).join("delivery.json"), 16384) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
fn save(state: &Path, record: &Delivery) -> Result<()> {
    private_write(
        &directory(state, record.deployment.component).join("delivery.json"),
        &serde_json::to_vec(record)?,
    )
}
pub(crate) fn finish_controller_delivery(state: &Path, deployment: &Deployment) -> Result<()> {
    let mut record =
        delivery(state, Component::Controller)?.ok_or("Controller delivery is missing")?;
    if &record.deployment != deployment {
        return Err("Controller receipt differs from its delivery journal".into());
    }
    record.terminal = true;
    save(state, &record)
}
pub fn health(config: &crate::Config, state: &Path) -> Option<UpdateHealth> {
    component_health(config, state, Component::Agent)
}
pub fn component_health(
    config: &crate::Config,
    state: &Path,
    component: Component,
) -> Option<UpdateHealth> {
    if !config.updates.enabled()
        || (component == Component::Controller && config.updates.controller_path.is_none())
    {
        return None;
    }
    let mut health = UpdateHealth {
        automatic: match component {
            Component::Agent => config.updates.automatic,
            Component::Controller => config.updates.controller_automatic,
        },
        supervised: match component {
            Component::Agent => crate::supervisor::child_context(state).is_some(),
            Component::Controller => crate::guardian::supervised(state),
        },
        managed: match component {
            Component::Agent => config.updates.managed,
            Component::Controller => config.updates.controller_managed,
        },
        key_fingerprint: wire::fingerprint(&config.updates.public_key).unwrap_or_default(),
        channel: config.updates.channel.clone(),
        highwater: config.updates.minimum_sequence,
        staged_release: None,
        installed_release: None,
        state: "ready".into(),
        error: String::new(),
    };
    match update::status_component(state, component.into()) {
        Ok(status) => {
            health.highwater = health.highwater.max(status.highwater);
            health.staged_release = status.staged.as_ref().and_then(|r| r.id().ok());
            health.installed_release = status.installed.as_ref().and_then(|r| r.id().ok());
            health.error = status.last_error.chars().take(128).collect();
            health.state = if status
                .transaction
                .as_ref()
                .is_some_and(|t| t.trial.is_some())
            {
                "verifying"
            } else if status.transaction.is_some() {
                "recovery_required"
            } else if status.staged.is_some() {
                "staged"
            } else if status.last_result == "rolled_back" {
                "rolled_back"
            } else if status.installed.is_some() {
                "installed"
            } else {
                "ready"
            }
            .into();
        }
        Err(error) => {
            health.state = "error".into();
            health.error = error.to_string().chars().take(128).collect();
        }
    }
    Some(health)
}

impl Client {
    pub fn managed_updates(&self, store: &Store) -> Result<()> {
        self.installation_receipts(&store.directory)?;
        self.controller_installation_receipts(&store.directory)?;
        for component in [Component::Agent, Component::Controller] {
            if let Some(mut record) = delivery(&store.directory, component)? {
                if record.deployment.component != component {
                    return Err("Update delivery journal has the wrong component".into());
                }
                let staged = update::status_component(&store.directory, component.into())?;
                if record.receipt.is_none()
                    && staged.staged.as_ref() == Some(&record.deployment.release)
                {
                    // Preserve a committed stage even if cancellation/expiry or a
                    // crash prevented its first receipt from reaching the portal.
                    let result = (|| -> Result<()> {
                        let bytes = update::read_bounded(
                            &directory(&store.directory, component).join("candidate.bin"),
                            wire::MAX_BINARY,
                        )?;
                        if bytes.len() as u64 != record.deployment.release.release.bytes
                            || athernex_endpoint_protocol::hash(&bytes)
                                != record.deployment.release.release.sha256
                        {
                            return Err(
                                "Previously staged update bytes changed before receipt recovery"
                                    .into(),
                            );
                        }
                        Ok(())
                    })();
                    let mut recovered = receipt(&record.deployment, result);
                    if recovered.outcome == "staged" {
                        recovered.finished_ms = staged.updated_ms;
                    }
                    record.receipt = Some(recovered);
                    save(&store.directory, &record)?;
                }
                if let Some(receipt) = &record.receipt {
                    if self.post("updates/receipt", receipt)?["committed"] != true {
                        return Err("Server did not commit the update receipt".into());
                    }
                    if receipt.outcome == "staged" && !record.terminal {
                        match component {
                            Component::Agent => {
                                self.prepare_installation(&store.directory, &record.deployment)?
                            }
                            Component::Controller if record.deployment.install => {
                                crate::guardian::request_fleet(
                                    &store.directory,
                                    &record.deployment,
                                )?
                            }
                            Component::Controller => {
                                record.terminal = true;
                                save(&store.directory, &record)?;
                            }
                        }
                    }
                }
            }
        }
        if (!self.config.updates.managed && !self.config.updates.controller_managed)
            || crate::supervisor::requested(&store.directory)?
            || crate::guardian::status(&store.directory)?.is_some_and(|r| {
                matches!(
                    r.phase,
                    crate::guardian::Phase::Queued | crate::guardian::Phase::Applying
                )
            })
        {
            return Ok(());
        }
        let offered: Option<Deployment> =
            serde_json::from_value(self.post("updates/poll", &serde_json::json!({}))?)?;
        let Some(offered) = offered else {
            return Ok(());
        };
        offered.validate(&self.config.endpoint_id, now_ms())?;
        let allowed = match offered.component {
            Component::Agent => self.config.updates.managed,
            Component::Controller => self.config.updates.controller_managed,
        };
        if !allowed {
            return Err("Local policy does not permit delivery for this component".into());
        }
        let mut record = match delivery(&store.directory, offered.component)? {
            Some(record) if record.deployment.id == offered.id => {
                if record.deployment != offered {
                    return Err("Update deployment changed after delivery began".into());
                }
                if record.receipt.is_some() {
                    return Ok(());
                }
                record
            }
            _ => Delivery {
                deployment: offered,
                attempts: 0,
                receipt: None,
                terminal: false,
            },
        };
        if record.attempts >= 3 {
            record.receipt = Some(receipt(
                &record.deployment,
                Err("Update delivery interrupted three times".into()),
            ));
            return save(&store.directory, &record);
        }
        record.attempts += 1;
        save(&store.directory, &record)?;
        let result = self.deliver_update(&store.directory, &record.deployment);
        // Download failures can be retried, but every attempt is recorded before
        // I/O so repeated process crashes cannot reset the retry budget.
        if result.is_ok() || record.attempts == 3 {
            record.receipt = Some(receipt(&record.deployment, result));
            save(&store.directory, &record)?;
        } else {
            result?;
        }
        Ok(())
    }
    fn deliver_update(&self, state: &Path, deployment: &Deployment) -> Result<()> {
        let component = deployment.component;
        let status = update::status_component(state, component.into())?;
        let floor = if status.staged.as_ref() == Some(&deployment.release) {
            self.config.updates.minimum_sequence
        } else {
            status.highwater.max(self.config.updates.minimum_sequence)
        };
        deployment.release.admit(
            &self.config.updates.public_key,
            &wire::target(),
            &self.config.updates.channel,
            floor,
            now_ms(),
        )?;
        let authorize = || -> Result<()> {
            deployment.validate(&self.config.endpoint_id, now_ms())?;
            let authorized: Deployment = serde_json::from_value(self.post(
                &format!("updates/{}/start", deployment.id),
                &serde_json::json!({}),
            )?)?;
            if &authorized != deployment {
                return Err("Update authorization changed".into());
            }
            Ok(())
        };
        if status.staged.as_ref() == Some(&deployment.release) {
            authorize()?;
            // Recheck the durable candidate, including bytes, after a lost receipt.
            let manifest = tempfile::NamedTempFile::new_in(directory(state, component))?;
            fs::write(manifest.path(), serde_json::to_vec(&deployment.release)?)?;
            update::stage_component(
                state,
                component.into(),
                manifest.path(),
                &directory(state, component).join("candidate.bin"),
            )?;
            return Ok(());
        }
        let mut file = tempfile::NamedTempFile::new_in(directory(state, component))?;
        let started = Instant::now();
        let mut offset = 0;
        while offset < deployment.release.release.bytes {
            if started.elapsed() >= Duration::from_secs(120) {
                return Err("Release download exceeded its time budget".into());
            }
            deployment.validate(&self.config.endpoint_id, now_ms())?;
            let response = self
                .http
                .get(self.url(&format!("updates/{}/binary?offset={offset}", deployment.id)))
                .bearer_auth(&self.config.credential)
                .timeout(Duration::from_secs(15))
                .send()?
                .error_for_status()?;
            let expected = wire::CHUNK_BYTES.min(deployment.release.release.bytes - offset);
            let mut bytes = Vec::new();
            response.take(expected + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 != expected {
                return Err("Release chunk has an unexpected byte count".into());
            }
            file.write_all(&bytes)?;
            offset += expected;
        }
        file.as_file().sync_all()?;
        authorize()?;
        let manifest = tempfile::NamedTempFile::new_in(directory(state, component))?;
        fs::write(manifest.path(), serde_json::to_vec(&deployment.release)?)?;
        update::stage_component(state, component.into(), manifest.path(), file.path())?;
        Ok(())
    }
}
fn receipt(deployment: &Deployment, result: Result<()>) -> DeploymentReceipt {
    let (outcome, detail) = match result {
        Ok(()) => (
            "staged",
            "Signed release staged; installation requires a maintenance window".into(),
        ),
        Err(e) => ("failed", e.to_string().chars().take(128).collect()),
    };
    DeploymentReceipt {
        deployment_id: deployment.id.clone(),
        release_id: deployment.release_id.clone(),
        outcome: outcome.into(),
        detail,
        finished_ms: now_ms(),
    }
}
