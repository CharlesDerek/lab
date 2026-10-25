//! Durable, operator-reviewed delivery of immutable signed endpoint releases.
use crate::{
    engine::{Engine, LabResult},
    gateway::secret,
};
use athernex_endpoint_protocol::{
    self as protocol,
    update::{
        self as wire, Component, Deployment, DeploymentReceipt, InstallationReceipt, SignedRelease,
    },
    Heartbeat, Platform,
};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

#[derive(Serialize)]
pub struct DeploymentRecord {
    pub row: u64,
    pub deployment: Deployment,
    pub state: String,
    pub receipt: Option<DeploymentReceipt>,
    pub installation: Option<InstallationReceipt>,
}

impl Engine {
    pub(crate) fn init_updates(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS endpoint_deployments(
          id TEXT PRIMARY KEY,endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
          payload TEXT NOT NULL,key_fingerprint TEXT NOT NULL,state TEXT NOT NULL,
          expires_ms INTEGER NOT NULL,approved_ms INTEGER,receipt TEXT,receipt_hash TEXT);
          CREATE UNIQUE INDEX IF NOT EXISTS one_active_endpoint_deployment ON endpoint_deployments(endpoint_id) WHERE state IN('pending','approved');")?;
        let columns = self
            .connection
            .prepare("PRAGMA table_info(endpoint_deployments)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        for (name, kind) in [
            ("install_started_ms", "INTEGER"),
            ("installation_receipt", "TEXT"),
            ("installation_hash", "TEXT"),
            ("installation_received_ms", "INTEGER"),
        ] {
            if !columns.iter().any(|c| c == name) {
                self.connection.execute_batch(&format!(
                    "ALTER TABLE endpoint_deployments ADD COLUMN {name} {kind}"
                ))?;
            }
        }
        self.connection.execute_batch("CREATE UNIQUE INDEX IF NOT EXISTS one_endpoint_maintenance ON endpoint_deployments(endpoint_id) WHERE state IN('pending','approved','ready_to_install','installing');")?;
        Ok(())
    }
    pub(crate) fn expire_updates(&self, now: u64) -> LabResult<()> {
        self.connection.execute("UPDATE endpoint_deployments SET state='expired' WHERE state IN('pending','approved','ready_to_install') AND expires_ms<=?1", [now])?;
        Ok(())
    }
    pub(crate) fn component_endpoint_matches(
        &self,
        endpoint: &str,
        release: &SignedRelease,
        fingerprint: &str,
        retry: bool,
        component: Component,
        now: u64,
    ) -> LabResult<()> {
        let (platform, arch, seen, health): (String, String, u64, String) = self.connection.query_row(
            "SELECT platform,arch,last_seen_ms,health FROM endpoints WHERE id=?1 AND state='active'", [endpoint], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        let platform: Platform = serde_json::from_str(&platform)?;
        let platform = match platform {
            Platform::Linux => "linux",
            Platform::Windows => "windows",
            Platform::Macos => "macos",
        };
        let health: Heartbeat = serde_json::from_str(&health)?;
        let updates = match component {
            Component::Agent => health.updates,
            Component::Controller => health.controller_updates,
        }
        .ok_or("Endpoint has not reported this component's update policy")?;
        if !updates.managed
            || updates.key_fingerprint != fingerprint
            || updates.channel != release.release.channel
            || release.release.target != format!("{platform}-{arch}")
            || now.saturating_sub(seen) > 120_000
            || seen > now.saturating_add(60_000)
            || (release.release.sequence <= updates.highwater
                && !(retry && updates.staged_release.as_deref() == Some(&release.id()?)))
            || matches!(updates.state.as_str(), "error" | "recovery_required")
        {
            return Err(
                "Endpoint update policy, freshness, target or sequence does not match this release"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn propose_endpoint_update(
        &self,
        endpoint: &str,
        release: &SignedRelease,
        public_key: &str,
        now: u64,
    ) -> LabResult<String> {
        self.propose_endpoint_release(endpoint, release, public_key, false, now)
    }
    pub fn propose_endpoint_release(
        &self,
        endpoint: &str,
        release: &SignedRelease,
        public_key: &str,
        install: bool,
        now: u64,
    ) -> LabResult<String> {
        self.propose_component_release(
            endpoint,
            release,
            public_key,
            Component::Agent,
            install,
            now,
        )
    }
    pub fn propose_component_release(
        &self,
        endpoint: &str,
        release: &SignedRelease,
        public_key: &str,
        component: Component,
        install: bool,
        now: u64,
    ) -> LabResult<String> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.ensure_endpoint_unreserved(endpoint)?;
        let id = self.insert_component_release(
            endpoint,
            release,
            public_key,
            install,
            (component, None),
            now,
        )?;
        tx.commit()?;
        Ok(id)
    }
    pub(crate) fn insert_component_release(
        &self,
        endpoint: &str,
        release: &SignedRelease,
        public_key: &str,
        install: bool,
        destination: (Component, Option<u64>),
        now: u64,
    ) -> LabResult<String> {
        let (component, rollout_deadline) = destination;
        self.ensure_engine_idle(endpoint)?;
        let rollout = rollout_deadline.is_some();
        release.admit(
            public_key,
            &release.release.target,
            &release.release.channel,
            0,
            now,
        )?;
        let fingerprint = wire::fingerprint(public_key)?;
        self.expire_updates(now)?;
        self.component_endpoint_matches(endpoint, release, &fingerprint, install, component, now)?;
        if install {
            self.component_installation_policy(endpoint, component)?;
        }
        let count: u64 =
            self.connection
                .query_row("SELECT count(*) FROM endpoint_deployments", [], |r| {
                    r.get(0)
                })?;
        if count
            + self
                .reserved_rollout_slots()?
                .saturating_sub(u64::from(rollout))
            >= 2048
        {
            return Err(
                "Retained deployment capacity reached; further deployments are held".into(),
            );
        }
        let active: u64 = self.connection.query_row(
            "SELECT count(*) FROM endpoint_deployments WHERE state IN('pending','approved','ready_to_install','installing')",
            [],
            |r| r.get(0),
        )?;
        if active >= 128 {
            return Err("Active endpoint deployment capacity reached".into());
        }
        let deployment = Deployment {
            component,
            install,
            id: secret()?,
            endpoint_id: endpoint.into(),
            release_id: release.id()?,
            release: release.clone(),
            created_ms: now,
            expires_ms: (now + 900_000)
                .min(release.release.expires_ms)
                .min(rollout_deadline.unwrap_or(u64::MAX)),
        };
        deployment.validate(endpoint, now)?;
        self.connection.execute("INSERT INTO endpoint_deployments(id,endpoint_id,payload,key_fingerprint,state,expires_ms,approved_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![deployment.id,endpoint,serde_json::to_string(&deployment)?,fingerprint,if rollout {"approved"} else {"pending"},deployment.expires_ms,rollout.then_some(now)])?;
        self.audit("endpoint.update_proposed", &deployment.id, now)?;
        Ok(deployment.id)
    }
    pub fn review_endpoint_update(&self, id: &str, approve: bool, now: u64) -> LabResult<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.expire_updates(now)?;
        let (raw, fingerprint, state): (String, String, String) = tx.query_row(
            "SELECT payload,key_fingerprint,state FROM endpoint_deployments WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let deployment: Deployment = serde_json::from_str(&raw)?;
        if approve {
            if state != "pending" {
                return Err("Deployment is no longer pending review".into());
            }
            deployment.validate(&deployment.endpoint_id, now)?;
            if deployment.install {
                self.component_installation_policy(&deployment.endpoint_id, deployment.component)?;
            }
            self.component_endpoint_matches(
                &deployment.endpoint_id,
                &deployment.release,
                &fingerprint,
                deployment.install,
                deployment.component,
                now,
            )?;
            tx.execute(
                "UPDATE endpoint_deployments SET state='approved',approved_ms=?1 WHERE id=?2",
                params![now, id],
            )?;
        } else {
            if !["pending", "approved", "ready_to_install"].contains(&state.as_str()) {
                return Err("Deployment can no longer be cancelled".into());
            }
            tx.execute(
                "UPDATE endpoint_deployments SET state='cancelled' WHERE id=?1",
                [id],
            )?;
        }
        self.audit(
            "endpoint.update_reviewed",
            &format!("{id}: {}", if approve { "approved" } else { "cancelled" }),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn authorized_endpoint_update(
        &self,
        endpoint: &str,
        id: &str,
        now: u64,
    ) -> LabResult<Deployment> {
        self.expire_updates(now)?;
        self.rollout_dispatch_allowed(id, now)?;
        let (raw, fingerprint): (String,String) = self.connection.query_row("SELECT payload,key_fingerprint FROM endpoint_deployments WHERE id=?1 AND endpoint_id=?2 AND state='approved'", params![id,endpoint], |r| Ok((r.get(0)?,r.get(1)?)))?;
        let deployment: Deployment = serde_json::from_str(&raw)?;
        deployment.validate(endpoint, now)?;
        self.component_endpoint_matches(
            endpoint,
            &deployment.release,
            &fingerprint,
            true,
            deployment.component,
            now,
        )?;
        Ok(deployment)
    }
    pub fn poll_endpoint_update(&self, endpoint: &str, now: u64) -> LabResult<Option<Deployment>> {
        self.expire_updates(now)?;
        let id: Option<String> = self
            .connection
            .query_row(
                "SELECT id FROM endpoint_deployments WHERE endpoint_id=?1 AND state='approved'",
                [endpoint],
                |r| r.get(0),
            )
            .optional()?;
        id.map(|id| self.authorized_endpoint_update(endpoint, &id, now))
            .transpose()
    }
    pub fn endpoint_update_receipt(
        &self,
        endpoint: &str,
        receipt: &DeploymentReceipt,
        now: u64,
    ) -> LabResult<()> {
        receipt.validate()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.expire_updates(now)?;
        let (raw, approved, prior): (String, Option<u64>, Option<String>) = tx.query_row("SELECT payload,approved_ms,receipt_hash FROM endpoint_deployments WHERE id=?1 AND endpoint_id=?2",params![receipt.deployment_id,endpoint],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let deployment: Deployment = serde_json::from_str(&raw)?;
        let payload = serde_json::to_string(receipt)?;
        let hash = protocol::hash(payload.as_bytes());
        if let Some(prior) = prior {
            if prior != hash {
                return Err("Update receipt replay changed its committed content".into());
            }
            return Ok(());
        }
        if receipt.release_id != deployment.release_id
            || approved.is_none()
            || receipt.finished_ms < approved.unwrap_or(0)
            || receipt.finished_ms > now.saturating_add(60_000)
        {
            return Err("Update receipt does not match an approved deployment".into());
        }
        // A cancellation/expiry cannot erase side effects that already occurred.
        // Retain that control state alongside the exact late endpoint receipt.
        tx.execute("UPDATE endpoint_deployments SET state=CASE WHEN state='approved' THEN ?1 ELSE state END,receipt=?2,receipt_hash=?3 WHERE id=?4", params![if receipt.outcome=="staged" && deployment.install {"ready_to_install"} else {&receipt.outcome},payload,hash,receipt.deployment_id])?;
        self.audit(
            "endpoint.update_receipt",
            &format!("{}: {}", receipt.deployment_id, receipt.outcome),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn component_installation_policy(
        &self,
        endpoint: &str,
        component: Component,
    ) -> LabResult<()> {
        let raw: String = self.connection.query_row(
            "SELECT health FROM endpoints WHERE id=?1 AND state='active'",
            [endpoint],
            |r| r.get(0),
        )?;
        let health: Heartbeat = serde_json::from_str(&raw)?;
        let updates = match component {
            Component::Agent => health.updates,
            Component::Controller => health.controller_updates,
        };
        if !updates.is_some_and(|u| u.managed && u.automatic && u.supervised) {
            return Err(
                "Endpoint has not enabled automatic installation under a live controller".into(),
            );
        }
        Ok(())
    }
    pub fn start_endpoint_installation(
        &self,
        endpoint: &str,
        id: &str,
        now: u64,
    ) -> LabResult<Deployment> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.expire_updates(now)?;
        let (raw,fingerprint,state):(String,String,String)=tx.query_row("SELECT payload,key_fingerprint,state FROM endpoint_deployments WHERE id=?1 AND endpoint_id=?2 AND state IN('ready_to_install','installing')",params![id,endpoint],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if state != "installing" {
            self.rollout_dispatch_allowed(id, now)?;
        }
        let deployment: Deployment = serde_json::from_str(&raw)?;
        deployment.validate(endpoint, now)?;
        if !deployment.install {
            return Err("This deployment authorizes staging only".into());
        }
        self.component_installation_policy(endpoint, deployment.component)?;
        self.component_endpoint_matches(
            endpoint,
            &deployment.release,
            &fingerprint,
            true,
            deployment.component,
            now,
        )?;
        let health: String = tx.query_row(
            "SELECT health FROM endpoints WHERE id=?1",
            [endpoint],
            |r| r.get(0),
        )?;
        let health: Heartbeat = serde_json::from_str(&health)?;
        let updates = match deployment.component {
            Component::Agent => health.updates,
            Component::Controller => health.controller_updates,
        };
        if updates.and_then(|h| h.staged_release).as_deref() != Some(&deployment.release_id) {
            return Err("Endpoint has not reported the exact staged release".into());
        }
        if state == "ready_to_install" {
            tx.execute("UPDATE endpoint_deployments SET state='installing',install_started_ms=?1 WHERE id=?2",params![now,id])?;
            self.audit("endpoint.install_started", id, now)?;
        }
        tx.commit()?;
        Ok(deployment)
    }
    pub fn endpoint_installation_receipt(
        &self,
        endpoint: &str,
        receipt: &InstallationReceipt,
        now: u64,
    ) -> LabResult<()> {
        receipt.validate()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let (raw,approved,started,prior):(String,Option<u64>,Option<u64>,Option<String>)=tx.query_row("SELECT payload,approved_ms,install_started_ms,installation_hash FROM endpoint_deployments WHERE id=?1 AND endpoint_id=?2",params![receipt.deployment_id,endpoint],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        let deployment: Deployment = serde_json::from_str(&raw)?;
        let raw_receipt = serde_json::to_string(receipt)?;
        let hash = protocol::hash(raw_receipt.as_bytes());
        if let Some(prior) = prior {
            if prior != hash {
                return Err("Installation receipt replay changed committed content".into());
            }
            return Ok(());
        }
        if !deployment.install
            || receipt.release_id != deployment.release_id
            || approved.is_none()
            || (receipt.outcome != "refused" && started.is_none())
            || receipt.finished_ms < started.or(approved).unwrap_or(0)
            || receipt.finished_ms > now.saturating_add(60_000)
        {
            return Err("Installation receipt does not match an authorized deployment".into());
        }
        tx.execute("UPDATE endpoint_deployments SET state=CASE WHEN state IN('cancelled','expired') THEN state ELSE ?1 END,installation_receipt=?2,installation_hash=?3,installation_received_ms=?4 WHERE id=?5",params![receipt.outcome,raw_receipt,hash,now,receipt.deployment_id])?;
        self.audit(
            "endpoint.install_receipt",
            &format!("{}: {}", receipt.deployment_id, receipt.outcome),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn endpoint_deployments(&self, before: u64, now: u64) -> LabResult<Vec<DeploymentRecord>> {
        self.expire_updates(now)?;
        let rows = self.connection.prepare("SELECT rowid,payload,state,receipt,installation_receipt FROM endpoint_deployments WHERE rowid<?1 ORDER BY rowid DESC LIMIT 64")?
            .query_map([before.min(i64::MAX as u64)], |r| Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<String>>(4)?)))?.collect::<Result<Vec<_>,_>>()?;
        rows.into_iter()
            .map(|(row, raw, state, receipt, installation)| {
                Ok(DeploymentRecord {
                    row,
                    deployment: serde_json::from_str(&raw)?,
                    state,
                    receipt: receipt.map(|r| serde_json::from_str(&r)).transpose()?,
                    installation: installation.map(|r| serde_json::from_str(&r)).transpose()?,
                })
            })
            .collect()
    }
}
