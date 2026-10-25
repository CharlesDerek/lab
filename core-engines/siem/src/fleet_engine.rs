//! Fleet engine proposals and receipts. Agent-local policy remains authoritative.
use crate::{
    engine::{Engine, LabResult},
    gateway::{digest, secret},
};
use athernex_endpoint_protocol::{
    engine::SignedRelease,
    engine_fleet::{Deployment, Health, Receipt},
    update,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
#[derive(Serialize)]
pub struct EngineDeployment {
    pub deployment: Deployment,
    pub plan_hash: String,
    pub state: String,
    pub staging_receipt: Option<Receipt>,
    pub installation_receipt: Option<Receipt>,
}
impl Engine {
    pub(crate) fn init_engine_fleet(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS endpoint_engine_health(endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id),health TEXT NOT NULL,seen_ms INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS engine_deployments(id TEXT PRIMARY KEY,endpoint_id TEXT NOT NULL REFERENCES endpoints(id),plan TEXT NOT NULL,plan_hash TEXT NOT NULL,key_fingerprint TEXT NOT NULL,state TEXT NOT NULL,staging_receipt TEXT,installation_receipt TEXT,updated_ms INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS engine_deployment_queue ON engine_deployments(endpoint_id,state);")?;
        Ok(())
    }
    pub fn endpoint_engine_health(
        &self,
        endpoint: &str,
        health: &Health,
        now: u64,
    ) -> LabResult<()> {
        health.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.connection.execute("INSERT INTO endpoint_engine_health VALUES(?1,?2,?3) ON CONFLICT(endpoint_id) DO UPDATE SET health=excluded.health,seen_ms=excluded.seen_ms",params![endpoint,serde_json::to_string(health)?,now])?;
        self.observe_engine_rollout_endpoint(endpoint, now)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn engine_target(
        &self,
        endpoint: &str,
        release: &SignedRelease,
        key: &str,
        install: bool,
        now: u64,
    ) -> LabResult<()> {
        let (raw,seen):(String,u64)=self.connection.query_row("SELECT h.health,h.seen_ms FROM endpoint_engine_health h JOIN endpoints e ON e.id=h.endpoint_id WHERE e.id=?1 AND e.state='active'",[endpoint],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let health: Health = serde_json::from_str(&raw)?;
        let (platform, arch): (String, String) = self.connection.query_row(
            "SELECT platform,arch FROM endpoints WHERE id=?1",
            [endpoint],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let platform: athernex_endpoint_protocol::Platform = serde_json::from_str(&platform)?;
        let platform = match platform {
            athernex_endpoint_protocol::Platform::Linux => "linux",
            athernex_endpoint_protocol::Platform::Windows => "windows",
            athernex_endpoint_protocol::Platform::Macos => "macos",
        };
        let recovered = if health.phase == "rolled_back" {
            let (raw, seen): (String, u64) = self.connection.query_row(
                "SELECT health,last_seen_ms FROM endpoints WHERE id=?1",
                [endpoint],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let endpoint_health: athernex_endpoint_protocol::Heartbeat =
                serde_json::from_str(&raw)?;
            let gate = crate::fleet_rollout::HealthGate {
                network_events: endpoint_health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.network_events.is_some()),
                process_events: endpoint_health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.process_events.is_some()),
                authentication: endpoint_health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.authentication.is_some()),
                protection_fingerprint: crate::fleet_rollout::protection_scope(&endpoint_health),
                collector: endpoint_health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.mode != "disabled"),
                signatures: true,
            };
            crate::fleet_rollout::fresh(seen, now)
                && crate::fleet_rollout::healthy(&endpoint_health, &gate, now)
        } else {
            false
        };
        if now.saturating_sub(seen) > 120000
            || seen > now
            || !health.managed
            || (!health.error.is_empty() && !recovered)
            || health.target != format!("{platform}-{arch}")
            || health.key_fingerprint != update::fingerprint(key)?
            || (install && (!health.automatic || !health.supervised))
        {
            return Err(
                "Fresh opted-in endpoint engine policy and controller health required".into(),
            );
        }
        let floor = if health.staged_release.as_deref() == Some(release.id()?.as_str()) {
            0
        } else {
            health.highwater
        };
        release.admit(key, &health.target, &health.channel, floor, now)?;
        Ok(())
    }
    pub fn propose_engine_update(
        &self,
        endpoint: &str,
        release: &SignedRelease,
        key: &str,
        install: bool,
        now: u64,
    ) -> LabResult<EngineDeployment> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.ensure_endpoint_unreserved(endpoint)?;
        let id = self.insert_engine_release(endpoint, release, key, install, None, now)?;
        tx.commit()?;
        self.engine_deployment(&id)
    }
    pub(crate) fn ensure_component_idle(&self, endpoint: &str) -> LabResult<()> {
        let busy: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM endpoint_deployments WHERE endpoint_id=?1 AND state IN('pending','approved','ready_to_install','installing'))", [endpoint], |r| r.get(0))?;
        if busy {
            return Err("Agent or controller maintenance already owns this endpoint".into());
        }
        Ok(())
    }
    pub(crate) fn ensure_engine_idle(&self, endpoint: &str) -> LabResult<()> {
        let busy: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM engine_deployments WHERE endpoint_id=?1 AND state IN('pending','approved','downloading','staged','installing'))", [endpoint], |r| r.get(0))?;
        if busy {
            return Err("Engine maintenance already owns this endpoint".into());
        }
        Ok(())
    }
    pub(crate) fn expire_engine_deliveries(&self, now: u64) -> LabResult<()> {
        self.connection.execute("UPDATE engine_deployments SET state='expired',updated_ms=?1 WHERE state IN('pending','approved','downloading','staged') AND json_extract(plan,'$.expires_ms')<=?1", [now])?;
        Ok(())
    }
    pub(crate) fn insert_engine_release(
        &self,
        endpoint: &str,
        release: &SignedRelease,
        key: &str,
        install: bool,
        rollout_deadline: Option<u64>,
        now: u64,
    ) -> LabResult<String> {
        if self.connection.is_autocommit() {
            return Err("Engine proposal requires a transaction".into());
        }
        self.expire_engine_deliveries(now)?;
        self.expire_updates(now)?;
        self.ensure_component_idle(endpoint)?;
        self.engine_target(endpoint, release, key, install, now)?;
        let busy:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM engine_deployments WHERE endpoint_id=?1 AND state IN('pending','approved','downloading','staged','installing'))",[endpoint],|r|r.get(0))?;
        if busy {
            return Err("Endpoint already owns an unfinished engine deployment".into());
        }
        let count: u64 =
            self.connection
                .query_row("SELECT count(*) FROM engine_deployments", [], |r| r.get(0))?;
        if count
            + self
                .reserved_engine_rollout_slots()?
                .saturating_sub(u64::from(rollout_deadline.is_some()))
            >= 4096
        {
            return Err("Engine delivery history capacity reached".into());
        }
        let deployment = Deployment {
            id: secret()?,
            endpoint_id: endpoint.into(),
            release: release.clone(),
            install,
            created_ms: now,
            expires_ms: now
                .saturating_add(900000)
                .min(release.release.expires_ms)
                .min(rollout_deadline.unwrap_or(u64::MAX)),
        };
        deployment.validate(endpoint, now)?;
        let raw = serde_json::to_string(&deployment)?;
        self.connection.execute(
            "INSERT INTO engine_deployments VALUES(?1,?2,?3,?4,?5,?7,NULL,NULL,?6)",
            params![
                deployment.id,
                endpoint,
                raw,
                digest(&raw),
                update::fingerprint(key)?,
                now,
                if rollout_deadline.is_some() {
                    "approved"
                } else {
                    "pending"
                }
            ],
        )?;
        self.audit("engine.proposed", &deployment.id, now)?;
        Ok(deployment.id)
    }
    pub fn engine_deployment(&self, id: &str) -> LabResult<EngineDeployment> {
        let (raw,plan_hash,state,staged,installed):(String,String,String,Option<String>,Option<String>)=self.connection.query_row("SELECT plan,plan_hash,state,staging_receipt,installation_receipt FROM engine_deployments WHERE id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        if digest(&raw) != plan_hash {
            return Err("Engine deployment integrity failed".into());
        }
        Ok(EngineDeployment {
            deployment: serde_json::from_str(&raw)?,
            plan_hash,
            state,
            staging_receipt: staged.map(|v| serde_json::from_str(&v)).transpose()?,
            installation_receipt: installed.map(|v| serde_json::from_str(&v)).transpose()?,
        })
    }
    pub fn engine_deployments(&self) -> LabResult<Vec<EngineDeployment>> {
        let ids = self
            .connection
            .prepare("SELECT id FROM engine_deployments ORDER BY rowid DESC LIMIT 256")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter().map(|id| self.engine_deployment(id)).collect()
    }
    pub fn review_engine_update(
        &self,
        id: &str,
        hash: &str,
        key: &str,
        approve: bool,
        now: u64,
    ) -> LabResult<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = self.engine_deployment(id)?;
        let grouped: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM engine_rollout_members WHERE deployment_id=?1)",
            [id],
            |r| r.get(0),
        )?;
        if grouped {
            return Err(
                "Review the immutable engine rollout instead of an individual member".into(),
            );
        }
        if record.plan_hash != hash
            || record.state == "installing"
            || [
                "installed",
                "rolled_back",
                "refused",
                "cancelled",
                "expired",
                "delivered",
            ]
            .contains(&record.state.as_str())
        {
            return Err(
                "Engine review is stale, terminal or installation already authorized".into(),
            );
        }
        if approve {
            if record.state != "pending" {
                return Err("Engine proposal already reviewed".into());
            }
            record
                .deployment
                .validate(&record.deployment.endpoint_id, now)?;
            self.engine_target(
                &record.deployment.endpoint_id,
                &record.deployment.release,
                key,
                record.deployment.install,
                now,
            )?;
        }
        tx.execute(
            "UPDATE engine_deployments SET state=?2,updated_ms=?3 WHERE id=?1",
            params![id, if approve { "approved" } else { "cancelled" }, now],
        )?;
        self.audit("engine.reviewed", &format!("{id}: {approve}"), now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn poll_engine_update(
        &self,
        endpoint: &str,
        key: &str,
        now: u64,
    ) -> LabResult<Option<Deployment>> {
        let id:Option<String>=self.connection.query_row("SELECT id FROM engine_deployments WHERE endpoint_id=?1 AND state IN('approved','downloading','staged','installing') ORDER BY rowid LIMIT 1",[endpoint],|r|r.get(0)).optional()?;
        let Some(id) = id else {
            return Ok(None);
        };
        let record = self.engine_deployment(&id)?;
        self.engine_rollout_dispatch_allowed(&id, now)?;
        record.deployment.validate(endpoint, now)?;
        self.engine_target(
            endpoint,
            &record.deployment.release,
            key,
            record.deployment.install,
            now,
        )?;
        Ok(Some(record.deployment))
    }
    pub fn authorize_engine_download(
        &self,
        endpoint: &str,
        id: &str,
        key: &str,
        now: u64,
    ) -> LabResult<Deployment> {
        let record = self.engine_deployment(id)?;
        self.engine_rollout_dispatch_allowed(id, now)?;
        if record.deployment.endpoint_id != endpoint
            || !["approved", "downloading"].contains(&record.state.as_str())
        {
            return Err("Engine download is not authorized".into());
        }
        record.deployment.validate(endpoint, now)?;
        self.engine_target(
            endpoint,
            &record.deployment.release,
            key,
            record.deployment.install,
            now,
        )?;
        Ok(record.deployment)
    }
    pub fn authorize_engine_install(
        &self,
        endpoint: &str,
        id: &str,
        key: &str,
        now: u64,
    ) -> LabResult<Deployment> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = self.engine_deployment(id)?;
        self.engine_rollout_dispatch_allowed(id, now)?;
        if record.deployment.endpoint_id != endpoint
            || !record.deployment.install
            || !["staged", "installing"].contains(&record.state.as_str())
        {
            return Err("Engine installation is not approved or staged".into());
        }
        record.deployment.validate(endpoint, now)?;
        self.engine_target(endpoint, &record.deployment.release, key, true, now)?;
        tx.execute(
            "UPDATE engine_deployments SET state='installing',updated_ms=?2 WHERE id=?1",
            params![id, now],
        )?;
        self.audit("engine.installation_authorized", id, now)?;
        tx.commit()?;
        Ok(record.deployment)
    }
    pub fn finish_engine_delivery(
        &self,
        endpoint: &str,
        receipt: &Receipt,
        now: u64,
    ) -> LabResult<()> {
        receipt.validate()?;
        if receipt.finished_ms > now.saturating_add(60000) {
            return Err("Engine receipt timestamp is in the future".into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = self.engine_deployment(&receipt.deployment_id)?;
        if record.deployment.endpoint_id != endpoint
            || record.deployment.release.id()? != receipt.release_id
        {
            return Err("Engine receipt does not match this endpoint/release".into());
        }
        let installing = record
            .staging_receipt
            .as_ref()
            .is_some_and(|r| r.outcome == "staged")
            && receipt.outcome != "staged";
        let previous = if installing {
            &record.installation_receipt
        } else {
            &record.staging_receipt
        };
        if let Some(previous) = previous {
            if previous == receipt {
                return Ok(());
            }
            return Err("Engine receipt replay conflicts".into());
        }
        let authorized = if installing {
            record.state == "installing"
        } else {
            ["approved", "downloading", "cancelled", "expired"].contains(&record.state.as_str())
                && !["installed", "rolled_back"].contains(&receipt.outcome.as_str())
        };
        if !authorized {
            return Err("Engine receipt arrived outside its authorized lifecycle".into());
        }
        let state = if ["cancelled", "expired"].contains(&record.state.as_str()) {
            record.state.as_str()
        } else if receipt.outcome == "staged" && !record.deployment.install {
            "delivered"
        } else {
            receipt.outcome.as_str()
        };
        let column = if installing {
            "installation_receipt"
        } else {
            "staging_receipt"
        };
        tx.execute(
            &format!(
                "UPDATE engine_deployments SET state=?2,{column}=?3,updated_ms=?4 WHERE id=?1"
            ),
            params![
                receipt.deployment_id,
                state,
                serde_json::to_string(receipt)?,
                now
            ],
        )?;
        self.audit(
            "engine.receipt",
            &format!("{}: {}", receipt.deployment_id, receipt.outcome),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
}
