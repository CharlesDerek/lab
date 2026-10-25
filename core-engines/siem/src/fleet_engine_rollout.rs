//! Engine canaries share immutable membership and protection health gates with agent rollouts.
use crate::{
    engine::{Engine, LabResult},
    fleet_rollout::{fresh, healthy, protection_scope, HealthGate, RolloutMember, RolloutRequest},
    gateway::secret,
};
use athernex_endpoint_protocol::{
    self as protocol, engine::SignedRelease, update as wire, Heartbeat,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const FRESH_MS: u64 = 120_000;
const ACTIVE: &str = "'pending','scheduled','running','paused'";

#[derive(Clone, Serialize, Deserialize)]
pub struct EngineRolloutPlan {
    pub request: RolloutRequest,
    pub release: SignedRelease,
    pub public_key: String,
    pub gates: Vec<HealthGate>,
    pub created_ms: u64,
}
#[derive(Serialize)]
pub struct EngineRolloutRecord {
    pub id: String,
    pub plan: EngineRolloutPlan,
    pub plan_hash: String,
    pub state: String,
    pub reason: String,
    pub updated_ms: u64,
    pub members: Vec<RolloutMember>,
}

impl Engine {
    fn engine_sample_time(&self, endpoint: &str) -> LabResult<u64> {
        Ok(self.connection.query_row("SELECT min(e.last_seen_ms,h.seen_ms) FROM endpoints e JOIN endpoint_engine_health h ON h.endpoint_id=e.id WHERE e.id=?1", [endpoint], |r| r.get(0))?)
    }
    fn installed_engine_health(
        &self,
        plan: &EngineRolloutPlan,
        index: usize,
        health: &Heartbeat,
        receipt_ms: u64,
        now: u64,
    ) -> LabResult<bool> {
        let endpoint = &plan.request.endpoint_ids[index];
        let (raw, seen): (String, u64) = self.connection.query_row(
            "SELECT health,seen_ms FROM endpoint_engine_health WHERE endpoint_id=?1",
            [endpoint],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let engine: athernex_endpoint_protocol::engine_fleet::Health = serde_json::from_str(&raw)?;
        Ok(fresh(seen, now)
            && self.engine_sample_time(endpoint)? > receipt_ms
            && healthy(health, &plan.gates[index], now)
            && engine.managed
            && engine.automatic
            && engine.supervised
            && engine.error.is_empty()
            && engine.phase == "installed"
            && engine.highwater == plan.release.release.sequence
            && engine.installed_release.as_deref() == Some(plan.release.id()?.as_str())
            && engine.channel == plan.release.release.channel
            && engine.key_fingerprint == wire::fingerprint(&plan.public_key)?)
    }
    pub(crate) fn init_engine_rollouts(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS engine_rollouts(
          id TEXT PRIMARY KEY,plan TEXT NOT NULL,plan_hash TEXT NOT NULL,state TEXT NOT NULL,
          reason TEXT NOT NULL DEFAULT '',updated_ms INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS engine_rollout_members(
          rollout_id TEXT NOT NULL REFERENCES engine_rollouts(id),position INTEGER NOT NULL,
          endpoint_id TEXT NOT NULL REFERENCES endpoints(id),cohort INTEGER NOT NULL,
          deployment_id TEXT UNIQUE REFERENCES engine_deployments(id),
          healthy_since_ms INTEGER,last_healthy_ms INTEGER,
          PRIMARY KEY(rollout_id,position),UNIQUE(rollout_id,endpoint_id));
          CREATE INDEX IF NOT EXISTS engine_engine_rollout_device ON engine_rollout_members(endpoint_id);")?;
        Ok(())
    }
    pub(crate) fn reserved_engine_rollout_slots(&self) -> LabResult<u64> {
        Ok(self.connection.query_row(&format!("SELECT count(*) FROM engine_rollout_members m JOIN engine_rollouts r ON r.id=m.rollout_id WHERE r.state IN({ACTIVE}) AND m.deployment_id IS NULL"),[],|r|r.get(0))?)
    }
    pub(crate) fn ensure_engine_rollout_unreserved(&self, endpoint: &str) -> LabResult<()> {
        let reserved: bool = self.connection.query_row(&format!("SELECT EXISTS(SELECT 1 FROM engine_rollout_members m JOIN engine_rollouts r ON r.id=m.rollout_id WHERE m.endpoint_id=?1 AND r.state IN({ACTIVE}))"),[endpoint],|r|r.get(0))?;
        if reserved {
            return Err("Endpoint belongs to an active rollout; cancel that rollout before proposing separate maintenance".into());
        }
        Ok(())
    }
    pub(crate) fn engine_rollout_dispatch_allowed(
        &self,
        deployment: &str,
        now: u64,
    ) -> LabResult<()> {
        let row: Option<(String,String)> = self.connection.query_row("SELECT r.state,r.plan FROM engine_rollout_members m JOIN engine_rollouts r ON r.id=m.rollout_id WHERE m.deployment_id=?1",[deployment],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((state, raw)) = row {
            let plan: EngineRolloutPlan = serde_json::from_str(&raw)?;
            if state != "running"
                || now < plan.request.not_before_ms
                || now >= plan.request.deadline_ms
            {
                return Err(
                    "Fleet rollout is paused, stopped or outside its approved window".into(),
                );
            }
            let failed:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM engine_rollout_members m JOIN engine_deployments d ON d.id=m.deployment_id JOIN endpoints e ON e.id=m.endpoint_id WHERE m.rollout_id=(SELECT rollout_id FROM engine_rollout_members WHERE deployment_id=?1) AND (d.state NOT IN('approved','downloading','staged','installing','installed') OR e.state!='active'))",[deployment],|r|r.get(0))?;
            if failed {
                return Err(
                    "A rollout member failed or was revoked; further dispatch is held".into(),
                );
            }
        }
        Ok(())
    }
    fn engine_rollout_device(&self, endpoint: &str) -> LabResult<(u64, Heartbeat)> {
        let (seen, raw): (u64, String) = self.connection.query_row(
            "SELECT last_seen_ms,health FROM endpoints WHERE id=?1 AND state='active'",
            [endpoint],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((seen, serde_json::from_str(&raw)?))
    }
    fn engine_rollout_target_ready(
        &self,
        plan: &EngineRolloutPlan,
        index: usize,
        now: u64,
    ) -> LabResult<()> {
        let endpoint = &plan.request.endpoint_ids[index];
        self.engine_target(endpoint, &plan.release, &plan.public_key, true, now)?;
        self.ensure_component_idle(endpoint)?;
        let (seen, health) = self.engine_rollout_device(endpoint)?;
        if !fresh(seen, now) || !healthy(&health, &plan.gates[index], now) {
            return Err("Rollout target has stale or degraded protection/collection health".into());
        }
        let active: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM engine_deployments WHERE endpoint_id=?1 AND state IN('pending','approved','downloading','staged','installing'))",[endpoint],|r|r.get(0))?;
        if active {
            return Err("Rollout target already has active maintenance".into());
        }
        Ok(())
    }
    pub fn propose_engine_rollout(
        &self,
        request: RolloutRequest,
        release: &SignedRelease,
        public_key: &str,
        now: u64,
    ) -> LabResult<String> {
        if !protocol::text(&request.name, 64)
            || request.endpoint_ids.is_empty()
            || request.endpoint_ids.len() > 64
            || request.endpoint_ids.iter().any(|id| !protocol::hex_id(id))
            || request.endpoint_ids.iter().collect::<HashSet<_>>().len()
                != request.endpoint_ids.len()
            || !(1..=16).contains(&request.canary_count)
            || request.canary_count > request.endpoint_ids.len()
            || !(1..=16).contains(&request.batch_size)
            || !(60..=3600).contains(&request.observe_secs)
            || request.not_before_ms < now
            || request.deadline_ms > now.saturating_add(7 * 86_400_000)
            || request.deadline_ms > release.release.expires_ms
            || request.deadline_ms
                <= request
                    .not_before_ms
                    .saturating_add(request.observe_secs * 1000 + 60_000)
        {
            return Err("Invalid rollout: select 1–64 distinct devices, groups of 1–16, 60–3600 seconds observation and a valid window within seven days and release expiry".into());
        }
        release.admit(
            public_key,
            &release.release.target,
            &release.release.channel,
            0,
            now,
        )?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.expire_engine_deliveries(now)?;
        let count: u64 = tx.query_row("SELECT count(*) FROM engine_rollouts", [], |r| r.get(0))?;
        let active: u64 = tx.query_row(
            &format!("SELECT count(*) FROM engine_rollouts WHERE state IN({ACTIVE})"),
            [],
            |r| r.get(0),
        )?;
        let deployments: u64 =
            tx.query_row("SELECT count(*) FROM engine_deployments", [], |r| r.get(0))?;
        if count >= 32
            || active >= 8
            || deployments
                + self.reserved_engine_rollout_slots()?
                + request.endpoint_ids.len() as u64
                > 4096
        {
            return Err("Rollout or retained deployment capacity reached".into());
        }
        let mut gates = Vec::new();
        for endpoint in &request.endpoint_ids {
            self.ensure_endpoint_unreserved(endpoint)?;
            let (_, health) = self.engine_rollout_device(endpoint)?;
            gates.push(HealthGate {
                network_events: health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.network_events.is_some()),
                process_events: health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.process_events.is_some()),
                windows_process_events: health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.windows_process_events.is_some()),
                authentication: health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.authentication.is_some()),
                windows_authentication: health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.windows_authentication.is_some()),
                protection_fingerprint: protection_scope(&health),
                collector: health
                    .collector
                    .as_ref()
                    .is_some_and(|c| c.mode != "disabled"),
                signatures: !health.signature_version.is_empty(),
            });
        }
        let plan = EngineRolloutPlan {
            request,
            release: release.clone(),
            public_key: public_key.into(),
            gates,
            created_ms: now,
        };
        for index in 0..plan.request.endpoint_ids.len() {
            self.engine_rollout_target_ready(&plan, index, now)?;
        }
        let raw = serde_json::to_string(&plan)?;
        let id = secret()?;
        tx.execute("INSERT INTO engine_rollouts(id,plan,plan_hash,state,updated_ms) VALUES(?1,?2,?3,'pending',?4)",params![id,raw,protocol::hash(raw.as_bytes()),now])?;
        for (position, endpoint) in plan.request.endpoint_ids.iter().enumerate() {
            let cohort = if position < plan.request.canary_count {
                0
            } else {
                1 + (position - plan.request.canary_count) / plan.request.batch_size
            };
            tx.execute("INSERT INTO engine_rollout_members(rollout_id,position,endpoint_id,cohort) VALUES(?1,?2,?3,?4)",params![id,position,endpoint,cohort])?;
        }
        self.audit("engine.rollout_proposed", &id, now)?;
        tx.commit()?;
        Ok(id)
    }
    pub fn engine_rollouts(&self) -> LabResult<Vec<EngineRolloutRecord>> {
        let ids = self
            .connection
            .prepare("SELECT id FROM engine_rollouts ORDER BY rowid DESC LIMIT 32")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.engine_rollout(id)).collect()
    }
    pub fn engine_rollout(&self, id: &str) -> LabResult<EngineRolloutRecord> {
        let (raw, hash, state, reason, updated): (String, String, String, String, u64) =
            self.connection.query_row(
                "SELECT plan,plan_hash,state,reason,updated_ms FROM engine_rollouts WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        if protocol::hash(raw.as_bytes()) != hash {
            return Err("Rollout approval content changed".into());
        }
        let members=self.connection.prepare("SELECT m.endpoint_id,m.cohort,m.deployment_id,d.state,m.healthy_since_ms,m.last_healthy_ms,CASE WHEN d.state='installed' THEN d.updated_ms ELSE NULL END FROM engine_rollout_members m LEFT JOIN engine_deployments d ON d.id=m.deployment_id WHERE m.rollout_id=?1 ORDER BY m.position")?.query_map([id],|r|Ok(RolloutMember{endpoint_id:r.get(0)?,cohort:r.get(1)?,deployment_id:r.get(2)?,deployment_state:r.get(3)?,healthy_since_ms:r.get(4)?,last_healthy_ms:r.get(5)?,installation_received_ms:r.get(6)?}))?.collect::<Result<Vec<_>,_>>()?;
        let plan: EngineRolloutPlan = serde_json::from_str(&raw)?;
        if members.len() != plan.request.endpoint_ids.len()
            || members
                .iter()
                .zip(&plan.request.endpoint_ids)
                .any(|(m, id)| &m.endpoint_id != id)
            || plan.gates.len() != members.len()
        {
            return Err("Rollout membership differs from its immutable approval".into());
        }
        if members.iter().enumerate().any(|(i, m)| {
            m.cohort
                != if i < plan.request.canary_count {
                    0
                } else {
                    1 + (i - plan.request.canary_count) / plan.request.batch_size
                }
        }) {
            return Err("Rollout groups differ from their immutable approval".into());
        }
        Ok(EngineRolloutRecord {
            id: id.into(),
            plan,
            plan_hash: hash,
            state,
            reason,
            updated_ms: updated,
            members,
        })
    }
    fn stop_engine_rollout(&self, id: &str, state: &str, reason: &str, now: u64) -> LabResult<()> {
        self.connection.execute("UPDATE engine_deployments SET state='cancelled' WHERE id IN(SELECT deployment_id FROM engine_rollout_members WHERE rollout_id=?1) AND state IN('pending','approved','downloading','staged')",[id])?;
        self.connection.execute(
            "UPDATE engine_rollouts SET state=?1,reason=?2,updated_ms=?3 WHERE id=?4",
            params![state, reason.chars().take(256).collect::<String>(), now, id],
        )?;
        self.audit(
            "engine.rollout_stopped",
            &format!(
                "{id}: {state}: {}",
                reason.chars().take(128).collect::<String>()
            ),
            now,
        )?;
        Ok(())
    }
    pub fn review_engine_rollout(
        &self,
        id: &str,
        hash: &str,
        action: &str,
        now: u64,
    ) -> LabResult<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = self.engine_rollout(id)?;
        if record.plan_hash != hash {
            return Err("Approval does not match the immutable rollout plan".into());
        }
        match action {
            "cancel"
                if ["pending", "scheduled", "running", "paused"]
                    .contains(&record.state.as_str()) =>
            {
                self.stop_engine_rollout(
                    id,
                    "cancelled",
                    "Cancelled by operator; started installations must finish or recover",
                    now,
                )?
            }
            "pause" if ["scheduled", "running"].contains(&record.state.as_str()) => {
                self.connection.execute("UPDATE engine_rollouts SET state='paused',reason='Paused by operator; started installations may finish',updated_ms=?1 WHERE id=?2",params![now,id])?;
                self.connection.execute("UPDATE engine_rollout_members SET healthy_since_ms=NULL,last_healthy_ms=NULL WHERE rollout_id=?1",[id])?;
            }
            "approve" if record.state == "pending" => {
                if now >= record.plan.request.deadline_ms {
                    return Err("Rollout approval window expired".into());
                }
                record.plan.release.admit(
                    &record.plan.public_key,
                    &record.plan.release.release.target,
                    &record.plan.release.release.channel,
                    0,
                    now,
                )?;
                for index in 0..record.members.len() {
                    self.engine_rollout_target_ready(&record.plan, index, now)?;
                }
                self.connection.execute("UPDATE engine_rollouts SET state='scheduled',reason='',updated_ms=?1 WHERE id=?2",params![now,id])?;
            }
            "resume" if record.state == "paused" => {
                if now >= record.plan.request.deadline_ms {
                    return Err("Rollout window expired; cancel this plan".into());
                }
                self.connection.execute("UPDATE engine_rollouts SET state='running',reason='',updated_ms=?1 WHERE id=?2",params![now,id])?;
            }
            _ => return Err("Rollout action does not match its current state".into()),
        }
        self.audit(
            "engine.rollout_reviewed",
            &format!("{id}: {action}: {hash}"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn observe_engine_rollout_endpoint(
        &self,
        endpoint: &str,
        now: u64,
    ) -> LabResult<()> {
        let rows=self.connection.prepare("SELECT m.rollout_id,m.position FROM engine_rollout_members m JOIN engine_rollouts r ON r.id=m.rollout_id WHERE m.endpoint_id=?1 AND r.state='running' AND m.deployment_id IS NOT NULL")?.query_map([endpoint],|r|Ok((r.get::<_,String>(0)?,r.get::<_,usize>(1)?)))?.collect::<Result<Vec<_>,_>>()?;
        if rows.is_empty() {
            return Ok(());
        }
        let (_, health) = self.engine_rollout_device(endpoint)?;
        for (id, index) in rows {
            let record = self.engine_rollout(&id)?;
            let member = &record.members[index];
            if member.deployment_state.as_deref() == Some("installed")
                && self.installed_engine_health(
                    &record.plan,
                    index,
                    &health,
                    member.installation_received_ms.unwrap_or(now),
                    now,
                )?
            {
                let sample = self.engine_sample_time(endpoint)?;
                let since = if member
                    .last_healthy_ms
                    .is_some_and(|last| last <= sample && sample - last <= FRESH_MS)
                {
                    member.healthy_since_ms.unwrap_or(sample)
                } else {
                    sample
                };
                self.connection.execute("UPDATE engine_rollout_members SET healthy_since_ms=?1,last_healthy_ms=?2 WHERE rollout_id=?3 AND position=?4",params![since,sample,id,index])?;
            } else {
                self.connection.execute("UPDATE engine_rollout_members SET healthy_since_ms=NULL,last_healthy_ms=NULL WHERE rollout_id=?1 AND position=?2",params![id,index])?;
                if member.deployment_state.as_deref() == Some("installed")
                    && member.healthy_since_ms.is_some()
                {
                    self.stop_engine_rollout(
                        &id,
                        "failed",
                        &format!("Installed endpoint {endpoint} reported degraded health"),
                        now,
                    )?;
                }
            }
        }
        Ok(())
    }
    pub fn tick_engine_rollouts(&self, now: u64) -> LabResult<()> {
        self.expire_engine_deliveries(now)?;
        let ids = self
            .connection
            .prepare(&format!(
                "SELECT id FROM engine_rollouts WHERE state IN({ACTIVE}) ORDER BY rowid"
            ))?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for id in ids {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            match self.advance_engine_rollout(&id, now) {
                Ok(()) => tx.commit()?,
                Err(error) => {
                    tx.rollback()?;
                    let tx = Transaction::new_unchecked(
                        &self.connection,
                        TransactionBehavior::Immediate,
                    )?;
                    self.stop_engine_rollout(&id, "failed", &error.to_string(), now)?;
                    tx.commit()?;
                }
            }
        }
        Ok(())
    }
    fn advance_engine_rollout(&self, id: &str, now: u64) -> LabResult<()> {
        self.expire_engine_deliveries(now)?;
        let record = self.engine_rollout(id)?;
        let request = &record.plan.request;
        if now >= request.deadline_ms {
            return self.stop_engine_rollout(
                id,
                "expired",
                "Rollout deadline reached; started installations must finish or recover",
                now,
            );
        }
        if ["pending", "paused"].contains(&record.state.as_str()) || now < request.not_before_ms {
            return Ok(());
        }
        record.plan.release.admit(
            &record.plan.public_key,
            &record.plan.release.release.target,
            &record.plan.release.release.channel,
            0,
            now,
        )?;
        let mut waiting = false;
        for (index, member) in record
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.deployment_id.is_some())
        {
            let (seen, health) = self.engine_rollout_device(&member.endpoint_id)?;
            match member.deployment_state.as_deref() {
                Some("approved" | "downloading" | "staged" | "installing") => waiting = true,
                Some("installed") => {
                    if member.healthy_since_ms.is_none()
                        && member
                            .installation_received_ms
                            .is_some_and(|received| now >= received && now - received < FRESH_MS)
                    {
                        waiting = true;
                        continue;
                    }
                    if !fresh(seen, now)
                        || !self.installed_engine_health(
                            &record.plan,
                            index,
                            &health,
                            member.installation_received_ms.unwrap_or(now),
                            now,
                        )?
                    {
                        return Err(format!(
                            "Installed endpoint {} lost required health",
                            member.endpoint_id
                        )
                        .into());
                    }
                    let observed = member
                        .healthy_since_ms
                        .zip(member.last_healthy_ms)
                        .is_some_and(|(first, last)| {
                            last >= first.saturating_add(request.observe_secs * 1000)
                                && last <= now
                                && now - last <= FRESH_MS
                        });
                    if !observed {
                        waiting = true;
                    }
                }
                _ => {
                    return Err(format!(
                        "Endpoint {} deployment ended as {}",
                        member.endpoint_id,
                        member.deployment_state.as_deref().unwrap_or("missing")
                    )
                    .into())
                }
            }
        }
        // A receipt may arrive before the following heartbeat. Wait for that
        // heartbeat within the existing freshness allowance, rather than using
        // a previous release's health to authorize the next cohort.
        if waiting {
            return Ok(());
        }
        let Some(cohort) = record
            .members
            .iter()
            .find(|m| m.deployment_id.is_none())
            .map(|m| m.cohort)
        else {
            self.connection.execute("UPDATE engine_rollouts SET state='completed',reason='Every device completed installation and the required health window',updated_ms=?1 WHERE id=?2",params![now,id])?;
            self.audit("engine.rollout_completed", id, now)?;
            return Ok(());
        };
        let indexes = record
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.cohort == cohort && m.deployment_id.is_none())
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let active:u64=self.connection.query_row("SELECT count(*) FROM engine_deployments WHERE state IN('pending','approved','downloading','staged','installing')",[],|r|r.get(0))?;
        if active + indexes.len() as u64 > 128 {
            return Ok(());
        }
        for &index in &indexes {
            self.engine_rollout_target_ready(&record.plan, index, now)?;
        }
        self.connection.execute(
            "UPDATE engine_rollouts SET state='running',reason='',updated_ms=?1 WHERE id=?2",
            params![now, id],
        )?;
        for index in indexes {
            let deployment = self.insert_engine_release(
                &request.endpoint_ids[index],
                &record.plan.release,
                &record.plan.public_key,
                true,
                Some(request.deadline_ms),
                now,
            )?;
            self.connection.execute("UPDATE engine_rollout_members SET deployment_id=?1 WHERE rollout_id=?2 AND position=?3",params![deployment,id,index])?;
        }
        self.audit(
            "engine.rollout_cohort",
            &format!("{id}: group {}", cohort + 1),
            now,
        )?;
        Ok(())
    }
}
