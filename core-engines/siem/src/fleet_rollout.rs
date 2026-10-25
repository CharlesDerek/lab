//! Immutable fleet approvals and durable health-gated promotion.
use crate::{
    engine::{Engine, LabResult},
    gateway::secret,
};
use athernex_endpoint_protocol::{
    self as protocol,
    update::{self as wire, Component, SignedRelease, UpdateHealth},
    Heartbeat,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const FRESH_MS: u64 = 120_000;
const ACTIVE: &str = "'pending','scheduled','running','paused'";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutRequest {
    pub name: String,
    /// Order is intentional: the first canary_count identities are canaries.
    pub endpoint_ids: Vec<String>,
    pub canary_count: usize,
    pub batch_size: usize,
    pub observe_secs: u64,
    pub not_before_ms: u64,
    pub deadline_ms: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct HealthGate {
    pub protection_fingerprint: Option<String>,
    pub collector: bool,
    pub signatures: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub process_events: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub windows_process_events: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authentication: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub windows_authentication: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network_events: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct RolloutPlan {
    #[serde(default, skip_serializing_if = "Component::is_agent")]
    pub component: Component,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_identities: Vec<AgentIdentity>,
    pub request: RolloutRequest,
    pub release: SignedRelease,
    pub public_key: String,
    pub gates: Vec<HealthGate>,
    pub created_ms: u64,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub version: String,
    pub installed_release: Option<String>,
}
impl AgentIdentity {
    fn observed(health: &Heartbeat) -> Self {
        Self {
            version: health.version.clone(),
            installed_release: health
                .updates
                .as_ref()
                .and_then(|u| u.installed_release.clone()),
        }
    }
}
fn component_health(health: &Heartbeat, component: Component) -> Option<&UpdateHealth> {
    match component {
        Component::Agent => health.updates.as_ref(),
        Component::Controller => health.controller_updates.as_ref(),
    }
}
fn agent_preserved(plan: &RolloutPlan, index: usize, health: &Heartbeat) -> bool {
    plan.component == Component::Agent
        || plan.agent_identities.get(index) == Some(&AgentIdentity::observed(health))
}
#[derive(Serialize)]
pub struct RolloutMember {
    pub endpoint_id: String,
    pub cohort: usize,
    pub deployment_id: Option<String>,
    pub deployment_state: Option<String>,
    pub healthy_since_ms: Option<u64>,
    pub last_healthy_ms: Option<u64>,
    pub installation_received_ms: Option<u64>,
}
#[derive(Serialize)]
pub struct RolloutRecord {
    pub id: String,
    pub plan: RolloutPlan,
    pub plan_hash: String,
    pub state: String,
    pub reason: String,
    pub updated_ms: u64,
    pub members: Vec<RolloutMember>,
}

pub(crate) fn protection_scope(health: &Heartbeat) -> Option<String> {
    health
        .protection
        .as_ref()
        .filter(|p| p.state != "disabled")
        .map(|p| {
            protocol::hash(
                &serde_json::to_vec(&(&p.backend, &p.roots, p.excluded_uid))
                    .expect("Serializable scope"),
            )
        })
}
pub(crate) fn fresh(time: u64, now: u64) -> bool {
    time > 0 && time <= now.saturating_add(60_000) && now.saturating_sub(time) <= FRESH_MS
}
pub(crate) fn healthy(health: &Heartbeat, gate: &HealthGate, now: u64) -> bool {
    let scope = protection_scope(health);
    health.error.is_empty()
        && (!gate.network_events
            || health
                .collector
                .as_ref()
                .and_then(|c| c.network_events.as_ref())
                .is_some_and(|h| h.healthy(now)))
        && health
            .collector
            .as_ref()
            .and_then(|c| c.network_events.as_ref())
            .is_none_or(|h| h.healthy(now))
        && (!gate.authentication
            || health
                .collector
                .as_ref()
                .and_then(|c| c.authentication.as_ref())
                .is_some_and(|h| h.healthy(now)))
        && health
            .collector
            .as_ref()
            .and_then(|c| c.authentication.as_ref())
            .is_none_or(|h| h.healthy(now))
        && (!gate.windows_authentication
            || health
                .collector
                .as_ref()
                .and_then(|c| c.windows_authentication.as_ref())
                .is_some_and(|h| h.healthy(now)))
        && health
            .collector
            .as_ref()
            .and_then(|c| c.windows_authentication.as_ref())
            .is_none_or(|h| h.healthy(now))
        && (!gate.process_events
            || health
                .collector
                .as_ref()
                .and_then(|c| c.process_events.as_ref())
                .is_some_and(|h| h.healthy(now)))
        && health
            .collector
            .as_ref()
            .and_then(|c| c.process_events.as_ref())
            .is_none_or(|h| h.healthy(now))
        && (!gate.windows_process_events
            || health
                .collector
                .as_ref()
                .and_then(|c| c.windows_process_events.as_ref())
                .is_some_and(|h| h.healthy(now)))
        && health
            .collector
            .as_ref()
            .and_then(|c| c.windows_process_events.as_ref())
            .is_none_or(|h| h.healthy(now))
        && (!gate.signatures || !health.signature_version.is_empty())
        && (gate.protection_fingerprint.is_none() || scope == gate.protection_fingerprint)
        && (scope.is_none()
            || (health.realtime
                && health.protection.as_ref().is_some_and(|p| {
                    p.state == "active"
                        && p.error.is_empty()
                        && p.dropped_events == 0
                        && fresh(p.checked_ms, now)
                })))
        && (!(gate.collector
            || health
                .collector
                .as_ref()
                .is_some_and(|c| c.mode != "disabled"))
            || health.collector.as_ref().is_some_and(|c| {
                c.mode == "snapshot"
                    && !c.incomplete
                    && c.error.is_empty()
                    && fresh(c.last_success_ms, now)
            }))
}

fn installed_health(plan: &RolloutPlan, index: usize, health: &Heartbeat, now: u64) -> bool {
    healthy(health, &plan.gates[index], now)
        && agent_preserved(plan, index, health)
        && (plan.component == Component::Controller
            || health.version == plan.release.release.version)
        && component_health(health, plan.component).is_some_and(|u| {
            u.managed
                && u.automatic
                && u.supervised
                && u.state == "installed"
                && u.error.is_empty()
                && u.installed_release.as_deref() == plan.release.id().ok().as_deref()
                && u.highwater == plan.release.release.sequence
                && u.channel == plan.release.release.channel
                && wire::fingerprint(&plan.public_key).ok().as_deref() == Some(&u.key_fingerprint)
        })
}

impl Engine {
    pub(crate) fn init_rollouts(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS endpoint_rollouts(
          id TEXT PRIMARY KEY,plan TEXT NOT NULL,plan_hash TEXT NOT NULL,state TEXT NOT NULL,
          reason TEXT NOT NULL DEFAULT '',updated_ms INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS endpoint_rollout_members(
          rollout_id TEXT NOT NULL REFERENCES endpoint_rollouts(id),position INTEGER NOT NULL,
          endpoint_id TEXT NOT NULL REFERENCES endpoints(id),cohort INTEGER NOT NULL,
          deployment_id TEXT UNIQUE REFERENCES endpoint_deployments(id),
          healthy_since_ms INTEGER,last_healthy_ms INTEGER,
          PRIMARY KEY(rollout_id,position),UNIQUE(rollout_id,endpoint_id));
          CREATE INDEX IF NOT EXISTS endpoint_rollout_device ON endpoint_rollout_members(endpoint_id);")?;
        Ok(())
    }
    pub(crate) fn reserved_rollout_slots(&self) -> LabResult<u64> {
        Ok(self.connection.query_row(&format!("SELECT count(*) FROM endpoint_rollout_members m JOIN endpoint_rollouts r ON r.id=m.rollout_id WHERE r.state IN({ACTIVE}) AND m.deployment_id IS NULL"),[],|r|r.get(0))?)
    }
    pub(crate) fn ensure_endpoint_unreserved(&self, endpoint: &str) -> LabResult<()> {
        self.ensure_engine_rollout_unreserved(endpoint)?;
        let reserved: bool = self.connection.query_row(&format!("SELECT EXISTS(SELECT 1 FROM endpoint_rollout_members m JOIN endpoint_rollouts r ON r.id=m.rollout_id WHERE m.endpoint_id=?1 AND r.state IN({ACTIVE}))"),[endpoint],|r|r.get(0))?;
        if reserved {
            return Err("Endpoint belongs to an active rollout; cancel that rollout before proposing separate maintenance".into());
        }
        Ok(())
    }
    pub(crate) fn rollout_dispatch_allowed(&self, deployment: &str, now: u64) -> LabResult<()> {
        let row: Option<(String,String)> = self.connection.query_row("SELECT r.state,r.plan FROM endpoint_rollout_members m JOIN endpoint_rollouts r ON r.id=m.rollout_id WHERE m.deployment_id=?1",[deployment],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((state, raw)) = row {
            let plan: RolloutPlan = serde_json::from_str(&raw)?;
            if state != "running"
                || now < plan.request.not_before_ms
                || now >= plan.request.deadline_ms
            {
                return Err(
                    "Fleet rollout is paused, stopped or outside its approved window".into(),
                );
            }
            let failed:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM endpoint_rollout_members m JOIN endpoint_deployments d ON d.id=m.deployment_id JOIN endpoints e ON e.id=m.endpoint_id WHERE m.rollout_id=(SELECT rollout_id FROM endpoint_rollout_members WHERE deployment_id=?1) AND (d.state NOT IN('approved','ready_to_install','installing','installed') OR e.state!='active'))",[deployment],|r|r.get(0))?;
            if failed {
                return Err(
                    "A rollout member failed or was revoked; further dispatch is held".into(),
                );
            }
        }
        Ok(())
    }
    fn rollout_device(&self, endpoint: &str) -> LabResult<(u64, Heartbeat)> {
        let (seen, raw): (u64, String) = self.connection.query_row(
            "SELECT last_seen_ms,health FROM endpoints WHERE id=?1 AND state='active'",
            [endpoint],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((seen, serde_json::from_str(&raw)?))
    }
    fn rollout_target_ready(&self, plan: &RolloutPlan, index: usize, now: u64) -> LabResult<()> {
        let endpoint = &plan.request.endpoint_ids[index];
        self.ensure_engine_idle(endpoint)?;
        self.component_endpoint_matches(
            endpoint,
            &plan.release,
            &wire::fingerprint(&plan.public_key)?,
            true,
            plan.component,
            now,
        )?;
        self.component_installation_policy(endpoint, plan.component)?;
        let (seen, health) = self.rollout_device(endpoint)?;
        if !fresh(seen, now)
            || !healthy(&health, &plan.gates[index], now)
            || !agent_preserved(plan, index, &health)
        {
            return Err("Rollout target has stale or degraded protection/collection health".into());
        }
        let active: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM endpoint_deployments WHERE endpoint_id=?1 AND state IN('pending','approved','ready_to_install','installing'))",[endpoint],|r|r.get(0))?;
        if active {
            return Err("Rollout target already has active maintenance".into());
        }
        Ok(())
    }
    pub fn propose_endpoint_rollout(
        &self,
        request: RolloutRequest,
        release: &SignedRelease,
        public_key: &str,
        now: u64,
    ) -> LabResult<String> {
        self.propose_component_rollout(request, release, public_key, Component::Agent, now)
    }
    pub fn propose_component_rollout(
        &self,
        request: RolloutRequest,
        release: &SignedRelease,
        public_key: &str,
        component: Component,
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
        self.expire_updates(now)?;
        let count: u64 =
            tx.query_row("SELECT count(*) FROM endpoint_rollouts", [], |r| r.get(0))?;
        let active: u64 = tx.query_row(
            &format!("SELECT count(*) FROM endpoint_rollouts WHERE state IN({ACTIVE})"),
            [],
            |r| r.get(0),
        )?;
        let deployments: u64 =
            tx.query_row("SELECT count(*) FROM endpoint_deployments", [], |r| {
                r.get(0)
            })?;
        if count >= 32
            || active >= 8
            || deployments + self.reserved_rollout_slots()? + request.endpoint_ids.len() as u64
                > 2048
        {
            return Err("Rollout or retained deployment capacity reached".into());
        }
        let mut gates = Vec::new();
        let mut agent_identities = Vec::new();
        for endpoint in &request.endpoint_ids {
            self.ensure_endpoint_unreserved(endpoint)?;
            let (_, health) = self.rollout_device(endpoint)?;
            if component == Component::Controller {
                agent_identities.push(AgentIdentity::observed(&health));
            }
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
        let plan = RolloutPlan {
            component,
            agent_identities,
            request,
            release: release.clone(),
            public_key: public_key.into(),
            gates,
            created_ms: now,
        };
        for index in 0..plan.request.endpoint_ids.len() {
            self.rollout_target_ready(&plan, index, now)?;
        }
        let raw = serde_json::to_string(&plan)?;
        let id = secret()?;
        tx.execute("INSERT INTO endpoint_rollouts(id,plan,plan_hash,state,updated_ms) VALUES(?1,?2,?3,'pending',?4)",params![id,raw,protocol::hash(raw.as_bytes()),now])?;
        for (position, endpoint) in plan.request.endpoint_ids.iter().enumerate() {
            let cohort = if position < plan.request.canary_count {
                0
            } else {
                1 + (position - plan.request.canary_count) / plan.request.batch_size
            };
            tx.execute("INSERT INTO endpoint_rollout_members(rollout_id,position,endpoint_id,cohort) VALUES(?1,?2,?3,?4)",params![id,position,endpoint,cohort])?;
        }
        self.audit("endpoint.rollout_proposed", &id, now)?;
        tx.commit()?;
        Ok(id)
    }
    pub fn endpoint_rollouts(&self) -> LabResult<Vec<RolloutRecord>> {
        let ids = self
            .connection
            .prepare("SELECT id FROM endpoint_rollouts ORDER BY rowid DESC LIMIT 32")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.endpoint_rollout(id)).collect()
    }
    pub fn endpoint_rollout(&self, id: &str) -> LabResult<RolloutRecord> {
        let (raw, hash, state, reason, updated): (String, String, String, String, u64) =
            self.connection.query_row(
                "SELECT plan,plan_hash,state,reason,updated_ms FROM endpoint_rollouts WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        if protocol::hash(raw.as_bytes()) != hash {
            return Err("Rollout approval content changed".into());
        }
        let members=self.connection.prepare("SELECT m.endpoint_id,m.cohort,m.deployment_id,d.state,m.healthy_since_ms,m.last_healthy_ms,d.installation_received_ms FROM endpoint_rollout_members m LEFT JOIN endpoint_deployments d ON d.id=m.deployment_id WHERE m.rollout_id=?1 ORDER BY m.position")?.query_map([id],|r|Ok(RolloutMember{endpoint_id:r.get(0)?,cohort:r.get(1)?,deployment_id:r.get(2)?,deployment_state:r.get(3)?,healthy_since_ms:r.get(4)?,last_healthy_ms:r.get(5)?,installation_received_ms:r.get(6)?}))?.collect::<Result<Vec<_>,_>>()?;
        let plan: RolloutPlan = serde_json::from_str(&raw)?;
        if members.len() != plan.request.endpoint_ids.len()
            || members
                .iter()
                .zip(&plan.request.endpoint_ids)
                .any(|(m, id)| &m.endpoint_id != id)
            || plan.gates.len() != members.len()
            || (plan.component == Component::Controller
                && plan.agent_identities.len() != members.len())
            || (plan.component == Component::Agent && !plan.agent_identities.is_empty())
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
        Ok(RolloutRecord {
            id: id.into(),
            plan,
            plan_hash: hash,
            state,
            reason,
            updated_ms: updated,
            members,
        })
    }
    fn stop_rollout(&self, id: &str, state: &str, reason: &str, now: u64) -> LabResult<()> {
        self.connection.execute("UPDATE endpoint_deployments SET state='cancelled' WHERE id IN(SELECT deployment_id FROM endpoint_rollout_members WHERE rollout_id=?1) AND state IN('pending','approved','ready_to_install')",[id])?;
        self.connection.execute(
            "UPDATE endpoint_rollouts SET state=?1,reason=?2,updated_ms=?3 WHERE id=?4",
            params![state, reason.chars().take(256).collect::<String>(), now, id],
        )?;
        self.audit(
            "endpoint.rollout_stopped",
            &format!(
                "{id}: {state}: {}",
                reason.chars().take(128).collect::<String>()
            ),
            now,
        )?;
        Ok(())
    }
    pub fn review_endpoint_rollout(
        &self,
        id: &str,
        hash: &str,
        action: &str,
        now: u64,
    ) -> LabResult<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = self.endpoint_rollout(id)?;
        if record.plan_hash != hash {
            return Err("Approval does not match the immutable rollout plan".into());
        }
        match action {
            "cancel"
                if ["pending", "scheduled", "running", "paused"]
                    .contains(&record.state.as_str()) =>
            {
                self.stop_rollout(
                    id,
                    "cancelled",
                    "Cancelled by operator; started installations must finish or recover",
                    now,
                )?
            }
            "pause" if ["scheduled", "running"].contains(&record.state.as_str()) => {
                self.connection.execute("UPDATE endpoint_rollouts SET state='paused',reason='Paused by operator; started installations may finish',updated_ms=?1 WHERE id=?2",params![now,id])?;
                self.connection.execute("UPDATE endpoint_rollout_members SET healthy_since_ms=NULL,last_healthy_ms=NULL WHERE rollout_id=?1",[id])?;
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
                    self.rollout_target_ready(&record.plan, index, now)?;
                }
                self.connection.execute("UPDATE endpoint_rollouts SET state='scheduled',reason='',updated_ms=?1 WHERE id=?2",params![now,id])?;
            }
            "resume" if record.state == "paused" => {
                if now >= record.plan.request.deadline_ms {
                    return Err("Rollout window expired; cancel this plan".into());
                }
                self.connection.execute("UPDATE endpoint_rollouts SET state='running',reason='',updated_ms=?1 WHERE id=?2",params![now,id])?;
            }
            _ => return Err("Rollout action does not match its current state".into()),
        }
        self.audit(
            "endpoint.rollout_reviewed",
            &format!("{id}: {action}: {hash}"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn observe_rollout_endpoint(
        &self,
        endpoint: &str,
        health: &Heartbeat,
        now: u64,
    ) -> LabResult<()> {
        let rows=self.connection.prepare("SELECT m.rollout_id,m.position FROM endpoint_rollout_members m JOIN endpoint_rollouts r ON r.id=m.rollout_id WHERE m.endpoint_id=?1 AND r.state='running' AND m.deployment_id IS NOT NULL")?.query_map([endpoint],|r|Ok((r.get::<_,String>(0)?,r.get::<_,usize>(1)?)))?.collect::<Result<Vec<_>,_>>()?;
        for (id, index) in rows {
            let record = self.endpoint_rollout(&id)?;
            let member = &record.members[index];
            if member.deployment_state.as_deref() == Some("installed")
                && installed_health(&record.plan, index, health, now)
            {
                let since = if member
                    .last_healthy_ms
                    .is_some_and(|last| last <= now && now - last <= FRESH_MS)
                {
                    member.healthy_since_ms.unwrap_or(now)
                } else {
                    now
                };
                self.connection.execute("UPDATE endpoint_rollout_members SET healthy_since_ms=?1,last_healthy_ms=?2 WHERE rollout_id=?3 AND position=?4",params![since,now,id,index])?;
            } else {
                self.connection.execute("UPDATE endpoint_rollout_members SET healthy_since_ms=NULL,last_healthy_ms=NULL WHERE rollout_id=?1 AND position=?2",params![id,index])?;
                if member.deployment_state.as_deref() == Some("installed") {
                    self.stop_rollout(
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
    pub fn tick_endpoint_rollouts(&self, now: u64) -> LabResult<()> {
        let ids = self
            .connection
            .prepare(&format!(
                "SELECT id FROM endpoint_rollouts WHERE state IN({ACTIVE}) ORDER BY rowid"
            ))?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for id in ids {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            match self.advance_rollout(&id, now) {
                Ok(()) => tx.commit()?,
                Err(error) => {
                    tx.rollback()?;
                    let tx = Transaction::new_unchecked(
                        &self.connection,
                        TransactionBehavior::Immediate,
                    )?;
                    self.stop_rollout(&id, "failed", &error.to_string(), now)?;
                    tx.commit()?;
                }
            }
        }
        Ok(())
    }
    fn advance_rollout(&self, id: &str, now: u64) -> LabResult<()> {
        self.expire_updates(now)?;
        let record = self.endpoint_rollout(id)?;
        let request = &record.plan.request;
        if now >= request.deadline_ms {
            return self.stop_rollout(
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
            let (seen, health) = self.rollout_device(&member.endpoint_id)?;
            match member.deployment_state.as_deref() {
                Some("approved" | "ready_to_install" | "installing") => waiting = true,
                Some("installed") => {
                    if member.healthy_since_ms.is_none()
                        && member
                            .installation_received_ms
                            .is_some_and(|received| now >= received && now - received < FRESH_MS)
                    {
                        waiting = true;
                        continue;
                    }
                    if !fresh(seen, now) || !installed_health(&record.plan, index, &health, now) {
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
            self.connection.execute("UPDATE endpoint_rollouts SET state='completed',reason='Every device completed installation and the required health window',updated_ms=?1 WHERE id=?2",params![now,id])?;
            self.audit("endpoint.rollout_completed", id, now)?;
            return Ok(());
        };
        let indexes = record
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.cohort == cohort && m.deployment_id.is_none())
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let active:u64=self.connection.query_row("SELECT count(*) FROM endpoint_deployments WHERE state IN('pending','approved','ready_to_install','installing')",[],|r|r.get(0))?;
        if active + indexes.len() as u64 > 128 {
            return Ok(());
        }
        for &index in &indexes {
            self.rollout_target_ready(&record.plan, index, now)?;
        }
        self.connection.execute(
            "UPDATE endpoint_rollouts SET state='running',reason='',updated_ms=?1 WHERE id=?2",
            params![now, id],
        )?;
        for index in indexes {
            let deployment = self.insert_component_release(
                &request.endpoint_ids[index],
                &record.plan.release,
                &record.plan.public_key,
                true,
                (record.plan.component, Some(request.deadline_ms)),
                now,
            )?;
            self.connection.execute("UPDATE endpoint_rollout_members SET deployment_id=?1 WHERE rollout_id=?2 AND position=?3",params![deployment,id,index])?;
        }
        self.audit(
            "endpoint.rollout_cohort",
            &format!("{id}: group {}", cohort + 1),
            now,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod native_coverage_tests {
    use super::*;
    use athernex_endpoint_protocol::{
        process_events::ProcessEventHealth, telemetry::CollectorHealth,
    };
    #[test]
    fn approved_native_coverage_cannot_disappear_or_hide_loss_and_legacy_hashes_remain_stable() {
        let now = 1_800_000_000_000;
        let legacy = HealthGate {
            protection_fingerprint: None,
            collector: true,
            signatures: false,
            process_events: false,
            windows_process_events: false,
            authentication: false,
            windows_authentication: false,
            network_events: false,
        };
        assert_eq!(
            serde_json::to_string(&legacy).unwrap(),
            r#"{"protection_fingerprint":null,"collector":true,"signatures":false}"#
        );
        let gate = HealthGate {
            process_events: true,
            ..legacy.clone()
        };
        let mut health = Heartbeat {
            updates: None,
            controller_updates: None,
            protection: None,
            collector: Some(CollectorHealth {
                mode: "snapshot".into(),
                last_success_ms: now,
                last_attempt_ms: now,
                process_events: Some(ProcessEventHealth {
                    boot_id: "a".repeat(64),
                    stream_id: "b".repeat(64),
                    state: "active".into(),
                    started_ms: now,
                    checked_ms: now,
                    received_events: 12,
                    dropped_events: 0,
                    loss_signals: 0,
                    subscriptions: 1,
                    error: String::new(),
                }),
                ..Default::default()
            }),
            version: "fixture".into(),
            capabilities: vec![],
            scanner: String::new(),
            realtime: false,
            signature_version: String::new(),
            spool_events: 0,
            error: String::new(),
        };
        assert!(healthy(&health, &gate, now));
        let events = health
            .collector
            .as_mut()
            .unwrap()
            .process_events
            .take()
            .unwrap();
        assert!(!healthy(&health, &gate, now));
        assert!(healthy(&health, &legacy, now));
        health.collector.as_mut().unwrap().process_events = Some(events.clone());
        health
            .collector
            .as_mut()
            .unwrap()
            .process_events
            .as_mut()
            .unwrap()
            .loss_signals = 1;
        assert!(!healthy(&health, &gate, now));
        assert!(!healthy(&health, &legacy, now));
        health.collector.as_mut().unwrap().process_events = Some(events.clone());
        assert!(!healthy(&health, &gate, now + 30_001));
        health
            .collector
            .as_mut()
            .unwrap()
            .process_events
            .as_mut()
            .unwrap()
            .state = "stopped".into();
        assert!(!healthy(&health, &gate, now));
        health.collector.as_mut().unwrap().process_events = None;
        let network_gate = HealthGate {
            network_events: true,
            ..legacy.clone()
        };
        let network = protocol::network_events::NetworkEventHealth {
            boot_id: "a".repeat(64),
            stream_id: "b".repeat(64),
            namespace: 42,
            families: vec![4, 6],
            state: "active".into(),
            started_ms: now,
            checked_ms: now,
            source_checked_ms: now,
            received_events: 10,
            skipped_protocols: 0,
            dropped_events: 0,
            loss_signals: 0,
            subscriptions: 1,
            error: String::new(),
        };
        assert!(!healthy(&health, &network_gate, now));
        health.collector.as_mut().unwrap().network_events = Some(network.clone());
        assert!(healthy(&health, &network_gate, now));
        for degraded in [
            protocol::network_events::NetworkEventHealth {
                source_checked_ms: now - 15_001,
                ..network.clone()
            },
            protocol::network_events::NetworkEventHealth {
                loss_signals: 1,
                ..network.clone()
            },
            protocol::network_events::NetworkEventHealth {
                families: vec![],
                ..network.clone()
            },
            protocol::network_events::NetworkEventHealth {
                dropped_events: 1,
                ..network
            },
        ] {
            health.collector.as_mut().unwrap().network_events = Some(degraded);
            assert!(!healthy(&health, &network_gate, now));
            assert!(!healthy(&health, &legacy, now));
        }
        health.collector.as_mut().unwrap().network_events = None;
        let gate = HealthGate {
            authentication: true,
            ..legacy.clone()
        };
        let auth = athernex_endpoint_protocol::authentication::AuthenticationHealth {
            state: "active".into(),
            started_ms: now,
            checked_ms: now,
            caught_up: true,
            ..Default::default()
        };
        health.collector.as_mut().unwrap().authentication = Some(auth.clone());
        assert!(healthy(&health, &gate, now));
        health.collector.as_mut().unwrap().authentication = None;
        assert!(!healthy(&health, &gate, now));
        assert!(healthy(&health, &legacy, now));
        for degraded in [
            athernex_endpoint_protocol::authentication::AuthenticationHealth {
                backpressure: true,
                ..auth.clone()
            },
            athernex_endpoint_protocol::authentication::AuthenticationHealth {
                loss_signals: 1,
                ..auth.clone()
            },
            athernex_endpoint_protocol::authentication::AuthenticationHealth {
                caught_up: false,
                ..auth
            },
        ] {
            health.collector.as_mut().unwrap().authentication = Some(degraded);
            assert!(!healthy(&health, &gate, now));
            assert!(!healthy(&health, &legacy, now));
        }
        health.collector.as_mut().unwrap().authentication = None;
        let windows_gate = HealthGate {
            windows_authentication: true,
            ..legacy.clone()
        };
        let windows = protocol::authentication::AuthenticationHealth {
            state: "active".into(),
            started_ms: now,
            checked_ms: now,
            caught_up: true,
            ..Default::default()
        };
        // A different platform's healthy source cannot replace the pinned one.
        health.collector.as_mut().unwrap().authentication = Some(windows.clone());
        assert!(!healthy(&health, &windows_gate, now));
        health.collector.as_mut().unwrap().authentication = None;
        health.collector.as_mut().unwrap().windows_authentication = Some(windows.clone());
        assert!(healthy(&health, &windows_gate, now));
        assert!(!healthy(&health, &windows_gate, now + 30_001));
        health.collector.as_mut().unwrap().windows_authentication = None;
        assert!(!healthy(&health, &windows_gate, now));
        for degraded in [
            protocol::authentication::AuthenticationHealth {
                backpressure: true,
                ..windows.clone()
            },
            protocol::authentication::AuthenticationHealth {
                loss_signals: 1,
                ..windows.clone()
            },
            protocol::authentication::AuthenticationHealth {
                rejected_records: 1,
                received_records: 1,
                ..windows.clone()
            },
            protocol::authentication::AuthenticationHealth {
                error: "Logon auditing policy is unavailable".into(),
                ..windows.clone()
            },
            protocol::authentication::AuthenticationHealth {
                caught_up: false,
                ..windows
            },
        ] {
            health.collector.as_mut().unwrap().windows_authentication = Some(degraded);
            assert!(!healthy(&health, &windows_gate, now));
            assert!(!healthy(&health, &legacy, now));
        }
    }

    #[test]
    fn windows_process_coverage_is_separate_and_restored_gaps_remain_unhealthy() {
        use protocol::windows_process_events::WindowsProcessEventHealth;
        let now = 1_800_000_000_000;
        let legacy: HealthGate = serde_json::from_str(
            r#"{"protection_fingerprint":null,"collector":true,"signatures":false}"#,
        )
        .unwrap();
        assert!(!legacy.windows_process_events);
        assert_eq!(
            serde_json::to_string(&legacy).unwrap(),
            r#"{"protection_fingerprint":null,"collector":true,"signatures":false}"#
        );
        let gate = HealthGate {
            windows_process_events: true,
            ..legacy.clone()
        };
        let mut health = Heartbeat {
            version: "fixture".into(),
            capabilities: vec![],
            scanner: String::new(),
            realtime: false,
            signature_version: String::new(),
            spool_events: 0,
            error: String::new(),
            protection: None,
            updates: None,
            controller_updates: None,
            collector: Some(CollectorHealth {
                mode: "snapshot".into(),
                last_attempt_ms: now,
                last_success_ms: now,
                process_events: Some(ProcessEventHealth {
                    boot_id: "a".repeat(64),
                    stream_id: "b".repeat(64),
                    state: "active".into(),
                    started_ms: now,
                    checked_ms: now,
                    subscriptions: 1,
                    received_events: 0,
                    dropped_events: 0,
                    loss_signals: 0,
                    error: String::new(),
                }),
                ..Default::default()
            }),
        };
        assert!(healthy(&health, &legacy, now));
        assert!(!healthy(&health, &gate, now));
        let windows = WindowsProcessEventHealth {
            stream_id: "c".repeat(64),
            state: "active".into(),
            started_ms: now - 60_000,
            checked_ms: now,
            subscriptions: 1,
            ..Default::default()
        };
        health.collector.as_mut().unwrap().windows_process_events = Some(windows.clone());
        assert!(healthy(&health, &gate, now));
        for failure in 0..10 {
            let mut degraded = windows.clone();
            match failure {
                0 => degraded.checked_ms = now - 30_001,
                1 => degraded.callback_drops = 1,
                2 => degraded.queue_drops = 1,
                3 => degraded.events_lost = 1,
                4 => degraded.log_buffers_lost = 1,
                5 => degraded.realtime_buffers_lost = 1,
                6 => {
                    degraded.received_records = 1;
                    degraded.rejected_records = 1;
                }
                7 => degraded.backpressured = true,
                8 => degraded.error = "Source unavailable".into(),
                _ => {
                    // A new active subscription cannot erase an earlier gap.
                    degraded.subscriptions = 2;
                    degraded.loss_signals = 1;
                    degraded.error.clear();
                }
            }
            health.collector.as_mut().unwrap().windows_process_events = Some(degraded);
            assert!(
                !healthy(&health, &gate, now),
                "Windows source failure {failure}"
            );
            assert!(
                !healthy(&health, &legacy, now),
                "Reported unhealthy source {failure}"
            );
        }
    }
}
