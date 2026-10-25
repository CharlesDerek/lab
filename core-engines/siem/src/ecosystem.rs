//! Evidence-bound security response and shared scheduling admission.
use crate::{
    engine::{Engine, LabResult},
    gateway::digest,
};
use athernex_endpoint_protocol::{Action, Heartbeat, Receipt};
use orchestrator::governor::{self, Class, Request, Reservation, Resources};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncidentRequest {
    pub id: String,
    pub endpoint: String,
    pub evidence_id: u64,
    pub replacement_pool: String,
    pub resources: Resources,
    pub expires_ms: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct IncidentPlan {
    pub request: IncidentRequest,
    pub affected_pool: String,
    pub case_id: i64,
    pub command_id: String,
    pub evidence_hash: String,
    pub require_realtime: bool,
}
#[derive(Serialize)]
pub struct Incident {
    pub plan: IncidentPlan,
    pub plan_hash: String,
    pub state: String,
    pub approved_by: Option<String>,
    pub response_state: String,
    pub receipt: Option<Receipt>,
    pub reservation: Option<Reservation>,
}
impl Engine {
    pub(crate) fn init_ecosystem(&self) -> LabResult<()> {
        governor::initialize(&self.connection)?;
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS endpoint_pools(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),pool TEXT UNIQUE NOT NULL REFERENCES resource_pools(name));
          CREATE TABLE IF NOT EXISTS security_incidents(id TEXT PRIMARY KEY,plan TEXT NOT NULL,plan_hash TEXT NOT NULL,state TEXT NOT NULL,command_id TEXT UNIQUE NOT NULL REFERENCES endpoint_commands(id),approved_by TEXT,created_ms INTEGER NOT NULL,updated_ms INTEGER NOT NULL);")?;
        Ok(())
    }
    pub fn configure_pool(
        &self,
        pool: &str,
        capacity: Resources,
        reserve: Resources,
        now: u64,
    ) -> LabResult<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        governor::configure(&tx, pool, capacity, reserve)?;
        self.audit("capacity.configured", pool, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn resource_pools(&self) -> LabResult<Vec<governor::Pool>> {
        governor::pools(&self.connection)
    }
    pub fn reserve_resources(&self, request: &Request, now: u64) -> LabResult<Reservation> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let reservation = governor::reserve(&tx, request, now)?;
        self.audit("capacity.reserved", &request.id, now)?;
        tx.commit()?;
        Ok(reservation)
    }
    pub fn authorize_reservation(
        &self,
        id: &str,
        generation: u64,
        now: u64,
    ) -> LabResult<Reservation> {
        governor::authorize(&self.connection, id, generation, now)
    }
    pub fn release_resources(&self, id: &str, generation: u64, now: u64) -> LabResult<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        governor::release(&tx, id, generation)?;
        self.audit("capacity.released", id, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn bind_endpoint_pool(&self, endpoint: &str, pool: &str, now: u64) -> LabResult<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM endpoints WHERE id=?1 AND state='active')",
            [endpoint],
            |r| r.get(0),
        )?;
        if !active {
            return Err("Active endpoint required".into());
        }
        tx.execute(
            "INSERT OR IGNORE INTO endpoint_pools VALUES(?1,?2)",
            params![endpoint, pool],
        )?;
        let bound: String = tx.query_row(
            "SELECT pool FROM endpoint_pools WHERE endpoint=?1",
            [endpoint],
            |r| r.get(0),
        )?;
        if bound != pool {
            return Err("Endpoint pool binding is immutable".into());
        }
        self.audit("capacity.endpoint_bound", endpoint, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn incident(&self, id: &str) -> LabResult<Incident> {
        let (raw,plan_hash,state,approved_by,response_state,receipt):(String,String,String,Option<String>,String,Option<String>)=self.connection.query_row("SELECT i.plan,i.plan_hash,i.state,i.approved_by,c.state,c.receipt FROM security_incidents i JOIN endpoint_commands c ON c.id=i.command_id WHERE i.id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        if digest(&raw) != plan_hash {
            return Err("Incident plan integrity failed".into());
        }
        Ok(Incident {
            plan: serde_json::from_str(&raw)?,
            plan_hash,
            state,
            approved_by,
            response_state,
            receipt: receipt.map(|v| serde_json::from_str(&v)).transpose()?,
            reservation: governor::lookup(&self.connection, &format!("incident:{id}"))?,
        })
    }
    pub fn incidents(&self) -> LabResult<Vec<Incident>> {
        let ids = self
            .connection
            .prepare("SELECT id FROM security_incidents ORDER BY created_ms DESC LIMIT 256")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter().map(|id| self.incident(id)).collect()
    }
    pub fn propose_incident(&self, request: &IncidentRequest, now: u64) -> LabResult<Incident> {
        if !governor::label(&request.id)
            || request.id.len() > 100
            || request.expires_ms <= now
            || request.expires_ms > now.saturating_add(900_000).min(i64::MAX as u64)
        {
            return Err("Invalid incident identity or deadline".into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM security_incidents WHERE id=?1)",
            [&request.id],
            |r| r.get(0),
        )?;
        if exists {
            let previous = self.incident(&request.id)?;
            if previous.plan.request != *request {
                return Err("Incident identity reused with different work".into());
            }
            return Ok(previous);
        }
        let assigned:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM security_incidents WHERE json_extract(plan,'$.request.endpoint')=?1 AND json_extract(plan,'$.request.evidence_id')=?2)",params![request.endpoint,request.evidence_id],|r|r.get(0))?;
        if assigned {
            return Err(
                "This malware evidence is already bound to an incident; review its existing plan"
                    .into(),
            );
        }
        let count: u64 =
            tx.query_row("SELECT count(*) FROM security_incidents", [], |r| r.get(0))?;
        if count >= 4096 {
            return Err("Incident history capacity reached".into());
        }
        let affected_pool: String = tx.query_row(
            "SELECT pool FROM endpoint_pools WHERE endpoint=?1",
            [&request.endpoint],
            |r| r.get(0),
        )?;
        if affected_pool == request.replacement_pool {
            return Err("Replacement capacity must be independent of the affected pool".into());
        }
        let observation = self
            .endpoint_observation(request.evidence_id)?
            .ok_or("Endpoint evidence unavailable")?;
        let owner:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM all_endpoint_events WHERE endpoint_id=?1 AND evidence_id=?2)",params![request.endpoint,request.evidence_id],|r|r.get(0))?;
        if !owner || observation.event.kind != "malware" {
            return Err("Exact endpoint malware evidence required".into());
        }
        let case_id = observation
            .case_id
            .ok_or("Malware evidence has no investigation")?;
        let evidence_hash = crate::memory::hex(&self.evidence_hash(request.evidence_id)?);
        let health: String = tx.query_row(
            "SELECT health FROM endpoints WHERE id=?1",
            [&request.endpoint],
            |r| r.get(0),
        )?;
        let health: Heartbeat = serde_json::from_str(&health)?;
        let command_id = self.queue_endpoint_action_in_transaction(
            &request.endpoint,
            Action::Quarantine {
                path: observation.event.path,
                sha256: observation.event.sha256,
            },
            case_id,
            now,
        )?;
        let mut command: athernex_endpoint_protocol::Command =
            serde_json::from_str(&tx.query_row(
                "SELECT payload FROM endpoint_commands WHERE id=?1",
                [&command_id],
                |r| r.get::<_, String>(0),
            )?)?;
        command.expires_ms = request.expires_ms;
        tx.execute(
            "UPDATE endpoint_commands SET payload=?2,expires_ms=?3 WHERE id=?1",
            params![
                command_id,
                serde_json::to_string(&command)?,
                request.expires_ms
            ],
        )?;
        let plan = IncidentPlan {
            request: request.clone(),
            affected_pool,
            case_id,
            command_id: command_id.clone(),
            evidence_hash,
            require_realtime: health.realtime,
        };
        let raw = serde_json::to_string(&plan)?;
        tx.execute(
            "INSERT INTO security_incidents VALUES(?1,?2,?3,'pending',?4,NULL,?5,?5)",
            params![request.id, raw, digest(&raw), command_id, now],
        )?;
        self.audit("incident.proposed", &request.id, now)?;
        tx.commit()?;
        self.incident(&request.id)
    }
    pub fn approve_incident(
        &self,
        id: &str,
        plan_hash: &str,
        actor: &str,
        now: u64,
    ) -> LabResult<Incident> {
        if !governor::label(actor) {
            return Err("Named operator required".into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let current = self.incident(id)?;
        if current.plan_hash != plan_hash || current.plan.request.expires_ms <= now {
            return Err("Incident approval is stale or mismatched".into());
        }
        if current.state == "approved" {
            return Ok(current);
        }
        if current.state != "pending" {
            return Err("Incident is no longer reviewable".into());
        }
        if crate::memory::hex(&self.evidence_hash(current.plan.request.evidence_id)?)
            != current.plan.evidence_hash
        {
            return Err("Incident evidence changed".into());
        }
        governor::hold(&tx, &current.plan.affected_pool, id, now)?;
        governor::reserve(
            &tx,
            &Request {
                id: format!("incident:{id}"),
                pool: current.plan.request.replacement_pool.clone(),
                class: Class::Response,
                resources: current.plan.request.resources,
                expires_ms: current.plan.request.expires_ms,
            },
            now,
        )?;
        self.review_endpoint_action_in_transaction(&current.plan.command_id, true, now)?;
        tx.execute("UPDATE security_incidents SET state='approved',approved_by=?2,updated_ms=?3 WHERE id=?1",params![id,actor,now])?;
        self.audit("incident.approved", &format!("{id} by {actor}"), now)?;
        tx.commit()?;
        self.incident(id)
    }
    pub(crate) fn incident_dispatch_allowed(&self, command: &str, now: u64) -> LabResult<()> {
        let id: Option<String> = self
            .connection
            .query_row(
                "SELECT id FROM security_incidents WHERE command_id=?1",
                [command],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = id {
            let incident = self.incident(&id)?;
            if incident.state != "approved" {
                return Err("Incident is not approved".into());
            }
            let reservation = incident
                .reservation
                .ok_or("Replacement capacity is missing")?;
            governor::authorize(
                &self.connection,
                &reservation.request.id,
                reservation.generation,
                now,
            )?;
        }
        Ok(())
    }
    pub fn recover_incident(
        &self,
        id: &str,
        plan_hash: &str,
        actor: &str,
        note: &str,
        now: u64,
    ) -> LabResult<Incident> {
        if !governor::label(actor) || note.trim().is_empty() || note.len() > 1000 {
            return Err("Recovery requires a named operator and bounded verification note".into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let incident = self.incident(id)?;
        if incident.plan_hash != plan_hash {
            return Err("Recovery plan mismatch".into());
        }
        if incident.state == "recovered" {
            return Ok(incident);
        }
        let receipt = incident
            .receipt
            .as_ref()
            .ok_or("Endpoint execution receipt required")?;
        if incident.state != "approved" || receipt.outcome != "succeeded" {
            return Err("Successful reviewed response is required".into());
        }
        let (seen, raw): (u64, String) = tx.query_row(
            "SELECT last_seen_ms,health FROM endpoints WHERE id=?1 AND state='active'",
            [&incident.plan.request.endpoint],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let health: Heartbeat = serde_json::from_str(&raw)?;
        if seen <= receipt.finished_ms
            || seen > now
            || now.saturating_sub(seen) > 120_000
            || !health.error.is_empty()
            || (incident.plan.require_realtime
                && (!health.realtime
                    || !health.protection.as_ref().is_some_and(|p| {
                        p.state == "active"
                            && p.error.is_empty()
                            && p.dropped_events == 0
                            && p.checked_ms <= now
                            && now.saturating_sub(p.checked_ms) <= 120_000
                    })))
        {
            return Err("Fresh post-response endpoint health is required".into());
        }
        let notes: u64 = tx.query_row(
            "SELECT count(*) FROM case_notes WHERE case_id=?1",
            [incident.plan.case_id],
            |r| r.get(0),
        )?;
        if notes >= 64 {
            return Err("Investigation note capacity reached".into());
        }
        governor::clear_hold(&tx, &incident.plan.affected_pool, id)?;
        tx.execute(
            "UPDATE security_incidents SET state='recovered',updated_ms=?2 WHERE id=?1",
            params![id, now],
        )?;
        tx.execute(
            "INSERT INTO case_notes(case_id,time_ms,text) VALUES(?1,?2,?3)",
            params![
                incident.plan.case_id,
                now,
                format!("Incident {id}: placement restored by {actor}. Verification: {note}")
            ],
        )?;
        tx.execute(
            "UPDATE cases SET version=version+1,updated_ms=?2 WHERE id=?1",
            params![incident.plan.case_id, now],
        )?;
        self.audit("incident.recovered", &format!("{id} by {actor}"), now)?;
        tx.commit()?;
        self.incident(id)
    }
}
