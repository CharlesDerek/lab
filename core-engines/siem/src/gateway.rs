//! Task-bound capabilities. Possession of a grant authorizes only this gateway,
//! never the operator console, host filesystem, or a downstream tool by itself.
use crate::{
    engine::{Engine, LabResult},
    model::*,
};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const RESOURCES: &[(&str, &str, &str)] = &[
    ("evidence", "read", "Normalized finding summaries"),
    ("rules", "read", "Detection contracts"),
    ("archive", "read", "Archive capacity and block inventory"),
    ("lab-note", "append", "Bounded synthetic agent notebook"),
];
pub fn secret() -> LabResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("Entropy unavailable: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
pub fn same_secret(a: &str, b: &str) -> bool {
    let x = Sha256::digest(a.as_bytes());
    let y = Sha256::digest(b.as_bytes());
    x.iter().zip(y).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
}

#[derive(Debug, Serialize)]
pub struct Hive {
    pub agents: Vec<Agent>,
    pub tasks: Vec<Task>,
    pub grants: Vec<Grant>,
    pub decisions: Vec<Decision>,
    pub notes: Vec<Note>,
}
#[derive(Debug, Serialize)]
pub struct Agent {
    pub id: i64,
    pub name: String,
    pub role: String,
    pub state: String,
    pub created_ms: u64,
}
#[derive(Debug, Serialize)]
pub struct Task {
    pub id: i64,
    pub agent_id: i64,
    pub title: String,
    pub resource: String,
    pub action: String,
    pub state: String,
    pub created_ms: u64,
    pub expires_ms: u64,
}
#[derive(Debug, Serialize)]
pub struct Grant {
    pub id: i64,
    pub task_id: i64,
    pub agent_id: i64,
    pub resource: String,
    pub action: String,
    pub state: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub uses: u64,
    pub max_uses: u64,
}
#[derive(Debug, Serialize)]
pub struct Decision {
    pub id: i64,
    pub time_ms: u64,
    pub agent_id: Option<i64>,
    pub task_id: Option<i64>,
    pub grant_id: Option<i64>,
    pub resource: String,
    pub action: String,
    pub allowed: bool,
    pub reason: String,
}
#[derive(Debug, Serialize)]
pub struct Note {
    pub id: i64,
    pub agent_id: i64,
    pub text: String,
    pub time_ms: u64,
}
#[derive(Debug, Serialize)]
pub struct IssuedGrant {
    pub id: i64,
    pub token: String,
    pub expires_ms: u64,
}

impl Engine {
    pub(crate) fn init_gateway(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE NOT NULL,role TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'active',created_ms INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS agent_tasks(id INTEGER PRIMARY KEY AUTOINCREMENT,agent_id INTEGER NOT NULL REFERENCES agents(id),title TEXT NOT NULL,resource TEXT NOT NULL,action TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'active',created_ms INTEGER NOT NULL,expires_ms INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS grants(id INTEGER PRIMARY KEY AUTOINCREMENT,task_id INTEGER NOT NULL REFERENCES agent_tasks(id),token_hash TEXT UNIQUE NOT NULL,state TEXT NOT NULL DEFAULT 'active',created_ms INTEGER NOT NULL,expires_ms INTEGER NOT NULL,uses INTEGER NOT NULL DEFAULT 0,max_uses INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS access_decisions(id INTEGER PRIMARY KEY AUTOINCREMENT,time_ms INTEGER NOT NULL,agent_id INTEGER,task_id INTEGER,grant_id INTEGER,resource TEXT NOT NULL,action TEXT NOT NULL,allowed INTEGER NOT NULL,reason TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS agent_decision_time ON access_decisions(agent_id,time_ms);
        CREATE TABLE IF NOT EXISTS agent_notes(id INTEGER PRIMARY KEY AUTOINCREMENT,agent_id INTEGER NOT NULL,text TEXT NOT NULL,time_ms INTEGER NOT NULL);")?;
        Ok(())
    }
    pub fn register_agent(&self, name: &str, role: &str, now: u64) -> LabResult<i64> {
        if name.is_empty()
            || name.len() > 48
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || role.is_empty()
            || role.len() > 96
            || role.chars().any(char::is_control)
        {
            return Err(
                "Agent names use 1–48 letters, digits or hyphens; role is 1–96 printable bytes."
                    .into(),
            );
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let count: u64 = tx.query_row("SELECT count(*) FROM agents", [], |r| r.get(0))?;
        if count >= 32 {
            return Err("Hive budget is 32 identities.".into());
        }
        tx.execute(
            "INSERT INTO agents(name,role,created_ms) VALUES (?1,?2,?3)",
            params![name, role, now],
        )?;
        let id = tx.last_insert_rowid();
        self.audit("agent.registered", name, now)?;
        tx.commit()?;
        Ok(id)
    }
    pub fn create_task(
        &self,
        agent: i64,
        title: &str,
        resource: &str,
        minutes: u64,
        now: u64,
    ) -> LabResult<i64> {
        let action = if let Some((_, action, _)) = RESOURCES.iter().find(|r| r.0 == resource) {
            *action
        } else if let Some(id) = resource
            .strip_prefix("finding-")
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|id| *id > 0)
        {
            let exists: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1)",
                [id],
                |r| r.get(0),
            )?;
            if !exists || resource != format!("finding-{id}") {
                return Err("Unknown finding resource".into());
            }
            "read"
        } else if let Some(id) = resource
            .strip_prefix("event-")
            .and_then(|v| v.parse::<u64>().ok())
        {
            if resource != format!("event-{id}") || self.evidence_hash(id).is_err() {
                return Err("Unknown evidence resource".into());
            }
            "read"
        } else {
            return Err("Unknown resource".into());
        };
        if title.trim().is_empty()
            || title.len() > 120
            || title.chars().any(char::is_control)
            || !(1..=1440).contains(&minutes)
        {
            return Err("Use a 1–120 byte task title and a 1–1440 minute deadline.".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let state: String = tx.query_row("SELECT state FROM agents WHERE id=?1", [agent], |r| {
            r.get(0)
        })?;
        if state != "active" {
            return Err("Quarantined identities cannot receive tasks.".into());
        }
        let count: u64 = tx.query_row("SELECT count(*) FROM agent_tasks", [], |r| r.get(0))?;
        if count >= 128 {
            return Err(
                "Task ledger budget reached (128); export and start another lab ledger.".into(),
            );
        }
        tx.execute("INSERT INTO agent_tasks(agent_id,title,resource,action,created_ms,expires_ms) VALUES (?1,?2,?3,?4,?5,?6)",params![agent,title,resource,action,now,now.saturating_add(minutes*60_000)])?;
        let id = tx.last_insert_rowid();
        self.audit(
            "task.created",
            &format!("task-{id} / agent-{agent} / {action}:{resource}"),
            now,
        )?;
        tx.commit()?;
        Ok(id)
    }
    pub fn issue_grant(
        &self,
        task: i64,
        seconds: u64,
        max_uses: u64,
        now: u64,
    ) -> LabResult<IssuedGrant> {
        if !(1..=3600).contains(&seconds) || !(1..=1000).contains(&max_uses) {
            return Err("Grant lifetime is 1–3600 seconds with 1–1000 uses.".into());
        }
        let token = secret()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let (state,deadline,agent_state):(String,u64,String)=tx.query_row("SELECT t.state,t.expires_ms,a.state FROM agent_tasks t JOIN agents a ON a.id=t.agent_id WHERE t.id=?1",[task],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if state != "active" || agent_state != "active" || now >= deadline {
            return Err("Task or identity is no longer eligible for access.".into());
        }
        let count: u64 = tx.query_row("SELECT count(*) FROM grants", [], |r| r.get(0))?;
        if count >= 256 {
            return Err("Grant ledger budget reached (256).".into());
        }
        let expiry = deadline.min(now.saturating_add(seconds * 1000));
        tx.execute("INSERT INTO grants(task_id,token_hash,created_ms,expires_ms,max_uses) VALUES (?1,?2,?3,?4,?5)",params![task,digest(&token),now,expiry,max_uses])?;
        let id = tx.last_insert_rowid();
        self.audit(
            "grant.issued",
            &format!("grant-{id} / task-{task} / expires {expiry}"),
            now,
        )?;
        tx.commit()?;
        Ok(IssuedGrant {
            id,
            token,
            expires_ms: expiry,
        })
    }
    pub fn set_agent_state(&self, id: i64, state: &str, now: u64) -> LabResult<()> {
        if !["active", "quarantined"].contains(&state) {
            return Err("Invalid identity transition".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if tx.execute("UPDATE agents SET state=?1 WHERE id=?2", params![state, id])? != 1 {
            return Err("Unknown identity".into());
        }
        if state == "quarantined" {
            tx.execute("UPDATE grants SET state='revoked' WHERE task_id IN (SELECT id FROM agent_tasks WHERE agent_id=?1)",[id])?;
        }
        self.audit("agent.state", &format!("agent-{id}: {state}"), now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn finish_task(&self, id: i64, now: u64) -> LabResult<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if tx.execute(
            "UPDATE agent_tasks SET state='completed' WHERE id=?1 AND state='active'",
            [id],
        )? != 1
        {
            return Err("Task is not active".into());
        }
        tx.execute("UPDATE grants SET state='revoked' WHERE task_id=?1", [id])?;
        self.audit(
            "task.completed",
            &format!("task-{id}; every associated grant revoked"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn revoke_grant(&self, id: i64, now: u64) -> LabResult<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if tx.execute("UPDATE grants SET state='revoked' WHERE id=?1", [id])? != 1 {
            return Err("Unknown grant".into());
        }
        self.audit("grant.revoked", &format!("grant-{id}"), now)?;
        tx.commit()?;
        Ok(())
    }
    /// The actual operation is selected by the server route, not a bearer claim.
    /// Consumption, durable decision, and optional note mutation share one commit.
    pub fn access(
        &mut self,
        token: &str,
        resource: &str,
        action: &str,
        note: Option<&str>,
        now: u64,
    ) -> LabResult<Decision> {
        if resource.len() > 64
            || !resource
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !["read", "append"].contains(&action)
        {
            return Err("Invalid gateway route".into());
        }
        if note.is_some_and(|n| n.is_empty() || n.len() > 256 || n.chars().any(char::is_control)) {
            return Err("Notes must contain 1–256 printable bytes.".into());
        }
        if (action == "append") != note.is_some() {
            return Err("Append requires a note; read does not accept one.".into());
        }
        // Reserve room before the authorization transaction; a full archive fails closed.
        if self.pending_count()? >= 512 {
            self.flush(now)?;
        }
        self.reserve_ids(1)?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        #[allow(clippy::type_complexity)]
        let row:Option<(i64,i64,i64,String,String,String,u64,u64,u64,String,String,u64)>=tx.query_row("SELECT g.id,t.id,a.id,g.state,t.state,a.state,g.expires_ms,g.uses,g.max_uses,t.resource,t.action,t.expires_ms FROM grants g JOIN agent_tasks t ON t.id=g.task_id JOIN agents a ON a.id=t.agent_id WHERE g.token_hash=?1",[digest(token)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?))).optional()?;
        let (mut agent_id, mut task_id, mut grant_id) = (None, None, None);
        let reason = if let Some((
            grant,
            task,
            agent,
            gs,
            ts,
            ast,
            expires,
            uses,
            max_uses,
            res,
            act,
            task_expiry,
        )) = row
        {
            agent_id = Some(agent);
            task_id = Some(task);
            grant_id = Some(grant);
            if ast != "active" {
                "identity_quarantined"
            } else if gs != "active" {
                "grant_revoked"
            } else if ts != "active" {
                "task_closed"
            } else if now >= expires || now >= task_expiry {
                "task_or_grant_expired"
            } else if resource != res || action != act {
                "scope_mismatch"
            } else if uses >= max_uses {
                "use_budget_exhausted"
            } else {
                "allowed"
            }
        } else {
            "invalid_token"
        };
        let allowed = reason == "allowed";
        if allowed {
            tx.execute("UPDATE grants SET uses=uses+1 WHERE id=?1", [grant_id])?;
            if let Some(note) = note {
                tx.execute(
                    "INSERT INTO agent_notes(agent_id,text,time_ms) VALUES (?1,?2,?3)",
                    params![agent_id, note, now],
                )?;
                tx.execute("DELETE FROM agent_notes WHERE id NOT IN (SELECT id FROM agent_notes ORDER BY id DESC LIMIT 64)",[])?;
            }
        }
        tx.execute("INSERT INTO access_decisions(time_ms,agent_id,task_id,grant_id,resource,action,allowed,reason) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![now,agent_id,task_id,grant_id,resource,action,allowed,reason])?;
        let id = tx.last_insert_rowid();
        tx.execute("DELETE FROM access_decisions WHERE id NOT IN (SELECT id FROM access_decisions ORDER BY id DESC LIMIT 512)",[])?;
        // Three known-identity denials in 60s revoke all grants. Unknown-token
        // noise cannot quarantine an arbitrary identity supplied by the caller.
        if !allowed {
            if let Some(agent) = agent_id {
                let denied:u64=tx.query_row("SELECT count(*) FROM access_decisions WHERE agent_id=?1 AND allowed=0 AND time_ms>=?2",params![agent,now.saturating_sub(60_000)],|r|r.get(0))?;
                if denied >= 3 {
                    tx.execute("UPDATE agents SET state='quarantined' WHERE id=?1", [agent])?;
                    tx.execute("UPDATE grants SET state='revoked' WHERE task_id IN (SELECT id FROM agent_tasks WHERE agent_id=?1)",[agent])?;
                    self.audit(
                        "agent.auto-quarantined",
                        &format!("agent-{agent}: three denials / 60s"),
                        now,
                    )?;
                }
            }
        }
        self.audit(
            if allowed {
                "gateway.allow"
            } else {
                "gateway.deny"
            },
            &format!("decision-{id} / {action}:{resource} / {reason}"),
            now,
        )?;
        // One commit binds consumption, operation, decision, normalized event
        // and any resulting finding, including its durable evidence reference.
        self.ingest_in_transaction(
            &[InputEvent {
                time_ms: now,
                source: "agent-gateway".into(),
                subject: agent_id
                    .map(|a| format!("agent-{a}"))
                    .unwrap_or_else(|| "unknown-agent".into()),
                object: resource.into(),
                kind: Kind::Policy,
                outcome: if allowed {
                    Outcome::Allow
                } else {
                    Outcome::Deny
                },
                severity: if allowed { 1 } else { 4 },
                bytes: 0,
                trace: task_id.unwrap_or(0).try_into()?,
                idempotency_key: format!("decision-{id}"),
                context: None,
            }],
            now,
        )?;
        tx.commit()?;
        Ok(Decision {
            id,
            time_ms: now,
            agent_id,
            task_id,
            grant_id,
            resource: resource.into(),
            action: action.into(),
            allowed,
            reason: reason.into(),
        })
    }
    pub fn hive(&self, now: u64) -> LabResult<Hive> {
        let agents = self
            .connection
            .prepare("SELECT id,name,role,state,created_ms FROM agents ORDER BY id")?
            .query_map([], |r| {
                Ok(Agent {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    role: r.get(2)?,
                    state: r.get(3)?,
                    created_ms: r.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        let tasks=self.connection.prepare("SELECT id,agent_id,title,resource,action,CASE WHEN state='active' AND expires_ms<=?1 THEN 'expired' ELSE state END,created_ms,expires_ms FROM agent_tasks ORDER BY id DESC")?.query_map([now],|r|Ok(Task{id:r.get(0)?,agent_id:r.get(1)?,title:r.get(2)?,resource:r.get(3)?,action:r.get(4)?,state:r.get(5)?,created_ms:r.get(6)?,expires_ms:r.get(7)?}))?.collect::<Result<_,_>>()?;
        let grants=self.connection.prepare("SELECT g.id,t.id,t.agent_id,t.resource,t.action,CASE WHEN g.state='revoked' THEN 'revoked' WHEN g.expires_ms<=?1 OR t.expires_ms<=?1 THEN 'expired' WHEN g.uses>=g.max_uses THEN 'exhausted' ELSE g.state END,g.created_ms,g.expires_ms,g.uses,g.max_uses FROM grants g JOIN agent_tasks t ON t.id=g.task_id ORDER BY g.id DESC")?.query_map([now],|r|Ok(Grant{id:r.get(0)?,task_id:r.get(1)?,agent_id:r.get(2)?,resource:r.get(3)?,action:r.get(4)?,state:r.get(5)?,created_ms:r.get(6)?,expires_ms:r.get(7)?,uses:r.get(8)?,max_uses:r.get(9)?}))?.collect::<Result<_,_>>()?;
        let decisions=self.connection.prepare("SELECT id,time_ms,agent_id,task_id,grant_id,resource,action,allowed,reason FROM access_decisions ORDER BY id DESC LIMIT 100")?.query_map([],|r|Ok(Decision{id:r.get(0)?,time_ms:r.get(1)?,agent_id:r.get(2)?,task_id:r.get(3)?,grant_id:r.get(4)?,resource:r.get(5)?,action:r.get(6)?,allowed:r.get(7)?,reason:r.get(8)?}))?.collect::<Result<_,_>>()?;
        let notes = self
            .connection
            .prepare("SELECT id,agent_id,text,time_ms FROM agent_notes ORDER BY id DESC LIMIT 64")?
            .query_map([], |r| {
                Ok(Note {
                    id: r.get(0)?,
                    agent_id: r.get(1)?,
                    text: r.get(2)?,
                    time_ms: r.get(3)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(Hive {
            agents,
            tasks,
            grants,
            decisions,
            notes,
        })
    }
    pub fn seed_hive(&mut self, now: u64) -> LabResult<()> {
        let count: u64 = self
            .connection
            .query_row("SELECT count(*) FROM agents", [], |r| r.get(0))?;
        if count > 0 {
            return Ok(());
        }
        for (name, role, resource, title) in [
            (
                "sentinel-01",
                "Evidence analyst",
                "evidence",
                "Investigate identity burst",
            ),
            (
                "cartographer-02",
                "Detection researcher",
                "rules",
                "Map rule coverage to retained facts",
            ),
            (
                "archivist-03",
                "Storage observer",
                "archive",
                "Inspect the rolling retention budget",
            ),
            (
                "scribe-04",
                "Incident scribe",
                "lab-note",
                "Record an investigation handoff",
            ),
        ] {
            let agent = self.register_agent(name, role, now)?;
            let task = self.create_task(agent, title, resource, 120, now)?;
            let grant = self.issue_grant(task, 3600, 24, now)?;
            self.access(
                &grant.token,
                resource,
                if resource == "lab-note" {
                    "append"
                } else {
                    "read"
                },
                if resource == "lab-note" {
                    Some("Synthetic investigation opened. Evidence remains bound to its task.")
                } else {
                    None
                },
                now,
            )?;
            // Seed tokens are deliberately discarded; operators issue new ones explicitly.
            if name == "cartographer-02" {
                for i in 1..=3 {
                    self.access(&grant.token, "evidence", "read", None, now + i)?;
                }
            }
        }
        Ok(())
    }
}

impl Engine {
    /// Explicit operator-triggered synthetic exercise. The temporary credential
    /// is never displayed or persisted in plaintext, and is revoked afterwards.
    pub fn exercise_hive(&mut self, agent: i64, now: u64) -> LabResult<()> {
        let task = self.create_task(
            agent,
            "Synthetic scope-boundary exercise",
            "evidence",
            5,
            now,
        )?;
        let grant = self.issue_grant(task, 60, 5, now)?;
        self.access(&grant.token, "evidence", "read", None, now)?;
        for i in 1..=3 {
            self.access(&grant.token, "rules", "read", None, now + i)?;
        }
        self.revoke_grant(grant.id, now + 4)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_800_000_000_000;
    fn fixture() -> (Engine, i64, i64, IssuedGrant) {
        let e = Engine::memory().unwrap();
        let a = e.register_agent("test-agent", "Fixture", NOW).unwrap();
        let t = e
            .create_task(a, "Read findings", "evidence", 2, NOW)
            .unwrap();
        let g = e.issue_grant(t, 3600, 2, NOW).unwrap();
        (e, a, t, g)
    }
    #[test]
    fn task_deadline_scope_and_operation_budget_are_enforced() {
        let (mut e, _, t, g) = fixture();
        assert_eq!(g.expires_ms, NOW + 120_000);
        assert_eq!(
            e.access("forged", "evidence", "read", None, NOW)
                .unwrap()
                .reason,
            "invalid_token"
        );
        assert_eq!(
            e.access(&g.token, "rules", "read", None, NOW)
                .unwrap()
                .reason,
            "scope_mismatch"
        );
        assert!(
            e.access(&g.token, "evidence", "read", None, NOW + 1)
                .unwrap()
                .allowed
        );
        assert!(
            e.access(&g.token, "evidence", "read", None, NOW + 2)
                .unwrap()
                .allowed
        );
        assert_eq!(
            e.access(&g.token, "evidence", "read", None, NOW + 3)
                .unwrap()
                .reason,
            "use_budget_exhausted"
        );
        let g = e.issue_grant(t, 3600, 2, NOW + 4).unwrap();
        assert_eq!(
            e.access(&g.token, "evidence", "read", None, g.expires_ms)
                .unwrap()
                .reason,
            "task_or_grant_expired"
        );
        assert!(e.issue_grant(t, 60, 1, NOW + 120_000).is_err());
    }
    #[test]
    fn completion_and_quarantine_never_revive_old_grants() {
        let (mut e, a, t, g) = fixture();
        e.finish_task(t, NOW + 1).unwrap();
        assert!(
            !e.access(&g.token, "evidence", "read", None, NOW + 2)
                .unwrap()
                .allowed
        );
        assert!(e.issue_grant(t, 60, 1, NOW + 2).is_err());
        let t = e
            .create_task(a, "Another purpose", "rules", 10, NOW + 3)
            .unwrap();
        let g = e.issue_grant(t, 600, 10, NOW + 3).unwrap();
        for i in 4..7 {
            assert!(
                !e.access(&g.token, "evidence", "read", None, NOW + i)
                    .unwrap()
                    .allowed
            );
        }
        assert_eq!(e.hive(NOW + 7).unwrap().agents[0].state, "quarantined");
        assert!(e
            .findings()
            .unwrap()
            .iter()
            .any(|f| f.rule == "AX-004" && f.subject == format!("agent-{a}")));
        e.set_agent_state(a, "active", NOW + 8).unwrap();
        assert_eq!(
            e.access(&g.token, "rules", "read", None, NOW + 9)
                .unwrap()
                .reason,
            "grant_revoked"
        );
    }
    #[test]
    fn security_state_survives_without_a_telemetry_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lab.db");
        let token;
        {
            let mut e = Engine::open(&path).unwrap();
            let a = e.register_agent("worker", "fixture", NOW).unwrap();
            let t = e.create_task(a, "note", "lab-note", 10, NOW).unwrap();
            let g = e.issue_grant(t, 600, 1, NOW).unwrap();
            token = g.token;
            e.access(
                &token,
                "lab-note",
                "append",
                Some("Durable authorized mutation"),
                NOW,
            )
            .unwrap();
            assert_eq!(e.pending_count().unwrap(), 1);
        }
        let mut e = Engine::open(&path).unwrap();
        let h = e.hive(NOW).unwrap();
        assert_eq!(h.notes.len(), 1);
        assert_eq!(h.decisions.len(), 1);
        assert_eq!(h.grants[0].uses, 1);
        assert_eq!(e.events().unwrap().len(), 1);
        assert_eq!(
            e.access(&token, "lab-note", "append", Some("Must fail"), NOW + 1)
                .unwrap()
                .reason,
            "use_budget_exhausted"
        );
        assert_eq!(e.hive(NOW).unwrap().notes.len(), 1);
        let encoded = serde_json::to_string(&e.snapshot().unwrap()).unwrap();
        assert!(!encoded.contains(&token));
        let db = std::fs::read(&path).unwrap();
        assert!(!db.windows(token.len()).any(|w| w == token.as_bytes()));
    }
    #[test]
    fn failed_audit_rolls_back_consumption_and_side_effects() {
        let mut e = Engine::memory().unwrap();
        let a = e.register_agent("writer", "fixture", NOW).unwrap();
        let t = e.create_task(a, "write", "lab-note", 10, NOW).unwrap();
        let g = e.issue_grant(t, 600, 1, NOW).unwrap();
        e.connection.execute_batch("CREATE TRIGGER reject_gateway_audit BEFORE INSERT ON audit WHEN NEW.action='gateway.allow' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(e
            .access(&g.token, "lab-note", "append", Some("Must roll back"), NOW)
            .is_err());
        let h = e.hive(NOW).unwrap();
        assert_eq!(h.grants[0].uses, 0);
        assert!(h.notes.is_empty());
        assert!(h.decisions.is_empty());
    }
    #[test]
    fn unknown_tokens_cannot_quarantine_a_registered_identity() {
        let (mut e, _, _, _) = fixture();
        for _ in 0..8 {
            e.access("unknown", "evidence", "read", None, NOW).unwrap();
        }
        assert_eq!(e.hive(NOW).unwrap().agents[0].state, "active");
    }
    #[test]
    fn failed_siem_mirror_rolls_back_the_gateway_operation() {
        let (mut e, _, _, g) = fixture();
        e.connection.execute_batch("CREATE TEMP TRIGGER reject_mirror BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(e.access(&g.token, "evidence", "read", None, NOW).is_err());
        let h = e.hive(NOW).unwrap();
        assert_eq!(h.grants[0].uses, 0);
        assert!(h.decisions.is_empty());
    }
    #[test]
    fn an_item_grant_cannot_read_other_findings() {
        let (mut e, a, _, _) = fixture();
        e.scenario("chain", NOW).unwrap();
        let ids = e
            .findings()
            .unwrap()
            .iter()
            .map(|f| f.id)
            .collect::<Vec<_>>();
        let resource = format!("finding-{}", ids[0]);
        let t = e
            .create_task(a, "Only this finding", &resource, 5, NOW)
            .unwrap();
        let g = e.issue_grant(t, 60, 10, NOW).unwrap();
        assert!(
            e.access(&g.token, &resource, "read", None, NOW)
                .unwrap()
                .allowed
        );
        assert_eq!(
            e.access(&g.token, &format!("finding-{}", ids[1]), "read", None, NOW)
                .unwrap()
                .reason,
            "scope_mismatch"
        );
    }
}
