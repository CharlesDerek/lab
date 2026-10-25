//! Named local operators, revocable sessions, and exportable audit checkpoints.
use crate::{
    engine::{Engine, LabResult},
    gateway::{digest, secret},
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Responder,
    Analyst,
    Viewer,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Actor {
    pub id: String,
    pub role: Role,
    pub revision: u64,
}
impl Actor {
    pub fn bootstrap() -> Self {
        Self {
            id: "bootstrap".into(),
            role: Role::Admin,
            revision: 0,
        }
    }
    pub fn allows(&self, method: &str, path: &str) -> bool {
        if method == "GET" || method == "HEAD" || path == "/logout" {
            return true;
        }
        match self.role {
            Role::Admin => true,
            Role::Viewer => false,
            Role::Analyst => {
                matches!(
                    path,
                    "/cases/action"
                        | "/api/control"
                        | "/control/setup"
                        | "/api/investigations"
                        | "/analysis/run"
                ) || (path.starts_with("/api/investigations/") && path.ends_with("/cancel"))
            }
            Role::Responder => {
                !matches!(path, "/api/agent-certificates" | "/api/evidence-locations")
            }
        }
    }
}
#[derive(Serialize)]
pub struct Operator {
    pub id: String,
    pub role: Role,
    pub revision: u64,
    pub expires_ms: u64,
    pub active: bool,
}
#[derive(Serialize)]
pub struct IssuedOperator {
    pub operator: Operator,
    pub token: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditCheckpoint {
    pub sequence: u64,
    pub sha256: String,
}
#[derive(Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub time_ms: u64,
    pub action: String,
    pub detail: String,
    pub previous: String,
    pub sha256: String,
}

impl Engine {
    pub(crate) fn init_identity(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS operators(id TEXT PRIMARY KEY,role TEXT NOT NULL,revision INTEGER NOT NULL,credential_hash TEXT UNIQUE NOT NULL,expires_ms INTEGER NOT NULL,active INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS audit_chain(sequence INTEGER PRIMARY KEY,time_ms INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL,previous TEXT NOT NULL,sha256 TEXT NOT NULL);")?;
        let expected = self.audit_checkpoint()?;
        if expected.sequence > 100_000 {
            return Err("Audit history exceeds its verification budget".into());
        }
        let mut head = AuditCheckpoint {
            sequence: 0,
            sha256: "0".repeat(64),
        };
        loop {
            let records = self.export_audit(head.sequence, 256)?;
            let Some(last) = records.last() else {
                break;
            };
            let end = AuditCheckpoint {
                sequence: last.sequence,
                sha256: last.sha256.clone(),
            };
            verify_audit(&records, &head, &end)?;
            head = end;
        }
        if head != expected {
            return Err("Audit checkpoint changed during startup verification".into());
        }
        Ok(())
    }
    pub fn operators(&self) -> LabResult<Vec<Operator>> {
        let rows = self
            .connection
            .prepare("SELECT id,role,revision,expires_ms,active FROM operators ORDER BY id")?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(id, role, revision, expires_ms, active)| {
                Ok(Operator {
                    id,
                    role: serde_json::from_str(&role)?,
                    revision,
                    expires_ms,
                    active,
                })
            })
            .collect()
    }
    pub fn issue_operator(
        &self,
        id: &str,
        role: Role,
        expires_ms: u64,
        now: u64,
    ) -> LabResult<IssuedOperator> {
        if !orchestrator::governor::label(id)
            || id == "bootstrap"
            || expires_ms <= now
            || expires_ms > now.saturating_add(90 * 86_400_000).min(i64::MAX as u64)
        {
            return Err("Invalid named operator or credential lifetime".into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let previous: Option<u64> = tx
            .query_row("SELECT revision FROM operators WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        let count: u64 = tx.query_row("SELECT count(*) FROM operators", [], |r| r.get(0))?;
        if count >= 64 && previous.is_none() {
            return Err("Named operator capacity reached".into());
        }
        let revision = previous
            .unwrap_or(0)
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or("Operator revision exhausted")?;
        let token = secret()?;
        tx.execute("INSERT INTO operators VALUES(?1,?2,?3,?4,?5,1) ON CONFLICT(id) DO UPDATE SET role=excluded.role,revision=excluded.revision,credential_hash=excluded.credential_hash,expires_ms=excluded.expires_ms,active=1",params![id,serde_json::to_string(&role)?,revision,digest(&token),expires_ms])?;
        self.audit("operator.credential_rotated", id, now)?;
        tx.commit()?;
        Ok(IssuedOperator {
            operator: Operator {
                id: id.into(),
                role,
                revision,
                expires_ms,
                active: true,
            },
            token,
        })
    }
    pub fn revoke_operator(&self, id: &str, now: u64) -> LabResult<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if tx.execute("UPDATE operators SET active=0 WHERE id=?1", [id])? != 1 {
            return Err("Named operator not found".into());
        }
        self.audit("operator.revoked", id, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn authenticate_operator(&self, token: &str, now: u64) -> LabResult<Actor> {
        if token.len() != 64 {
            return Err("Operator credential rejected".into());
        }
        let (id,role,revision):(String,String,u64)=self.connection.query_row("SELECT id,role,revision FROM operators WHERE credential_hash=?1 AND active=1 AND expires_ms>?2",params![digest(token),now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        Ok(Actor {
            id,
            role: serde_json::from_str(&role)?,
            revision,
        })
    }
    pub fn validate_operator_session(&self, actor: &Actor, now: u64) -> LabResult<Actor> {
        let (role, revision): (String, u64) = self.connection.query_row(
            "SELECT role,revision FROM operators WHERE id=?1 AND active=1 AND expires_ms>?2",
            params![actor.id, now],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if revision != actor.revision {
            return Err("Operator session revoked by credential rotation".into());
        }
        Ok(Actor {
            id: actor.id.clone(),
            role: serde_json::from_str(&role)?,
            revision,
        })
    }
    pub fn audit_checkpoint(&self) -> LabResult<AuditCheckpoint> {
        Ok(self
            .connection
            .query_row(
                "SELECT sequence,sha256 FROM audit_chain ORDER BY sequence DESC LIMIT 1",
                [],
                |r| {
                    Ok(AuditCheckpoint {
                        sequence: r.get(0)?,
                        sha256: r.get(1)?,
                    })
                },
            )
            .optional()?
            .unwrap_or(AuditCheckpoint {
                sequence: 0,
                sha256: "0".repeat(64),
            }))
    }
    pub(crate) fn append_audit_chain(&self, action: &str, detail: &str, now: u64) -> LabResult<()> {
        let head = self.audit_checkpoint()?;
        if head.sequence >= 100_000
            || action.len() > 128
            || detail.len() > 16384
            || now > i64::MAX as u64
        {
            return Err("Durable audit capacity reached or invalid record".into());
        }
        let sequence = head.sequence + 1;
        let sha256 = audit_hash(sequence, now, action, detail, &head.sha256)?;
        self.connection.execute(
            "INSERT INTO audit_chain VALUES(?1,?2,?3,?4,?5,?6)",
            params![sequence, now, action, detail, head.sha256, sha256],
        )?;
        Ok(())
    }
    pub fn export_audit(&self, after: u64, limit: usize) -> LabResult<Vec<AuditRecord>> {
        if after > i64::MAX as u64 || !(1..=1000).contains(&limit) {
            return Err("Invalid audit page".into());
        }
        Ok(self.connection.prepare("SELECT sequence,time_ms,action,detail,previous,sha256 FROM audit_chain WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?.query_map(params![after,limit],|r|Ok(AuditRecord{sequence:r.get(0)?,time_ms:r.get(1)?,action:r.get(2)?,detail:r.get(3)?,previous:r.get(4)?,sha256:r.get(5)?}))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}
fn audit_hash(
    sequence: u64,
    time_ms: u64,
    action: &str,
    detail: &str,
    previous: &str,
) -> LabResult<String> {
    Ok(digest(&serde_json::to_string(&(
        sequence, time_ms, action, detail, previous,
    ))?))
}
/// The expected final checkpoint must be retained independently by the caller.
pub fn verify_audit(
    records: &[AuditRecord],
    start: &AuditCheckpoint,
    end: &AuditCheckpoint,
) -> LabResult<()> {
    let mut head = start.clone();
    for record in records {
        if record.sequence != head.sequence + 1
            || record.previous != head.sha256
            || record.sha256
                != audit_hash(
                    record.sequence,
                    record.time_ms,
                    &record.action,
                    &record.detail,
                    &record.previous,
                )?
        {
            return Err("Audit sequence or integrity failure".into());
        }
        head = AuditCheckpoint {
            sequence: record.sequence,
            sha256: record.sha256.clone(),
        };
    }
    if &head != end {
        return Err("Audit does not reach the independently retained checkpoint".into());
    }
    Ok(())
}
