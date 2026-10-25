//! Durable evidence coverage. Kernel totals belong to a driver load, not a client
//! or policy. Checkpoints never turn an unobserved interval into a zero-loss claim.
use super::*;
use athernex_endpoint_native::windows_filter::wire;
use rusqlite::{Transaction, TransactionBehavior};

pub(super) const NOTICES: u64 = 64;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KernelCheckpoint {
    /// Hash of the opaque driver-load UUID; scoped to this endpoint's database.
    pub instance: String,
    pub checked_ms: u64,
    pub allowed: u64,
    pub malware: u64,
    pub errors: u64,
    pub evidence_dropped: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub schema: u32,
    pub session: String,
    pub policy: String,
    pub revision: u64,
    pub started_ms: u64,
    pub checked_ms: u64,
    pub state: String,
    pub kernel: Option<KernelCheckpoint>,
    /// Observed kernel delivery drops accumulated once per driver-load counter.
    pub kernel_dropped: u64,
    pub local_dropped: u64,
    /// Detected interruptions/reloads/regressions, not a missing-event count.
    pub gaps: u64,
    pub legacy_history_unknown: bool,
    pub reason: String,
}
impl Coverage {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || !protocol::hex_id(&self.session)
            || !protocol::hex_id(&self.policy)
            || self.revision == 0
            || self.started_ms == 0
            || self.checked_ms == 0
            || !["starting", "active", "failed", "stopped"].contains(&self.state.as_str())
            || self.reason.len() > 512
            || self.reason.chars().any(char::is_control)
            || self.kernel.as_ref().is_some_and(|k| {
                !protocol::hex_id(&k.instance)
                    || k.checked_ms == 0
                    || k.evidence_dropped > self.kernel_dropped
            })
        {
            return Err("Invalid Windows evidence coverage checkpoint".into());
        }
        Ok(())
    }
    pub fn incomplete(&self) -> bool {
        self.state != "active"
            || self.kernel.is_none()
            || self.kernel_dropped != 0
            || self.local_dropped != 0
            || self.gaps != 0
            || self.legacy_history_unknown
    }
    fn event(&self) -> Result<EndpointEvent> {
        self.validate()?;
        let raw = serde_json::to_string(self)?;
        let detail = serde_json::json!({"windows_evidence_coverage":self,"coverage_incomplete":self.incomplete(),
            "scope":"Kernel totals are driver-wide, including earlier policies. Gaps count detected interruptions, not missing events. Unobserved tail losses may be unknown. This is evidence coverage, not a live blocking proof."}).to_string();
        let event = EndpointEvent {
            id: protocol::hash(format!("windows-evidence-coverage-v1\0{raw}").as_bytes()),
            time_ms: self.checked_ms,
            kind: if self.kernel_dropped != 0
                || self.local_dropped != 0
                || self.gaps != 0
                || self.legacy_history_unknown
                || self.state == "failed"
            {
                "agent_error"
            } else {
                "inventory"
            }
            .into(),
            path: String::new(),
            sha256: String::new(),
            detection: String::new(),
            detail,
            telemetry: None,
        };
        event.validate(now_ms())?;
        Ok(event)
    }
}
pub(super) fn initialize(connection: &Connection, legacy: bool) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS coverage_state(name TEXT PRIMARY KEY,payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS coverage_events(id TEXT PRIMARY KEY,payload TEXT NOT NULL);",
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO coverage_state VALUES('legacy',?1)",
        [if legacy { "true" } else { "false" }],
    )?;
    Ok(())
}
fn read(connection: &Connection) -> Result<Option<Coverage>> {
    let raw: Option<String> = connection
        .query_row(
            "SELECT payload FROM coverage_state WHERE name='current'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|s| {
        if s.len() > 8192 {
            return Err("Windows coverage checkpoint exceeds its byte budget".into());
        }
        let c: Coverage = serde_json::from_str(&s)?;
        c.validate()?;
        Ok(c)
    })
    .transpose()
}
fn save(tx: &Transaction<'_>, coverage: &Coverage, notify: bool) -> Result<()> {
    coverage.validate()?;
    let raw = serde_json::to_string(coverage)?;
    if notify {
        let count: u64 = tx.query_row("SELECT count(*) FROM coverage_events", [], |r| r.get(0))?;
        if count >= NOTICES {
            return Err("Windows coverage notice queue is full; retained history must be delivered before collection resumes".into());
        }
        tx.execute(
            "INSERT INTO coverage_events VALUES(?1,?2)",
            params![coverage.event()?.id, raw],
        )?;
    }
    tx.execute("INSERT INTO coverage_state VALUES('current',?1) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload",[raw])?;
    Ok(())
}
fn advance(coverage: &mut Coverage) -> Result<()> {
    coverage.revision = coverage
        .revision
        .checked_add(1)
        .ok_or("Windows coverage revision exhausted")?;
    coverage.checked_ms = now_ms();
    Ok(())
}
impl Queue {
    pub fn coverage(&self) -> Result<Option<Coverage>> {
        read(&self.connection)
    }
    /// Caller owns client.lock before starting a new session. A new session never
    /// erases prior loss, or assumes a previous worker drained before it died.
    pub fn begin_session(&self, session: &str, policy: &str) -> Result<Coverage> {
        if !protocol::hex_id(session) || !protocol::hex_id(policy) {
            return Err("Invalid Windows evidence session".into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let prior = read(&tx)?;
        if prior.as_ref().is_some_and(|p| p.session == session) {
            return Err("Windows evidence session cannot be reused".into());
        }
        let local: u64 = tx.query_row("SELECT value FROM counters WHERE name='lost'", [], |r| {
            r.get(0)
        })?;
        let legacy: String = tx.query_row(
            "SELECT payload FROM coverage_state WHERE name='legacy'",
            [],
            |r| r.get(0),
        )?;
        let unknown: bool = serde_json::from_str(&legacy)?;
        let c=Coverage {schema:1,session:session.into(),policy:policy.into(),
            revision:prior.as_ref().map_or(Ok(1),|p|p.revision.checked_add(1).ok_or("Windows coverage revision exhausted"))?,
            started_ms:now_ms(),checked_ms:now_ms(),state:"starting".into(),kernel:prior.as_ref().and_then(|p|p.kernel.clone()),
            kernel_dropped:prior.as_ref().map_or(0,|p|p.kernel_dropped),local_dropped:local,
            gaps:prior.as_ref().map_or(0,|p|p.gaps.saturating_add(u64::from(p.state!="stopped"))),
            legacy_history_unknown:unknown || prior.as_ref().is_some_and(|p|p.legacy_history_unknown),
            reason:"New client subscription; activity before the first checkpoint and between subscriptions is not fully observed".into()};
        save(&tx, &c, true)?;
        tx.commit()?;
        Ok(c)
    }
    pub fn observe_kernel(
        &self,
        session: &str,
        checked_ms: u64,
        status: &wire::Status,
    ) -> Result<Coverage> {
        status.validate()?;
        if checked_ms == 0
            || checked_ms > now_ms().saturating_add(1000)
            || now_ms().saturating_sub(checked_ms) > 5000
        {
            return Err("Windows kernel evidence checkpoint is stale".into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut c = read(&tx)?.ok_or("Windows evidence session has not begun")?;
        if c.session != session
            || !["starting", "active"].contains(&c.state.as_str())
            || status.armed != 1
            || status.connected != 1
            || checked_ms < c.started_ms
            || c.policy
                != status
                    .policy_sha256
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
        {
            return Err("Windows kernel checkpoint belongs to another session or policy".into());
        }
        let next = KernelCheckpoint {
            instance: protocol::hash(&status.instance),
            checked_ms,
            allowed: status.allowed,
            malware: status.malware,
            errors: status.errors,
            evidence_dropped: status.evidence_dropped,
        };
        let old = c.kernel.as_ref();
        let same = old.is_some_and(|p| p.instance == next.instance);
        let regressed = old.is_some_and(|p| {
            same && (next.checked_ms < p.checked_ms
                || next.allowed < p.allowed
                || next.malware < p.malware
                || next.errors < p.errors
                || next.evidence_dropped < p.evidence_dropped)
        });
        let changed = old.is_some() && !same;
        let baseline = if same {
            old.unwrap().evidence_dropped
        } else {
            0
        };
        let notify = old.is_none() || changed || regressed || next.evidence_dropped != baseline;
        advance(&mut c)?;
        if regressed {
            c.gaps = c.gaps.saturating_add(1);
            c.state = "failed".into();
            c.reason="Kernel counters or checkpoint time regressed within one driver instance; prior baseline retained".into();
        } else {
            c.kernel_dropped = c
                .kernel_dropped
                .saturating_add(next.evidence_dropped - baseline);
            if changed {
                c.gaps = c.gaps.saturating_add(1);
            }
            c.state = "active".into();
            c.kernel = Some(next);
            if notify {
                c.reason = if changed {
                    "Driver instance changed; the previous instance's unobserved tail is unknown"
                } else {
                    "Observed driver-wide evidence counters"
                }
                .into();
            }
        }
        save(&tx, &c, notify)?;
        tx.commit()?;
        Ok(c)
    }
    /// A stopped client cannot account for its unsampled kernel/channel tail.
    pub fn end_session(&self, session: &str, reason: &str) -> Result<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut c = read(&tx)?.ok_or("Windows evidence session has not begun")?;
        if c.session != session {
            return Err("Windows evidence shutdown belongs to another session".into());
        }
        if c.state == "stopped" {
            return Ok(());
        }
        if c.state != "failed" {
            c.gaps = c.gaps.saturating_add(1);
        }
        advance(&mut c)?;
        c.state = "stopped".into();
        c.reason.clear();
        for character in reason.chars().filter(|c| !c.is_control()) {
            if c.reason.len() + character.len_utf8() > 512 {
                break;
            }
            c.reason.push(character);
        }
        save(&tx, &c, true)?;
        tx.commit()?;
        Ok(())
    }
    pub(super) fn collect_coverage(&self, store: &Store) -> Result<()> {
        let rows = self
            .connection
            .prepare("SELECT id,payload FROM coverage_events ORDER BY rowid LIMIT 32")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (id, raw) in rows {
            if raw.len() > 8192 {
                return Err("Windows coverage notice exceeds its byte budget".into());
            }
            let coverage: Coverage = serde_json::from_str(&raw)?;
            let event = coverage.event()?;
            if event.id != id {
                return Err("Windows coverage notice identity changed".into());
            }
            self.admit(store, &event, &raw)?;
            if self.connection.execute(
                "DELETE FROM coverage_events WHERE id=?1 AND payload=?2",
                params![id, raw],
            )? != 1
            {
                return Err("Windows coverage notice changed during acknowledgement".into());
            }
            store
                .connection
                .execute("DELETE FROM windows_receipt_transfers WHERE id=?1", [id])?;
        }
        Ok(())
    }
}
pub(super) fn local_loss(tx: &Transaction<'_>) -> Result<()> {
    if let Some(mut c) = read(tx)? {
        c.local_dropped =
            tx.query_row("SELECT value FROM counters WHERE name='lost'", [], |r| {
                r.get(0)
            })?;
        advance(&mut c)?;
        c.reason = "Client channel or durable receipt admission lost observations".into();
        save(tx, &c, true)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
