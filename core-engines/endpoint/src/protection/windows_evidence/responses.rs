//! A denied read can verify quarantine only through the applied decision for
//! that disposable worker's single source-open attempt. This grants no access.
use super::*;
use rusqlite::{Transaction, TransactionBehavior};

const LIMIT: u64 = 64;
const LIFETIME_MS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub id: String,
    pub session: String,
    pub policy: String,
    pub actor_pid: u32,
    pub actor_created: u64,
    pub path: String,
    pub volume: u64,
    pub file_id: String,
    pub bytes: u64,
    pub started_ms: u64,
    pub expires_ms: u64,
}
impl Probe {
    fn validate(&self, now: u64) -> Result<()> {
        if ![&self.id, &self.session, &self.policy]
            .into_iter()
            .all(|s| protocol::hex_id(s))
            || self.actor_pid == 0
            || self.actor_created == 0
            || !drive_path(&self.path)
            || self.file_id.len() != 32
            || !self
                .file_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.bytes > athernex_endpoint_native::MAX_FILE
            || self.started_ms == 0
            || self.started_ms > now
            || self.expires_ms <= now
            || self.expires_ms > self.started_ms.saturating_add(LIFETIME_MS)
            || self.expires_ms > i64::MAX as u64
        {
            return Err("Invalid or expired Windows response probe".into());
        }
        Ok(())
    }
    fn actor(&self) -> String {
        format!("{}:{}", self.actor_pid, self.actor_created)
    }
    fn verdict(
        &self,
        receipt: &Receipt,
        scope: &Scope,
        now: u64,
    ) -> Result<athernex_endpoint_native::Verdict> {
        self.validate(now)?;
        receipt.event(scope)?;
        let observation = &receipt.observation;
        if receipt.session != self.session
            || observation.policy_sha256 != self.policy
            || observation.actor_pid != u64::from(self.actor_pid)
            || observation.actor_created != self.actor_created
            || observation.volume != self.volume
            || observation.file_id != self.file_id
            || observation.bytes != self.bytes
            || !prefix_equal(&scope.path(&observation.path)?, &self.path)
            || observation.checked_ms < self.started_ms
            || observation.checked_ms > now
            || observation.outcome != "denied_malware"
        {
            return Err(
                "Windows response requires this worker's exact applied malware denial".into(),
            );
        }
        Ok(athernex_endpoint_native::Verdict {
            sha256: observation.sha256.clone(),
            bytes: observation.bytes,
            detection: observation.detection.clone(),
        })
    }
}
pub(super) fn initialize(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch("CREATE TABLE IF NOT EXISTS response_probes(id TEXT PRIMARY KEY,actor TEXT NOT NULL UNIQUE,expires INTEGER NOT NULL,payload TEXT NOT NULL,receipt TEXT,conflict INTEGER NOT NULL DEFAULT 0);")?;
    Ok(())
}
pub(super) fn record(tx: &Transaction<'_>, receipt: &Receipt) -> Result<()> {
    let actor = format!(
        "{}:{}",
        receipt.observation.actor_pid, receipt.observation.actor_created
    );
    let pending: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT payload,receipt FROM response_probes WHERE actor=?1 AND expires>?2",
            params![actor, now_ms()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((request, prior)) = pending else {
        return Ok(());
    };
    if request.len() > 4096 {
        return Err("Windows response probe exceeds budget".into());
    }
    let probe: Probe = serde_json::from_str(&request)?;
    if receipt.session != probe.session || receipt.observation.policy_sha256 != probe.policy {
        return Ok(());
    }
    let raw = serde_json::to_string(receipt)?;
    if prior.as_ref().is_some_and(|p| p != &raw) {
        tx.execute(
            "UPDATE response_probes SET conflict=1 WHERE id=?1",
            [&probe.id],
        )?;
        return Ok(());
    }
    tx.execute(
        "UPDATE response_probes SET receipt=?1 WHERE id=?2",
        params![raw, probe.id],
    )?;
    Ok(())
}
impl Queue {
    fn response_session(&self, probe: &Probe, now: u64) -> Result<()> {
        let coverage = self
            .coverage()?
            .ok_or("Windows response has no live coverage checkpoint")?;
        coverage.validate()?;
        if coverage.session != probe.session
            || coverage.policy != probe.policy
            || coverage.state != "active"
            || coverage.checked_ms > now
            || now.saturating_sub(coverage.checked_ms) > 5000
            || coverage
                .kernel
                .as_ref()
                .is_none_or(|k| k.checked_ms > now || now.saturating_sub(k.checked_ms) > 5000)
        {
            return Err("Windows response protection session is unavailable or changed".into());
        }
        Ok(())
    }
    pub fn begin_response(&self, probe: &Probe) -> Result<()> {
        let now = now_ms();
        probe.validate(now)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.response_session(probe, now)?;
        // Resolve the policy now, before any source read is attempted.
        let scope = self.scope(&probe.policy)?;
        if !scope
            .roots
            .iter()
            .any(|r| suffix(&probe.path, &r.dos).is_some_and(|s| !s.is_empty()))
        {
            return Err("Windows response probe is outside the protected policy".into());
        }
        tx.execute("DELETE FROM response_probes WHERE expires<=?1", [now])?;
        let count: u64 = tx.query_row("SELECT count(*) FROM response_probes", [], |r| r.get(0))?;
        if count >= LIMIT {
            return Err("Windows response probe capacity exhausted".into());
        }
        tx.execute(
            "INSERT INTO response_probes(id,actor,expires,payload) VALUES(?1,?2,?3,?4)",
            params![
                probe.id,
                probe.actor(),
                probe.expires_ms,
                serde_json::to_string(probe)?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Successful consume is atomic. Failed, missing and interrupted probes
    /// never authorize a mutation; expired rows are reclaimed at next admission.
    pub fn take_response(
        &self,
        probe: &Probe,
    ) -> Result<Option<athernex_endpoint_native::Verdict>> {
        let now = now_ms();
        probe.validate(now)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.response_session(probe, now)?;
        let (raw, receipt, conflict): (String, Option<String>, bool) = tx.query_row(
            "SELECT payload,receipt,conflict FROM response_probes WHERE id=?1",
            [&probe.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if conflict {
            return Err("Windows response worker produced multiple distinct denials".into());
        }
        if raw != serde_json::to_string(probe)? {
            return Err("Windows response probe changed".into());
        }
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        if receipt.len() > 4096 {
            return Err("Windows response receipt exceeds budget".into());
        }
        let receipt: Receipt = serde_json::from_str(&receipt)?;
        let verdict = probe.verdict(&receipt, &self.scope(&probe.policy)?, now)?;
        tx.execute(
            "DELETE FROM response_probes WHERE id=?1 AND payload=?2",
            params![probe.id, raw],
        )?;
        tx.commit()?;
        Ok(Some(verdict))
    }
    pub fn cancel_response(&self, probe: &Probe) -> Result<()> {
        self.connection.execute(
            "DELETE FROM response_probes WHERE id=?1 AND payload=?2",
            params![probe.id, serde_json::to_string(probe)?],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
