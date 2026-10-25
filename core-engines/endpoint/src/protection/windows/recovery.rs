//! Scanner launch journal. The supervisor leases must be held throughout
//! reconciliation. Schema 2 guarantees suspended, single-process job creation
//! and a durable ownership transition before ResumeThread. Older policy-only
//! journals do not supply that guarantee and are never adopted automatically.
use super::{Directory, NetworkEngine, NetworkPolicy, Result};
use crate::protection::windows_launch::Launch;
use athernex_endpoint_native::windows_filter::peer;
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    schema: u32,
    pub(super) network: NetworkPolicy,
    launch: Launch,
}
impl Record {
    pub(super) fn prepared(network: NetworkPolicy) -> Result<Self> {
        let record = Self {
            schema: 2,
            network,
            launch: Launch::Prepared {},
        };
        record.validate(&record.network.id)?;
        Ok(record)
    }
    pub(super) fn validate(&self, id: &str) -> Result<()> {
        self.network.validate()?;
        if self.schema != 2 || self.network.id != id {
            return Err("Windows scanner recovery journal identity/schema changed".into());
        }
        self.launch.validate()?;
        Ok(())
    }
    pub(super) fn save(&self, journal: &Directory) -> Result<()> {
        self.validate(&self.network.id)?;
        journal.write_json(&format!("{}.json", self.network.id), self)
    }
    pub(super) fn own(
        &mut self,
        journal: &Directory,
        pid: u32,
        created: u64,
        logon: &str,
    ) -> Result<()> {
        if !matches!(self.launch, Launch::Prepared {}) {
            return Err("Scanner ownership was already recorded".into());
        }
        let owned = Self {
            schema: self.schema,
            network: self.network.clone(),
            launch: Launch::Owned {
                pid,
                created,
                logon: logon.into(),
            },
        };
        owned.save(journal)?;
        *self = owned;
        Ok(())
    }
    pub(super) fn matches_scanner(&self, pid: u32, created: u64, logon: &str) -> bool {
        matches!(&self.launch, Launch::Owned { pid: p, created: c, logon: l }
            if *p == pid && *c == created && l == logon)
    }
    fn ensure_stopped(&self) -> Result<()> {
        match &self.launch {
            // The process either was never created or never resumed. The
            // previous supervisor cannot resume it while we hold both leases.
            Launch::Prepared {} => Ok(()),
            // The launch contract forbids children/breakaway. Never terminate
            // a PID from disk, and never treat access denial as proof of exit.
            Launch::Owned { pid, created, .. } => {
                if peer::original_process_ended(*pid, *created)? {
                    Ok(())
                } else {
                    Err("Previous Windows scanner is still alive; network policy retained".into())
                }
            }
        }
    }
}

pub(super) fn read(journal: &Directory, id: &str) -> Result<Record> {
    if !athernex_endpoint_protocol::hex_id(id) {
        return Err("Invalid Windows scanner journal filename".into());
    }
    let record: Record = journal.read_json(&format!("{id}.json")).map_err(|e| {
        format!("Cannot recover Windows scanner journal {id}: {e}; legacy policy-only journals require offline review")
    })?;
    record.validate(id)?;
    Ok(record)
}

/// Requires the standard protection lease, Windows supervisor lease and a
/// healthy/empty in-process reaper. This operation does not restart scanners.
pub(super) fn recover(journal: &Directory) -> Result<()> {
    let mut records = Vec::new();
    let mut temporary = Vec::new();
    for (index, entry) in std::fs::read_dir(journal.path())?.enumerate() {
        if index >= 64 {
            return Err("Windows scanner recovery exceeds its entry budget".into());
        }
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| "Windows scanner recovery contains a non-Unicode filename")?;
        if let Some(id) = name.strip_suffix(".json") {
            records.push(read(journal, id)?);
        } else if let Some(id) = name
            .strip_prefix('.')
            .and_then(|n| n.strip_suffix(".json.new"))
        {
            if !athernex_endpoint_protocol::hex_id(id) {
                return Err("Unknown Windows scanner journal temporary file".into());
            }
            // A failed atomic write is never authority to resume. Inspect its
            // private, regular, no-reparse handle even when JSON is incomplete.
            let file = journal.read(&name)?;
            if file.metadata()?.len() > 65536 {
                return Err("Scanner journal temporary file exceeds its byte budget".into());
            }
            temporary.push(name);
        } else {
            return Err("Unknown entry in Windows scanner recovery directory".into());
        }
    }
    // Validate every record and process before changing the first policy.
    for record in &records {
        record.ensure_stopped()?;
    }
    if !records.is_empty() {
        let engine = NetworkEngine::open()?;
        for record in records {
            match record.launch {
                Launch::Prepared {} => engine.remove_before_first_resume(&record.network)?,
                Launch::Owned { .. } => engine.remove_after_job_exit(&record.network)?,
            }
            journal.remove(&format!("{}.json", record.network.id))?;
        }
    }
    for name in temporary {
        journal.remove(&name)?;
    }
    journal.sync()
}
