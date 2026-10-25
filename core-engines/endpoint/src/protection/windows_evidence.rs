//! Windows decisions enter a durable bounded spool before management delivery.
//! A transfer journal bridges the two databases, including server ACK/restart.
use crate::{now_ms, Result, Store};
use athernex_endpoint_native::windows_filter::{evidence::Observation, wire::Configuration};
use athernex_endpoint_protocol::{self as protocol, EndpointEvent};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
mod coverage;
pub mod responses;
pub use coverage::Coverage;
pub const LIMIT: u64 = 2048;
const TRANSFER_LIMIT: u64 = LIMIT + coverage::NOTICES;
pub fn prefix_equal(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
        let left: Vec<u16> = left.encode_utf16().collect();
        let right: Vec<u16> = right.encode_utf16().collect();
        if left.len() > i32::MAX as usize || right.len() > i32::MAX as usize {
            return false;
        }
        unsafe {
            CompareStringOrdinal(
                left.as_ptr(),
                left.len() as i32,
                right.as_ptr(),
                right.len() as i32,
                1,
            ) == CSTR_EQUAL
        }
    }
    #[cfg(not(windows))]
    {
        left.eq_ignore_ascii_case(right)
    }
}
/// Match Windows names in UTF-16 units, then return a UTF-8-safe suffix.
/// Case-equivalent Unicode characters can have different UTF-8 byte lengths.
pub fn suffix<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    let target = root.encode_utf16().count();
    let (mut units, mut boundary) = (0, 0);
    for character in path.chars() {
        if units >= target {
            break;
        }
        units += character.len_utf16();
        boundary += character.len_utf8();
    }
    if units != target || !prefix_equal(&path[..boundary], root) {
        return None;
    }
    let tail = &path[boundary..];
    if tail.is_empty() || tail.starts_with('\\') {
        Some(tail)
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub nt: String,
    pub dos: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub roots: Vec<Root>,
    pub timeout_ms: u32,
}
pub fn drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() > 3
        && bytes.len() <= 1024
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..3] == *b":\\"
        && !path.contains(char::is_control)
        && !path[3..].chars().any(|c| ":/\"<>|?*".contains(c))
        && path[3..].split('\\').all(|part| {
            !part.is_empty() && ![".", ".."].contains(&part) && !part.ends_with(['.', ' '])
        })
}
/// Internal workers receive the canonical name retained by Directory. Accept
/// its verbatim DOS prefix without broadening public scope/response paths.
/// This is syntax validation only; Directory::open still checks pinned ancestry,
/// directory type, reparse refusal and the private security descriptor.
pub fn worker_state_path(path: &str) -> bool {
    path.len() <= 1024 && drive_path(path.strip_prefix(r"\\?\").unwrap_or(path))
}
impl Scope {
    pub fn config(&self) -> Result<Configuration> {
        if self.roots.iter().any(|r| !drive_path(&r.dos)) {
            return Err("Windows scope needs absolute local drive paths".into());
        }
        Configuration::new(
            &self.roots.iter().map(|r| r.nt.clone()).collect::<Vec<_>>(),
            self.timeout_ms,
        )
    }
    pub fn digest(&self) -> Result<String> {
        Ok(athernex_endpoint_native::windows_filter::evidence::hex(
            &self.config()?.policy_sha256,
        ))
    }
    pub fn path(&self, nt: &str) -> Result<String> {
        let (root, tail) = self
            .roots
            .iter()
            .filter_map(|r| {
                suffix(nt, &r.nt)
                    .filter(|tail| !tail.is_empty())
                    .map(|tail| (r, tail))
            })
            .max_by_key(|(r, _)| r.nt.len())
            .ok_or("Windows decision is outside its registered scope")?;
        let result = format!("{}{}", root.dos, tail);
        if !drive_path(&result) {
            return Err("Windows decision cannot be represented as a local response path".into());
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub session: String,
    pub observation: Observation,
}
impl Receipt {
    pub fn id(&self) -> String {
        protocol::hash(
            format!(
                "windows-applied-v1:{}:{}:{}",
                self.session, self.observation.request_id, self.observation.policy_sha256
            )
            .as_bytes(),
        )
    }
    pub fn event(&self, scope: &Scope) -> Result<EndpointEvent> {
        self.observation.validate(now_ms())?;
        if !protocol::hex_id(&self.session)
            || self.observation.policy_sha256 != scope.digest()?
            || self.observation.outcome == "allowed"
        {
            return Err("Invalid Windows denial receipt or policy identity".into());
        }
        let event = EndpointEvent {
            id: self.id(),
            time_ms: self.observation.checked_ms,
            kind: if self.observation.detection.is_some() {
                "malware"
            } else {
                "agent_error"
            }
            .into(),
            path: scope.path(&self.observation.path)?,
            sha256: self.observation.sha256.clone(),
            detection: self.observation.detection.clone().unwrap_or_default(),
            detail: serde_json::to_string(self)?,
            telemetry: None,
        };
        event.validate(now_ms())?;
        Ok(event)
    }
}
pub struct Queue {
    connection: Connection,
}
impl Queue {
    /// The Windows caller must hold a pinned, private parent for this path.
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=8192; PRAGMA wal_autocheckpoint=128;")?;
        let tx = rusqlite::Transaction::new_unchecked(
            &connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let legacy: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='counters') AND NOT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='coverage_state')", [], |r| r.get(0))?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY,policy TEXT NOT NULL,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
            INSERT OR IGNORE INTO counters VALUES('lost',0);")?;
        coverage::initialize(&tx, legacy)?;
        responses::initialize(&tx)?;
        tx.commit()?;
        Ok(Self { connection })
    }
    pub fn register(&self, scope: &Scope) -> Result<()> {
        let digest = scope.digest()?;
        let raw = serde_json::to_string(scope)?;
        let tx = self.connection.unchecked_transaction()?;
        let prior: Option<String> = tx
            .query_row("SELECT payload FROM policies WHERE id=?1", [&digest], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(prior) = prior {
            if prior != raw {
                return Err("Windows policy mapping changed for an existing identity".into());
            }
        } else {
            // Retain every scope still referenced by pending decisions.
            tx.execute(
                "DELETE FROM policies WHERE id NOT IN (SELECT DISTINCT policy FROM decisions)",
                [],
            )?;
            let count: u64 = tx.query_row("SELECT count(*) FROM policies", [], |r| r.get(0))?;
            if count >= 64 {
                return Err("Windows evidence policy history is full".into());
            }
            tx.execute("INSERT INTO policies VALUES(?1,?2)", params![digest, raw])?;
        }
        tx.commit()?;
        Ok(())
    }
    fn scope(&self, id: &str) -> Result<Scope> {
        let raw: String =
            self.connection
                .query_row("SELECT payload FROM policies WHERE id=?1", [id], |r| {
                    r.get(0)
                })?;
        if raw.len() > 65536 {
            return Err("Windows evidence scope exceeds budget".into());
        }
        Ok(serde_json::from_str(&raw)?)
    }
    pub fn counts(&self) -> Result<(u64, u64)> {
        Ok((
            self.connection.query_row(
                "SELECT (SELECT count(*) FROM decisions)+(SELECT count(*) FROM coverage_events)",
                [],
                |r| r.get(0),
            )?,
            self.connection
                .query_row("SELECT value FROM counters WHERE name='lost'", [], |r| {
                    r.get(0)
                })?,
        ))
    }
    pub fn lost(&self, count: u64) -> Result<()> {
        if count > i64::MAX as u64 {
            return Err("Windows evidence loss counter overflow".into());
        }
        if count == 0 {
            return Ok(());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        tx.execute("UPDATE counters SET value=CASE WHEN value>9223372036854775807-?1 THEN 9223372036854775807 ELSE value+?1 END WHERE name='lost'", [count as i64])?;
        coverage::local_loss(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub fn record(&self, receipt: &Receipt) -> Result<()> {
        let scope = self.scope(&receipt.observation.policy_sha256)?;
        receipt.event(&scope)?;
        let id = receipt.id();
        let raw = serde_json::to_string(receipt)?;
        // Probe admission/consumption and management acknowledgement use other
        // connections. Acquire the writer slot before reading prior evidence.
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let previous: Option<String> = tx
            .query_row("SELECT payload FROM decisions WHERE id=?1", [&id], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(previous) = previous {
            if previous != raw {
                return Err("Windows decision replay changed immutable evidence".into());
            }
        } else {
            let count: u64 = tx.query_row("SELECT count(*) FROM decisions", [], |r| r.get(0))?;
            if count >= LIMIT {
                return Err("Windows evidence queue is full".into());
            }
            tx.execute(
                "INSERT INTO decisions VALUES(?1,?2,?3)",
                params![id, receipt.observation.policy_sha256, raw],
            )?;
        }
        responses::record(&tx, receipt)?;
        tx.commit()?;
        Ok(())
    }
    pub fn collect(&self, store: &Store) -> Result<()> {
        store.connection.execute_batch("CREATE TABLE IF NOT EXISTS windows_receipt_transfers(id TEXT PRIMARY KEY,sha256 TEXT NOT NULL);")?;
        let transfers = store
            .connection
            .prepare("SELECT id FROM windows_receipt_transfers LIMIT ?1")?
            .query_map([TRANSFER_LIMIT + 1], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if transfers.len() as u64 > TRANSFER_LIMIT {
            return Err("Windows transfer journal exceeds its capacity".into());
        }
        // Inspect the whole bounded journal: repeatedly checking only its first
        // live entries could hide retired entries and prevent all new transfers.
        let cleanup = store.connection.unchecked_transaction()?;
        for id in transfers {
            if !self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM decisions WHERE id=?1) OR EXISTS(SELECT 1 FROM coverage_events WHERE id=?1)",
                [&id],
                |r| r.get::<_, bool>(0),
            )? {
                cleanup.execute("DELETE FROM windows_receipt_transfers WHERE id=?1", [id])?;
            }
        }
        cleanup.commit()?;
        self.collect_coverage(store)?;
        let rows = self
            .connection
            .prepare("SELECT id,policy,payload FROM decisions ORDER BY rowid LIMIT 64")?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (id, policy, raw) in rows {
            if raw.len() > 4096 {
                return Err("Windows receipt exceeds its byte budget".into());
            }
            let receipt: Receipt = serde_json::from_str(&raw)?;
            if id != receipt.id() || policy != receipt.observation.policy_sha256 {
                return Err("Windows receipt identity changed".into());
            }
            let event = receipt.event(&self.scope(&policy)?)?;
            self.admit(store, &event, &raw)?;
            let deleted = self.connection.execute(
                "DELETE FROM decisions WHERE id=?1 AND payload=?2",
                params![id, raw],
            )?;
            if deleted != 1 {
                return Err("Windows receipt changed during acknowledgement".into());
            }
            store
                .connection
                .execute("DELETE FROM windows_receipt_transfers WHERE id=?1", [id])?;
        }
        Ok(())
    }
    fn admit(&self, store: &Store, event: &EndpointEvent, receipt: &str) -> Result<()> {
        let digest = protocol::hash(receipt.as_bytes());
        let raw = serde_json::to_string(event)?;
        let tx = store.connection.unchecked_transaction()?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT sha256 FROM windows_receipt_transfers WHERE id=?1",
                [&event.id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            if prior != digest {
                return Err("Windows receipt changed after durable transfer".into());
            }
        } else {
            let count: u64 =
                tx.query_row("SELECT count(*) FROM windows_receipt_transfers", [], |r| {
                    r.get(0)
                })?;
            if count >= TRANSFER_LIMIT {
                return Err("Windows transfer journal is full".into());
            }
            let existing: Option<String> = tx
                .query_row("SELECT payload FROM outbox WHERE id=?1", [&event.id], |r| {
                    r.get(0)
                })
                .optional()?;
            if let Some(existing) = existing {
                if existing != raw {
                    return Err("Windows event conflicts with existing outbox evidence".into());
                }
            } else {
                store.enqueue(event)?;
            }
            tx.execute(
                "INSERT INTO windows_receipt_transfers VALUES(?1,?2)",
                params![event.id, digest],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
