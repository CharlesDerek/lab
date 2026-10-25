use crate::{codec, model::*};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

pub type LabResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct LedgerOwner(std::fs::File);
impl Drop for LedgerOwner {
    fn drop(&mut self) {
        // Collector children may briefly inherit a file description before exec.
        let _ = self.0.unlock();
    }
}

pub struct Engine {
    pub(crate) connection: Connection,
    pub(crate) path: Option<PathBuf>,
    pub live: bool,
    pub demo: bool,
    pub storage_error: String,
    _owner: Option<LedgerOwner>,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub events: Vec<DisplayEvent>,
    pub findings: Vec<Finding>,
    pub plans: Vec<Plan>,
    pub audit: Vec<Audit>,
    pub enabled_rules: Vec<String>,
    pub payload_bytes: usize,
    pub normalized_json_bytes: usize,
    pub database_bytes: u64,
    pub wal_bytes: u64,
    pub dictionary_entries: usize,
    pub total_received: u64,
    pub duplicates: u64,
    pub live: bool,
    pub hive: crate::gateway::Hive,
    pub retention: crate::retention::Retention,
    pub memory: crate::memory::MemoryState,
    pub sources: Vec<crate::operations::Source>,
    pub cases: Vec<crate::operations::Case>,
    pub demo: bool,
    pub storage_error: String,
    pub selected_archive: Option<i64>,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

impl Engine {
    pub fn open(path: &Path) -> LabResult<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let owner = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(std::path::PathBuf::from(lock_path))?;
        owner
            .try_lock()
            .map_err(|_| "This ledger is already owned by another SIEM process")?;
        let owner = LedgerOwner(owner);
        // The ledger can hold outbound evidence credentials; create and restrict it before SQLite opens WAL files.
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        drop(file);
        let mut engine = Self::initialize(Connection::open(path)?, Some(path.to_path_buf()))?;
        engine._owner = Some(owner);
        Ok(engine)
    }

    pub fn memory() -> LabResult<Self> {
        Self::initialize(Connection::open_in_memory()?, None)
    }

    fn initialize(connection: Connection, path: Option<PathBuf>) -> LabResult<Self> {
        let version: u32 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 6 {
            return Err("Ledger schema is newer than this binary".into());
        }
        connection.busy_timeout(std::time::Duration::from_secs(3))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
             PRAGMA max_page_count=4096; PRAGMA journal_size_limit=2097152;
             PRAGMA wal_autocheckpoint=256;
             CREATE TABLE IF NOT EXISTS labels(id INTEGER PRIMARY KEY, value TEXT UNIQUE NOT NULL);
             CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, time_ms INTEGER NOT NULL, kind INTEGER NOT NULL, severity INTEGER NOT NULL, source INTEGER NOT NULL, subject INTEGER NOT NULL, payload BLOB NOT NULL, json_bytes INTEGER NOT NULL, dedup TEXT UNIQUE NOT NULL, input_hash BLOB NOT NULL);
             CREATE INDEX IF NOT EXISTS event_time ON events(time_ms);
             CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT UNIQUE NOT NULL, rule TEXT NOT NULL, title TEXT NOT NULL, severity INTEGER NOT NULL, subject TEXT NOT NULL, time_ms INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', explanation TEXT NOT NULL, evidence TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER UNIQUE NOT NULL REFERENCES findings(id) ON DELETE CASCADE, title TEXT NOT NULL, state TEXT NOT NULL, rationale TEXT NOT NULL, steps TEXT NOT NULL, evidence_hash TEXT NOT NULL, created_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, time_ms INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
             INSERT OR IGNORE INTO settings VALUES ('received',0),('duplicates',0);",
        )?;
        for rule in &RULES {
            connection.execute("INSERT OR IGNORE INTO settings VALUES (?1,1)", [rule.id])?;
        }
        let engine = Self {
            connection,
            path,
            live: false,
            demo: false,
            storage_error: String::new(),
            _owner: None,
        };
        engine.init_identity()?;
        engine.init_retention()?;
        engine.init_gateway()?;
        engine.init_operations()?;
        engine.init_storage()?;
        engine.init_memory()?;
        engine.init_evidence_transport()?;
        engine.init_fleet()?;
        engine.init_ecosystem()?;
        engine.init_signals()?;
        engine.init_investigator()?;
        engine.init_engine_fleet()?;
        engine.init_engine_rollouts()?;
        engine.init_background()?;
        engine.connection.execute_batch("PRAGMA user_version=6")?;
        Ok(engine)
    }

    pub(crate) fn audit(&self, action: &str, detail: &str, now: u64) -> LabResult<()> {
        let tx = if self.connection.is_autocommit() {
            Some(rusqlite::Transaction::new_unchecked(
                &self.connection,
                rusqlite::TransactionBehavior::Immediate,
            )?)
        } else {
            None
        };
        self.append_audit_chain(action, detail, now)?;
        self.connection.execute(
            "INSERT INTO audit(time_ms,action,detail) VALUES (?1,?2,?3)",
            params![now, action, detail],
        )?;
        self.connection.execute(
            "DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 256)",
            [],
        )?;
        if let Some(tx) = tx {
            tx.commit()?;
        }
        Ok(())
    }

    pub fn ingest(&mut self, inputs: &[InputEvent], now: u64) -> LabResult<usize> {
        if inputs.is_empty() || inputs.len() > MAX_BATCH {
            return Err("A batch must contain 1–256 events.".into());
        }
        for input in inputs {
            input.validate(now)?;
        }
        self.prepare_storage(now)?;
        if self.pending_count()? + inputs.len() > 512 {
            self.flush(now)?;
        }
        self.reserve_ids(inputs.len())?;
        // Immutable transaction access lets the detector share this same commit.
        // Runtime nesting is rejected by SQLite; the engine lock owns each operation.
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let lease = self.reserve_essential_work("ingest", now)?;
        let inserted = self.ingest_in_transaction(inputs, now)?;
        self.complete_essential_work(lease)?;
        tx.commit()?;
        Ok(inserted)
    }

    pub(crate) fn ingest_in_transaction(
        &self,
        inputs: &[InputEvent],
        now: u64,
    ) -> LabResult<usize> {
        if self.connection.is_autocommit() {
            return Err("Ingestion requires an active transaction".into());
        }
        let tx = &self.connection;
        let memory_config = self.memory_config()?;
        let mut inserted = 0;
        let mut duplicates = 0;
        for input in inputs {
            let dedup = format!("{}:{}", input.source, input.idempotency_key);
            let input_hash = Sha256::digest(serde_json::to_vec(input)?).to_vec();
            let previous: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT input_hash FROM all_evidence_refs WHERE dedup=?1 UNION ALL SELECT input_hash FROM events WHERE dedup=?1 LIMIT 1",
                    [&dedup],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(previous) = previous {
                if previous != input_hash {
                    return Err("Idempotency key reused with different event facts".into());
                }
                duplicates += 1;
                continue;
            }
            let mut ids = Vec::new();
            for value in [&input.source, &input.subject, &input.object] {
                let existing: Option<u32> = tx
                    .query_row("SELECT id FROM labels WHERE value=?1", [value], |r| {
                        r.get(0)
                    })
                    .optional()?;
                let id = match existing {
                    Some(id) => id,
                    None => {
                        let count: usize =
                            tx.query_row("SELECT count(*) FROM labels", [], |r| r.get(0))?;
                        if count >= MAX_LABELS {
                            return Err(
                                "Dictionary capacity exhausted; batch not acknowledged".into()
                            );
                        }
                        let available:u32=tx.query_row("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM labels WHERE id=1) THEN 1 ELSE (SELECT min(l.id+1) FROM labels l LEFT JOIN labels n ON n.id=l.id+1 WHERE n.id IS NULL) END",[],|r|r.get(0))?;
                        tx.execute(
                            "INSERT INTO labels(id,value) VALUES (?1,?2)",
                            params![available, value],
                        )?;
                        let id = tx.last_insert_rowid() as u32;
                        // Dictionary identities are durable metadata, preventing aliasing after a crash.
                        tx.execute(
                            "INSERT INTO main.labels(id,value) VALUES (?1,?2)",
                            params![id, value],
                        )?;
                        id
                    }
                };
                ids.push(id);
            }
            tx.execute("INSERT INTO events(time_ms,kind,severity,source,subject,payload,json_bytes,dedup,input_hash,outcome) VALUES (?1,?2,?3,?4,?5,x'',0,?6,?7,?8)", params![input.time_ms, input.kind as u8, input.severity, ids[0], ids[1], dedup, input_hash,input.outcome as u8])?;
            let event = Event {
                id: tx.last_insert_rowid() as u64,
                time_ms: input.time_ms,
                observed_ms: now,
                source: ids[0].try_into()?,
                subject: ids[1],
                object: ids[2],
                kind: input.kind,
                outcome: input.outcome,
                severity: input.severity,
                bytes: input.bytes,
                trace: input.trace,
            };
            let payload = codec::encode(&event);
            let json_bytes = serde_json::to_vec(&event)?.len();
            tx.execute(
                "UPDATE events SET payload=?1,json_bytes=?2 WHERE id=?3",
                params![payload, json_bytes, event.id],
            )?;
            tx.execute("INSERT INTO pending VALUES (?1)", [event.id])?;
            if let Some(context) = &input.context {
                tx.execute(
                    "INSERT INTO event_context VALUES (?1,?2)",
                    params![event.id, serde_json::to_string(context)?],
                )?;
            }
            if input.source == "agent-gateway" {
                tx.execute("UPDATE sources SET received=received+1,last_event_ms=?1,last_poll_ms=?1 WHERE id='agent-gateway'",[now])?;
            }
            let display = DisplayEvent {
                event: event.clone(),
                source_label: input.source.clone(),
                subject_label: input.subject.clone(),
                object_label: input.object.clone(),
                encoded_bytes: payload.len(),
                json_bytes,
                notation: String::new(),
                context: input.context.clone(),
            };
            self.preserve_event(&display, Some(&dedup), Some(&input_hash))?;
            if input.severity >= memory_config.trigger_severity
                || input.bytes >= memory_config.anomaly_bytes
            {
                self.correlate(event.id, now)?;
            }
            inserted += 1;
        }
        tx.execute(
            "UPDATE runtime_counts SET value=value+?1 WHERE key='received'",
            [inserted],
        )?;
        tx.execute(
            "UPDATE runtime_counts SET value=value+?1 WHERE key='duplicates'",
            [duplicates],
        )?;
        // Durable evidence references retain idempotency independently of the hot window.
        tx.execute(
            "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT max(0,(SELECT count(*) FROM events)-?1))",
            [MAX_EVENTS],
        )?;
        tx.execute(
            "DELETE FROM event_context WHERE event_id NOT IN (SELECT id FROM events)",
            [],
        )?;
        let last_finding: i64 =
            tx.query_row("SELECT coalesce(max(id),0) FROM findings", [], |r| r.get(0))?;
        self.detect()?;
        let alerts = tx
            .prepare(
                "SELECT id,rule,severity,evidence FROM findings WHERE id>?1 ORDER BY id LIMIT 128",
            )?
            .query_map([last_finding], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u8>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (id, rule, severity, raw) in alerts {
            let evidence: Vec<DisplayEvent> = serde_json::from_str(&raw)?;
            for e in &evidence {
                // Existing cases may include legacy facts; preserve them before linking.
                self.preserve_event(e, None, None)?;
                tx.execute(
                    "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
                    params![
                        format!("detection:{rule}:{id}"),
                        e.event.id,
                        e.event.time_ms
                    ],
                )?;
            }
            if let Some(e) = evidence.last() {
                self.correlate_signal(e.event.id, Some(severity), now)?;
            }
        }
        tx.execute("UPDATE main.settings SET value=(SELECT value FROM runtime_counts WHERE runtime_counts.key=settings.key) WHERE key IN ('received','duplicates')",[])?;
        self.maintain_memory(now)?;
        Ok(inserted)
    }

    pub fn events(&self) -> LabResult<Vec<DisplayEvent>> {
        self.read_hot_events(true)
    }

    fn read_hot_events(&self, include_observations: bool) -> LabResult<Vec<DisplayEvent>> {
        let mut labels: Option<HashMap<u32, String>> = None;
        let query = if include_observations {
            "SELECT e.payload,e.json_bytes,c.payload FROM events e LEFT JOIN event_context c ON c.event_id=e.id ORDER BY e.time_ms,e.id"
        } else {
            "SELECT e.payload,e.json_bytes,c.payload FROM events e LEFT JOIN event_context c ON c.event_id=e.id WHERE e.outcome IN(0,1) ORDER BY e.time_ms,e.id"
        };
        let mut statement = self.connection.prepare(query)?;
        let mut rows = statement.query([])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            let bytes: Vec<u8> = row.get(0)?;
            let event = codec::decode(&bytes)?;
            if !include_observations && event.outcome == Outcome::Observe {
                return Err("Hot detection index disagrees with encoded evidence".into());
            }
            if labels.is_none() {
                labels = Some(
                    self.connection
                        .prepare("SELECT id,value FROM labels")?
                        .query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?)))?
                        .collect::<Result<HashMap<_, _>, _>>()?,
                );
            }
            let label = |id: u32| -> LabResult<String> {
                labels
                    .as_ref()
                    .and_then(|labels| labels.get(&id))
                    .cloned()
                    .ok_or_else(|| "Missing identity dictionary entry".into())
            };
            let context: Option<String> = row.get(2)?;
            events.push(DisplayEvent {
                source_label: label(u32::from(event.source))?,
                subject_label: label(event.subject)?,
                object_label: label(event.object)?,
                notation: format!(
                    "{}{} s{}:{}→{}",
                    event.kind.code(),
                    event.outcome.symbol(),
                    event.severity,
                    event.subject,
                    event.object
                ),
                encoded_bytes: bytes.len(),
                json_bytes: row.get(1)?,
                context: context.map(|v| serde_json::from_str(&v)).transpose()?,
                event,
            });
        }
        Ok(events)
    }

    pub fn findings(&self) -> LabResult<Vec<Finding>> {
        let mut query = self.connection.prepare("SELECT id,rule,title,severity,subject,time_ms,status,explanation,evidence FROM findings ORDER BY time_ms DESC,id DESC")?;
        let rows = query.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u8>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, u64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?;
        rows.map(|row| {
            let (id, rule, title, severity, subject, time_ms, status, explanation, evidence) = row?;
            Ok(Finding {
                id,
                rule,
                title,
                severity,
                subject,
                time_ms,
                status,
                explanation,
                evidence: serde_json::from_str(&evidence)?,
            })
        })
        .collect()
    }

    pub fn plans(&self) -> LabResult<Vec<Plan>> {
        let mut query = self.connection.prepare("SELECT id,finding_id,title,state,rationale,steps,evidence_hash,created_ms,expires_ms FROM plans ORDER BY id DESC")?;
        let rows = query.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, u64>(7)?,
                r.get::<_, u64>(8)?,
            ))
        })?;
        rows.map(|row| {
            let (
                id,
                finding_id,
                title,
                state,
                rationale,
                steps,
                evidence_hash,
                created_ms,
                expires_ms,
            ) = row?;
            Ok(Plan {
                id,
                finding_id,
                title,
                state,
                rationale,
                steps: serde_json::from_str(&steps)?,
                evidence_hash,
                created_ms,
                expires_ms,
            })
        })
        .collect()
    }

    pub fn enabled_rules(&self) -> LabResult<Vec<String>> {
        Ok(self
            .connection
            .prepare("SELECT key FROM settings WHERE key LIKE 'AX-%' AND value=1 ORDER BY key")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?)
    }

    pub fn toggle_rule(&self, id: &str, now: u64) -> LabResult<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if !RULES.iter().any(|rule| rule.id == id) {
            return Err("Unknown rule".into());
        }
        self.connection
            .execute("UPDATE settings SET value=1-value WHERE key=?1", [id])?;
        self.audit("rule.changed", id, now)?;
        tx.commit()?;
        Ok(())
    }

    fn detect(&self) -> LabResult<()> {
        // These rules consume Allow/Deny facts only. The temporary outcome index
        // avoids scanning and expanding every passive observation per record.
        // Keep the same window and chronological order. Expiration is evaluated
        // at the next relevant fact, so omitted observations cannot extend it.
        self.detect_events(self.read_hot_events(false)?)
    }

    fn detect_events(&self, events: Vec<DisplayEvent>) -> LabResult<()> {
        #[derive(Default)]
        struct History {
            denied: VecDeque<DisplayEvent>,
            auth: Option<DisplayEvent>,
            process: Option<DisplayEvent>,
        }
        struct Candidate {
            fingerprint: String,
            rule: usize,
            current: DisplayEvent,
            evidence: Vec<DisplayEvent>,
        }
        let mut candidates: HashMap<String, Candidate> = HashMap::new();
        let enabled = self.enabled_rules()?;
        let mut subjects: HashMap<u32, History> = HashMap::new();
        for current in &events {
            let event = &current.event;
            let history = subjects.entry(event.subject).or_default();
            history
                .denied
                .retain(|prior| event.time_ms.saturating_sub(prior.event.time_ms) <= 120_000);
            let mut matches: Vec<(usize, Vec<DisplayEvent>)> = Vec::new();
            if event.kind == Kind::Authentication && event.outcome == Outcome::Deny {
                history.denied.push_back(current.clone());
                while history.denied.len() > 8 {
                    history.denied.pop_front();
                }
                if history.denied.len() == 8 {
                    matches.push((0, history.denied.iter().cloned().collect()));
                }
            }
            if event.kind == Kind::Authentication && event.outcome == Outcome::Allow {
                history.auth = Some(current.clone());
            }
            if event.kind == Kind::Process && event.severity >= 4 && event.outcome == Outcome::Allow
            {
                if let Some(auth) = &history.auth {
                    if event.time_ms.saturating_sub(auth.event.time_ms) <= 60_000 {
                        matches.push((1, vec![auth.clone(), current.clone()]));
                    }
                }
                history.process = Some(current.clone());
            }
            if event.kind == Kind::Network
                && event.outcome == Outcome::Allow
                && event.bytes >= 10 * 1024 * 1024
            {
                if let Some(process) = &history.process {
                    if event.time_ms.saturating_sub(process.event.time_ms) <= 180_000 {
                        matches.push((2, vec![process.clone(), current.clone()]));
                    }
                }
            }
            if event.kind == Kind::Policy && event.outcome == Outcome::Deny && event.severity >= 3 {
                matches.push((3, vec![current.clone()]));
            }
            if event.kind == Kind::System
                && event.outcome == Outcome::Deny
                && event.severity >= 3
                && current
                    .context
                    .as_ref()
                    .is_some_and(|c| c.pid == Some(1) && c.uid == Some(0) && c.program == "systemd")
            {
                matches.push((4, vec![current.clone()]));
            }
            for (index, evidence) in matches {
                let rule = &RULES[index];
                if !enabled.iter().any(|id| id == rule.id) {
                    continue;
                }
                let group = if event.trace > 0 {
                    u64::from(event.trace)
                } else {
                    event.time_ms / 180_000
                };
                let fingerprint = if index == 4 {
                    hash(
                        format!("{}:{}:{group}:{}", rule.id, event.subject, event.object)
                            .as_bytes(),
                    )
                } else {
                    hash(format!("{}:{}:{group}", rule.id, event.subject).as_bytes())
                };
                candidates
                    .entry(fingerprint.clone())
                    .or_insert_with(|| Candidate {
                        fingerprint,
                        rule: index,
                        current: current.clone(),
                        evidence,
                    });
            }
        }
        let mut candidates = candidates.into_values().collect::<Vec<_>>();
        candidates
            .sort_by_key(|candidate| (candidate.current.event.time_ms, candidate.current.event.id));
        // Select the retained horizon before writes, so old matches cannot churn
        // findings and audit records on every new event after the budget fills.
        let candidates = candidates.split_off(candidates.len().saturating_sub(MAX_FINDINGS));
        for candidate in candidates {
            let rule = &RULES[candidate.rule];
            let current = &candidate.current;
            let evidence = &candidate.evidence;
            let explanation = format!("{} Matched {} retained fact(s) for {}. This is a deterministic signal; investigate context before attributing intent.",rule.description,evidence.len(),current.subject_label);
            let changed = self.connection.execute("INSERT OR IGNORE INTO findings(fingerprint,rule,title,severity,subject,time_ms,explanation,evidence) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![candidate.fingerprint,rule.id,rule.title,rule.severity,current.subject_label,current.event.time_ms,explanation,serde_json::to_string(evidence)?])?;
            if changed > 0 {
                self.sync_case(
                    self.connection.last_insert_rowid(),
                    rule.title,
                    rule.severity,
                    &serde_json::to_string(evidence)?,
                    current.event.observed_ms,
                )?;
                self.audit(
                    "detection.matched",
                    &format!(
                        "{} · {} · {} facts",
                        rule.id,
                        current.subject_label,
                        evidence.len()
                    ),
                    current.event.observed_ms,
                )?;
            }
        }
        self.connection.execute("DELETE FROM findings WHERE id NOT IN (SELECT id FROM findings ORDER BY id DESC LIMIT ?1)", [MAX_FINDINGS])?;
        Ok(())
    }

    pub fn propose(&self, finding_id: i64, now: u64) -> LabResult<i64> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let finding = self
            .findings()?
            .into_iter()
            .find(|f| f.id == finding_id)
            .ok_or("Finding not found")?;
        if finding.status != "open" {
            return Err("Only open findings can create a plan".into());
        }
        if let Some(plan) = self.plans()?.iter().find(|p| p.finding_id == finding_id) {
            return Ok(plan.id);
        }
        let pending: usize = self.connection.query_row(
            "SELECT count(*) FROM plans WHERE state IN ('awaiting_review','approved')",
            [],
            |r| r.get(0),
        )?;
        if pending >= 16 {
            return Err("Review budget reached: finish or reject pending plans first".into());
        }
        let steps = vec![format!("Preserve {} normalized evidence facts and their AEF1 dictionary context.",finding.evidence.len()),format!("Review the {} signal for {} and verify the approved workload baseline.",finding.rule,finding.subject),"Simulate a scoped containment proposal. No network, host, or power action is executed.".into(),"Record the review decision and require new evidence before any private deployment.".into()];
        let steps = if self.demo {
            steps
        } else {
            vec![format!("Verify the {} copied facts attached to this finding.",finding.evidence.len()),"On execution: move its investigation to triage and append a durable review receipt.".into(),"This action only changes the investigation. Agent quarantine remains an explicit identity control.".into()]
        };
        let rationale = format!("Evidence policy v1 selected a bounded investigation for {}. {} The planner is deterministic; no language model generated this plan.",finding.title,finding.explanation);
        let evidence_hash = hash(serde_json::to_string(&finding.evidence)?.as_bytes());
        self.connection.execute("INSERT INTO plans(finding_id,title,state,rationale,steps,evidence_hash,created_ms,expires_ms) VALUES (?1,?2,'awaiting_review',?3,?4,?5,?6,?7)",params![finding_id,format!("Review {}",finding.subject),rationale,serde_json::to_string(&steps)?,evidence_hash,now,now+900_000])?;
        let id = self.connection.last_insert_rowid();
        self.audit(
            "plan.proposed",
            &format!("plan-{id} · finding-{finding_id} · human review required"),
            now,
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn review_plan(&self, id: i64, action: &str, now: u64) -> LabResult<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let plan = self
            .plans()?
            .into_iter()
            .find(|p| p.id == id)
            .ok_or("Plan not found")?;
        let next = match (plan.state.as_str(),action) {
            ("awaiting_review","approve") => "approved",
            ("awaiting_review" | "approved","reject") => "rejected",
            ("approved","simulate") if self.demo => "simulation_complete",
            ("approved","execute") if !self.demo => "executed",
            _ => return Err("Transition refused: approval must precede execution and terminal plans cannot replay".into()),
        };
        if action != "reject" {
            if now >= plan.expires_ms {
                return Err("Plan expired; reject it and investigate current evidence".into());
            }
            let finding = self
                .findings()?
                .into_iter()
                .find(|f| f.id == plan.finding_id)
                .ok_or("Evidence unavailable")?;
            if finding.status != "open"
                || hash(serde_json::to_string(&finding.evidence)?.as_bytes()) != plan.evidence_hash
            {
                return Err("Evidence changed or finding is closed; approval is invalid".into());
            }
        }
        if action == "execute" {
            let case = self
                .cases()?
                .into_iter()
                .find(|c| c.finding_id == Some(plan.finding_id))
                .ok_or("Investigation unavailable")?;
            if !crate::operations::case_open(&case.status) {
                return Err("Investigation is closed".into());
            }
            let count: u64 = self.connection.query_row(
                "SELECT count(*) FROM case_notes WHERE case_id=?1",
                [case.id],
                |r| r.get(0),
            )?;
            if count >= 64 {
                return Err("Investigation note budget reached".into());
            }
            self.connection.execute(
                "UPDATE cases SET status='triage',updated_ms=?1,version=version+1 WHERE id=?2",
                params![now, case.id],
            )?;
            self.connection.execute(
                "INSERT INTO case_notes(case_id,time_ms,text) VALUES (?1,?2,?3)",
                params![
                    case.id,
                    now,
                    format!(
                        "Reviewed plan {id}; evidence SHA-256 {}. Investigation moved to triage.",
                        plan.evidence_hash
                    )
                ],
            )?;
        }
        let changed = self.connection.execute(
            "UPDATE plans SET state=?1 WHERE id=?2 AND state=?3",
            params![next, id, plan.state],
        )?;
        if changed != 1 {
            return Err("Concurrent plan transition refused".into());
        }
        self.audit(
            &format!("plan.{next}"),
            &format!("plan-{id} · {next} · evidence and deadline verified"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn close_finding(&self, id: i64, now: u64) -> LabResult<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if self.connection.execute(
            "UPDATE findings SET status='resolved' WHERE id=?1 AND status='open'",
            [id],
        )? != 1
        {
            return Err("Finding is missing or already resolved".into());
        }
        self.connection.execute("UPDATE plans SET state='rejected' WHERE finding_id=?1 AND state IN ('awaiting_review','approved')",[id])?;
        self.connection.execute("UPDATE cases SET status='resolved',updated_ms=?1,version=version+1 WHERE finding_id=?2",params![now,id])?;
        self.audit(
            "finding.resolved",
            &format!("finding-{id} · analyst disposition"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn snapshot(&self) -> LabResult<Snapshot> {
        let events = self.events()?;
        let payload_bytes = events.iter().map(|e| e.encoded_bytes).sum();
        let normalized_json_bytes = events.iter().map(|e| e.json_bytes).sum();
        let pages: u64 = self
            .connection
            .query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let page_size: u64 = self
            .connection
            .query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let wal_bytes = self
            .path
            .as_ref()
            .and_then(|path| std::fs::metadata(format!("{}-wal", path.display())).ok())
            .map(|m| m.len())
            .unwrap_or(0);
        let audit = self
            .connection
            .prepare("SELECT time_ms,action,detail FROM audit ORDER BY id DESC LIMIT 40")?
            .query_map([], |r| {
                Ok(Audit {
                    time_ms: r.get(0)?,
                    action: r.get(1)?,
                    detail: r.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(Snapshot {
            events,
            findings: self.findings()?,
            plans: self.plans()?,
            audit,
            enabled_rules: self.enabled_rules()?,
            payload_bytes,
            normalized_json_bytes,
            database_bytes: pages * page_size,
            wal_bytes,
            dictionary_entries: self.connection.query_row(
                "SELECT count(*) FROM labels",
                [],
                |r| r.get(0),
            )?,
            total_received: self.connection.query_row(
                "SELECT value FROM runtime_counts WHERE key='received'",
                [],
                |r| r.get(0),
            )?,
            duplicates: self.connection.query_row(
                "SELECT value FROM runtime_counts WHERE key='duplicates'",
                [],
                |r| r.get(0),
            )?,
            live: self.live,
            hive: self.hive(now_ms())?,
            retention: self.retention()?,
            memory: self.memory_state()?,
            sources: self.sources()?,
            cases: self.cases()?,
            demo: self.demo,
            storage_error: self.storage_error.clone(),
            selected_archive: None,
        })
    }

    pub fn seed(&mut self, now: u64) -> LabResult<()> {
        let count: usize = self
            .connection
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        if count > 0 {
            return Ok(());
        }
        for batch in 0..3 {
            let events: Vec<_> = (0..160)
                .map(|i| {
                    let n = batch * 160 + i;
                    self.normal_event(n, now.saturating_sub((480 - n) * 2500), 1)
                })
                .collect();
            self.ingest(&events, now)?;
        }
        self.scenario_at("chain", now.saturating_sub(60_000), now)?;
        self.scenario_at("policy", now.saturating_sub(15_000), now)?;
        self.audit(
            "lab.seeded",
            "Synthetic sources only · bounded retention · no raw logs",
            now,
        )
    }

    fn normal_event(&self, n: u64, time_ms: u64, trace: u32) -> InputEvent {
        let kind = match n % 10 {
            0..=2 => Kind::Authentication,
            3..=6 => Kind::Network,
            7..=8 => Kind::Process,
            _ => Kind::Heartbeat,
        };
        InputEvent {
            time_ms,
            source: [
                "edge-sensor",
                "identity-sensor",
                "runtime-sensor",
                "control-sensor",
            ][(n % 4) as usize]
                .into(),
            subject: format!("service-{:02}", n % 12),
            object: [
                "artifact-store",
                "compute-pool",
                "service-mesh",
                "control-api",
            ][(n % 4) as usize]
                .into(),
            kind,
            outcome: if n.is_multiple_of(37) {
                Outcome::Deny
            } else {
                Outcome::Allow
            },
            severity: if n.is_multiple_of(37) { 2 } else { 1 },
            bytes: if kind == Kind::Network {
                1024 + (n * 137) % 65_536
            } else {
                0
            },
            trace,
            idempotency_key: format!("baseline-{trace}-{n}-{time_ms}"),
            context: None,
        }
    }

    pub fn tick(&mut self, now: u64) -> LabResult<()> {
        self.tick_endpoint_rollouts(now)?;
        self.tick_engine_rollouts(now)?;
        self.maintain_memory(now)?;
        if now.saturating_sub(self.setting("last_flush")?) >= self.setting("flush_seconds")? * 1000
            && (self.pending_count()? > 0
                || self.archive_expired(now)?
                || self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM source_cursors)",
                    [],
                    |r| r.get::<_, bool>(0),
                )?)
        {
            self.flush(now)?;
        }
        if !self.demo || !self.live {
            return Ok(());
        }
        let serial: u64 =
            self.connection
                .query_row("SELECT COALESCE(MAX(id),0)+1 FROM events", [], |r| r.get(0))?;
        let events = (0..5)
            .map(|i| self.normal_event(serial + i, now, 0))
            .collect::<Vec<_>>();
        self.ingest(&events, now)?;
        Ok(())
    }

    pub fn scenario(&mut self, name: &str, now: u64) -> LabResult<usize> {
        self.scenario_at(name, now, now)
    }

    fn scenario_at(&mut self, name: &str, end: u64, now: u64) -> LabResult<usize> {
        if !["chain", "auth", "policy", "normal"].contains(&name) {
            return Err("Unknown scenario".into());
        }
        let serial: u64 =
            self.connection
                .query_row("SELECT COALESCE(MAX(id),0)+1 FROM events", [], |r| r.get(0))?;
        let trace = u32::try_from(serial)?;
        if name == "normal" {
            let events = (0..48)
                .map(|i| self.normal_event(serial + i, end.saturating_sub((48 - i) * 100), trace))
                .collect::<Vec<_>>();
            return self.ingest(&events, now);
        }
        let mut events = Vec::new();
        let subject = format!("operator-{trace:04}");
        if name == "chain" || name == "auth" {
            for i in 0..9 {
                events.push(InputEvent {
                    time_ms: end.saturating_sub(50_000 - i * 4000),
                    source: "identity-sensor".into(),
                    subject: subject.clone(),
                    object: "control-api".into(),
                    kind: Kind::Authentication,
                    outcome: Outcome::Deny,
                    severity: 3,
                    bytes: 0,
                    trace,
                    idempotency_key: format!("scenario-{trace}-{i}"),
                    context: None,
                });
            }
        }
        if name == "chain" {
            for (i, kind, outcome, severity, bytes, object) in [
                (
                    10,
                    Kind::Authentication,
                    Outcome::Allow,
                    2,
                    0,
                    "control-api",
                ),
                (11, Kind::Process, Outcome::Allow, 5, 0, "privileged-worker"),
                (
                    12,
                    Kind::Network,
                    Outcome::Allow,
                    5,
                    32 * 1024 * 1024,
                    "external-sink",
                ),
            ] {
                events.push(InputEvent {
                    time_ms: end.saturating_sub((12 - i) * 3000),
                    source: if kind == Kind::Authentication {
                        "identity-sensor"
                    } else {
                        "runtime-sensor"
                    }
                    .into(),
                    subject: subject.clone(),
                    object: object.into(),
                    kind,
                    outcome,
                    severity,
                    bytes,
                    trace,
                    idempotency_key: format!("scenario-{trace}-{i}"),
                    context: None,
                });
            }
        }
        if name == "policy" {
            events.push(InputEvent {
                time_ms: end,
                source: "control-sensor".into(),
                subject,
                object: "power-policy".into(),
                kind: Kind::Policy,
                outcome: Outcome::Deny,
                severity: 4,
                bytes: 0,
                trace,
                idempotency_key: format!("scenario-{trace}-policy"),
                context: None,
            });
        }
        let inserted = self.ingest(&events, now)?;
        self.audit(
            "scenario.injected",
            &format!("{name} · {inserted} synthetic events · trace {trace}"),
            now,
        )?;
        Ok(inserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_800_000_000_000;
    #[test]
    fn restored_detection_index_preserves_denials_and_passive_originals() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ledger.sqlite3");
        let mut lab = Engine::open(&path).unwrap();
        lab.toggle_rule("AX-001", NOW).unwrap();
        lab.scenario("auth", NOW).unwrap();
        let mut passive = lab.normal_event(100, NOW, 100);
        passive.kind = Kind::Authentication;
        passive.outcome = Outcome::Observe;
        lab.ingest(std::slice::from_ref(&passive), NOW).unwrap();
        let original = serde_json::to_value(lab.events().unwrap()).unwrap();
        lab.flush(NOW).unwrap();
        drop(lab);
        let mut lab = Engine::open(&path).unwrap();
        assert_eq!(
            original,
            serde_json::to_value(lab.events().unwrap()).unwrap()
        );
        assert!(lab.findings().unwrap().is_empty());
        lab.toggle_rule("AX-001", NOW).unwrap();
        passive.idempotency_key.push_str("-after-restart");
        lab.ingest(&[passive], NOW).unwrap();
        assert_eq!(lab.findings().unwrap().len(), 1);
        assert_eq!(lab.findings().unwrap()[0].rule, "AX-001");
    }
    #[test]
    fn compact_detection_matches_full_history_with_passive_and_late_facts() {
        let mut compact = Engine::memory().unwrap();
        let mut full = Engine::memory().unwrap();
        for lab in [&mut compact, &mut full] {
            for rule in RULES {
                lab.toggle_rule(rule.id, NOW).unwrap();
            }
            lab.scenario("chain", NOW).unwrap();
            lab.scenario("policy", NOW).unwrap();
            let mut service = lab.normal_event(900, NOW, 900);
            service.kind = Kind::System;
            service.outcome = Outcome::Deny;
            service.severity = 4;
            service.context = Some(EventContext {
                host: "fixture".into(),
                program: "systemd".into(),
                pid: Some(1),
                uid: Some(0),
                parent_pid: None,
                process_start_ms: None,
                parent_start_ms: None,
                summary: "Controlled service failure".into(),
                journal_cursor: String::new(),
            });
            lab.ingest(&[service], NOW).unwrap();
            // Eight denials separated by an expired window must stay quiet.
            let mut facts: Vec<_> = (0..8)
                .map(|i| {
                    let mut event = lab.normal_event(
                        1000 + i,
                        if i == 7 {
                            NOW - 1
                        } else {
                            NOW - 240_000 + i * 1000
                        },
                        901,
                    );
                    event.subject = "expired-account".into();
                    event.kind = Kind::Authentication;
                    event.outcome = Outcome::Deny;
                    event
                })
                .collect();
            // Insert observations late and out of chronological order, including
            // the same subjects as both the positive and expired controls.
            facts.extend((0..120).map(|i| {
                let mut event = lab.normal_event(2000 + i, NOW - i * 2000, 902);
                event.kind = [
                    Kind::Authentication,
                    Kind::Process,
                    Kind::Network,
                    Kind::Policy,
                    Kind::System,
                ][i as usize % 5];
                event.outcome = Outcome::Observe;
                event.subject = if i % 2 == 0 {
                    "expired-account"
                } else {
                    "operator-0001"
                }
                .into();
                event
            }));
            lab.ingest(&facts, NOW).unwrap();
            assert!(lab.findings().unwrap().is_empty());
            for rule in RULES {
                lab.toggle_rule(rule.id, NOW).unwrap();
            }
        }
        compact.detect().unwrap();
        full.detect_events(full.events().unwrap()).unwrap();
        let actual = compact.findings().unwrap();
        assert_eq!(actual.len(), 5);
        for id in ["AX-001", "AX-002", "AX-003", "AX-004", "AX-005"] {
            assert!(actual.iter().any(|finding| finding.rule == id));
        }
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(full.findings().unwrap()).unwrap()
        );
        // Passive facts remain queryable and retain exact immutable originals.
        for event in compact.events().unwrap() {
            assert_eq!(
                serde_json::to_value(&event).unwrap(),
                serde_json::to_value(compact.reconstruct(event.event.id).unwrap()).unwrap()
            );
        }
    }
    #[test]
    fn attack_chain_correlates_and_normal_traffic_does_not() {
        let mut lab = Engine::memory().unwrap();
        lab.scenario("normal", NOW).unwrap();
        assert!(lab.findings().unwrap().is_empty());
        lab.scenario("chain", NOW).unwrap();
        let findings = lab.findings().unwrap();
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| !f.evidence.is_empty()));
        lab.detect().unwrap();
        assert_eq!(lab.findings().unwrap().len(), 3);
    }
    #[test]
    fn duplicate_and_invalid_batches_are_atomic() {
        let mut lab = Engine::memory().unwrap();
        let input = lab.normal_event(1, NOW, 1);
        assert_eq!(lab.ingest(std::slice::from_ref(&input), NOW).unwrap(), 1);
        assert_eq!(lab.ingest(std::slice::from_ref(&input), NOW).unwrap(), 0);
        let mut invalid = lab.normal_event(2, NOW, 1);
        invalid.subject = "<script>".into();
        assert!(lab
            .ingest(&[lab.normal_event(3, NOW, 1), invalid], NOW)
            .is_err());
        assert_eq!(lab.events().unwrap().len(), 1);
        assert_eq!(lab.snapshot().unwrap().duplicates, 1);
    }
    #[test]
    fn review_requires_approval_rejects_expiry_and_prevents_replay() {
        let mut lab = Engine::memory().unwrap();
        lab.scenario("chain", NOW).unwrap();
        let finding = lab.findings().unwrap()[0].id;
        let id = lab.propose(finding, NOW).unwrap();
        lab.demo = true;
        assert!(lab.review_plan(id, "simulate", NOW).is_err());
        assert!(lab.review_plan(id, "approve", NOW + 900_000).is_err());
        lab.review_plan(id, "approve", NOW + 1).unwrap();
        lab.review_plan(id, "simulate", NOW + 2).unwrap();
        assert!(lab.review_plan(id, "simulate", NOW + 3).is_err());
    }
    #[test]
    fn persisted_evidence_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lab.sqlite3");
        let mut lab = Engine::open(&path).unwrap();
        lab.scenario("chain", NOW).unwrap();
        lab.flush(NOW).unwrap();
        let before = lab.snapshot().unwrap();
        drop(lab);
        let after = Engine::open(&path).unwrap().snapshot().unwrap();
        assert_eq!(before.events.len(), after.events.len());
        assert_eq!(
            before.findings[0].evidence[0].event,
            after.findings[0].evidence[0].event
        );
    }
    #[test]
    fn late_events_correlate_and_disabled_rule_stays_quiet() {
        let mut lab = Engine::memory().unwrap();
        lab.toggle_rule("AX-001", NOW).unwrap();
        lab.scenario("chain", NOW).unwrap();
        assert_eq!(lab.findings().unwrap().len(), 2);
        let mut auth = lab.normal_event(44, NOW - 1000, 42);
        auth.subject = "late-actor".into();
        auth.kind = Kind::Authentication;
        auth.outcome = Outcome::Allow;
        let mut process = auth.clone();
        process.time_ms = NOW;
        process.idempotency_key = "late-process".into();
        process.kind = Kind::Process;
        process.severity = 5;
        lab.ingest(&[process], NOW).unwrap();
        lab.ingest(&[auth], NOW).unwrap();
        assert!(lab
            .findings()
            .unwrap()
            .iter()
            .any(|f| f.subject == "late-actor" && f.rule == "AX-002"));
    }
    #[test]
    fn closed_finding_invalidates_pending_approval() {
        let mut lab = Engine::memory().unwrap();
        lab.scenario("auth", NOW).unwrap();
        let finding = lab.findings().unwrap()[0].id;
        let plan = lab.propose(finding, NOW).unwrap();
        lab.close_finding(finding, NOW).unwrap();
        assert!(lab.review_plan(plan, "approve", NOW).is_err());
    }

    #[test]
    fn conflicting_idempotency_rolls_back_the_entire_batch() {
        let mut lab = Engine::memory().unwrap();
        let original = lab.normal_event(1, NOW, 1);
        lab.ingest(std::slice::from_ref(&original), NOW).unwrap();
        let mut conflicting = original;
        conflicting.severity = 5;
        assert!(lab
            .ingest(&[lab.normal_event(2, NOW, 1), conflicting], NOW)
            .is_err());
        assert_eq!(lab.events().unwrap().len(), 1);
        assert_eq!(lab.snapshot().unwrap().total_received, 1);
    }

    #[test]
    fn detection_write_failure_rolls_back_events_and_counters() {
        let mut lab = Engine::memory().unwrap();
        lab.connection.execute_batch("CREATE TRIGGER fail_finding BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;").unwrap();
        assert!(lab.scenario("chain", NOW).is_err());
        assert!(lab.events().unwrap().is_empty());
        assert_eq!(lab.snapshot().unwrap().total_received, 0);
    }

    #[test]
    fn bounded_event_rotation_preserves_finding_evidence() {
        let mut lab = Engine::memory().unwrap();
        lab.scenario("chain", NOW).unwrap();
        let evidence = lab.findings().unwrap()[0].evidence[0].event.clone();
        for batch in 0..17 {
            let inputs = (0..256)
                .map(|i| lab.normal_event(batch * 256 + i, NOW, 400))
                .collect::<Vec<_>>();
            lab.ingest(&inputs, NOW).unwrap();
        }
        let snapshot = lab.snapshot().unwrap();
        assert_eq!(snapshot.events.len(), MAX_EVENTS);
        assert!(!snapshot
            .events
            .iter()
            .any(|item| item.event.id == evidence.id));
        assert!(snapshot
            .findings
            .iter()
            .flat_map(|finding| &finding.evidence)
            .any(|item| item.event == evidence));
        assert!(snapshot.database_bytes < 16 * 1024 * 1024);
    }

    #[test]
    fn finding_budget_does_not_churn_on_repeated_evaluation() {
        let mut lab = Engine::memory().unwrap();
        let inputs = (0..200)
            .map(|i| {
                let mut event = lab.normal_event(i, NOW, i as u32 + 1);
                event.kind = Kind::Policy;
                event.outcome = Outcome::Deny;
                event.severity = 4;
                event
            })
            .collect::<Vec<_>>();
        lab.ingest(&inputs, NOW).unwrap();
        let before = lab
            .findings()
            .unwrap()
            .iter()
            .map(|f| f.id)
            .collect::<Vec<_>>();
        assert_eq!(before.len(), MAX_FINDINGS);
        lab.detect().unwrap();
        let after = lab
            .findings()
            .unwrap()
            .iter()
            .map(|f| f.id)
            .collect::<Vec<_>>();
        assert_eq!(before, after);
    }

    #[test]
    fn authentication_threshold_and_time_window_have_negative_controls() {
        let mut lab = Engine::memory().unwrap();
        let mut inputs = Vec::new();
        for i in 0..7 {
            let mut event = lab.normal_event(i, NOW - 130_000, 1);
            event.subject = "negative-control".into();
            event.kind = Kind::Authentication;
            event.outcome = Outcome::Deny;
            inputs.push(event);
        }
        lab.ingest(&inputs, NOW).unwrap();
        assert!(lab.findings().unwrap().is_empty());
        let mut late = inputs[0].clone();
        late.time_ms = NOW;
        late.idempotency_key = "eighth-outside-window".into();
        lab.ingest(&[late], NOW).unwrap();
        assert!(lab.findings().unwrap().is_empty());
    }
}
