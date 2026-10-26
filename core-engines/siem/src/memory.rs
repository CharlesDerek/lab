//! Durable content-addressed evidence and a bounded, disk-indexed investigation graph.
//! All writes participate in the existing ingestion transaction. RAM caches are TEMP tables.
use crate::{
    codec,
    engine::{Engine, LabResult},
    model::*,
};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    io::{Read, Write},
};

pub const DAY: u64 = 86_400_000;
pub const MAX_OBJECT: usize = 16_384;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryConfig {
    pub hot_ms: u64,
    pub hot_events: usize,
    pub hot_bytes: usize,
    pub context_ms: u64,
    pub context_events: usize,
    pub context_bytes: usize,
    pub max_depth: usize,
    pub fan_out: usize,
    pub max_candidates: usize,
    pub trigger_severity: u8,
    pub anomaly_bytes: u64,
    pub promotion_score: u32,
    pub severity_weight: u32,
    pub identity_weight: u32,
    pub endpoint_weight: u32,
    pub process_weight: u32,
    pub destination_weight: u32,
    pub behavior_weight: u32,
    pub temporal_weight: u32,
    pub context_weight: u32,
}
impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            hot_ms: 2 * DAY,
            hot_events: MAX_EVENTS,
            hot_bytes: 8 * 1024 * 1024,
            context_ms: 30 * 60_000,
            context_events: 128,
            context_bytes: 1024 * 1024,
            max_depth: 2,
            fan_out: 32,
            max_candidates: 128,
            trigger_severity: 4,
            anomaly_bytes: 10 * 1024 * 1024,
            promotion_score: 50,
            severity_weight: 5,
            identity_weight: 30,
            endpoint_weight: 10,
            process_weight: 30,
            destination_weight: 20,
            behavior_weight: 15,
            temporal_weight: 10,
            context_weight: 10,
        }
    }
}
impl MemoryConfig {
    pub fn validate(&self) -> LabResult<()> {
        if !(1000..=365 * DAY).contains(&self.hot_ms)
            || !(1..=MAX_EVENTS).contains(&self.hot_events)
            || !(2048..=64 * 1024 * 1024).contains(&self.hot_bytes)
            || !(1000..=DAY).contains(&self.context_ms)
            || !(1..=512).contains(&self.context_events)
            || !(2048..=8 * 1024 * 1024).contains(&self.context_bytes)
            || !(1..=4).contains(&self.max_depth)
            || !(1..=128).contains(&self.fan_out)
            || !(1..=512).contains(&self.max_candidates)
            || !(1..=5).contains(&self.trigger_severity)
            || !(1..=1 << 50).contains(&self.anomaly_bytes)
            || self.promotion_score > 1000
            || [
                self.severity_weight,
                self.identity_weight,
                self.endpoint_weight,
                self.process_weight,
                self.destination_weight,
                self.behavior_weight,
                self.temporal_weight,
                self.context_weight,
            ]
            .iter()
            .any(|w| *w > 100)
        {
            return Err("Invalid investigative memory budget or relevance weight".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relevance {
    pub event_id: u64,
    pub trigger_id: u64,
    pub score: u32,
    pub reasons: Vec<String>,
    pub path: Vec<u64>,
    pub computed_ms: u64,
    pub status: String,
}
#[derive(Debug, Serialize)]
pub struct ContextEvent {
    pub evidence: DisplayEvent,
    pub relevance: Relevance,
    pub expires_ms: u64,
}
#[derive(Debug, Serialize)]
pub struct MemoryState {
    pub config: MemoryConfig,
    pub references: u64,
    pub objects: u64,
    pub object_bytes: u64,
    pub graph_links: u64,
    pub hot_events: u64,
    pub hot_bytes: u64,
    pub context_bytes: u64,
    pub context: Vec<ContextEvent>,
    pub recent_relevance: Vec<Relevance>,
}
#[derive(Serialize, Deserialize)]
struct Template {
    source: String,
    subject: String,
    object: String,
    context: Option<EventContext>,
    description: Vec<u8>,
}

pub fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(value: &str) -> LabResult<Vec<u8>> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Expected SHA-256 digest".into());
    }
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}

impl Engine {
    pub(crate) fn init_memory(&self) -> LabResult<()> {
        self.connection.execute_batch("PRAGMA cache_size=-4096; PRAGMA mmap_size=0;
            CREATE TABLE IF NOT EXISTS memory_config(id INTEGER PRIMARY KEY CHECK(id=1),json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence_objects(hash BLOB PRIMARY KEY CHECK(length(hash)=32),payload BLOB NOT NULL,raw_bytes INTEGER NOT NULL) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS evidence_refs(id INTEGER PRIMARY KEY,hash BLOB UNIQUE NOT NULL,time_ms INTEGER NOT NULL,observed_ms INTEGER NOT NULL,source TEXT NOT NULL,subject TEXT NOT NULL,severity INTEGER NOT NULL,dedup TEXT UNIQUE,input_hash BLOB);
            CREATE INDEX IF NOT EXISTS evidence_time ON evidence_refs(time_ms,id);
            CREATE INDEX IF NOT EXISTS evidence_subject ON evidence_refs(subject,time_ms DESC);
            CREATE TABLE IF NOT EXISTS graph_links(entity TEXT NOT NULL,event_id INTEGER NOT NULL REFERENCES evidence_refs(id),time_ms INTEGER NOT NULL,PRIMARY KEY(entity,event_id)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS graph_entity_time ON graph_links(entity,time_ms DESC,event_id DESC);
            CREATE INDEX IF NOT EXISTS graph_event ON graph_links(event_id,entity);
            CREATE TABLE IF NOT EXISTS relevance(event_id INTEGER PRIMARY KEY REFERENCES evidence_refs(id),trigger_id INTEGER NOT NULL,score INTEGER NOT NULL,payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS relevance_trigger ON relevance(trigger_id,event_id);
            CREATE TEMP TABLE investigation_cache(event_id INTEGER PRIMARY KEY,payload TEXT NOT NULL,bytes INTEGER NOT NULL,score INTEGER NOT NULL,expires_ms INTEGER NOT NULL,relevance TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence_retrieval_audit(id INTEGER PRIMARY KEY,time_ms INTEGER NOT NULL,event_id INTEGER NOT NULL,location TEXT NOT NULL,outcome TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS retrieval_location_time ON evidence_retrieval_audit(location,time_ms);
            CREATE INDEX IF NOT EXISTS retrieval_event_time ON evidence_retrieval_audit(event_id,time_ms);
            CREATE TABLE IF NOT EXISTS evidence_locations(event_id INTEGER NOT NULL REFERENCES evidence_refs(id),agent_id INTEGER NOT NULL REFERENCES agents(id),address TEXT NOT NULL,server_name TEXT NOT NULL,cert_hash TEXT NOT NULL,token TEXT NOT NULL,PRIMARY KEY(event_id,agent_id));
            CREATE TRIGGER IF NOT EXISTS immutable_object_update BEFORE UPDATE ON evidence_objects BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_object_delete BEFORE DELETE ON evidence_objects BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_ref_update BEFORE UPDATE ON evidence_refs BEGIN SELECT RAISE(ABORT,'immutable reference'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_ref_delete BEFORE DELETE ON evidence_refs BEGIN SELECT RAISE(ABORT,'immutable reference'); END;
            INSERT OR IGNORE INTO settings VALUES('memory_watermark',0),('memory_migration',0);")?;
        self.connection.execute(
            "INSERT OR IGNORE INTO memory_config VALUES(1,?1)",
            [serde_json::to_string(&MemoryConfig::default())?],
        )?;
        // Stream legacy blocks once; never materialize the historical ledger in RAM.
        if self.setting("memory_migration")? == 0 {
            let mut after = 0i64;
            loop {
                let id: Option<i64> = self
                    .connection
                    .query_row(
                        "SELECT id FROM archive_blocks WHERE id>?1 ORDER BY id LIMIT 1",
                        [after],
                        |r| r.get(0),
                    )
                    .optional()?;
                let Some(id) = id else { break };
                let tx = rusqlite::Transaction::new_unchecked(
                    &self.connection,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                for event in self.archive_events(id)? {
                    self.preserve_event(&event, None, None)?;
                }
                tx.commit()?;
                after = id;
            }
            for event in self.events()? {
                self.preserve_event(&event, None, None)?;
            }
            self.connection.execute(
                "UPDATE settings SET value=1 WHERE key='memory_migration'",
                [],
            )?;
        }
        // Restore only the bounded hot set, including evidence committed before an archive flush.
        let config = self.memory_config()?;
        let cutoff = self
            .setting("memory_watermark")?
            .saturating_sub(config.hot_ms);
        let ids=self.connection.prepare("SELECT id FROM evidence_refs WHERE time_ms>?1 ORDER BY time_ms DESC,id DESC LIMIT ?2")?.query_map(params![cutoff,config.hot_events],|r|r.get::<_,u64>(0))?.collect::<Result<Vec<_>,_>>()?;
        for id in ids {
            let present: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM temp.events WHERE id=?1)",
                [id],
                |r| r.get(0),
            )?;
            if present {
                continue;
            }
            let event = self.reconstruct(id)?;
            let (dedup, input_hash): (Option<String>, Option<Vec<u8>>) =
                self.connection.query_row(
                    "SELECT dedup,input_hash FROM evidence_refs WHERE id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
            self.connection.execute(
                "INSERT INTO temp.events VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    id,
                    event.event.time_ms,
                    event.event.kind as u8,
                    event.event.severity,
                    event.event.source,
                    event.event.subject,
                    codec::encode(&event.event),
                    event.json_bytes,
                    dedup.unwrap_or_else(|| format!("migrated:{id}")),
                    input_hash.unwrap_or_default(),
                    event.event.outcome as u8
                ],
            )?;
            if let Some(context) = event.context {
                self.connection.execute(
                    "INSERT OR REPLACE INTO event_context VALUES(?1,?2)",
                    params![id, serde_json::to_string(&context)?],
                )?;
            }
            self.connection
                .execute("INSERT OR IGNORE INTO pending VALUES(?1)", [id])?;
        }
        // Historical reconstruction never depends on the legacy rotating archive.
        self.maintain_memory(self.setting("memory_watermark")?)?;
        Ok(())
    }
    pub fn memory_config(&self) -> LabResult<MemoryConfig> {
        let raw: String =
            self.connection
                .query_row("SELECT json FROM memory_config WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        let config: MemoryConfig = serde_json::from_str(&raw)?;
        config.validate()?;
        Ok(config)
    }
    pub fn configure_memory(&self, config: MemoryConfig, now: u64) -> LabResult<()> {
        config.validate()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.connection.execute(
            "UPDATE memory_config SET json=?1 WHERE id=1",
            [serde_json::to_string(&config)?],
        )?;
        self.maintain_memory(now)?;
        self.audit("memory.configured", &serde_json::to_string(&config)?, now)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn put_object(&self, raw: &[u8]) -> LabResult<Vec<u8>> {
        if raw.len() > MAX_OBJECT {
            return Err("Evidence object exceeds budget".into());
        }
        let hash = digest(raw);
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM evidence_objects WHERE hash=?1)",
            [&hash],
            |r| r.get(0),
        )?;
        if exists {
            if self.evidence_object(&hash)? != raw {
                return Err("Evidence collision or corruption".into());
            }
            return Ok(hash);
        }
        let mut compressed = ZlibEncoder::new(Vec::new(), Compression::fast());
        compressed.write_all(raw)?;
        self.connection.execute(
            "INSERT OR IGNORE INTO evidence_objects VALUES(?1,?2,?3)",
            params![hash, compressed.finish()?, raw.len()],
        )?;
        // A pre-existing object must pass integrity verification too.
        if self.evidence_object(&hash)? != raw {
            return Err("Evidence collision or corruption".into());
        }
        Ok(hash)
    }
    pub fn evidence_object(&self, hash: &[u8]) -> LabResult<Vec<u8>> {
        let (packed,length):(Vec<u8>,usize)=self.connection.query_row("SELECT payload,raw_bytes FROM all_evidence_objects WHERE hash=?1 AND length(payload)<=16512 AND raw_bytes<=16384 LIMIT 1",[hash],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if length > MAX_OBJECT || packed.len() > MAX_OBJECT + 128 {
            return Err("Evidence decode budget exceeded".into());
        }
        let mut raw = Vec::new();
        ZlibDecoder::new(packed.as_slice())
            .take((MAX_OBJECT + 1) as u64)
            .read_to_end(&mut raw)?;
        if raw.len() != length || digest(&raw) != hash {
            return Err("Evidence integrity verification failed".into());
        }
        Ok(raw)
    }
    pub fn evidence_hash(&self, id: u64) -> LabResult<Vec<u8>> {
        Ok(self.connection.query_row(
            "SELECT hash FROM all_evidence_refs WHERE id=?1 LIMIT 1",
            [id],
            |r| r.get(0),
        )?)
    }
    pub(crate) fn preserve_event(
        &self,
        display: &DisplayEvent,
        dedup: Option<&str>,
        input_hash: Option<&[u8]>,
    ) -> LabResult<()> {
        let mut context = display.context.clone();
        let cursor = context
            .as_mut()
            .map(|c| std::mem::take(&mut c.journal_cursor))
            .unwrap_or_default();
        let description = context
            .as_mut()
            .map(|c| std::mem::take(&mut c.summary))
            .unwrap_or_default();
        let description = self.put_object(description.as_bytes())?;
        let template = self.put_object(&serde_json::to_vec(&Template {
            source: display.source_label.clone(),
            subject: display.subject_label.clone(),
            object: display.object_label.clone(),
            context,
            description,
        })?)?;
        let payload = codec::encode(&display.event);
        let mut raw = b"IM01".to_vec();
        raw.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        raw.extend_from_slice(&payload);
        raw.extend_from_slice(&template);
        raw.extend_from_slice(cursor.as_bytes());
        let hash = self.put_object(&raw)?;
        let event = &display.event;
        self.connection.execute(
            "INSERT OR IGNORE INTO evidence_refs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                event.id,
                hash,
                event.time_ms,
                event.observed_ms,
                display.source_label,
                display.subject_label,
                event.severity,
                dedup,
                input_hash
            ],
        )?;
        if self.evidence_hash(event.id)? != hash {
            return Err("Conflicting immutable event identity".into());
        }
        for entity in entities(display) {
            self.connection.execute(
                "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
                params![entity, event.id, event.time_ms],
            )?;
        }
        Ok(())
    }
    pub fn reconstruct(&self, id: u64) -> LabResult<DisplayEvent> {
        let raw = self.evidence_object(&self.evidence_hash(id)?)?;
        let (event, template_hash, cursor) = decode_occurrence(&raw)?;
        if event.id != id {
            return Err("Evidence occurrence identity mismatch".into());
        }
        let mut template: Template =
            serde_json::from_slice(&self.evidence_object(&template_hash)?)?;
        let description = String::from_utf8(self.evidence_object(&template.description)?)?;
        if let Some(context) = template.context.as_mut() {
            context.journal_cursor = cursor;
            context.summary = description;
        }
        Ok(DisplayEvent {
            source_label: template.source,
            subject_label: template.subject,
            object_label: template.object,
            encoded_bytes: codec::encode(&event).len(),
            json_bytes: serde_json::to_vec(&event)?.len(),
            notation: format!(
                "{}{} s{}:{}→{}",
                event.kind.code(),
                event.outcome.symbol(),
                event.severity,
                event.subject,
                event.object
            ),
            event,
            context: template.context,
        })
    }
    pub fn evidence_bundle(&self, id: u64) -> LabResult<Vec<Vec<u8>>> {
        let raw = self.evidence_object(&self.evidence_hash(id)?)?;
        let (_, hash, _) = decode_occurrence(&raw)?;
        let template = self.evidence_object(&hash)?;
        let decoded: Template = serde_json::from_slice(&template)?;
        Ok(vec![
            raw,
            template,
            self.evidence_object(&decoded.description)?,
        ])
    }
    /// The expected root comes from a previously trusted central reference, never the responder.
    pub fn accept_evidence_bundle(&self, id: u64, bundle: &[Vec<u8>]) -> LabResult<()> {
        if bundle.len() != 3 || bundle.iter().any(|b| b.len() > MAX_OBJECT) {
            return Err("Invalid evidence bundle budget".into());
        }
        let expected = self.evidence_hash(id)?;
        if digest(&bundle[0]) != expected {
            return Err("Remote evidence root mismatch".into());
        }
        let (event, template_hash, _) = decode_occurrence(&bundle[0])?;
        if event.id != id || digest(&bundle[1]) != template_hash {
            return Err("Remote occurrence or template mismatch".into());
        }
        let template: Template = serde_json::from_slice(&bundle[1])?;
        if digest(&bundle[2]) != template.description {
            return Err("Remote description mismatch".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        for object in bundle {
            self.put_object(object)?;
        }
        self.reconstruct(id)?;
        tx.commit()?;
        Ok(())
    }
    pub fn maintain_memory(&self, now: u64) -> LabResult<()> {
        let config = self.memory_config()?;
        // A monotonic watermark avoids reviving expired records on clock rollback.
        let now = now.max(self.setting("memory_watermark")?);
        self.connection.execute(
            "UPDATE settings SET value=?1 WHERE key='memory_watermark' AND value<?1",
            [now],
        )?;
        let cutoff = now.saturating_sub(config.hot_ms);
        self.connection.execute(
            "DELETE FROM temp.events WHERE time_ms<=?1 AND ?2>=?3",
            params![cutoff, now, config.hot_ms],
        )?;
        self.connection.execute("DELETE FROM temp.events WHERE id IN(SELECT id FROM temp.events ORDER BY time_ms,id LIMIT max(0,(SELECT count(*) FROM temp.events)-?1))",[config.hot_events])?;
        loop {
            let size:u64=self.connection.query_row("SELECT coalesce(sum(length(e.payload)+length(e.dedup)+length(e.input_hash)+128+coalesce(length(c.payload),0)),0) FROM temp.events e LEFT JOIN event_context c ON c.event_id=e.id",[],|r|r.get(0))?;
            if size <= config.hot_bytes as u64 {
                break;
            }
            self.connection.execute("DELETE FROM temp.events WHERE id=(SELECT id FROM temp.events ORDER BY time_ms,id LIMIT 1)",[])?;
        }
        self.connection.execute(
            "DELETE FROM event_context WHERE event_id NOT IN(SELECT id FROM temp.events)",
            [],
        )?;
        self.connection.execute(
            "DELETE FROM pending WHERE event_id NOT IN(SELECT id FROM temp.events)",
            [],
        )?;
        self.connection.execute(
            "DELETE FROM investigation_cache WHERE expires_ms<=?1",
            [now],
        )?;
        loop {
            let (count, bytes): (usize, usize) = self.connection.query_row(
                "SELECT count(*),coalesce(sum(bytes),0) FROM investigation_cache",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if count <= config.context_events && bytes <= config.context_bytes {
                break;
            }
            self.connection.execute("DELETE FROM investigation_cache WHERE event_id=(SELECT event_id FROM investigation_cache ORDER BY (event_id=(SELECT max(trigger_id) FROM relevance)),score,expires_ms,event_id LIMIT 1)",[])?;
        }
        Ok(())
    }
    pub(crate) fn correlate(&self, trigger: u64, now: u64) -> LabResult<()> {
        self.correlate_signal(trigger, None, now)
    }
    pub(crate) fn correlate_signal(
        &self,
        trigger: u64,
        signal: Option<u8>,
        now: u64,
    ) -> LabResult<()> {
        let config = self.memory_config()?;
        let current = self.reconstruct(trigger)?;
        let severity = signal.unwrap_or(current.event.severity);
        // Volume alone is not a signal. Explicit severity (including rule findings)
        // or a concrete egress anomaly triggers bounded historical work.
        if severity < config.trigger_severity && current.event.bytes < config.anomaly_bytes {
            return Ok(());
        }
        self.promote(
            &current,
            Relevance {
                event_id: trigger,
                trigger_id: trigger,
                score: severity as u32 * config.severity_weight,
                reasons: vec!["current detection severity".into()],
                path: vec![trigger],
                computed_ms: now,
                status: "verified_local".into(),
            },
            now,
        )?;
        let mut queue = VecDeque::from([(trigger, 0usize, vec![trigger])]);
        let mut visited = HashSet::from([trigger]);
        let mut candidates = BTreeMap::<u64, (Vec<String>, Vec<u64>)>::new();
        while let Some((id, depth, path)) = queue.pop_front() {
            if depth >= config.max_depth {
                continue;
            }
            let keys = self.graph_keys(id)?;
            for key in keys {
                let mut neighbors =
                    self.graph_neighbors(&key, id, i64::MAX as u64, config.fan_out.div_ceil(2))?;
                let historical = self.graph_neighbors(
                    &key,
                    id,
                    now.saturating_sub(config.hot_ms),
                    config.fan_out / 2,
                )?;
                neighbors.extend(historical);
                for other in neighbors {
                    if other == trigger {
                        continue;
                    }
                    if !candidates.contains_key(&other) && candidates.len() >= config.max_candidates
                    {
                        continue;
                    }
                    let mut route = path.clone();
                    route.push(other);
                    let entry = candidates
                        .entry(other)
                        .or_insert_with(|| (Vec::new(), route.clone()));
                    if entry.0.len() < 16 && !entry.0.contains(&key) {
                        entry.0.push(key.clone());
                    }
                    if visited.insert(other) {
                        queue.push_back((other, depth + 1, route));
                    }
                }
            }
        }
        for (id, (links, path)) in candidates {
            self.localize_reference(id)?;
            let (historical_severity, time): (u32, u64) = self.connection.query_row(
                "SELECT severity,time_ms FROM evidence_refs WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let mut score = severity as u32 * config.severity_weight;
            let mut reasons = vec![format!(
                "new detection severity {} × {}",
                severity, config.severity_weight
            )];
            if current.event.bytes >= config.anomaly_bytes {
                score += config.behavior_weight;
                reasons.push(format!(
                    "egress volume anomaly: {} bytes (+{})",
                    current.event.bytes, config.behavior_weight
                ));
            }
            let mut types = HashSet::new();
            for key in links {
                let kind = key.split(':').next().unwrap_or("");
                let weight = match kind {
                    "identity" | "claimed-account" => config.identity_weight,
                    "endpoint" => config.endpoint_weight,
                    "process" => config.process_weight,
                    "destination" | "ip" => config.destination_weight,
                    "behavior" | "trace" | "detection" => config.behavior_weight,
                    _ => 0,
                };
                // A claim and its reporter UID remain separate relations but
                // share one scoring category; matching both adds no bonus.
                let category = if kind == "claimed-account" {
                    "identity"
                } else {
                    kind
                };
                if types.insert(category.to_string()) {
                    score += weight;
                    reasons.push(format!("{key} (+{weight})"));
                }
            }
            if current.event.time_ms.abs_diff(time) <= 300_000 {
                score += config.temporal_weight;
                reasons.push(format!("within five minutes (+{})", config.temporal_weight));
            }
            if historical_severity >= 4 {
                score += config.behavior_weight;
                reasons.push(format!(
                    "historical high severity (+{})",
                    config.behavior_weight
                ));
            }
            let active: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM investigation_cache WHERE event_id=?1)",
                [id],
                |r| r.get(0),
            )?;
            if active {
                score += config.context_weight;
                reasons.push(format!(
                    "active investigation context (+{})",
                    config.context_weight
                ));
            }
            if path.len() > 2 {
                score = score.saturating_sub(10 * (path.len() as u32 - 2));
                reasons.push("indirect path distance penalty".into());
            }
            let mut relevance = Relevance {
                event_id: id,
                trigger_id: trigger,
                score,
                reasons,
                path,
                computed_ms: now,
                status: "below_threshold".into(),
            };
            if score >= config.promotion_score {
                match self.reconstruct(id) {
                    Ok(event) => {
                        relevance.status = "verified_local".into();
                        self.promote(&event, relevance.clone(), now)?;
                        self.retrieval_audit(id, "local", "verified", now)?;
                    }
                    Err(error) => {
                        relevance.status = format!("unavailable_or_corrupt: {error}");
                        self.retrieval_audit(id, "local", "verification_failed", now)?;
                    }
                }
            }
            self.save_relevance(&relevance)?;
        }
        self.maintain_memory(now)?;
        Ok(())
    }
    pub(crate) fn save_relevance(&self, r: &Relevance) -> LabResult<()> {
        self.connection.execute("INSERT INTO relevance VALUES(?1,?2,?3,?4) ON CONFLICT(event_id) DO UPDATE SET trigger_id=excluded.trigger_id,score=excluded.score,payload=excluded.payload",params![r.event_id,r.trigger_id,r.score,serde_json::to_string(r)?])?;
        Ok(())
    }
    pub(crate) fn promote(
        &self,
        event: &DisplayEvent,
        relevance: Relevance,
        now: u64,
    ) -> LabResult<()> {
        let config = self.memory_config()?;
        let expires = relevance.computed_ms.saturating_add(config.context_ms);
        if expires <= now {
            return Ok(());
        }
        let payload = serde_json::to_string(event)?;
        let why = serde_json::to_string(&relevance)?;
        let bytes = payload.len() + why.len() + 128;
        if bytes > config.context_bytes {
            return Ok(());
        }
        self.connection.execute("INSERT INTO investigation_cache VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(event_id) DO UPDATE SET payload=excluded.payload,bytes=excluded.bytes,score=excluded.score,expires_ms=excluded.expires_ms,relevance=excluded.relevance",params![event.event.id,payload,bytes,relevance.score,expires,why])?;
        self.save_relevance(&relevance)?;
        Ok(())
    }
    pub(crate) fn retrieval_audit(
        &self,
        id: u64,
        location: &str,
        outcome: &str,
        now: u64,
    ) -> LabResult<()> {
        self.connection.execute("INSERT INTO evidence_retrieval_audit(time_ms,event_id,location,outcome) VALUES(?1,?2,?3,?4)",params![now,id,location,outcome])?;
        // Audit is durable and fails closed when the ledger fills; it is never silently rotated.
        Ok(())
    }
    pub fn memory_state(&self) -> LabResult<MemoryState> {
        let context=self.connection.prepare("SELECT payload,relevance,expires_ms FROM investigation_cache ORDER BY score DESC,event_id")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,u64>(2)?)))?.collect::<Result<Vec<_>,_>>()?.into_iter().map(|(e,r,expires_ms)|Ok(ContextEvent {evidence:serde_json::from_str(&e)?,relevance:serde_json::from_str(&r)?,expires_ms})).collect::<LabResult<Vec<_>>>()?;
        let recent_relevance = self
            .connection
            .prepare(
                "SELECT payload FROM relevance ORDER BY trigger_id DESC,event_id DESC LIMIT 128",
            )?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|r| serde_json::from_str(&r).map_err(Into::into))
            .collect::<LabResult<Vec<_>>>()?;
        Ok(MemoryState {config:self.memory_config()?,references:self.connection.query_row("SELECT count(*) FROM evidence_refs",[],|r|r.get(0))?,objects:self.connection.query_row("SELECT count(*) FROM evidence_objects",[],|r|r.get(0))?,object_bytes:self.connection.query_row("SELECT coalesce(sum(length(payload)),0) FROM evidence_objects",[],|r|r.get(0))?,graph_links:self.connection.query_row("SELECT count(*) FROM graph_links",[],|r|r.get(0))?,hot_events:self.connection.query_row("SELECT count(*) FROM temp.events",[],|r|r.get(0))?,hot_bytes:self.connection.query_row("SELECT coalesce(sum(length(e.payload)+length(e.dedup)+length(e.input_hash)+128+coalesce(length(c.payload),0)),0) FROM temp.events e LEFT JOIN event_context c ON c.event_id=e.id",[],|r|r.get(0))?,context_bytes:self.connection.query_row("SELECT coalesce(sum(bytes),0) FROM investigation_cache",[],|r|r.get(0))?,context,recent_relevance})
    }
}

fn decode_occurrence(raw: &[u8]) -> LabResult<(Event, Vec<u8>, String)> {
    if raw.len() < 40 || &raw[..4] != b"IM01" {
        return Err("Invalid occurrence format".into());
    }
    let length = u32::from_le_bytes(raw[4..8].try_into()?) as usize;
    if length > MAX_OBJECT || 8 + length + 32 > raw.len() || raw.len() - (8 + length + 32) > 512 {
        return Err("Invalid occurrence length".into());
    }
    Ok((
        codec::decode(&raw[8..8 + length])?,
        raw[8 + length..8 + length + 32].to_vec(),
        String::from_utf8(raw[8 + length + 32..].to_vec())?,
    ))
}
fn entities(event: &DisplayEvent) -> Vec<String> {
    let endpoint = event
        .context
        .as_ref()
        .map(|c| c.host.as_str())
        .filter(|h| !h.is_empty())
        .unwrap_or(&event.source_label);
    let subject = match event
        .context
        .as_ref()
        .and_then(|context| context.claimed_account.as_deref())
    {
        Some(account) => format!(
            "claimed-account:{}",
            hex(&digest(
                &serde_json::to_vec(&("claimed-account-graph-v1", &event.source_label, account,))
                    .expect("Claim graph identity contains only strings")
            ))
        ),
        // Keep old graph identities intact. A new claim must never share this
        // namespace merely because its compact digest equals an old username.
        None => format!("identity:{}", event.subject_label),
    };
    let mut keys = vec![subject, format!("endpoint:{endpoint}")];
    if event.event.kind == Kind::Network {
        keys.push(format!("destination:{}", event.object_label));
        if event.object_label.parse::<std::net::IpAddr>().is_ok() {
            keys.push(format!("ip:{}", event.object_label));
        }
    }
    if let Some(context) = &event.context {
        if let (Some(pid), Some(start)) = (context.pid, context.process_start_ms) {
            keys.push(format!("process:{endpoint}:{pid}:{start}"));
        }
        if let (Some(pid), Some(start)) = (context.parent_pid, context.parent_start_ms) {
            keys.push(format!("process:{endpoint}:{pid}:{start}"));
        }
        if let Some(uid) = context.uid {
            keys.push(format!("identity:{endpoint}:uid-{uid}"));
        }
    }
    if event.event.trace != 0 {
        keys.push(format!(
            "trace:{}:{}",
            event.source_label, event.event.trace
        ));
    }
    // Specific behavior relationships; never link every event of a broad kind.
    if event.event.severity >= 4 {
        keys.push(format!(
            "behavior:{}:{}:{}",
            event.event.kind.code(),
            event.event.outcome.label(),
            event.object_label
        ));
    }
    keys.sort();
    keys.dedup();
    keys
}

#[derive(Debug, Serialize)]
pub struct HistoricalReference {
    pub id: u64,
    pub sha256: String,
    pub time_ms: u64,
    pub observed_ms: u64,
    pub source: String,
    pub subject: String,
    pub severity: u8,
}
impl Engine {
    /// Indexed entity search with keyset pagination; no full-event reconstruction or history scan.
    pub fn search_history(
        &self,
        entity: &str,
        before_ms: u64,
        before_id: u64,
        limit: usize,
    ) -> LabResult<Vec<HistoricalReference>> {
        self.with_background_budget(
            "history",
            orchestrator::governor::Resources {
                cpu_millis: 250,
                memory_mib: 64,
                io_mib: 8,
                ..Default::default()
            },
            crate::model::now_ms(),
            || self.search_history_inner(entity, before_ms, before_id, limit),
        )
    }
    fn search_history_inner(
        &self,
        entity: &str,
        before_ms: u64,
        before_id: u64,
        limit: usize,
    ) -> LabResult<Vec<HistoricalReference>> {
        if entity.is_empty()
            || entity.len() > 256
            || !(1..=128).contains(&limit)
            || before_ms > i64::MAX as u64
            || before_id > i64::MAX as u64
        {
            return Err("Invalid historical search bounds".into());
        }
        let mut rows = Vec::new();
        for schema in self.evidence_schemas()? {
            rows.extend(self.connection.prepare(&format!("SELECT r.id,r.hash,r.time_ms,r.observed_ms,r.source,r.subject,r.severity FROM {schema}.graph_links g JOIN {schema}.evidence_refs r ON r.id=g.event_id WHERE g.entity=?1 AND (g.time_ms,g.event_id)<(?2,?3) ORDER BY g.time_ms DESC,g.event_id DESC LIMIT ?4"))?.query_map(params![entity,before_ms,before_id,limit],|r|Ok(HistoricalReference{id:r.get(0)?,sha256:hex(&r.get::<_,Vec<u8>>(1)?),time_ms:r.get(2)?,observed_ms:r.get(3)?,source:r.get(4)?,subject:r.get(5)?,severity:r.get(6)?}))?.collect::<Result<Vec<_>,_>>()?);
        }
        rows.sort_unstable_by(|a, b| (b.time_ms, b.id).cmp(&(a.time_ms, a.id)));
        rows.dedup_by_key(|r| r.id);
        rows.truncate(limit);
        Ok(rows)
    }
}
impl Engine {
    pub fn retrieve_local(&self, id: u64, now: u64) -> LabResult<DisplayEvent> {
        let result = self.reconstruct(id);
        self.retrieval_audit(
            id,
            "local",
            if result.is_ok() {
                "verified"
            } else {
                "unavailable_or_corrupt"
            },
            now,
        )?;
        result
    }
}
