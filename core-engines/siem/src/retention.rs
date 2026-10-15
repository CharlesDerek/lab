//! RAM query window + AXR2 archive blocks with AXR1 read compatibility.
//! Security state stays in main SQLite; TEMP telemetry never spills to disk.
use crate::{
    codec,
    engine::{Engine, LabResult},
    model::*,
};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use rusqlite::params;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

const MAX_BLOCK_EVENTS: usize = 512;
const MAX_DECODED: usize = 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Retention {
    pub days: u64,
    pub cap_bytes: u64,
    pub flush_seconds: u64,
    pub pending_events: usize,
    pub hot_bytes: u64,
    pub archive_bytes: u64,
    pub archived_events: u64,
    pub rotated_events: u64,
    pub last_flush_ms: u64,
    pub blocks: Vec<BlockInfo>,
    pub persistent: bool,
}
#[derive(Debug, Serialize)]
pub struct BlockInfo {
    pub id: i64,
    pub first_ms: u64,
    pub last_ms: u64,
    pub events: u64,
    pub compressed_bytes: u64,
    pub decoded_bytes: u64,
}
struct Record {
    payload: Vec<u8>,
    json_bytes: usize,
    dedup: String,
    input_hash: Vec<u8>,
    context: Option<EventContext>,
}

impl Engine {
    pub(crate) fn init_retention(&self) -> LabResult<()> {
        self.connection.execute_batch(
            "PRAGMA temp_store=MEMORY;
             CREATE TABLE IF NOT EXISTS archive_blocks(id INTEGER PRIMARY KEY AUTOINCREMENT,first_ms INTEGER NOT NULL,last_ms INTEGER NOT NULL,events INTEGER NOT NULL,payload BLOB NOT NULL,decoded_bytes INTEGER NOT NULL,digest BLOB NOT NULL);
             INSERT OR IGNORE INTO settings VALUES ('retention_days',30),('archive_cap',1048576),('flush_seconds',5),('last_flush',0),('rotated_events',0),('event_sequence',0),('reserved_sequence',0);
             CREATE TEMP TABLE labels(id INTEGER PRIMARY KEY,value TEXT UNIQUE NOT NULL);
             CREATE TEMP TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,time_ms INTEGER NOT NULL,kind INTEGER NOT NULL,severity INTEGER NOT NULL,source INTEGER NOT NULL,subject INTEGER NOT NULL,payload BLOB NOT NULL,json_bytes INTEGER NOT NULL,dedup TEXT UNIQUE NOT NULL,input_hash BLOB NOT NULL);
             CREATE TEMP TABLE event_context(event_id INTEGER PRIMARY KEY,payload TEXT NOT NULL);
             CREATE INDEX temp.hot_event_time ON events(time_ms);
             CREATE TEMP TABLE runtime_counts(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
             INSERT INTO runtime_counts SELECT key,value FROM main.settings WHERE key IN ('received','duplicates');
             INSERT INTO temp.labels SELECT * FROM main.labels;
             INSERT INTO temp.events SELECT * FROM main.events;
             CREATE TEMP TABLE pending(event_id INTEGER PRIMARY KEY);
             INSERT INTO pending SELECT id FROM temp.events;"
        )?;
        // Load newest blocks only. Each carries its own identity dictionary.
        let blocks = self
            .connection
            .prepare("SELECT id FROM archive_blocks ORDER BY id DESC LIMIT 4096")?
            .query_map([], |r| r.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut restored = 0;
        for id in blocks {
            let (labels, records) = self.read_block(id)?;
            for record in records.into_iter().rev() {
                if restored >= MAX_EVENTS {
                    break;
                }
                let event = codec::decode(&record.payload)?;
                let existing: bool = self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM temp.events WHERE id=?1)",
                    [event.id],
                    |r| r.get(0),
                )?;
                if existing {
                    continue;
                }
                for key in [u32::from(event.source), event.subject, event.object] {
                    let value = labels.get(&key).ok_or("Missing archive label")?;
                    self.connection.execute(
                        "INSERT OR IGNORE INTO temp.labels VALUES (?1,?2)",
                        params![key, value],
                    )?;
                }
                self.connection.execute(
                    "INSERT INTO temp.events VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![
                        event.id,
                        event.time_ms,
                        event.kind as u8,
                        event.severity,
                        event.source,
                        event.subject,
                        record.payload,
                        record.json_bytes,
                        record.dedup,
                        record.input_hash
                    ],
                )?;
                if let Some(context) = record.context {
                    self.connection.execute(
                        "INSERT OR REPLACE INTO event_context VALUES (?1,?2)",
                        params![event.id, serde_json::to_string(&context)?],
                    )?;
                }
                restored += 1;
            }
            if restored >= MAX_EVENTS {
                break;
            }
        }
        // Preserve monotonic IDs even when every archive has rotated away.
        let sequence = self
            .setting("event_sequence")?
            .max(self.setting("reserved_sequence")?);
        self.connection.execute("INSERT INTO temp.sqlite_sequence(name,seq) SELECT 'events',?1 WHERE NOT EXISTS(SELECT 1 FROM temp.sqlite_sequence WHERE name='events')",[sequence])?;
        self.connection.execute(
            "UPDATE temp.sqlite_sequence SET seq=max(seq,?1) WHERE name='events'",
            [sequence],
        )?;
        Ok(())
    }
    pub(crate) fn archive_expired(&self, now: u64) -> LabResult<bool> {
        let days = self.setting("retention_days")?;
        if days == 0 {
            return Ok(false);
        }
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM archive_blocks WHERE last_ms<?1)",
            [now.saturating_sub(days * 86_400_000)],
            |r| r.get(0),
        )?)
    }
    pub(crate) fn reserve_ids(&self, incoming: usize) -> LabResult<()> {
        let next: u64 = self.connection.query_row(
            "SELECT coalesce(max(seq),0) FROM temp.sqlite_sequence WHERE name='events'",
            [],
            |r| r.get(0),
        )?;
        if next.saturating_add(incoming as u64) > self.setting("reserved_sequence")? {
            self.connection.execute(
                "UPDATE main.settings SET value=?1 WHERE key='reserved_sequence'",
                [next.saturating_add(4096)],
            )?;
        }
        Ok(())
    }
    pub(crate) fn setting(&self, key: &str) -> LabResult<u64> {
        Ok(self.connection.query_row(
            "SELECT value FROM main.settings WHERE key=?1",
            [key],
            |r| r.get(0),
        )?)
    }
    pub fn retention(&self) -> LabResult<Retention> {
        let blocks=self.connection.prepare("SELECT id,first_ms,last_ms,events,length(payload),decoded_bytes FROM archive_blocks ORDER BY id DESC LIMIT 48")?
            .query_map([],|r| Ok(BlockInfo{id:r.get(0)?,first_ms:r.get(1)?,last_ms:r.get(2)?,events:r.get(3)?,compressed_bytes:r.get(4)?,decoded_bytes:r.get(5)?}))?.collect::<Result<Vec<_>,_>>()?;
        let (archive_bytes, archived_events) = self.connection.query_row(
            "SELECT coalesce(sum(length(payload)),0),coalesce(sum(events),0) FROM archive_blocks",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(Retention {
            days: self.setting("retention_days")?,
            cap_bytes: self.setting("archive_cap")?,
            flush_seconds: self.setting("flush_seconds")?,
            pending_events: self.pending_count()?,
            hot_bytes: self.connection.query_row(
                "SELECT coalesce(sum(length(payload)),0) FROM temp.events",
                [],
                |r| r.get(0),
            )?,
            archive_bytes,
            archived_events,
            rotated_events: self.setting("rotated_events")?,
            last_flush_ms: self.setting("last_flush")?,
            blocks,
            persistent: self.path.is_some(),
        })
    }
    pub(crate) fn pending_count(&self) -> LabResult<usize> {
        Ok(self
            .connection
            .query_row("SELECT count(*) FROM pending", [], |r| r.get(0))?)
    }
    pub fn configure_retention(
        &mut self,
        days: u64,
        cap_kib: u64,
        seconds: u64,
        now: u64,
    ) -> LabResult<()> {
        if days > 365 || !(64..=8192).contains(&cap_kib) || !(1..=60).contains(&seconds) {
            return Err("Use 0–365 days (0 = size only), 64–8192 KiB archive capacity, and a 1–60 second flush interval.".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        for (key, value) in [
            ("retention_days", days),
            ("archive_cap", cap_kib * 1024),
            ("flush_seconds", seconds),
        ] {
            tx.execute(
                "UPDATE settings SET value=?1 WHERE key=?2",
                params![value, key],
            )?;
        }
        self.rotate_archive(now, 0)?;
        self.audit(
            "retention.configured",
            &format!("{days} days / {cap_kib} KiB / {seconds}s flush"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Compress before opening a write transaction. Pending telemetry remains on failure.
    pub fn flush(&mut self, now: u64) -> LabResult<()> {
        let records=self.connection.prepare("SELECT events.payload,json_bytes,dedup,input_hash,c.payload FROM temp.events JOIN pending ON events.id=pending.event_id LEFT JOIN event_context c ON c.event_id=events.id ORDER BY events.id")?
            .query_map([],|r| Ok(Record{payload:r.get(0)?,json_bytes:r.get(1)?,dedup:r.get(2)?,input_hash:r.get(3)?,context:r.get::<_,Option<String>>(4)?.map(|v|serde_json::from_str(&v)).transpose().map_err(|e|rusqlite::Error::FromSqlConversionFailure(4,rusqlite::types::Type::Text,Box::new(e)))?}))?.collect::<Result<Vec<_>,_>>()?;
        let labels = self
            .connection
            .prepare("SELECT id,value FROM temp.labels")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<BTreeMap<u32, String>, _>>()?;
        let mut blocks = Vec::new();
        for batch in records.chunks(128) {
            let mut used = BTreeMap::new();
            let mut first = u64::MAX;
            let mut last = 0;
            for record in batch {
                let event = codec::decode(&record.payload)?;
                first = first.min(event.observed_ms);
                last = last.max(event.observed_ms);
                for key in [u32::from(event.source), event.subject, event.object] {
                    used.insert(key, labels.get(&key).ok_or("Missing hot label")?.clone());
                }
            }
            let raw = encode_block(&used, batch)?;
            let mut compressor = ZlibEncoder::new(Vec::new(), Compression::fast());
            compressor.write_all(&raw)?;
            blocks.push((
                first,
                last,
                batch.len(),
                compressor.finish()?,
                raw.len(),
                Sha256::digest(&raw).to_vec(),
            ));
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        for (first, last, count, packed, raw_len, digest) in blocks {
            if packed.len() as u64 > self.setting("archive_cap")? {
                return Err("Archive block exceeds the allocation; increase the cap.".into());
            }
            self.rotate_archive(now, packed.len() as u64)?;
            tx.execute("INSERT INTO archive_blocks(first_ms,last_ms,events,payload,decoded_bytes,digest) VALUES (?1,?2,?3,?4,?5,?6)",params![first,last,count,packed,raw_len,digest])?;
        }
        self.rotate_archive(now, 0)?;
        tx.execute("UPDATE main.settings SET value=(SELECT value FROM runtime_counts WHERE runtime_counts.key=settings.key) WHERE key IN ('received','duplicates')",[])?;
        tx.execute(
            "UPDATE main.settings SET value=?1 WHERE key='last_flush'",
            [now],
        )?;
        tx.execute("UPDATE main.settings SET value=(SELECT coalesce(max(seq),0) FROM temp.sqlite_sequence WHERE name='events') WHERE key='event_sequence'",[])?;
        // Migration is atomic with the first archive commit. Existing events survive a failed flush.
        tx.execute("DELETE FROM main.events", [])?;
        tx.execute(
            "INSERT OR IGNORE INTO main.labels SELECT * FROM temp.labels",
            [],
        )?;
        tx.execute("DELETE FROM pending", [])?;
        tx.execute("UPDATE sources SET cursor=(SELECT cursor FROM source_cursors WHERE source_cursors.id=sources.id) WHERE id IN (SELECT id FROM source_cursors)",[])?;
        tx.execute("DELETE FROM source_cursors", [])?;
        tx.execute("UPDATE sources SET received=sources.received+h.received,rejected=sources.rejected+h.rejected,last_event_ms=max(sources.last_event_ms,h.last_event_ms),last_poll_ms=max(sources.last_poll_ms,h.last_poll_ms),error=h.error FROM source_progress h WHERE sources.id=h.id",[])?;
        tx.execute("DELETE FROM source_progress", [])?;
        tx.commit()?;
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }
    fn rotate_archive(&self, now: u64, incoming: u64) -> LabResult<()> {
        let days = self.setting("retention_days")?;
        let cutoff = if days == 0 {
            0
        } else {
            now.saturating_sub(days * 86_400_000)
        };
        let cap = self.setting("archive_cap")?;
        let expired: u64 = self.connection.query_row(
            "SELECT coalesce(sum(events),0) FROM archive_blocks WHERE last_ms<?1",
            [cutoff],
            |r| r.get(0),
        )?;
        self.connection
            .execute("DELETE FROM archive_blocks WHERE last_ms<?1", [cutoff])?;
        self.connection.execute(
            "UPDATE settings SET value=value+?1 WHERE key='rotated_events'",
            [expired],
        )?;
        loop {
            let used: u64 = self.connection.query_row(
                "SELECT coalesce(sum(length(payload)),0) FROM archive_blocks",
                [],
                |r| r.get(0),
            )?;
            let oldest = self
                .connection
                .prepare("SELECT id,last_ms,events FROM archive_blocks ORDER BY id LIMIT 1")?
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, u64>(1)?,
                        r.get::<_, u64>(2)?,
                    ))
                })?
                .next()
                .transpose()?;
            let Some((id, last, count)) = oldest else {
                break;
            };
            if last >= cutoff && used.saturating_add(incoming) <= cap {
                break;
            }
            self.connection
                .execute("DELETE FROM archive_blocks WHERE id=?1", [id])?;
            self.connection.execute(
                "UPDATE settings SET value=value+?1 WHERE key='rotated_events'",
                [count],
            )?;
        }
        // Day retention applies to the query window too; evidence is a separate bounded tier.
        self.connection.execute(
            "DELETE FROM temp.events WHERE id NOT IN (SELECT event_id FROM pending) AND time_ms<?1",
            [cutoff],
        )?;
        Ok(())
    }
    fn read_block(&self, id: i64) -> LabResult<(BTreeMap<u32, String>, Vec<Record>)> {
        let (packed, length, digest): (Vec<u8>, usize, Vec<u8>) = self.connection.query_row(
            "SELECT payload,decoded_bytes,digest FROM archive_blocks WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if length > MAX_DECODED {
            return Err("Archive decode budget exceeded".into());
        }
        let mut raw = Vec::with_capacity(length);
        ZlibDecoder::new(packed.as_slice())
            .take((MAX_DECODED + 1) as u64)
            .read_to_end(&mut raw)?;
        if raw.len() != length || Sha256::digest(&raw).as_slice() != digest {
            return Err("Archive integrity check failed".into());
        }
        decode_block(&raw)
    }
    pub fn archive_events(&self, id: i64) -> LabResult<Vec<DisplayEvent>> {
        let (labels, records) = self.read_block(id)?;
        records
            .into_iter()
            .map(|r| {
                let event = codec::decode(&r.payload)?;
                let label = |id| -> LabResult<String> {
                    labels
                        .get(&id)
                        .cloned()
                        .ok_or_else(|| "Missing archive label".into())
                };
                Ok(DisplayEvent {
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
                    encoded_bytes: r.payload.len(),
                    json_bytes: r.json_bytes,
                    context: r.context,
                    event,
                })
            })
            .collect()
    }
}
fn encode_block(labels: &BTreeMap<u32, String>, records: &[Record]) -> LabResult<Vec<u8>> {
    let mut out = b"AXR2".to_vec();
    out.extend_from_slice(&(labels.len() as u16).to_le_bytes());
    for (id, label) in labels {
        out.extend_from_slice(&id.to_le_bytes());
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.extend_from_slice(&(records.len() as u16).to_le_bytes());
    for r in records {
        out.push(r.payload.len() as u8);
        out.extend_from_slice(&r.payload);
        out.extend_from_slice(&(r.json_bytes as u16).to_le_bytes());
        out.push(r.dedup.len() as u8);
        out.extend_from_slice(r.dedup.as_bytes());
        out.extend_from_slice(&r.input_hash);
        let context = serde_json::to_vec(&r.context)?;
        out.extend_from_slice(&(context.len() as u16).to_le_bytes());
        out.extend_from_slice(&context);
    }
    if out.len() > MAX_DECODED {
        return Err("Archive block too large".into());
    }
    Ok(out)
}
fn decode_block(raw: &[u8]) -> LabResult<(BTreeMap<u32, String>, Vec<Record>)> {
    let mut cursor = std::io::Cursor::new(raw);
    fn bytes(c: &mut std::io::Cursor<&[u8]>, n: usize) -> LabResult<Vec<u8>> {
        let mut b = vec![0; n];
        c.read_exact(&mut b)?;
        Ok(b)
    }
    fn num(c: &mut std::io::Cursor<&[u8]>, n: usize) -> LabResult<u32> {
        let b = bytes(c, n)?;
        Ok(b.iter()
            .enumerate()
            .fold(0, |v, (i, b)| v | u32::from(*b) << (i * 8)))
    }
    let magic = bytes(&mut cursor, 4)?;
    if magic != b"AXR1" && magic != b"AXR2" {
        return Err("Unknown archive version".into());
    }
    let label_count = num(&mut cursor, 2)?;
    if label_count > 1536 {
        return Err("Archive dictionary budget exceeded".into());
    }
    let mut labels = BTreeMap::new();
    for _ in 0..label_count {
        let id = num(&mut cursor, 4)?;
        let len = num(&mut cursor, 1)? as usize;
        if !(1..=64).contains(&len) {
            return Err("Invalid archive label".into());
        }
        let label = String::from_utf8(bytes(&mut cursor, len)?)?;
        if labels.insert(id, label).is_some() {
            return Err("Duplicate archive label".into());
        }
    }
    let count = num(&mut cursor, 2)? as usize;
    if count > MAX_BLOCK_EVENTS {
        return Err("Archive event budget exceeded".into());
    }
    let mut records = Vec::new();
    for _ in 0..count {
        let len = num(&mut cursor, 1)? as usize;
        let payload = bytes(&mut cursor, len)?;
        codec::decode(&payload)?;
        let json_bytes = num(&mut cursor, 2)? as usize;
        let len = num(&mut cursor, 1)? as usize;
        if len > 129 {
            return Err("Invalid dedup key".into());
        }
        let dedup = String::from_utf8(bytes(&mut cursor, len)?)?;
        let input_hash = bytes(&mut cursor, 32)?;
        let context: Option<EventContext> = if magic == b"AXR2" {
            let len = num(&mut cursor, 2)? as usize;
            if len > 2048 {
                return Err("Archive context budget exceeded".into());
            }
            serde_json::from_slice(&bytes(&mut cursor, len)?)?
        } else {
            None
        };
        if let Some(c) = &context {
            c.validate()?;
        }
        records.push(Record {
            payload,
            json_bytes,
            dedup,
            input_hash,
            context,
        });
    }
    if cursor.position() != raw.len() as u64 {
        return Err("Trailing archive bytes".into());
    }
    Ok((labels, records))
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_800_000_000_000;
    fn events(start: u64, count: u64) -> Vec<InputEvent> {
        (start..start + count)
            .map(|i| InputEvent {
                time_ms: NOW,
                source: "sensor".into(),
                subject: format!("service-{}", i % 64),
                object: "artifact".into(),
                kind: Kind::Network,
                outcome: Outcome::Allow,
                severity: 1,
                bytes: i * 11,
                trace: 0,
                idempotency_key: format!("event-{i}"),
                context: None,
            })
            .collect()
    }
    #[test]
    fn unflushed_telemetry_is_ram_only_and_blocks_restore_exact_facts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lab.db");
        let mut e = Engine::open(&path).unwrap();
        e.ingest(&events(0, 64), NOW).unwrap();
        let disk = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            disk.query_row("SELECT count(*) FROM events", [], |r| r.get::<_, usize>(0))
                .unwrap(),
            0
        );
        let before = e.events().unwrap();
        e.flush(NOW).unwrap();
        let r = e.retention().unwrap();
        assert_eq!(r.pending_events, 0);
        assert_eq!(r.archived_events, 64);
        assert!(r.archive_bytes < r.blocks[0].decoded_bytes);
        let block = e.archive_events(r.blocks[0].id).unwrap();
        assert_eq!(before[0].event, block[0].event);
        drop(e);
        let mut e = Engine::open(&path).unwrap();
        let after = e.events().unwrap();
        assert_eq!(before.len(), after.len());
        for (a, b) in before.iter().zip(&after) {
            assert_eq!(a.event, b.event);
            assert_eq!(a.subject_label, b.subject_label);
        }
        assert_eq!(e.ingest(&events(0, 64), NOW + 1).unwrap(), 0);
    }
    #[test]
    fn byte_cap_rotates_oldest_blocks_and_days_expire_history() {
        let mut e = Engine::memory().unwrap();
        e.configure_retention(30, 64, 5, NOW).unwrap();
        for batch in 0..16 {
            e.ingest(&events(batch * 256, 256), NOW + batch).unwrap();
            e.flush(NOW + batch).unwrap();
            assert!(e.retention().unwrap().archive_bytes <= 65536);
        }
        let r = e.retention().unwrap();
        assert!(r.rotated_events > 0);
        assert!(r.archived_events < 4096);
        assert!(r.blocks.last().unwrap().id > 1);
        e.flush(NOW + 31 * 86_400_000).unwrap();
        let r = e.retention().unwrap();
        assert_eq!(r.archive_bytes, 0);
        assert_eq!(r.archived_events, 0);
        assert_eq!(r.rotated_events, 4096);
        assert!(e.events().unwrap().is_empty());
    }
    #[test]
    fn size_only_keeps_old_blocks_and_failed_flush_keeps_pending() {
        let mut e = Engine::memory().unwrap();
        e.configure_retention(0, 64, 5, NOW).unwrap();
        e.ingest(&events(0, 20), NOW).unwrap();
        e.connection.execute_batch("CREATE TRIGGER fail_archive BEFORE INSERT ON archive_blocks BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(e.flush(NOW).is_err());
        assert_eq!(e.pending_count().unwrap(), 20);
        assert_eq!(e.retention().unwrap().archived_events, 0);
        e.connection
            .execute_batch("DROP TRIGGER fail_archive")
            .unwrap();
        e.flush(NOW).unwrap();
        e.flush(NOW + 366 * 86_400_000).unwrap();
        assert_eq!(e.retention().unwrap().archived_events, 20);
    }
    #[test]
    fn checksum_and_decode_budgets_reject_corruption() {
        let mut e = Engine::memory().unwrap();
        e.ingest(&events(0, 20), NOW).unwrap();
        e.flush(NOW).unwrap();
        e.connection
            .execute("UPDATE archive_blocks SET digest=zeroblob(32)", [])
            .unwrap();
        assert!(e.archive_events(1).is_err());
        e.connection
            .execute("UPDATE archive_blocks SET decoded_bytes=1000000000", [])
            .unwrap();
        assert!(e.archive_events(1).is_err());
        assert!(decode_block(b"AXR2").is_err());
        assert!(decode_block(b"AXR1\xff\xff").is_err());
    }
    #[test]
    fn legacy_rows_migrate_only_when_the_archive_commits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        let mut e = Engine::open(&path).unwrap();
        e.ingest(&events(0, 20), NOW).unwrap();
        e.connection.execute_batch("INSERT OR IGNORE INTO main.labels SELECT * FROM temp.labels; INSERT INTO main.events SELECT * FROM temp.events;").unwrap();
        drop(e);
        let mut e = Engine::open(&path).unwrap();
        assert_eq!(e.events().unwrap().len(), 20);
        assert_eq!(e.pending_count().unwrap(), 20);
        e.flush(NOW).unwrap();
        assert_eq!(
            e.connection
                .query_row("SELECT count(*) FROM main.events", [], |r| r
                    .get::<_, usize>(0))
                .unwrap(),
            0
        );
        drop(e);
        assert_eq!(Engine::open(&path).unwrap().events().unwrap().len(), 20);
    }
    #[test]
    fn crash_lost_event_ids_are_not_reused_and_ledger_has_one_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lab.db");
        let mut e = Engine::open(&path).unwrap();
        assert!(Engine::open(&path).is_err());
        e.ingest(&events(0, 2), NOW).unwrap();
        let prior = e.events().unwrap().last().unwrap().event.id;
        drop(e);
        let mut e = Engine::open(&path).unwrap();
        assert!(e.events().unwrap().is_empty());
        e.ingest(&events(2, 1), NOW + 1).unwrap();
        assert!(e.events().unwrap()[0].event.id > prior);
    }
    #[test]
    fn idle_ticks_do_not_rewrite_the_checkpoint() {
        let mut e = Engine::memory().unwrap();
        e.ingest(&events(0, 2), NOW).unwrap();
        e.tick(NOW + 5001).unwrap();
        let flushed = e.retention().unwrap().last_flush_ms;
        e.tick(NOW + 20_000).unwrap();
        assert_eq!(e.retention().unwrap().last_flush_ms, flushed);
    }
}
