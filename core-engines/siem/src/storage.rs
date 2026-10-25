//! Sealed, independently verified evidence segments and pre-admission storage budgets.
//! A segment reaches durable storage before the live transaction removes any evidence.
use crate::{
    engine::{Engine, LabResult},
    gateway::secret,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub ledger_mib: u64,
    pub segment_limit: usize,
    pub segment_records: usize,
    pub minimum_free_mib: u64,
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            ledger_mib: 64,
            segment_limit: 8,
            segment_records: 8192,
            minimum_free_mib: 64,
        }
    }
}
impl StorageConfig {
    pub fn validate(&self) -> LabResult<()> {
        if !(16..=1024).contains(&self.ledger_mib)
            || !(1..=8).contains(&self.segment_limit)
            || !(64..=65536).contains(&self.segment_records)
            || self.minimum_free_mib > 1024 * 1024
        {
            return Err("Invalid storage budgets".into());
        }
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Segment {
    pub id: u64,
    pub filename: String,
    pub sha256: String,
    pub events: u64,
    pub bytes: u64,
    pub sealed_ms: u64,
}
#[derive(Debug, Serialize)]
pub struct StorageState {
    pub config: StorageConfig,
    pub allocated_bytes: u64,
    pub used_bytes: u64,
    pub free_disk_bytes: Option<u64>,
    pub segments: Vec<Segment>,
    pub admission_ready: bool,
}
#[derive(Debug, Serialize, Deserialize)]
struct BackupFile {
    path: String,
    sha256: String,
    bytes: u64,
}
#[derive(Debug, Serialize, Deserialize)]
struct BackupManifest {
    schema: u32,
    created_ms: u64,
    files: Vec<BackupFile>,
}
fn file_hash(path: &Path) -> LabResult<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn sync_file(path: &Path) -> std::io::Result<()> {
    // Windows FlushFileBuffers requires a handle opened for writing. Opening
    // without create/truncate preserves the bytes produced by SQLite or copy.
    fs::OpenOptions::new().write(true).open(path)?.sync_all()
}

impl Engine {
    pub(crate) fn evidence_schemas(&self) -> LabResult<Vec<String>> {
        let mut names = vec!["main".into()];
        names.extend(
            self.segments()?
                .into_iter()
                .map(|s| format!("history{}", s.id)),
        );
        Ok(names)
    }
    pub(crate) fn graph_keys(&self, id: u64) -> LabResult<Vec<String>> {
        let mut keys = Vec::new();
        for schema in self.evidence_schemas()? {
            keys.extend(self.connection.prepare(&format!("SELECT entity FROM {schema}.graph_links WHERE event_id=?1 ORDER BY entity LIMIT 16"))?.query_map([id],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?);
        }
        keys.sort();
        keys.dedup();
        keys.truncate(16);
        Ok(keys)
    }
    pub(crate) fn graph_neighbors(
        &self,
        entity: &str,
        id: u64,
        before_ms: u64,
        limit: usize,
    ) -> LabResult<Vec<u64>> {
        let mut rows = Vec::new();
        for schema in self.evidence_schemas()? {
            rows.extend(self.connection.prepare(&format!("SELECT event_id,time_ms FROM {schema}.graph_links WHERE entity=?1 AND event_id<>?2 AND time_ms<=?3 ORDER BY time_ms DESC,event_id DESC LIMIT ?4"))?.query_map(params![entity,id,before_ms,limit],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,u64>(1)?)))?.collect::<Result<Vec<_>,_>>()?);
        }
        rows.sort_unstable_by(|a, b| (b.1, b.0).cmp(&(a.1, a.0)));
        rows.dedup_by_key(|r| r.0);
        rows.truncate(limit);
        Ok(rows.into_iter().map(|r| r.0).collect())
    }
    pub fn backup_to(&mut self, destination: &Path, now: u64) -> LabResult<()> {
        if destination.exists() {
            return Err("Backup destination already exists; choose a new directory".into());
        }
        self.flush(now)?;
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let pending = parent.join(format!(".athernex-backup-{}", secret()?));
        fs::create_dir(&pending)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&pending, fs::Permissions::from_mode(0o700))?;
        }
        let ledger = pending.join("ledger.sqlite3");
        self.connection.execute(
            "VACUUM main INTO ?1",
            [ledger.to_str().ok_or("Backup path is not UTF-8")?],
        )?;
        let mut files = vec![BackupFile {
            path: "ledger.sqlite3".into(),
            sha256: file_hash(&ledger)?,
            bytes: fs::metadata(&ledger)?.len(),
        }];
        sync_file(&ledger)?;
        let directory = pending.join("ledger.sqlite3.segments");
        fs::create_dir(&directory)?;
        for segment in self.segments()? {
            let source = self.segment_path(segment.id)?;
            let target = directory.join(&segment.filename);
            fs::copy(source, &target)?;
            sync_file(&target)?;
            if file_hash(&target)? != segment.sha256 {
                return Err(
                    "Backup segment verification failed; live evidence is unchanged".into(),
                );
            }
            files.push(BackupFile {
                path: format!("ledger.sqlite3.segments/{}", segment.filename),
                sha256: segment.sha256,
                bytes: segment.bytes,
            });
        }
        let manifest = BackupManifest {
            schema: 5,
            created_ms: now,
            files,
        };
        let mut file = fs::File::create(pending.join("manifest.json"))?;
        file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
        file.sync_all()?;
        // Close all members before publishing the directory on Windows.
        drop(file);
        verify_backup(&pending)?;
        #[cfg(unix)]
        {
            fs::File::open(&directory)?.sync_all()?;
            fs::File::open(&pending)?.sync_all()?;
        }
        fs::rename(&pending, destination)
            .map_err(|e| format!("Publish verified backup directory: {e}"))?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub(crate) fn init_storage(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS storage_config(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence_segments(id INTEGER PRIMARY KEY,filename TEXT NOT NULL UNIQUE,sha256 TEXT NOT NULL,events INTEGER NOT NULL,bytes INTEGER NOT NULL,sealed_ms INTEGER NOT NULL);")?;
        self.connection.execute(
            "INSERT OR IGNORE INTO storage_config VALUES(1,?1)",
            [serde_json::to_string(&StorageConfig::default())?],
        )?;
        let config = self.storage_config()?;
        self.apply_page_budget(&config)?;
        for segment in self.segments()? {
            self.attach_segment(&segment)?;
        }
        self.refresh_history_views()?;
        Ok(())
    }
    fn apply_page_budget(&self, config: &StorageConfig) -> LabResult<()> {
        let page: u64 = self
            .connection
            .query_row("PRAGMA page_size", [], |r| r.get(0))?;
        self.connection.pragma_update(
            None,
            "max_page_count",
            config.ledger_mib * 1024 * 1024 / page,
        )?;
        Ok(())
    }
    pub fn storage_config(&self) -> LabResult<StorageConfig> {
        let raw: String = self.connection.query_row(
            "SELECT payload FROM storage_config WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        Ok(serde_json::from_str(&raw)?)
    }
    pub fn configure_storage(&self, config: StorageConfig, now: u64) -> LabResult<()> {
        config.validate()?;
        let state = self.storage_state()?;
        if config.ledger_mib * 1024 * 1024 < state.allocated_bytes
            || config.segment_limit < state.segments.len()
        {
            return Err(
                "New quota is below existing allocation; export/compact before reducing it".into(),
            );
        }
        self.connection.execute(
            "UPDATE storage_config SET payload=?1 WHERE id=1",
            [serde_json::to_string(&config)?],
        )?;
        self.apply_page_budget(&config)?;
        self.audit("storage.configured", &serde_json::to_string(&config)?, now)?;
        Ok(())
    }
    pub fn segments(&self) -> LabResult<Vec<Segment>> {
        Ok(self.connection.prepare("SELECT id,filename,sha256,events,bytes,sealed_ms FROM evidence_segments ORDER BY id")?.query_map([],|r|Ok(Segment{id:r.get(0)?,filename:r.get(1)?,sha256:r.get(2)?,events:r.get(3)?,bytes:r.get(4)?,sealed_ms:r.get(5)?}))?.collect::<Result<_,_>>()?)
    }
    fn segment_directory(&self) -> LabResult<PathBuf> {
        let path = self
            .path
            .as_ref()
            .ok_or("Evidence sealing requires a file-backed ledger")?;
        let mut name = path.as_os_str().to_os_string();
        name.push(".segments");
        Ok(name.into())
    }
    pub fn segment_path(&self, id: u64) -> LabResult<PathBuf> {
        let segment = self
            .segments()?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("Unknown segment")?;
        Ok(self.segment_directory()?.join(segment.filename))
    }
    fn attach_segment(&self, segment: &Segment) -> LabResult<()> {
        if !segment.filename.starts_with("segment-")
            || !segment.filename.ends_with(".sqlite3")
            || segment.filename.contains(['/', '\\'])
        {
            return Err("Invalid segment filename".into());
        }
        let path = self.segment_directory()?.join(&segment.filename);
        if fs::metadata(&path)?.len() != segment.bytes || file_hash(&path)? != segment.sha256 {
            return Err("Sealed evidence segment is missing or corrupt".into());
        }
        self.connection.execute(
            &format!("ATTACH DATABASE ?1 AS history{}", segment.id),
            [path.to_str().ok_or("Segment path is not UTF-8")?],
        )?;
        Ok(())
    }
    fn refresh_history_views(&self) -> LabResult<()> {
        let segments = self.segments()?;
        for table in [
            "evidence_refs",
            "evidence_objects",
            "graph_links",
            "endpoint_events",
        ] {
            let mut query = format!("SELECT * FROM main.{table}");
            for segment in &segments {
                query.push_str(&format!(
                    " UNION ALL SELECT * FROM history{}.{table}",
                    segment.id
                ));
            }
            self.connection.execute_batch(&format!(
                "DROP VIEW IF EXISTS temp.all_{table};CREATE TEMP VIEW all_{table} AS {query};"
            ))?;
        }
        Ok(())
    }
    pub fn storage_state(&self) -> LabResult<StorageState> {
        let config = self.storage_config()?;
        let page: u64 = self
            .connection
            .query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let pages: u64 = self
            .connection
            .query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let free: u64 = self
            .connection
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        let free_disk_bytes = self.path.as_ref().map(fs2::available_space).transpose()?;
        let segments = self.segments()?;
        let used_bytes = (pages - free) * page;
        let records: usize =
            self.connection
                .query_row("SELECT count(*) FROM evidence_refs", [], |r| r.get(0))?;
        let requires_seal = records >= config.segment_records
            || used_bytes >= config.ledger_mib * 1024 * 1024 * 75 / 100;
        let cold_exists: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM evidence_refs WHERE id NOT IN(SELECT id FROM temp.events) AND id NOT IN(SELECT event_id FROM investigation_cache) AND id NOT IN(SELECT event_id FROM evidence_locations))", [], |r| r.get(0))?;
        let segments_exhausted = self.path.is_some()
            && segments.len() >= config.segment_limit
            && requires_seal
            && cold_exists;
        let admission_ready = used_bytes < config.ledger_mib * 1024 * 1024 * 95 / 100
            && free_disk_bytes.is_none_or(|n| n >= config.minimum_free_mib * 1024 * 1024)
            && !segments_exhausted;
        Ok(StorageState {
            config,
            allocated_bytes: pages * page,
            used_bytes,
            free_disk_bytes,
            segments,
            admission_ready,
        })
    }
    pub(crate) fn prepare_storage(&self, now: u64) -> LabResult<()> {
        if !self.connection.is_autocommit() {
            return Err("Storage admission must precede the ingestion transaction".into());
        }
        let labels: usize = self
            .connection
            .query_row("SELECT count(*) FROM labels", [], |r| r.get(0))?;
        if labels + crate::model::MAX_BATCH * 3 > crate::model::MAX_LABELS {
            self.reclaim_dictionary()?;
        }
        let state = self.storage_state()?;
        if state
            .free_disk_bytes
            .is_some_and(|n| n < state.config.minimum_free_mib * 1024 * 1024)
        {
            return Err(
                "Storage capacity low: retry after freeing disk space; batch not acknowledged"
                    .into(),
            );
        }
        let records: u64 =
            self.connection
                .query_row("SELECT count(*) FROM evidence_refs", [], |r| r.get(0))?;
        if self.path.is_some()
            && (records >= state.config.segment_records as u64
                || state.used_bytes >= state.config.ledger_mib * 1024 * 1024 * 75 / 100)
        {
            self.seal_evidence_budgeted(now, orchestrator::governor::Class::Essential)?;
        }
        if !self.storage_state()?.admission_ready {
            return Err("Storage capacity exhausted: export or increase the ledger budget; batch not acknowledged".into());
        }
        Ok(())
    }
    pub fn seal_evidence(&self, now: u64) -> LabResult<Option<u64>> {
        self.seal_evidence_budgeted(now, orchestrator::governor::Class::Batch)
    }
    fn seal_evidence_budgeted(
        &self,
        now: u64,
        class: orchestrator::governor::Class,
    ) -> LabResult<Option<u64>> {
        self.with_job_budget(
            "sealing",
            class,
            orchestrator::governor::Resources {
                cpu_millis: 1000,
                memory_mib: 64,
                io_mib: 64,
                ..Default::default()
            },
            now,
            || self.seal_evidence_inner(now),
        )
    }
    fn seal_evidence_inner(&self, now: u64) -> LabResult<Option<u64>> {
        if !self.connection.is_autocommit() {
            return Err("Cannot seal during another transaction".into());
        }
        let config = self.storage_config()?;
        let segments = self.segments()?;
        // Hot/context and remotely registered evidence stays in the live ledger.
        let ids=self.connection.prepare("SELECT id FROM evidence_refs WHERE id NOT IN(SELECT id FROM temp.events) AND id NOT IN(SELECT event_id FROM investigation_cache) AND id NOT IN(SELECT event_id FROM evidence_locations) ORDER BY id LIMIT ?1")?.query_map([config.segment_records],|r|r.get::<_,u64>(0))?.collect::<Result<Vec<_>,_>>()?;
        if ids.is_empty() {
            return Ok(None);
        }
        if segments.len() >= config.segment_limit {
            return Err("Evidence segment capacity reached; export the ledger and segments or increase the configured segment budget".into());
        }
        let directory = self.segment_directory()?;
        fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let temp_path = directory.join(format!("pending-{}.sqlite3", secret()?));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.flush()?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
        }
        let outgoing = rusqlite::Connection::open(&temp_path)?;
        outgoing.execute_batch("PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;
            CREATE TABLE evidence_refs(id INTEGER PRIMARY KEY,hash BLOB UNIQUE NOT NULL,time_ms INTEGER NOT NULL,observed_ms INTEGER NOT NULL,source TEXT NOT NULL,subject TEXT NOT NULL,severity INTEGER NOT NULL,dedup TEXT UNIQUE,input_hash BLOB);
            CREATE INDEX evidence_time ON evidence_refs(time_ms,id);
            CREATE TABLE evidence_objects(hash BLOB PRIMARY KEY,payload BLOB NOT NULL,raw_bytes INTEGER NOT NULL) WITHOUT ROWID;
            CREATE TABLE graph_links(entity TEXT NOT NULL,event_id INTEGER NOT NULL,time_ms INTEGER NOT NULL,PRIMARY KEY(entity,event_id)) WITHOUT ROWID;
            CREATE INDEX graph_event ON graph_links(event_id);
            CREATE INDEX graph_time ON graph_links(entity,time_ms,event_id);
            CREATE TABLE endpoint_events(endpoint_id TEXT NOT NULL,event_id TEXT NOT NULL,event_hash TEXT NOT NULL,evidence_id INTEGER NOT NULL,case_id INTEGER,payload TEXT NOT NULL,PRIMARY KEY(endpoint_id,event_id));
            CREATE INDEX endpoint_observation_lookup ON endpoint_events(endpoint_id,evidence_id);")?;
        let tx = rusqlite::Transaction::new_unchecked(
            &outgoing,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        for id in &ids {
            let row=self.connection.query_row("SELECT hash,time_ms,observed_ms,source,subject,severity,dedup,input_hash FROM evidence_refs WHERE id=?1",[id],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,u64>(1)?,r.get::<_,u64>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,u8>(5)?,r.get::<_,Option<String>>(6)?,r.get::<_,Option<Vec<u8>>>(7)?)))?;
            tx.execute(
                "INSERT INTO evidence_refs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![id, row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7],
            )?;
            for object in self.evidence_bundle(*id)? {
                let hash = Sha256::digest(&object).to_vec();
                let mut compressed =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
                compressed.write_all(&object)?;
                tx.execute(
                    "INSERT OR IGNORE INTO evidence_objects VALUES(?1,?2,?3)",
                    params![hash, compressed.finish()?, object.len()],
                )?;
            }
            let links = self
                .connection
                .prepare("SELECT entity,time_ms FROM graph_links WHERE event_id=?1")?
                .query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            for (entity, time) in links {
                tx.execute(
                    "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
                    params![entity, id, time],
                )?;
            }
            let event=self.connection.query_row("SELECT endpoint_id,event_id,event_hash,case_id,payload FROM endpoint_events WHERE evidence_id=?1",[id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<i64>>(3)?,r.get::<_,String>(4)?))).optional()?;
            if let Some((endpoint, event, hash, case, payload)) = event {
                tx.execute(
                    "INSERT INTO endpoint_events VALUES(?1,?2,?3,?4,?5,?6)",
                    params![endpoint, event, hash, id, case, payload],
                )?;
            }
        }
        tx.commit()?;
        let integrity: String = outgoing.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err("Segment integrity check failed".into());
        }
        drop(outgoing);
        sync_file(&temp_path)?;
        let hash = file_hash(&temp_path)?;
        let filename = format!("segment-{hash}.sqlite3");
        let final_path = directory.join(&filename);
        if final_path.exists() {
            if file_hash(&final_path)? != hash {
                return Err("Orphaned evidence segment failed verification".into());
            }
            fs::remove_file(&temp_path)?;
        } else {
            fs::rename(&temp_path, &final_path)?;
        }
        #[cfg(unix)]
        fs::File::open(&directory)?.sync_all()?;
        let segment = Segment {
            id: segments.last().map_or(1, |s| s.id + 1),
            filename,
            sha256: hash,
            events: ids.len() as u64,
            bytes: fs::metadata(&final_path)?.len(),
            sealed_ms: now,
        };
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        tx.execute(
            "CREATE TEMP TABLE IF NOT EXISTS sealing_ids(id INTEGER PRIMARY KEY)",
            [],
        )?;
        tx.execute("DELETE FROM sealing_ids", [])?;
        for id in &ids {
            tx.execute("INSERT INTO sealing_ids VALUES(?1)", [id])?;
        }
        tx.execute(
            "INSERT INTO evidence_segments VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                segment.id,
                segment.filename,
                segment.sha256,
                segment.events,
                segment.bytes,
                now
            ],
        )?;
        // Triggers are lifted only inside this transaction after a verified durable copy exists.
        tx.execute_batch(
            "DROP TRIGGER immutable_ref_delete;DROP TRIGGER immutable_object_delete;
            DELETE FROM relevance WHERE event_id IN(SELECT id FROM sealing_ids);
            DELETE FROM graph_links WHERE event_id IN(SELECT id FROM sealing_ids);
            DELETE FROM endpoint_events WHERE evidence_id IN(SELECT id FROM sealing_ids);
            DELETE FROM evidence_refs WHERE id IN(SELECT id FROM sealing_ids);
            CREATE TEMP TABLE IF NOT EXISTS retained_objects(hash BLOB PRIMARY KEY);
            DELETE FROM retained_objects;",
        )?;
        let retained = self
            .connection
            .prepare("SELECT id FROM evidence_refs")?
            .query_map([], |r| r.get::<_, u64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for id in retained {
            for object in self.evidence_bundle(id)? {
                tx.execute(
                    "INSERT OR IGNORE INTO retained_objects VALUES(?1)",
                    [Sha256::digest(object).to_vec()],
                )?;
            }
        }
        tx.execute_batch("DELETE FROM evidence_objects WHERE hash NOT IN(SELECT hash FROM retained_objects);
            CREATE TRIGGER immutable_ref_delete BEFORE DELETE ON evidence_refs BEGIN SELECT RAISE(ABORT,'immutable reference'); END;
            CREATE TRIGGER immutable_object_delete BEFORE DELETE ON evidence_objects BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;")?;
        self.audit(
            "storage.segment_sealed",
            &format!("{} events; SHA-256 {}", segment.events, segment.sha256),
            now,
        )?;
        tx.commit()?;
        self.attach_segment(&segment)?;
        self.refresh_history_views()?;
        self.reclaim_dictionary()?;
        Ok(Some(segment.id))
    }
    /// Rehydrate the small reference/graph only when historical evidence becomes active again.
    pub(crate) fn localize_reference(&self, id: u64) -> LabResult<()> {
        self.connection.execute("INSERT OR IGNORE INTO evidence_refs SELECT * FROM all_evidence_refs WHERE id=?1 LIMIT 1",[id])?;
        self.connection.execute(
            "INSERT OR IGNORE INTO graph_links SELECT * FROM all_graph_links WHERE event_id=?1",
            [id],
        )?;
        Ok(())
    }
    fn reclaim_dictionary(&self) -> LabResult<()> {
        let events = self.events()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS active_labels(id INTEGER PRIMARY KEY);DELETE FROM active_labels;")?;
        for event in events {
            for id in [
                u32::from(event.event.source),
                event.event.subject,
                event.event.object,
            ] {
                tx.execute("INSERT OR IGNORE INTO active_labels VALUES(?1)", [id])?;
            }
        }
        tx.execute_batch("DELETE FROM main.labels WHERE id NOT IN(SELECT id FROM active_labels);DELETE FROM temp.labels WHERE id NOT IN(SELECT id FROM active_labels);")?;
        tx.commit()?;
        Ok(())
    }
}

pub fn verify_backup(directory: &Path) -> LabResult<usize> {
    let raw = fs::read(directory.join("manifest.json"))?;
    if raw.len() > 16384 {
        return Err("Invalid backup manifest size".into());
    }
    let manifest: BackupManifest = serde_json::from_slice(&raw)?;
    if manifest.schema != 5
        || manifest.files.is_empty()
        || manifest.files.len() > 9
        || manifest.files[0].path != "ledger.sqlite3"
    {
        return Err("Unsupported backup manifest".into());
    }
    for file in &manifest.files {
        if file.path != "ledger.sqlite3"
            && !(file.path.starts_with("ledger.sqlite3.segments/segment-")
                && file.path.ends_with(".sqlite3")
                && file.path.bytes().filter(|b| *b == b'/').count() == 1)
        {
            return Err("Invalid backup member path".into());
        }
        if file.path.contains("..") || file.path.contains('\\') {
            return Err("Invalid backup member path".into());
        }
        let path = directory.join(&file.path);
        if fs::symlink_metadata(&path)?.file_type().is_symlink()
            || fs::metadata(&path)?.len() != file.bytes
            || file_hash(&path)? != file.sha256
        {
            return Err("Backup checksum mismatch".into());
        }
        let db = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let result: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if result != "ok" {
            return Err("Backup SQLite integrity check failed".into());
        }
    }
    Ok(manifest.files.len())
}

/// Restore into a new private directory, then verify the copied bytes again.
/// Existing directories are never replaced; an incomplete restore is retained
/// for inspection and cannot be mistaken for a successful return value.
pub fn restore_backup(source: &Path, destination: &Path) -> LabResult<std::path::PathBuf> {
    verify_backup(source)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&fs::read(source.join("manifest.json"))?)?;
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder.create(destination)?;
    for name in manifest
        .files
        .iter()
        .map(|f| f.path.as_str())
        .chain(std::iter::once("manifest.json"))
    {
        let path = destination.join(name);
        if let Some(parent) = path.parent().filter(|p| *p != destination) {
            if !parent.exists() {
                builder.create(parent)?;
            }
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&path)?;
        let mut input = fs::File::open(source.join(name))?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
    }
    verify_backup(destination)?;
    #[cfg(unix)]
    {
        let segments = destination.join("ledger.sqlite3.segments");
        if segments.exists() {
            fs::File::open(segments)?.sync_all()?;
        }
        fs::File::open(destination)?.sync_all()?;
    }
    Ok(destination.join("ledger.sqlite3"))
}
