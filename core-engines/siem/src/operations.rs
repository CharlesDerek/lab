//! Persistent operational sources and analyst-owned investigations.
use crate::{
    engine::{Engine, LabResult},
    gateway::{digest, secret},
    model::*,
};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub id: String,
    pub kind: String,
    pub selector: String,
    pub enabled: bool,
    pub received: u64,
    pub rejected: u64,
    pub last_event_ms: u64,
    pub last_poll_ms: u64,
    pub error: String,
    #[serde(skip)]
    pub cursor: String,
    #[serde(skip)]
    pub generation: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct Case {
    pub id: i64,
    pub finding_id: Option<i64>,
    pub title: String,
    pub owner: String,
    pub severity: u8,
    pub status: String,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub version: u64,
    pub evidence: Vec<DisplayEvent>,
    pub notes: Vec<CaseNote>,
}
#[derive(Debug, Clone, Serialize)]
pub struct CaseNote {
    pub time_ms: u64,
    pub text: String,
}
pub struct CaseUpdate<'a> {
    pub owner: &'a str,
    pub status: &'a str,
    pub severity: u8,
    pub note: &'a str,
}
pub const CASE_STATES: &[&str] = &[
    "open",
    "triage",
    "in_progress",
    "resolved",
    "false_positive",
];
pub fn case_open(status: &str) -> bool {
    matches!(status, "open" | "triage" | "in_progress")
}
fn text_valid(value: &str, max: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max
        && !value.chars().any(|c| c.is_control() && c != '\n')
}
impl Engine {
    pub(crate) fn init_operations(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY,kind TEXT NOT NULL,selector TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1,token_hash TEXT NOT NULL DEFAULT '',received INTEGER NOT NULL DEFAULT 0,rejected INTEGER NOT NULL DEFAULT 0,last_event_ms INTEGER NOT NULL DEFAULT 0,last_poll_ms INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',cursor TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL DEFAULT 0);
        CREATE TEMP TABLE source_cursors(id TEXT PRIMARY KEY,cursor TEXT NOT NULL);
        CREATE TEMP TABLE source_progress(id TEXT PRIMARY KEY,received INTEGER NOT NULL DEFAULT 0,rejected INTEGER NOT NULL DEFAULT 0,last_event_ms INTEGER NOT NULL DEFAULT 0,last_poll_ms INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '');
        INSERT OR IGNORE INTO sources(id,kind) VALUES ('agent-gateway','internal');
        CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY AUTOINCREMENT,finding_id INTEGER UNIQUE,title TEXT NOT NULL,owner TEXT NOT NULL DEFAULT '',severity INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'open',created_ms INTEGER NOT NULL,updated_ms INTEGER NOT NULL,version INTEGER NOT NULL DEFAULT 1,evidence TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS case_notes(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,time_ms INTEGER NOT NULL,text TEXT NOT NULL);")?;
        // Preserve previous findings as independently retained investigations.
        if !self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='cases_migrated')",
            [],
            |r| r.get::<_, bool>(0),
        )? {
            self.connection.execute("INSERT OR IGNORE INTO cases(finding_id,title,severity,status,created_ms,updated_ms,evidence) SELECT id,title,severity,status,time_ms,time_ms,evidence FROM findings",[])?;
            self.connection
                .execute("INSERT INTO metadata VALUES ('cases_migrated','1')", [])?;
        }
        Ok(())
    }
    pub fn configure_mode(&mut self, demo: bool) -> LabResult<()> {
        let requested = if demo { "demo" } else { "operational" };
        let existing: Option<String> = self
            .connection
            .query_row("SELECT value FROM metadata WHERE key='mode'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(existing) = existing {
            if existing != requested {
                return Err("This ledger belongs to a different mode. Use separate live and demo databases.".into());
            }
        } else {
            let populated:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM events) OR EXISTS(SELECT 1 FROM findings) OR EXISTS(SELECT 1 FROM agents) OR EXISTS(SELECT 1 FROM settings WHERE key='received' AND value>0)",[],|r|r.get(0))?;
            if populated && !demo {
                return Err("An existing unclassified ledger cannot become a live ledger. Keep it with --demo and use a fresh live database.".into());
            }
            self.connection
                .execute("INSERT INTO metadata VALUES ('mode',?1)", [requested])?;
        }
        self.demo = demo;
        Ok(())
    }
    pub fn sources(&self) -> LabResult<Vec<Source>> {
        Ok(self.connection.prepare("SELECT s.id,kind,selector,enabled,s.received+coalesce(h.received,0),s.rejected+coalesce(h.rejected,0),max(s.last_event_ms,coalesce(h.last_event_ms,0)),max(s.last_poll_ms,coalesce(h.last_poll_ms,0)),coalesce(h.error,s.error),coalesce(p.cursor,s.cursor),generation FROM sources s LEFT JOIN source_cursors p ON p.id=s.id LEFT JOIN source_progress h ON h.id=s.id ORDER BY kind,s.id")?.query_map([],|r|Ok(Source{id:r.get(0)?,kind:r.get(1)?,selector:r.get(2)?,enabled:r.get(3)?,received:r.get(4)?,rejected:r.get(5)?,last_event_ms:r.get(6)?,last_poll_ms:r.get(7)?,error:r.get(8)?,cursor:r.get(9)?,generation:r.get(10)?}))?.collect::<Result<_,_>>()?)
    }
    pub fn create_source(
        &self,
        id: &str,
        kind: &str,
        selector: &str,
        now: u64,
    ) -> LabResult<Option<String>> {
        if id.is_empty()
            || id.len() > 48
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || id == "agent-gateway"
            || !["journal", "api"].contains(&kind)
        {
            return Err(
                "Use a unique 1–48 character source ID and the journal or API adapter.".into(),
            );
        }
        if selector.len() > 96
            || !selector
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            || (kind == "api" && !selector.is_empty())
        {
            return Err(
                "Journal selector must be an exact systemd unit name; leave empty for all units."
                    .into(),
            );
        }
        let count: u64 = self
            .connection
            .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))?;
        if count >= 32 {
            return Err("Source budget reached (32)".into());
        }
        let token = if kind == "api" { Some(secret()?) } else { None };
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        tx.execute(
            "INSERT INTO sources(id,kind,selector,token_hash) VALUES (?1,?2,?3,?4)",
            params![
                id,
                kind,
                selector,
                token.as_deref().map(digest).unwrap_or_default()
            ],
        )?;
        self.audit("source.created", &format!("{id} / {kind}"), now)?;
        tx.commit()?;
        Ok(token)
    }
    pub fn source_action(&self, id: &str, action: &str, now: u64) -> LabResult<Option<String>> {
        let source = self
            .sources()?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("Source not found")?;
        if source.kind == "internal" {
            return Err("The authority audit source is always enabled".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let token = match action {
            "pause" | "resume" => {
                tx.execute(
                    "UPDATE sources SET enabled=?1,error='' WHERE id=?2",
                    params![action == "resume", id],
                )?;
                None
            }
            "rotate_token" if source.kind == "api" => {
                let token = secret()?;
                tx.execute(
                    "UPDATE sources SET token_hash=?1 WHERE id=?2",
                    params![digest(&token), id],
                )?;
                Some(token)
            }
            "reset_cursor" if source.kind == "journal" => {
                tx.execute("UPDATE sources SET cursor='',error='' WHERE id=?1", [id])?;
                tx.execute("DELETE FROM source_cursors WHERE id=?1", [id])?;
                None
            }
            _ => return Err("Unsupported source operation".into()),
        };
        tx.execute(
            "UPDATE sources SET generation=generation+1 WHERE id=?1",
            [id],
        )?;
        tx.execute("UPDATE source_progress SET error='' WHERE id=?1", [id])?;
        self.audit(&format!("source.{action}"), id, now)?;
        tx.commit()?;
        Ok(token)
    }
    pub fn source_error(&self, id: &str, error: &str, rejected: u64, now: u64) -> LabResult<()> {
        // Operational errors are bounded; never include journal MESSAGE content.
        let error = error.chars().take(240).collect::<String>();
        self.connection.execute(
            "INSERT INTO source_progress(id,error,last_poll_ms,rejected) VALUES (?4,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET error=excluded.error,last_poll_ms=excluded.last_poll_ms,rejected=source_progress.rejected+excluded.rejected",
            params![error, now, rejected, id],
        )?;
        Ok(())
    }
    pub fn ingest_source(
        &mut self,
        id: &str,
        token: Option<&str>,
        inputs: &[InputEvent],
        cursor: Option<&str>,
        skipped: u64,
        now: u64,
    ) -> LabResult<usize> {
        let source = self
            .sources()?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or("Source not found")?;
        if !source.enabled {
            return Err("Source is paused".into());
        }
        if source.kind == "api" {
            let expected: String = self.connection.query_row(
                "SELECT token_hash FROM sources WHERE id=?1",
                [id],
                |r| r.get(0),
            )?;
            if token.map(digest).as_deref() != Some(expected.as_str()) {
                return Err("Source credential rejected".into());
            }
        } else if source.kind != "journal" || token.is_some() {
            return Err("Wrong ingestion boundary".into());
        }
        if inputs.len() > MAX_BATCH || inputs.iter().any(|e| e.source != id) {
            return Err(
                "A batch must use its registered source and contain at most 256 events".into(),
            );
        }
        for input in inputs {
            if source.kind == "api" && input.context.is_some() {
                return Err("Collector provenance cannot be supplied through API ingestion".into());
            }
            input.validate(now)?;
        }
        self.prepare_storage(now)?;
        if self.pending_count()? + inputs.len() > 512 {
            self.flush(now)?;
        }
        self.reserve_ids(inputs.len())?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let accepted = if inputs.is_empty() {
            0
        } else {
            self.ingest_in_transaction(inputs, now)?
        };
        tx.execute("UPDATE sources SET received=received+?1,rejected=rejected+?2,last_event_ms=CASE WHEN ?1>0 THEN max(last_event_ms,?3) ELSE last_event_ms END,last_poll_ms=max(last_poll_ms,?3),error='' WHERE id=?4",params![accepted,skipped,now,id])?;
        if let Some(cursor) = cursor {
            if cursor.len() > 512 || cursor.chars().any(char::is_control) {
                return Err("Invalid journal checkpoint".into());
            }
            tx.execute(
                "UPDATE sources SET cursor=?2 WHERE id=?1",
                params![id, cursor],
            )?;
        }
        tx.commit()?;
        Ok(accepted)
    }
    pub(crate) fn sync_case(
        &self,
        finding_id: i64,
        title: &str,
        severity: u8,
        evidence: &str,
        now: u64,
    ) -> LabResult<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE finding_id=?1)",
            [finding_id],
            |r| r.get(0),
        )?;
        if exists {
            return Ok(());
        }
        self.case_capacity()?;
        self.connection.execute("INSERT INTO cases(finding_id,title,severity,created_ms,updated_ms,evidence) VALUES (?1,?2,?3,?4,?4,?5)",params![finding_id,title,severity,now,evidence])?;
        Ok(())
    }
    fn case_capacity(&self) -> LabResult<()> {
        let count: u64 = self
            .connection
            .query_row("SELECT count(*) FROM cases", [], |r| r.get(0))?;
        if count >= 256 {
            return Err("Investigation capacity reached (256). Export and archive closed cases before admitting more.".into());
        }
        Ok(())
    }
    pub fn create_case(&self, title: &str, severity: u8, now: u64) -> LabResult<i64> {
        if !text_valid(title, 160) || !(1..=5).contains(&severity) {
            return Err("Use a 1–160 byte title and severity 1–5".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.case_capacity()?;
        tx.execute("INSERT INTO cases(title,severity,created_ms,updated_ms,evidence) VALUES (?1,?2,?3,?3,'[]')",params![title,severity,now])?;
        let id = tx.last_insert_rowid();
        self.audit("case.created", &format!("case-{id}"), now)?;
        tx.commit()?;
        Ok(id)
    }
    pub fn cases(&self) -> LabResult<Vec<Case>> {
        let rows=self.connection.prepare("SELECT id,finding_id,title,owner,severity,status,created_ms,updated_ms,version,evidence FROM cases ORDER BY updated_ms DESC,id DESC")?.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,Option<i64>>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,u8>(4)?,r.get::<_,String>(5)?,r.get::<_,u64>(6)?,r.get::<_,u64>(7)?,r.get::<_,u64>(8)?,r.get::<_,String>(9)?)))?.collect::<Result<Vec<_>,_>>()?;
        rows.into_iter()
            .map(
                |(
                    id,
                    finding_id,
                    title,
                    owner,
                    severity,
                    status,
                    created_ms,
                    updated_ms,
                    version,
                    evidence,
                )| {
                    let notes = self
                        .connection
                        .prepare(
                            "SELECT time_ms,text FROM case_notes WHERE case_id=?1 ORDER BY id",
                        )?
                        .query_map([id], |r| {
                            Ok(CaseNote {
                                time_ms: r.get(0)?,
                                text: r.get(1)?,
                            })
                        })?
                        .collect::<Result<_, _>>()?;
                    Ok(Case {
                        id,
                        finding_id,
                        title,
                        owner,
                        severity,
                        status,
                        created_ms,
                        updated_ms,
                        version,
                        evidence: serde_json::from_str(&evidence)?,
                        notes,
                    })
                },
            )
            .collect()
    }
    pub fn update_case(
        &self,
        id: i64,
        version: u64,
        update: CaseUpdate<'_>,
        now: u64,
    ) -> LabResult<()> {
        let CaseUpdate {
            owner,
            status,
            severity,
            note,
        } = update;
        if owner.len() > 64
            || owner.chars().any(char::is_control)
            || !CASE_STATES.contains(&status)
            || !(1..=5).contains(&severity)
            || (!note.is_empty() && !text_valid(note, 2000))
        {
            return Err("Invalid investigation update".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if tx.execute("UPDATE cases SET owner=?1,status=?2,severity=?3,updated_ms=?4,version=version+1 WHERE id=?5 AND version=?6",params![owner,status,severity,now,id,version])?!=1{return Err("Investigation changed. Reload before saving.".into());}
        if !note.is_empty() {
            let count: u64 = tx.query_row(
                "SELECT count(*) FROM case_notes WHERE case_id=?1",
                [id],
                |r| r.get(0),
            )?;
            if count >= 64 {
                return Err("Case note budget reached (64); export before archiving".into());
            }
            tx.execute(
                "INSERT INTO case_notes(case_id,time_ms,text) VALUES (?1,?2,?3)",
                params![id, now, note],
            )?;
        }
        tx.execute(
            "UPDATE findings SET status=?1 WHERE id=(SELECT finding_id FROM cases WHERE id=?2)",
            params![
                if case_open(status) {
                    "open"
                } else {
                    "resolved"
                },
                id
            ],
        )?;
        if !case_open(status) {
            tx.execute("UPDATE plans SET state='rejected' WHERE finding_id=(SELECT finding_id FROM cases WHERE id=?1) AND state IN ('awaiting_review','approved')",[id])?;
        }
        self.audit(
            "case.updated",
            &format!("case-{id} / {status} / assigned {owner}"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn attach_case_event(
        &self,
        id: i64,
        version: u64,
        event: DisplayEvent,
        now: u64,
    ) -> LabResult<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let status: String =
            tx.query_row("SELECT status FROM cases WHERE id=?1", [id], |r| r.get(0))?;
        if !case_open(&status) {
            return Err("Reopen the investigation before attaching evidence".into());
        }
        let raw: String = tx.query_row(
            "SELECT evidence FROM cases WHERE id=?1 AND version=?2",
            params![id, version],
            |r| r.get(0),
        )?;
        let mut evidence: Vec<DisplayEvent> = serde_json::from_str(&raw)?;
        if evidence.iter().any(|e| e.event.id == event.event.id) {
            return Err("Event is already attached".into());
        }
        if evidence.len() >= 64 {
            return Err("Case evidence budget reached (64 events)".into());
        }
        let event_id = event.event.id;
        evidence.push(event);
        tx.execute("UPDATE cases SET evidence=?1,version=version+1,updated_ms=?2 WHERE id=?3 AND version=?4",params![serde_json::to_string(&evidence)?,now,id,version])?;
        self.audit(
            "case.evidence-attached",
            &format!("case-{id} / event-{event_id}"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn delete_case(&self, id: i64, version: u64, now: u64) -> LabResult<()> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let responses: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM endpoint_commands WHERE case_id=?1)",
            [id],
            |r| r.get(0),
        )?;
        if responses {
            return Err("Cases with endpoint response records are retained for receipt replay and audit; export the case or a complete backup".into());
        }
        let finding: Option<i64> =
            tx.query_row("SELECT finding_id FROM cases WHERE id=?1", [id], |r| {
                r.get(0)
            })?;
        if tx.execute("DELETE FROM cases WHERE id=?1 AND version=?2 AND status IN ('resolved','false_positive')",params![id,version])?!=1{return Err("Only a current, closed case can be removed after export".into());}
        // A retained finding must not recreate the case on next startup.
        tx.execute("DELETE FROM plans WHERE finding_id=?1", [finding])?;
        self.audit(
            "case.deleted",
            &format!("case-{id}; operator confirmed exported copy"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_800_000_000_000;
    fn fact(source: &str, n: u64) -> InputEvent {
        InputEvent {
            time_ms: NOW + n,
            source: source.into(),
            subject: "fixture-user".into(),
            object: "ssh:192.0.2.10".into(),
            kind: Kind::Authentication,
            outcome: Outcome::Deny,
            severity: 3,
            bytes: 0,
            trace: 0,
            idempotency_key: format!("fixture-{n}"),
            context: None,
        }
    }
    #[test]
    fn source_credentials_are_scoped_rotatable_and_pauseable() {
        let mut e = Engine::memory().unwrap();
        let key = e.create_source("fixture", "api", "", NOW).unwrap().unwrap();
        let f = fact("fixture", 1);
        assert!(e
            .ingest_source(
                "fixture",
                Some("wrong"),
                std::slice::from_ref(&f),
                None,
                0,
                NOW + 10
            )
            .is_err());
        assert!(e
            .ingest_source(
                "fixture",
                Some(&key),
                &[fact("agent-gateway", 2)],
                None,
                0,
                NOW + 10
            )
            .is_err());
        assert_eq!(
            e.ingest_source(
                "fixture",
                Some(&key),
                std::slice::from_ref(&f),
                None,
                0,
                NOW + 10
            )
            .unwrap(),
            1
        );
        assert_eq!(
            e.ingest_source("fixture", Some(&key), &[f], None, 0, NOW + 10)
                .unwrap(),
            0
        );
        e.source_action("fixture", "pause", NOW).unwrap();
        assert!(e
            .ingest_source(
                "fixture",
                Some(&key),
                &[fact("fixture", 2)],
                None,
                0,
                NOW + 10
            )
            .is_err());
        e.source_action("fixture", "resume", NOW).unwrap();
        let replacement = e
            .source_action("fixture", "rotate_token", NOW)
            .unwrap()
            .unwrap();
        assert!(e
            .ingest_source(
                "fixture",
                Some(&key),
                &[fact("fixture", 2)],
                None,
                0,
                NOW + 10
            )
            .is_err());
        assert_eq!(
            e.ingest_source(
                "fixture",
                Some(&replacement),
                &[fact("fixture", 2)],
                None,
                0,
                NOW + 10
            )
            .unwrap(),
            1
        );
        let mut forged = fact("fixture", 3);
        forged.context = Some(EventContext {
            parent_pid: None,
            process_start_ms: None,
            parent_start_ms: None,
            host: "forged".into(),
            program: "sshd".into(),
            pid: Some(1),
            uid: Some(0),
            summary: "forged".into(),
            journal_cursor: "forged".into(),
        });
        assert!(e
            .ingest_source("fixture", Some(&replacement), &[forged], None, 0, NOW + 10)
            .is_err());
        assert_eq!(
            e.sources()
                .unwrap()
                .iter()
                .find(|s| s.id == "fixture")
                .unwrap()
                .received,
            2
        );
    }
    #[test]
    fn cursor_provenance_and_counts_commit_with_evidence_and_recover_after_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.db");
        let mut e = Engine::open(&path).unwrap();
        e.configure_mode(false).unwrap();
        e.create_source("journal", "journal", "", NOW).unwrap();
        let row = serde_json::json!({"__CURSOR":"s=fixture;i=1","__REALTIME_TIMESTAMP":((NOW+1)*1000).to_string(),"_COMM":"fixture","_UID":"1000","MESSAGE":"private-body-never-archived"});
        let f = crate::collector::normalize(&row, "journal", NOW + 10).unwrap();
        e.ingest_source(
            "journal",
            None,
            std::slice::from_ref(&f),
            Some("s=fixture;i=1"),
            0,
            NOW + 10,
        )
        .unwrap();
        // Evidence and its source checkpoint now commit together before the archive flush.
        drop(e);
        let mut e = Engine::open(&path).unwrap();
        e.configure_mode(false).unwrap();
        let source = e
            .sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == "journal")
            .unwrap();
        assert_eq!(source.cursor, "s=fixture;i=1");
        assert_eq!(source.received, 1);
        assert_eq!(e.events().unwrap().len(), 1);
        e.ingest_source(
            "journal",
            None,
            std::slice::from_ref(&f),
            Some("s=fixture;i=1"),
            0,
            NOW + 10,
        )
        .unwrap();
        e.connection.execute_batch("CREATE TRIGGER fail_archive BEFORE INSERT ON archive_blocks BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(e.flush(NOW + 10).is_err());
        assert_eq!(
            e.connection
                .query_row("SELECT cursor FROM sources WHERE id='journal'", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
            "s=fixture;i=1"
        );
        e.connection
            .execute_batch("DROP TRIGGER fail_archive")
            .unwrap();
        e.flush(NOW + 10).unwrap();
        drop(e);
        let mut e = Engine::open(&path).unwrap();
        let source = e
            .sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == "journal")
            .unwrap();
        assert_eq!(source.cursor, "s=fixture;i=1");
        assert_eq!(source.received, 1);
        let events = e.events().unwrap();
        assert_eq!(events[0].context, f.context);
        assert!(!serde_json::to_string(&events)
            .unwrap()
            .contains("private-body-never-archived"));
        assert_eq!(
            e.ingest_source("journal", None, &[f], Some("s=fixture;i=1"), 0, NOW + 10)
                .unwrap(),
            0
        );
    }
    #[test]
    fn cases_are_versioned_preserve_evidence_and_do_not_resurrect_after_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cases.db");
        let mut e = Engine::open(&path).unwrap();
        let events = (0..8).map(|n| fact("fixture", n)).collect::<Vec<_>>();
        e.ingest(&events, NOW + 10).unwrap();
        let c = e.cases().unwrap().remove(0);
        assert_eq!(c.evidence.len(), 8);
        e.update_case(
            c.id,
            c.version,
            crate::operations::CaseUpdate {
                owner: "analyst",
                status: "triage",
                severity: 4,
                note: "Verifying the source",
            },
            NOW + 20,
        )
        .unwrap();
        assert!(e
            .update_case(
                c.id,
                c.version,
                crate::operations::CaseUpdate {
                    owner: "stale",
                    status: "resolved",
                    severity: 1,
                    note: ""
                },
                NOW + 21
            )
            .is_err());
        assert!(e.delete_case(c.id, c.version + 1, NOW + 22).is_err());
        // Case evidence does not rely on hot events, archive blocks or retained findings.
        e.connection
            .execute_batch("DELETE FROM temp.events;DELETE FROM pending;DELETE FROM findings;")
            .unwrap();
        drop(e);
        let e = Engine::open(&path).unwrap();
        let c = e.cases().unwrap().remove(0);
        assert_eq!(c.owner, "analyst");
        assert_eq!(c.notes.len(), 1);
        assert_eq!(c.evidence.len(), 8);
        e.update_case(
            c.id,
            c.version,
            crate::operations::CaseUpdate {
                owner: "analyst",
                status: "resolved",
                severity: 4,
                note: "Reviewed",
            },
            NOW + 30,
        )
        .unwrap();
        e.delete_case(c.id, c.version + 1, NOW + 31).unwrap();
        drop(e);
        let e = Engine::open(&path).unwrap();
        assert!(e.cases().unwrap().is_empty());
    }
    #[test]
    fn operational_plans_execute_real_triage_once_and_closure_revokes_approval() {
        let mut e = Engine::memory().unwrap();
        e.ingest(
            &(0..8).map(|n| fact("fixture", n)).collect::<Vec<_>>(),
            NOW + 10,
        )
        .unwrap();
        let c = e.cases().unwrap().remove(0);
        let p = e.propose(c.finding_id.unwrap(), NOW + 11).unwrap();
        assert!(e.review_plan(p, "execute", NOW + 12).is_err());
        e.review_plan(p, "approve", NOW + 12).unwrap();
        assert!(e.review_plan(p, "simulate", NOW + 13).is_err());
        e.review_plan(p, "execute", NOW + 13).unwrap();
        assert!(e.review_plan(p, "execute", NOW + 14).is_err());
        let c = e.cases().unwrap().remove(0);
        assert_eq!(c.status, "triage");
        assert_eq!(c.notes.len(), 1);
        assert_eq!(e.plans().unwrap()[0].state, "executed");
    }
    #[test]
    fn operational_and_demo_ledgers_cannot_mix() {
        let mut e = Engine::memory().unwrap();
        e.configure_mode(true).unwrap();
        assert!(e.configure_mode(false).is_err());
        let mut e = Engine::memory().unwrap();
        e.configure_mode(false).unwrap();
        assert!(e.configure_mode(true).is_err());
    }
}
