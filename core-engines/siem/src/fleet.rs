//! Durable endpoint enrollment, telemetry and evidence-bound response commands.
use crate::{
    engine::{Engine, LabResult},
    gateway::{digest, secret},
    model::*,
};
use athernex_endpoint_protocol as protocol;
use protocol::telemetry::Telemetry;
use protocol::{Action, Command, EndpointEvent, Enrollment, Heartbeat, Platform, Receipt};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Endpoint {
    pub id: String,
    pub hostname: String,
    pub platform: Platform,
    pub arch: String,
    pub state: String,
    pub last_seen_ms: u64,
    pub health: Heartbeat,
}
#[derive(Debug, Serialize)]
pub struct FleetCommand {
    pub command: Command,
    pub state: String,
    pub receipt: Option<Receipt>,
}
#[derive(Debug, Serialize)]
pub struct EndpointObservation {
    pub evidence_id: u64,
    pub case_id: Option<i64>,
    pub event: EndpointEvent,
}
#[derive(Debug, Serialize)]
pub struct Fleet {
    pub endpoints: Vec<Endpoint>,
    pub commands: Vec<FleetCommand>,
    pub playbooks: Vec<Playbook>,
}
#[derive(Debug, Serialize)]
pub struct Playbook {
    pub endpoint_id: String,
    pub mode: String,
    pub revision: u64,
}

impl Engine {
    pub fn endpoint_observations(
        &self,
        endpoint: &str,
        before: u64,
        limit: usize,
    ) -> LabResult<Vec<EndpointObservation>> {
        if !protocol::hex_id(endpoint) || !(1..=64).contains(&limit) {
            return Err("Invalid endpoint observation query".into());
        }
        let mut rows = Vec::new();
        for schema in self.evidence_schemas()? {
            let sql = format!("SELECT evidence_id,case_id,payload FROM {schema}.endpoint_events WHERE endpoint_id=?1 AND evidence_id<?2 ORDER BY evidence_id DESC LIMIT ?3");
            rows.extend(
                self.connection
                    .prepare(&sql)?
                    .query_map(params![endpoint, before.min(i64::MAX as u64), limit], |r| {
                        Ok((
                            r.get::<_, u64>(0)?,
                            r.get::<_, Option<i64>>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.0));
        rows.dedup_by_key(|r| r.0);
        rows.truncate(limit);
        rows.into_iter()
            .map(|(evidence_id, case_id, raw)| {
                Ok(EndpointObservation {
                    evidence_id,
                    case_id,
                    event: serde_json::from_str(&raw)?,
                })
            })
            .collect()
    }
    pub fn endpoint_observation(&self, evidence: u64) -> LabResult<Option<EndpointObservation>> {
        let row = self.connection.query_row("SELECT evidence_id,case_id,payload FROM all_endpoint_events WHERE evidence_id=?1 LIMIT 1", [evidence], |r| Ok((r.get::<_,u64>(0)?,r.get::<_,Option<i64>>(1)?,r.get::<_,String>(2)?))).optional()?;
        row.map(|(evidence_id, case_id, raw)| {
            Ok(EndpointObservation {
                evidence_id,
                case_id,
                event: serde_json::from_str(&raw)?,
            })
        })
        .transpose()
    }
    pub fn case_endpoint_commands(&self, case_id: i64) -> LabResult<Vec<FleetCommand>> {
        let rows = self.connection.prepare("SELECT payload,state,receipt FROM endpoint_commands WHERE case_id=?1 ORDER BY rowid LIMIT 257")?
            .query_map([case_id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?)))?
            .collect::<Result<Vec<_>,_>>()?;
        if rows.len() > 256 {
            return Err(
                "Case response export exceeds 256 actions; create a complete verified backup"
                    .into(),
            );
        }
        rows.into_iter()
            .map(|(raw, state, receipt)| {
                Ok(FleetCommand {
                    command: serde_json::from_str(&raw)?,
                    state,
                    receipt: receipt.map(|s| serde_json::from_str(&s)).transpose()?,
                })
            })
            .collect()
    }
    pub(crate) fn init_fleet(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS endpoint_enrollments(hash TEXT PRIMARY KEY,platform TEXT NOT NULL,expires_ms INTEGER NOT NULL,endpoint_id TEXT);
        CREATE TABLE IF NOT EXISTS endpoints(id TEXT PRIMARY KEY,credential_hash TEXT NOT NULL,hostname TEXT NOT NULL,platform TEXT NOT NULL,arch TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'active',last_seen_ms INTEGER NOT NULL,health TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS endpoint_events(endpoint_id TEXT NOT NULL REFERENCES endpoints(id),event_id TEXT NOT NULL,event_hash TEXT NOT NULL,evidence_id INTEGER NOT NULL,case_id INTEGER,payload TEXT NOT NULL,PRIMARY KEY(endpoint_id,event_id));
        CREATE INDEX IF NOT EXISTS endpoint_observation_lookup ON endpoint_events(endpoint_id,evidence_id);
        CREATE TABLE IF NOT EXISTS endpoint_commands(id TEXT PRIMARY KEY,endpoint_id TEXT NOT NULL REFERENCES endpoints(id),payload TEXT NOT NULL,state TEXT NOT NULL,expires_ms INTEGER NOT NULL,case_id INTEGER NOT NULL REFERENCES cases(id),receipt TEXT,receipt_hash TEXT);
        CREATE INDEX IF NOT EXISTS endpoint_command_queue ON endpoint_commands(endpoint_id,state,expires_ms);
        CREATE TABLE IF NOT EXISTS endpoint_playbooks(endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id),mode TEXT NOT NULL,revision INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS endpoint_playbook_runs(command_id TEXT PRIMARY KEY REFERENCES endpoint_commands(id),endpoint_id TEXT NOT NULL,revision INTEGER NOT NULL);
        INSERT OR IGNORE INTO sources(id,kind) VALUES('endpoint','internal');")?;
        self.init_updates()?;
        self.init_rollouts()?;
        self.init_endpoint_detection()?;
        Ok(())
    }
    pub fn create_enrollment(&self, platform: Platform, now: u64) -> LabResult<String> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        tx.execute(
            "DELETE FROM endpoint_enrollments WHERE expires_ms<?1 AND endpoint_id IS NULL",
            [now],
        )?;
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM endpoint_enrollments WHERE endpoint_id IS NULL",
            [],
            |r| r.get(0),
        )?;
        if count >= 128 {
            return Err("Pending enrollment budget reached".into());
        }
        let token = secret()?;
        tx.execute(
            "INSERT INTO endpoint_enrollments VALUES(?1,?2,?3,NULL)",
            params![
                digest(&token),
                serde_json::to_string(&platform)?,
                now + 900_000
            ],
        )?;
        self.audit(
            "endpoint.enrollment_created",
            "Single-device enrollment, 15-minute expiry",
            now,
        )?;
        tx.commit()?;
        Ok(token)
    }
    pub fn enroll_endpoint(&self, request: &Enrollment, now: u64) -> LabResult<()> {
        request.validate()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let (platform, expiry, used): (String, u64, Option<String>) = tx
            .query_row(
                "SELECT platform,expires_ms,endpoint_id FROM endpoint_enrollments WHERE hash=?1",
                [digest(&request.enrollment_token)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or("Enrollment rejected")?;
        if let Some(id) = used {
            if id == request.endpoint_id
                && self.authenticate_endpoint(&id, &request.credential).is_ok()
            {
                return Ok(());
            }
            return Err("Enrollment already used".into());
        }
        if now >= expiry || platform != serde_json::to_string(&request.platform)? {
            return Err("Enrollment expired or platform mismatch".into());
        }
        let count: u64 = tx.query_row("SELECT count(*) FROM endpoints", [], |r| r.get(0))?;
        if count >= 1024 {
            return Err("Endpoint inventory budget reached".into());
        }
        let health = Heartbeat {
            controller_updates: None,
            updates: None,
            protection: None,
            collector: None,
            version: request.version.clone(),
            capabilities: vec![],
            scanner: "unverified".into(),
            realtime: false,
            signature_version: String::new(),
            spool_events: 0,
            error: "Waiting for first heartbeat".into(),
        };
        tx.execute("INSERT INTO endpoints(id,credential_hash,hostname,platform,arch,last_seen_ms,health) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![request.endpoint_id,digest(&request.credential),request.hostname,platform,request.arch,now,serde_json::to_string(&health)?])?;
        tx.execute(
            "UPDATE endpoint_enrollments SET endpoint_id=?1 WHERE hash=?2",
            params![request.endpoint_id, digest(&request.enrollment_token)],
        )?;
        self.audit("endpoint.enrolled", &request.endpoint_id, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn authenticate_endpoint(&self, id: &str, token: &str) -> LabResult<()> {
        if !protocol::hex_id(id) || !protocol::hex_id(token) {
            return Err("Endpoint credential rejected".into());
        }
        let valid:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM endpoints WHERE id=?1 AND credential_hash=?2 AND state='active')",params![id,digest(token)],|r|r.get(0))?;
        if valid {
            Ok(())
        } else {
            Err("Endpoint credential rejected".into())
        }
    }
    pub fn endpoint_heartbeat(&self, id: &str, health: &Heartbeat, now: u64) -> LabResult<()> {
        health.validate()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.connection.execute(
            "UPDATE endpoints SET health=?1,last_seen_ms=?2 WHERE id=?3 AND state='active'",
            params![serde_json::to_string(health)?, now, id],
        )?;
        self.observe_rollout_endpoint(id, health, now)?;
        self.observe_engine_rollout_endpoint(id, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn endpoint_state(&self, id: &str, state: &str, now: u64) -> LabResult<()> {
        if !["active", "revoked"].contains(&state) {
            return Err("Invalid endpoint state".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if tx.execute(
            "UPDATE endpoints SET state=?1 WHERE id=?2",
            params![state, id],
        )? != 1
        {
            return Err("Unknown endpoint".into());
        }
        if state == "revoked" {
            tx.execute("UPDATE endpoint_commands SET state='cancelled' WHERE endpoint_id=?1 AND state IN ('pending','approved')",[id])?;
        }
        self.audit("endpoint.state", &format!("{id}: {state}"), now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn endpoint_events(
        &self,
        id: &str,
        events: &[EndpointEvent],
        now: u64,
    ) -> LabResult<usize> {
        if events.is_empty() || events.len() > protocol::MAX_EVENTS {
            return Err("Endpoint batches contain 1–64 events".into());
        }
        for event in events {
            event.validate(now)?;
        }
        self.prepare_storage(now)?;
        self.reserve_ids(events.len())?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let mut accepted = 0;
        let mut observations = Vec::new();
        for event in events {
            let payload = serde_json::to_string(event)?;
            let hash = protocol::hash(payload.as_bytes());
            let previous: Option<String> = tx
                .query_row(
                    "SELECT event_hash FROM all_endpoint_events WHERE endpoint_id=?1 AND event_id=?2 LIMIT 1",
                    params![id, event.id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(previous) = previous {
                if previous != hash {
                    return Err("Endpoint replay conflicts with preserved evidence".into());
                }
                continue;
            }
            let key = protocol::hash(format!("{id}:{}", event.id).as_bytes());
            let process = event.telemetry.as_ref().and_then(Telemetry::process);
            let authentication = match &event.telemetry {
                Some(Telemetry::Authentication { event }) => Some(event),
                _ => None,
            };
            let windows_authentication = match &event.telemetry {
                Some(Telemetry::WindowsAuthentication { event }) => Some(event),
                _ => None,
            };
            let authentication_outcome = authentication
                .and_then(|a| a.service_outcome())
                .or_else(|| windows_authentication.and_then(|a| a.service_outcome()));
            let mut context = EventContext {
                host: id.into(),
                program: process
                    .map(|p| {
                        p.name
                            .chars()
                            .filter(|c| c.is_ascii_graphic())
                            .take(64)
                            .collect()
                    })
                    .unwrap_or_default(),
                pid: process.map(|p| p.pid),
                parent_pid: process.and_then(|p| p.parent_pid),
                process_start_ms: process.map(|p| p.started_ms).filter(|s| *s != 0),
                parent_start_ms: process.and_then(|p| p.parent_started_ms),
                uid: process
                    .and_then(|p| p.user_id.as_ref())
                    .and_then(|u| u.parse().ok()),
                summary: if matches!(event.telemetry, Some(Telemetry::ProcessEvent { .. })) {
                    "Linux kernel lifecycle event; executable identity is not inferred"
                } else if matches!(event.telemetry, Some(Telemetry::NetworkEvent { .. })) {
                    "Netfilter tracker observation; no process owner or firewall verdict. Counters are cumulative, not byte deltas"
                } else if event.telemetry.is_some() {
                    "Native OS snapshot observation; not a complete execution trace"
                } else {
                    "Authenticated endpoint observation"
                }
                .into(),
                journal_cursor: String::new(),
            };
            if let Some(authentication) = authentication {
                context.program = authentication
                    .journal
                    .executable
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .into();
                context.pid = Some(authentication.journal.reporter_pid);
                context.uid = Some(authentication.journal.reporter_uid);
                context.journal_cursor = authentication.journal.cursor.clone();
                context.summary = if authentication.service_outcome().is_some() {
                    "Service authentication report; PID/UID identify the reporter, while the claimed account remains separate"
                } else {
                    "PAM module failure; service authentication outcome is not established. PID/UID identify the reporter, while the claimed account remains separate"
                }.into();
            }
            if let Some(authentication) = windows_authentication {
                context.program = "Microsoft-Windows-Security-Auditing".into();
                context.pid = authentication.caller_pid;
                context.summary = if authentication.service_outcome().is_some() {
                    "Windows Security logon report; PID identifies the reported caller, while target account/domain and original XML remain separate. No Unix UID or process lifetime is inferred"
                } else {
                    "Windows NewCredentials session; outbound credential authentication is not established. Caller and target account remain separate, and original XML is retained"
                }.into();
            }
            let object = match &event.telemetry {
                Some(Telemetry::NetworkEvent { event, .. }) => {
                    format!("{}:{}", event.protocol.label(), event.original.destination)
                }
                Some(Telemetry::Authentication { event }) => event
                    .source_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "local-authentication".into()),
                Some(Telemetry::WindowsAuthentication { event }) => event
                    .source_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "local-authentication".into()),
                Some(Telemetry::ProcessEvent {
                    boot_id,
                    stream_id,
                    event,
                }) => protocol::hash(
                    format!(
                        "{boot_id}:{stream_id}:{}:{}:{}",
                        event.cpu, event.sequence, event.monotonic_ns
                    )
                    .as_bytes(),
                ),
                Some(Telemetry::Connection { connection, .. }) => connection
                    .remote
                    .unwrap_or(connection.local)
                    .ip()
                    .to_string(),
                Some(Telemetry::Process { process, .. }) => protocol::hash(
                    process
                        .executable
                        .as_deref()
                        .unwrap_or(&process.name)
                        .as_bytes(),
                ),
                None if !event.sha256.is_empty() => event.sha256.clone(),
                None => "endpoint-observation".into(),
            };
            let input = InputEvent {
                time_ms: event.time_ms,
                source: "endpoint".into(),
                subject: authentication
                    .map(|a| {
                        a.claimed_user
                            .as_ref()
                            .map(|user| {
                                protocol::hash(
                                    format!("{id}:authentication-account:{user}").as_bytes(),
                                )
                            })
                            .unwrap_or_else(|| event.id.clone())
                    })
                    .or_else(|| {
                        windows_authentication.map(|a| {
                            a.target_user
                                .as_ref()
                                .map(|user| {
                                    protocol::hash(
                                        &serde_json::to_vec(&(
                                            "windows-authentication-account",
                                            id,
                                            &a.target_domain,
                                            user,
                                        ))
                                        .expect("Serializable account scope"),
                                    )
                                })
                                .unwrap_or_else(|| event.id.clone())
                        })
                    })
                    .unwrap_or_else(|| {
                        process
                            .and_then(|p| p.user_id.as_ref())
                            .map(|u| protocol::hash(format!("{id}:user:{u}").as_bytes()))
                            .unwrap_or_else(|| id.into())
                    }),
                object,
                kind: match event.kind.as_str() {
                    "malware" => Kind::Malware,
                    "process" | "process_event" => Kind::Process,
                    "connection" | "network_event" => Kind::Network,
                    "authentication" => Kind::Authentication,
                    _ => Kind::System,
                },
                outcome: authentication_outcome
                    .map(|outcome| match outcome {
                        protocol::authentication::AuthenticationOutcome::Allowed => Outcome::Allow,
                        protocol::authentication::AuthenticationOutcome::Denied => Outcome::Deny,
                    })
                    .unwrap_or(Outcome::Observe),
                severity: if event.kind == "malware" {
                    5
                } else if authentication_outcome
                    == Some(protocol::authentication::AuthenticationOutcome::Denied)
                {
                    3
                } else {
                    1
                },
                bytes: 0,
                trace: 0,
                idempotency_key: key.clone(),
                context: Some(context),
            };
            self.ingest_in_transaction(&[input], now)?;
            let evidence_id: u64 = tx.query_row(
                "SELECT id FROM evidence_refs WHERE dedup=?1",
                [format!("endpoint:{key}")],
                |r| r.get(0),
            )?;
            let mut case_id = None;
            let file_key = format!("file-path:{id}:{}", protocol::hash(event.path.as_bytes()));
            if !event.path.is_empty() {
                tx.execute(
                    "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
                    params![file_key, evidence_id, event.time_ms],
                )?;
            }
            if event.kind == "malware" {
                let count: u64 = tx.query_row("SELECT count(*) FROM cases", [], |r| r.get(0))?;
                if count >= 256 {
                    return Err(
                        "Investigation budget reached; endpoint retains its unacknowledged event"
                            .into(),
                    );
                }
                let mut evidence = vec![self.reconstruct(evidence_id)?];
                if !event.path.is_empty() {
                    for related in self.graph_neighbors(&file_key, evidence_id, event.time_ms, 8)? {
                        let observation = self.reconstruct(related)?;
                        if event.time_ms.saturating_sub(observation.event.time_ms) <= 3_600_000 {
                            evidence.push(observation);
                        }
                    }
                }
                tx.execute("INSERT INTO cases(title,severity,created_ms,updated_ms,evidence) VALUES(?1,5,?2,?2,?3)",params![format!("Endpoint malware: {}",event.detection.chars().take(100).collect::<String>()),now,serde_json::to_string(&evidence)?])?;
                let cid = tx.last_insert_rowid();
                case_id = Some(cid);
                tx.execute(
                    "INSERT INTO case_notes(case_id,time_ms,text) VALUES(?1,?2,?3)",
                    params![
                        cid,
                        now,
                        format!(
                            "Endpoint {id}; event {}; SHA-256 {}; path {}. Related observations share this endpoint and path within one hour; they do not prove execution of the detected file content.",
                            event.id, event.sha256, event.path
                        )
                    ],
                )?;
            }
            tx.execute(
                "INSERT INTO endpoint_events VALUES(?1,?2,?3,?4,?5,?6)",
                params![id, event.id, hash, evidence_id, case_id, payload],
            )?;
            self.index_endpoint_process(id, event, evidence_id)?;
            observations.push((event, evidence_id));
            if let Some(case) = case_id {
                self.apply_malware_playbook(id, event, case, now)?;
            }
            accepted += 1;
        }
        for (event, evidence_id) in observations {
            self.detect_endpoint(id, event, evidence_id, now)?;
        }
        tx.execute("UPDATE sources SET received=received+?1,last_event_ms=?2,last_poll_ms=?2 WHERE id='endpoint'",params![accepted,now])?;
        tx.commit()?;
        Ok(accepted)
    }
    pub fn queue_endpoint_action(
        &self,
        id: &str,
        action: Action,
        case_id: i64,
        now: u64,
    ) -> LabResult<String> {
        action.validate()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let command = self.queue_endpoint_action_in_transaction(id, action, case_id, now)?;
        tx.commit()?;
        Ok(command)
    }
    pub(crate) fn queue_endpoint_action_in_transaction(
        &self,
        id: &str,
        action: Action,
        case_id: i64,
        now: u64,
    ) -> LabResult<String> {
        if self.connection.is_autocommit() {
            return Err("Endpoint proposal requires a transaction".into());
        }
        action.validate()?;
        let tx = &self.connection;
        let health: String = tx.query_row(
            "SELECT health FROM endpoints WHERE id=?1 AND state='active'",
            [id],
            |r| r.get(0),
        )?;
        let health: Heartbeat = serde_json::from_str(&health)?;
        if !health.capabilities.iter().any(|c| c == action.capability()) {
            return Err("Endpoint has not reported this capability".into());
        }
        let open:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1 AND status IN ('open','triage','in_progress'))",[case_id],|r|r.get(0))?;
        if !open {
            return Err("An open investigation is required".into());
        }
        let count:u64=tx.query_row("SELECT count(*) FROM endpoint_commands WHERE state IN ('pending','approved','running')",[],|r|r.get(0))?;
        if count >= 256 {
            return Err("Endpoint work queue is full".into());
        }
        let command = Command {
            id: secret()?,
            endpoint_id: id.into(),
            action_hash: protocol::hash(&serde_json::to_vec(&action)?),
            action,
            created_ms: now,
            expires_ms: now + 900_000,
            timeout_secs: 300,
            case_id,
        };
        tx.execute("INSERT INTO endpoint_commands(id,endpoint_id,payload,state,expires_ms,case_id) VALUES(?1,?2,?3,'pending',?4,?5)",params![command.id,id,serde_json::to_string(&command)?,command.expires_ms,case_id])?;
        self.audit("endpoint.action_proposed", &command.id, now)?;
        Ok(command.id)
    }
    pub fn review_endpoint_action(&self, id: &str, approve: bool, now: u64) -> LabResult<()> {
        let linked: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM security_incidents WHERE command_id=?1)",
            [id],
            |r| r.get(0),
        )?;
        if linked {
            return Err("Review this command through its complete incident plan".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.review_endpoint_action_in_transaction(id, approve, now)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn review_endpoint_action_in_transaction(
        &self,
        id: &str,
        approve: bool,
        now: u64,
    ) -> LabResult<()> {
        if self.connection.is_autocommit() {
            return Err("Endpoint review requires a transaction".into());
        }
        let tx = &self.connection;
        let state = if approve { "approved" } else { "cancelled" };
        if tx.execute("UPDATE endpoint_commands SET state=?1 WHERE id=?2 AND state='pending' AND expires_ms>?3 AND endpoint_id IN(SELECT id FROM endpoints WHERE state='active') AND case_id IN(SELECT id FROM cases WHERE status IN('open','triage','in_progress'))",params![state,id,now])?!=1 {return Err("Command is expired, changed, or its endpoint/case is closed".into());}
        self.audit("endpoint.action_reviewed", &format!("{id}: {state}"), now)?;
        Ok(())
    }
    pub fn poll_endpoint_commands(&self, id: &str, now: u64) -> LabResult<Vec<Command>> {
        self.connection.execute("UPDATE endpoint_commands SET state='expired' WHERE expires_ms<=?1 AND state IN('pending','approved')",[now])?;
        let rows=self.connection.prepare("SELECT payload FROM endpoint_commands WHERE endpoint_id=?1 AND state='approved' AND expires_ms>?2 AND case_id IN(SELECT id FROM cases WHERE status IN('open','triage','in_progress')) ORDER BY rowid LIMIT 4")?.query_map(params![id,now],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
        rows.into_iter()
            .map(|r| Ok(serde_json::from_str(&r)?))
            .collect()
    }
    pub fn start_endpoint_command(&self, endpoint: &str, id: &str, now: u64) -> LabResult<Command> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let payload:String=tx.query_row("SELECT payload FROM endpoint_commands WHERE id=?1 AND endpoint_id=?2 AND state='approved' AND expires_ms>?3 AND endpoint_id IN(SELECT id FROM endpoints WHERE state='active') AND case_id IN(SELECT id FROM cases WHERE status IN('open','triage','in_progress'))",params![id,endpoint,now],|r|r.get(0))?;
        let command: Command = serde_json::from_str(&payload)?;
        self.incident_dispatch_allowed(id, now)?;
        command.validate(endpoint, now)?;
        tx.execute(
            "UPDATE endpoint_commands SET state='running' WHERE id=?1",
            [id],
        )?;
        self.audit("endpoint.action_started", id, now)?;
        tx.commit()?;
        Ok(command)
    }
    pub fn finish_endpoint_command(
        &self,
        endpoint: &str,
        receipt: &Receipt,
        now: u64,
    ) -> LabResult<()> {
        receipt.validate()?;
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let (raw,state,previous):(String,String,Option<String>)=tx.query_row("SELECT payload,state,receipt_hash FROM endpoint_commands WHERE id=?1 AND endpoint_id=?2",params![receipt.command_id,endpoint],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let command: Command = serde_json::from_str(&raw)?;
        let raw = serde_json::to_string(receipt)?;
        let hash = protocol::hash(raw.as_bytes());
        if let Some(previous) = previous {
            if hash == previous {
                return Ok(());
            }
            return Err("Receipt replay conflicts".into());
        }
        if command.action_hash != receipt.action_hash
            || !["running", "approved", "cancelled", "expired"].contains(&state.as_str())
            || (state != "running"
                && !["interrupted", "refused"].contains(&receipt.outcome.as_str()))
        {
            return Err("Receipt does not match dispatched work".into());
        }
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM case_notes WHERE case_id=?1",
            [command.case_id],
            |r| r.get(0),
        )?;
        if count >= 64 {
            return Err("Investigation note budget reached; receipt remains on endpoint".into());
        }
        tx.execute(
            "UPDATE endpoint_commands SET state=?1,receipt=?2,receipt_hash=?3 WHERE id=?4",
            params![receipt.outcome, raw, hash, receipt.command_id],
        )?;
        tx.execute(
            "INSERT INTO case_notes(case_id,time_ms,text) VALUES(?1,?2,?3)",
            params![
                command.case_id,
                now,
                format!(
                    "Endpoint action {}: {}. Receipt SHA-256 {hash}. {}",
                    receipt.command_id,
                    receipt.outcome,
                    receipt.output.chars().take(1500).collect::<String>()
                )
            ],
        )?;
        tx.execute(
            "UPDATE cases SET version=version+1,updated_ms=?1 WHERE id=?2",
            params![now, command.case_id],
        )?;
        self.audit(
            "endpoint.action_finished",
            &format!("{}: {}", receipt.command_id, receipt.outcome),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn fleet(&self) -> LabResult<Fleet> {
        let rows=self.connection.prepare("SELECT id,hostname,platform,arch,state,last_seen_ms,health FROM endpoints ORDER BY last_seen_ms DESC")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,u64>(5)?,r.get::<_,String>(6)?)))?.collect::<Result<Vec<_>,_>>()?;
        let endpoints = rows
            .into_iter()
            .map(
                |(id, hostname, platform, arch, state, last_seen_ms, health)| {
                    Ok(Endpoint {
                        id,
                        hostname,
                        platform: serde_json::from_str(&platform)?,
                        arch,
                        state,
                        last_seen_ms,
                        health: serde_json::from_str(&health)?,
                    })
                },
            )
            .collect::<LabResult<_>>()?;
        let rows = self
            .connection
            .prepare(
                "SELECT payload,state,receipt FROM endpoint_commands ORDER BY rowid DESC LIMIT 128",
            )?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let commands = rows
            .into_iter()
            .map(|(raw, state, receipt)| {
                Ok(FleetCommand {
                    command: serde_json::from_str(&raw)?,
                    state,
                    receipt: receipt.map(|s| serde_json::from_str(&s)).transpose()?,
                })
            })
            .collect::<LabResult<_>>()?;
        let playbooks = self
            .connection
            .prepare(
                "SELECT endpoint_id,mode,revision FROM endpoint_playbooks ORDER BY endpoint_id",
            )?
            .query_map([], |r| {
                Ok(Playbook {
                    endpoint_id: r.get(0)?,
                    mode: r.get(1)?,
                    revision: r.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Fleet {
            endpoints,
            commands,
            playbooks,
        })
    }
    pub fn configure_malware_playbook(
        &self,
        endpoint: &str,
        mode: &str,
        now: u64,
    ) -> LabResult<()> {
        if !["disabled", "review", "automatic"].contains(&mode) {
            return Err("Unknown playbook mode".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        tx.execute("INSERT INTO endpoint_playbooks VALUES(?1,?2,1) ON CONFLICT(endpoint_id) DO UPDATE SET mode=excluded.mode,revision=revision+1",params![endpoint,mode])?;
        tx.execute("UPDATE endpoint_commands SET state='cancelled' WHERE state IN('pending','approved') AND id IN(SELECT command_id FROM endpoint_playbook_runs WHERE endpoint_id=?1)",[endpoint])?;
        self.audit(
            "endpoint.playbook_configured",
            &format!("{endpoint}: malware → hash-bound quarantine; {mode}"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    fn apply_malware_playbook(
        &self,
        endpoint: &str,
        event: &EndpointEvent,
        case: i64,
        now: u64,
    ) -> LabResult<()> {
        if !protocol::hex_id(&event.sha256) {
            return Ok(());
        }
        let rule:Option<(String,u64)>=self.connection.query_row("SELECT mode,revision FROM endpoint_playbooks WHERE endpoint_id=?1 AND mode<>'disabled'",[endpoint],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((mode, revision)) = rule else {
            return Ok(());
        };
        let health: String = self.connection.query_row(
            "SELECT health FROM endpoints WHERE id=?1",
            [endpoint],
            |r| r.get(0),
        )?;
        if !serde_json::from_str::<Heartbeat>(&health)?
            .capabilities
            .iter()
            .any(|s| s == "quarantine")
        {
            return Ok(());
        }
        let count: u64 = self.connection.query_row(
            "SELECT count(*) FROM endpoint_commands WHERE state IN('pending','approved','running')",
            [],
            |r| r.get(0),
        )?;
        if count >= 256 {
            return Err("Playbook work queue budget reached; endpoint retains evidence".into());
        }
        let action = Action::Quarantine {
            path: event.path.clone(),
            sha256: event.sha256.clone(),
        };
        action.validate()?;
        let command = Command {
            id: secret()?,
            endpoint_id: endpoint.into(),
            action_hash: protocol::hash(&serde_json::to_vec(&action)?),
            action,
            created_ms: now,
            expires_ms: now + 900_000,
            timeout_secs: 60,
            case_id: case,
        };
        self.connection.execute("INSERT INTO endpoint_commands(id,endpoint_id,payload,state,expires_ms,case_id) VALUES(?1,?2,?3,?4,?5,?6)",params![command.id,endpoint,serde_json::to_string(&command)?,if mode=="automatic"{"approved"}else{"pending"},command.expires_ms,case])?;
        self.connection.execute(
            "INSERT INTO endpoint_playbook_runs VALUES(?1,?2,?3)",
            params![command.id, endpoint, revision],
        )?;
        self.connection.execute("INSERT INTO case_notes(case_id,time_ms,text) VALUES(?1,?2,?3)",params![case,now,format!("Malware quarantine playbook revision {revision}, mode {mode}. Command {}, bound to file SHA-256 {}. Endpoint local path policy applies.",command.id,event.sha256)])?;
        self.audit(
            "endpoint.playbook_triggered",
            &format!("{} / revision {revision} / {mode}", command.id),
            now,
        )?;
        Ok(())
    }
}
