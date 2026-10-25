//! Versioned security facts, explicit identity mappings and replayable rules.
//! Kubernetes audit metadata is normalized; request/response bodies are never
//! retained. The source credential, not event content, selects the authority.
use crate::{
    engine::{Engine, LabResult},
    gateway::digest,
    model::{InputEvent, Kind, Outcome},
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    AuthenticationDenied,
    AccessDenied,
    AuthenticationAllowed,
    SecretRead,
    WorkloadExec,
    RoleChanged,
    Observation,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    pub id: String,
    pub time_ms: u64,
    pub principal: String,
    pub kind: SignalKind,
    pub namespace: String,
    pub object: String,
    pub object_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<std::net::IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignalPolicy {
    pub enabled_rules: Vec<String>,
    pub keep_source_ip: bool,
    pub keep_user_agent: bool,
    pub history_ms: u64,
    pub accepted_lateness_ms: u64,
}
impl Default for SignalPolicy {
    fn default() -> Self {
        Self {
            enabled_rules: vec!["EK-001".into(), "EK-002".into(), "EK-003".into()],
            keep_source_ip: true,
            keep_user_agent: true,
            history_ms: 86_400_000,
            accepted_lateness_ms: 86_400_000,
        }
    }
}
#[derive(Clone, Serialize)]
pub struct SignalRule {
    pub id: &'static str,
    pub version: u32,
    pub window_ms: u64,
    pub description: &'static str,
    pub requires_source_ip: bool,
}
pub const SIGNAL_RULES:[SignalRule;3]=[
    SignalRule{id:"EK-001",version:1,window_ms:600_000,description:"Five denied requests followed by successful workload execution for the same mapped identity",requires_source_ip:false},
    SignalRule{id:"EK-002",version:1,window_ms:600_000,description:"Secret access followed by workload execution by the same identity in the same source and namespace",requires_source_ip:false},
    SignalRule{id:"EK-003",version:1,window_ms:120_000,description:"Denied authentication for five distinct principals from one IP within one source",requires_source_ip:true},
];
impl SignalPolicy {
    fn validate(&self) -> LabResult<()> {
        if self.history_ms < 600_000
            || self.history_ms > 30 * 86_400_000
            || self.accepted_lateness_ms > self.history_ms
            || self.enabled_rules.len() > 3
            || self.enabled_rules.iter().collect::<BTreeSet<_>>().len() != self.enabled_rules.len()
        {
            return Err("Invalid detection retention or lateness budget".into());
        }
        for id in &self.enabled_rules {
            let rule = SIGNAL_RULES
                .iter()
                .find(|r| r.id == id)
                .ok_or("Unsupported rule/version")?;
            if rule.window_ms > self.history_ms || (rule.requires_source_ip && !self.keep_source_ip)
            {
                return Err("Retention projection would make an enabled rule unsupported".into());
            }
        }
        Ok(())
    }
    fn project(&self, signal: &Signal) -> Signal {
        let mut result = signal.clone();
        if !self.keep_source_ip {
            result.source_ip = None;
        }
        if !self.keep_user_agent {
            result.user_agent = None;
        }
        result
    }
}
#[derive(Serialize)]
pub struct SignalRecord {
    pub evidence_id: u64,
    pub source: String,
    pub canonical_identity: String,
    pub signal: Signal,
}
#[derive(Serialize)]
pub struct SignalCoverage {
    pub records: u64,
    pub payload_bytes: u64,
    pub missing_auth_source_ip: u64,
    pub policy: SignalPolicy,
    pub rules: Vec<SignalRule>,
}
fn bounded(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(char::is_control)
}

impl Engine {
    pub(crate) fn init_signals(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS signal_facts(evidence_id INTEGER PRIMARY KEY,source TEXT NOT NULL,event_id TEXT NOT NULL,input_hash TEXT NOT NULL,identity TEXT NOT NULL,time_ms INTEGER NOT NULL,kind TEXT NOT NULL,source_ip TEXT,payload TEXT NOT NULL,UNIQUE(source,event_id));
          CREATE INDEX IF NOT EXISTS signal_identity_time ON signal_facts(identity,time_ms);
          CREATE INDEX IF NOT EXISTS signal_ip_time ON signal_facts(source,source_ip,time_ms);
          CREATE TABLE IF NOT EXISTS signal_identity_aliases(source TEXT NOT NULL REFERENCES sources(id),principal TEXT NOT NULL,canonical TEXT NOT NULL,endpoint_key TEXT,PRIMARY KEY(source,principal));
          CREATE TABLE IF NOT EXISTS signal_matches(fingerprint TEXT PRIMARY KEY,rule TEXT NOT NULL,version INTEGER NOT NULL,evidence TEXT NOT NULL,created_ms INTEGER NOT NULL);")?;
        self.connection.execute(
            "INSERT OR IGNORE INTO metadata VALUES('signal_policy',?1)",
            [serde_json::to_string(&SignalPolicy::default())?],
        )?;
        Ok(())
    }
    pub fn signal_policy(&self) -> LabResult<SignalPolicy> {
        Ok(serde_json::from_str(&self.connection.query_row(
            "SELECT value FROM metadata WHERE key='signal_policy'",
            [],
            |r| r.get::<_, String>(0),
        )?)?)
    }
    pub fn configure_signal_policy(&self, policy: &SignalPolicy, now: u64) -> LabResult<()> {
        policy.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.connection.execute(
            "UPDATE metadata SET value=?1 WHERE key='signal_policy'",
            [serde_json::to_string(policy)?],
        )?;
        self.audit("signals.policy", &serde_json::to_string(policy)?, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn map_signal_identity(
        &self,
        source: &str,
        principal: &str,
        canonical: &str,
        endpoint_uid: Option<(&str, u32)>,
        now: u64,
    ) -> LabResult<()> {
        if principal.is_empty()
            || !bounded(principal, 512)
            || !orchestrator::governor::label(canonical)
        {
            return Err("Invalid explicit identity mapping".into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let count: u64 = tx.query_row("SELECT count(*) FROM signal_identity_aliases", [], |r| {
            r.get(0)
        })?;
        if count >= 4096 {
            return Err("Identity mapping budget reached".into());
        }
        let endpoint_key = if let Some((endpoint, uid)) = endpoint_uid {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM endpoints WHERE id=?1 AND state='active')",
                [endpoint],
                |r| r.get(0),
            )?;
            if !exists {
                return Err("Mapped endpoint is not active".into());
            }
            Some(format!("identity:{endpoint}:uid-{uid}"))
        } else {
            None
        };
        // Historical mappings are not silently rewritten. A different mapping
        // requires a new source identity and explicit evidence review.
        tx.execute(
            "INSERT INTO signal_identity_aliases VALUES(?1,?2,?3,?4)",
            params![source, principal, canonical, endpoint_key],
        )?;
        self.audit(
            "signals.identity_mapped",
            &format!("{source}: {canonical}"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn ingest_signals(
        &mut self,
        source: &str,
        token: &str,
        signals: &[Signal],
        now: u64,
    ) -> LabResult<usize> {
        if signals.is_empty() || signals.len() > 64 {
            return Err("Signal batches contain 1–64 records".into());
        }
        let accepted:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM sources WHERE id=?1 AND kind='api' AND enabled=1 AND token_hash=?2)",params![source,digest(token)],|r|r.get(0))?;
        if !accepted {
            return Err("Signal source credential rejected or source paused".into());
        }
        let policy = self.signal_policy()?;
        for signal in signals {
            if signal.id.is_empty()
                || !bounded(&signal.id, 128)
                || signal.principal.is_empty()
                || !bounded(&signal.principal, 512)
                || !bounded(&signal.namespace, 128)
                || !bounded(&signal.object, 512)
                || signal
                    .object_uid
                    .as_ref()
                    .is_some_and(|s| s.is_empty() || !bounded(s, 128))
                || signal
                    .user_agent
                    .as_ref()
                    .is_some_and(|s| !bounded(s, 2048))
                || signal.time_ms > now.saturating_add(60_000)
                || signal.time_ms > i64::MAX as u64
            {
                return Err("Signal exceeds field, timestamp or accepted lateness limits".into());
            }
        }
        self.prepare_storage(now)?;
        if self.pending_count()? + signals.len() > 512 {
            self.flush(now)?;
        }
        self.reserve_ids(signals.len())?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let lease = self.reserve_essential_work("signals", now)?;
        let count: u64 = tx.query_row("SELECT count(*) FROM signal_facts", [], |r| r.get(0))?;
        let mut inserted = 0;
        for signal in signals {
            let input_hash = digest(&serde_json::to_string(signal)?);
            let previous: Option<String> = tx
                .query_row(
                    "SELECT input_hash FROM signal_facts WHERE source=?1 AND event_id=?2",
                    params![source, signal.id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(previous) = previous {
                if previous != input_hash {
                    return Err("Signal identity reused with changed facts".into());
                }
                continue;
            }
            if count + inserted as u64 >= 65536 {
                return Err(
                    "Signal evidence capacity reached; batch remains unacknowledged".into(),
                );
            }
            if now.saturating_sub(signal.time_ms) > policy.accepted_lateness_ms {
                return Err(
                    "New signal exceeds accepted lateness; existing exact replays remain valid"
                        .into(),
                );
            }
            let mapping:Option<(String,Option<String>)>=tx.query_row("SELECT canonical,endpoint_key FROM signal_identity_aliases WHERE source=?1 AND principal=?2",params![source,signal.principal],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            let canonical = mapping
                .as_ref()
                .map(|(s, _)| format!("mapped:{s}"))
                .unwrap_or_else(|| format!("source:{source}:{}", signal.principal));
            let identity = digest(&canonical);
            let input = InputEvent {
                time_ms: signal.time_ms,
                source: source.into(),
                subject: identity.clone(),
                object: digest(&serde_json::to_string(&(
                    source,
                    &signal.namespace,
                    &signal.object,
                    &signal.object_uid,
                ))?),
                kind: if matches!(
                    signal.kind,
                    SignalKind::AuthenticationDenied | SignalKind::AuthenticationAllowed
                ) {
                    Kind::Authentication
                } else {
                    Kind::System
                },
                outcome: if matches!(
                    signal.kind,
                    SignalKind::AuthenticationDenied | SignalKind::AccessDenied
                ) {
                    Outcome::Deny
                } else if signal.kind == SignalKind::AuthenticationAllowed {
                    Outcome::Allow
                } else {
                    Outcome::Observe
                },
                severity: 2,
                bytes: 0,
                trace: 0,
                idempotency_key: digest(&format!("signal:{}", signal.id)),
                context: None,
            };
            let dedup = format!("{source}:{}", input.idempotency_key);
            self.ingest_in_transaction(&[input], now)?;
            let evidence: u64 = tx.query_row(
                "SELECT id FROM all_evidence_refs WHERE dedup=?1",
                [dedup],
                |r| r.get(0),
            )?;
            let projection = policy.project(signal);
            tx.execute(
                "INSERT INTO signal_facts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    evidence,
                    source,
                    signal.id,
                    input_hash,
                    identity,
                    signal.time_ms,
                    serde_json::to_string(&signal.kind)?,
                    projection.source_ip.map(|ip| ip.to_string()),
                    serde_json::to_string(&projection)?
                ],
            )?;
            if let Some((_, Some(key))) = mapping {
                tx.execute(
                    "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
                    params![key, evidence, signal.time_ms],
                )?;
            }
            if let Some(uid) = &signal.object_uid {
                tx.execute(
                    "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
                    params![
                        format!("workload:{source}:{}:{uid}", signal.namespace),
                        evidence,
                        signal.time_ms
                    ],
                )?;
            }
            self.detect_signals(&identity, source, &projection, now)?;
            inserted += 1;
        }
        tx.execute("UPDATE sources SET received=received+?1,last_event_ms=max(last_event_ms,?2),last_poll_ms=max(last_poll_ms,?2),error='' WHERE id=?3",params![inserted,now,source])?;
        self.complete_essential_work(lease)?;
        tx.commit()?;
        Ok(inserted)
    }
    fn signal_rows(
        &self,
        identity: &str,
        source: &str,
        ip: Option<std::net::IpAddr>,
        start: u64,
        end: u64,
    ) -> LabResult<Vec<SignalRecord>> {
        let rows=self.connection.prepare("SELECT evidence_id,source,identity,payload FROM signal_facts WHERE time_ms BETWEEN ?1 AND ?2 AND (identity=?3 OR (?4 IS NOT NULL AND source=?5 AND source_ip=?4)) ORDER BY time_ms,evidence_id LIMIT 2049")?.query_map(params![start,end,identity,ip.map(|p|p.to_string()),source],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get::<_,String>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 2048 {
            return Err("Detection candidate budget exhausted; batch not acknowledged".into());
        }
        rows.into_iter()
            .map(|(evidence_id, source, canonical_identity, raw)| {
                Ok(SignalRecord {
                    evidence_id,
                    source,
                    canonical_identity,
                    signal: serde_json::from_str(&raw)?,
                })
            })
            .collect()
    }
    fn detect_signals(
        &self,
        identity: &str,
        source: &str,
        signal: &Signal,
        now: u64,
    ) -> LabResult<()> {
        let policy = self.signal_policy()?;
        let rows = self.signal_rows(
            identity,
            source,
            signal.source_ip,
            signal.time_ms.saturating_sub(600000),
            signal.time_ms.saturating_add(600000).min(i64::MAX as u64),
        )?;
        for current in &rows {
            for rule in &SIGNAL_RULES {
                if !policy.enabled_rules.iter().any(|id| id == rule.id) {
                    continue;
                }
                let prior: Vec<_> = rows
                    .iter()
                    .filter(|r| {
                        r.signal.time_ms <= current.signal.time_ms
                            && current.signal.time_ms - r.signal.time_ms <= rule.window_ms
                    })
                    .collect();
                let evidence = match rule.id {
                    "EK-001" if current.signal.kind == SignalKind::WorkloadExec => {
                        let mut denied: Vec<_> = prior
                            .iter()
                            .filter(|r| {
                                r.canonical_identity == current.canonical_identity
                                    && matches!(
                                        r.signal.kind,
                                        SignalKind::AuthenticationDenied | SignalKind::AccessDenied
                                    )
                            })
                            .map(|r| r.evidence_id)
                            .take(5)
                            .collect();
                        if denied.len() != 5 {
                            continue;
                        }
                        denied.push(current.evidence_id);
                        denied
                    }
                    "EK-002" if current.signal.kind == SignalKind::WorkloadExec => {
                        let Some(secret) = prior.iter().find(|r| {
                            r.canonical_identity == current.canonical_identity
                                && r.source == current.source
                                && r.signal.namespace == current.signal.namespace
                                && r.signal.kind == SignalKind::SecretRead
                        }) else {
                            continue;
                        };
                        vec![secret.evidence_id, current.evidence_id]
                    }
                    "EK-003"
                        if current.signal.kind == SignalKind::AuthenticationDenied
                            && current.signal.source_ip.is_some() =>
                    {
                        let mut principals = BTreeSet::new();
                        let denied: Vec<_> = prior
                            .iter()
                            .filter(|r| {
                                r.source == current.source
                                    && r.signal.kind == SignalKind::AuthenticationDenied
                                    && r.signal.source_ip == current.signal.source_ip
                                    && principals.insert(&r.signal.principal)
                            })
                            .map(|r| r.evidence_id)
                            .take(5)
                            .collect();
                        if denied.len() != 5 {
                            continue;
                        }
                        denied
                    }
                    _ => continue,
                };
                self.signal_match(rule, &evidence, now)?;
            }
        }
        Ok(())
    }
    fn signal_match(&self, rule: &SignalRule, ids: &[u64], now: u64) -> LabResult<()> {
        let fingerprint = digest(&serde_json::to_string(&(rule.id, rule.version, ids))?);
        let raw = serde_json::to_string(ids)?;
        if self.connection.execute(
            "INSERT OR IGNORE INTO signal_matches VALUES(?1,?2,?3,?4,?5)",
            params![fingerprint, rule.id, rule.version, raw, now],
        )? == 0
        {
            return Ok(());
        }
        let evidence = ids
            .iter()
            .map(|id| self.reconstruct(*id))
            .collect::<LabResult<Vec<_>>>()?;
        let last = evidence.last().ok_or("Missing detection evidence")?;
        let raw = serde_json::to_string(&evidence)?;
        self.connection.execute("INSERT INTO findings(fingerprint,rule,title,severity,subject,time_ms,explanation,evidence) VALUES(?1,?2,?3,4,?4,?5,?6,?7)",params![fingerprint,rule.id,rule.description,last.subject_label,last.event.time_ms,format!("Rule {} version {}. Correlated observations require investigation; they do not establish malicious intent. Typed source facts remain linked by evidence ID.",rule.id,rule.version),raw])?;
        self.sync_case(
            self.connection.last_insert_rowid(),
            rule.description,
            4,
            &raw,
            now,
        )?;
        self.correlate_signal(last.event.id, Some(4), now)?;
        self.audit(
            "signals.matched",
            &format!("{} v{}", rule.id, rule.version),
            now,
        )?;
        Ok(())
    }
    pub fn signal_fact(&self, id: u64) -> LabResult<SignalRecord> {
        let (source, canonical_identity, raw): (String, String, String) =
            self.connection.query_row(
                "SELECT source,identity,payload FROM signal_facts WHERE evidence_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
        Ok(SignalRecord {
            evidence_id: id,
            source,
            canonical_identity,
            signal: serde_json::from_str(&raw)?,
        })
    }
    pub fn signal_coverage(&self) -> LabResult<SignalCoverage> {
        let (records,payload_bytes,missing_auth_source_ip)=self.connection.query_row("SELECT count(*),COALESCE(sum(length(CAST(payload AS BLOB))),0),COALESCE(sum(kind='\"authentication_denied\"' AND source_ip IS NULL),0) FROM signal_facts",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        Ok(SignalCoverage {
            records,
            payload_bytes,
            missing_auth_source_ip,
            policy: self.signal_policy()?,
            rules: SIGNAL_RULES.to_vec(),
        })
    }
    pub fn compact_signals(&self, now: u64) -> LabResult<(u64, u64)> {
        self.with_background_budget(
            "compaction",
            orchestrator::governor::Resources {
                cpu_millis: 1000,
                memory_mib: 256,
                io_mib: 128,
                ..Default::default()
            },
            now,
            || self.compact_signals_inner(now),
        )
    }
    fn compact_signals_inner(&self, now: u64) -> LabResult<(u64, u64)> {
        let policy = self.signal_policy()?;
        policy.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.signal_coverage()?.payload_bytes;
        let mut after_id = 0u64;
        loop {
            let rows = self.connection.prepare("SELECT evidence_id,payload FROM signal_facts WHERE evidence_id>?1 ORDER BY evidence_id LIMIT 256")?
                .query_map([after_id], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            if rows.is_empty() {
                break;
            }
            for (id, raw) in rows {
                let projected = policy.project(&serde_json::from_str(&raw)?);
                self.connection.execute(
                    "UPDATE signal_facts SET payload=?2,source_ip=?3 WHERE evidence_id=?1",
                    params![
                        id,
                        serde_json::to_string(&projected)?,
                        projected.source_ip.map(|ip| ip.to_string())
                    ],
                )?;
                after_id = id;
            }
        }
        let after = self.signal_coverage()?.payload_bytes;
        self.audit(
            "signals.compacted",
            &format!("{before} -> {after} typed payload bytes; normalized evidence preserved"),
            now,
        )?;
        tx.commit()?;
        Ok((before, after))
    }
    pub fn replay_signals(&self, now: u64) -> LabResult<usize> {
        let rows=self.connection.prepare("SELECT identity,source,payload FROM signal_facts ORDER BY time_ms,evidence_id LIMIT 2049")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 2048 {
            return Err(
                "Replay exceeds bounded 2048-record evaluation; select a smaller fixture ledger"
                    .into(),
            );
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        for (identity, source, raw) in &rows {
            self.detect_signals(identity, source, &serde_json::from_str(raw)?, now)?;
        }
        tx.commit()?;
        Ok(rows.len())
    }
    /// Each committed page is replay-safe. Follow the returned cursor until None;
    /// detection candidates retain their independent per-rule bounds.
    pub fn replay_signal_page(
        &self,
        after: u64,
        limit: usize,
        now: u64,
    ) -> LabResult<(usize, Option<u64>)> {
        if after > i64::MAX as u64 || !(1..=128).contains(&limit) {
            return Err("Invalid replay cursor or page size".into());
        }
        self.with_background_budget("signal-replay", orchestrator::governor::Resources {cpu_millis:500,memory_mib:64,io_mib:8,..Default::default()}, now, || {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            let rows=self.connection.prepare("SELECT evidence_id,identity,source,payload FROM signal_facts WHERE evidence_id>?1 ORDER BY evidence_id LIMIT ?2")?.query_map(params![after,limit+1],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let count = rows.len().min(limit);
            for (_,identity,source,raw) in rows.iter().take(count) { self.detect_signals(identity,source,&serde_json::from_str(raw)?,now)?; }
            let cursor = if rows.len()>limit { Some(rows[count-1].0) } else { None };
            self.audit("signals.replayed", &format!("after={after} count={count}"), now)?;
            tx.commit()?;
            Ok((count,cursor))
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesBatch {
    pub api_version: String,
    pub kind: String,
    pub items: Vec<KubernetesEvent>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesEvent {
    #[serde(rename = "auditID")]
    pub audit_id: String,
    pub stage: String,
    pub verb: String,
    pub user: KubernetesUser,
    pub object_ref: Option<KubernetesObject>,
    pub response_status: Option<KubernetesStatus>,
    pub request_received_timestamp: String,
    #[serde(default, rename = "sourceIPs")]
    pub source_ips: Vec<std::net::IpAddr>,
    pub user_agent: Option<String>,
}
#[derive(Deserialize)]
pub struct KubernetesUser {
    pub username: String,
}
#[derive(Deserialize, Default)]
pub struct KubernetesObject {
    pub resource: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub name: String,
    pub uid: Option<String>,
    #[serde(default)]
    pub subresource: String,
}
#[derive(Deserialize)]
pub struct KubernetesStatus {
    pub code: u16,
}
impl KubernetesBatch {
    pub fn normalize(self) -> LabResult<Vec<Signal>> {
        if self.api_version != "audit.k8s.io/v1"
            || self.kind != "EventList"
            || self.items.is_empty()
            || self.items.len() > 64
        {
            return Err("Expected a bounded audit.k8s.io/v1 EventList".into());
        }
        self.items
            .into_iter()
            .map(|e| {
                if e.stage != "ResponseComplete" {
                    return Err(
                        "Configure the audit source to send ResponseComplete records only".into(),
                    );
                }
                let timestamp = time::OffsetDateTime::parse(
                    &e.request_received_timestamp,
                    &time::format_description::well_known::Rfc3339,
                )?;
                let time_ms = u64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)?;
                let status = e
                    .response_status
                    .ok_or("Completed audit event lacks response status")?
                    .code;
                let object = e.object_ref.unwrap_or_default();
                let kind = if status == 401 {
                    SignalKind::AuthenticationDenied
                } else if status == 403 {
                    SignalKind::AccessDenied
                } else if (200..300).contains(&status)
                    && object.resource == "secrets"
                    && ["get", "list", "watch"].contains(&e.verb.as_str())
                {
                    SignalKind::SecretRead
                } else if (200..300).contains(&status)
                    && object.resource == "pods"
                    && object.subresource == "exec"
                    && ["create", "get"].contains(&e.verb.as_str())
                {
                    SignalKind::WorkloadExec
                } else if (200..300).contains(&status)
                    && ["rolebindings", "clusterrolebindings"].contains(&object.resource.as_str())
                    && ["create", "update", "patch"].contains(&e.verb.as_str())
                {
                    SignalKind::RoleChanged
                } else {
                    SignalKind::Observation
                };
                Ok(Signal {
                    id: e.audit_id,
                    time_ms,
                    principal: e.user.username,
                    kind,
                    namespace: object.namespace,
                    object: format!("{}/{}", object.resource, object.name),
                    object_uid: object.uid,
                    source_ip: e.source_ips.first().copied(),
                    user_agent: e.user_agent,
                })
            })
            .collect()
    }
}
