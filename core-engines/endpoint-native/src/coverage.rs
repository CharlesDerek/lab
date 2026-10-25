//! Cumulative authorization coverage. The adapter holds native.lock while writing
//! this single atomic checkpoint. Readers never acknowledge or delete it. Polls
//! may coalesce revisions; totals and restart intervals survive those omissions.
use crate::{receipt, service, Policy, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

pub const FILE: &str = "authorization-coverage.json";
pub const MAX_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Loss {
    pub evidence_dropped: u64,
    pub event_gaps: u64,
    pub response_errors: u64,
}
impl Loss {
    fn contains(self, previous: Self) -> bool {
        self.evidence_dropped >= previous.evidence_dropped
            && self.event_gaps >= previous.event_gaps
            && self.response_errors >= previous.response_errors
    }
    fn advance(self, previous: Self, next: Self) -> Result<Self> {
        fn counter(total: u64, previous: u64, next: u64) -> Result<u64> {
            total
                .checked_add(
                    next.checked_sub(previous)
                        .ok_or("Native coverage counter regressed")?,
                )
                .ok_or_else(|| "Native coverage counter exhausted".into())
        }
        Ok(Self {
            evidence_dropped: counter(
                self.evidence_dropped,
                previous.evidence_dropped,
                next.evidence_dropped,
            )?,
            event_gaps: counter(self.event_gaps, previous.event_gaps, next.event_gaps)?,
            response_errors: counter(
                self.response_errors,
                previous.response_errors,
                next.response_errors,
            )?,
        })
    }
}

/// Immutable within one revision. Freshness is stored separately so a heartbeat
/// cannot change an already delivered event or fill the management outbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: u32,
    pub lineage: String,
    pub session: String,
    pub policy_sha256: String,
    pub pid: u32,
    pub pidversion: i32,
    pub started_ms: u64,
    pub changed_ms: u64,
    pub revision: u64,
    pub sessions: u64,
    pub unobserved_intervals: u64,
    pub legacy_history_unknown: bool,
    pub subscribed: bool,
    pub scope_valid: bool,
    pub scope_losses: u64,
    pub totals: Loss,
}
impl Evidence {
    pub fn incomplete(&self) -> bool {
        !self.subscribed
            || !self.scope_valid
            || self.scope_losses != 0
            || self.unobserved_intervals != 0
            || self.legacy_history_unknown
            || self.totals != Loss::default()
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        if self.schema != 1
            || !receipt::hex_id(&self.lineage)
            || !receipt::hex_id(&self.session)
            || !receipt::hex_id(&self.policy_sha256)
            || self.pid == 0
            || self.pid > i32::MAX as u32
            || self.started_ms == 0
            || self.changed_ms < self.started_ms
            || self.changed_ms > now.saturating_add(60_000)
            || self.changed_ms > i64::MAX as u64
            || self.sessions == 0
            || self.revision < self.sessions
            || self.unobserved_intervals != self.sessions - 1
            || (!self.scope_valid && self.scope_losses == 0)
        {
            return Err("Invalid native authorization coverage".into());
        }
        Ok(())
    }
    pub fn follows(&self, previous: &Self) -> Result<()> {
        if self.lineage != previous.lineage
            || self.revision < previous.revision
            || self.sessions < previous.sessions
            || !self.totals.contains(previous.totals)
            || self.scope_losses < previous.scope_losses
            || (previous.legacy_history_unknown && !self.legacy_history_unknown)
            || (self.revision == previous.revision && self != previous)
            || (self.session == previous.session
                && (self.sessions != previous.sessions
                    || self.policy_sha256 != previous.policy_sha256
                    || self.pid != previous.pid
                    || self.pidversion != previous.pidversion
                    || self.started_ms != previous.started_ms
                    || self.changed_ms < previous.changed_ms
                    || (previous.subscribed && !self.subscribed)
                    || (!previous.scope_valid && self.scope_valid)))
            || (self.session != previous.session && self.sessions <= previous.sessions)
        {
            return Err("Native coverage history was replaced, changed or regressed".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub evidence: Evidence,
    pub checked_ms: u64,
    pub sample: Loss,
}
fn nonce() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn increment(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| "Native coverage generation exhausted".into())
}
impl Snapshot {
    pub fn begin(
        previous: Option<&Self>,
        policy: &Policy,
        pid: u32,
        pidversion: i32,
        legacy: bool,
        now: u64,
    ) -> Result<Self> {
        policy.validate()?;
        if let Some(previous) = previous {
            previous.validate(now)?;
        }
        let previous = previous.map(|s| &s.evidence);
        let sessions = increment(previous.map_or(0, |e| e.sessions))?;
        let snapshot = Self {
            evidence: Evidence {
                schema: 1,
                lineage: match previous {
                    Some(e) => e.lineage.clone(),
                    None => nonce()?,
                },
                session: nonce()?,
                policy_sha256: receipt::policy_hash(policy)?,
                pid,
                pidversion,
                started_ms: now,
                changed_ms: now,
                revision: increment(previous.map_or(0, |e| e.revision))?,
                sessions,
                // Even an orderly restart has no replayable ES stream between
                // subscriptions. The uncheckpointed tail is also unknown.
                unobserved_intervals: sessions - 1,
                legacy_history_unknown: previous.map_or(legacy, |e| e.legacy_history_unknown),
                subscribed: false,
                scope_valid: true,
                scope_losses: previous.map_or(0, |e| e.scope_losses),
                totals: previous.map_or(Loss::default(), |e| e.totals),
            },
            checked_ms: now,
            sample: Loss::default(),
        };
        snapshot.validate(now)?;
        Ok(snapshot)
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        self.evidence.validate(now)?;
        if self.checked_ms < self.evidence.changed_ms
            || self.checked_ms > now.saturating_add(60_000)
            || self.checked_ms > i64::MAX as u64
            || !self.evidence.totals.contains(self.sample)
        {
            return Err("Invalid native coverage checkpoint".into());
        }
        Ok(())
    }
    pub fn observe(
        &self,
        sample: Loss,
        subscribed: bool,
        scope_valid: bool,
        now: u64,
    ) -> Result<Self> {
        if now < self.checked_ms {
            return Err("Native coverage clock regressed".into());
        }
        let mut next = self.clone();
        next.checked_ms = now;
        next.sample = sample;
        next.evidence.totals = self.evidence.totals.advance(self.sample, sample)?;
        next.evidence.subscribed = subscribed;
        next.evidence.scope_valid = scope_valid;
        if self.evidence.scope_valid && !scope_valid {
            next.evidence.scope_losses = increment(self.evidence.scope_losses)?;
        }
        if next.evidence != self.evidence {
            next.evidence.revision = increment(self.evidence.revision)?;
            next.evidence.changed_ms = now;
        }
        next.validate(now)?;
        next.evidence.follows(&self.evidence)?;
        Ok(next)
    }
    pub fn check_live(&self, policy: &Policy, pid: u32, now: u64) -> Result<()> {
        self.validate(now)?;
        if self.evidence.policy_sha256 != receipt::policy_hash(policy)?
            || self.evidence.pid != pid
            || !self.evidence.subscribed
            || !self.evidence.scope_valid
            || self.checked_ms > now.saturating_add(1000)
            || now.saturating_sub(self.checked_ms) > 3000
        {
            return Err(
                "Native coverage checkpoint is stale or belongs to another subscription".into(),
            );
        }
        Ok(())
    }
    pub fn save(&self, state: &Path) -> Result<()> {
        self.validate(service::now_ms())?;
        crate::broker::trusted(state, true)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_BYTES {
            return Err("Native coverage exceeds its byte budget".into());
        }
        service::write(&state.join(FILE), &bytes, 0o600)
    }
}

pub fn load(state: &Path) -> Result<Snapshot> {
    let snapshot: Snapshot = service::read(&state.join(FILE), MAX_BYTES as u64)?;
    snapshot.validate(service::now_ms())?;
    Ok(snapshot)
}

/// Call only while holding the adapter's exclusive native.lock, before subscribing.
pub fn begin(policy: &Policy, pidversion: i32) -> Result<Snapshot> {
    let previous = match fs::symlink_metadata(policy.state.join(FILE)) {
        Ok(_) => Some(load(&policy.state)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    if let Some(previous) = &previous {
        let bound: Policy = service::read(
            &policy
                .state
                .join("policies")
                .join(format!("{}.json", previous.evidence.policy_sha256)),
            65536,
        )?;
        bound.validate()?;
        if bound.state != policy.state
            || receipt::policy_hash(&bound)? != previous.evidence.policy_sha256
        {
            return Err(
                "Native coverage history belongs to another policy or endpoint state".into(),
            );
        }
    }
    let legacy = match fs::symlink_metadata(policy.state.join("native-status.json")) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let snapshot = Snapshot::begin(
        previous.as_ref(),
        policy,
        std::process::id(),
        pidversion,
        legacy,
        service::now_ms(),
    )?;
    snapshot.save(&policy.state)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests;
