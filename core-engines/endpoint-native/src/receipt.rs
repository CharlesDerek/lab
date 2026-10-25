//! Versioned authorization evidence shared by the native writer and agent inbox.
use crate::{Identity, Policy, Result, Verdict, MAX_FILE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const MAX_RECEIPT: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub pid: u32,
    pub uid: u32,
    pub pidversion: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub id: String,
    pub policy_sha256: String,
    pub time_ms: u64,
    pub operation: String,
    pub response_delivered: bool,
    pub actor: Actor,
    pub path: String,
    pub identity: Identity,
    pub verdict: Option<Verdict>,
    pub error: String,
}

pub fn policy_hash(policy: &Policy) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(policy)?)))
}

pub fn hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Receipt {
    pub fn validate(&self, now_ms: u64) -> Result<()> {
        if self.schema != 1
            || !hex_id(&self.id)
            || !hex_id(&self.policy_sha256)
            || self.time_ms == 0
            || self.time_ms > now_ms.saturating_add(60000)
            || self.time_ms > i64::MAX as u64
            || self.actor.pid == 0
            || !["open", "exec", "mmap"].contains(&self.operation.as_str())
            || self.path.is_empty()
            || self.path.len() > 1024
            || !self.path.starts_with('/')
            || self.path.contains(char::is_control)
            || self.path.split('/').any(|part| [".", ".."].contains(&part))
            || !(0..1_000_000_000).contains(&self.identity.modified_nsec)
            || !(0..1_000_000_000).contains(&self.identity.changed_nsec)
            || self.error.len() > 256
            || self.error.contains(char::is_control)
        {
            return Err("Invalid native authorization receipt".into());
        }
        match &self.verdict {
            Some(verdict)
                if self.error.is_empty()
                    && hex_id(&verdict.sha256)
                    && verdict.bytes == self.identity.size
                    && verdict.bytes <= MAX_FILE
                    && verdict.detection.as_ref().is_some_and(|d| {
                        !d.is_empty() && d.len() <= 256 && !d.contains(char::is_control)
                    }) => {}
            None if !self.error.is_empty() => {}
            _ => {
                return Err(
                    "Native denial must contain either a verified detection or an error".into(),
                )
            }
        }
        if serde_json::to_vec(self)?.len() > MAX_RECEIPT {
            return Err("Native receipt exceeds its evidence budget".into());
        }
        Ok(())
    }

    pub fn validate_policy(&self, policy: &Policy, now_ms: u64) -> Result<()> {
        policy.validate()?;
        self.validate(now_ms)?;
        if self.policy_sha256 != policy_hash(policy)?
            || !policy.contains_observed_path(Path::new(&self.path), false)
        {
            return Err("Native receipt does not match its pinned authorization scope".into());
        }
        Ok(())
    }
}
