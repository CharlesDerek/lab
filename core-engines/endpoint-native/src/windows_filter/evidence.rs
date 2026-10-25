//! Applied kernel decisions, kept separate from submitted scanner replies.
use super::wire;
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: u32,
    pub request_id: u64,
    pub checked_ms: u64,
    pub path: String,
    pub volume: u64,
    pub file_id: String,
    pub actor_pid: u64,
    /// Windows FILETIME ticks; not Unix milliseconds.
    pub actor_created: u64,
    pub bytes: u64,
    pub sha256: String,
    pub detection: Option<String>,
    pub policy_sha256: String,
    pub outcome: String,
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl Observation {
    pub fn applied(event: wire::Applied, digest: &[u8; 32], now_ms: u64) -> Result<Self> {
        let path = event.file.validate()?;
        let detection = event.decision.detection(event.file.request_id)?;
        if event.file.policy_sha256 != *digest
            || event.file.operation != wire::APPLIED
            || event.reserved != 0
            || (event.decision.verdict == wire::CLEAN) != (event.status == 0)
            || (event.status != 0 && event.status as u32 != 0xc0000022)
        {
            return Err("Invalid applied Windows decision or policy identity".into());
        }
        let value = Self {
            schema: 1,
            request_id: event.file.request_id,
            checked_ms: now_ms,
            path,
            volume: event.file.volume,
            file_id: hex(&event.file.file_id),
            actor_pid: event.file.actor_pid,
            actor_created: event.file.actor_created,
            bytes: event.file.bytes,
            sha256: if event.decision.verdict == wire::ERROR {
                String::new()
            } else {
                hex(&event.decision.sha256)
            },
            detection,
            policy_sha256: hex(digest),
            outcome: match event.decision.verdict {
                wire::CLEAN => "allowed",
                wire::MALWARE => "denied_malware",
                _ => "denied_error",
            }
            .into(),
        };
        value.validate(now_ms)?;
        Ok(value)
    }
    pub fn validate(&self, now_ms: u64) -> Result<()> {
        let hex = |text: &str, length| {
            text.len() == length
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.schema != 1
            || self.request_id == 0
            || self.checked_ms == 0
            || self.checked_ms > now_ms.saturating_add(60_000)
            || self.checked_ms > i64::MAX as u64
            || !self.path.starts_with("\\Device\\")
            || self.path.encode_utf16().count() >= wire::PATH_CHARS
            || self.path.contains(char::is_control)
            || self.path.split('\\').any(|p| [".", ".."].contains(&p))
            || !hex(&self.file_id, 32)
            || !hex(&self.policy_sha256, 64)
            || self.bytes > crate::MAX_FILE
            || !["allowed", "denied_malware", "denied_error"].contains(&self.outcome.as_str())
        {
            return Err("Invalid Windows applied observation".into());
        }
        match self.outcome.as_str() {
            "allowed" if hex(&self.sha256, 64) && self.detection.is_none() => (),
            "denied_malware"
                if hex(&self.sha256, 64)
                    && self.detection.as_ref().is_some_and(|d| {
                        !d.is_empty()
                            && d.len() <= 255
                            && d.bytes().all(|b| (0x20..=0x7e).contains(&b))
                    }) => {}
            "denied_error" if self.sha256.is_empty() && self.detection.is_none() => (),
            _ => return Err("Windows observation verdict fields disagree".into()),
        }
        Ok(())
    }
}
