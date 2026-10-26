use serde::{Deserialize, Serialize};

pub const MAX_EVENTS: usize = 4096;
pub const MAX_LABELS: usize = 16384;
pub const MAX_FINDINGS: usize = 128;
pub const MAX_BATCH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Kind {
    Authentication = 1,
    Process = 2,
    Network = 3,
    Policy = 4,
    Heartbeat = 5,
    System = 6,
    Malware = 7,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Authentication => "Authentication",
            Self::Process => "Process",
            Self::Network => "Network",
            Self::Policy => "Policy",
            Self::Heartbeat => "Heartbeat",
            Self::System => "System",
            Self::Malware => "Malware",
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::Authentication => "AU",
            Self::Process => "PX",
            Self::Network => "NF",
            Self::Policy => "PL",
            Self::Heartbeat => "HB",
            Self::System => "SY",
            Self::Malware => "MW",
        }
    }
    pub fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Authentication,
            2 => Self::Process,
            3 => Self::Network,
            4 => Self::Policy,
            5 => Self::Heartbeat,
            6 => Self::System,
            7 => Self::Malware,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Outcome {
    Allow = 0,
    Deny = 1,
    Observe = 2,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Observe => "observe",
        }
    }
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Allow => "+",
            Self::Deny => "−",
            Self::Observe => "·",
        }
    }
    pub fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Allow,
            1 => Self::Deny,
            2 => Self::Observe,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventContext {
    pub host: String,
    pub program: String,
    pub pid: Option<u32>,
    #[serde(default)]
    pub parent_pid: Option<u32>,
    #[serde(default)]
    pub process_start_ms: Option<u64>,
    #[serde(default)]
    pub parent_start_ms: Option<u64>,
    pub uid: Option<u32>,
    /// Exact account claimed by a supported local journal report, not reporter UID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_account: Option<String>,
    pub summary: String,
    pub journal_cursor: String,
}
impl EventContext {
    pub fn validate(&self) -> Result<(), String> {
        if self.claimed_account.as_ref().is_some_and(|account| {
            account.is_empty() || account.len() > 256 || account.chars().any(char::is_control)
        }) {
            return Err("Claimed account exceeds its field budget".into());
        }
        for (value, max) in [
            (&self.host, 64),
            (&self.program, 64),
            (&self.summary, 160),
            (&self.journal_cursor, 512),
        ] {
            if value.len() > max || value.chars().any(char::is_control) {
                return Err("Event context exceeds its field budget".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    pub time_ms: u64,
    pub observed_ms: u64,
    pub source: u16,
    pub subject: u32,
    pub object: u32,
    pub kind: Kind,
    pub outcome: Outcome,
    pub severity: u8,
    pub bytes: u64,
    pub trace: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputEvent {
    pub time_ms: u64,
    pub source: String,
    pub subject: String,
    pub object: String,
    pub kind: Kind,
    pub outcome: Outcome,
    pub severity: u8,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub trace: u32,
    pub idempotency_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<EventContext>,
}

impl InputEvent {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        for value in [
            &self.source,
            &self.subject,
            &self.object,
            &self.idempotency_key,
        ] {
            if value.is_empty()
                || value.len() > 64
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@:/".contains(&b))
            {
                return Err(
                    "Labels must contain 1–64 ASCII letters, digits, or -_.@:/ characters.".into(),
                );
            }
        }
        if let Some(context) = &self.context {
            context.validate()?;
        }
        if !(1..=5).contains(&self.severity) {
            return Err("Severity must be between 1 and 5.".into());
        }
        if self.time_ms > now.saturating_add(60_000)
            || self.time_ms > i64::MAX as u64
            || self.bytes > 1 << 50
        {
            return Err("Event exceeds future timestamp or numeric limits.".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayEvent {
    #[serde(flatten)]
    pub event: Event,
    pub source_label: String,
    pub subject_label: String,
    pub object_label: String,
    pub encoded_bytes: usize,
    pub json_bytes: usize,
    pub notation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<EventContext>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: i64,
    pub rule: String,
    pub title: String,
    pub severity: u8,
    pub subject: String,
    pub time_ms: u64,
    pub status: String,
    pub explanation: String,
    pub evidence: Vec<DisplayEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub id: i64,
    pub finding_id: i64,
    pub title: String,
    pub state: String,
    pub rationale: String,
    pub steps: Vec<String>,
    pub evidence_hash: String,
    pub created_ms: u64,
    pub expires_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Audit {
    pub time_ms: u64,
    pub action: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub severity: u8,
    pub fields: &'static str,
    pub window: &'static str,
    pub tactic: &'static str,
}

pub const RULES: [Rule; 8] = [
    Rule { id: "AX-001", title: "Authentication burst", description: "Eight denied authentication events for one subject inside two minutes.", severity: 4, fields: "subject · time · kind · outcome", window: "120 seconds", tactic: "Credential access" },
    Rule { id: "AX-002", title: "Privilege sequence", description: "A high-severity process execution follows a successful authentication for the same subject inside one minute.", severity: 5, fields: "subject · time · kind · outcome · severity", window: "60 seconds", tactic: "Privilege escalation" },
    Rule { id: "AX-003", title: "Egress after execution", description: "At least 10 MiB sent after a high-severity process execution by the same subject inside three minutes.", severity: 5, fields: "subject · time · kind · outcome · bytes · severity", window: "180 seconds", tactic: "Exfiltration signal" },
    Rule { id: "AX-004", title: "Policy boundary denied", description: "A high-severity policy denial signals a blocked action at the control-plane boundary.", severity: 3, fields: "kind · outcome · severity", window: "Single event", tactic: "Defense boundary" },
    Rule { id: "AX-005", title: "System service failure", description: "A trusted system manager reports a failed service or process exit.", severity: 4, fields: "kind · outcome · severity · provenance", window: "Single event", tactic: "Service availability" },
    Rule { id: "AX-006", title: "Browser or document interpreter child", description: "An interpreter observation names a browser or document process as its parent, matching device, boot, PID and start time.", severity: 4, fields: "endpoint · boot · process · parent identity", window: "120 seconds", tactic: "Execution signal" },
    Rule { id: "AX-007", title: "Interpreter with external TCP connection", description: "An interpreter process and an established TCP socket share the exact observed process identity and metadata, with a non-local peer.", severity: 3, fields: "endpoint · boot · process identity · socket", window: "120 seconds", tactic: "Network investigation" },
    Rule { id: "AX-008", title: "Process identity became privileged", description: "The same observed process identity and executable changed from a non-system user to root or SYSTEM.", severity: 4, fields: "endpoint · boot · process identity · user", window: "120 seconds", tactic: "Privilege change" },
];

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn severity_label(severity: u8) -> &'static str {
    match severity {
        5 => "critical",
        4 => "high",
        3 => "medium",
        2 => "low",
        _ => "info",
    }
}
