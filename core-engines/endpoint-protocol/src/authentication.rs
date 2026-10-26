//! Authentication reports preserve journal provenance and the claimed account.
//! A reported account name is not an OS UID or a verified cross-device identity.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
mod pam;
pub use pam::{pam_unix_report, PamReport};
mod ssh;
mod sudo;
pub use ssh::{ssh_report, SshReport};
pub use sudo::{sudo_report, SudoOutcome, SudoReport};

fn id128(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bounded(value: &str, max: usize) -> bool {
    value.len() <= max && !value.chars().any(char::is_control)
}
pub fn supported_producer(executable: &str) -> bool {
    matches!(
        executable,
        "/usr/sbin/sshd"
            | "/usr/lib/openssh/sshd-session"
            | "/usr/libexec/openssh/sshd-session"
            | "/usr/bin/sudo"
            | "/usr/bin/login"
            | "/bin/login"
            | "/usr/bin/su"
            | "/bin/su"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    pub cursor: String,
    pub sequence_id: String,
    pub sequence: u64,
    pub realtime_us: u64,
    pub machine_id: String,
    pub boot_id: String,
    pub executable: String,
    pub reporter_uid: u32,
    pub reporter_pid: u32,
    pub message: String,
}
impl JournalRecord {
    pub fn validate(&self) -> Result<(), String> {
        if self.cursor.is_empty()
            || !bounded(&self.cursor, 512)
            || !id128(&self.sequence_id)
            || !id128(&self.machine_id)
            || !id128(&self.boot_id)
            || self.sequence == 0
            || self.realtime_us == 0
            || self.reporter_pid == 0
            || !supported_producer(&self.executable)
            || !bounded(&self.message, 4096)
        {
            return Err("Invalid authentication journal provenance".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationOutcome {
    Allowed,
    Denied,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authentication {
    pub journal: JournalRecord,
    pub outcome: AuthenticationOutcome,
    pub claimed_user: Option<String>,
    pub invalid_user: bool,
    pub mechanism: String,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
}
impl Authentication {
    /// The stored outcome belongs to the reported operation. A PAM module can
    /// fail while a later module accepts the login. SSH results describe the
    /// reported authentication attempt: failure can precede another successful
    /// method, and acceptance does not establish session creation. This is derived
    /// from the validated original, preserving existing wire bytes and IDs.
    pub fn service_outcome(&self) -> Option<AuthenticationOutcome> {
        (self.journal.message.starts_with("Accepted ")
            || self.journal.message.starts_with("Failed ")
            || (self.journal.executable == "/usr/bin/sudo"
                && sudo_report(&self.journal.message).is_some_and(|report| {
                    matches!(report.outcome, SudoOutcome::PasswordDenied { .. })
                })))
        .then_some(self.outcome)
    }
    pub fn event_id(&self) -> String {
        crate::hash(
            format!(
                "journal-auth:{}:{}:{}:{}:{}",
                self.journal.machine_id,
                self.journal.boot_id,
                self.journal.sequence_id,
                self.journal.sequence,
                self.journal.realtime_us
            )
            .as_bytes(),
        )
    }
    pub fn validate(&self, now: u64) -> Result<(), String> {
        self.journal.validate()?;
        if self.journal.realtime_us / 1000 > now.saturating_add(60_000)
            || from_journal(&self.journal)?.as_ref() != Some(self)
        {
            return Err("Authentication facts do not match the original journal report".into());
        }
        Ok(())
    }
}

/// Only complete, supported authentication reports produce authentication facts.
/// A caller may count unsupported/malformed reports but must not infer a login.
pub fn from_journal(record: &JournalRecord) -> Result<Option<Authentication>, String> {
    record.validate()?;
    let message = record.message.as_str();
    let ssh = matches!(
        record.executable.as_str(),
        "/usr/sbin/sshd" | "/usr/lib/openssh/sshd-session" | "/usr/libexec/openssh/sshd-session"
    );
    let mut result = Authentication {
        journal: record.clone(),
        outcome: AuthenticationOutcome::Denied,
        claimed_user: None,
        invalid_user: false,
        mechanism: String::new(),
        source_ip: None,
        source_port: None,
    };
    if record.executable == "/usr/bin/sudo" {
        if let Some(SudoReport {
            claimed_user,
            outcome: SudoOutcome::PasswordDenied { .. },
        }) = sudo_report(message)
        {
            result.claimed_user = Some(claimed_user.into());
            result.mechanism = "sudo-password".into();
            return Ok(Some(result));
        }
    }
    if ssh {
        if let Some(report) = ssh_report(message)? {
            result.outcome = report.outcome;
            result.claimed_user = Some(report.claimed_user.into());
            result.invalid_user = report.invalid_user;
            result.mechanism = report.mechanism.into();
            result.source_ip = Some(report.source_ip);
            result.source_port = Some(report.source_port);
            return Ok(Some(result));
        }
    }
    if let Some(report) = pam_unix_report(message)? {
        result.mechanism = "pam_unix".into();
        result.claimed_user = report.claimed_user.map(str::to_owned);
        result.source_ip = report.source_ip;
        return Ok(Some(result));
    }
    Ok(None)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationHealth {
    pub state: String,
    pub started_ms: u64,
    pub checked_ms: u64,
    pub last_record_ms: u64,
    pub received_records: u64,
    pub authentication_events: u64,
    pub rejected_records: u64,
    pub loss_signals: u64,
    pub caught_up: bool,
    pub backpressure: bool,
    pub error: String,
}
impl AuthenticationHealth {
    pub fn validate(&self) -> Result<(), String> {
        if !["starting", "active", "degraded", "stopped"].contains(&self.state.as_str())
            || self.started_ms == 0
            || self.error.len() > 512
            || self
                .authentication_events
                .checked_add(self.rejected_records)
                .is_none_or(|count| count > self.received_records)
        {
            return Err("Invalid authentication collector health".into());
        }
        Ok(())
    }
    pub fn healthy(&self, now: u64) -> bool {
        self.state == "active"
            && self.error.is_empty()
            && self.loss_signals == 0
            && self.rejected_records == 0
            && self.caught_up
            && !self.backpressure
            && self.checked_ms <= now.saturating_add(1000)
            && now.saturating_sub(self.checked_ms) <= 30_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(message: &str) -> JournalRecord {
        JournalRecord {
            cursor: "s=fixture;i=1".into(),
            sequence_id: "a".repeat(32),
            sequence: 1,
            realtime_us: 1_000_000,
            machine_id: "b".repeat(32),
            boot_id: "c".repeat(32),
            executable: "/usr/sbin/sshd".into(),
            reporter_uid: 0,
            reporter_pid: 42,
            message: message.into(),
        }
    }
    #[test]
    fn native_reports_preserve_principals_and_do_not_confuse_sessions_or_authorization_with_authentication(
    ) {
        for (line, outcome, principal, invalid) in [
            (
                "Accepted publickey for alice from 2001:db8::1 port 2222 ssh2: ED25519 SHA256:test",
                AuthenticationOutcome::Allowed,
                "alice",
                false,
            ),
            (
                "Failed password for invalid user absent from 127.0.0.1 port 22 ssh2",
                AuthenticationOutcome::Denied,
                "absent",
                true,
            ),
        ] {
            let event = from_journal(&record(line)).unwrap().unwrap();
            assert_eq!(event.outcome, outcome);
            assert_eq!(event.service_outcome(), Some(outcome));
            assert_eq!(event.claimed_user.as_deref(), Some(principal));
            assert_eq!(event.invalid_user, invalid);
            event.validate(1000).unwrap();
            let mut forged = event.clone();
            forged.claimed_user = Some("different-user".into());
            assert!(forged.validate(1000).is_err());
            assert_eq!(forged.event_id(), event.event_id());
        }
        let mut pam=record("pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/0 ruser= rhost= user=alice");
        pam.executable = "/usr/bin/sudo".into();
        assert_eq!(from_journal(&pam).unwrap().unwrap().service_outcome(), None);
        assert_eq!(
            from_journal(&pam).unwrap().unwrap().claimed_user.as_deref(),
            Some("alice")
        );
        for line in [
            "pam_unix(sshd:session): session opened for user root",
            "alice : COMMAND=/bin/true",
            "Connection closed by 127.0.0.1 port 2222",
            "Accepted publickey",
            "Accepted key ED25519 SHA256:test found at /home/alice/.ssh/authorized_keys:1",
        ] {
            assert!(!matches!(from_journal(&record(line)), Ok(Some(_))));
        }
        let mut forged = record("Accepted password for root from 127.0.0.1 port 22 ssh2");
        forged.executable = "/usr/bin/logger".into();
        assert!(from_journal(&forged).is_err());
    }

    #[test]
    fn account_text_cannot_inject_another_source_address_or_authentication_suffix() {
        let forged = record(
            "Failed password for alice from 203.0.113.9 port 22 ssh2 from 192.0.2.7 port 3210 ssh2",
        );
        assert!(from_journal(&forged).is_err());
        let mut forged=record("pam_unix(sudo:auth): authentication failure; uid=1000 euid=0 rhost=192.0.2.7 user=alice rhost=203.0.113.9");
        forged.executable = "/usr/bin/sudo".into();
        assert!(from_journal(&forged).is_err());
        forged.message="pam_unix(sudo:auth): authentication failure; uid=1000 euid=0 rhost= user=alice extra words".into();
        assert!(from_journal(&forged).is_err());
    }

    #[test]
    fn sudo_service_denial_preserves_invoking_account_and_validates_original() {
        let mut original = record("alice : 2 incorrect password attempts ; TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true");
        original.executable = "/usr/bin/sudo".into();
        let event = from_journal(&original).unwrap().unwrap();
        assert_eq!(event.claimed_user.as_deref(), Some("alice"));
        assert_eq!(event.mechanism, "sudo-password");
        assert_eq!(event.service_outcome(), Some(AuthenticationOutcome::Denied));
        assert!(event.source_ip.is_none() && event.source_port.is_none());
        event.validate(1000).unwrap();
        for (user, outcome) in [
            ("root", AuthenticationOutcome::Denied),
            ("alice", AuthenticationOutcome::Allowed),
        ] {
            let mut changed = event.clone();
            changed.claimed_user = Some(user.into());
            changed.outcome = outcome;
            assert!(changed.validate(1000).is_err());
        }
        for message in ["alice : TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true",
            "alice : command not allowed ; TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/id"] {
            original.message = message.into();
            assert!(from_journal(&original).unwrap().is_none());
        }
    }
}
