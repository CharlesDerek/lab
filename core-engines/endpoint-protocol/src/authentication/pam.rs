//! Supported PAM module-failure fields; a module result is not a service result.
use super::bounded;
use std::{collections::BTreeSet, net::IpAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PamReport<'a> {
    /// Only the exact user field names the claimed account. ruser is distinct.
    pub claimed_user: Option<&'a str>,
    /// A reported IP literal, never a guessed address for a DNS name.
    pub source_ip: Option<IpAddr>,
}

/// Parse the existing pam_unix auth-failure grammar. The caller must validate
/// journal producer provenance and preserve module-only outcome semantics.
pub fn pam_unix_report(message: &str) -> Result<Option<PamReport<'_>>, &'static str> {
    if !bounded(message, 4096) {
        return Err("Invalid PAM authentication message budget");
    }
    let Some((prefix, fields)) = message.split_once("): authentication failure;") else {
        return Ok(None);
    };
    if !prefix.starts_with("pam_unix(") || !prefix.ends_with(":auth") {
        return Ok(None);
    }
    let mut report = PamReport {
        claimed_user: None,
        source_ip: None,
    };
    let mut seen = BTreeSet::new();
    for word in fields.split_whitespace() {
        let (key, value) = word
            .split_once('=')
            .ok_or("Ambiguous PAM authentication fields")?;
        if !["logname", "uid", "euid", "tty", "ruser", "rhost", "user"].contains(&key)
            || !seen.insert(key)
        {
            return Err("Ambiguous or unsupported PAM authentication fields");
        }
        if key == "user" && !value.is_empty() {
            if !bounded(value, 256) {
                return Err("Ambiguous PAM account");
            }
            report.claimed_user = Some(value);
        }
        if key == "rhost" {
            report.source_ip = value.parse().ok();
        }
    }
    Ok(Some(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::{from_journal, AuthenticationOutcome, JournalRecord};

    #[test]
    fn only_exact_user_field_supplies_the_claimed_account() {
        for fields in [
            "logname=caller uid=1000 euid=0 tty=pts/0 ruser=caller rhost=192.0.2.8 user=target",
            "ruser= rhost=192.0.2.8 user=target",
            "user=target rhost=192.0.2.8 ruser=caller",
            "ruser=user=decoy rhost=192.0.2.8 user=target",
        ] {
            let message = format!("pam_unix(su:auth): authentication failure; {fields}");
            let report = pam_unix_report(&message).unwrap().unwrap();
            assert_eq!(report.claimed_user, Some("target"));
            assert_eq!(report.source_ip, Some("192.0.2.8".parse().unwrap()));
        }
        for fields in [
            "ruser=caller rhost=",
            "ruser=caller rhost=host.example user=",
            "",
        ] {
            let message = format!("pam_unix(sudo:auth): authentication failure; {fields}");
            let report = pam_unix_report(&message).unwrap().unwrap();
            assert_eq!(report.claimed_user, None);
            assert_eq!(report.source_ip, None);
        }
    }

    #[test]
    fn ambiguous_fields_and_unsupported_module_reports_are_not_guessed() {
        for fields in [
            "user=one user=two",
            "ruser=one ruser=two user=target",
            "rhost=192.0.2.1 rhost=203.0.113.8 user=target",
            "USER=target",
            "user=target unknown=value",
            "user=target extra words",
        ] {
            assert!(pam_unix_report(&format!(
                "pam_unix(su:auth): authentication failure; {fields}"
            ))
            .is_err());
        }
        for message in [
            "pam_unix(su:session): authentication failure; user=target",
            "pam_other(su:auth): authentication failure; user=target",
            "prefix pam_unix(su:auth): authentication failure; user=target",
            "pam_unix(su:auth): authentication success; user=target",
        ] {
            assert_eq!(pam_unix_report(message).unwrap(), None);
        }
        assert!(pam_unix_report(&format!(
            "pam_unix(su:auth): authentication failure; user={}",
            "a".repeat(257)
        ))
        .is_err());
        assert!(
            pam_unix_report("pam_unix(su:auth): authentication failure; user=target\n").is_err()
        );
        assert!(pam_unix_report(&"a".repeat(4097)).is_err());
    }

    #[test]
    fn extraction_preserves_original_wire_fields_and_module_only_semantics() {
        let original = JournalRecord {
            cursor: "s=fixture;i=1".into(), sequence_id: "1".repeat(32), sequence: 1,
            realtime_us: 1_800_000_000_000_000, machine_id: "2".repeat(32), boot_id: "3".repeat(32),
            executable: "/usr/bin/su".into(), reporter_uid: 1000, reporter_pid: 42,
            message: "pam_unix(su:auth): authentication failure; logname=caller uid=1000 euid=0 tty=pts/0 ruser=caller rhost=192.0.2.8 user=target".into(),
        };
        let event = from_journal(&original).unwrap().unwrap();
        assert_eq!(event.journal, original);
        assert_eq!(event.claimed_user.as_deref(), Some("target"));
        assert_eq!(event.outcome, AuthenticationOutcome::Denied);
        assert_eq!(event.service_outcome(), None);
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            serde_json::json!({
                "journal": original, "outcome": "denied", "claimed_user": "target", "invalid_user": false,
                "mechanism": "pam_unix", "source_ip": "192.0.2.8", "source_port": null,
            })
        );
        event.validate(1_800_000_000_000).unwrap();
    }
}
