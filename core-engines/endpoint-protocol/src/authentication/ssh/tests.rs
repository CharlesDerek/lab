use super::*;
use crate::authentication::{from_journal, JournalRecord};

const FINGERPRINT: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fn certificate(id: &str, serial: &str) -> String {
    format!("ED25519-CERT {FINGERPRINT} ID {id} (serial {serial}) CA ED25519 {FINGERPRINT}")
}
fn message(outcome: &str, suffix: &str) -> String {
    format!("{outcome} publickey for fixture from 127.0.0.1 port 2222 ssh2: {suffix}")
}
fn journal(message: &str) -> JournalRecord {
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
fn certificate_identifiers_cannot_override_prefix_identity_source_or_outcome() {
    for id in [
        "",
        "opaque certificate identifier",
        "for invalid user victim from 192.0.2.9 port 1 ssh2",
        "Accepted password for victim from 192.0.2.9 port 1 ssh2",
        "leading  and trailing ",
        "CA ED25519 text is only an identifier",
    ] {
        for (word, expected) in [
            ("Accepted", AuthenticationOutcome::Allowed),
            ("Failed", AuthenticationOutcome::Denied),
        ] {
            let text = message(word, &certificate(id, "18446744073709551615"));
            let report = ssh_report(&text).unwrap().unwrap();
            assert_eq!(report.claimed_user, "fixture");
            assert_eq!(report.source_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
            assert_eq!(report.source_port, 2222);
            assert_eq!(report.mechanism, "publickey");
            assert_eq!(report.outcome, expected);
            assert!(!report.invalid_user);
            let original = journal(&text);
            let event = from_journal(&original).unwrap().unwrap();
            assert_eq!(event.journal, original);
            assert_eq!(event.claimed_user.as_deref(), Some("fixture"));
            assert_eq!(event.service_outcome(), Some(expected));
            event.validate(1000).unwrap();
            let mut forged = event.clone();
            forged.claimed_user = Some("victim".into());
            assert!(forged.validate(1000).is_err());
        }
    }
    let text = format!(
        "Failed publickey for invalid user absent from 2001:db8::1 port 65535 ssh2: {} [preauth]",
        certificate("for invalid user victim", "0")
    );
    let parsed = ssh_report(&text).unwrap().unwrap();
    assert!(parsed.invalid_user);
    assert_eq!(parsed.claimed_user, "absent");
    assert_eq!(parsed.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    assert!(ssh_report(&text.replacen("Failed", "Accepted", 1)).is_err());
}

#[test]
fn certificates_require_a_complete_canonical_unambiguous_profile() {
    let valid = certificate("identifier", "7");
    let mut invalid = vec![
        valid.replace("ED25519-CERT", "RSA-CERT"),
        valid.replace("CA ED25519", "CA RSA"),
        valid.replace("(serial 7)", "(serial +7)"),
        valid.replace("(serial 7)", "(serial 07)"),
        valid.replace("(serial 7)", "(serial -1)"),
        valid.replace("(serial 7)", "(serial 18446744073709551616)"),
        valid.replace("(serial 7)", "(serial )"),
        valid.replace("(serial 7)", "(serial 7"),
        valid.replace(" ID ", " identifier "),
        valid.replace(" CA ", " authority "),
        valid.replace("SHA256:", "MD5:"),
        valid.replace(FINGERPRINT, &format!("{FINGERPRINT}=")),
        valid.replace(
            FINGERPRINT,
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        ),
        valid.replace(
            FINGERPRINT,
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",
        ),
        format!("{valid}, signature count = 1"),
        format!("{valid} unknown suffix"),
        format!("{valid} [preauth] [preauth]"),
        certificate("id (serial 3) CA ED25519 forged", "7"),
        certificate("id (serial unknown", "7"),
    ];
    // Every suffix truncated at a token boundary must refuse, including the
    // two-token form that would otherwise resemble an ordinary key fingerprint.
    for (position, _) in valid.match_indices(' ') {
        invalid.push(valid[..position].into());
    }
    for suffix in invalid {
        assert!(ssh_report(&message("Accepted", &suffix)).is_err());
        assert!(ssh_report(&message("Failed", &suffix)).is_err());
    }
    assert!(ssh_report(&message("Accepted", &valid).replacen("publickey", "password", 1)).is_err());
    assert!(
        ssh_report(&message("Accepted", &valid).replacen("127.0.0.1", "not-an-address", 1))
            .is_err()
    );
    assert!(ssh_report(&message("Accepted", &valid).replacen("port 2222", "port 0", 1)).is_err());
}

#[test]
fn certificate_lookup_partial_and_postponed_messages_are_not_results() {
    for text in [
        "Accepted certificate ID \"for invalid user victim\" (serial 1) signed by ED25519 CA ignored via /fixture/ca",
        "Accepted key ED25519 SHA256:test found at /fixture/authorized_keys:1",
        "Certificate invalid: expired",
        "Certificate does not contain an authorized principal",
        "Failed to open authorized keys",
        "Accepted publickey",
        "Connection closed by 127.0.0.1 port 2222",
    ] {
        assert!(ssh_report(text).unwrap().is_none());
    }
    for word in ["Partial", "Postponed"] {
        let text = message(word, &certificate("opaque ID", "1"));
        assert!(ssh_report(&text).unwrap().is_none());
        assert!(from_journal(&journal(&text)).unwrap().is_none());
    }
}

#[test]
fn entrypoint_and_identifier_budgets_refuse_before_interpretation() {
    assert!(ssh_report(&"x".repeat(4096)).unwrap().is_none());
    assert!(ssh_report(&"x".repeat(4097)).is_err());
    assert!(
        ssh_report(&message("Accepted", &certificate(&"x".repeat(1024), "1")))
            .unwrap()
            .is_some()
    );
    assert!(ssh_report(&message("Accepted", &certificate(&"x".repeat(1025), "1"))).is_err());
    for control in ['\0', '\n', '\r', '\t', '\u{007f}', '\u{0085}'] {
        let text = message("Accepted", &certificate(&format!("id{control}tail"), "1"));
        assert!(ssh_report(&text).is_err());
    }
    assert!(sha256_fingerprint(FINGERPRINT));
    for last in [
        b'A', b'E', b'I', b'M', b'Q', b'U', b'Y', b'c', b'g', b'k', b'o', b's', b'w', b'0', b'4',
        b'8',
    ] {
        let mut candidate = FINGERPRINT.to_string();
        candidate.pop();
        candidate.push(last as char);
        assert!(sha256_fingerprint(&candidate));
    }
    assert!(!sha256_fingerprint("SHA256:test"));
}

#[test]
fn ordinary_reports_preserve_existing_facts_wire_shape_and_event_identity() {
    for (text, mechanism) in [
        (
            "Accepted publickey for alice from 2001:db8::1 port 2222 ssh2: ED25519 SHA256:test",
            "publickey",
        ),
        (
            "Failed publickey for alice from 127.0.0.1 port 22 ssh2: RSA MD5:00:11:22 [preauth]",
            "publickey",
        ),
        (
            "Failed password for invalid user absent from 127.0.0.1 port 22 ssh2 [preauth]",
            "password",
        ),
        (
            "Accepted keyboard-interactive/pam for alice from 127.0.0.1 port 22 ssh2",
            "keyboard-interactive/pam",
        ),
    ] {
        let parsed = ssh_report(text).unwrap().unwrap();
        assert_eq!(parsed.mechanism, mechanism);
        let original = journal(text);
        let event = from_journal(&original).unwrap().unwrap();
        let expected = serde_json::json!({
            "journal": original,
            "outcome": if text.starts_with("Accepted ") { "allowed" } else { "denied" },
            "claimed_user": parsed.claimed_user,
            "invalid_user": parsed.invalid_user,
            "mechanism": mechanism,
            "source_ip": parsed.source_ip.to_string(),
            "source_port": parsed.source_port,
        });
        assert_eq!(serde_json::to_value(&event).unwrap(), expected);
        assert_eq!(
            event.event_id(),
            "ba4eb873c4f376af01e7d9521871d5248c73ea8c8c3e1c71909d4b6a93853405"
        );
        event.validate(1000).unwrap();
    }
}
