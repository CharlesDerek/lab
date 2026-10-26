use super::*;

const NOW: u64 = 1_800_000_000_000;

fn record(message: &str, exe: &str) -> Value {
    serde_json::json!({
        "__CURSOR": "s=identity;i=1", "__REALTIME_TIMESTAMP": (NOW * 1000).to_string(),
        "MESSAGE": message, "_EXE": exe, "_COMM": "sshd", "_UID": "0", "_PID": "50"
    })
}

fn denial(account: &str, source: &str, ordinal: usize) -> InputEvent {
    let row = serde_json::json!({
        "__CURSOR": format!("s=identity;i={ordinal}"),
        "__REALTIME_TIMESTAMP": (NOW * 1000).to_string(),
        "MESSAGE": format!("Failed password for invalid user {account} from 192.0.2.10 port 2222 ssh2"),
        "_EXE": "/usr/sbin/sshd", "_COMM": "sshd", "_UID": "0", "_PID": "50",
        "_HOSTNAME": "fixture-host", "_SYSTEMD_UNIT": "ssh.service", "PRIORITY": "6"
    });
    normalize(&row, source, NOW).unwrap()
}

fn legacy_alias(ordinal: usize) -> InputEvent {
    // This literal64hex username was valid in the old compact label grammar;
    // matching a new digest string needs no cryptographic collision.
    let account = "57d718f1198920b3e435385a0e16ab634e66a9d18ffd94236340f214de245e48";
    let mut event = denial(account, "host-journal", ordinal);
    event.subject = account.into();
    event.context.as_mut().unwrap().claimed_account = None;
    event
}

#[test]
fn a_legacy_digest_named_account_cannot_supply_new_account_denials() {
    let mut engine = Engine::memory().unwrap();
    for ordinal in 1..=7 {
        engine.ingest(&[legacy_alias(ordinal)], NOW).unwrap();
    }
    let modern = denial("alice", "host-journal", 8);
    assert_eq!(modern.subject, legacy_alias(1).subject);
    engine.ingest(&[modern], NOW).unwrap();
    assert!(engine.findings().unwrap().is_empty());
}

#[test]
fn legacy_and_modern_aliases_keep_distinct_findings_after_restart_and_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alias.db");
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    for ordinal in 1..=8 {
        engine.ingest(&[legacy_alias(ordinal)], NOW).unwrap();
    }
    let legacy = engine.findings().unwrap().remove(0);
    let legacy_json = serde_json::to_value(&legacy).unwrap();
    let fingerprint: String = engine
        .connection
        .query_row(
            "SELECT fingerprint FROM findings WHERE id=?1",
            [legacy.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        fingerprint,
        digest(&format!(
            "AX-001:{}:{}",
            legacy.evidence[0].event.subject,
            NOW / 180_000
        ))
    );
    for ordinal in 9..=16 {
        engine
            .ingest(&[denial("alice", "host-journal", ordinal)], NOW)
            .unwrap();
    }
    let findings = engine.findings().unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].subject, findings[1].subject);
    assert_eq!(
        serde_json::to_value(findings.iter().find(|f| f.id == legacy.id).unwrap()).unwrap(),
        legacy_json
    );
    let modern = findings.iter().find(|f| f.id != legacy.id).unwrap();
    assert_eq!(modern.evidence.len(), 8);
    assert!(modern
        .evidence
        .iter()
        .all(|e| e.context.as_ref().unwrap().claimed_account.as_deref() == Some("alice")));
    let modern_fingerprint: String = engine
        .connection
        .query_row(
            "SELECT fingerprint FROM findings WHERE id=?1",
            [modern.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(fingerprint, modern_fingerprint);
    let before = serde_json::to_value(&findings).unwrap();
    engine.flush(NOW).unwrap();
    drop(engine);
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    assert_eq!(
        engine
            .ingest(&[legacy_alias(1), denial("alice", "host-journal", 16)], NOW)
            .unwrap(),
        0
    );
    // A new observation causes detection to revisit retained history without
    // changing either saved finding or creating a second legacy fingerprint.
    let mut observation = denial("unrelated", "host-journal", 17);
    observation.outcome = Outcome::Observe;
    engine.ingest(&[observation], NOW).unwrap();
    assert_eq!(
        serde_json::to_value(engine.findings().unwrap()).unwrap(),
        before
    );
}

#[test]
fn claimed_authentication_does_not_seed_legacy_process_correlations() {
    for legacy in [false, true] {
        let mut engine = Engine::memory().unwrap();
        let mut authentication = normalize(
            &record(
                "Accepted password for alice from 192.0.2.10 port 2222 ssh2",
                "/usr/sbin/sshd",
            ),
            "host-journal",
            NOW,
        )
        .unwrap();
        if legacy {
            authentication.context.as_mut().unwrap().claimed_account = None;
        }
        let subject = authentication.subject.clone();
        engine.ingest(&[authentication], NOW).unwrap();
        let mut process = InputEvent {
            time_ms: NOW + 1,
            source: "host-journal".into(),
            subject,
            object: "generic-process".into(),
            kind: Kind::Process,
            outcome: Outcome::Allow,
            severity: 4,
            bytes: 0,
            trace: 0,
            idempotency_key: "generic-process".into(),
            context: None,
        };
        engine
            .ingest(std::slice::from_ref(&process), NOW + 1)
            .unwrap();
        assert_eq!(
            engine
                .findings()
                .unwrap()
                .iter()
                .any(|f| f.rule == "AX-002"),
            legacy
        );
        process.kind = Kind::Network;
        process.time_ms += 1;
        process.bytes = 10 * 1024 * 1024;
        process.idempotency_key = "generic-network".into();
        engine.ingest(&[process], NOW + 2).unwrap();
        let findings = engine.findings().unwrap();
        assert!(
            findings.iter().any(|f| f.rule == "AX-003"),
            "Legacy process/network behavior must remain intact"
        );
        assert_eq!(findings.iter().any(|f| f.rule == "AX-002"), legacy);
    }
}

#[test]
fn mixed_supported_methods_share_one_claim_without_module_double_counting() {
    let mut engine = Engine::memory().unwrap();
    for index in 0..8 {
        let mut module = record("pam_unix(sshd:auth): authentication failure; ruser=caller rhost=192.0.2.10 user=alice!", "/usr/sbin/sshd");
        module["__CURSOR"] = format!("module-{index}").into();
        let module = normalize(&module, "host-journal", NOW).unwrap();
        assert_eq!(module.outcome, Outcome::Observe);
        engine.ingest(&[module], NOW).unwrap();
        let denied = if index % 2 == 0 {
            denial("alice!", "host-journal", index)
        } else {
            let mut row = record("alice! : 1 incorrect password attempt ; TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true", "/usr/bin/sudo");
            row["__CURSOR"] = format!("sudo-{index}").into();
            normalize(&row, "host-journal", NOW).unwrap()
        };
        assert_eq!(
            denied.context.as_ref().unwrap().claimed_account.as_deref(),
            Some("alice!")
        );
        engine.ingest(&[denied], NOW).unwrap();
        assert_eq!(
            engine
                .findings()
                .unwrap()
                .iter()
                .any(|f| f.rule == "AX-001"),
            index == 7
        );
    }
    let finding = engine.findings().unwrap().remove(0);
    assert_eq!(finding.evidence.len(), 8);
    assert!(finding
        .evidence
        .iter()
        .all(|e| e.event.outcome == Outcome::Deny
            && e.context.as_ref().unwrap().claimed_account.as_deref() == Some("alice!")));
}

#[test]
fn event_search_retains_exact_claim_without_assigning_it_to_legacy_facts() {
    let mut engine = Engine::memory().unwrap();
    engine
        .ingest(
            &[
                legacy_alias(1),
                denial("alice!é", "host-journal", 2),
                denial("alice", "host-journal", 3),
            ],
            NOW,
        )
        .unwrap();
    let events = engine.events().unwrap();
    let exact = crate::render::filter_events(
        &events,
        &crate::web::Filters {
            q: "ALICE!É".into(),
            ..Default::default()
        },
    );
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].event.id, events[1].event.id);
    assert!(!exact[0].subject_label.contains("alice"));
    let existing = crate::render::filter_events(
        &events,
        &crate::web::Filters {
            q: events[0].subject_label.clone(),
            ..Default::default()
        },
    );
    assert!(existing
        .iter()
        .any(|event| event.event.id == events[0].event.id));
    assert!(crate::render::filter_events(
        &events,
        &crate::web::Filters {
            q: "alice!é".into(),
            kind: "PROCESS".into(),
            ..Default::default()
        }
    )
    .is_empty());
}

#[test]
fn investigator_packets_bound_and_cite_exact_claims_without_inventing_identity() {
    use crate::investigator::{Analysis, Fact, InvestigationRequest};
    use orchestrator::governor::Resources;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("claimed-packet.db");
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    let account = "é".repeat(128);
    assert_eq!(account.len(), 256);
    let mut legacy = legacy_alias(2);
    legacy.time_ms += 1;
    engine
        .ingest(&[denial(&account, "host-journal", 1), legacy], NOW + 1)
        .unwrap();
    let case_id = engine
        .create_case("Account claim evidence", 2, NOW + 1)
        .unwrap();
    for (index, event) in engine.events().unwrap().into_iter().enumerate() {
        engine
            .attach_case_event(case_id, index as u64 + 1, event, NOW + 1)
            .unwrap();
    }
    engine
        .configure_pool(
            "analysis",
            Resources {
                cpu_millis: 1000,
                memory_mib: 1024,
                tokens: 20000,
                ..Default::default()
            },
            Resources::default(),
            NOW + 1,
        )
        .unwrap();
    let mut request = InvestigationRequest {
        id: "bounded-claims".into(),
        case_id,
        pool: "analysis".into(),
        max_events: 1,
        token_budget: 4096,
        deadline_ms: NOW + 60000,
    };
    let bounded = engine
        .prepare_investigation(&request, "analyst", NOW + 1)
        .unwrap();
    assert!(bounded.incomplete);
    assert_eq!(bounded.evidence.len(), 1);
    assert_eq!(bounded.evidence[0].fields["claimed_account"], account);
    assert!(serde_json::to_vec(&bounded).unwrap().len() <= 32768);
    request.id = "complete-claims".into();
    request.max_events = 32;
    let complete = engine
        .prepare_investigation(&request, "analyst", NOW + 1)
        .unwrap();
    assert!(!complete.incomplete);
    assert_eq!(complete.evidence.len(), 2);
    assert_eq!(complete.evidence[0].fields["source"], "host-journal");
    assert_eq!(complete.evidence[0].fields["claimed_account"], account);
    assert_eq!(complete.evidence[0].fields.as_object().unwrap().len(), 9);
    assert!(complete.evidence[0].fields.get("uid").is_none());
    assert!(complete.evidence[0]
        .fields
        .get("verified_principal")
        .is_none());
    assert_eq!(complete.evidence[1].fields.as_object().unwrap().len(), 8);
    assert!(complete.evidence[1].fields.get("claimed_account").is_none());
    let cited = &complete.evidence[0];
    let mut analysis = Analysis {
        facts: vec![Fact {
            event_id: cited.id,
            sha256: cited.sha256.clone(),
            field: "/claimed_account".into(),
            value: account.clone().into(),
        }],
        hypotheses: Vec::new(),
        abstain_reason: None,
    };
    analysis.validate(&complete).unwrap();
    assert!(
        analysis.validate(&bounded).is_err(),
        "Truncation still requires abstention"
    );
    analysis.facts[0].value = "uid-0".into();
    assert!(analysis.validate(&complete).is_err());
    analysis.facts[0].value = account.into();
    analysis.facts[0].field = "/verified_principal".into();
    assert!(analysis.validate(&complete).is_err());
    analysis.facts[0].field = "/claimed_account".into();
    analysis.facts[0].event_id = complete.evidence[1].id;
    analysis.facts[0]
        .sha256
        .clone_from(&complete.evidence[1].sha256);
    analysis.facts[0].value = Value::Null;
    assert!(
        analysis.validate(&complete).is_err(),
        "Absent is not an observed null claim"
    );
    drop(engine);
    let engine = Engine::open(&path).unwrap();
    let restored = engine.investigation(&request.id).unwrap().packet;
    assert_eq!(
        serde_json::to_value(restored).unwrap(),
        serde_json::to_value(complete).unwrap()
    );
    request.id = "excess-events".into();
    request.max_events = 33;
    assert!(engine
        .prepare_investigation(&request, "analyst", NOW + 1)
        .is_err());
}

#[test]
fn retained_graph_separates_claims_from_legacy_aliases_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("graph-alias.db");
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    engine
        .ingest(
            &[
                legacy_alias(1),
                denial("alice", "host-journal", 2),
                denial("alice", "other-journal", 4),
            ],
            NOW,
        )
        .unwrap();
    let events = engine.events().unwrap();
    let legacy_id = events[0].event.id;
    let modern_id = events[1].event.id;
    let other_source_id = events[2].event.id;
    let legacy_key = format!("identity:{}", events[0].subject_label);
    let legacy_keys = engine.graph_keys(legacy_id).unwrap();
    assert!(legacy_keys.contains(&legacy_key));
    let modern_keys = engine.graph_keys(modern_id).unwrap();
    assert!(!modern_keys.contains(&legacy_key));
    let claim_key = modern_keys
        .iter()
        .find(|key| key.starts_with("claimed-account:"))
        .unwrap()
        .clone();
    assert!(!legacy_keys.contains(&claim_key));
    let other_keys = engine.graph_keys(other_source_id).unwrap();
    assert!(!other_keys.contains(&claim_key));
    assert!(other_keys
        .iter()
        .any(|key| key.starts_with("claimed-account:")));
    // Same reporter and endpoint are legitimate shared context, distinct from
    // the claimed account. They must not be removed to make this test pass.
    assert!(legacy_keys.contains(&"identity:fixture-host:uid-0".into()));
    assert!(modern_keys.contains(&"identity:fixture-host:uid-0".into()));
    engine.flush(NOW).unwrap();
    drop(engine);
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    assert_eq!(engine.graph_keys(legacy_id).unwrap(), legacy_keys);
    assert_eq!(engine.graph_keys(modern_id).unwrap(), modern_keys);
    assert_eq!(engine.graph_keys(other_source_id).unwrap(), other_keys);
    let mut trigger = denial("alice", "host-journal", 3);
    trigger.severity = 5;
    engine.ingest(&[trigger], NOW).unwrap();
    let trigger_id = engine.events().unwrap().last().unwrap().event.id;
    let state = engine.memory_state().unwrap();
    let legacy = state
        .recent_relevance
        .iter()
        .find(|r| r.event_id == legacy_id && r.trigger_id == trigger_id)
        .unwrap();
    assert!(legacy
        .reasons
        .iter()
        .any(|r| r.starts_with("endpoint:fixture-host ")));
    assert!(legacy
        .reasons
        .iter()
        .any(|r| r.starts_with("identity:fixture-host:uid-0 ")));
    assert!(!legacy
        .reasons
        .iter()
        .any(|r| r.starts_with(&format!("{legacy_key} ")) || r.starts_with("claimed-account:")));
    let other = state
        .recent_relevance
        .iter()
        .find(|r| r.event_id == other_source_id && r.trigger_id == trigger_id)
        .unwrap();
    assert!(!other
        .reasons
        .iter()
        .any(|r| r.starts_with("claimed-account:")));
    let modern = state
        .recent_relevance
        .iter()
        .find(|r| r.event_id == modern_id && r.trigger_id == trigger_id)
        .unwrap();
    let identity_reasons = modern
        .reasons
        .iter()
        .filter(|r| r.starts_with("identity:") || r.starts_with("claimed-account:"))
        .collect::<Vec<_>>();
    assert_eq!(
        identity_reasons.len(),
        1,
        "Claim and reporter must not double identity weight"
    );
    assert!(identity_reasons[0].starts_with(&format!("{claim_key} ")));
    assert!(identity_reasons[0].ends_with(&format!("(+{})", state.config.identity_weight)));
    assert_eq!(
        engine
            .graph_neighbors(&claim_key, trigger_id, NOW, 16)
            .unwrap(),
        vec![modern_id]
    );
    assert_eq!(
        engine
            .graph_neighbors(&legacy_key, trigger_id, NOW, 16)
            .unwrap(),
        vec![legacy_id]
    );
}

#[test]
fn distinct_claimed_accounts_do_not_combine_denials() {
    let mut engine = Engine::memory().unwrap();
    for ordinal in 1..=8 {
        let account = format!("alice{}", "!".repeat(ordinal));
        let event = denial(&account, "host-journal", ordinal);
        assert_eq!(event.kind, Kind::Authentication);
        assert_eq!(event.outcome, Outcome::Deny);
        engine.ingest(&[event], NOW).unwrap();
    }
    assert!(!engine
        .findings()
        .unwrap()
        .iter()
        .any(|finding| finding.rule == "AX-001"));
}

#[test]
fn exact_account_and_source_bytes_have_stable_distinct_keys() {
    // Independently calculated SHA-256 of the specified UTF-8 JSON tuple.
    for (account, expected) in [
        (
            "alice",
            "57d718f1198920b3e435385a0e16ab634e66a9d18ffd94236340f214de245e48",
        ),
        (
            "alice!",
            "e56c3b700874d02979bcc7f37abe6e9d81c4d9b4607697398033f52412f4d12e",
        ),
        (
            "álîce",
            "713df5d9b586a1d344ed90108f5298fccb50d91bccba18dd8f4039737cdbbaf6",
        ),
    ] {
        assert_eq!(denial(account, "host-journal", 1).subject, expected);
    }
    let prefix = "a".repeat(64);
    let accounts = [
        "alice".into(),
        "alice!".into(),
        "alice+".into(),
        "Alice".into(),
        "álîce".into(),
        "a\u{301}lîce".into(),
        "!".into(),
        "unknown".into(),
        "uid-0".into(),
        format!("{prefix}1"),
        format!("{prefix}2"),
        "a".repeat(256),
    ];
    let mut keys = std::collections::BTreeSet::new();
    for source in ["host-journal", "other-journal"] {
        for (index, account) in accounts.iter().enumerate() {
            let event = denial(account, source, index);
            assert_eq!(event.subject.len(), 64);
            event.validate(NOW).unwrap();
            assert!(keys.insert(event.subject));
            let context = event.context.unwrap();
            assert_eq!(context.claimed_account.as_deref(), Some(account.as_str()));
            assert_eq!(context.uid, Some(0));
            assert_eq!(context.pid, Some(50));
        }
    }
    assert_ne!(
        journal_account_subject("a-b", "c"),
        journal_account_subject("a", "b-c")
    );
}

#[test]
fn separate_accounts_and_sources_cannot_supply_the_eighth_denial() {
    let mut engine = Engine::memory().unwrap();
    let prefix = "a".repeat(64);
    let accounts = [
        "alice".to_string(),
        "alice!".into(),
        format!("{prefix}1"),
        format!("{prefix}2"),
    ];
    for source in ["host-journal", "other-journal"] {
        for (index, account) in accounts.iter().enumerate() {
            for count in 1..=7 {
                engine
                    .ingest(&[denial(account, source, index * 10 + count)], NOW)
                    .unwrap();
            }
        }
    }
    assert!(engine.findings().unwrap().is_empty());
    let eighth = denial("alice", "host-journal", 8);
    assert_eq!(
        engine.ingest(std::slice::from_ref(&eighth), NOW).unwrap(),
        1
    );
    let findings = engine.findings().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "AX-001");
    assert_eq!(findings[0].subject, eighth.subject);
    assert_eq!(findings[0].evidence.len(), 8);
    assert!(findings[0]
        .evidence
        .iter()
        .all(|e| e.source_label == "host-journal" && e.subject_label == eighth.subject));
    assert_eq!(engine.ingest(&[eighth], NOW).unwrap(), 0);
    assert_eq!(engine.findings().unwrap().len(), 1);
}

#[test]
fn supported_methods_share_exact_claimed_account_but_not_reporter_uid() {
    let expected = denial("uid-0!", "host-journal", 1).subject;
    for (message, exe, kind, outcome) in [
        ("pam_unix(sshd:auth): authentication failure; ruser=decoy rhost=192.0.2.10 user=uid-0!", "/usr/sbin/sshd", Kind::Authentication, Outcome::Observe),
        ("uid-0! : 1 incorrect password attempt ; TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true", "/usr/bin/sudo", Kind::Authentication, Outcome::Deny),
        ("uid-0! : TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true", "/usr/bin/sudo", Kind::Policy, Outcome::Allow),
        ("Accepted keyboard-interactive/pam for uid-0! from 192.0.2.10 port 2222 ssh2", "/usr/sbin/sshd", Kind::Authentication, Outcome::Allow),
    ] {
        let event = normalize(&record(message, exe), "host-journal", NOW).unwrap();
        assert_eq!(event.subject, expected);
        assert_eq!(event.kind, kind);
        assert_eq!(event.outcome, outcome);
        let context = event.context.unwrap();
        assert_eq!(context.uid, Some(0));
        assert_eq!(context.claimed_account.as_deref(), Some("uid-0!"));
    }
    for message in [
        "pam_unix(sshd:auth): authentication failure; ruser=decoy rhost=192.0.2.10",
        "Partial keyboard-interactive/pam for uid-0! from 192.0.2.10 port 2222 ssh2",
        "Accepted certificate ID uid-0! (serial 1) signed by ED25519 CA",
    ] {
        let event = normalize(&record(message, "/usr/sbin/sshd"), "host-journal", NOW).unwrap();
        assert_eq!(event.subject, "uid-0");
        assert_eq!(event.outcome, Outcome::Observe);
        assert_ne!(event.subject, expected);
        assert!(event.context.unwrap().claimed_account.is_none());
    }
}

#[test]
fn persisted_legacy_facts_remain_unchanged_and_cursor_reinterpretation_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.db");
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    engine
        .create_source("host-journal", "journal", "", NOW)
        .unwrap();
    let mut legacy = Vec::new();
    for count in 1..=8 {
        let mut event = denial("alice!", "host-journal", count);
        // Previously committed normalized facts are immutable. This simulates
        // the exact old lossy account label without changing the shared parser.
        event.subject = "alice".into();
        event.context.as_mut().unwrap().claimed_account = None;
        let cursor = event.context.as_ref().unwrap().journal_cursor.clone();
        engine
            .ingest_source(
                "host-journal",
                None,
                std::slice::from_ref(&event),
                Some(&cursor),
                0,
                NOW,
            )
            .unwrap();
        legacy.push(event);
    }
    let before = serde_json::to_value(engine.events().unwrap()).unwrap();
    let findings = serde_json::to_value(engine.findings().unwrap()).unwrap();
    assert_eq!(findings.as_array().unwrap().len(), 1);
    drop(engine);
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    assert_eq!(
        serde_json::to_value(engine.events().unwrap()).unwrap(),
        before
    );
    assert_eq!(
        serde_json::to_value(engine.findings().unwrap()).unwrap(),
        findings
    );
    let source = engine
        .sources()
        .unwrap()
        .into_iter()
        .find(|s| s.id == "host-journal")
        .unwrap();
    assert_eq!(source.cursor, "s=identity;i=8");
    // Normal resume starts after the committed cursor. Seven new facts must
    // not combine with the old account label or rewrite its investigation.
    for count in 9..=15 {
        let event = denial("alice!", "host-journal", count);
        let cursor = event.context.as_ref().unwrap().journal_cursor.clone();
        engine
            .ingest_source("host-journal", None, &[event], Some(&cursor), 0, NOW)
            .unwrap();
    }
    assert_eq!(
        serde_json::to_value(engine.findings().unwrap()).unwrap(),
        findings
    );
    assert_eq!(engine.ingest(&[legacy[0].clone()], NOW).unwrap(), 0);
    let reinterpreted = denial("alice!", "host-journal", 1);
    let error = engine
        .ingest_source(
            "host-journal",
            None,
            &[reinterpreted],
            Some("s=identity;i=1"),
            0,
            NOW,
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Idempotency key reused with different event facts"
    );
    assert_eq!(
        engine
            .sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == "host-journal")
            .unwrap()
            .cursor,
        "s=identity;i=15"
    );
    let eighth = denial("alice!", "host-journal", 16);
    engine
        .ingest_source(
            "host-journal",
            None,
            std::slice::from_ref(&eighth),
            Some("s=identity;i=16"),
            0,
            NOW,
        )
        .unwrap();
    assert_eq!(engine.findings().unwrap().len(), 2);
    drop(engine);
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    assert_eq!(
        engine.ingest(std::slice::from_ref(&eighth), NOW).unwrap(),
        0
    );
    let mut changed = eighth;
    changed.object = "ssh:192.0.2.11".into();
    assert!(engine.ingest(&[changed], NOW).is_err());
    assert_eq!(engine.findings().unwrap().len(), 2);
}

#[test]
fn optional_account_context_preserves_legacy_bytes_and_enforces_exact_budget() {
    let raw = r#"{"host":"fixture","program":"sshd","pid":50,"parent_pid":null,"process_start_ms":null,"parent_start_ms":null,"uid":0,"summary":"Supported report","journal_cursor":"s=identity;i=1"}"#;
    let mut context: EventContext = serde_json::from_str(raw).unwrap();
    assert!(context.claimed_account.is_none());
    context.validate().unwrap();
    assert_eq!(serde_json::to_string(&context).unwrap(), raw);
    for account in ["a".repeat(256), "é".repeat(128), "<claimed&account>".into()] {
        context.claimed_account = Some(account.clone());
        context.validate().unwrap();
        let restored: EventContext =
            serde_json::from_str(&serde_json::to_string(&context).unwrap()).unwrap();
        assert_eq!(restored.claimed_account, Some(account));
    }
    for account in [
        String::new(),
        "a".repeat(257),
        "é".repeat(129),
        "alice\n".into(),
        "alice\0".into(),
    ] {
        context.claimed_account = Some(account);
        assert!(context.validate().is_err());
    }
    let mut input = denial("alice", "host-journal", 1);
    input.subject = "<claimed&account>".into();
    assert!(
        input.validate(NOW).is_err(),
        "Generic compact labels must not expand"
    );
}

#[test]
fn exact_claim_survives_archive_restart_and_is_escaped_in_event_details() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("claim.db");
    let account = "<claimed&account>";
    let mut engine = Engine::open(&path).unwrap();
    engine.configure_mode(false).unwrap();
    for count in 1..=8 {
        engine
            .ingest(&[denial(account, "host-journal", count)], NOW)
            .unwrap();
    }
    engine.flush(NOW).unwrap();
    let finding = engine.findings().unwrap().remove(0);
    let evidence_id = finding.evidence[0].event.id;
    let preserved = serde_json::to_value(&finding.evidence).unwrap();
    drop(engine);
    let engine = Engine::open(&path).unwrap();
    assert_eq!(
        serde_json::to_value(&engine.findings().unwrap()[0].evidence).unwrap(),
        preserved
    );
    let event = engine.reconstruct(evidence_id).unwrap();
    let context = event.context.as_ref().unwrap();
    assert_eq!(context.claimed_account.as_deref(), Some(account));
    assert_eq!(context.uid, Some(0));
    assert_eq!(context.pid, Some(50));
    assert_eq!(context.journal_cursor, "s=identity;i=1");
    assert!(!serde_json::to_string(&event)
        .unwrap()
        .contains("Failed password"));
    let mut html = String::new();
    crate::render_ops::event_controls(
        &mut html,
        &engine.snapshot().unwrap(),
        &event,
        "fixture-csrf",
    );
    assert!(html.contains("Claimed account (not reporter UID)"));
    assert!(html.contains("&lt;claimed&amp;account&gt;"));
    assert!(!html.contains(account));
}
