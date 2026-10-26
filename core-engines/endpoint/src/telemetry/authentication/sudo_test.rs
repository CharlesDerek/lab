//! Real sudo/PAM reports in the disposable journal fixture only.
use super::{
    native_test::{queued, until},
    *,
};
use athernex_siem::{
    collector,
    engine::Engine,
    model::{Kind, Outcome},
};
use std::process::Command;

fn attempt(mode: &str) {
    assert_eq!(
        std::env::var("ATHERNEX_AUTH_FIXTURE").as_deref(),
        Ok("private-container")
    );
    let result = Command::new("/usr/bin/python3")
        .args(["/fixture/sudo-attempt.py", mode])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "Requires private sudo/PAM/journald fixture with isolated policy and root identity helper"]
fn native_sudo_denials_preserve_module_scope_identity_and_replay() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("endpoint");
    let db = state.join("endpoint.sqlite3");
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    for _ in 0..8 {
        attempt("fallback");
    }
    until(|| queued(&db).len() == 8 && health(&store).unwrap().unwrap().healthy(now_ms()));
    let module_only = queued(&db);
    assert!(module_only.iter().all(|row| matches!(&row.telemetry, Some(Telemetry::Authentication { event }) if event.mechanism=="pam_unix" && event.service_outcome().is_none())));
    let engine = Engine::open(&temp.path().join("server.db")).unwrap();
    let endpoint_id = "a".repeat(64);
    let token = engine
        .create_enrollment(protocol::Platform::current(), now_ms())
        .unwrap();
    engine
        .enroll_endpoint(
            &protocol::Enrollment {
                protocol: protocol::PROTOCOL,
                enrollment_token: token,
                endpoint_id: endpoint_id.clone(),
                credential: "b".repeat(64),
                hostname: "Private native sudo fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    engine
        .endpoint_events(&endpoint_id, &module_only, now_ms())
        .unwrap();
    assert!(!engine
        .findings()
        .unwrap()
        .iter()
        .any(|f| f.rule == "AX-001"));
    // Authentication is not established by NOPASSWD, a permitted command, or a
    // policy refusal. Capture the following real denial while collection is down.
    drop(collector);
    drop(store);
    for mode in ["nopasswd", "arguments", "policy", "deny-two"] {
        attempt(mode);
    }
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| queued(&db).len() == 11 && health(&store).unwrap().unwrap().healthy(now_ms()));
    let mut events = queued(&db);
    assert_eq!(events.iter().filter(|r|matches!(&r.telemetry,Some(Telemetry::Authentication {event}) if event.mechanism=="sudo-password")).count(), 1);
    // The aggregate two-password failure is one completed service report; the
    // detector must wait for seven more reports, not six, before threshold eight.
    for index in 0..7 {
        engine
            .endpoint_events(&endpoint_id, &events, now_ms())
            .unwrap();
        assert!(!engine
            .findings()
            .unwrap()
            .iter()
            .any(|f| f.rule == "AX-001"));
        attempt("deny");
        until(|| {
            queued(&db).len() == 13 + index * 2
                && health(&store).unwrap().unwrap().healthy(now_ms())
        });
        events = queued(&db);
    }
    engine
        .endpoint_events(&endpoint_id, &events, now_ms())
        .unwrap();
    let findings = engine.findings().unwrap();
    let finding = findings
        .iter()
        .find(|f| f.rule == "AX-001")
        .expect("Eight sudo service reports must trigger authentication burst");
    assert_eq!(finding.evidence.len(), 8);
    let journal = Command::new("/usr/bin/journalctl")
        .args(["--no-pager", "--output=json", "_EXE=/usr/bin/sudo"])
        .output()
        .unwrap();
    assert!(journal.status.success());
    let mut saw_arguments = false;
    let mut saw_policy = false;
    for line in String::from_utf8(journal.stdout).unwrap().lines() {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        let message = record["MESSAGE"].as_str().unwrap();
        if message.contains("COMMAND=/usr/bin/printf") {
            let input = collector::normalize(&record, "fixture-journal", now_ms()).unwrap();
            assert_eq!(input.kind, Kind::Policy);
            assert_eq!(input.outcome, Outcome::Allow);
            saw_arguments = true;
        }
        if message.contains("command not allowed ;") {
            let input = collector::normalize(&record, "fixture-journal", now_ms()).unwrap();
            assert_eq!(input.kind, Kind::Policy);
            assert_eq!(input.outcome, Outcome::Deny);
            saw_policy = true;
        }
    }
    assert!(
        saw_arguments && saw_policy,
        "Native sudo control reports missing"
    );
    let observations = engine
        .endpoint_observations(&endpoint_id, i64::MAX as u64, 64)
        .unwrap();
    assert_eq!(observations.len(), 25);
    let mut nonempty_remote_user_controls = 0;
    for row in &observations {
        let Some(Telemetry::Authentication { event }) = &row.event.telemetry else {
            panic!("Missing original authentication");
        };
        event.validate(now_ms()).unwrap();
        assert_eq!(event.journal.executable, "/usr/bin/sudo");
        assert_eq!(event.claimed_user.as_deref(), Some("fixture"));
        assert!(event.source_ip.is_none() && event.source_port.is_none());
        let normalized = engine.reconstruct(row.evidence_id).unwrap();
        assert_eq!(normalized.event.kind, Kind::Authentication);
        let expected = if event.mechanism == "sudo-password" {
            Outcome::Deny
        } else {
            Outcome::Observe
        };
        assert_eq!(normalized.event.outcome, expected);
        let local=collector::normalize(&serde_json::json!({"__CURSOR":event.journal.cursor,"__REALTIME_TIMESTAMP":event.journal.realtime_us.to_string(),
            "_EXE":event.journal.executable,"_UID":event.journal.reporter_uid.to_string(),"_PID":event.journal.reporter_pid.to_string(),
            "_COMM":"sudo","MESSAGE":event.journal.message}),"fixture-journal",now_ms()).unwrap();
        assert_eq!(local.kind, Kind::Authentication);
        assert_eq!(local.outcome, expected);
        assert!(
            Some(local.subject.as_str()) == event.claimed_user.as_deref(),
            "Local sudo/PAM claimed identity differs from the endpoint user field"
        );
        if event.mechanism == "pam_unix" {
            let fields = event
                .journal
                .message
                .split_once(" authentication failure;")
                .expect("Native sudo PAM field boundary missing")
                .1
                .split_whitespace()
                .collect::<Vec<_>>();
            assert!(
                fields
                    .iter()
                    .filter_map(|field| field.strip_prefix("user="))
                    .collect::<Vec<_>>()
                    == ["fixture"],
                "Native sudo PAM user field changed"
            );
            assert!(
                fields
                    .iter()
                    .filter_map(|field| field.strip_prefix("ruser="))
                    .collect::<Vec<_>>()
                    == ["fixture"],
                "Native nonempty remote-user control missing"
            );
            assert!(
                fields.iter().position(|field| field.starts_with("ruser="))
                    < fields.iter().position(|field| field.starts_with("user=")),
                "Native sudo PAM field-order control missing"
            );
            assert!(
                event.service_outcome().is_none() && local.outcome == Outcome::Observe,
                "Native sudo PAM module report became a service result"
            );
            nonempty_remote_user_controls += 1;
        }
        assert!(events
            .iter()
            .any(|original| serde_json::to_value(original).unwrap()
                == serde_json::to_value(&row.event).unwrap()));
    }
    assert!(
        nonempty_remote_user_controls == 17,
        "Native nonempty remote-user control count changed"
    );
    drop(collector);
    drop(store);
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    assert_eq!(
        serde_json::to_value(queued(&db)).unwrap(),
        serde_json::to_value(&events).unwrap()
    );
    drop(engine);
    let engine = Engine::open(&temp.path().join("server.db")).unwrap();
    assert_eq!(
        engine
            .endpoint_events(&endpoint_id, &events, now_ms())
            .unwrap(),
        0
    );
    println!("Verified actual sudo/PAM fallback, NOPASSWD and policy boundaries, aggregate password denial, offline journal replay, exact originals and eight-report detection without module double counting");
    drop(collector);
}

#[test]
#[ignore = "Requires private sudo fixture without journald executable-inspection capability"]
fn missing_sudo_executable_provenance_is_visible_without_inventing_authentication() {
    assert_eq!(
        std::env::var("ATHERNEX_AUTH_MISSING_PROVENANCE").as_deref(),
        Ok("1")
    );
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    attempt("deny");
    until(|| health(&store).unwrap().unwrap().rejected_records > 0);
    let before = health(&store).unwrap().unwrap();
    assert!(!before.healthy(now_ms()));
    assert_eq!(before.authentication_events, 0);
    assert_eq!(before.loss_signals, 0);
    assert!(queued(&temp.path().join("endpoint.sqlite3")).is_empty());
    let journal = Command::new("/usr/bin/journalctl")
        .args(["--no-pager", "--output=json", "_COMM=sudo"])
        .output()
        .unwrap();
    assert!(journal.status.success());
    assert!(String::from_utf8(journal.stdout)
        .unwrap()
        .lines()
        .any(|line| {
            let record: serde_json::Value = serde_json::from_str(line).unwrap();
            record.get("_EXE").is_none()
                && missing_provenance("sudo", record["MESSAGE"].as_str().unwrap())
        }));
    drop(collector);
    drop(store);
    let store = Store::open(temp.path()).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().caught_up);
    let after = health(&store).unwrap().unwrap();
    assert!(after.rejected_records >= before.rejected_records);
    assert!(!after.healthy(now_ms()));
    assert_eq!(after.authentication_events, 0);
    println!("Verified real sudo records without executable provenance stay out of authentication facts and leave durable degraded coverage across restart");
    drop(collector);
}
