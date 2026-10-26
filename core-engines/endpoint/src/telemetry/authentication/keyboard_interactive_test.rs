//! A keyboard-interactive method result is distinct from PAM and partial factors.
use super::{
    certificate_test::{
        consumed, exact_contains, for_port, guard, native_row, noncompletion,
        verify_server_with_conflict,
    },
    native_test::{queued, until},
    *,
};
use athernex_siem::{
    collector,
    model::{Kind, Outcome},
};
use protocol::authentication::{pam_unix_report, supported_producer, AuthenticationOutcome};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    process::Command,
};

fn stack(mode: &str) {
    guard();
    assert!(matches!(mode, "deny" | "fallback"), "Invalid fixture stack");
    let output = Command::new("/usr/bin/python3")
        .args(["/fixture/pam-stack.py", mode])
        .output()
        .expect("Private PAM stack helper could not start");
    assert!(output.status.success(), "Private PAM stack helper failed");
}

fn attempt(mode: &str, allowed: bool) -> u16 {
    assert!(
        matches!(mode, "deny" | "fallback" | "partial"),
        "Invalid keyboard-interactive fixture mode"
    );
    let output = Command::new("/usr/bin/python3")
        .args(["/fixture/keyboard-interactive-attempt.py", mode])
        .output()
        .expect("Private keyboard-interactive helper could not start");
    assert!(
        output.status.success(),
        "Private keyboard-interactive helper failed"
    );
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Attempt {
        port: u16,
        success: bool,
    }
    let result: Attempt = serde_json::from_slice(&output.stdout)
        .expect("Private keyboard-interactive result invalid");
    assert!(
        result.port != 0 && result.success == allowed,
        "Keyboard-interactive command outcome changed"
    );
    result.port
}

fn check_reporter(row: &serde_json::Value) -> u32 {
    assert!(
        row["_EXE"].as_str().is_some_and(supported_producer) && row["_UID"].as_str() == Some("0"),
        "Native keyboard-interactive producer not trusted"
    );
    let pid = row["_PID"]
        .as_str()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid != 0)
        .expect("Native keyboard-interactive reporter missing");
    assert!(
        row["__CURSOR"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "Native keyboard-interactive cursor missing"
    );
    pid
}

fn journal_rows(arguments: &[&str]) -> Vec<serde_json::Value> {
    let output = Command::new("/usr/bin/journalctl")
        .args(["--no-pager", "--output=json"])
        .args(arguments)
        .output()
        .expect("Private keyboard-interactive journal read could not start");
    assert!(output.status.success(), "Private journal read failed");
    assert!(
        output.stdout.len() <= 4 * 1024 * 1024,
        "Private journal range exceeds bound"
    );
    let rows = std::str::from_utf8(&output.stdout)
        .expect("Private journal text invalid")
        .lines()
        .map(|line| serde_json::from_str(line).expect("Private journal row invalid"))
        .collect::<Vec<_>>();
    assert!(
        !rows.is_empty() && rows.len() <= 4096,
        "Private journal range invalid"
    );
    rows
}

fn before_attempt() -> String {
    let rows = journal_rows(&["--lines=1"]);
    assert!(rows.len() == 1, "Native journal tail is ambiguous");
    rows[0]["__CURSOR"]
        .as_str()
        .filter(|cursor| !cursor.is_empty())
        .expect("Native pre-attempt cursor missing")
        .to_owned()
}

fn module_row(before: &str, terminal: &serde_json::Value) -> serde_json::Value {
    // OpenSSH runs the keyboard-interactive PAM conversation in a child process.
    // This fixture serializes one controlled attempt between opaque journal
    // cursors; it does not infer a production PID or connection relationship.
    let rows = journal_rows(&["--cursor", before]);
    assert!(
        rows[0]["__CURSOR"].as_str() == Some(before),
        "Pre-attempt cursor was not retained"
    );
    let terminal_cursor = terminal["__CURSOR"]
        .as_str()
        .expect("Native end cursor missing");
    let end = rows
        .iter()
        .position(|row| row["__CURSOR"].as_str() == Some(terminal_cursor))
        .filter(|index| *index > 0)
        .expect("Native attempt end cursor was not reached");
    assert!(rows[end] == *terminal, "Native terminal original changed");
    let modules = rows[1..end]
        .iter()
        .filter(|row| {
            row["_EXE"].as_str().is_some_and(supported_producer)
                && row["_UID"].as_str() == Some("0")
                && row["MESSAGE"].as_str().is_some_and(|message| {
                    message.starts_with("pam_unix(sshd:auth): authentication failure;")
                })
        })
        .collect::<Vec<_>>();
    assert!(
        modules.len() == 1,
        "Controlled attempt PAM interval is ambiguous"
    );
    modules[0].clone()
}

fn terminal(
    store: &Store,
    database: &std::path::Path,
    port: u16,
    allowed: bool,
) -> serde_json::Value {
    let prefix = if allowed { "Accepted" } else { "Failed" };
    let expected =
        format!("{prefix} keyboard-interactive/pam for fixture from 127.0.0.1 port {port} ssh2");
    let native =
        native_row(|_, message| message.strip_suffix(" [preauth]").unwrap_or(message) == expected);
    let reporter = check_reporter(&native);
    consumed(store, &native);
    let events = queued(database);
    let reports = for_port(&events, port);
    assert!(
        reports.len() == 1,
        "Keyboard-interactive result count changed"
    );
    let event = reports[0];
    assert!(
        event.mechanism == "keyboard-interactive/pam"
            && event.claimed_user.as_deref() == Some("fixture")
            && !event.invalid_user
            && event.source_ip == Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
            && event.source_port == Some(port)
            && event.journal.reporter_pid == reporter
            && event.journal.reporter_uid == 0
            && event.journal.cursor == native["__CURSOR"].as_str().unwrap()
            && event.journal.message == native["MESSAGE"].as_str().unwrap()
            && event.journal.executable == native["_EXE"].as_str().unwrap(),
        "Keyboard-interactive facts differ from the controlled source"
    );
    assert!(
        event.outcome
            == if allowed {
                AuthenticationOutcome::Allowed
            } else {
                AuthenticationOutcome::Denied
            },
        "Keyboard-interactive reported outcome changed"
    );
    event.validate(now_ms()).unwrap();
    let local = collector::normalize(&native, "fixture-journal", now_ms()).unwrap();
    assert!(
        local.kind == Kind::Authentication
            && local.subject == "fixture"
            && local.object == "ssh:127.0.0.1"
            && local.outcome
                == if allowed {
                    Outcome::Allow
                } else {
                    Outcome::Deny
                },
        "Local keyboard-interactive facts changed"
    );
    native
}

fn module(store: &Store, database: &std::path::Path, before: &str, terminal: &serde_json::Value) {
    let native = module_row(before, terminal);
    let reporter = check_reporter(&native);
    consumed(store, &native);
    let events = queued(database);
    let reports = events
        .iter()
        .filter_map(|row| match &row.telemetry {
            Some(Telemetry::Authentication { event })
                if event.journal.cursor == native["__CURSOR"].as_str().unwrap() =>
            {
                Some(event)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(reports.len() == 1, "Native module result count changed");
    let event = reports[0];
    let parsed = pam_unix_report(native["MESSAGE"].as_str().unwrap())
        .unwrap()
        .expect("Native PAM report missing");
    assert!(
        parsed.claimed_user == Some("fixture")
            && parsed.source_ip == Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
            && event.mechanism == "pam_unix"
            && event.journal.reporter_pid == reporter
            && event.journal.reporter_uid == 0
            && event.source_ip == parsed.source_ip
            && event.source_port.is_none()
            && event.claimed_user.as_deref() == parsed.claimed_user
            && event.journal.message == native["MESSAGE"].as_str().unwrap()
            && event.journal.cursor == native["__CURSOR"].as_str().unwrap()
            && event.journal.executable == native["_EXE"].as_str().unwrap()
            && event.service_outcome().is_none(),
        "PAM original identity or module scope changed"
    );
    event.validate(now_ms()).unwrap();
    let local = collector::normalize(&native, "fixture-journal", now_ms()).unwrap();
    assert!(
        local.kind == Kind::Authentication
            && local.subject == "fixture"
            && local.outcome == Outcome::Observe,
        "Local PAM failure became a completed method result"
    );
}

#[test]
#[ignore = "Requires disposable keyboard-interactive SSH/PAM/journald fixture with private namespaces"]
fn native_keyboard_interactive_preserves_method_results_and_partial_scope() {
    guard();
    let temp = tempfile::tempdir_in("/fixture").unwrap();
    let state = temp.path().join("endpoint");
    let database = state.join("endpoint.sqlite3");
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    let mut ports = BTreeSet::new();
    let mut reporters = BTreeSet::new();
    stack("deny");
    let before = before_attempt();
    let denied = attempt("deny", false);
    assert!(ports.insert(denied), "Controlled source port reused");
    let row = terminal(&store, &database, denied, false);
    assert!(
        reporters.insert(check_reporter(&row)),
        "Controlled reporter reused"
    );
    module(&store, &database, &before, &row);
    stack("fallback");
    // Eight genuine module failures followed by completed successful methods
    // must not reach the service-denial burst threshold.
    for _ in 0..8 {
        let before = before_attempt();
        let port = attempt("fallback", true);
        assert!(ports.insert(port), "Controlled source port reused");
        let row = terminal(&store, &database, port, true);
        assert!(
            reporters.insert(check_reporter(&row)),
            "Controlled reporter reused"
        );
        module(&store, &database, &before, &row);
    }
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    let completed = queued(&database);
    assert!(
        completed.len() == 18,
        "Completed method/module count changed"
    );
    let before = before_attempt();
    let partial_port = attempt("partial", false);
    assert!(ports.insert(partial_port), "Controlled source port reused");
    let partial_prefix = format!(
        "Partial keyboard-interactive/pam for fixture from 127.0.0.1 port {partial_port} ssh2"
    );
    let partial = native_row(|_, message| {
        message.strip_suffix(" [preauth]").unwrap_or(message) == partial_prefix
    });
    let partial_reporter = check_reporter(&partial);
    assert!(
        reporters.insert(partial_reporter),
        "Controlled partial reporter reused"
    );
    noncompletion(&store, &partial);
    module(&store, &database, &before, &partial);
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    let preserved = queued(&database);
    assert!(
        preserved.len() == 19 && for_port(&preserved, partial_port).is_empty(),
        "Partial method was admitted as a terminal result"
    );
    exact_contains(&preserved, &completed);
    drop(collector);
    drop(store);
    // A real completed method while collection is stopped must be replayed
    // from the durable journal checkpoint, without rewriting earlier originals.
    let before = before_attempt();
    let offline_port = attempt("fallback", true);
    assert!(ports.insert(offline_port), "Controlled source port reused");
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| queued(&database).len() == 21 && health(&store).unwrap().unwrap().healthy(now_ms()));
    let row = terminal(&store, &database, offline_port, true);
    assert!(
        reporters.insert(check_reporter(&row)),
        "Controlled offline reporter reused"
    );
    module(&store, &database, &before, &row);
    let selected = queued(&database);
    exact_contains(&selected, &preserved);
    assert!(
        for_port(&selected, partial_port).is_empty(),
        "Partial replay became a result"
    );
    drop(collector);
    drop(store);
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    assert!(
        queued(&database).len() == selected.len(),
        "Restart duplicated originals"
    );
    exact_contains(&queued(&database), &selected);
    drop(collector);
    let mut changed = selected
        .iter()
        .find(|row| {
            matches!(&row.telemetry, Some(Telemetry::Authentication { event })
            if event.source_port == Some(offline_port))
        })
        .expect("Controlled offline original missing")
        .clone();
    let Some(Telemetry::Authentication { event }) = &mut changed.telemetry else {
        panic!("Authentication original missing");
    };
    assert!(
        !event.journal.message.ends_with(" [preauth]"),
        "Conflict control already has suffix"
    );
    event.journal.message.push_str(" [preauth]");
    changed.validate(now_ms()).unwrap();
    verify_server_with_conflict(temp.path(), &selected, changed);
    println!("Verified native keyboard-interactive method outcomes, PAM/partial scope, exact claimed identity, durable originals, authenticated export and replay");
}
