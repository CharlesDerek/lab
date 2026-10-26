//! Native certificate results remain claimed method outcomes, not session identity.
use super::{
    native_test::{queued, until},
    *,
};
use athernex_siem::{
    collector,
    engine::Engine,
    model::{Kind, Outcome},
    web::{router, App},
};
use protocol::authentication::{ssh_report, supported_producer, AuthenticationOutcome};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, TcpListener},
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

fn guard() {
    assert!(
        std::env::var("ATHERNEX_AUTH_FIXTURE").as_deref() == Ok("private-container"),
        "Private fixture required"
    );
    assert!(
        unsafe { libc::geteuid() } == 0,
        "Private fixture identity required"
    );
    assert!(
        std::fs::read_to_string("/proc/1/comm").unwrap().trim() == "docker-init",
        "Private PID namespace required"
    );
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    for path in ["/fixture", "/run", "/etc/pam.d", "/etc/sudoers.d"] {
        assert!(
            mounts
                .lines()
                .any(|line| line.split_whitespace().nth(4) == Some(path)
                    && line.contains(" - tmpfs ")),
            "Private fixture mounts required"
        );
    }
    assert!(
        std::fs::read_dir("/sys/class/net")
            .unwrap()
            .all(|entry| entry.unwrap().file_name() == "lo"),
        "Private network namespace required"
    );
}

fn attempt(mode: &str, allowed: bool) -> u16 {
    let output = Command::new("/usr/bin/python3")
        .args(["/fixture/certificate-attempt.py", mode])
        .output()
        .unwrap();
    assert!(output.status.success(), "Certificate client fixture failed");
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Attempt {
        port: u16,
        success: bool,
    }
    let result: Attempt =
        serde_json::from_slice(&output.stdout).expect("Private certificate client result invalid");
    assert!(
        result.success == allowed && result.port != 0,
        "Native certificate command outcome mismatch"
    );
    result.port
}

fn for_port(events: &[EndpointEvent], port: u16) -> Vec<&Authentication> {
    events
        .iter()
        .filter_map(|row| match &row.telemetry {
            Some(Telemetry::Authentication { event }) if event.source_port == Some(port) => {
                Some(event)
            }
            _ => None,
        })
        .collect()
}

fn check_port(events: &[EndpointEvent], port: u16, outcomes: &[AuthenticationOutcome]) {
    let mut reports = for_port(events, port);
    reports.sort_by_key(|event| event.journal.sequence);
    assert!(
        reports.len() == outcomes.len(),
        "Unexpected certificate result count"
    );
    for (event, expected) in reports.iter().zip(outcomes) {
        assert!(
            event.outcome == *expected
                && event.claimed_user.as_deref() == Some("fixture")
                && !event.invalid_user,
            "Certificate outcome or claimed account changed"
        );
        assert!(
            event.source_ip == Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
                && event.source_port == Some(port),
            "Certificate source differs from controlled socket"
        );
        assert!(
            event.mechanism == "publickey"
                && event.journal.message.contains("ssh2: ED25519-CERT SHA256:"),
            "Certificate profile not observed"
        );
        assert!(
            supported_producer(&event.journal.executable) && event.journal.reporter_uid == 0,
            "Certificate producer identity changed"
        );
        event.validate(now_ms()).unwrap();
        let local = collector::normalize(&serde_json::json!({"__CURSOR":event.journal.cursor,"__REALTIME_TIMESTAMP":event.journal.realtime_us.to_string(),
            "_EXE":event.journal.executable,"_UID":event.journal.reporter_uid.to_string(),"_PID":event.journal.reporter_pid.to_string(),"MESSAGE":event.journal.message}), "fixture-journal", now_ms()).unwrap();
        assert!(
            local.kind == Kind::Authentication
                && local.subject == "fixture"
                && local.object == "ssh:127.0.0.1",
            "Local collector changed certificate claimed identity"
        );
        assert!(
            local.outcome
                == if *expected == AuthenticationOutcome::Allowed {
                    Outcome::Allow
                } else {
                    Outcome::Deny
                },
            "Local certificate outcome differs"
        );
    }
    if reports.len() > 1 {
        assert!(
            reports
                .iter()
                .all(|event| event.journal.reporter_pid == reports[0].journal.reporter_pid),
            "Retry results did not share the native connection reporter"
        );
    }
}

fn exact_contains(actual: &[EndpointEvent], expected: &[EndpointEvent]) {
    for row in expected {
        assert!(
            actual
                .iter()
                .any(|candidate| serde_json::to_value(candidate).unwrap()
                    == serde_json::to_value(row).unwrap()),
            "Original certificate evidence changed"
        );
    }
}

fn raw_journal() -> Vec<serde_json::Value> {
    let output = Command::new("/usr/bin/journalctl")
        .args(["--no-pager", "--output=json", "--lines=4096"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Private certificate journal read failed"
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn trusted(row: &serde_json::Value) -> bool {
    row["_EXE"].as_str().is_some_and(supported_producer) && row["_UID"].as_str() == Some("0")
}

fn native_row(predicate: impl Fn(&serde_json::Value, &str) -> bool) -> serde_json::Value {
    let mut selected = None;
    until(|| {
        selected = raw_journal().into_iter().find(|row| {
            trusted(row)
                && row["MESSAGE"]
                    .as_str()
                    .is_some_and(|message| predicate(row, message))
        });
        selected.is_some()
    });
    selected.unwrap()
}

fn consumed(store: &Store, row: &serde_json::Value) {
    let cursor = row["__CURSOR"]
        .as_str()
        .expect("Native control cursor missing");
    // Treat cursors as opaque. Ask journald to establish ordering rather than
    // interpreting its implementation-specific cursor/sequence representation.
    until(|| {
        let Some(checkpoint): Option<Checkpoint> =
            metadata(store, "authentication_checkpoint").unwrap()
        else {
            return false;
        };
        if checkpoint.cursor == cursor {
            return true;
        }
        let output = Command::new("/usr/bin/journalctl")
            .args(["--no-pager", "--output=json", "--after-cursor", cursor])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Native control cursor lookup failed"
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .any(|line| {
                let candidate: serde_json::Value = serde_json::from_str(line).unwrap();
                candidate["__CURSOR"].as_str() == Some(checkpoint.cursor.as_str())
            })
    });
}

fn noncompletion(store: &Store, row: &serde_json::Value) {
    consumed(store, row);
    assert!(
        ssh_report(row["MESSAGE"].as_str().unwrap())
            .unwrap()
            .is_none(),
        "Native noncompletion became method result"
    );
    let local = collector::normalize(row, "fixture-journal", now_ms()).unwrap();
    assert!(
        local.kind != Kind::Authentication && local.outcome == Outcome::Observe,
        "Native noncompletion became local authentication"
    );
}

#[test]
#[ignore = "Requires disposable certificate SSH/PAM/journald fixture with private namespaces"]
fn native_ssh_certificates_preserve_terminal_account_source_and_originals() {
    guard();
    let temp = tempfile::tempdir_in("/fixture").unwrap();
    let state = temp.path().join("endpoint");
    let database = state.join("endpoint.sqlite3");
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    let allowed = AuthenticationOutcome::Allowed;
    let denied = AuthenticationOutcome::Denied;
    let mut controls = Vec::new();
    let mut count = 0;
    for (mode, successful, outcomes) in [
        ("valid", true, vec![allowed]),
        ("principal", false, vec![denied]),
        ("untrusted", false, vec![denied]),
        ("expired", false, vec![denied]),
        ("retry", true, vec![denied, allowed]),
        ("delimiters", true, vec![allowed]),
    ] {
        let port = attempt(mode, successful);
        count += outcomes.len();
        until(|| {
            queued(&database).len() == count && health(&store).unwrap().unwrap().healthy(now_ms())
        });
        check_port(&queued(&database), port, &outcomes);
        controls.push((port, outcomes));
    }
    assert!(count == 7, "Controlled certificate result count changed");
    let partial_port = attempt("partial", false);
    let partial = native_row(|_, message| {
        message.starts_with("Partial publickey for fixture from 127.0.0.1 port ")
            && message.contains(&format!(" port {partial_port} "))
    });
    noncompletion(&store, &partial);
    let eligibility = native_row(|row, message| {
        row["_PID"] == partial["_PID"] && message.starts_with("Accepted certificate ID ")
    });
    noncompletion(&store, &eligibility);
    for reason in [
        "Certificate invalid: expired",
        "Certificate invalid: name is not a listed principal",
    ] {
        let row = native_row(|_, message| {
            let message = message.strip_prefix("error: ").unwrap_or(message);
            message.strip_suffix(" [preauth]").unwrap_or(message) == reason
        });
        noncompletion(&store, &row);
    }
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    let preserved = queued(&database);
    assert!(
        preserved.len() == 7 && for_port(&preserved, partial_port).is_empty(),
        "Partial certificate result was admitted"
    );
    drop(collector);
    drop(store);
    let offline_port = attempt("valid", true);
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| queued(&database).len() == 8 && health(&store).unwrap().unwrap().healthy(now_ms()));
    let selected = queued(&database);
    exact_contains(&selected, &preserved);
    check_port(&selected, offline_port, &[allowed]);
    for (port, outcomes) in &controls {
        check_port(&selected, *port, outcomes);
    }
    // The daemon may accept an opaque ID that our bounded grammar cannot
    // unambiguously partition. Preserve a visible rejection, never guess facts.
    let rejected = health(&store).unwrap().unwrap().rejected_records;
    let ambiguous_port = attempt("ambiguous", true);
    let ambiguous = native_row(|_, message| {
        message.starts_with("Accepted publickey for fixture from 127.0.0.1 port ")
            && message.contains(&format!(" port {ambiguous_port} "))
            && message.contains(" ID outer (serial 3) CA ED25519 spoof (serial ")
    });
    assert!(
        ssh_report(ambiguous["MESSAGE"].as_str().unwrap()).is_err(),
        "Ambiguous native row unexpectedly parsed"
    );
    consumed(&store, &ambiguous);
    until(|| health(&store).unwrap().unwrap().rejected_records > rejected);
    assert!(
        !health(&store).unwrap().unwrap().healthy(now_ms()),
        "Ambiguous certificate did not degrade coverage"
    );
    assert!(
        for_port(&queued(&database), ambiguous_port).is_empty(),
        "Ambiguous certificate was admitted"
    );
    assert!(
        queued(&database).len() == 8,
        "Ambiguous certificate changed durable evidence"
    );
    exact_contains(&queued(&database), &selected);
    drop(collector);
    drop(store);
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().caught_up);
    assert!(
        health(&store).unwrap().unwrap().rejected_records > rejected,
        "Certificate rejection was not durable"
    );
    assert!(
        queued(&database).len() == selected.len(),
        "Certificate restart duplicated evidence"
    );
    exact_contains(&queued(&database), &selected);
    drop(collector);
    verify_server(temp.path(), &selected);
    println!("Verified native certificate outcomes, opaque identity boundaries, partial/eligibility refusal, durable originals, authenticated export and exact replay");
}

fn verify_server(root: &std::path::Path, selected: &[EndpointEvent]) {
    let database = root.join("server.db");
    let endpoint_id = "a".repeat(64);
    let credential = "b".repeat(64);
    let engine = Engine::open(&database).unwrap();
    let token = engine
        .create_enrollment(protocol::Platform::current(), now_ms())
        .unwrap();
    engine
        .enroll_endpoint(
            &protocol::Enrollment {
                protocol: protocol::PROTOCOL,
                enrollment_token: token,
                endpoint_id: endpoint_id.clone(),
                credential: credential.clone(),
                hostname: "Disposable certificate fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    assert!(
        engine
            .endpoint_events(&endpoint_id, selected, now_ms())
            .unwrap()
            == selected.len(),
        "Certificate ingestion count differs"
    );
    assert!(
        engine
            .endpoint_events(&endpoint_id, selected, now_ms())
            .unwrap()
            == 0,
        "Certificate replay duplicated evidence"
    );
    let mut changed = selected
        .iter()
        .find(|row| {
            matches!(&row.telemetry,
        Some(Telemetry::Authentication { event }) if event.outcome == AuthenticationOutcome::Allowed
            && event.journal.message.contains(" ID fixture certificate (serial "))
        })
        .expect("Controlled certificate original missing")
        .clone();
    let Some(Telemetry::Authentication { event }) = &mut changed.telemetry else {
        panic!("Certificate original missing");
    };
    event.journal.message = event.journal.message.replacen(
        " ID fixture certificate (serial ",
        " ID changed certificate (serial ",
        1,
    );
    assert!(
        event
            .journal
            .message
            .contains(" ID changed certificate (serial "),
        "Certificate conflict fixture unchanged"
    );
    changed.validate(now_ms()).unwrap();
    assert!(
        engine
            .endpoint_events(&endpoint_id, &[changed], now_ms())
            .is_err(),
        "Conflicting certificate replay accepted"
    );
    assert!(
        !engine
            .findings()
            .unwrap()
            .iter()
            .any(|finding| finding.rule == "AX-001"),
        "Replayed certificate offers accelerated denial detection"
    );
    drop(engine);
    let engine = Engine::open(&database).unwrap();
    assert!(
        engine
            .endpoint_events(&endpoint_id, selected, now_ms())
            .unwrap()
            == 0,
        "Server restart duplicated certificate evidence"
    );
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "public-certificate-fixture".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("public-certificate-fixture-operator-32")
                .unwrap(),
        ),
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serve = app.clone();
    let task = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                axum::serve(
                    tokio::net::TcpListener::from_std(listener).unwrap(),
                    router(serve),
                )
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
            })
    });
    struct Server(
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<thread::JoinHandle<()>>,
    );
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
            let task = self.1.take().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            while !task.is_finished() {
                if std::time::Instant::now() >= deadline {
                    std::process::abort();
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(task.join().is_ok(), "Certificate server cleanup failed");
        }
    }
    let _server = Server(Some(stop), Some(task));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let export = format!("http://{address}/api/endpoints/{endpoint_id}/events");
    assert!(
        client.get(&export).send().unwrap().status() == reqwest::StatusCode::UNAUTHORIZED,
        "Anonymous certificate export succeeded"
    );
    assert!(
        client
            .get(&export)
            .bearer_auth(credential)
            .send()
            .unwrap()
            .status()
            == reqwest::StatusCode::UNAUTHORIZED,
        "Endpoint credential exported certificate evidence"
    );
    #[derive(Deserialize)]
    struct Observation {
        event: EndpointEvent,
    }
    let exported: Vec<Observation> = client
        .get(&export)
        .bearer_auth("public-certificate-fixture-operator-32")
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert!(
        exported.len() == selected.len(),
        "Certificate export count differs"
    );
    let mut actual = BTreeMap::new();
    for row in exported {
        assert!(
            actual.insert(row.event.id.clone(), row.event).is_none(),
            "Duplicate certificate export identity"
        );
    }
    assert!(
        actual.len() == selected.len(),
        "Certificate export count differs"
    );
    exact_contains(&actual.into_values().collect::<Vec<_>>(), selected);
}
