//! Native PAM-stack outcomes are distinct from individual module reports.
use super::{
    native_test::{queued, until},
    *,
};
use athernex_siem::{engine::Engine, model::Outcome};
use std::process::{Command, Stdio};

fn stack(mode: &str) {
    assert_eq!(
        std::env::var("ATHERNEX_AUTH_FIXTURE").as_deref(),
        Ok("private-container")
    );
    assert!(Command::new("/usr/bin/python3")
        .args(["/fixture/pam-stack.py", mode])
        .status()
        .unwrap()
        .success());
}
fn attempt(allowed: bool) {
    let output = Command::new("/usr/bin/ssh")
        .env("SSH_ASKPASS", "/fixture/askpass")
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "private-fixture")
        .args([
            "-F",
            "/dev/null",
            "-p",
            "2223",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "fixture@127.0.0.1",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        allowed,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
const FILLER: &str = "Controlled native queue capacity filler";
fn fill_queues(store: &Store) {
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )
    .unwrap();
    for (table, limit) in [("telemetry_pending", 8192), ("outbox", 3072)] {
        let count: usize = tx
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        let mut insert = tx
            .prepare(&format!("INSERT INTO {table} VALUES(?1,?2)"))
            .unwrap();
        for index in count..limit {
            let event = EndpointEvent {
                id: protocol::hash(format!("{table}-filler-{index}").as_bytes()),
                time_ms: now_ms(),
                kind: "inventory".into(),
                path: String::new(),
                sha256: String::new(),
                detection: String::new(),
                detail: FILLER.into(),
                telemetry: None,
            };
            insert
                .execute(rusqlite::params![
                    event.id,
                    serde_json::to_string(&event).unwrap()
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
}

#[test]
#[ignore = "Requires private native SSH/PAM/journald fixture, root and libsystemd >= 254"]
fn native_pam_preserves_module_scope_and_resumes_after_full_queue_restart() {
    stack("deny");
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("endpoint");
    let db = state.join("endpoint.sqlite3");
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    fill_queues(&store);
    attempt(false);
    until(|| health(&store).unwrap().unwrap().backpressure);
    let checkpoint: Checkpoint = metadata(&store, "authentication_checkpoint")
        .unwrap()
        .unwrap();
    assert!(queued(&db).is_empty());
    assert_eq!(health(&store).unwrap().unwrap().authentication_events, 0);
    drop(collector);
    drop(store);
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().backpressure);
    assert!(queued(&db).is_empty());
    assert_eq!(
        serde_json::to_value(
            metadata::<Checkpoint>(&store, "authentication_checkpoint")
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(checkpoint).unwrap()
    );
    // Release a small amount of controlled capacity, leaving older queued
    // observations intact; both real reports must be admitted exactly once.
    store.connection.execute("DELETE FROM telemetry_pending WHERE rowid IN (SELECT rowid FROM telemetry_pending ORDER BY rowid LIMIT 16)", []).unwrap();
    until(|| queued(&db).len() == 2 && health(&store).unwrap().unwrap().healthy(now_ms()));
    let preserved = queued(&db);
    drop(collector);
    drop(store);
    let store = Store::open(&state).unwrap();
    let collector = Collector::start(&store).unwrap();
    until(|| health(&store).unwrap().unwrap().healthy(now_ms()));
    assert_eq!(
        serde_json::to_value(queued(&db)).unwrap(),
        serde_json::to_value(&preserved).unwrap()
    );
    for table in ["outbox", "telemetry_pending"] {
        store
            .connection
            .execute(
                &format!("DELETE FROM {table} WHERE json_extract(payload,'$.detail')=?1"),
                [FILLER],
            )
            .unwrap();
    }
    // A sufficient PAM module can fail before a later module accepts the same
    // login. These eight real successful logins must not form a denial burst.
    stack("fallback");
    for _ in 0..8 {
        attempt(true);
    }
    until(|| queued(&db).len() == 18 && health(&store).unwrap().unwrap().healthy(now_ms()));
    let events = queued(&db);
    assert_eq!(events.iter().filter(|event|matches!(&event.telemetry,Some(Telemetry::Authentication {event}) if event.mechanism=="pam_unix")).count(),9);
    assert_eq!(events.iter().filter(|event|matches!(&event.telemetry,Some(Telemetry::Authentication {event}) if event.outcome==protocol::authentication::AuthenticationOutcome::Allowed)).count(),8);
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
                hostname: "Native PAM stack fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            now_ms(),
        )
        .unwrap();
    engine
        .endpoint_events(&endpoint_id, &events, now_ms())
        .unwrap();
    assert!(
        !engine
            .snapshot()
            .unwrap()
            .findings
            .iter()
            .any(|f| f.rule == "AX-001"),
        "Module failures preceding successful PAM fallback must not create a denied-login burst"
    );
    for row in engine
        .endpoint_observations(&endpoint_id, i64::MAX as u64, 64)
        .unwrap()
    {
        let Some(Telemetry::Authentication { event }) = &row.event.telemetry else {
            panic!("Authentication original missing")
        };
        let normalized = engine.reconstruct(row.evidence_id).unwrap();
        if event.mechanism == "pam_unix" {
            assert_eq!(normalized.event.outcome, Outcome::Observe);
            assert!(normalized.context.unwrap().summary.contains("module"));
        }
        assert!(events
            .iter()
            .any(|expected| serde_json::to_value(expected).unwrap()
                == serde_json::to_value(&row.event).unwrap()));
    }
    println!("Verified real PAM module failure plus SSH denial, full-queue cursor retention across restart, exact admission after capacity returns, and eight successful fallback logins without a false denial burst");
    drop(collector);
}
