//! Native test only: tools/verify_auth_events.py owns the private SSH/journal services.
#![cfg(target_os = "linux")]
use athernex_endpoint::private_write;
use athernex_endpoint_protocol::{
    authentication::{AuthenticationHealth, AuthenticationOutcome},
    telemetry::Telemetry,
    EndpointEvent,
};
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn attempt(allowed: bool) {
    assert_eq!(
        std::env::var("ATHERNEX_AUTH_FIXTURE").as_deref(),
        Ok("private-container")
    );
    let status = Command::new("/usr/bin/ssh")
        .args([
            "-F",
            "/dev/null",
            "-p",
            "2222",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "-i",
            if allowed {
                "/fixture/client"
            } else {
                "/fixture/wrong"
            },
            "fixture@127.0.0.1",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.success(), allowed);
}
#[test]
#[ignore = "Requires private native SSH/journald fixture, root and libsystemd >= 254"]
fn actual_agent_replays_authentication_written_while_it_was_dead_and_while_http_is_stalled() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = serde_json::json!({"server":format!("http://{}/",listener.local_addr().unwrap()),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":null,"scanner":temp.path().join("no-scanner"),"updater":temp.path().join("no-updater"),"scan_roots":[temp.path()],"allow_scripts":false,"telemetry":{"enabled":true,"interval_secs":30,"linux_authentication":true}});
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let binary = std::env::var_os("ATHERNEX_NATIVE_AUTH_AGENT")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_athernex-endpoint").into());
    let start = || {
        Process(
            Command::new(&binary)
                .arg("run")
                .arg(&state)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        )
    };
    let first = start();
    let deadline = Instant::now() + Duration::from_secs(15);
    let request = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) => panic!("Agent never reached controlled heartbeat: {error}"),
        }
    };
    let db = rusqlite::Connection::open_with_flags(
        state.join("endpoint.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(2)).unwrap();
    let records = || {
        db.prepare("SELECT payload FROM outbox UNION ALL SELECT payload FROM telemetry_pending")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| serde_json::from_str::<EndpointEvent>(&r.unwrap()).unwrap())
            .filter(|e| matches!(e.telemetry, Some(Telemetry::Authentication { .. })))
            .collect::<Vec<_>>()
    };
    attempt(false);
    let deadline = Instant::now() + Duration::from_secs(10);
    while records().len() != 1 {
        assert!(
            Instant::now() < deadline,
            "Authentication was not captured during blocked HTTP"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let before = records().remove(0);
    drop(first);
    drop(request);
    attempt(true); // The journal retains this successful authentication during the crash gap.
    let second = start();
    let deadline = Instant::now() + Duration::from_secs(15);
    let after = loop {
        let records = records();
        let raw: String = db
            .query_row(
                "SELECT value FROM telemetry_metadata WHERE key='authentication_health'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let health: AuthenticationHealth = serde_json::from_str(&raw).unwrap();
        if records.len() == 2 && health.healthy(athernex_endpoint::now_ms()) {
            break records;
        }
        assert!(
            Instant::now() < deadline,
            "Agent did not resume retained authentication without a false gap: {raw}"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(after
        .iter()
        .any(|e| serde_json::to_value(e).unwrap() == serde_json::to_value(&before).unwrap()));
    assert!(after.iter().any(|e|matches!(&e.telemetry,Some(Telemetry::Authentication {event}) if event.outcome==AuthenticationOutcome::Allowed)));
    drop(second);
    println!("Verified actual agent capture during stalled HTTP and exact recovery of a native successful login written while the agent was dead");
}
