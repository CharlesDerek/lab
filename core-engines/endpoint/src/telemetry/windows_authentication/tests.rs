use super::*;
fn batch(sequence: u64) -> Batch {
    let xml = format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/><EventID>4625</EventID><Version>0</Version><TimeCreated SystemTime="2026-01-02T03:04:05.123456700Z"/><EventRecordID>{sequence}</EventRecordID><Channel>Security</Channel><Computer>fixture.invalid</Computer></System><EventData><Data Name="TargetUserSid">S-1-0-0</Data><Data Name="ProcessId">0x0</Data><Data Name="ProcessName">-</Data><Data Name="IpAddress">-</Data><Data Name="IpPort">0</Data><Data Name="TargetUserName">fixture</Data><Data Name="TargetDomainName">EXAMPLE</Data><Data Name="LogonType">3</Data><Data Name="LogonProcessName">NtLmSsp</Data><Data Name="AuthenticationPackageName">NTLM</Data><Data Name="Status">0xc000006d</Data><Data Name="SubStatus">0xc000006a</Data></EventData></Event>"#
    );
    let event = protocol::windows_authentication::from_xml(&xml)
        .unwrap()
        .unwrap();
    Batch {
        checkpoint: Checkpoint {
            bookmark: format!("fixture-{sequence}"),
            anchor_sha256: protocol::hash(xml.as_bytes()),
            record_id: sequence,
            log_created_filetime: 116_444_736_000_000_001,
            policy_healthy: true,
            cursor_missing: false,
        },
        received_records: 1,
        caught_up: true,
        last_record_ms: event.time_ms,
        events: vec![event],
        ..Default::default()
    }
}
fn status() -> AuthenticationHealth {
    AuthenticationHealth {
        state: "active".into(),
        started_ms: now_ms(),
        ..Default::default()
    }
}
#[test]
fn backpressure_preserves_the_exact_cursor_and_resumes_without_dropping_authentication() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    let pending = batch(2);
    set_metadata(
        &store,
        "windows_authentication_checkpoint",
        &batch(1).checkpoint,
    )
    .unwrap();
    store.connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<8192) INSERT INTO telemetry_pending SELECT printf('%064x',x),'{}' FROM n; WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<3072) INSERT INTO outbox SELECT printf('%064x',x),'{}' FROM n;").unwrap();
    assert!(!persist(&store, &mut h, &pending).unwrap());
    assert!(h.backpressure);
    assert_eq!(h.received_records, 0);
    assert_eq!(
        metadata::<Checkpoint>(&store, "windows_authentication_checkpoint")
            .unwrap()
            .unwrap()
            .bookmark,
        "fixture-1"
    );
    store
        .connection
        .execute(
            "DELETE FROM telemetry_pending WHERE rowid=(SELECT min(rowid) FROM telemetry_pending)",
            [],
        )
        .unwrap();
    assert!(persist(&store, &mut h, &pending).unwrap());
    assert!(!h.backpressure);
    assert_eq!(h.authentication_events, 1);
    assert_eq!(
        metadata::<Checkpoint>(&store, "windows_authentication_checkpoint")
            .unwrap()
            .unwrap()
            .bookmark,
        "fixture-2"
    );
    let raw: String = store
        .connection
        .query_row(
            "SELECT payload FROM telemetry_pending WHERE id=?1",
            [pending.events[0].event_id()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        raw,
        serde_json::to_string(&envelope(&pending.events[0])).unwrap()
    );
}
#[test]
fn failed_cursor_commit_rolls_back_every_event_and_health_counter() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    let pending = batch(2);
    set_metadata(
        &store,
        "windows_authentication_checkpoint",
        &batch(1).checkpoint,
    )
    .unwrap();
    store.connection.execute_batch("CREATE TRIGGER fail_auth_cursor BEFORE INSERT ON telemetry_metadata WHEN NEW.key='windows_authentication_checkpoint' BEGIN SELECT RAISE(ABORT,'injected cursor failure'); END;").unwrap();
    assert!(persist(&store, &mut h, &pending).is_err());
    assert_eq!(h.authentication_events, 0);
    let count: u64 = store
        .connection
        .query_row(
            "SELECT (SELECT count(*) FROM outbox)+(SELECT count(*) FROM telemetry_pending)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        metadata::<Checkpoint>(&store, "windows_authentication_checkpoint")
            .unwrap()
            .unwrap()
            .bookmark,
        "fixture-1"
    );
    store
        .connection
        .execute_batch("DROP TRIGGER fail_auth_cursor")
        .unwrap();
    assert!(persist(&store, &mut h, &pending).unwrap());
    drop(store);
    let reopened = Store::open(temp.path()).unwrap();
    assert!(!health(&reopened).unwrap().unwrap().healthy(now_ms()));
    let raw: String = reopened
        .connection
        .query_row(
            "SELECT payload FROM outbox WHERE id=?1",
            [pending.events[0].event_id()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        raw,
        serde_json::to_string(&envelope(&pending.events[0])).unwrap()
    );
}
#[test]
fn source_policy_loss_and_unsupported_reports_remain_visible_after_a_healthy_read() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    let mut bad = batch(1);
    bad.loss_signals = 1;
    bad.rejected_records = 1;
    bad.events.clear();
    assert!(persist(&store, &mut h, &bad).unwrap());
    assert!(!h.healthy(now_ms()));
    assert!(persist(&store, &mut h, &batch(2)).unwrap());
    assert_eq!(h.loss_signals, 1);
    assert_eq!(h.rejected_records, 1);
    assert!(!h.healthy(now_ms()));
}

#[test]
fn partial_or_corrupt_resume_state_cannot_clear_collection_history() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    assert!(persist(&store, &mut h, &batch(1)).unwrap());
    store
        .connection
        .execute(
            "DELETE FROM telemetry_metadata WHERE key='windows_authentication_health'",
            [],
        )
        .unwrap();
    assert!(load_state(&store).is_err());
    set_metadata(&store, "windows_authentication_health", &h).unwrap();
    store
        .connection
        .execute(
            "DELETE FROM telemetry_metadata WHERE key='windows_authentication_checkpoint'",
            [],
        )
        .unwrap();
    assert!(load_state(&store).is_err());
    let mut bad = batch(1).checkpoint;
    bad.anchor_sha256 = "invalid".into();
    set_metadata(&store, "windows_authentication_checkpoint", &bad).unwrap();
    assert!(load_state(&store).is_err());
    set_metadata(
        &store,
        "windows_authentication_checkpoint",
        &batch(1).checkpoint,
    )
    .unwrap();
    let (recovered, _) = load_state(&store).unwrap();
    assert_eq!(recovered.authentication_events, 1);
}

#[test]
fn replay_accepts_only_identical_queued_originals() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    let pending = batch(1);
    assert!(persist(&store, &mut h, &pending).unwrap());
    assert!(persist(&store, &mut h, &pending).unwrap());
    let count: u64 = store
        .connection
        .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    store
        .connection
        .execute(
            "UPDATE outbox SET payload='{}' WHERE id=?1",
            [pending.events[0].event_id()],
        )
        .unwrap();
    assert!(persist(&store, &mut h, &pending).is_err());
    assert_eq!(h.authentication_events, 2);
}
#[test]
fn unknown_source_policy_and_backlog_cannot_report_healthy() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    let mut pending = batch(1);
    pending.source_error = "Audit policy inspection is unavailable".into();
    pending.checkpoint.policy_healthy = false;
    pending.loss_signals = 1;
    assert!(persist(&store, &mut h, &pending).unwrap());
    assert!(!h.healthy(now_ms()));
    assert!(persist(&store, &mut h, &batch(2)).unwrap());
    assert!(!h.healthy(now_ms()));
    assert_eq!(h.loss_signals, 1);
}
