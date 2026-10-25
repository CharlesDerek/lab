use super::*;
use protocol::authentication::{from_journal, JournalRecord};
fn batch(sequence: u64) -> Batch {
    let record = JournalRecord {
        cursor: format!("fixture-{sequence}"),
        sequence_id: "a".repeat(32),
        sequence,
        realtime_us: now_ms() * 1000,
        machine_id: "b".repeat(32),
        boot_id: "c".repeat(32),
        executable: "/usr/sbin/sshd".into(),
        reporter_uid: 0,
        reporter_pid: 42,
        message: "Failed publickey for fixture from 127.0.0.1 port 2222 ssh2".into(),
    };
    Batch {
        checkpoint: Checkpoint {
            cursor: record.cursor.clone(),
            sequences: [(record.sequence_id.clone(), sequence)].into(),
            cursor_missing: false,
        },
        events: vec![from_journal(&record).unwrap().unwrap()],
        received_records: 1,
        caught_up: true,
        last_record_ms: record.realtime_us / 1000,
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
    set_metadata(&store, "authentication_checkpoint", &batch(1).checkpoint).unwrap();
    store.connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<8192) INSERT INTO telemetry_pending SELECT printf('%064x',x),'{}' FROM n; WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<3072) INSERT INTO outbox SELECT printf('%064x',x),'{}' FROM n;").unwrap();
    assert!(!persist(&store, &mut h, &pending).unwrap());
    assert!(h.backpressure);
    assert_eq!(h.received_records, 0);
    assert_eq!(
        metadata::<Checkpoint>(&store, "authentication_checkpoint")
            .unwrap()
            .unwrap()
            .cursor,
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
        metadata::<Checkpoint>(&store, "authentication_checkpoint")
            .unwrap()
            .unwrap()
            .cursor,
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
    set_metadata(&store, "authentication_checkpoint", &batch(1).checkpoint).unwrap();
    store.connection.execute_batch("CREATE TRIGGER fail_auth_cursor BEFORE INSERT ON telemetry_metadata WHEN NEW.key='authentication_checkpoint' BEGIN SELECT RAISE(ABORT,'injected cursor failure'); END;").unwrap();
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
        metadata::<Checkpoint>(&store, "authentication_checkpoint")
            .unwrap()
            .unwrap()
            .cursor,
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
fn journal_loss_and_unsupported_reports_remain_visible_after_a_healthy_read() {
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
fn authentication_hints_without_provenance_only_degrade_coverage() {
    assert!(missing_provenance(
        "sudo",
        "alice : 1 incorrect password attempt ; PWD=/ ; USER=root ; COMMAND=/bin/true"
    ));
    assert!(missing_provenance(
        "sshd",
        "Failed password for alice from 127.0.0.1 port 22 ssh2"
    ));
    assert!(missing_provenance(
        "su",
        "pam_unix(su:auth): authentication failure; user=alice"
    ));
    assert!(!missing_provenance(
        "logger",
        "Failed password for alice from 127.0.0.1 port 22 ssh2"
    ));
    assert!(!missing_provenance(
        "sudo",
        "alice : PWD=/ ; USER=root ; COMMAND=/bin/echo 1 incorrect password attempt"
    ));
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    let mut uncertain = batch(1);
    uncertain.events.clear();
    uncertain.rejected_records = 1;
    assert!(persist(&store, &mut h, &uncertain).unwrap());
    assert_eq!(h.authentication_events, 0);
    assert!(!h.healthy(now_ms()));
    assert_eq!(
        store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
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
            "DELETE FROM telemetry_metadata WHERE key='authentication_health'",
            [],
        )
        .unwrap();
    assert!(load_state(&store).is_err());
    set_metadata(&store, "authentication_health", &h).unwrap();
    store
        .connection
        .execute(
            "DELETE FROM telemetry_metadata WHERE key='authentication_checkpoint'",
            [],
        )
        .unwrap();
    assert!(load_state(&store).is_err());
    let mut bad = batch(1).checkpoint;
    bad.sequences.insert("invalid".into(), 1);
    set_metadata(&store, "authentication_checkpoint", &bad).unwrap();
    assert!(load_state(&store).is_err());
    set_metadata(&store, "authentication_checkpoint", &batch(1).checkpoint).unwrap();
    let (recovered, _) = load_state(&store).unwrap();
    assert_eq!(recovered.authentication_events, 1);
}
