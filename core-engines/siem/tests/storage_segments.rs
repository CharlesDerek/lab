use athernex_siem::{engine::Engine, memory::DAY, model::*, storage::StorageConfig};
const NOW: u64 = 1_800_000_000_000;
fn event(n: u64) -> InputEvent {
    InputEvent {
        time_ms: NOW + n,
        source: "fixture".into(),
        subject: "alice".into(),
        object: "fixture-object".into(),
        kind: Kind::System,
        outcome: Outcome::Observe,
        severity: 1,
        bytes: 0,
        trace: 0,
        idempotency_key: format!("event-{n}"),
        context: None,
    }
}
#[test]
fn sealed_history_survives_restart_dedup_and_correlation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let event_id;
    {
        let mut e = Engine::open(&path).unwrap();
        e.configure_mode(false).unwrap();
        e.ingest(&[event(0)], NOW).unwrap();
        event_id = e.events().unwrap()[0].event.id;
        e.tick(NOW + 3 * DAY).unwrap();
        assert!(e.events().unwrap().is_empty());
        assert_eq!(e.seal_evidence(NOW + 3 * DAY).unwrap(), Some(1));
        assert_eq!(e.reconstruct(event_id).unwrap().subject_label, "alice");
        assert_eq!(e.ingest(&[event(0)], NOW + 3 * DAY).unwrap(), 0);
    }
    let mut e = Engine::open(&path).unwrap();
    assert_eq!(e.reconstruct(event_id).unwrap().subject_label, "alice");
    let history = e
        .search_history("identity:alice", i64::MAX as u64, i64::MAX as u64, 32)
        .unwrap();
    assert_eq!(history.len(), 1);
    let mut trigger = event(1);
    trigger.time_ms = NOW + 5 * DAY;
    trigger.severity = 5;
    e.ingest(&[trigger], NOW + 5 * DAY).unwrap();
    assert!(e
        .memory_state()
        .unwrap()
        .context
        .iter()
        .any(|c| c.evidence.event.id == event_id));
    assert_eq!(e.ingest(&[event(0)], NOW + 5 * DAY).unwrap(), 0);
}
#[test]
fn segment_corruption_fails_closed_at_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let segment;
    {
        let mut e = Engine::open(&path).unwrap();
        e.ingest(&[event(0)], NOW).unwrap();
        e.tick(NOW + 3 * DAY).unwrap();
        e.seal_evidence(NOW + 3 * DAY).unwrap();
        segment = e.segment_path(1).unwrap();
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(segment)
        .unwrap();
    file.write_all(b"corruption").unwrap();
    assert!(Engine::open(&path).is_err());
}

#[test]
fn complete_backup_verifies_and_restores_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(&dir.path().join("original.db")).unwrap();
    e.ingest(&[event(0)], NOW).unwrap();
    e.tick(NOW + 3 * DAY).unwrap();
    e.seal_evidence(NOW + 3 * DAY).unwrap();
    let destination = dir.path().join("backup");
    e.backup_to(&destination, NOW + 3 * DAY).unwrap();
    assert_eq!(
        athernex_siem::storage::verify_backup(&destination).unwrap(),
        2
    );
    let restored = Engine::open(&destination.join("ledger.sqlite3")).unwrap();
    assert_eq!(restored.reconstruct(1).unwrap().subject_label, "alice");
    assert!(e.backup_to(&destination, NOW).is_err());
}
#[test]
fn low_disk_and_segment_limits_backpressure_without_acknowledging() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut e = Engine::open(&path).unwrap();
    e.configure_storage(
        StorageConfig {
            ledger_mib: 64,
            segment_limit: 1,
            segment_records: 64,
            minimum_free_mib: 0,
        },
        NOW,
    )
    .unwrap();
    e.ingest(&[event(0)], NOW).unwrap();
    e.tick(NOW + 3 * DAY).unwrap();
    e.seal_evidence(NOW + 3 * DAY).unwrap();
    let next: Vec<_> = (1..=64)
        .map(|n| {
            let mut row = event(n);
            row.time_ms = NOW + 3 * DAY;
            row
        })
        .collect();
    e.ingest(&next, NOW + 3 * DAY).unwrap();
    e.tick(NOW + 6 * DAY).unwrap();
    assert!(!e.storage_state().unwrap().admission_ready);
    assert!(e.ingest(&[event(65)], NOW + 6 * DAY).is_err());
    assert!(e.seal_evidence(NOW + 6 * DAY).is_err());
    assert_eq!(e.segments().unwrap().len(), 1);
    assert_eq!(e.reconstruct(1).unwrap().subject_label, "alice");
}

#[test]
fn high_cardinality_labels_recycle_without_changing_historical_facts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger.db");
    let mut e = Engine::open(&path).unwrap();
    for batch in 0..24 {
        let rows: Vec<_> = (batch * 256..(batch + 1) * 256)
            .map(|n| {
                let mut row = event(n);
                row.source = format!("source-{n}");
                row.subject = format!("subject-{n}");
                row.object = format!("object-{n}");
                row
            })
            .collect();
        assert_eq!(e.ingest(&rows, NOW + 6144).unwrap(), 256);
    }
    assert!(e.snapshot().unwrap().dictionary_entries <= MAX_LABELS);
    assert_eq!(e.reconstruct(1).unwrap().source_label, "source-0");
    assert_eq!(e.reconstruct(6144).unwrap().subject_label, "subject-6143");
    drop(e);
    let e = Engine::open(&path).unwrap();
    assert_eq!(e.reconstruct(1).unwrap().object_label, "object-0");
    assert_eq!(e.reconstruct(6144).unwrap().source_label, "source-6143");
}
