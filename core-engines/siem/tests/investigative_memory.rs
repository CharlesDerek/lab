use athernex_siem::{
    engine::Engine,
    memory::{MemoryConfig, DAY},
    model::*,
};
const NOW: u64 = 1_800_000_000_000;
fn event(n: u64, time: u64, severity: u8) -> InputEvent {
    InputEvent {
        time_ms: time,
        source: "endpoint-a".into(),
        subject: "alice".into(),
        object: "203.0.113.42".into(),
        kind: Kind::Network,
        outcome: Outcome::Observe,
        severity,
        bytes: 4096,
        trace: 7,
        idempotency_key: format!("occurrence-{n}"),
        context: Some(EventContext {
            host: "workstation-a".into(),
            program: "curl".into(),
            pid: Some(7),
            parent_pid: Some(6),
            process_start_ms: Some(NOW - 1000),
            parent_start_ms: Some(NOW - 2000),
            uid: Some(1000),
            summary: "Outbound TLS connection to a documentation address".into(),
            journal_cursor: format!("cursor-{n}"),
        }),
    }
}
#[test]
fn full_lifecycle_offline_history_promotes_then_expires_without_changing_age() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.db");
    let mut e = Engine::open(&path).unwrap();
    let old = event(1, NOW, 1);
    e.ingest(std::slice::from_ref(&old), NOW).unwrap();
    let id = e.events().unwrap()[0].event.id;
    let hash = e.evidence_hash(id).unwrap();
    assert_eq!(e.memory_state().unwrap().hot_events, 1);
    e.tick(NOW + 2 * DAY - 1).unwrap();
    assert_eq!(e.events().unwrap().len(), 1);
    e.tick(NOW + 2 * DAY).unwrap();
    assert!(e.events().unwrap().is_empty());
    assert_eq!(e.evidence_hash(id).unwrap(), hash);
    assert_eq!(e.reconstruct(id).unwrap().context, old.context);
    drop(e); // Endpoint is absent: reconstruction uses only the central ledger.
    let mut e = Engine::open(&path).unwrap();
    assert!(e.events().unwrap().is_empty());
    e.ingest(&[event(2, NOW + 5 * DAY, 5)], NOW + 5 * DAY)
        .unwrap();
    let state = e.memory_state().unwrap();
    assert_eq!(state.references, 2);
    assert_eq!(state.hot_events, 1);
    let historical = state
        .context
        .iter()
        .find(|c| c.evidence.event.id == id)
        .unwrap();
    assert_eq!(historical.evidence.event.time_ms, NOW);
    assert_eq!(historical.evidence.event.observed_ms, NOW);
    assert!(historical.relevance.score >= state.config.promotion_score);
    assert!(historical
        .relevance
        .reasons
        .iter()
        .any(|r| r.contains("identity:alice")));
    assert_eq!(
        historical.relevance.path.first(),
        Some(&historical.relevance.trigger_id)
    );
    assert!(state
        .context
        .iter()
        .any(|c| c.evidence.event.time_ms == NOW + 5 * DAY));
    assert!(e
        .retrieval_audits()
        .unwrap()
        .iter()
        .any(|a| a["outcome"] == "verified"));
    e.tick(NOW + 5 * DAY + state.config.context_ms).unwrap();
    assert!(e.memory_state().unwrap().context.is_empty());
    assert_eq!(e.reconstruct(id).unwrap().event.time_ms, NOW);
}
#[test]
fn descriptions_deduplicate_but_occurrences_and_cursors_remain_distinct() {
    let mut e = Engine::memory().unwrap();
    e.ingest(&[event(1, NOW, 1), event(2, NOW + 1, 1)], NOW + 1)
        .unwrap();
    let events = e.events().unwrap();
    let state = e.memory_state().unwrap();
    assert_eq!(state.references, 2);
    assert_eq!(state.objects, 4); // description + template + two occurrences
    assert_ne!(
        e.evidence_hash(events[0].event.id).unwrap(),
        e.evidence_hash(events[1].event.id).unwrap()
    );
    for original in events {
        let restored = e.reconstruct(original.event.id).unwrap();
        assert_eq!(restored.event, original.event);
        assert_eq!(restored.context, original.context);
    }
}
#[test]
fn retention_is_configurable_and_late_telemetry_never_gets_a_fresh_hot_age() {
    let mut e = Engine::memory().unwrap();
    e.configure_memory(
        MemoryConfig {
            hot_ms: 3_600_000,
            ..Default::default()
        },
        NOW,
    )
    .unwrap();
    e.ingest(&[event(1, NOW, 1)], NOW).unwrap();
    e.tick(NOW + 3_600_000).unwrap();
    assert!(e.events().unwrap().is_empty());
    e.ingest(&[event(2, NOW - 5 * DAY, 1)], NOW + 3_600_000)
        .unwrap();
    assert!(e.events().unwrap().is_empty());
    assert_eq!(e.memory_state().unwrap().references, 2);
    e.tick(NOW).unwrap();
    assert!(e.events().unwrap().is_empty()); // clock rollback
}
#[test]
fn volume_bounds_hot_memory_and_investigation_cache() {
    let mut e = Engine::memory().unwrap();
    let config = MemoryConfig {
        hot_events: 3,
        hot_bytes: 2048,
        context_events: 2,
        context_bytes: 4096,
        fan_out: 4,
        max_candidates: 5,
        ..Default::default()
    };
    e.configure_memory(config.clone(), NOW).unwrap();
    for n in 0..40 {
        e.ingest(
            &[event(n, NOW + n, if n % 10 == 0 { 5 } else { 1 })],
            NOW + n,
        )
        .unwrap();
    }
    let state = e.memory_state().unwrap();
    assert_eq!(state.references, 40);
    assert!(state.hot_events <= 3);
    assert!(state.hot_bytes <= config.hot_bytes as u64);
    assert!(state.context.len() <= 2);
    assert!(state.context_bytes <= config.context_bytes as u64);
    assert!(state
        .context
        .iter()
        .all(|c| c.relevance.path.len() <= config.max_depth + 1));
}
#[test]
fn durable_idempotency_survives_demotion_and_restart_before_archive_flush() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut e = Engine::open(&path).unwrap();
    let input = event(1, NOW, 1);
    e.ingest(std::slice::from_ref(&input), NOW).unwrap();
    drop(e);
    let mut e = Engine::open(&path).unwrap();
    assert_eq!(e.events().unwrap().len(), 1);
    e.tick(NOW + 3 * DAY).unwrap();
    assert_eq!(
        e.ingest(std::slice::from_ref(&input), NOW + 3 * DAY)
            .unwrap(),
        0
    );
    let mut conflict = input;
    conflict.bytes += 1;
    assert!(e.ingest(&[conflict], NOW + 3 * DAY).is_err());
    assert_eq!(e.memory_state().unwrap().references, 1);
}
#[test]
fn immutable_evidence_rejects_mutations_and_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut e = Engine::open(&path).unwrap();
    e.ingest(&[event(1, NOW, 1)], NOW).unwrap();
    let id = e.events().unwrap()[0].event.id;
    let db = rusqlite::Connection::open(&path).unwrap();
    assert!(db
        .execute("UPDATE evidence_objects SET payload=x'00'", [])
        .is_err());
    assert!(db.execute("DELETE FROM evidence_refs", []).is_err());
    // Deliberate bypass simulates storage tampering below application authority.
    db.execute_batch(
        "DROP TRIGGER immutable_object_update;UPDATE evidence_objects SET payload=x'00';",
    )
    .unwrap();
    assert!(e.reconstruct(id).is_err());
}
#[test]
fn remote_bundle_cannot_supply_its_own_trust_anchor() {
    let mut e = Engine::memory().unwrap();
    e.ingest(&[event(1, NOW, 1)], NOW).unwrap();
    let id = e.events().unwrap()[0].event.id;
    let bundle = e.evidence_bundle(id).unwrap();
    assert!(e.accept_evidence_bundle(id, &bundle).is_ok());
    for index in 0..3 {
        let mut corrupt = bundle.clone();
        corrupt[index][0] ^= 1;
        assert!(e.accept_evidence_bundle(id, &corrupt).is_err());
    }
    assert!(e.accept_evidence_bundle(id + 1, &bundle).is_err());
    assert!(e.accept_evidence_bundle(id, &bundle[..2]).is_err());
}
#[test]
fn unrelated_events_do_not_promote_history_and_depth_is_bounded() {
    let mut e = Engine::memory().unwrap();
    e.ingest(&[event(1, NOW, 1)], NOW).unwrap();
    e.tick(NOW + 3 * DAY).unwrap();
    let mut other = event(2, NOW + 3 * DAY, 5);
    other.subject = "bob".into();
    other.source = "endpoint-b".into();
    other.object = "198.51.100.4".into();
    other.trace = 0;
    other.context = None;
    e.ingest(&[other], NOW + 3 * DAY).unwrap();
    assert_eq!(e.memory_state().unwrap().context.len(), 1);
}
#[test]
fn process_tree_and_historical_fanout_reservation_find_old_evidence() {
    let mut e = Engine::memory().unwrap();
    let old = event(1, NOW, 1);
    e.ingest(&[old], NOW).unwrap();
    let id = e.events().unwrap()[0].event.id;
    for n in 2..50 {
        let mut input = event(n, NOW + 3 * DAY, 1);
        input.subject = "noise".into();
        input.trace = 0;
        input.context = None;
        e.ingest(&[input], NOW + 3 * DAY).unwrap();
    }
    let mut child = event(100, NOW + 3 * DAY, 5);
    child.subject = "child-user".into();
    child.context.as_mut().unwrap().parent_pid = Some(7);
    child.context.as_mut().unwrap().parent_start_ms = Some(NOW - 1000);
    e.ingest(&[child], NOW + 3 * DAY).unwrap();
    let state = e.memory_state().unwrap();
    let found = state
        .context
        .iter()
        .find(|c| c.evidence.event.id == id)
        .unwrap();
    assert!(found
        .relevance
        .reasons
        .iter()
        .any(|r| r.contains("process:")));
}
#[test]
fn failed_ingest_rolls_back_evidence_graph_and_hot_rows() {
    let mut e = Engine::memory().unwrap();
    let a = event(1, NOW, 1);
    let mut b = a.clone();
    b.bytes += 1;
    assert!(e.ingest(&[a, b], NOW).is_err());
    let s = e.memory_state().unwrap();
    assert_eq!(s.references, 0);
    assert_eq!(s.graph_links, 0);
    assert_eq!(s.objects, 0);
    assert_eq!(s.hot_events, 0);
}

#[test]
fn rule_findings_recompute_history_even_when_individual_events_have_low_severity() {
    let mut e = Engine::memory().unwrap();
    e.ingest(&[event(1, NOW, 1)], NOW).unwrap();
    let id = e.events().unwrap()[0].event.id;
    e.tick(NOW + 4 * DAY).unwrap();
    let inputs = (2..10)
        .map(|n| {
            let mut input = event(n, NOW + 4 * DAY + n, 3);
            input.kind = Kind::Authentication;
            input.outcome = Outcome::Deny;
            input
        })
        .collect::<Vec<_>>();
    e.ingest(&inputs, NOW + 4 * DAY + 10).unwrap();
    assert!(e.findings().unwrap().iter().any(|f| f.rule == "AX-001"));
    let state = e.memory_state().unwrap();
    let historical = state
        .context
        .iter()
        .find(|c| c.evidence.event.id == id)
        .unwrap();
    assert!(historical
        .relevance
        .reasons
        .iter()
        .any(|r| r.contains("new detection severity 4")));
}
#[test]
fn history_search_is_keyset_paginated_and_memory_configuration_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.db");
    let mut e = Engine::open(&path).unwrap();
    e.configure_memory(
        MemoryConfig {
            hot_ms: 7_200_000,
            fan_out: 8,
            ..Default::default()
        },
        NOW,
    )
    .unwrap();
    for n in 0..10 {
        e.ingest(&[event(n, NOW + n, 1)], NOW + 10).unwrap();
    }
    e.tick(NOW + 3 * DAY).unwrap();
    drop(e);
    let e = Engine::open(&path).unwrap();
    assert_eq!(e.memory_config().unwrap().hot_ms, 7_200_000);
    let first = e
        .search_history("identity:alice", i64::MAX as u64, i64::MAX as u64, 3)
        .unwrap();
    assert_eq!(first.len(), 3);
    let last = first.last().unwrap();
    let next = e
        .search_history("identity:alice", last.time_ms, last.id, 3)
        .unwrap();
    assert_eq!(next.len(), 3);
    assert!(first.iter().all(|a| next.iter().all(|b| a.id != b.id)));
    assert!(e.events().unwrap().is_empty());
}
#[test]
fn persistent_evidence_failure_backpressures_the_entire_batch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("full.db");
    let mut e = Engine::open(&path).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER injected_full BEFORE INSERT ON evidence_refs BEGIN SELECT RAISE(ABORT,'disk full fixture'); END;").unwrap();
    assert!(e.ingest(&[event(1, NOW, 1)], NOW).is_err());
    let state = e.memory_state().unwrap();
    assert_eq!(state.references, 0);
    assert_eq!(state.objects, 0);
    assert_eq!(state.hot_events, 0);
    assert_eq!(e.snapshot().unwrap().total_received, 0);
    db.execute_batch("DROP TRIGGER injected_full").unwrap();
    assert_eq!(e.ingest(&[event(1, NOW, 1)], NOW).unwrap(), 1);
}
#[test]
fn newest_trigger_stays_in_a_small_context_under_high_fanout() {
    let mut e = Engine::memory().unwrap();
    e.configure_memory(
        MemoryConfig {
            context_events: 2,
            ..Default::default()
        },
        NOW,
    )
    .unwrap();
    for n in 0..10 {
        e.ingest(&[event(n, NOW + n, 1)], NOW + 10).unwrap();
    }
    e.tick(NOW + 5 * DAY).unwrap();
    e.ingest(&[event(11, NOW + 5 * DAY, 5)], NOW + 5 * DAY)
        .unwrap();
    let state = e.memory_state().unwrap();
    assert_eq!(state.context.len(), 2);
    assert!(state
        .context
        .iter()
        .any(|c| c.evidence.event.time_ms == NOW + 5 * DAY));
    assert!(state
        .context
        .iter()
        .any(|c| c.evidence.event.time_ms < NOW + DAY));
}
