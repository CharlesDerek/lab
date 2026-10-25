use super::super::tests::Fixture;
use super::*;
use athernex_endpoint_native::coverage::Loss;

fn write(f: &Fixture, snapshot: &Snapshot) {
    crate::private_write(
        &f.policy.state.join(coverage::FILE),
        &serde_json::to_vec(snapshot).unwrap(),
    )
    .unwrap();
}
fn start(f: &Fixture) -> Snapshot {
    let start = Snapshot::begin(None, &f.policy, 42, 7, false, now_ms()).unwrap();
    start
        .observe(Loss::default(), true, true, now_ms())
        .unwrap()
}
fn events(store: &Store) -> Vec<EndpointEvent> {
    store
        .connection
        .prepare("SELECT payload FROM outbox ORDER BY rowid")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| serde_json::from_str(&r.unwrap()).unwrap())
        .collect()
}

#[test]
fn coverage_is_atomic_with_outbox_and_heartbeat_does_not_refill_after_ack() {
    let f = Fixture::new();
    let active = start(&f);
    // Create the table without a source, then force failure after outbox insertion.
    collect(&f.store, &f.policy.state).unwrap();
    write(&f, &active);
    f.store.connection.execute_batch("CREATE TRIGGER fail_coverage BEFORE INSERT ON native_coverage_transfer BEGIN SELECT RAISE(ABORT,'checkpoint failure'); END;").unwrap();
    assert!(collect(&f.store, &f.policy.state).is_err());
    assert!(events(&f.store).is_empty());
    f.store
        .connection
        .execute_batch("DROP TRIGGER fail_coverage")
        .unwrap();
    collect(&f.store, &f.policy.state).unwrap();
    let delivered = events(&f.store);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].kind, "inventory");
    assert!(delivered[0].sha256.is_empty());
    f.store
        .connection
        .execute("DELETE FROM outbox", [])
        .unwrap();
    let directory = f.store.directory.clone();
    let native = f.policy.state.clone();
    write(
        &f,
        &active
            .observe(Loss::default(), true, true, now_ms())
            .unwrap(),
    );
    drop(f.store);
    let reopened = Store::open(&directory).unwrap();
    collect(&reopened, &native).unwrap();
    assert!(events(&reopened).is_empty());
}

#[test]
fn full_spool_then_offline_restarts_deliver_latest_exact_totals_once() {
    let f = Fixture::new();
    let active = start(&f);
    write(&f, &active);
    collect(&f.store, &f.policy.state).unwrap();
    f.store
        .connection
        .execute_batch(
            "CREATE TRIGGER full BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'full'); END;",
        )
        .unwrap();
    let loss = active
        .observe(
            Loss {
                evidence_dropped: 3,
                event_gaps: 7,
                response_errors: 2,
            },
            true,
            true,
            now_ms(),
        )
        .unwrap();
    write(&f, &loss);
    assert!(collect(&f.store, &f.policy.state).is_err());
    let restarted = Snapshot::begin(Some(&loss), &f.policy, 43, 8, false, now_ms()).unwrap();
    let restarted = Snapshot::begin(Some(&restarted), &f.policy, 44, 9, false, now_ms()).unwrap();
    let final_state = restarted
        .observe(
            Loss {
                evidence_dropped: 2,
                ..Default::default()
            },
            true,
            true,
            now_ms(),
        )
        .unwrap();
    write(&f, &final_state);
    f.store
        .connection
        .execute_batch("DROP TRIGGER full")
        .unwrap();
    collect(&f.store, &f.policy.state).unwrap();
    collect(&f.store, &f.policy.state).unwrap();
    let events = events(&f.store);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].kind, "agent_error");
    let detail: serde_json::Value = serde_json::from_str(&events[1].detail).unwrap();
    assert_eq!(
        detail["native_authorization_coverage"],
        serde_json::to_value(&final_state.evidence).unwrap()
    );
    assert_eq!(
        detail["native_authorization_coverage"]["totals"]["evidence_dropped"],
        5
    );
    assert_eq!(
        detail["native_authorization_coverage"]["unobserved_intervals"],
        2
    );
    assert_eq!(
        fs::read(f.policy.state.join(coverage::FILE)).unwrap(),
        serde_json::to_vec(&final_state).unwrap()
    );
}

#[test]
fn missing_replaced_regressed_and_foreign_scope_are_not_silently_accepted() {
    let f = Fixture::new();
    let active = start(&f);
    write(&f, &active);
    collect(&f.store, &f.policy.state).unwrap();
    fs::remove_file(f.policy.state.join(coverage::FILE)).unwrap();
    assert!(collect(&f.store, &f.policy.state).is_err());
    let replaced = start(&f);
    write(&f, &replaced);
    assert!(collect(&f.store, &f.policy.state).is_err());
    let lost = active
        .observe(
            Loss {
                event_gaps: 3,
                ..Default::default()
            },
            true,
            true,
            now_ms(),
        )
        .unwrap();
    write(&f, &lost);
    collect(&f.store, &f.policy.state).unwrap();
    write(&f, &active);
    assert!(collect(&f.store, &f.policy.state).is_err());
    let mut changed = lost;
    changed.evidence.totals.event_gaps += 1;
    write(&f, &changed);
    assert!(collect(&f.store, &f.policy.state).is_err());
    let mut policy = f.policy.clone();
    policy.state = "/foreign/native".into();
    let foreign = Snapshot::begin(None, &policy, 42, 7, false, now_ms()).unwrap();
    crate::private_write(
        &f.policy
            .state
            .join("policies")
            .join(format!("{}.json", foreign.evidence.policy_sha256)),
        &serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    write(&f, &foreign);
    assert!(collect(&f.store, &f.policy.state).is_err());
    assert_eq!(events(&f.store).len(), 2);
}

#[test]
fn coverage_collection_does_not_require_denial_receipt_directory() {
    let f = Fixture::new();
    fs::remove_file(f.path()).unwrap();
    fs::remove_dir(f.policy.state.join("verdicts")).unwrap();
    write(&f, &start(&f));
    super::super::collect(&f.store).unwrap();
    assert_eq!(events(&f.store).len(), 1);
}
