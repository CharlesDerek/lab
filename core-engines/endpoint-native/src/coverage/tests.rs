use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn fixture() -> (tempfile::TempDir, Policy) {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().canonicalize().unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let policy = Policy {
        roots: vec!["/watched".into()],
        socket: "/scanner/clamd.sock".into(),
        state,
        scanner_uid: 1234,
        scan_timeout_ms: 1000,
    };
    fs::create_dir(policy.state.join("policies")).unwrap();
    fs::set_permissions(
        policy.state.join("policies"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    service::write(
        &policy
            .state
            .join("policies")
            .join(format!("{}.json", receipt::policy_hash(&policy).unwrap())),
        &serde_json::to_vec(&policy).unwrap(),
        0o600,
    )
    .unwrap();
    (temp, policy)
}

#[test]
fn heartbeat_preserves_revision_and_restarts_retain_cumulative_loss() {
    let (_temp, policy) = fixture();
    let start = Snapshot::begin(None, &policy, 42, 7, false, 1000).unwrap();
    let active = start.observe(Loss::default(), true, true, 1001).unwrap();
    assert!(!active.evidence.incomplete());
    let heartbeat = active.observe(Loss::default(), true, true, 1002).unwrap();
    assert_eq!(heartbeat.evidence, active.evidence);
    let loss = Loss {
        evidence_dropped: 4,
        event_gaps: 5,
        response_errors: 2,
    };
    let last = heartbeat.observe(loss, true, false, 1003).unwrap();
    let restart = Snapshot::begin(Some(&last), &policy, 42, 8, false, 1010).unwrap();
    assert_ne!(restart.evidence.session, last.evidence.session);
    assert_eq!(restart.evidence.lineage, last.evidence.lineage);
    assert_eq!(restart.evidence.unobserved_intervals, 1);
    assert_eq!(restart.evidence.totals, loss);
    assert_eq!(restart.evidence.scope_losses, 1);
    let next = restart
        .observe(
            Loss {
                evidence_dropped: 1,
                ..Default::default()
            },
            true,
            true,
            1011,
        )
        .unwrap();
    assert_eq!(next.evidence.totals.evidence_dropped, 5);
    assert_eq!(next.evidence.totals.event_gaps, 5);
    assert!(next.evidence.incomplete());
    next.evidence.follows(&last.evidence).unwrap();
}

#[test]
fn persisted_restart_marks_unknown_tail_without_inventing_lost_event_counts() {
    let (_temp, policy) = fixture();
    let start = begin(&policy, 7).unwrap();
    let saved = start
        .observe(
            Loss {
                evidence_dropped: 2,
                ..Default::default()
            },
            true,
            true,
            service::now_ms(),
        )
        .unwrap();
    saved.save(&policy.state).unwrap();
    let unpersisted = saved
        .observe(
            Loss {
                evidence_dropped: 9,
                ..Default::default()
            },
            true,
            true,
            service::now_ms(),
        )
        .unwrap();
    assert_eq!(unpersisted.evidence.totals.evidence_dropped, 9);
    let restart = begin(&policy, 8).unwrap();
    assert_eq!(restart.evidence.totals.evidence_dropped, 2);
    assert_eq!(restart.evidence.unobserved_intervals, 1);
    assert_eq!(load(&policy.state).unwrap().evidence, restart.evidence);
    // A start that never subscribed still cannot be silently discarded.
    assert_eq!(begin(&policy, 9).unwrap().evidence.unobserved_intervals, 2);
}

#[test]
fn regression_overflow_and_scope_repair_cannot_reset_history() {
    let (_temp, policy) = fixture();
    let initial = Snapshot::begin(None, &policy, 42, 7, false, 1000).unwrap();
    let lost = initial
        .observe(
            Loss {
                evidence_dropped: u64::MAX,
                ..Default::default()
            },
            true,
            false,
            1001,
        )
        .unwrap();
    assert!(lost.observe(Loss::default(), true, false, 1002).is_err());
    assert!(lost.observe(lost.sample, true, true, 1002).is_err());
    assert!(lost.observe(lost.sample, false, false, 1002).is_err());
    assert!(lost.observe(lost.sample, true, false, 999).is_err());
    let next = Snapshot::begin(Some(&lost), &policy, 43, 8, false, 1010).unwrap();
    assert!(next
        .observe(
            Loss {
                evidence_dropped: 1,
                ..Default::default()
            },
            true,
            true,
            1011
        )
        .is_err());
    let mut exhausted = next.clone();
    exhausted.evidence.revision = u64::MAX;
    assert!(Snapshot::begin(Some(&exhausted), &policy, 44, 9, false, 1020).is_err());
}

#[test]
fn coalesced_sessions_remain_monotonic_and_same_revision_is_immutable() {
    let (_temp, policy) = fixture();
    let first = Snapshot::begin(None, &policy, 42, 7, true, 1000).unwrap();
    let second = Snapshot::begin(Some(&first), &policy, 43, 8, false, 1001).unwrap();
    let third = Snapshot::begin(Some(&second), &policy, 44, 9, false, 1002).unwrap();
    third.evidence.follows(&first.evidence).unwrap();
    assert!(third.evidence.legacy_history_unknown);
    for mutation in 0..4 {
        let mut changed = third.evidence.clone();
        match mutation {
            0 => changed.lineage = "f".repeat(64),
            1 => changed.legacy_history_unknown = false,
            2 => changed.changed_ms += 1,
            _ => changed.policy_sha256 = "e".repeat(64),
        }
        assert!(changed.follows(&third.evidence).is_err());
    }
    assert!(first.evidence.follows(&third.evidence).is_err());
}

#[test]
fn live_checkpoint_requires_fresh_subscription_and_exact_policy_actor() {
    let (_temp, mut policy) = fixture();
    let first = Snapshot::begin(None, &policy, 42, 7, false, 1000).unwrap();
    assert!(first.check_live(&policy, 42, 1000).is_err());
    let active = first.observe(Loss::default(), true, true, 1001).unwrap();
    active.check_live(&policy, 42, 1001).unwrap();
    assert!(active.check_live(&policy, 43, 1001).is_err());
    assert!(active.check_live(&policy, 42, 4002).is_err());
    policy.scanner_uid += 1;
    assert!(active.check_live(&policy, 42, 1001).is_err());
}

#[test]
fn invalid_checkpoint_is_retained_and_legacy_unknown_is_sticky() {
    let (_temp, policy) = fixture();
    service::write(&policy.state.join("native-status.json"), b"{}", 0o600).unwrap();
    let legacy = begin(&policy, 7).unwrap();
    assert!(legacy.evidence.legacy_history_unknown);
    assert!(begin(&policy, 8).unwrap().evidence.legacy_history_unknown);
    fs::write(policy.state.join(FILE), b"truncated").unwrap();
    assert!(begin(&policy, 9).is_err());
    assert_eq!(fs::read(policy.state.join(FILE)).unwrap(), b"truncated");
    fs::remove_file(policy.state.join(FILE)).unwrap();
    symlink(
        policy.state.join("native-status.json"),
        policy.state.join(FILE),
    )
    .unwrap();
    assert!(begin(&policy, 9).is_err());
    assert_eq!(
        fs::read(policy.state.join("native-status.json")).unwrap(),
        b"{}"
    );
}

#[test]
fn policy_changes_retain_lineage_totals_but_foreign_state_history_is_refused() {
    let (_temp, mut policy) = fixture();
    let initial = begin(&policy, 7).unwrap();
    let lost = initial
        .observe(
            Loss {
                event_gaps: 3,
                ..Default::default()
            },
            true,
            true,
            service::now_ms(),
        )
        .unwrap();
    lost.save(&policy.state).unwrap();
    policy.roots = vec!["/different-watch".into()];
    let restarted = begin(&policy, 8).unwrap();
    assert_eq!(restarted.evidence.totals.event_gaps, 3);
    assert_ne!(
        restarted.evidence.policy_sha256,
        lost.evidence.policy_sha256
    );
    restarted.evidence.follows(&lost.evidence).unwrap();
    let mut foreign = policy.clone();
    foreign.state = "/foreign/native".into();
    let copied = Snapshot::begin(None, &foreign, 42, 7, false, service::now_ms()).unwrap();
    copied.save(&policy.state).unwrap();
    service::write(
        &policy
            .state
            .join("policies")
            .join(format!("{}.json", copied.evidence.policy_sha256)),
        &serde_json::to_vec(&foreign).unwrap(),
        0o600,
    )
    .unwrap();
    assert!(begin(&policy, 9).is_err());
    assert_eq!(load(&policy.state).unwrap().evidence, copied.evidence);
}
