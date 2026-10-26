//! Portable state controls use synthetic identities only. They do not establish
//! native code identity, OS replacement, fsync durability, or provider retirement.
use super::*;
use athernex_endpoint_protocol::installer::MacosNetworkArtifact;
use athernex_macos_network::upgrade::UpgradeCodePin;

const BOOT: &str = "11111111-2222-3333-4444-555555555555";
const NEXT_BOOT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

fn fixture() -> Record {
    let old = Deployment {
        path: crate::macos_network_bundle::INSTALL_PATH.into(),
        target: "macos-aarch64".into(),
        artifact: MacosNetworkArtifact {
            schema: 1,
            backend: "macos-network-extension".into(),
            signing: "native-signature-verified".into(),
            sha256: "a".repeat(64),
            bytes: 100,
            tree_sha256: "b".repeat(64),
            container_sha256: "c".repeat(64),
            provider_sha256: "d".repeat(64),
            source_policy_sha256: protocol::macos_network_events::source_policy_sha256(),
            team_id: "ABCDE12345".into(),
            agent_identifier: "invalid.example.agent".into(),
            container_identifier: "invalid.example.container".into(),
            provider_identifier: "invalid.example.provider".into(),
            app_group: "ABCDE12345.invalid.example.group".into(),
            mach_service_name: "ABCDE12345.invalid.example.group.telemetry".into(),
            provider_cdhashes: vec!["a".repeat(40)],
        },
    };
    let mut candidate = old.clone();
    candidate.artifact.provider_cdhashes = vec!["b".repeat(40)];
    candidate.artifact.provider_sha256 = "e".repeat(64);
    candidate.artifact.container_sha256 = "f".repeat(64);
    candidate.artifact.tree_sha256 = "1".repeat(64);
    candidate.artifact.sha256 = "2".repeat(64);
    let plan = UpgradePlan {
        mode: UpgradeMode::Submit,
        transaction_id: "3".repeat(64),
        generation: 9,
        identity: identity(&old),
        source_policy_sha256: old.artifact.source_policy_sha256.clone(),
        old: UpgradeCodePin {
            executable_sha256: old.artifact.provider_sha256.clone(),
            cdhashes: old.artifact.provider_cdhashes.clone(),
            info_plist_sha256: "4".repeat(64),
            bundle_version: "1".into(),
            short_version: "0.1".into(),
        },
        new: UpgradeCodePin {
            executable_sha256: candidate.artifact.provider_sha256.clone(),
            cdhashes: candidate.artifact.provider_cdhashes.clone(),
            info_plist_sha256: "5".repeat(64),
            bundle_version: "2.0.0".into(),
            short_version: "0.2.0".into(),
        },
        container_cdhashes: vec!["c".repeat(40)],
    };
    let record = Record {
        schema: 1,
        id: plan.transaction_id.clone(),
        state_path: "/Library/Application Support/AthernexNetwork/state.json".into(),
        original_boot: BOOT.into(),
        operator_uid: 501,
        old,
        candidate,
        original_config_sha256: "6".repeat(64),
        candidate_config_sha256: "7".repeat(64),
        management_sha256: "8".repeat(64),
        old_container_cdhashes: vec!["d".repeat(40)],
        plan,
        phase: Phase::Prepared,
        attempt: None,
        reconciliation: None,
        rollback: None,
    };
    record.validate().unwrap();
    record
}

fn owner() -> OwnerBinding {
    OwnerBinding {
        instance_nonce: "9".repeat(64),
        // Connection and listener generations are independent bindings.
        connection_generation: 12,
        operator_uid: 501,
    }
}
fn inspection(record: &Record, candidate: bool, filter: FilterState) -> Inspection {
    let pin = if candidate {
        &record.plan.new
    } else {
        &record.plan.old
    };
    Inspection {
        property: ExtensionProperty {
            url: "/Library/SystemExtensions/synthetic/invalid.example.provider.systemextension"
                .into(),
            bundle_identifier: record.plan.identity.provider_identifier.clone(),
            bundle_version: pin.bundle_version.clone(),
            bundle_short_version: pin.short_version.clone(),
            is_enabled: true,
            is_awaiting_user_approval: false,
            is_uninstalling: false,
        },
        filter,
    }
}
fn claim_with_filter(filter: FilterState) -> Record {
    let placed = fixture().candidate_placed().unwrap();
    let inspected = inspection(&placed, false, filter);
    placed
        .claim(
            BOOT,
            owner(),
            "a".repeat(64),
            "b".repeat(64),
            &placed.plan_sha256().unwrap(),
            inspected,
        )
        .unwrap()
}
fn claimed() -> Record {
    claim_with_filter(FilterState::Owned { enabled: true })
}
fn report(record: &Record, sequence: u64, outcome: UpgradeOutcome) -> Result<Record> {
    record.report(
        &owner(),
        &"a".repeat(64),
        &"b".repeat(64),
        Report { sequence, outcome },
    )
}
fn completed() -> Record {
    report(
        &report(&claimed(), 1, UpgradeOutcome::ReplacementAllowed).unwrap(),
        2,
        UpgradeOutcome::Completed,
    )
    .unwrap()
}
fn roundtrip(record: &Record) -> Record {
    let bytes = serde_json::to_vec(record).unwrap();
    assert!(bytes.len() <= MAX_RECORD_BYTES);
    let recovered: Record = serde_json::from_slice(&bytes).unwrap();
    recovered.validate().unwrap();
    recovered
}
fn same(left: &Record, right: &Record) {
    assert!(
        serde_json::to_vec(left).unwrap() == serde_json::to_vec(right).unwrap(),
        "Journal changed unexpectedly"
    );
}

#[test]
fn claim_is_single_use_and_does_not_mutate_the_unsaved_record() {
    let prepared = fixture();
    let placed = prepared.candidate_placed().unwrap();
    assert_eq!(prepared.phase, Phase::Prepared);
    assert!(prepared.attempt.is_none());
    let original = serde_json::to_vec(&placed).unwrap();
    let pending = claimed();
    assert_eq!(pending.phase, Phase::MayBePending);
    assert!(serde_json::to_vec(&placed).unwrap() == original);
    let recovered = roundtrip(&pending); // Permit may have been lost after this save.
    let mut reconnected_owner = owner();
    reconnected_owner.connection_generation += 1;
    reconnected_owner.instance_nonce = "e".repeat(64);
    for next_owner in [owner(), reconnected_owner] {
        assert!(recovered
            .claim(
                BOOT,
                next_owner,
                "c".repeat(64),
                "d".repeat(64),
                &recovered.plan_sha256().unwrap(),
                recovered.attempt.as_ref().unwrap().inspection.clone()
            )
            .is_err());
    }
    assert!(recovered.abort_before_claim().is_err());
    assert!(recovered.candidate_placed().is_err());
    assert_eq!(placed.abort_before_claim().unwrap().phase, Phase::Aborted);
}

#[test]
fn claim_binds_boot_plan_authenticated_owner_and_verified_old_metadata() {
    let placed = fixture().candidate_placed().unwrap();
    let valid = inspection(&placed, false, FilterState::Absent);
    let digest = placed.plan_sha256().unwrap();
    let attempt = |boot: &str, who: OwnerBinding, hash: &str, value: Inspection| {
        placed.claim(boot, who, "a".repeat(64), "b".repeat(64), hash, value)
    };
    assert!(attempt(NEXT_BOOT, owner(), &digest, valid.clone()).is_err());
    let mut other = owner();
    other.operator_uid += 1;
    assert!(attempt(BOOT, other, &digest, valid.clone()).is_err());
    assert!(attempt(BOOT, owner(), &"f".repeat(64), valid.clone()).is_err());
    for change in 0..5 {
        let mut bad = valid.clone();
        match change {
            0 => bad.property.bundle_version = "2.0.0".into(),
            1 => bad.property.is_awaiting_user_approval = true,
            2 => bad.property.is_uninstalling = true,
            3 => bad.filter = FilterState::Foreign,
            _ => bad.property.url = "/Library/../outside".into(),
        }
        assert!(attempt(BOOT, owner(), &digest, bad).is_err());
    }
    assert!(attempt(BOOT, owner(), &digest, valid).is_ok());
}

#[test]
fn report_refuses_changed_owner_connection_uid_ids_and_reordered_sequences() {
    let record = claimed();
    let progress = Report {
        sequence: 1,
        outcome: UpgradeOutcome::AwaitingApproval,
    };
    for change in 0..3 {
        let mut who = owner();
        match change {
            0 => who.instance_nonce = "f".repeat(64),
            1 => who.connection_generation += 1,
            _ => who.operator_uid += 1,
        }
        assert!(record
            .report(&who, &"a".repeat(64), &"b".repeat(64), progress.clone())
            .is_err());
        assert!(record.owner_lost(&who).is_err());
    }
    assert!(record
        .report(&owner(), &"f".repeat(64), &"b".repeat(64), progress.clone())
        .is_err());
    assert!(record
        .report(&owner(), &"a".repeat(64), &"f".repeat(64), progress)
        .is_err());
    assert!(report(&record, 0, UpgradeOutcome::AwaitingApproval).is_err());
    assert!(report(&record, 2, UpgradeOutcome::AwaitingApproval).is_err());
    let progressed = report(&record, 1, UpgradeOutcome::AwaitingApproval).unwrap();
    same(
        &progressed,
        &report(&progressed, 1, UpgradeOutcome::AwaitingApproval).unwrap(),
    );
    assert!(report(&progressed, 1, UpgradeOutcome::ReplacementAllowed).is_err());
    assert!(report(&progressed, 3, UpgradeOutcome::ReplacementAllowed).is_err());
}

#[test]
fn terminal_ack_crash_retains_result_and_only_exact_last_replay_is_idempotent() {
    let complete = roundtrip(&completed());
    same(
        &complete,
        &report(&complete, 2, UpgradeOutcome::Completed).unwrap(),
    );
    same(&complete, &complete.owner_lost(&owner()).unwrap());
    for (sequence, outcome) in [
        (2, UpgradeOutcome::Failed),
        (3, UpgradeOutcome::Completed),
        (1, UpgradeOutcome::ReplacementAllowed),
    ] {
        assert!(report(&complete, sequence, outcome).is_err());
    }
    assert!(complete.abort_before_claim().is_err());
    assert!(complete
        .abort_failed(complete.attempt.as_ref().unwrap().inspection.clone())
        .is_err());
}

#[test]
fn one_replacement_callback_is_required_and_cannot_be_changed() {
    for outcome in [
        UpgradeOutcome::Completed,
        UpgradeOutcome::RebootRequired,
        UpgradeOutcome::UnexpectedCompleted,
    ] {
        let unexpected = report(&claimed(), 1, outcome).unwrap();
        assert_eq!(unexpected.phase, Phase::Unexpected);
        assert!(unexpected.can_reconcile(BOOT).is_err());
        assert!(unexpected.config_committed(BOOT).is_err());
        assert!(report(&unexpected, 2, UpgradeOutcome::ReplacementAllowed).is_err());
        same(&unexpected, &unexpected.owner_lost(&owner()).unwrap());
    }
    let allowed = report(&claimed(), 1, UpgradeOutcome::ReplacementAllowed).unwrap();
    assert!(report(&allowed, 2, UpgradeOutcome::ReplacementAllowed).is_err());
    assert!(report(&allowed, 2, UpgradeOutcome::ReplacementRefused).is_err());
    let refused = report(&claimed(), 1, UpgradeOutcome::ReplacementRefused).unwrap();
    assert_eq!(refused.phase, Phase::MayBePending);
    assert!(refused
        .abort_failed(refused.attempt.as_ref().unwrap().inspection.clone())
        .is_err());
    assert_eq!(
        report(&refused, 2, UpgradeOutcome::Completed)
            .unwrap()
            .phase,
        Phase::Unexpected
    );
    let failed = report(&refused, 2, UpgradeOutcome::Failed).unwrap();
    let original = failed.attempt.as_ref().unwrap().inspection.clone();
    let mut different = original.clone();
    different.filter = FilterState::Absent;
    assert!(failed.abort_failed(different).is_err());
    let aborted = failed.abort_failed(original).unwrap();
    assert_eq!(roundtrip(&aborted).phase, Phase::Aborted);
    assert!(aborted.can_reconcile(NEXT_BOOT).is_err());
}

#[test]
fn abandoned_disconnected_and_timed_out_claims_retain_uncertainty() {
    for pending in [
        claimed(),
        report(&claimed(), 1, UpgradeOutcome::ReplacementAllowed).unwrap(),
    ] {
        let uncertain = roundtrip(&pending.owner_lost(&owner()).unwrap());
        assert_eq!(uncertain.phase, Phase::Uncertain);
        same(&uncertain, &uncertain.owner_lost(&owner()).unwrap());
        assert!(uncertain.can_reconcile(BOOT).is_err());
        assert!(uncertain.abort_before_claim().is_err());
        assert!(uncertain
            .abort_failed(uncertain.attempt.as_ref().unwrap().inspection.clone())
            .is_err());
        let next = pending
            .attempt
            .as_ref()
            .unwrap()
            .last_report
            .as_ref()
            .map_or(1, |last| last.sequence + 1);
        assert!(report(&uncertain, next, UpgradeOutcome::Completed).is_err());
    }
    let abandoned = report(&claimed(), 1, UpgradeOutcome::Abandoned).unwrap();
    assert_eq!(abandoned.phase, Phase::Uncertain);
    assert!(abandoned.can_reconcile(BOOT).is_err());
    assert!(abandoned.can_reconcile(NEXT_BOOT).is_ok());
}

#[test]
fn reconciliation_preserves_inactive_filter_and_does_not_fabricate_callbacks() {
    for filter in [
        FilterState::Absent,
        FilterState::Owned { enabled: false },
        FilterState::Owned { enabled: true },
    ] {
        for terminal in [UpgradeOutcome::Completed, UpgradeOutcome::RebootRequired] {
            let pending = claim_with_filter(filter.clone());
            let allowed = report(&pending, 1, UpgradeOutcome::ReplacementAllowed).unwrap();
            let terminal_record = report(&allowed, 2, terminal).unwrap();
            let boot = if terminal == UpgradeOutcome::Completed {
                BOOT
            } else {
                NEXT_BOOT
            };
            let candidate = inspection(&terminal_record, true, filter.clone());
            assert!(terminal_record.config_committed(boot).is_err());
            let reconciled = terminal_record
                .reconcile_candidate(boot, candidate)
                .unwrap();
            assert_eq!(reconciled.phase, terminal_record.phase);
            assert_eq!(reconciled.attempt, terminal_record.attempt);
            assert_eq!(
                reconciled.reconciliation.as_ref().unwrap().candidate.filter,
                filter
            );
            let done = reconciled
                .config_committed(boot)
                .unwrap()
                .complete(boot)
                .unwrap();
            assert_eq!(roundtrip(&done).phase, Phase::Complete);
            assert_eq!(done.attempt, terminal_record.attempt);
            same(&done, &report(&done, 2, terminal).unwrap());
        }
    }
}

#[test]
fn changed_boot_reconciliation_records_separate_proof_for_unknown_request() {
    let uncertain = claimed().owner_lost(&owner()).unwrap();
    let candidate = inspection(&uncertain, true, FilterState::Owned { enabled: true });
    assert!(uncertain
        .reconcile_candidate(BOOT, candidate.clone())
        .is_err());
    let reconciled = uncertain.reconcile_candidate(NEXT_BOOT, candidate).unwrap();
    assert_eq!(reconciled.phase, Phase::Uncertain);
    assert!(reconciled.attempt.as_ref().unwrap().last_report.is_none());
    assert!(reconciled.config_committed(BOOT).is_err());
    assert_eq!(
        reconciled
            .config_committed(NEXT_BOOT)
            .unwrap()
            .complete(NEXT_BOOT)
            .unwrap()
            .phase,
        Phase::Complete
    );
    let unexpected = report(&claimed(), 1, UpgradeOutcome::Completed).unwrap();
    let candidate = inspection(&unexpected, true, FilterState::Owned { enabled: true });
    let recovered = unexpected
        .reconcile_candidate(NEXT_BOOT, candidate)
        .unwrap();
    assert_eq!(
        recovered
            .attempt
            .as_ref()
            .unwrap()
            .last_report
            .as_ref()
            .unwrap()
            .outcome,
        UpgradeOutcome::Completed
    );
    assert!(recovered.attempt.as_ref().unwrap().replacement.is_none());
    assert_eq!(
        recovered.config_committed(NEXT_BOOT).unwrap().phase,
        Phase::ConfigCommitted
    );
}

#[test]
fn candidate_proof_requires_exact_pin_filter_and_enabled_settled_registration() {
    let completed = completed();
    let good = inspection(&completed, true, FilterState::Owned { enabled: true });
    for change in 0..7 {
        let mut candidate = good.clone();
        match change {
            0 => candidate.property.bundle_version = "1".into(),
            1 => candidate.property.bundle_identifier = "invalid.example.other".into(),
            2 => candidate.property.is_enabled = false,
            3 => candidate.property.is_awaiting_user_approval = true,
            4 => candidate.property.is_uninstalling = true,
            5 => candidate.filter = FilterState::Owned { enabled: false },
            _ => candidate.filter = FilterState::Foreign,
        }
        assert!(completed.reconcile_candidate(BOOT, candidate).is_err());
    }
    let committed = completed
        .reconcile_candidate(BOOT, good.clone())
        .unwrap()
        .config_committed(BOOT)
        .unwrap();
    assert!(committed.complete(NEXT_BOOT).is_err());
    let recovered = roundtrip(&committed)
        .reconcile_candidate(NEXT_BOOT, good)
        .unwrap();
    assert_eq!(
        recovered.complete(NEXT_BOOT).unwrap().phase,
        Phase::Complete
    );
}

#[test]
fn durable_validation_rejects_forged_bindings_phases_and_unbounded_paths() {
    for change in 0..10 {
        let mut bad = fixture();
        match change {
            0 => bad.schema = 2,
            1 => bad.id = "f".repeat(64),
            2 => bad.original_boot = BOOT.to_uppercase().replace('1', "A"),
            3 => bad.old_container_cdhashes = vec!["z".repeat(40)],
            4 => bad.plan.old.executable_sha256 = "f".repeat(64),
            5 => bad.candidate.artifact.provider_cdhashes = vec!["e".repeat(40)],
            6 => bad.candidate.artifact.agent_identifier = "invalid.example.other".into(),
            7 => bad.candidate.target = "macos-x86_64".into(),
            8 => bad.management_sha256 = "not-a-hash".into(),
            _ => bad.phase = Phase::Complete,
        }
        assert!(bad.validate().is_err());
    }
    for path in [
        "relative",
        "/",
        "/trailing/",
        "/a//b",
        "/a/./b",
        "/a/../b",
        "/a\\b",
        "/a\0b",
        "/a\nb",
        &format!("/{}", "x".repeat(4096)),
    ] {
        let mut bad = fixture();
        bad.state_path = path.into();
        assert!(bad.validate().is_err());
    }
    let mut forged = claimed();
    forged.phase = Phase::OsCompleted;
    assert!(forged.validate().is_err());
    let mut forged = completed();
    forged.attempt.as_mut().unwrap().replacement = None;
    assert!(forged.validate().is_err());
    let mut forged = completed();
    forged.phase = Phase::Complete;
    assert!(forged.validate().is_err());
}

#[test]
fn normalized_equal_or_older_versions_and_same_code_identity_cannot_claim() {
    for version in ["1", "1.0", "1.0.0", "0.9.9"] {
        let mut bad = fixture();
        bad.plan.new.bundle_version = version.into();
        assert!(bad.validate().is_err());
    }
    let mut bad = fixture();
    bad.plan.new.cdhashes = bad.plan.old.cdhashes.clone();
    bad.candidate.artifact.provider_cdhashes = bad.plan.new.cdhashes.clone();
    assert!(bad.validate().is_err());
}

#[test]
fn exhausted_sequence_does_not_wrap_or_regrant_a_decision() {
    let mut record = claimed();
    record.attempt.as_mut().unwrap().last_report = Some(Report {
        sequence: u64::MAX,
        outcome: UpgradeOutcome::AwaitingApproval,
    });
    record.validate().unwrap();
    same(
        &record,
        &report(&record, u64::MAX, UpgradeOutcome::AwaitingApproval).unwrap(),
    );
    assert!(report(&record, 1, UpgradeOutcome::ReplacementAllowed).is_err());
    assert!(report(&record, u64::MAX, UpgradeOutcome::Completed).is_err());
}
