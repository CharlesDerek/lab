use super::*;
use athernex_endpoint_native::windows_driver_lifecycle::ServiceConfiguration;
fn id() -> ObjectIdentity {
    ObjectIdentity {
        volume: 7,
        file_id: [3; 16],
    }
}
fn member() -> Member {
    Member {
        bytes: 128,
        sha256: "a".repeat(64),
    }
}
fn initial() -> Record {
    let d = Descriptor {
        schema: 1,
        sha256: "b".repeat(64),
        bytes: 416,
        profile: protocol::windows_filter_package::PROFILE.into(),
        trust_policy: protocol::windows_filter_package::TRUST.into(),
        source_revision: "a".repeat(40),
        expected_abi: 2,
        deployment: Some(Deployment::InstallAndObserveDisarmedV1),
        driver_version: "1.2.3.4".into(),
        driver_date: "10/26/2026".into(),
        altitude: "325000.01".into(),
        sys: member(),
        inf: member(),
        cat: member(),
    };
    let mut inputs: BTreeMap<_, _> = INPUTS
        .iter()
        .map(|n| {
            (
                n.to_string(),
                Input {
                    approved: member(),
                    identity: None,
                },
            )
        })
        .collect();
    inputs.get_mut("windows-filter.axpkg").unwrap().approved = Member {
        bytes: d.bytes,
        sha256: d.sha256.clone(),
    };
    inputs.get_mut("windows-filter.required").unwrap().approved = Member {
        bytes: 2,
        sha256: protocol::hash(b"1\n"),
    };
    let path = if cfg!(windows) {
        r"C:\fixture"
    } else {
        "/fixture"
    };
    Record {
        schema: 1,
        transaction: "1".repeat(64),
        nonce: "2".repeat(64),
        source_sha256: "a".repeat(64),
        state: PathBuf::from(path).join("state"),
        state_identity: id(),
        agent: PathBuf::from(path).join("agent"),
        descriptor: d,
        epoch: "3".repeat(64),
        epoch_confirmed: false,
        refresh_epoch: None,
        previous_load: None,
        snapshot: None,
        inputs,
        phase: Phase::Snapshot,
        operation: Operation::Install,
        helper_created: false,
        helper_owner_system: false,
        resume_phase: None,
        archive: None,
        publication: None,
        worker: None,
        registration: None,
        load: None,
        effect: None,
    }
}
fn ready() -> Record {
    let mut r = initial();
    r.snapshot = Some(id());
    r.epoch_confirmed = true;
    for input in r.inputs.values_mut() {
        input.identity = Some(id());
    }
    r.ready().unwrap();
    r
}
fn endpoint() -> Record {
    let mut r = ready();
    r.create_intent().unwrap();
    r.created().unwrap();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(101, 99).unwrap();
    r.endpoint().unwrap();
    r
}
fn registration() -> Registration {
    Registration {
        published_inf: "fixture-oem.inf".into(),
        store_inf: "fixture-store.inf".into(),
        published_identity: id(),
        member_identities: [id(), id(), id()],
        configuration: ServiceConfiguration {
            service_type: 2,
            start_type: 3,
            error_control: 1,
            binary_path: "fixture.sys".into(),
            load_order_group: "FSFilter Anti-Virus".into(),
            dependencies: vec!["FltMgr".into()],
            account: String::new(),
        },
        instance: "AthernexFilter".into(),
        altitude: "325000.01".into(),
        instance_flags: 0,
    }
}
fn load() -> LoadObserved {
    LoadObserved {
        version: 2,
        instance: [9; 16],
        armed: 0,
        connected: 1,
        pending: 0,
        policy_sha256: [0; 32],
    }
}
fn success() -> NativeEffect {
    NativeEffect {
        succeeded: true,
        need_reboot: false,
        code: 0,
    }
}
fn loaded() -> Record {
    let mut r = endpoint();
    r.intent().unwrap();
    r.result(success(), Some(registration()), None).unwrap();
    r.intent().unwrap();
    r.result(success(), None, Some(load())).unwrap();
    r
}
#[test]
fn only_durable_load_observation_authorizes_installer_complete() {
    let mut r = endpoint();
    assert!(r.complete().is_err());
    assert!(r.authorize_complete(true, [9; 16]).is_err());
    r.intent().unwrap();
    r.result(success(), Some(registration()), None).unwrap();
    assert!(r.complete().is_err());
    r.intent().unwrap();
    r.result(success(), None, Some(load())).unwrap();
    r.authorize_complete(true, [9; 16]).unwrap();
    assert!(r.authorize_complete(false, [9; 16]).is_err());
    assert!(r.authorize_complete(true, [8; 16]).is_err());
    r.complete().unwrap();
    assert!(r.complete().is_err());
}
#[test]
fn every_native_intent_is_nonreplayable_after_lost_completion_receipt() {
    let mut installed = endpoint();
    installed.intent().unwrap();
    let install_intent = installed.clone();
    installed
        .result(success(), Some(registration()), None)
        .unwrap();
    installed.intent().unwrap();
    let load_intent = installed.clone();
    let mut retiring = loaded();
    retiring.complete().unwrap();
    retiring.request_retirement().unwrap();
    retiring.start_intent().unwrap();
    retiring.started().unwrap();
    retiring.claim(201, 199).unwrap();
    retiring.intent().unwrap();
    let unload_intent = retiring.clone();
    retiring.result(success(), None, None).unwrap();
    retiring.intent().unwrap();
    for mut saved in [install_intent, load_intent, unload_intent, retiring] {
        // Model persisted-before-call / OS-completed-before-save crash boundary.
        let encoded = serde_json::to_vec(&saved).unwrap();
        saved = serde_json::from_slice(&encoded).unwrap();
        saved.validate().unwrap();
        assert!(saved.intent().is_err());
        assert!(saved.start_intent().is_err());
        assert!(saved.complete().is_err());
        assert!(saved.authorize_complete(true, [9; 16]).is_err());
    }
}
#[test]
fn known_native_boundaries_resume_without_repeating_prior_effect() {
    let mut r = endpoint();
    r.intent().unwrap();
    r.result(success(), Some(registration()), None).unwrap();
    let saved_registration = r.registration.clone();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(201, 199).unwrap();
    assert_eq!(r.phase, Phase::Installed);
    assert_eq!(r.registration, saved_registration);
    r.intent().unwrap();
    assert_eq!(r.phase, Phase::LoadIntent);
    r.result(success(), None, Some(load())).unwrap();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(301, 299).unwrap();
    assert_eq!(r.phase, Phase::Loaded);
    assert!(r.intent().is_err());
    r.complete().unwrap();
}
#[test]
fn failed_and_reboot_native_results_remain_blocked_without_adoption() {
    for effect in [
        NativeEffect {
            succeeded: false,
            need_reboot: false,
            code: 5,
        },
        NativeEffect {
            succeeded: false,
            need_reboot: true,
            code: 5,
        },
        NativeEffect {
            succeeded: true,
            need_reboot: true,
            code: 0,
        },
    ] {
        let mut r = endpoint();
        r.intent().unwrap();
        r.result(effect, None, None).unwrap();
        assert!(matches!(r.phase, Phase::Uncertain | Phase::RebootPending));
        assert!(r.start_intent().is_err());
        assert!(r.intent().is_err());
        assert!(r.complete().is_err());
    }
}
#[test]
fn ownership_claim_requires_complete_snapshot_create_and_start_receipts() {
    let r = initial();
    r.validate().unwrap();
    for stage in 0..4 {
        let mut changed = r.clone();
        if stage >= 1 {
            changed.snapshot = Some(id());
        }
        if stage >= 2 {
            changed.epoch_confirmed = true;
        }
        if stage >= 3 {
            for input in changed.inputs.values_mut() {
                input.identity = Some(id());
            }
        }
        assert_eq!(changed.ready().is_ok(), stage == 3);
    }
    let mut r = ready();
    assert!(r.claim(101, 99).is_err());
    r.create_intent().unwrap();
    assert!(r.start_intent().is_err());
    assert!(r.create_intent().is_err());
    r.created().unwrap();
    r.start_intent().unwrap();
    assert!(r.claim(101, 99).is_err());
    r.started().unwrap();
    r.claim(101, 99).unwrap();
    assert!(r.claim(101, 99).is_err());
}
#[test]
fn retirement_is_owned_normal_unload_then_exact_native_uninstall() {
    let mut r = loaded();
    assert!(r.request_retirement().is_err());
    r.complete().unwrap();
    r.request_retirement().unwrap();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(201, 199).unwrap();
    r.intent().unwrap();
    assert_eq!(r.phase, Phase::UnloadIntent);
    r.result(success(), None, None).unwrap();
    r.intent().unwrap();
    assert_eq!(r.phase, Phase::UninstallIntent);
    r.result(success(), None, None).unwrap();
    assert_eq!(r.phase, Phase::Retired);
    assert!(r.complete().is_err());
    assert!(r.start_intent().is_err());
}
#[test]
fn malformed_handoff_cannot_invent_missing_identity_or_effect_receipts() {
    let r = loaded();
    for key in [
        "schema",
        "nonce",
        "source_sha256",
        "descriptor",
        "snapshot",
        "helper_created",
        "registration",
        "load",
        "resume_phase",
    ] {
        let mut value = serde_json::to_value(&r).unwrap();
        value[key] = match key {
            "schema" => 2.into(),
            "nonce" | "source_sha256" => "unknown".into(),
            "helper_created" => false.into(),
            "resume_phase" => "complete".into(),
            _ => serde_json::Value::Null,
        };
        assert!(
            serde_json::from_value::<Record>(value).map_or(true, |v| v.validate().is_err()),
            "{key}"
        );
    }
}
#[test]
fn abi_observation_is_disarmed_and_not_a_retained_rundown_attestation() {
    for field in 0..6 {
        let mut value = load();
        match field {
            0 => value.version = 1,
            1 => value.instance = [0; 16],
            2 => value.armed = 1,
            3 => value.connected = 0,
            4 => value.pending = 1,
            _ => value.policy_sha256 = [1; 32],
        };
        assert!(value.validate().is_err());
    }
    load().validate().unwrap();
}

#[test]
fn terminal_retirement_requires_confirmed_helper_deletion_and_archive_before_release() {
    let mut r = loaded();
    r.complete().unwrap();
    r.request_retirement().unwrap();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(201, 199).unwrap();
    r.intent().unwrap();
    r.result(success(), None, None).unwrap();
    r.intent().unwrap();
    r.result(success(), None, None).unwrap();
    assert!(r.release().is_err());
    r.delete_intent().unwrap();
    assert!(r.delete_intent().is_err());
    assert!(r.release().is_err());
    r.helper_deleted().unwrap();
    assert!(r.release().is_err());
    assert!(r.archived().is_err());
    r.publish_intent(publication(
        ReceiptKind::Retired,
        Input {
            approved: member(),
            identity: Some(id()),
        },
    ))
    .unwrap();
    assert!(r.release().is_err());
    r.archived().unwrap();
    r.release().unwrap();
    assert_eq!(r.phase, Phase::Released);
    r.validate().unwrap();
    assert!(r.start_intent().is_err());
    assert!(r.intent().is_err());
    let mut invalid = r.clone();
    invalid.archive = None;
    assert!(invalid.validate().is_err());
}
#[test]
fn only_returned_failed_load_with_owned_registration_and_actual_absence_can_rollback() {
    let failure = NativeEffect {
        succeeded: false,
        need_reboot: false,
        code: 5,
    };
    let mut failed_install = endpoint();
    failed_install.intent().unwrap();
    failed_install.result(failure, None, None).unwrap();
    assert!(failed_install.failed_load_retirement(true).is_err());
    let mut r = endpoint();
    r.intent().unwrap();
    r.result(success(), Some(registration()), None).unwrap();
    r.intent().unwrap();
    assert!(r.failed_load_retirement(true).is_err()); // Lost result remains unowned completion.
    r.result(failure, None, None).unwrap();
    assert!(r.failed_load_retirement(false).is_err());
    r.failed_load_retirement(true).unwrap();
    assert_eq!(r.phase, Phase::Unloaded);
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(201, 199).unwrap();
    r.intent().unwrap();
    assert_eq!(r.phase, Phase::UninstallIntent);
}

fn publication(kind: ReceiptKind, receipt: Input) -> Publication {
    Publication {
        kind,
        temporary: "e".repeat(64),
        receipt,
    }
}
fn previous(r: &Record) -> CompletedLoad {
    CompletedLoad {
        epoch: r.epoch.clone(),
        load: r.load.clone().unwrap(),
        receipt: Input {
            approved: member(),
            identity: Some(id()),
        },
    }
}
#[test]
fn completed_reload_preserves_history_and_never_reinstalls_the_package() {
    let mut r = loaded();
    r.complete().unwrap();
    let prior = previous(&r);
    r.publish_intent(publication(ReceiptKind::Completed, prior.receipt.clone()))
        .unwrap();
    r.refresh_intent("4".repeat(64), prior.clone()).unwrap();
    assert_eq!(r.phase, Phase::RefreshIntent);
    assert!(r.intent().is_err());
    assert!(r.start_intent().is_err());
    assert!(r.refreshed(&"5".repeat(64)).is_err());
    r.refreshed(&"4".repeat(64)).unwrap();
    assert_eq!(r.previous_load, Some(prior));
    assert_eq!(r.registration, Some(registration()));
    assert!(r.load.is_none());
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(301, 299).unwrap();
    r.intent().unwrap();
    assert_eq!(r.phase, Phase::LoadIntent);
    let mut fresh = load();
    fresh.instance = [10; 16];
    r.result(success(), None, Some(fresh)).unwrap();
    r.authorize_complete(true, [10; 16]).unwrap();
    assert!(r.authorize_complete(true, [9; 16]).is_err());
    r.complete().unwrap();
}
#[test]
fn epoch_refresh_never_discharges_unknown_effect_or_reboot_requirement() {
    let mut complete = loaded();
    complete.complete().unwrap();
    let prior = previous(&complete);
    for phase in [
        Phase::InstallIntent,
        Phase::LoadIntent,
        Phase::Uncertain,
        Phase::RebootPending,
        Phase::Loaded,
        Phase::Unloaded,
    ] {
        let mut r = complete.clone();
        r.phase = phase;
        let unchanged = r.clone();
        assert!(r.refresh_intent("4".repeat(64), prior.clone()).is_err());
        assert_eq!(r, unchanged);
    }
    let mut r = complete.clone();
    let mut wrong = prior;
    wrong.load.instance = [1; 16];
    assert!(r.refresh_intent("4".repeat(64), wrong).is_err());
    assert_eq!(r, complete);
}
#[test]
fn completed_reload_cannot_accept_old_uuid_or_replay_a_lost_load_result() {
    let mut r = loaded();
    r.complete().unwrap();
    let prior = previous(&r);
    // An unchanged epoch is only an invalidation token, not OS absence proof.
    r.publish_intent(publication(ReceiptKind::Completed, prior.receipt.clone()))
        .unwrap();
    r.refresh_intent(r.epoch.clone(), prior).unwrap();
    r.refreshed(&r.epoch.clone()).unwrap();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(301, 299).unwrap();
    r.intent().unwrap();
    assert!(r.clone().result(success(), None, Some(load())).is_err());
    assert!(r.intent().is_err());
    assert!(r.start_intent().is_err());
    assert!(r.complete().is_err());
    let mut r2 = r.clone();
    r2.result(
        NativeEffect {
            succeeded: false,
            need_reboot: false,
            code: 5,
        },
        None,
        None,
    )
    .unwrap();
    assert_eq!(r2.phase, Phase::Uncertain);
    assert!(r2
        .refresh_intent("4".repeat(64), r.previous_load.unwrap())
        .is_err());
}

#[test]
fn ended_claimed_worker_may_resume_only_the_boundary_before_any_native_intent() {
    let mut r = ready();
    r.create_intent().unwrap();
    r.created().unwrap();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(101, 99).unwrap();
    assert_eq!(r.phase, Phase::Claimed);
    assert!(r.registration.is_none());
    assert!(r.effect.is_none());
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(201, 199).unwrap();
    assert_eq!(r.phase, Phase::Claimed);
    r.endpoint().unwrap();
    r.intent().unwrap();
    assert_eq!(r.phase, Phase::InstallIntent);
    assert!(r.start_intent().is_err());
    let mut r = loaded();
    r.complete().unwrap();
    r.request_retirement().unwrap();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(201, 199).unwrap();
    r.start_intent().unwrap();
    r.started().unwrap();
    r.claim(301, 299).unwrap();
    r.intent().unwrap();
    assert_eq!(r.phase, Phase::UnloadIntent);
    assert!(r.start_intent().is_err());
}

#[test]
fn local_receipt_publication_is_bound_and_does_not_authorize_native_effects() {
    let mut r = loaded();
    r.complete().unwrap();
    let prior = previous(&r);
    assert!(r
        .clone()
        .refresh_intent("4".repeat(64), prior.clone())
        .is_err());
    let claim = publication(ReceiptKind::Completed, prior.receipt.clone());
    assert!(r
        .clone()
        .publish_intent(Publication {
            kind: ReceiptKind::Retired,
            ..claim.clone()
        })
        .is_err());
    assert!(r
        .clone()
        .publish_intent(Publication {
            temporary: "invalid".into(),
            ..claim.clone()
        })
        .is_err());
    r.publish_intent(claim.clone()).unwrap();
    let recovered: Record = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
    assert_eq!(recovered.publication, Some(claim.clone()));
    assert!(r.publish_intent(claim).is_err());
    assert!(r.intent().is_err());
    let mut foreign = prior.clone();
    foreign.receipt.identity = Some(ObjectIdentity {
        volume: 8,
        file_id: [8; 16],
    });
    assert!(r.clone().refresh_intent("4".repeat(64), foreign).is_err());
    r.refresh_intent("4".repeat(64), prior).unwrap();
    assert!(r.publication.is_none());
    assert!(r.intent().is_err());
}
