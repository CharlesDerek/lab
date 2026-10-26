//! Deterministic controller/effect ordering, not native signature, OS activation,
//! filesystem durability or live-provider proof. The memory backend models a
//! durable write that can fail either before or after its new value is visible.
use super::*;
use crate::macos_network_bundle::Deployment;
use athernex_endpoint_protocol::{self as protocol, installer::MacosNetworkArtifact};
use athernex_macos_network::{
    upgrade::{UpgradeCodePin, UpgradeOutcome, UpgradePlan},
    BundleIdentity,
};
use std::{cell::RefCell, rc::Rc};

const BOOT: &str = "11111111-2222-3333-4444-555555555555";
const NEXT_BOOT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const GENERATION: u64 = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Before,
    After,
}

struct Disk {
    durable: Record,
    events: Vec<&'static str>,
    writes: usize,
    fail_write: Option<(usize, Failure)>,
    fail_inspect: bool,
    fail_before_permit: bool,
    fail_config: Option<Failure>,
    fail_restore: Option<Failure>,
    config_written: bool,
    rollback_intent: bool,
    original_restored: bool,
}

#[derive(Clone)]
struct Memory(Rc<RefCell<Disk>>);
impl Memory {
    fn new(record: Record) -> Self {
        Self(Rc::new(RefCell::new(Disk {
            durable: record,
            events: Vec::new(),
            writes: 0,
            fail_write: None,
            fail_inspect: false,
            fail_before_permit: false,
            fail_config: None,
            fail_restore: None,
            config_written: false,
            rollback_intent: false,
            original_restored: false,
        })))
    }
    fn record(&self) -> Record {
        self.0.borrow().durable.clone()
    }
    fn fail_next_write(&self, when: Failure) {
        let mut disk = self.0.borrow_mut();
        disk.fail_write = Some((disk.writes + 1, when));
    }
    fn events(&self) -> Vec<&'static str> {
        self.0.borrow().events.clone()
    }
}
impl Backend for Memory {
    fn persist(&mut self, previous: &Record, next: &Record) -> Result<()> {
        previous.validate()?;
        next.validate()?;
        let mut disk = self.0.borrow_mut();
        disk.events.push("persist_started");
        disk.writes += 1;
        if serde_json::to_vec(previous)? != serde_json::to_vec(&disk.durable)? {
            return Err("Synthetic durable compare refused".into());
        }
        if disk.fail_write == Some((disk.writes, Failure::Before)) {
            return Err("Synthetic pre-write failure".into());
        }
        disk.durable = next.clone();
        disk.events.push("persist_visible");
        if disk.fail_write == Some((disk.writes, Failure::After)) {
            return Err("Synthetic post-write failure".into());
        }
        disk.events.push("persist_confirmed");
        Ok(())
    }
    fn inspect(
        &mut self,
        _record: &Record,
        target: InspectTarget,
        properties: &[ExtensionProperty],
        filter: &FilterState,
    ) -> Result<Inspection> {
        let mut disk = self.0.borrow_mut();
        disk.events.push(match target {
            InspectTarget::Original => "inspect_original",
            InspectTarget::Candidate => "inspect_candidate",
        });
        if disk.fail_inspect || properties.len() != 1 {
            return Err("Synthetic inspection refused".into());
        }
        Ok(Inspection {
            property: properties[0].clone(),
            filter: filter.clone(),
        })
    }
    fn before_permit(&mut self, record: &Record, _inspection: &Inspection) -> Result<()> {
        assert_eq!(record.phase, Phase::CandidatePlaced);
        let mut disk = self.0.borrow_mut();
        disk.events.push("before_permit");
        if disk.fail_before_permit {
            return Err("Synthetic pre-permit refusal".into());
        }
        Ok(())
    }
    fn commit_config(&mut self, record: &Record) -> Result<()> {
        let mut disk = self.0.borrow_mut();
        assert!(
            record.reconciliation.is_some(),
            "Config must follow retained reconciliation"
        );
        assert!(
            serde_json::to_vec(record)? == serde_json::to_vec(&disk.durable)?,
            "Reconciliation must be durable before config"
        );
        assert_eq!(disk.events.last(), Some(&"persist_confirmed"));
        disk.events.push("config_started");
        if disk.fail_config == Some(Failure::Before) {
            return Err("Synthetic pre-config failure".into());
        }
        disk.config_written = true;
        disk.events.push("config_visible");
        if disk.fail_config == Some(Failure::After) {
            return Err("Synthetic post-config failure".into());
        }
        disk.events.push("config_confirmed");
        Ok(())
    }
    fn restore_original(&mut self, record: &Record, _inspection: &Inspection) -> Result<()> {
        let mut disk = self.0.borrow_mut();
        assert_eq!(record.phase, Phase::OsFailed);
        assert!(serde_json::to_vec(record)? == serde_json::to_vec(&disk.durable)?);
        disk.events.push("restore_started");
        if disk.fail_restore == Some(Failure::Before) {
            return Err("Synthetic pre-restore failure".into());
        }
        // The real filesystem backend, not the journal model, owns this intent.
        disk.rollback_intent = true;
        disk.events.push("rollback_intent_visible");
        disk.original_restored = true;
        disk.events.push("restore_visible");
        if disk.fail_restore == Some(Failure::After) {
            return Err("Synthetic post-restore failure".into());
        }
        disk.events.push("restore_confirmed");
        Ok(())
    }
}

fn fixture() -> Record {
    let artifact = MacosNetworkArtifact {
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
    };
    let old = Deployment {
        path: crate::macos_network_bundle::INSTALL_PATH.into(),
        target: "macos-aarch64".into(),
        artifact,
    };
    let mut candidate = old.clone();
    candidate.artifact.provider_sha256 = "e".repeat(64);
    candidate.artifact.provider_cdhashes = vec!["b".repeat(40)];
    candidate.artifact.container_sha256 = "f".repeat(64);
    candidate.artifact.tree_sha256 = "1".repeat(64);
    candidate.artifact.sha256 = "2".repeat(64);
    let a = &old.artifact;
    let plan = UpgradePlan {
        mode: UpgradeMode::Submit,
        transaction_id: "3".repeat(64),
        generation: 8,
        identity: BundleIdentity {
            team_id: a.team_id.clone(),
            agent_identifier: a.agent_identifier.clone(),
            container_identifier: a.container_identifier.clone(),
            provider_identifier: a.provider_identifier.clone(),
            app_group: a.app_group.clone(),
            mach_service_name: a.mach_service_name.clone(),
        },
        source_policy_sha256: a.source_policy_sha256.clone(),
        old: UpgradeCodePin {
            executable_sha256: a.provider_sha256.clone(),
            cdhashes: a.provider_cdhashes.clone(),
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
        phase: Phase::CandidatePlaced,
        attempt: None,
        reconciliation: None,
        rollback: None,
    };
    record.validate().unwrap();
    record
}
fn incoming(token: u64, request: UpgradeRequest) -> UpgradeIncoming {
    UpgradeIncoming {
        connection_generation: GENERATION,
        request_token: token,
        peer_euid: 501,
        event: UpgradeEvent::Request { request },
    }
}
fn inspect_request(record: &Record, target: InspectTarget) -> UpgradeRequest {
    let pin = match target {
        InspectTarget::Original => &record.plan.old,
        InspectTarget::Candidate => &record.plan.new,
    };
    UpgradeRequest::Inspect {
        properties: vec![ExtensionProperty {
            url: "/Library/SystemExtensions/synthetic/invalid.example.provider.systemextension"
                .into(),
            bundle_identifier: record.plan.identity.provider_identifier.clone(),
            bundle_version: pin.bundle_version.clone(),
            bundle_short_version: pin.short_version.clone(),
            is_enabled: true,
            is_awaiting_user_approval: false,
            is_uninstalling: false,
        }],
        filter: FilterState::Owned { enabled: true },
    }
}
fn start(record: Record) -> (Owner<Memory>, Memory) {
    let memory = Memory::new(record.clone());
    let owner = Owner::new(record, memory.clone(), BOOT.into(), "9".repeat(64)).unwrap();
    (owner, memory)
}
fn plan(owner: &mut Owner<Memory>) -> (UpgradeMode, String) {
    let reply = owner
        .handle(&incoming(1, UpgradeRequest::Plan))
        .unwrap()
        .unwrap();
    let UpgradeReply::Plan { plan, plan_sha256 } = reply else {
        panic!("Expected plan reply")
    };
    assert_eq!(
        plan_sha256,
        protocol::hash(&serde_json::to_vec(&plan).unwrap())
    );
    (plan.mode, plan_sha256)
}
fn ready() -> (Owner<Memory>, Memory, String) {
    let (mut owner, memory) = start(fixture());
    let (mode, hash) = plan(&mut owner);
    assert_eq!(mode, UpgradeMode::Submit);
    let request = inspect_request(&owner.record, InspectTarget::Original);
    assert_eq!(
        owner.handle(&incoming(2, request)).unwrap(),
        Some(UpgradeReply::Inspected)
    );
    (owner, memory, hash)
}
fn claim(owner: &mut Owner<Memory>, hash: &str) -> Result<Option<UpgradeReply>> {
    owner.handle(&incoming(
        3,
        UpgradeRequest::Claim {
            plan_sha256: hash.into(),
        },
    ))
}
fn claimed() -> (Owner<Memory>, Memory, UpgradePermit) {
    let (mut owner, memory, hash) = ready();
    let Some(UpgradeReply::Permit { permit }) = claim(&mut owner, &hash).unwrap() else {
        panic!("Expected permit")
    };
    (owner, memory, permit)
}
fn report(permit: &UpgradePermit, sequence: u64, outcome: UpgradeOutcome) -> UpgradeIncoming {
    incoming(
        4 + sequence,
        UpgradeRequest::Report {
            attempt_id: permit.attempt_id.clone(),
            attempt_nonce: permit.attempt_nonce.clone(),
            sequence,
            outcome,
        },
    )
}
fn terminal(outcome: UpgradeOutcome) -> Record {
    let (mut owner, memory, permit) = claimed();
    assert_eq!(
        owner
            .handle(&report(&permit, 1, UpgradeOutcome::ReplacementAllowed))
            .unwrap(),
        Some(UpgradeReply::Recorded)
    );
    assert_eq!(
        owner.handle(&report(&permit, 2, outcome)).unwrap(),
        Some(UpgradeReply::Recorded)
    );
    memory.record()
}

#[test]
fn durable_claim_and_each_report_precede_permit_and_ack() {
    let (mut owner, memory, permit) = claimed();
    let durable = memory.record();
    assert_eq!(durable.phase, Phase::MayBePending);
    assert_eq!(durable.attempt.as_ref().unwrap().id, permit.attempt_id);
    assert_eq!(
        durable.attempt.as_ref().unwrap().nonce,
        permit.attempt_nonce
    );
    assert_eq!(
        memory.events(),
        vec![
            "inspect_original",
            "before_permit",
            "persist_started",
            "persist_visible",
            "persist_confirmed"
        ]
    );
    for (sequence, outcome) in [
        (1, UpgradeOutcome::ReplacementAllowed),
        (2, UpgradeOutcome::Completed),
    ] {
        assert_eq!(
            owner.handle(&report(&permit, sequence, outcome)).unwrap(),
            Some(UpgradeReply::Recorded)
        );
        let record = memory.record();
        let last = record
            .attempt
            .as_ref()
            .unwrap()
            .last_report
            .as_ref()
            .unwrap();
        assert_eq!(last.sequence, sequence);
        assert_eq!(last.outcome, outcome);
        assert_eq!(memory.events().last(), Some(&"persist_confirmed"));
    }
}

#[test]
fn failed_claim_write_before_or_after_visibility_never_returns_permit_or_reuses_owner() {
    for when in [Failure::Before, Failure::After] {
        let (mut owner, memory, hash) = ready();
        memory.fail_next_write(when);
        assert!(claim(&mut owner, &hash).is_err());
        assert!(owner.poisoned);
        let writes = memory.0.borrow().writes;
        assert!(claim(&mut owner, &hash).is_err());
        assert!(owner.handle(&incoming(10, UpgradeRequest::Plan)).is_err());
        owner.lost().unwrap();
        assert_eq!(memory.0.borrow().writes, writes);
        let disk = memory.record();
        assert_eq!(
            disk.phase,
            if when == Failure::Before {
                Phase::CandidatePlaced
            } else {
                Phase::MayBePending
            }
        );
        if when == Failure::After {
            let original_attempt = disk.attempt.clone();
            assert!(Owner::new(disk, memory.clone(), BOOT.into(), "a".repeat(64)).is_err());
            let recovered = memory.record();
            assert_eq!(recovered.phase, Phase::Uncertain);
            assert_eq!(
                recovered.attempt.as_ref().unwrap().id,
                original_attempt.as_ref().unwrap().id
            );
            assert!(recovered.attempt.as_ref().unwrap().owner_lost);
            let mut reader =
                Owner::new(recovered, memory.clone(), NEXT_BOOT.into(), "b".repeat(64)).unwrap();
            let (mode, hash) = plan(&mut reader);
            assert_eq!(mode, UpgradeMode::Reconcile);
            assert!(claim(&mut reader, &hash).is_err());
        }
    }
}

#[test]
fn lost_permit_recovered_from_durable_pending_becomes_uncertain_without_regrant() {
    let (owner, memory, _not_delivered) = claimed();
    drop(owner);
    assert!(Owner::new(memory.record(), memory.clone(), BOOT.into(), "c".repeat(64)).is_err());
    assert_eq!(memory.record().phase, Phase::Uncertain);
    assert_eq!(memory.0.borrow().writes, 2); // Claim, then owner-loss barrier.
    assert!(Owner::new(memory.record(), memory.clone(), BOOT.into(), "d".repeat(64)).is_err());
    assert_eq!(memory.0.borrow().writes, 2);
}

#[test]
fn terminal_write_error_after_visibility_recovers_as_readonly_reconciliation() {
    let (mut owner, memory, permit) = claimed();
    owner
        .handle(&report(&permit, 1, UpgradeOutcome::ReplacementAllowed))
        .unwrap();
    memory.fail_next_write(Failure::After);
    assert!(owner
        .handle(&report(&permit, 2, UpgradeOutcome::Completed))
        .is_err());
    assert!(owner.poisoned);
    assert_eq!(memory.record().phase, Phase::OsCompleted);
    owner.lost().unwrap();
    assert_eq!(memory.record().phase, Phase::OsCompleted);
    let mut reader =
        Owner::new(memory.record(), memory.clone(), BOOT.into(), "e".repeat(64)).unwrap();
    let (mode, hash) = plan(&mut reader);
    assert_eq!(mode, UpgradeMode::Reconcile);
    assert!(claim(&mut reader, &hash).is_err());
    assert!(reader
        .handle(&report(&permit, 2, UpgradeOutcome::Completed))
        .is_err());
    let request = inspect_request(&reader.record, InspectTarget::Candidate);
    assert_eq!(
        reader.handle(&incoming(20, request)).unwrap(),
        Some(UpgradeReply::Inspected)
    );
    assert_eq!(memory.record().phase, Phase::ConfigCommitted);
    assert_eq!(
        memory.record().attempt.as_ref().unwrap().id,
        permit.attempt_id
    );
}

#[test]
fn report_failure_before_visibility_keeps_prior_report_and_poisoned_owner() {
    let (mut owner, memory, permit) = claimed();
    memory.fail_next_write(Failure::Before);
    assert!(owner
        .handle(&report(&permit, 1, UpgradeOutcome::ReplacementAllowed))
        .is_err());
    assert!(memory
        .record()
        .attempt
        .as_ref()
        .unwrap()
        .last_report
        .is_none());
    assert!(owner.poisoned);
    assert!(owner
        .handle(&report(&permit, 1, UpgradeOutcome::ReplacementAllowed))
        .is_err());
    assert!(Owner::new(memory.record(), memory.clone(), BOOT.into(), "c".repeat(64)).is_err());
    assert_eq!(memory.record().phase, Phase::Uncertain);
}

#[test]
fn exact_terminal_replay_is_durable_but_changed_peer_nonce_sequence_or_result_is_refused() {
    let (mut owner, memory, permit) = claimed();
    owner
        .handle(&report(&permit, 1, UpgradeOutcome::ReplacementAllowed))
        .unwrap();
    let complete = report(&permit, 2, UpgradeOutcome::Completed);
    owner.handle(&complete).unwrap();
    let before = serde_json::to_vec(&memory.record()).unwrap();
    let writes = memory.0.borrow().writes;
    assert_eq!(
        owner.handle(&complete).unwrap(),
        Some(UpgradeReply::Recorded)
    );
    assert_eq!(memory.0.borrow().writes, writes + 1);
    assert!(serde_json::to_vec(&memory.record()).unwrap() == before);
    for change in 0..6 {
        let mut altered = complete.clone();
        match change {
            0 => altered.connection_generation += 1,
            1 => altered.peer_euid += 1,
            2 => altered.request_token = 0,
            _ => {
                let UpgradeEvent::Request {
                    request:
                        UpgradeRequest::Report {
                            attempt_nonce,
                            sequence,
                            outcome,
                            ..
                        },
                } = &mut altered.event
                else {
                    unreachable!()
                };
                match change {
                    3 => *attempt_nonce = "f".repeat(64),
                    4 => *sequence += 1,
                    _ => *outcome = UpgradeOutcome::Failed,
                }
            }
        }
        let writes = memory.0.borrow().writes;
        assert!(owner.handle(&altered).is_err());
        assert_eq!(memory.0.borrow().writes, writes);
    }
}

#[test]
fn terminal_disconnect_cannot_erase_result_and_shutdown_before_plan_is_final() {
    let (mut owner, memory, permit) = claimed();
    owner
        .handle(&report(&permit, 1, UpgradeOutcome::ReplacementAllowed))
        .unwrap();
    owner
        .handle(&report(&permit, 2, UpgradeOutcome::Completed))
        .unwrap();
    let disconnect = UpgradeIncoming {
        connection_generation: GENERATION,
        request_token: 0,
        peer_euid: 501,
        event: UpgradeEvent::Disconnected,
    };
    assert!(owner.handle(&disconnect).unwrap().is_none());
    assert_eq!(memory.record().phase, Phase::OsCompleted);
    assert!(owner.poisoned);
    let (mut unconnected, untouched) = start(fixture());
    unconnected.lost().unwrap();
    assert!(unconnected.poisoned);
    assert!(unconnected
        .handle(&incoming(1, UpgradeRequest::Plan))
        .is_err());
    assert!(untouched.events().is_empty());
    assert_eq!(untouched.record().phase, Phase::CandidatePlaced);
}

#[test]
fn config_failure_before_or_after_write_never_returns_inspected_and_poisons_owner() {
    for when in [Failure::Before, Failure::After] {
        let (mut owner, memory) = start(terminal(UpgradeOutcome::Completed));
        assert_eq!(plan(&mut owner).0, UpgradeMode::Reconcile);
        memory.0.borrow_mut().fail_config = Some(when);
        let request = inspect_request(&owner.record, InspectTarget::Candidate);
        assert!(owner.handle(&incoming(2, request.clone())).is_err());
        assert!(owner.poisoned);
        assert_eq!(memory.record().phase, Phase::OsCompleted);
        assert!(memory.record().reconciliation.is_some());
        assert_eq!(memory.0.borrow().config_written, when == Failure::After);
        let events = memory.events();
        assert!(
            events
                .iter()
                .position(|v| *v == "persist_confirmed")
                .unwrap()
                < events.iter().position(|v| *v == "config_started").unwrap()
        );
        assert!(owner.handle(&incoming(3, request)).is_err());
        memory.0.borrow_mut().fail_config = None;
        let mut resumed =
            Owner::new(memory.record(), memory.clone(), BOOT.into(), "e".repeat(64)).unwrap();
        assert_eq!(plan(&mut resumed).0, UpgradeMode::Reconcile);
        let request = inspect_request(&resumed.record, InspectTarget::Candidate);
        assert_eq!(
            resumed.handle(&incoming(4, request)).unwrap(),
            Some(UpgradeReply::Inspected)
        );
        assert_eq!(memory.record().phase, Phase::ConfigCommitted);
    }
}

#[test]
fn reconciliation_write_failures_stop_before_config_or_inspected_reply() {
    for (write, when) in [
        (1, Failure::Before),
        (1, Failure::After),
        (2, Failure::Before),
        (2, Failure::After),
    ] {
        let (mut owner, memory) = start(terminal(UpgradeOutcome::Completed));
        plan(&mut owner);
        memory.0.borrow_mut().fail_write = Some((write, when));
        let request = inspect_request(&owner.record, InspectTarget::Candidate);
        assert!(owner.handle(&incoming(2, request)).is_err());
        assert!(owner.poisoned);
        assert_eq!(memory.0.borrow().config_written, write == 2);
        assert_eq!(
            memory.record().phase,
            if write == 2 && when == Failure::After {
                Phase::ConfigCommitted
            } else {
                Phase::OsCompleted
            }
        );
        assert!(owner.handle(&incoming(3, UpgradeRequest::Plan)).is_err());
    }
}

#[test]
fn failed_sdk_result_requires_exact_old_proof_then_bound_restore_and_persist() {
    let failed = terminal(UpgradeOutcome::Failed);
    for when in [Failure::Before, Failure::After] {
        let (mut owner, memory) = start(failed.clone());
        plan(&mut owner);
        memory.0.borrow_mut().fail_restore = Some(when);
        let request = inspect_request(&owner.record, InspectTarget::Original);
        assert!(owner.handle(&incoming(2, request)).is_err());
        assert!(owner.poisoned);
        assert_eq!(memory.record().phase, Phase::OsFailed);
        assert_eq!(memory.0.borrow().original_restored, when == Failure::After);
        assert_eq!(memory.0.borrow().rollback_intent, when == Failure::After);
        assert!(owner.handle(&incoming(3, UpgradeRequest::Plan)).is_err());
    }
    let (mut owner, memory) = start(failed);
    plan(&mut owner);
    let mut invalid = inspect_request(&owner.record, InspectTarget::Original);
    let UpgradeRequest::Inspect { filter, .. } = &mut invalid else {
        unreachable!()
    };
    *filter = FilterState::Absent;
    assert!(owner.handle(&incoming(2, invalid)).is_err());
    assert!(!memory.events().contains(&"restore_started"));
    let valid = inspect_request(&owner.record, InspectTarget::Original);
    assert_eq!(
        owner.handle(&incoming(3, valid)).unwrap(),
        Some(UpgradeReply::Inspected)
    );
    assert_eq!(memory.record().phase, Phase::Aborted);
    let events = memory.events();
    assert!(
        events
            .iter()
            .position(|v| *v == "rollback_intent_visible")
            .unwrap()
            < events.iter().position(|v| *v == "restore_visible").unwrap()
    );
    assert_eq!(events.last(), Some(&"persist_confirmed"));
}

#[test]
fn rollback_journal_write_error_never_acknowledges_even_after_restoration() {
    for when in [Failure::Before, Failure::After] {
        let (mut owner, memory) = start(terminal(UpgradeOutcome::Failed));
        plan(&mut owner);
        memory.fail_next_write(when);
        let request = inspect_request(&owner.record, InspectTarget::Original);
        assert!(owner.handle(&incoming(2, request)).is_err());
        assert!(owner.poisoned);
        assert!(memory.0.borrow().original_restored);
        assert_eq!(
            memory.record().phase,
            if when == Failure::After {
                Phase::Aborted
            } else {
                Phase::OsFailed
            }
        );
        owner.lost().unwrap();
        assert!(owner.handle(&incoming(3, UpgradeRequest::Plan)).is_err());
    }
}

#[test]
fn failed_native_revalidation_or_durable_compare_never_grants_permit() {
    let (mut owner, memory, hash) = ready();
    memory.0.borrow_mut().fail_before_permit = true;
    assert!(claim(&mut owner, &hash).is_err());
    assert_eq!(memory.0.borrow().writes, 0);
    assert!(memory.record().attempt.is_none());
    // The consumed inspection cannot silently be reused after this failure.
    memory.0.borrow_mut().fail_before_permit = false;
    assert!(claim(&mut owner, &hash).is_err());
    assert_eq!(memory.0.borrow().writes, 0);
    let (mut owner, memory, hash) = ready();
    memory.0.borrow_mut().durable.phase = Phase::Aborted;
    assert!(claim(&mut owner, &hash).is_err());
    assert!(owner.poisoned);
    assert_eq!(memory.record().phase, Phase::Aborted);
}

#[test]
fn boot_barrier_and_missing_replacement_callback_are_not_bypassed_by_reconnect() {
    let reboot = terminal(UpgradeOutcome::RebootRequired);
    let memory = Memory::new(reboot.clone());
    assert!(Owner::new(reboot.clone(), memory.clone(), BOOT.into(), "e".repeat(64)).is_err());
    let mut later = Owner::new(reboot, memory.clone(), NEXT_BOOT.into(), "e".repeat(64)).unwrap();
    let (mode, hash) = plan(&mut later);
    assert_eq!(mode, UpgradeMode::Reconcile);
    assert!(claim(&mut later, &hash).is_err());
    let (mut owner, memory, permit) = claimed();
    assert_eq!(
        owner
            .handle(&report(&permit, 1, UpgradeOutcome::Completed))
            .unwrap(),
        Some(UpgradeReply::Recorded)
    );
    assert_eq!(memory.record().phase, Phase::Unexpected);
    owner.lost().unwrap();
    assert_eq!(memory.record().phase, Phase::Unexpected);
    assert!(Owner::new(memory.record(), memory.clone(), BOOT.into(), "f".repeat(64)).is_err());
    let mut later = Owner::new(
        memory.record(),
        memory.clone(),
        NEXT_BOOT.into(),
        "f".repeat(64),
    )
    .unwrap();
    assert_eq!(plan(&mut later).0, UpgradeMode::Reconcile);
    let request = inspect_request(&later.record, InspectTarget::Candidate);
    assert_eq!(
        later.handle(&incoming(2, request)).unwrap(),
        Some(UpgradeReply::Inspected)
    );
    assert!(memory
        .record()
        .attempt
        .as_ref()
        .unwrap()
        .replacement
        .is_none());
}
