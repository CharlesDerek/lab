use athernex_endpoint_protocol::{
    self as p, EndpointEvent, Enrollment, Heartbeat, Platform, Receipt,
};
use athernex_siem::{ecosystem::IncidentRequest, engine::Engine};
use orchestrator::governor::{Class, Request, Resources};
const NOW: u64 = 1_800_000_000_000;
fn budget() -> Resources {
    Resources {
        cpu_millis: 1000,
        memory_mib: 256,
        ..Default::default()
    }
}
fn health() -> Heartbeat {
    Heartbeat {
        controller_updates: None,
        updates: None,
        protection: None,
        collector: None,
        version: "0.1.0".into(),
        capabilities: vec!["quarantine".into()],
        scanner: "fixture".into(),
        realtime: false,
        signature_version: "fixture".into(),
        spool_events: 0,
        error: String::new(),
    }
}
fn setup(e: &mut Engine) -> IncidentRequest {
    e.configure_mode(false).unwrap();
    let enrollment = Enrollment {
        protocol: 1,
        enrollment_token: e.create_enrollment(Platform::Linux, NOW).unwrap(),
        endpoint_id: "a".repeat(64),
        credential: "b".repeat(64),
        hostname: "fixture".into(),
        platform: Platform::Linux,
        arch: "x86_64".into(),
        version: "0.1.0".into(),
    };
    e.enroll_endpoint(&enrollment, NOW).unwrap();
    e.endpoint_heartbeat(&enrollment.endpoint_id, &health(), NOW)
        .unwrap();
    e.configure_pool("affected", budget(), Resources::default(), NOW)
        .unwrap();
    e.configure_pool("replacement", budget(), Resources::default(), NOW)
        .unwrap();
    e.bind_endpoint_pool(&enrollment.endpoint_id, "affected", NOW)
        .unwrap();
    let event = EndpointEvent {
        telemetry: None,
        id: "c".repeat(64),
        time_ms: NOW,
        kind: "malware".into(),
        path: "/fixture/sample".into(),
        sha256: p::hash(b"benign"),
        detection: "Fixture".into(),
        detail: "public fixture".into(),
    };
    e.endpoint_events(&enrollment.endpoint_id, &[event], NOW)
        .unwrap();
    let observation = e
        .endpoint_observations(&enrollment.endpoint_id, u64::MAX, 1)
        .unwrap()
        .remove(0);
    IncidentRequest {
        id: "incident-1".into(),
        endpoint: enrollment.endpoint_id,
        evidence_id: observation.evidence_id,
        replacement_pool: "replacement".into(),
        resources: budget(),
        expires_ms: NOW + 60000,
    }
}
#[test]
fn incident_approval_dispatch_restart_receipt_and_reviewed_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("siem.db");
    let mut e = Engine::open(&path).unwrap();
    let req = setup(&mut e);
    let proposal = e.propose_incident(&req, NOW).unwrap();
    let mut duplicate = req.clone();
    duplicate.id = "duplicate-evidence".into();
    assert!(e.propose_incident(&duplicate, NOW).is_err());
    assert_eq!(
        e.propose_incident(&req, NOW).unwrap().plan_hash,
        proposal.plan_hash
    );
    assert!(e
        .review_endpoint_action(&proposal.plan.command_id, true, NOW)
        .is_err());
    assert!(e
        .approve_incident(&req.id, "changed", "operator", NOW)
        .is_err());
    e.approve_incident(&req.id, &proposal.plan_hash, "operator", NOW)
        .unwrap();
    assert!(e
        .reserve_resources(
            &Request {
                id: "blocked".into(),
                pool: "affected".into(),
                class: Class::Batch,
                resources: budget(),
                expires_ms: NOW + 10000
            },
            NOW
        )
        .is_err());
    drop(e);
    let e = Engine::open(&path).unwrap();
    e.approve_incident(&req.id, &proposal.plan_hash, "operator", NOW + 1)
        .unwrap();
    let command = e
        .start_endpoint_command(&req.endpoint, &proposal.plan.command_id, NOW + 2)
        .unwrap();
    assert!(e
        .start_endpoint_command(&req.endpoint, &command.id, NOW + 3)
        .is_err());
    let receipt = Receipt {
        command_id: command.id,
        action_hash: command.action_hash,
        outcome: "succeeded".into(),
        output: "Retained verified private copy".into(),
        finished_ms: NOW + 4,
    };
    e.finish_endpoint_command(&req.endpoint, &receipt, NOW + 4)
        .unwrap();
    e.finish_endpoint_command(&req.endpoint, &receipt, NOW + 5)
        .unwrap();
    assert!(e
        .recover_incident(
            &req.id,
            &proposal.plan_hash,
            "operator",
            "Reviewed",
            NOW + 5
        )
        .is_err());
    e.endpoint_heartbeat(&req.endpoint, &health(), NOW + 6)
        .unwrap();
    let done = e
        .recover_incident(
            &req.id,
            &proposal.plan_hash,
            "operator",
            "Verified containment and fresh endpoint health",
            NOW + 7,
        )
        .unwrap();
    assert_eq!(done.state, "recovered");
    assert!(e
        .resource_pools()
        .unwrap()
        .iter()
        .all(|p| p.holds.is_empty()));
    assert_eq!(
        done.reservation.unwrap().state,
        "active",
        "replacement ownership needs its own explicit completion"
    );
    let case = e
        .cases()
        .unwrap()
        .into_iter()
        .find(|c| c.id == proposal.plan.case_id)
        .unwrap();
    assert!(case
        .notes
        .iter()
        .any(|n| n.text.contains("placement restored")));
}
#[test]
fn failed_admission_rolls_back_hold_and_command_approval_and_expiry_never_unholds() {
    let mut e = Engine::memory().unwrap();
    let req = setup(&mut e);
    let proposal = e.propose_incident(&req, NOW).unwrap();
    let occupied = e
        .reserve_resources(
            &Request {
                id: "occupied".into(),
                pool: "replacement".into(),
                class: Class::Batch,
                resources: budget(),
                expires_ms: NOW + 60000,
            },
            NOW,
        )
        .unwrap();
    assert!(e
        .approve_incident(&req.id, &proposal.plan_hash, "operator", NOW)
        .is_err());
    assert!(e
        .resource_pools()
        .unwrap()
        .iter()
        .all(|p| p.holds.is_empty()));
    assert_eq!(e.incident(&req.id).unwrap().response_state, "pending");
    e.release_resources("occupied", occupied.generation, NOW)
        .unwrap();
    e.approve_incident(&req.id, &proposal.plan_hash, "operator", NOW)
        .unwrap();
    assert!(e
        .start_endpoint_command(&req.endpoint, &proposal.plan.command_id, NOW + 60001)
        .is_err());
    assert!(e
        .resource_pools()
        .unwrap()
        .iter()
        .any(|p| !p.holds.is_empty()));
}
