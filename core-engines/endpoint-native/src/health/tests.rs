use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
fn fixture() -> (tempfile::TempDir, service::Plan) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["watched", "state", "db"] {
        fs::create_dir(root.join(name)).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let owner = unsafe { libc::geteuid() };
    let plan = service::Plan {
        engine_libraries: Vec::new(),
        engine_certificates: None,
        schema: 1,
        policy: Policy {
            roots: vec![root.join("watched")],
            state: root.join("state"),
            socket: root.join("runtime/clamd.sock"),
            scanner_uid: if owner == 1234 { 1235 } else { 1234 },
            scan_timeout_ms: 1000,
        },
        daemon: root.join("clamd"),
        database: root.join("db"),
        scanner_gid: 1234,
        startup_secs: 5,
    };
    (temp, plan)
}
fn proof(plan: &service::Plan, m: &Manifest) -> Proof {
    let time = now_ms();
    let checks = m
        .roots
        .iter()
        .enumerate()
        .flat_map(|(root, r)| {
            operations().into_iter().map(move |operation| {
                let (good, bad) = indices(&operation);
                let make = |s: &files::Sample, pid| Attempt {
                    schema: 1,
                    nonce: "a".repeat(64),
                    operation: operation.clone(),
                    path: s.path.clone(),
                    identity: s.identity.clone(),
                    actor: receipt::Actor {
                        pid,
                        uid: m.owner_uid,
                        pidversion: 2,
                    },
                    time_ms: time,
                };
                let clean = make(&r.samples[good], 44);
                let blocked = make(&r.samples[bad], 45);
                let receipt = Receipt {
                    schema: 1,
                    id: "b".repeat(64),
                    policy_sha256: m.policy_sha256.clone(),
                    time_ms: time,
                    operation: name(&operation).into(),
                    response_delivered: true,
                    actor: blocked.actor.clone(),
                    path: blocked.path.display().to_string(),
                    identity: blocked.identity.clone(),
                    verdict: Some(crate::Verdict {
                        sha256: r.samples[bad].sha256.clone(),
                        bytes: blocked.identity.size,
                        detection: r.samples[bad].detection.clone(),
                    }),
                    error: String::new(),
                };
                Check {
                    root,
                    operation,
                    clean,
                    blocked,
                    receipt,
                }
            })
        })
        .collect();
    let _ = plan;
    Proof {
        schema: 1,
        manifest_sha256: hash(&serde_json::to_vec(m).unwrap()),
        started_ms: time,
        checked_ms: time,
        supervisor_pid: 42,
        adapter_pid: 43,
        boot: service::boot().unwrap(),
        checks,
    }
}
#[test]
fn all_roots_need_complete_fresh_operation_specific_proof() {
    let (_temp, mut plan) = fixture();
    let second = plan.policy.roots[0].parent().unwrap().join("second");
    fs::create_dir(&second).unwrap();
    plan.policy.roots.push(second);
    let prepared = prepare(&plan).unwrap();
    let manifest = &prepared.manifest;
    let original = proof(&plan, manifest);
    validate_proof(&original, manifest, &plan, 42, 43, now_ms()).unwrap();
    for field in 0..13 {
        let mut p = original.clone();
        match field {
            0 => {
                p.checks.pop();
            }
            1 => p.checks[3] = p.checks[0].clone(),
            2 => p.checks[0].receipt.response_delivered = false,
            3 => p.checks[0].receipt.actor.pidversion += 1,
            4 => p.checks[0].clean.identity.inode += 1,
            5 => p.checks[0].receipt.verdict.as_mut().unwrap().sha256 = "c".repeat(64),
            6 => p.adapter_pid += 1,
            7 => p.supervisor_pid += 1,
            8 => p.manifest_sha256 = "d".repeat(64),
            9 => p.boot = "00000000-0000-0000-0000-000000000000".into(),
            10 => {
                p.checked_ms += CYCLE_MS + 1;
            }
            11 => p.checks[0].blocked.operation = Operation::Mmap,
            _ => p.checks[0].clean.actor.uid = plan.policy.scanner_uid,
        }
        assert!(
            validate_proof(&p, manifest, &plan, 42, 43, now_ms()).is_err(),
            "field {field}"
        );
    }
    assert!(validate_proof(
        &original,
        manifest,
        &plan,
        42,
        43,
        original.checked_ms + MAX_AGE_MS + 1
    )
    .is_err());
}
#[test]
fn synthetic_routing_never_uses_just_a_name_or_path_prefix() {
    let (_temp, plan) = fixture();
    let prepared = prepare(&plan).unwrap();
    let m = &prepared.manifest;
    let p = proof(&plan, m);
    let event = &p.checks[0].receipt;
    assert!(m.is_probe(event));
    for field in 0..6 {
        let mut e = event.clone();
        match field {
            0 => e.identity.inode += 1,
            1 => e.verdict.as_mut().unwrap().sha256 = "f".repeat(64),
            2 => e.path.push_str(".other"),
            3 => e.actor.uid += 1,
            4 => e.policy_sha256 = "e".repeat(64),
            _ => e.verdict.as_mut().unwrap().detection = Some("OtherThreat".into()),
        }
        assert!(!m.is_probe(&e), "field {field}");
    }
}
#[test]
fn preparation_refuses_links_preserves_foreign_bytes_and_binds_restart_samples() {
    let (_temp, plan) = fixture();
    let first = prepare(&plan).unwrap();
    let old = first.manifest.clone();
    let path = first.manifest.roots[0].samples[0].path.clone();
    let outside = plan.policy.state.join("unrelated");
    fs::write(&outside, b"unrelated bytes").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&path).unwrap();
    fs::hard_link(&outside, &path).unwrap();
    assert!(prepare(&plan).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"unrelated bytes");
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    assert!(prepare(&plan).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"unrelated bytes");
    fs::remove_file(&path).unwrap();
    let next = prepare(&plan).unwrap();
    assert_ne!(old.session, next.manifest.session);
    assert!(old.validate(&plan.policy).is_err());
    assert_eq!(
        fs::metadata(plan.database.join("athernex-health.hsb"))
            .unwrap()
            .mode()
            & 0o777,
        0o644
    );
    let original = next.manifest.roots[0].directory.path.clone();
    fs::rename(&original, original.with_extension("moved")).unwrap();
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(next.manifest.validate(&plan.policy).is_err());
}
#[test]
fn probe_directory_symlink_cannot_redirect_writes() {
    let (_temp, plan) = fixture();
    let folder = format!(
        ".athernex-native-check-{}",
        hash(plan.policy.state.as_os_str().as_encoded_bytes())
    );
    std::os::unix::fs::symlink(&plan.policy.state, plan.policy.roots[0].join(folder)).unwrap();
    assert!(prepare(&plan).is_err());
    assert!(!plan.policy.state.join("clean-text").exists());
}

#[test]
fn immutable_proofs_survive_status_transition_but_authorization_gaps_invalidate_them() {
    let (_temp, plan) = fixture();
    let prepared = prepare(&plan).unwrap();
    let mut p = proof(&plan, &prepared.manifest);
    let status_path = plan.policy.state.join("native-status.json");
    let coverage = crate::coverage::Snapshot::begin(None, &plan.policy, 43, 7, false, now_ms())
        .unwrap()
        .observe(crate::coverage::Loss::default(), true, true, now_ms())
        .unwrap();
    coverage.save(&plan.policy.state).unwrap();
    let mut status = serde_json::json!({"schema":1,"pid":43,"pidversion":7,"coverage_session":coverage.evidence.session,"coverage_revision":coverage.evidence.revision,"coverage_current":true,"scope_valid":true,"roots":plan.policy.roots,"scanner_uid":plan.policy.scanner_uid,"checked_ms":now_ms(),"response_errors":0,"event_gaps":0,"evidence_dropped":0});
    service::write(&status_path, &serde_json::to_vec(&status).unwrap(), 0o600).unwrap();
    let first = publish_proof(&plan.policy.state, &p).unwrap();
    let pending = plan.policy.state.join("health/proofs").join(format!(
        "{}.{}.pending",
        "f".repeat(64),
        "a".repeat(32)
    ));
    fs::write(&pending, b"interrupted publication").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    p.checks[0].clean.nonce = "c".repeat(64);
    let second = publish_proof(&plan.policy.state, &p).unwrap();
    assert!(!pending.exists());
    assert_ne!(first.sha256, second.sha256);
    observe(&plan, &first, 42, 43).unwrap();
    observe(&plan, &second, 42, 43).unwrap();
    status["coverage_session"] = serde_json::json!("f".repeat(64));
    service::write(&status_path, &serde_json::to_vec(&status).unwrap(), 0o600).unwrap();
    assert!(observe(&plan, &first, 42, 43).is_err());
    status["coverage_session"] = serde_json::json!(coverage.evidence.session);
    status["coverage_current"] = serde_json::json!(false);
    service::write(&status_path, &serde_json::to_vec(&status).unwrap(), 0o600).unwrap();
    assert!(observe(&plan, &first, 42, 43).is_err());
    status["coverage_current"] = serde_json::json!(true);
    service::write(&status_path, &serde_json::to_vec(&status).unwrap(), 0o600).unwrap();
    let path = plan
        .policy
        .state
        .join("health/proofs")
        .join(format!("{}.json", second.sha256));
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, b"{}").unwrap();
    assert!(observe(&plan, &second, 42, 43).is_err());
    observe(&plan, &first, 42, 43).unwrap();
    fs::write(&path, bytes).unwrap();
    status["event_gaps"] = serde_json::json!(1);
    service::write(&status_path, &serde_json::to_vec(&status).unwrap(), 0o600).unwrap();
    assert!(observe(&plan, &first, 42, 43).is_err());
    status["event_gaps"] = serde_json::json!(0);
    service::write(&status_path, &serde_json::to_vec(&status).unwrap(), 0o600).unwrap();
    fs::write(
        &prepared.manifest.roots[0].samples[0].path,
        b"changed sample",
    )
    .unwrap();
    assert!(observe(&plan, &first, 42, 43).is_err());
}
