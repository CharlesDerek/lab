use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn image_budget_does_not_expand_journals_or_replace_bytes_after_refusal() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("image");
    let bytes = vec![b'x'; 262145];
    assert!(write(&path, &bytes, 0o600).is_err());
    assert!(!path.exists());
    write_health_image(&path, &bytes).unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    assert!(write_health_image(&path, &vec![0; 16 * 1024 * 1024 + 1]).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

fn plan() -> Plan {
    Plan {
        engine_libraries: Vec::new(),
        engine_certificates: None,
        schema: 1,
        policy: Policy {
            roots: vec!["/watched".into()],
            socket: "/engine/runtime/clamd.sock".into(),
            state: "/private/native".into(),
            scanner_uid: 1234,
            scan_timeout_ms: 1000,
        },
        daemon: "/engine/bin/clamd".into(),
        database: "/engine/db".into(),
        scanner_gid: 1234,
        startup_secs: 5,
    }
}
#[test]
fn service_plan_refuses_privileged_identity_and_overlapping_runtime_scope() {
    let original = plan();
    original.validate().unwrap();
    for field in 0..6 {
        let mut p = original.clone();
        match field {
            0 => p.scanner_gid = 0,
            1 => p.policy.scanner_uid = u32::MAX,
            2 => p.policy.roots = vec!["/engine".into()],
            3 => p.daemon = "/engine/../clamd".into(),
            4 => p.startup_secs = 301,
            _ => p.policy.socket = "/engine/runtime/other.sock".into(),
        }
        assert!(p.validate().is_err());
    }
}
fn record(state: &Path, pgid: u32, boot: String) {
    let record = Group {
        schema: 1,
        boot,
        pgid,
        plan_sha256: "a".repeat(64),
    };
    let journal = Journal {
        sha256: digest(&record).unwrap(),
        record,
    };
    write(
        &state.join("service-scanner.json"),
        &serde_json::to_vec(&journal).unwrap(),
        0o600,
    )
    .unwrap();
}
#[test]
fn recovery_refuses_live_groups_without_signalling_them_and_accepts_completed_cleanup() {
    let _serial = child::TEST_SERIAL.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().canonicalize().unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let mut service = child::Service::start(Command::new("/bin/sleep").arg("30"), 1024).unwrap();
    let pid = service.pid().unwrap();
    record(&state, pid, boot().unwrap());
    assert!(previous_group(&state, "scanner")
        .unwrap_err()
        .to_string()
        .contains("still exists"));
    assert_eq!(service.poll().unwrap(), None);
    service.stop().unwrap();
    previous_group(&state, "scanner").unwrap();
}
#[test]
fn previous_boot_records_never_signal_a_reused_group() {
    let _serial = child::TEST_SERIAL.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().canonicalize().unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let mut service = child::Service::start(Command::new("/bin/sleep").arg("30"), 1024).unwrap();
    record(
        &state,
        service.pid().unwrap(),
        "00000000-0000-0000-0000-000000000000".into(),
    );
    previous_group(&state, "scanner").unwrap();
    assert_eq!(service.poll().unwrap(), None);
}
#[test]
fn damaged_group_record_cannot_authorize_a_restart() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().canonicalize().unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    record(&state, 2000000000, boot().unwrap());
    let path = state.join("service-scanner.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["record"]["pgid"] = serde_json::json!(2000000001u32);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(previous_group(&state, "scanner")
        .unwrap_err()
        .to_string()
        .contains("damaged"));
}

#[test]
fn engine_runtime_cannot_be_rebound_to_another_endpoint_or_scanner_identity() {
    let _serial = child::TEST_SERIAL.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut original = plan();
    original.database = root.join("db");
    original.policy.state = root.join("state");
    let lease = claim_engine(&original).unwrap();
    let mut other = original.clone();
    other.policy.state = root.join("other");
    assert!(claim_engine(&other).is_err());
    drop(lease);
    assert!(claim_engine(&other)
        .unwrap_err()
        .to_string()
        .contains("different endpoint"));
    other = original.clone();
    other.policy.scanner_uid = 1235;
    assert!(claim_engine(&other).is_err());
    assert!(claim_engine(&original).is_ok());
}

#[test]
fn service_observation_rejects_stale_changed_and_unowned_status() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().canonicalize().unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let mut p = plan();
    p.policy.state = state;
    publish(&p, "starting", None, None, "").unwrap();
    assert!(observe(&p).is_err());
    let _lease = lock(&p.policy.state, "supervisor").unwrap();
    assert_eq!(observe(&p).unwrap().phase, "starting");
    let path = p.policy.state.join("service-status.json");
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for (key, value) in [
        ("checked_ms", serde_json::json!(0)),
        ("boot", serde_json::json!("different-boot")),
        ("plan_sha256", serde_json::json!("a".repeat(64))),
        ("runtime_protection_verified", serde_json::json!(true)),
        ("phase", serde_json::json!("running-unverified")),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        write(&path, &serde_json::to_vec(&changed).unwrap(), 0o600).unwrap();
        assert!(observe(&p).is_err(), "{key}");
    }
}
