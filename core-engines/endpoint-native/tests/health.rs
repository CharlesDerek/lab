#![cfg(any(target_os = "linux", target_os = "macos"))]
use athernex_endpoint_native::{health, service, Policy};
use std::{fs, os::unix::fs::PermissionsExt};
#[test]
fn prepared_samples_execute_and_map_before_protection_without_claiming_blocking() {
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
    let prepared = health::prepare(&plan).unwrap();
    health::baseline(
        &prepared,
        &plan.policy,
        std::path::Path::new(env!("CARGO_BIN_EXE_athernex-endpoint-native")),
    )
    .unwrap();
    assert_eq!(
        fs::read_dir(plan.policy.state.join("health/proofs"))
            .unwrap()
            .count(),
        0
    );
    assert!(health::observe(
        &plan,
        &health::Reference {
            checked_ms: 1,
            sha256: "a".repeat(64)
        },
        42,
        43
    )
    .is_err());
}
