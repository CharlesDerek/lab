use super::*;

fn journal(directory: &Directory, binary: &Path) -> Record {
    let identity = directory.identity().unwrap();
    Record {
        schema: 1,
        id: "a".repeat(64),
        source_sha256: crate::file_hash(binary).unwrap(),
        server: "https://example.com/".into(),
        agent_directory: r"C:\Program Files\Athernex Endpoint".into(),
        state_volume: identity.volume,
        state_file_id: identity.file_id,
        phase: Phase::Preparing,
        windows_filter_sha256: None,
        windows_filter_deployment: None,
    }
}
fn fixture() -> (tempfile::TempDir, Directory, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let state =
        Directory::maintenance_under(&std::path::absolute(temp.path()).unwrap(), "state").unwrap();
    let binary = temp.path().join("source.exe");
    fs::write(&binary, b"immutable fixture source").unwrap();
    (temp, state, binary)
}
#[test]
fn interrupted_install_requires_same_source_and_never_recreates_installed_identity() {
    let (_temp, state, binary) = fixture();
    assert!(preflight(state.path(), &binary).unwrap());
    let lease = Lease::acquire(state).unwrap();
    assert!(Lease::acquire(Directory::open(lease.state()).unwrap()).is_err());
    assert!(preflight(lease.state(), &binary).unwrap());
    let mut saved = journal(&lease.directory, &binary);
    lease
        .directory
        .write_maintenance_json(RECORD, &saved)
        .unwrap();
    assert!(preflight(lease.state(), &binary).unwrap());
    assert!(require_complete(lease.state()).is_err());
    fs::write(&binary, b"other source").unwrap();
    assert!(preflight(lease.state(), &binary).is_err());
    fs::write(&binary, b"immutable fixture source").unwrap();
    for phase in [Phase::Installing, Phase::Complete] {
        saved.phase = phase;
        lease
            .directory
            .write_maintenance_json(RECORD, &saved)
            .unwrap();
        assert!(
            preflight(lease.state(), &binary).is_err(),
            "Missing installed config must not reset identity"
        );
    }
    // A configured endpoint never skips the ordinary signed update checks.
    lease
        .directory
        .write_maintenance_json("config.json", &serde_json::json!({}))
        .unwrap();
    assert!(!preflight(lease.state(), &binary).unwrap());
    assert!(update::installer_check(lease.state(), &binary, false).is_err());
}
#[test]
fn installer_owns_service_leases_and_pending_journal_survives_guard_release() {
    let (_temp, state, binary) = fixture();
    let lease = Lease::acquire(state).unwrap();
    assert!(crate::windows_service::lease(&lease.directory).is_err());
    let mut saved = journal(&lease.directory, &binary);
    lease
        .directory
        .write_maintenance_json(RECORD, &saved)
        .unwrap();
    let guard = update::InstallerGuard::acquire(&lease).unwrap();
    assert!(crate::Store::open(lease.state()).is_err());
    assert!(crate::guardian::quiescent(lease.state()).is_err());
    assert!(crate::protection::windows::quiescent(lease.state()).is_err());
    assert!(update::maintenance_lock(lease.state()).is_err());
    assert!(update::controller_startup(lease.state()).is_err());
    assert!(crate::guardian::launch(lease.state(), &binary, &binary).is_err());
    drop(guard);
    assert!(update::require_recovered(lease.state()).is_err());
    assert!(setup::open_store(lease.state()).is_err());
    let guard = update::InstallerGuard::acquire(&lease).unwrap();
    saved.phase = Phase::Complete;
    lease
        .directory
        .write_maintenance_json(RECORD, &saved)
        .unwrap();
    require_complete(lease.state()).unwrap();
    // Even after readiness is committed, live ownership excludes mutations.
    assert!(update::maintenance_lock(lease.state()).is_err());
    drop(guard);
    update::maintenance_lock(lease.state()).unwrap();
    crate::Store::open(lease.state()).unwrap();
}

#[test]
fn scm_host_and_installer_exclude_each_other_even_before_launcher_startup() {
    let (_temp, state, binary) = fixture();
    let host = crate::windows_service::lease(&state).unwrap();
    assert!(Lease::acquire(Directory::open(state.path()).unwrap()).is_err());
    assert!(!state.path().join(RECORD).exists());
    drop(host);
    assert!(preflight(state.path(), &binary).unwrap());
    let install = Lease::acquire(Directory::open(state.path()).unwrap()).unwrap();
    assert!(crate::windows_service::lease(&state).is_err());
    drop(install);
    crate::windows_service::lease(&state).unwrap();
}

#[test]
fn reserved_service_lock_does_not_allow_nonempty_unknown_state_to_be_adopted() {
    let (_temp, state, binary) = fixture();
    state
        .write_maintenance(crate::windows_service::LOCK, b"not a lock")
        .unwrap();
    assert!(preflight(state.path(), &binary).is_err());
    assert!(Lease::acquire(Directory::open(state.path()).unwrap()).is_err());
    assert_eq!(
        fs::read(state.path().join(crate::windows_service::LOCK)).unwrap(),
        b"not a lock"
    );
}
#[test]
fn standalone_setup_creates_private_state_but_cannot_bypass_a_pending_install() {
    let temp = tempfile::tempdir().unwrap();
    let path = std::path::absolute(temp.path())
        .unwrap()
        .join("fresh-state");
    let store = setup::open_store(&path).unwrap();
    let directory = Directory::open(&path).unwrap();
    assert!(setup::open_store(&path).is_err());
    assert!(Lease::acquire(Directory::open(&path).unwrap()).is_err());
    drop(store);
    let binary = temp.path().join("source.exe");
    fs::write(&binary, b"fixture").unwrap();
    directory
        .write_maintenance_json(RECORD, &journal(&directory, &binary))
        .unwrap();
    assert!(setup::open_store(&path).is_err());
}
#[test]
fn foreign_malformed_and_unknown_state_is_retained_for_recovery() {
    let (_temp, state, binary) = fixture();
    state
        .write_maintenance("retained.bin", b"evidence")
        .unwrap();
    assert!(preflight(state.path(), &binary).is_err());
    state.remove("retained.bin").unwrap();
    let mut saved = journal(&state, &binary);
    saved.state_file_id[0] ^= 1;
    state.write_maintenance_json(RECORD, &saved).unwrap();
    assert!(preflight(state.path(), &binary).is_err());
    assert!(require_complete(state.path()).is_err());
    state.write_maintenance(RECORD, b"partial").unwrap();
    assert!(require_complete(state.path()).is_err());
    assert_eq!(fs::read(state.path().join(RECORD)).unwrap(), b"partial");
}
