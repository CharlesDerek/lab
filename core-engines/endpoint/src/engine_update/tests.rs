use super::*;

struct Fixture {
    _temp: tempfile::TempDir,
    state: PathBuf,
    source: PathBuf,
    root: PathBuf,
    manifest: PathBuf,
    release: SignedRelease,
    before: String,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let state = base.join("state");
    let source = base.join("source");
    let root = base.join("releases");
    fs::create_dir(&state).unwrap();
    fs::create_dir(&source).unwrap();
    let (key, public) = protocol::update::generate_key().unwrap();
    let roles = wire::Roles {
        scanner: "bin/clamscan".into(),
        updater: "bin/freshclam".into(),
        daemon: "sbin/clamd".into(),
        monitor: cfg!(target_os = "linux").then(|| "sbin/clamonacc".into()),
        library_dirs: vec!["lib".into()],
        certificates: "etc/certs".into(),
    };
    let mut names = vec![
        roles.scanner.clone(),
        roles.updater.clone(),
        roles.daemon.clone(),
        "lib/libfixture.so".into(),
        "etc/certs/clamav.crt".into(),
    ];
    names.extend(roles.monitor.iter().cloned());
    names.sort();
    let files = names
        .iter()
        .map(|name| {
            let path = source.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, name.as_bytes()).unwrap();
            wire::File {
                path: name.clone(),
                sha256: protocol::hash(name.as_bytes()),
                bytes: name.len() as u64,
                executable: !name.starts_with("lib/") && !name.starts_with("etc/"),
            }
        })
        .collect();
    let release = SignedRelease::sign(
        wire::Release {
            schema: 1,
            protocol: protocol::PROTOCOL,
            engine: "clamav".into(),
            target: protocol::update::target(),
            version: "fixture".into(),
            channel: "stable".into(),
            sequence: 1,
            issued_ms: now_ms(),
            expires_ms: now_ms() + 60_000,
            roles,
            files,
        },
        &key,
    )
    .unwrap();
    let config = serde_json::json!({"server":"http://127.0.0.1:1/","endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"scanner":base.join("old-scanner"),"updater":base.join("old-updater"),"scan_roots":[base.join("watched")],"allow_scripts":false,
        "engine_updates":{"public_key":public,"root":root,"allow_unsigned_native":true}});
    let before = serde_json::to_string(&config).unwrap();
    private_write(&state.join("config.json"), before.as_bytes()).unwrap();
    let manifest = base.join("release.json");
    fs::write(&manifest, serde_json::to_vec(&release).unwrap()).unwrap();
    Fixture {
        _temp: temp,
        state,
        source,
        root,
        manifest,
        release,
        before,
    }
}
fn prepare(f: &Fixture) {
    stage(&f.state, &f.manifest, &f.source).unwrap();
}
fn transaction(f: &Fixture) -> Status {
    let mut record = status(&f.state).unwrap();
    let candidate = candidate_config(&f.before, &f.root, &f.release).unwrap();
    record.transaction = Some(Activation {
        release: f.release.clone(),
        before: f.before.clone(),
        after_sha256: protocol::hash(&serde_json::to_vec_pretty(&candidate).unwrap()),
        token: crate::secret().unwrap(),
        owner_pid: std::process::id(),
        expires_ms: now_ms() + 240_000,
    });
    record.phase = "verifying".into();
    save(&f.state, &mut record).unwrap();
    record
}

#[cfg(any(target_os = "linux", windows))]
fn automatic_fixture() -> Fixture {
    let mut f = fixture();
    let mut config: serde_json::Value = serde_json::from_str(&f.before).unwrap();
    config["engine_updates"]["automatic"] = true.into();
    f.before = serde_json::to_string(&config).unwrap();
    private_write(&f.state.join("config.json"), f.before.as_bytes()).unwrap();
    prepare(&f);
    f
}
#[cfg(any(target_os = "linux", windows))]
fn controller(f: &Fixture) -> (crate::StateLock, String) {
    let directory = f.state.join("supervisor");
    fs::create_dir_all(&directory).unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("controller.lock"))
        .unwrap();
    file.try_lock().unwrap();
    let token = crate::secret().unwrap();
    private_write(
        &directory.join("lease.json"),
        &serde_json::to_vec(&serde_json::json!({
            "token":token,"controller_pid":std::process::id(),"child_pid":null
        }))
        .unwrap(),
    )
    .unwrap();
    (crate::StateLock(file), token)
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn automatic_request_requires_opt_in_exact_release_and_bounded_authorization() {
    let disabled = fixture();
    prepare(&disabled);
    assert!(automatic::request(
        &disabled.state,
        &disabled.release.id().unwrap(),
        now_ms() + 30_000
    )
    .is_err());
    let f = automatic_fixture();
    let id = f.release.id().unwrap();
    for (id, deadline) in [
        ("a".repeat(64), now_ms() + 30_000),
        (id.clone(), now_ms() - 1),
        (id.clone(), now_ms() + 900_001),
        (id.clone(), f.release.release.expires_ms + 1),
    ] {
        assert!(automatic::request(&f.state, &id, deadline).is_err());
    }
    let deadline = now_ms() + 30_000;
    automatic::request(&f.state, &id, deadline).unwrap();
    automatic::request(&f.state, &id, deadline).unwrap();
    assert!(automatic::request(&f.state, &id, deadline + 1).is_err());
    assert!(discard(&f.state).is_err());
    assert!(apply(&f.state).is_err());
    assert_eq!(
        fs::read_to_string(f.state.join("config.json")).unwrap(),
        f.before
    );
    assert!(status(&f.state).unwrap().maintenance.unwrap().phase == automatic::Phase::Queued);
}
#[test]
#[cfg(any(target_os = "linux", windows))]
fn automatic_cancellation_is_exact_idempotent_and_stops_before_activation() {
    let f = automatic_fixture();
    let id = f.release.id().unwrap();
    automatic::request(&f.state, &id, now_ms() + 30_000).unwrap();
    assert!(automatic::cancel(&f.state, &"f".repeat(64)).is_err());
    automatic::cancel(&f.state, &id).unwrap();
    automatic::cancel(&f.state, &id).unwrap();
    assert!(!automatic::queued(&f.state).unwrap());
    automatic::request(&f.state, &id, now_ms() + 30_000).unwrap();
    let mut record = transaction(&f);
    record.maintenance.as_mut().unwrap().phase = automatic::Phase::Applying;
    save(&f.state, &mut record).unwrap();
    assert!(automatic::cancel(&f.state, &id).is_err());
}

#[cfg(any(target_os = "linux", windows))]
fn fleet_request(f: &Fixture) -> protocol::engine_fleet::Deployment {
    protocol::engine_fleet::Deployment {
        id: "c".repeat(64),
        endpoint_id: "a".repeat(64),
        release: f.release.clone(),
        install: true,
        created_ms: now_ms(),
        expires_ms: now_ms() + 30_000,
    }
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn fleet_request_binds_policy_and_retains_refusal_until_receipt_delivery() {
    let f = automatic_fixture();
    let deployment = fleet_request(&f);
    assert!(automatic::request_fleet(&f.state, &deployment).is_err());
    let mut config: Config = serde_json::from_str(&f.before).unwrap();
    config.engine_updates.managed = true;
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    for failure in 0..3 {
        let mut bad = deployment.clone();
        match failure {
            0 => bad.endpoint_id = "d".repeat(64),
            1 => bad.install = false,
            _ => bad.release.release.sequence += 1,
        }
        assert!(automatic::request_fleet(&f.state, &bad).is_err());
    }
    automatic::request_fleet(&f.state, &deployment).unwrap();
    automatic::request_fleet(&f.state, &deployment).unwrap();
    let mut changed = deployment.clone();
    changed.id = "d".repeat(64);
    assert!(automatic::request_fleet(&f.state, &changed).is_err());
    config.engine_updates.managed = false;
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    assert!(!automatic::eligible(&f.state).unwrap());
    let request = status(&f.state).unwrap().maintenance.unwrap();
    let receipt = request.receipt.unwrap();
    assert_eq!(receipt.deployment_id, deployment.id);
    assert_eq!(receipt.outcome, "refused");
    assert!(!request.acknowledged);
    assert!(automatic::request(&f.state, &request.release_id, deployment.expires_ms).is_err());
    assert!(stage(&f.state, &f.manifest, &f.source).is_err());
    assert!(discard(&f.state).is_err());
    assert!(prune(&f.state).is_err());
    assert!(require_settled(&f.state).is_err());
    require_start_allowed(&f.state).unwrap();
    automatic::request_fleet(&f.state, &deployment).unwrap();
    assert_eq!(
        status(&f.state).unwrap().maintenance.unwrap().receipt,
        Some(receipt)
    );
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn cancelled_fleet_request_keeps_immutable_result_and_rejects_corrupt_journal() {
    let f = automatic_fixture();
    let mut config: Config = serde_json::from_str(&f.before).unwrap();
    config.engine_updates.managed = true;
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let deployment = fleet_request(&f);
    automatic::request_fleet(&f.state, &deployment).unwrap();
    automatic::cancel(&f.state, &deployment.release.id().unwrap()).unwrap();
    let request = status(&f.state).unwrap().maintenance.unwrap();
    automatic::cancel(&f.state, &request.release_id).unwrap();
    assert_eq!(
        status(&f.state).unwrap().maintenance.unwrap().receipt,
        request.receipt
    );
    for corruption in 0..5 {
        let mut record = status(&f.state).unwrap();
        let mut changed = request.clone();
        match corruption {
            0 => changed.deployment.as_mut().unwrap().id = "f".repeat(64),
            1 => changed.receipt.as_mut().unwrap().finished_ms += 1,
            2 => changed.receipt.as_mut().unwrap().outcome = "installed".into(),
            3 => changed.receipt = None,
            _ => changed.deadline_ms += 1,
        }
        record.maintenance = Some(changed);
        save(&f.state, &mut record).unwrap();
        assert!(status(&f.state).is_err());
        record.maintenance = Some(request.clone());
        save(&f.state, &mut record).unwrap();
    }
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn fleet_cannot_adopt_a_local_request_for_the_same_release() {
    let f = automatic_fixture();
    let mut config: Config = serde_json::from_str(&f.before).unwrap();
    config.engine_updates.managed = true;
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let deployment = fleet_request(&f);
    let id = deployment.release.id().unwrap();
    automatic::request(&f.state, &id, deployment.expires_ms).unwrap();
    assert!(automatic::request_fleet(&f.state, &deployment).is_err());
    assert!(status(&f.state)
        .unwrap()
        .maintenance
        .unwrap()
        .deployment
        .is_none());
    automatic::cancel(&f.state, &id).unwrap();
    automatic::request_fleet(&f.state, &deployment).unwrap();
    let queued = status(&f.state).unwrap().maintenance.unwrap();
    assert!(queued.phase == automatic::Phase::Queued);
    assert_eq!(queued.deployment, Some(deployment));
    assert!(queued.receipt.is_none());
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn fleet_crash_recovery_is_offline_and_receipt_survives_expiry_and_restarts() {
    let mut f = automatic_fixture();
    let mut config: Config = serde_json::from_str(&f.before).unwrap();
    config.engine_updates.managed = true;
    f.before = serde_json::to_string(&config).unwrap();
    private_write(&f.state.join("config.json"), f.before.as_bytes()).unwrap();
    let deployment = fleet_request(&f);
    automatic::request_fleet(&f.state, &deployment).unwrap();
    let mut record = transaction(&f);
    let request = record.maintenance.as_mut().unwrap();
    request.phase = automatic::Phase::Applying;
    request.deadline_ms = now_ms() - 1;
    let expired = request.deployment.as_mut().unwrap();
    expired.created_ms = now_ms() - 60_000;
    expired.expires_ms = request.deadline_ms;
    save(&f.state, &mut record).unwrap();
    let after = candidate_config(&f.before, &f.root, &f.release).unwrap();
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec_pretty(&after).unwrap(),
    )
    .unwrap();
    let (_controller, token) = controller(&f);
    automatic::reconcile(&f.state, &token).unwrap();
    let receipt = status(&f.state)
        .unwrap()
        .maintenance
        .unwrap()
        .receipt
        .unwrap();
    assert_eq!(receipt.outcome, "rolled_back");
    assert_eq!(receipt.deployment_id, deployment.id);
    assert_eq!(
        fs::read_to_string(f.state.join("config.json")).unwrap(),
        f.before
    );
    automatic::reconcile(&f.state, &token).unwrap();
    automatic::maintain(&f.state, &token).unwrap();
    assert_eq!(
        status(&f.state).unwrap().maintenance.unwrap().receipt,
        Some(receipt)
    );
    assert!(require_settled(&f.state).is_err());
    require_start_allowed(&f.state).unwrap();
}
#[test]
#[cfg(any(target_os = "linux", windows))]
fn expired_revoked_and_contended_requests_do_not_require_service_interruption() {
    let f = automatic_fixture();
    let id = f.release.id().unwrap();
    automatic::request(&f.state, &id, now_ms() + 30_000).unwrap();
    let lock = update::maintenance_lock(&f.state).unwrap();
    assert!(!automatic::eligible(&f.state).unwrap());
    assert!(automatic::queued(&f.state).unwrap());
    drop(lock);
    let mut record = status(&f.state).unwrap();
    record.maintenance.as_mut().unwrap().deadline_ms = now_ms() - 1;
    save(&f.state, &mut record).unwrap();
    assert!(!automatic::eligible(&f.state).unwrap());
    assert!(status(&f.state).unwrap().maintenance.unwrap().phase == automatic::Phase::Refused);
    automatic::request(&f.state, &id, now_ms() + 30_000).unwrap();
    let mut config: Config = serde_json::from_str(&f.before).unwrap();
    config.engine_updates.automatic = false;
    let revoked = serde_json::to_vec(&config).unwrap();
    private_write(&f.state.join("config.json"), &revoked).unwrap();
    assert!(!automatic::eligible(&f.state).unwrap());
    assert_eq!(fs::read(f.state.join("config.json")).unwrap(), revoked);
    assert!(status(&f.state).unwrap().transaction.is_none());
}
#[test]
#[cfg(any(target_os = "linux", windows))]
fn only_owned_automatic_transactions_recover_at_controller_startup() {
    let f = automatic_fixture();
    let id = f.release.id().unwrap();
    let mut record = transaction(&f);
    assert!(automatic::reconcile(&f.state, &"f".repeat(64)).is_err());
    let (_controller, token) = controller(&f);
    assert!(automatic::reconcile(&f.state, &token).is_err());
    record.maintenance = Some(automatic::Request {
        release_id: id,
        deadline_ms: now_ms() - 1,
        phase: automatic::Phase::Applying,
        detail: String::new(),
        updated_ms: now_ms() - 1000,
        deployment: None,
        receipt: None,
        acknowledged: false,
    });
    save(&f.state, &mut record).unwrap();
    let after = candidate_config(&f.before, &f.root, &f.release).unwrap();
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec_pretty(&after).unwrap(),
    )
    .unwrap();
    automatic::reconcile(&f.state, &token).unwrap();
    automatic::reconcile(&f.state, &token).unwrap();
    let recovered = status(&f.state).unwrap();
    assert!(recovered.transaction.is_none());
    assert!(recovered.maintenance.unwrap().phase == automatic::Phase::RolledBack);
    assert_eq!(recovered.highwater, 1);
    assert_eq!(
        fs::read_to_string(f.state.join("config.json")).unwrap(),
        f.before
    );
}
#[test]
#[cfg(any(target_os = "linux", windows))]
fn automatic_preflight_failure_is_terminal_and_keeps_the_previous_configuration() {
    let f = automatic_fixture();
    let id = f.release.id().unwrap();
    automatic::request(&f.state, &id, now_ms() + 30_000).unwrap();
    assert!(automatic::maintain(&f.state, &"e".repeat(64)).is_err());
    let (_controller, token) = controller(&f);
    automatic::maintain(&f.state, &token).unwrap();
    assert!(status(&f.state).unwrap().maintenance.unwrap().phase == automatic::Phase::RolledBack);
    assert_eq!(
        fs::read_to_string(f.state.join("config.json")).unwrap(),
        f.before
    );
    assert!(!automatic::queued(&f.state).unwrap());
    automatic::maintain(&f.state, &token).unwrap();
    assert_eq!(status(&f.state).unwrap().highwater, 1);
}

#[test]
fn signed_staging_is_independent_idempotent_and_monotonic() {
    let f = fixture();
    prepare(&f);
    prepare(&f);
    assert_eq!(
        fs::read_to_string(f.state.join("config.json")).unwrap(),
        f.before
    );
    assert_eq!(status(&f.state).unwrap().phase, "staged");
    let name = &f.release.release.roles.scanner;
    fs::write(f.source.join(name), b"changed upstream bytes").unwrap();
    assert_eq!(
        fs::read(f.root.join(f.release.id().unwrap()).join(name)).unwrap(),
        name.as_bytes()
    );
    assert_eq!(update::status(&f.state).unwrap().highwater, 0);
    discard(&f.state).unwrap();
    assert!(!f.root.join(f.release.id().unwrap()).exists());
    assert_eq!(status(&f.state).unwrap().highwater, 1);
    assert!(stage(&f.state, &f.manifest, &f.source).is_err());
}
#[test]
fn interrupted_or_bad_copies_retry_without_changing_active_configuration() {
    let f = fixture();
    let name = &f.release.release.files[0].path;
    fs::write(f.source.join(name), b"wrong size").unwrap();
    assert!(stage(&f.state, &f.manifest, &f.source).is_err());
    let record = status(&f.state).unwrap();
    assert_eq!(record.highwater, 1);
    assert_eq!(record.phase, "staging");
    assert_eq!(
        fs::read_to_string(f.state.join("config.json")).unwrap(),
        f.before
    );
    fs::write(f.source.join(name), name.as_bytes()).unwrap();
    let pending = f.root.join(format!(".pending-{}", f.release.id().unwrap()));
    fs::write(pending.join(name), b"partial copy").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(pending.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }
    prepare(&f);
    assert_eq!(status(&f.state).unwrap().phase, "staged");
    check_layout(&f.root.join(f.release.id().unwrap()), &f.release, false).unwrap();
}
#[test]
fn tampered_manifests_and_shared_installation_roots_are_refused() {
    let f = fixture();
    let mut bad = f.release.clone();
    bad.release.version = "altered".into();
    fs::write(&f.manifest, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(stage(&f.state, &f.manifest, &f.source).is_err());
    assert_eq!(status(&f.state).unwrap().highwater, 0);
    fs::write(&f.manifest, serde_json::to_vec(&f.release).unwrap()).unwrap();
    prepare(&f);
    let other = f.state.with_file_name("other-state");
    fs::create_dir(&other).unwrap();
    private_write(&other.join("config.json"), f.before.as_bytes()).unwrap();
    assert!(stage(&other, &f.manifest, &f.source)
        .err()
        .unwrap()
        .to_string()
        .contains("belongs to another"));
    assert_eq!(status(&other).unwrap().highwater, 0);
}
#[cfg(unix)]
#[test]
fn linked_inputs_and_replaceable_managed_directories_are_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = fixture();
    let name = &f.release.release.files[0].path;
    let target = f.source.join(name);
    let displaced = f.source.join("original");
    fs::rename(&target, &displaced).unwrap();
    symlink(&displaced, &target).unwrap();
    assert!(stage(&f.state, &f.manifest, &f.source).is_err());
    fs::remove_file(&target).unwrap();
    fs::rename(displaced, &target).unwrap();
    prepare(&f);
    let directory = f.root.join(f.release.id().unwrap()).join("bin");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(check_layout(&f.root.join(f.release.id().unwrap()), &f.release, false).is_err());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    check_layout(&f.root.join(f.release.id().unwrap()), &f.release, false).unwrap();
}
#[test]
fn recovery_is_idempotent_before_after_and_during_configuration_rollback() {
    for boundary in 0..3 {
        let f = fixture();
        prepare(&f);
        let record = transaction(&f);
        let candidate = candidate_config(&f.before, &f.root, &f.release).unwrap();
        if boundary > 0 {
            private_write(
                &f.state.join("config.json"),
                &serde_json::to_vec_pretty(&candidate).unwrap(),
            )
            .unwrap();
        }
        if boundary == 2 {
            private_write(&f.state.join("config.json"), f.before.as_bytes()).unwrap();
        }
        assert!(require_start_allowed(&f.state).is_err());
        assert!(update::installer_check(
            &f.state,
            &f.source.join(&f.release.release.roles.scanner),
            false
        )
        .is_err());
        assert!(summary(&f.state).unwrap().get("transaction").is_none());
        assert!(record.transaction.is_some());
        recover(&f.state).unwrap();
        recover(&f.state).unwrap();
        let after = status(&f.state).unwrap();
        assert!(after.transaction.is_none());
        assert_eq!(after.phase, "rolled_back");
        assert_eq!(after.highwater, 1);
        assert_eq!(after.retired.len(), 1);
        assert_eq!(
            fs::read_to_string(f.state.join("config.json")).unwrap(),
            f.before
        );
        assert_eq!(update::status(&f.state).unwrap().highwater, 0);
    }
}
#[test]
fn recovery_preserves_concurrent_policy_edits_and_rejects_corrupted_journals() {
    let f = fixture();
    prepare(&f);
    let mut record = transaction(&f);
    let mut changed: serde_json::Value = serde_json::from_str(&f.before).unwrap();
    changed["allow_scripts"] = true.into();
    let changed = serde_json::to_vec(&changed).unwrap();
    private_write(&f.state.join("config.json"), &changed).unwrap();
    assert!(recover(&f.state).is_err());
    assert!(status(&f.state).unwrap().transaction.is_some());
    assert_eq!(fs::read(f.state.join("config.json")).unwrap(), changed);
    private_write(&f.state.join("config.json"), f.before.as_bytes()).unwrap();
    record.transaction.as_mut().unwrap().after_sha256 = "0".repeat(64);
    save(&f.state, &mut record).unwrap();
    assert!(recover(&f.state).is_err());
    assert!(status(&f.state).unwrap().transaction.is_some());
}
#[test]
fn cleanup_requires_stopped_services_and_preserves_unknown_files() {
    let f = fixture();
    prepare(&f);
    transaction(&f);
    recover(&f.state).unwrap();
    let owner = crate::Store::open(&f.state).unwrap();
    assert!(prune(&f.state).is_err());
    drop(owner);
    let controller = OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.state.join("supervisor/controller.lock"))
        .unwrap();
    controller.try_lock().unwrap();
    assert!(apply(&f.state).is_err());
    assert!(prune(&f.state).is_err());
    controller.unlock().unwrap();
    let version = f.root.join(f.release.id().unwrap());
    fs::write(version.join("unexpected"), b"preserve").unwrap();
    assert!(prune(&f.state).is_err());
    assert_eq!(fs::read(version.join("unexpected")).unwrap(), b"preserve");
    fs::remove_file(version.join("unexpected")).unwrap();
    prune(&f.state).unwrap();
    assert!(!version.exists());
    assert!(status(&f.state).unwrap().retired.is_empty());
    assert_eq!(status(&f.state).unwrap().highwater, 1);
}

#[test]
fn native_library_and_certificate_paths_are_bound_to_the_signed_selection() {
    let f = fixture();
    prepare(&f);
    let mut candidate = candidate_config(&f.before, &f.root, &f.release).unwrap();
    assert_eq!(
        candidate.engine_updates.active_certificates,
        Some(f.root.join(f.release.id().unwrap()).join("etc/certs"))
    );
    let mut record = status(&f.state).unwrap();
    record.installed = record.staged.take();
    record.phase = "installed".into();
    save(&f.state, &mut record).unwrap();
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec_pretty(&candidate).unwrap(),
    )
    .unwrap();
    require_start_allowed(&f.state).unwrap();
    candidate.engine_updates.active_libraries.clear();
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec_pretty(&candidate).unwrap(),
    )
    .unwrap();
    assert!(require_start_allowed(&f.state).is_err());
}

#[test]
fn universal_macos_targets_require_a_matching_bounded_member() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("universal");
    for wide in [false, true] {
        let mut bytes = vec![0u8; 512];
        bytes[..4].copy_from_slice(if wide {
            b"\xca\xfe\xba\xbf"
        } else {
            b"\xca\xfe\xba\xbe"
        });
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&0x01000007u32.to_be_bytes());
        if wide {
            bytes[16..24].copy_from_slice(&256u64.to_be_bytes());
            bytes[24..32].copy_from_slice(&64u64.to_be_bytes());
        } else {
            bytes[16..20].copy_from_slice(&256u32.to_be_bytes());
            bytes[20..24].copy_from_slice(&64u32.to_be_bytes());
        }
        bytes[256..260].copy_from_slice(b"\xcf\xfa\xed\xfe");
        bytes[260..264].copy_from_slice(&0x01000007u32.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        assert!(supports_target(&path, "macos-x86_64").unwrap());
        assert!(!supports_target(&path, "macos-aarch64").unwrap());
        bytes[8..12].copy_from_slice(&0x0100000cu32.to_be_bytes());
        fs::write(&path, &bytes).unwrap();
        assert!(!supports_target(&path, "macos-aarch64").unwrap());
        bytes[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        fs::write(&path, &bytes).unwrap();
        assert!(!supports_target(&path, "macos-x86_64").unwrap());
    }
}
