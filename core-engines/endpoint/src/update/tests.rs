use super::*;

#[cfg(windows)]
#[test]
fn disabled_windows_protection_still_excludes_native_preview_maintenance() {
    use athernex_endpoint_native::windows_state::Directory;
    let root = tempfile::tempdir().unwrap();
    let (state, binary, _, _) = setup(root.path());
    let configuration = config(&state).unwrap();
    assert!(!configuration.protection.enabled);
    let quiet = quiescent(&state, &configuration).unwrap();
    let protection = Directory::open(&state)
        .unwrap()
        .directory("protection")
        .unwrap();
    assert!(protection.lock("supervisor.lock").is_err());
    drop(quiet);
    let lease = protection.lock("supervisor.lock").unwrap();
    assert!(quiescent(&state, &configuration).is_err());
    assert!(recover(&state).is_err());
    assert!(installer_check(&state, &binary, true).is_err());
    drop(lease);
    let native = protection.directory("windows").unwrap();
    let scratch = native.directory("scratch-journal").unwrap();
    scratch
        .write_json("pending.json", &serde_json::json!({"partial":true}))
        .unwrap();
    for error in [
        quiescent(&state, &configuration).err().unwrap().to_string(),
        recover(&state).err().unwrap().to_string(),
        installer_check(&state, &binary, true)
            .err()
            .unwrap()
            .to_string(),
    ] {
        assert!(error.contains("still requires recovery"), "{error}");
    }
    assert!(scratch.path().join("pending.json").exists());
    scratch.remove("pending.json").unwrap();
    let mut quiet = offline_maintenance(&state, &configuration).unwrap();
    assert!(native.lock("scratch-worker.lock").is_err());
    quiet.release_services();
    let worker = native.lock("scratch-worker.lock").unwrap();
    assert!(quiet.reacquire(&state, &configuration).is_err());
    drop(worker);
    quiet.reacquire(&state, &configuration).unwrap();
    assert!(protection.lock("supervisor.lock").is_err());
}

fn controller_setup(root: &Path) -> (PathBuf, PathBuf, PathBuf, Vec<u8>, SignedRelease) {
    let (state, agent, bytes, release) = setup(root);
    let controller = agent.with_file_name("controller");
    fs::copy(&agent, &controller).unwrap();
    let mut config: Config =
        serde_json::from_slice(&fs::read(state.join("config.json")).unwrap()).unwrap();
    config.updates.controller_path = Some(controller.clone());
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    (state, agent, controller, bytes, release)
}

#[test]
fn controller_staging_keeps_independent_sequence_and_requires_local_path() {
    let root = tempfile::tempdir().unwrap();
    let (state, agent, controller, bytes, release) = controller_setup(root.path());
    let manifest = root.path().join("release.json");
    let binary = root.path().join("binary");
    fs::write(&manifest, serde_json::to_vec(&release).unwrap()).unwrap();
    fs::write(&binary, &bytes).unwrap();
    stage_component(&state, Component::Controller, &manifest, &binary).unwrap();
    assert_eq!(status(&state).unwrap().highwater, 0);
    assert_eq!(
        status_component(&state, Component::Controller)
            .unwrap()
            .highwater,
        2
    );
    stage(&state, &manifest, &binary).unwrap();
    assert_eq!(status(&state).unwrap().highwater, 2);
    assert_eq!(fs::read(&agent).unwrap(), executable(1));
    assert_eq!(fs::read(&controller).unwrap(), executable(1));
    let mut configuration = config(&state).unwrap();
    configuration.updates.controller_path = None;
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&configuration).unwrap(),
    )
    .unwrap();
    assert!(stage_component(&state, Component::Controller, &manifest, &binary).is_err());
    configuration.updates.controller_path = Some(agent);
    assert!(configuration.validate().is_err());
    #[cfg(unix)]
    {
        let alias = root.path().join("controller-alias");
        std::os::unix::fs::symlink(configuration.updates.install_path.as_ref().unwrap(), &alias)
            .unwrap();
        configuration.updates.controller_path = Some(alias);
        configuration.validate().unwrap();
        private_write(
            &state.join("config.json"),
            &serde_json::to_vec(&configuration).unwrap(),
        )
        .unwrap();
        assert!(Component::Controller.config(&state).is_err());
    }
}

#[test]
fn controller_recovery_covers_each_boundary_without_changing_agent_history() {
    for boundary in 0..6 {
        let root = tempfile::tempdir().unwrap();
        let (state, agent, controller, bytes, release) = controller_setup(root.path());
        let guard = lock(&state).unwrap();
        prepare_component(&state, Component::Controller).unwrap();
        let (next_path, backup_path) = transaction_paths(&controller, &release).unwrap();
        let backup = Backup {
            path: backup_path,
            sha256: crate::file_hash(&controller).unwrap(),
        };
        let mut record = UpdateStatus {
            highwater: 2,
            staged: Some(release.clone()),
            transaction: Some(Transaction {
                trial: None,
                release,
                install_path: controller.clone(),
                backup: backup.clone(),
                next_path: next_path.clone(),
            }),
            ..Default::default()
        };
        save_component(&state, Component::Controller, &mut record).unwrap();
        assert!(require_recovered(&state).is_err());
        assert!(controller_startup(&state).is_err());
        if boundary >= 1 {
            fs::write(
                &next_path,
                if boundary == 1 { &bytes[..30] } else { &bytes },
            )
            .unwrap();
            fs::set_permissions(&next_path, fs::metadata(&controller).unwrap().permissions())
                .unwrap();
        }
        if boundary >= 2 {
            fs::hard_link(&controller, &backup.path).unwrap();
        }
        if boundary >= 3 {
            fs::rename(&next_path, &controller).unwrap();
        }
        if boundary == 4 {
            fs::rename(&backup.path, &controller).unwrap();
        }
        if boundary == 5 {
            fs::remove_file(&controller).unwrap();
        }
        drop(guard);
        // A missing installed path is also a recoverable interruption.
        let recovered = recover_component(&state, Component::Controller).unwrap();
        assert_eq!(recovered.last_result, "rolled_back");
        assert_eq!(recovered.highwater, 2);
        assert_eq!(fs::read(&controller).unwrap(), executable(1));
        assert_eq!(fs::read(&agent).unwrap(), executable(1));
        assert_eq!(status(&state).unwrap().highwater, 0);
        assert!(!backup.path.exists() && !next_path.exists());
        recover_component(&state, Component::Controller).unwrap();
        require_recovered(&state).unwrap();
    }
}

#[test]
fn live_controller_and_management_exclude_controller_replacement_and_recovery() {
    let root = tempfile::tempdir().unwrap();
    let (state, _, _, _, _) = controller_setup(root.path());
    let owner = controller_quiescent(&state, Component::Controller).unwrap();
    for result in [
        apply_component(&state, Component::Controller),
        recover_component(&state, Component::Controller),
    ] {
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("Stop the endpoint controller")
                || message.contains("Stop the endpoint launcher")
        );
    }
    drop(owner);
    let _management = Store::open(&state).unwrap();
    assert!(recover_component(&state, Component::Controller)
        .unwrap_err()
        .to_string()
        .contains("Stop the endpoint service"));
}
fn executable(seed: u8) -> Vec<u8> {
    let mut bytes = vec![seed; 256];
    #[cfg(target_os = "linux")]
    {
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18..20].copy_from_slice(
            &(if cfg!(target_arch = "aarch64") {
                183u16
            } else {
                62u16
            })
            .to_le_bytes(),
        );
    }
    #[cfg(windows)]
    {
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..70].copy_from_slice(b"PE\0\0\x64\x86");
    }
    #[cfg(target_os = "macos")]
    {
        bytes[..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        bytes[4..8].copy_from_slice(
            &(if cfg!(target_arch = "aarch64") {
                0x100000cu32
            } else {
                0x1000007u32
            })
            .to_le_bytes(),
        );
    }
    bytes
}
fn setup(root: &Path) -> (PathBuf, PathBuf, Vec<u8>, SignedRelease) {
    let root = root.canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    let installed = root.join("installed");
    fs::write(&installed, executable(1)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (private, public) = wire::generate_key().unwrap();
    let config = serde_json::json!({"updates":{"public_key":public,"channel":"stable","install_path":installed,"minimum_sequence":0,"allow_unsigned_native":true},"server":"http://127.0.0.1:8787/","endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"scanner":installed,"updater":installed,"scan_roots":[root],"allow_scripts":false});
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let bytes = executable(2);
    let release = SignedRelease::sign(
        wire::Release {
            schema: 1,
            target: wire::target(),
            version: "test".into(),
            channel: "stable".into(),
            sequence: 2,
            issued_ms: now_ms(),
            expires_ms: now_ms() + 60_000,
            protocol: protocol::PROTOCOL,
            sha256: protocol::hash(&bytes),
            bytes: bytes.len() as u64,
        },
        &private,
    )
    .unwrap();
    (state, installed, bytes, release)
}
#[test]
fn staging_rejects_tampering_and_preserves_durable_sequence_on_retry() {
    let directory = tempfile::tempdir().unwrap();
    let (state, _, bytes, release) = setup(directory.path());
    let manifest = directory.path().join("release.json");
    let binary = directory.path().join("binary");
    fs::write(&manifest, serde_json::to_vec(&release).unwrap()).unwrap();
    fs::write(&binary, &bytes).unwrap();
    assert_eq!(stage(&state, &manifest, &binary).unwrap().highwater, 2);
    assert_eq!(stage(&state, &manifest, &binary).unwrap().highwater, 2);
    fs::write(&binary, executable(3)).unwrap();
    assert!(stage(&state, &manifest, &binary).is_err());
    assert_eq!(status(&state).unwrap().highwater, 2);
    assert_eq!(
        read_bounded(&state.join("updates/candidate.bin"), wire::MAX_BINARY).unwrap(),
        bytes
    );
    let mut changed = release;
    changed.release.sequence = 3;
    fs::write(&manifest, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(stage(&state, &manifest, &binary).is_err());
    assert_eq!(status(&state).unwrap().highwater, 2);
}
#[test]
fn recovery_is_idempotent_at_each_unconfirmed_replacement_boundary() {
    for boundary in 0..6 {
        let directory = tempfile::tempdir().unwrap();
        let (state, installed, bytes, release) = setup(directory.path());
        let guard = lock(&state).unwrap();
        let (next_path, backup_path) = transaction_paths(&installed, &release).unwrap();
        let backup = Backup {
            path: backup_path,
            sha256: crate::file_hash(&installed).unwrap(),
        };
        let mut record = UpdateStatus {
            highwater: 2,
            staged: Some(release.clone()),
            transaction: Some(Transaction {
                trial: None,
                release,
                install_path: installed.clone(),
                backup: backup.clone(),
                next_path: next_path.clone(),
            }),
            ..Default::default()
        };
        save(&state, &mut record).unwrap();
        assert!(require_recovered(&state).is_err());
        if boundary >= 1 {
            fs::write(
                &next_path,
                if boundary == 1 { &bytes[..30] } else { &bytes },
            )
            .unwrap();
            fs::set_permissions(&next_path, fs::metadata(&installed).unwrap().permissions())
                .unwrap();
        }
        if boundary >= 2 {
            fs::hard_link(&installed, &backup.path).unwrap();
        }
        if boundary >= 3 {
            fs::rename(&next_path, &installed).unwrap();
        }
        if boundary == 4 {
            fs::rename(&backup.path, &installed).unwrap();
        }
        if boundary == 5 {
            fs::remove_file(&installed).unwrap();
        }
        drop(guard);
        let recovered = recover(&state).unwrap();
        assert_eq!(recovered.last_result, "rolled_back");
        assert_eq!(recovered.highwater, 2);
        assert_eq!(fs::read(&installed).unwrap(), executable(1));
        assert!(!backup.path.exists() && !next_path.exists());
        assert!(recover(&state).unwrap().transaction.is_none());
        require_recovered(&state).unwrap();
    }
}
#[test]
fn damaged_backup_and_running_agent_prevent_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let (state, installed, _, release) = setup(directory.path());
    let guard = lock(&state).unwrap();
    let (next_path, backup_path) = transaction_paths(&installed, &release).unwrap();
    let backup = Backup {
        path: backup_path,
        sha256: protocol::hash(b"expected"),
    };
    fs::write(&backup.path, b"damaged").unwrap();
    let mut record = UpdateStatus {
        highwater: 2,
        transaction: Some(Transaction {
            trial: None,
            release,
            install_path: installed.clone(),
            backup,
            next_path,
        }),
        ..Default::default()
    };
    save(&state, &mut record).unwrap();
    drop(guard);
    assert!(recover(&state).is_err());
    assert!(status(&state).unwrap().transaction.is_some());
    assert_eq!(fs::read(installed).unwrap(), executable(1));
    let _running = Store::open(&state).unwrap();
    assert!(apply(&state)
        .unwrap_err()
        .to_string()
        .contains("Stop the endpoint service"));
}
#[test]
fn transaction_paths_cannot_redirect_recovery_to_an_unrelated_file() {
    let directory = tempfile::tempdir().unwrap();
    let (state, installed, _, release) = setup(directory.path());
    let guard = lock(&state).unwrap();
    let (next_path, _) = transaction_paths(&installed, &release).unwrap();
    let unrelated = directory.path().join("unrelated");
    fs::write(&unrelated, b"unrelated public bytes").unwrap();
    let backup = Backup {
        path: unrelated.clone(),
        sha256: protocol::hash(b"unrelated public bytes"),
    };
    let mut record = UpdateStatus {
        highwater: 2,
        transaction: Some(Transaction {
            trial: None,
            release,
            install_path: installed.clone(),
            backup,
            next_path,
        }),
        ..Default::default()
    };
    save(&state, &mut record).unwrap();
    drop(guard);
    assert!(recover(&state).is_err());
    assert_eq!(fs::read(unrelated).unwrap(), b"unrelated public bytes");
    assert_eq!(fs::read(installed).unwrap(), executable(1));
}

#[test]
fn committed_cleanup_is_bound_to_the_confirmed_release_and_installation() {
    let directory = tempfile::tempdir().unwrap();
    let (state, installed, bytes, release) = setup(directory.path());
    let guard = lock(&state).unwrap();
    let (_, backup_path) = transaction_paths(&installed, &release).unwrap();
    let unrelated = directory.path().join("unrelated");
    fs::write(&unrelated, executable(1)).unwrap();
    fs::write(&installed, &bytes).unwrap();
    let mut record = UpdateStatus {
        highwater: 2,
        installed: Some(release),
        cleanup: Some(Backup {
            path: unrelated.clone(),
            sha256: protocol::hash(&executable(1)),
        }),
        ..Default::default()
    };
    save(&state, &mut record).unwrap();
    drop(guard);
    assert!(recover(&state).is_err());
    assert_eq!(fs::read(&unrelated).unwrap(), executable(1));
    assert!(status(&state).unwrap().cleanup.is_some());
    fs::copy(&unrelated, &backup_path).unwrap();
    record.cleanup.as_mut().unwrap().path = backup_path.clone();
    save(&state, &mut record).unwrap();
    assert!(recover(&state).unwrap().cleanup.is_none());
    assert!(!backup_path.exists());
    assert_eq!(fs::read(installed).unwrap(), bytes);
    assert_eq!(fs::read(unrelated).unwrap(), executable(1));
    assert_eq!(recover(&state).unwrap().highwater, 2);
}

#[test]
fn release_publication_serializes_publishers_and_cannot_replace_the_trusted_key() {
    let directory = tempfile::tempdir().unwrap();
    let (state, _, bytes, release) = setup(directory.path());
    let config = config(&state).unwrap();
    let manifest = directory.path().join("release.json");
    let binary = directory.path().join("binary");
    fs::write(&manifest, serde_json::to_vec(&release).unwrap()).unwrap();
    fs::write(&binary, bytes).unwrap();
    let catalog = directory.path().join("catalog");
    let id = publish(&manifest, &binary, &config.updates.public_key, &catalog).unwrap();
    let publisher = OpenOptions::new()
        .read(true)
        .write(true)
        .open(catalog.join(".publish.lock"))
        .unwrap();
    publisher.try_lock().unwrap();
    assert!(publish(&manifest, &binary, &config.updates.public_key, &catalog).is_err());
    publisher.unlock().unwrap();
    let (other_private, other_public) = wire::generate_key().unwrap();
    let other = SignedRelease::sign(release.release.clone(), &other_private).unwrap();
    fs::write(&manifest, serde_json::to_vec(&other).unwrap()).unwrap();
    assert!(publish(&manifest, &binary, &other_public, &catalog).is_err());
    assert_eq!(
        fs::read_to_string(catalog.join("public-key.txt")).unwrap(),
        config.updates.public_key
    );
    assert_eq!(
        serde_json::from_slice::<SignedRelease>(
            &fs::read(catalog.join(format!("{id}.json"))).unwrap()
        )
        .unwrap(),
        release
    );
}

#[test]
fn installer_cannot_bypass_signed_release_history_or_replace_a_running_agent() {
    let directory = tempfile::tempdir().unwrap();
    let (state, installed, bytes, _) = setup(directory.path());
    let candidate = directory.path().join("installer-candidate");
    fs::write(&candidate, bytes).unwrap();
    assert!(installer_check(&state, &candidate, false).is_err());
    installer_check(&state, &installed, false).unwrap();
    let running = Store::open(&state).unwrap();
    assert!(installer_check(&state, &installed, true).is_err());
    drop(running);
    installer_check(&state, &installed, true).unwrap();
    fs::remove_file(state.join("config.json")).unwrap();
    assert!(installer_check(&state, &installed, false).is_err());
}

#[cfg(unix)]
#[test]
fn installation_rejects_replaceable_ancestor_directories() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let ancestor = root.join("replaceable");
    let parent = ancestor.join("installation");
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let installed = parent.join("agent");
    fs::write(&installed, executable(1)).unwrap();
    fs::set_permissions(&installed, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(check_destination(&installed).is_err());
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
    check_destination(&installed).unwrap();
}
