use super::*;
use protocol::update::{Release, SignedRelease};
use std::io::Read;

struct Fixture {
    _temp: tempfile::TempDir,
    state: PathBuf,
    controller: PathBuf,
    agent: PathBuf,
    id: String,
    release: SignedRelease,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let state = root.join("state");
    let controller = root.join("controller");
    let agent = root.join("agent");
    let mut bytes = Vec::new();
    fs::File::open(std::env::current_exe().unwrap())
        .unwrap()
        .take(4096)
        .read_to_end(&mut bytes)
        .unwrap();
    fs::write(&controller, &bytes).unwrap();
    fs::write(&agent, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&controller, &agent] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let (key, public) = protocol::update::generate_key().unwrap();
    let config = serde_json::json!({"server":"http://127.0.0.1:1/","endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"scanner":agent,"updater":agent,"scan_roots":[root.join("watched")],"allow_scripts":false,
        "updates":{"public_key":public,"channel":"stable","install_path":agent,"controller_path":controller,"launcher_path":std::env::current_exe().unwrap().canonicalize().unwrap(),"controller_automatic":cfg!(any(target_os="linux",windows)),"allow_unsigned_native":true}});
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let release = SignedRelease::sign(
        Release {
            schema: 1,
            protocol: protocol::PROTOCOL,
            target: protocol::update::target(),
            version: "fixture".into(),
            channel: "stable".into(),
            sequence: 1,
            issued_ms: now_ms(),
            expires_ms: now_ms() + 60_000,
            sha256: protocol::hash(&bytes),
            bytes: bytes.len() as u64,
        },
        &key,
    )
    .unwrap();
    let manifest = root.join("manifest.json");
    fs::write(&manifest, serde_json::to_vec(&release).unwrap()).unwrap();
    update::stage_component(&state, Component::Controller, &manifest, &controller).unwrap();
    Fixture {
        _temp: temp,
        state,
        controller,
        agent,
        id: release.id().unwrap(),
        release,
    }
}
#[test]
#[cfg(any(target_os = "linux", windows))]
fn exact_local_request_requires_opt_in_and_cannot_be_silently_extended() {
    let f = fixture();
    let deadline = now_ms() + 30_000;
    for (id, until) in [
        ("f".repeat(64), deadline),
        (f.id.clone(), now_ms() - 1),
        (f.id.clone(), now_ms() + 900_001),
        (f.id.clone(), f.release.release.expires_ms + 1),
    ] {
        assert!(request(&f.state, &id, until).is_err());
    }
    request(&f.state, &f.id, deadline).unwrap();
    request(&f.state, &f.id, deadline).unwrap();
    assert!(request(&f.state, &f.id, deadline + 1).is_err());
    assert!(require_idle(&f.state).is_err());
    assert!(update::apply_component(&f.state, Component::Controller).is_err());
    assert!(cancel(&f.state, &"e".repeat(64)).is_err());
    cancel(&f.state, &f.id).unwrap();
    cancel(&f.state, &f.id).unwrap();
    require_idle(&f.state).unwrap();
    let (mut config, _) = configuration(&f.state).unwrap();
    config.updates.controller_automatic = false;
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    assert!(request(&f.state, &f.id, deadline).is_err());
    assert_eq!(update::status(&f.state).unwrap().highwater, 0);
}
#[test]
fn launcher_exclusion_and_nonce_require_the_actual_owning_process() {
    let f = fixture();
    let owner = acquire(&f.state).unwrap();
    assert!(quiescent(&f.state).is_err());
    let mut l = Lease {
        token: secret().unwrap(),
        launcher_pid: std::process::id() + 1,
        controller_pid: None,
        controller: f.controller,
        controller_sha256: f.release.release.sha256,
        agent: f.agent,
        agent_sha256: String::new(),
        config_sha256: String::new(),
        started_ms: now_ms(),
    };
    save_lease(&f.state, &l).unwrap();
    assert!(!owned(&f.state, &l.token));
    l.launcher_pid = std::process::id();
    save_lease(&f.state, &l).unwrap();
    assert!(owned(&f.state, &l.token));
    assert!(!owned(&f.state, &"b".repeat(64)));
    assert!(quiescent(&f.state).unwrap().is_none());
    drop(owner);
    assert!(!owned(&f.state, &l.token));
    assert!(quiescent(&f.state).unwrap().is_some());
}
#[test]
#[cfg(any(target_os = "linux", windows))]
fn expiry_and_contention_refuse_or_defer_without_claiming_an_activation() {
    let f = fixture();
    request(&f.state, &f.id, now_ms() + 30_000).unwrap();
    let update = update::maintenance_lock(&f.state).unwrap();
    assert!(!eligible(&f.state, &f.controller, &f.agent).unwrap());
    assert!(status(&f.state).unwrap().unwrap().phase == Phase::Queued);
    drop(update);
    let mut r = status(&f.state).unwrap().unwrap();
    r.deadline_ms = now_ms() - 1;
    save(&f.state, &mut r).unwrap();
    assert!(!eligible(&f.state, &f.controller, &f.agent).unwrap());
    assert!(status(&f.state).unwrap().unwrap().phase == Phase::Refused);
    assert!(status(&f.state)
        .unwrap()
        .unwrap()
        .detail
        .contains("expired"));
    assert!(update::status_component(&f.state, Component::Controller)
        .unwrap()
        .transaction
        .is_none());
}
#[test]
#[cfg(any(target_os = "linux", windows))]
fn cancellation_cannot_undo_claimed_controller_replacement() {
    let f = fixture();
    request(&f.state, &f.id, now_ms() + 30_000).unwrap();
    let mut r = status(&f.state).unwrap().unwrap();
    r.phase = Phase::Applying;
    save(&f.state, &mut r).unwrap();
    assert!(cancel(&f.state, &f.id).is_err());
    reconcile(&f.state).unwrap();
    assert!(status(&f.state).unwrap().unwrap().phase == Phase::Refused);
    assert!(update::status_component(&f.state, Component::Controller)
        .unwrap()
        .staged
        .is_some());
}

#[test]
fn confirmed_controller_and_agent_bytes_are_checked_before_launch() {
    let f = fixture();
    let installed = update::UpdateStatus {
        highwater: 1,
        installed: Some(f.release.clone()),
        ..Default::default()
    };
    private_write(
        &f.state.join("updates/controller/status.json"),
        &serde_json::to_vec(&installed).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verified_controller(&f.state, &f.controller, &"e".repeat(64)).unwrap(),
        f.release.release.sha256
    );
    let original = fs::read(&f.controller).unwrap();
    fs::write(&f.controller, b"unapproved executable bytes").unwrap();
    assert!(verified_controller(&f.state, &f.controller, &"e".repeat(64)).is_err());
    fs::write(&f.controller, original).unwrap();
    private_write(
        &f.state.join("updates/status.json"),
        &serde_json::to_vec(&installed).unwrap(),
    )
    .unwrap();
    let (config, _) = configuration(&f.state).unwrap();
    verified_agent(&f.state, &config, &f.agent).unwrap();
    fs::write(&f.agent, b"unapproved agent bytes").unwrap();
    assert!(verified_agent(&f.state, &config, &f.agent).is_err());
}

#[test]
#[cfg(any(target_os = "linux", windows))]
fn fleet_request_requires_separate_policy_and_retains_an_immutable_receipt() {
    let f = fixture();
    let deployment = Deployment {
        component: WireComponent::Controller,
        install: true,
        id: "c".repeat(64),
        endpoint_id: "a".repeat(64),
        release_id: f.id.clone(),
        release: f.release.clone(),
        created_ms: now_ms(),
        expires_ms: now_ms() + 30_000,
    };
    request_fleet(&f.state, &deployment).unwrap();
    let record = status(&f.state).unwrap().unwrap();
    assert!(record.phase == Phase::Refused);
    let receipt = record.receipt.unwrap();
    assert_eq!(receipt.outcome, "refused");
    assert!(require_idle(&f.state).is_err());
    request_fleet(&f.state, &deployment).unwrap();
    assert_eq!(
        status(&f.state).unwrap().unwrap().receipt.as_ref(),
        Some(&receipt)
    );
    assert!(request(&f.state, &f.id, deployment.expires_ms).is_err());
    let mut other = deployment.clone();
    other.id = "d".repeat(64);
    assert!(request_fleet(&f.state, &other).is_err());
    other.component = WireComponent::Agent;
    assert!(request_fleet(&f.state, &other).is_err());
    assert!(update::status_component(&f.state, Component::Controller)
        .unwrap()
        .transaction
        .is_none());
    assert_eq!(update::status(&f.state).unwrap().highwater, 0);
}
