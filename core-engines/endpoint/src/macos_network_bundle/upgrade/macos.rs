//! Root entry points. Every mutation follows a durable, narrowly bound intent.
//! A successful file operation never stands in for an SDK or live-source proof.
use super::{
    filesystem as owned, inspection,
    journal::{Phase, Record},
    launchd,
    owner::{self, Owner},
    storage::{JobOperation, Ledger, OwnedFiles, Storage},
};
use crate::{
    macos_network_bundle::{self as bundle, INSTALL_PATH},
    update, Config, Result,
};
use athernex_endpoint_protocol as protocol;
use athernex_macos_network::upgrade::{
    self as native, UpgradeEvent, UpgradeMode, UpgradePlan, UpgradeRequest, UpgradeServer,
    UpgradeServerConfig,
};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

const CURRENT: &str = "current.json";
const PENDING: &str = "pending";
const CONFIG_LIMIT: usize = 65_536;

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn object(path: &Path) -> Result<owned::Identity> {
    Ok(owned::Identity::of(&fs::symlink_metadata(path)?))
}
fn configuration(state: &Path) -> Result<(Vec<u8>, Config)> {
    let bytes = owned::read_owned(&state.join("config.json"), CONFIG_LIMIT, 0o600)?;
    let config: Config =
        serde_json::from_slice(&bytes).map_err(|_| "Network upgrade configuration is invalid")?;
    config.validate()?;
    Ok((bytes, config))
}

/// Ordinary work checks this before and after obtaining its service/update
/// lease. The upgrade owner alone uses the separate maintenance entry point.
pub fn require_settled() -> Result<()> {
    let root = Path::new(owned::ROOT);
    let marker = Path::new(owned::GUARD_DIRECTORY).join("upgrade-state.json");
    if !exists(root)? {
        if exists(&marker)? || exists(Path::new(launchd::PLIST))? {
            return Err("Network upgrade ownership requires recovery".into());
        }
        return Ok(());
    }
    owned::protected_directory(root, 0o700)?;
    let current = root.join(CURRENT);
    if exists(&current)? {
        let record: Ledger = serde_json::from_slice(&owned::read_owned(
            &current,
            super::storage::MAX_LEDGER_BYTES,
            0o600,
        )?)
        .map_err(|_| "Network upgrade journal is invalid")?;
        record.validate()?;
        if !record.retired || !matches!(record.record.phase, Phase::Complete | Phase::Aborted) {
            return Err(
                "Finish or recover the pending network upgrade before starting work".into(),
            );
        }
    }
    if exists(&root.join(PENDING))? || exists(&marker)? || exists(Path::new(launchd::PLIST))? {
        return Err("Network upgrade retirement is incomplete".into());
    }
    Ok(())
}

/// Status contains no configuration contents, native paths, code pins or peer
/// diagnostics. The complete evidence remains in the private root journal.
pub fn status(state: &Path) -> Result<serde_json::Value> {
    owned::require_state(state)?;
    let root = Path::new(owned::ROOT);
    if !exists(root)? || !exists(&root.join(CURRENT))? {
        require_settled()?;
        return Ok(serde_json::json!({"schema":1,"pending":false}));
    }
    owned::protected_directory(root, 0o700)?;
    // A bounded atomic snapshot remains readable while the broker owns its
    // mutation lease. A concurrent rename can refuse the read, never authorize
    // any transition or expose the private full record in this projection.
    let ledger: Ledger = serde_json::from_slice(&owned::read_owned(
        &root.join(CURRENT),
        super::storage::MAX_LEDGER_BYTES,
        0o600,
    )?)
    .map_err(|_| "Network upgrade journal is invalid")?;
    ledger.validate()?;
    let boot = inspection::current_boot()?;
    Ok(serde_json::json!({"schema":1,"pending":!ledger.retired,
        "phase":ledger.record.phase,"attempt_issued":ledger.record.attempt.is_some(),
        "requires_reboot":(matches!(ledger.record.phase, Phase::Uncertain | Phase::Unexpected | Phase::RebootRequired)
            && boot == ledger.record.original_boot)
            || (ledger.job_operation == Some(JobOperation::Bootout)
                && ledger.helper_plist_parked_boot.as_deref() == Some(boot.as_str())),
        "retirement_started":ledger.retirement_started}))
}

pub fn prepare(state: &Path, archive: &Path, manifest: &Path, operator_uid: u32) -> Result<()> {
    owned::require_state(state)?;
    if operator_uid == 0 || operator_uid == u32::MAX {
        return Err("Network upgrade requires an explicit non-root operator account".into());
    }
    let lease = owned::Lease::acquire()?;
    require_settled()?;
    inspection::require_applications_parent()?;
    owned::protected_directory(Path::new("/Library/LaunchDaemons"), 0o755)?;
    // The standard legacy controller does not know the new upgrade fence.
    // It must be unloaded before parking its boot registration.
    launchd::require_management_unloaded()?;
    let (original, mut config) = configuration(state)?;
    let _maintenance = update::network_upgrade_maintenance(state, &config, &lease)?;
    if configuration(state)?.0 != original {
        return Err("Network policy changed during preparation".into());
    }
    let old = config
        .telemetry
        .macos_network_deployment
        .clone()
        .ok_or("Install and approve the original network provider first")?;
    inspection::verify_app(Path::new(INSTALL_PATH), &old)?;
    let (snapshot, candidate) = bundle::stage(archive, manifest)?;
    let id = owner::nonce()?;
    let identity = bundle::identity(&old.artifact);
    let old_code = native::inspect_upgrade_bundle(Path::new(INSTALL_PATH), &identity)?;
    let new_code = native::inspect_upgrade_bundle(&snapshot.path().join(bundle::APP), &identity)?;
    let executable = std::env::current_exe()?;
    update::check_destination(&executable)?;
    let management = update::read_bounded(&executable, protocol::update::MAX_BINARY)?;
    let management_sha256 = protocol::hash(&management);
    // stage() bound the approved release to this executable. Recheck the
    // snapshot against the same approved manifest after reading its bytes.
    let release: protocol::installer::Artifact =
        serde_json::from_slice(&update::read_bounded(manifest, 16_384)?)
            .map_err(|_| "Network release is invalid")?;
    if release.sha256 != management_sha256 {
        return Err("Network upgrade management snapshot changed".into());
    }
    config.telemetry.macos_network_deployment = Some(candidate.clone());
    config.validate()?;
    let candidate_config = serde_json::to_vec_pretty(&config)?;
    if candidate_config.len() > CONFIG_LIMIT {
        return Err("Network upgrade config exceeds its bound".into());
    }
    let job = launchd::Job::new(&identity.app_group, state, &id, &management_sha256)?;
    let record = Record {
        schema: 1,
        id,
        state_path: state.into(),
        original_boot: inspection::current_boot()?,
        operator_uid,
        old,
        candidate,
        original_config_sha256: protocol::hash(&original),
        candidate_config_sha256: protocol::hash(&candidate_config),
        management_sha256,
        old_container_cdhashes: old_code.container_cdhashes,
        plan: UpgradePlan {
            mode: UpgradeMode::Submit,
            transaction_id: job.prepared_record().transaction_id,
            generation: 1,
            identity,
            source_policy_sha256: config
                .telemetry
                .macos_network_deployment
                .as_ref()
                .ok_or("Network candidate missing")?
                .artifact
                .source_policy_sha256
                .clone(),
            old: old_code.provider,
            new: new_code.provider,
            container_cdhashes: new_code.container_cdhashes,
        },
        phase: Phase::Prepared,
        attempt: None,
        reconciliation: None,
        rollback: None,
    };
    record.validate()?;
    let registration = owned::read_owned(Path::new(launchd::MANAGEMENT_PLIST), 16_384, 0o644)?;
    let registration_sha256 = protocol::hash(&registration);
    launchd::verify_management_snapshot(&registration, &registration_sha256)?;
    let staging = snapshot.path();
    for (name, bytes, mode) in [
        ("management", management.as_slice(), 0o700),
        ("original-config.json", original.as_slice(), 0o600),
        ("candidate-config.json", candidate_config.as_slice(), 0o600),
        ("upgrade-service.plist", job.plist_bytes().as_slice(), 0o644),
    ] {
        owned::write_owned(&staging.join(name), bytes, mode)?;
    }
    owned::sync_tree(staging)?;
    let ledger = Ledger {
        schema: 1,
        record,
        staging_path: staging.into(),
        staging_identity: object(staging)?,
        files: OwnedFiles {
            old_app: object(Path::new(INSTALL_PATH))?,
            new_app: object(&staging.join(bundle::APP))?,
            management_binary: object(&staging.join("management"))?,
            original_config_snapshot: object(&staging.join("original-config.json"))?,
            candidate_config_snapshot: object(&staging.join("candidate-config.json"))?,
            helper_plist: object(&staging.join("upgrade-service.plist"))?,
            original_management_plist: Some(object(Path::new(launchd::MANAGEMENT_PLIST))?),
        },
        original_management_plist_sha256: registration_sha256,
        job: job.prepared_record(),
        job_confirmed_boot: None,
        stage_placed: false,
        app_exchange_started: false,
        management_parked: false,
        retirement_started: false,
        retired: false,
        job_operation: None,
        job_operation_boot: None,
        helper_plist_parked_boot: None,
        rollback_intent: None,
        last_observation: None,
    };
    ledger.validate()?;
    // Only a retired prior record can be archived. Its immutable history is
    // retained privately; no event database, source cursor or loss is reset.
    let current = lease.directory()?.join(CURRENT);
    if exists(&current)? {
        let previous = Ledger::load(&lease)?;
        if !previous.retired {
            return Err("Another network upgrade is pending".into());
        }
        owned::move_exclusive(
            &current,
            object(&current)?,
            &lease
                .directory()?
                .join(format!("history-{}.json", previous.record.id)),
        )?;
    }
    // From here, even failure retains the staged ownership evidence. A crash
    // before create leaves only a private orphan, with no app/OS changes.
    let _retained = snapshot.keep();
    let mut storage = Storage::create(&lease, ledger)?;
    place(&lease, &mut storage)
}

fn place(lease: &owned::Lease, storage: &mut Storage<'_>) -> Result<()> {
    if storage.ledger().record.phase != Phase::Prepared || storage.ledger().record.attempt.is_some()
    {
        return Err("Network placement is not in its prepared phase".into());
    }
    launchd::require_management_unloaded()?;
    let pending = lease.directory()?.join(PENDING);
    if !storage.ledger().stage_placed {
        let before = storage.ledger().staging_path.clone();
        if exists(&before)? {
            owned::move_exclusive(&before, storage.ledger().staging_identity, &pending)?;
        } else {
            owned::confirm_move(&before, storage.ledger().staging_identity, &pending)?;
        }
        let mut next = storage.ledger().clone();
        next.stage_placed = true;
        storage.save(next)?;
    }
    owned::publish_guard(&storage.ledger().record.id)?;
    if !storage.ledger().management_parked {
        let mut next = storage.ledger().clone();
        next.job_operation = Some(JobOperation::ParkManagement);
        storage.save(next)?;
        let source = Path::new(launchd::MANAGEMENT_PLIST);
        let target = pending.join("management-registration.plist");
        let id = storage
            .ledger()
            .files
            .original_management_plist
            .ok_or("Network management registration missing")?;
        if exists(source)? {
            owned::move_exclusive(source, id, &target)?;
        } else {
            owned::confirm_move(source, id, &target)?;
        }
        let mut next = storage.ledger().clone();
        next.management_parked = true;
        next.job_operation = None;
        storage.save(next)?;
    }
    storage.verify_apps()?;
    if !storage.ledger().app_exchange_started {
        let mut next = storage.ledger().clone();
        next.app_exchange_started = true;
        storage.save(next)?;
    }
    let installed = object(Path::new(INSTALL_PATH))?;
    if installed == storage.ledger().files.old_app {
        owned::exchange(
            Path::new(INSTALL_PATH),
            storage.ledger().files.old_app,
            &pending.join(bundle::APP),
            storage.ledger().files.new_app,
        )?;
    } else if installed != storage.ledger().files.new_app {
        return Err("Network installed app ownership changed".into());
    }
    owned::confirm_exchange(
        Path::new(INSTALL_PATH),
        storage.ledger().files.new_app,
        &pending.join(bundle::APP),
        storage.ledger().files.old_app,
    )?;
    storage.verify_apps()?;
    let mut next = storage.ledger().clone();
    next.record = next.record.candidate_placed()?;
    storage.save(next)?;
    bootstrap(lease, storage)
}

fn bootstrap(lease: &owned::Lease, storage: &mut Storage<'_>) -> Result<()> {
    if storage.ledger().job.state != launchd::JobState::Prepared
        || storage.ledger().job_operation.is_some()
    {
        return Err("Network helper registration requires ownership reconciliation".into());
    }
    let job = launchd::Job::new(
        &storage.ledger().record.plan.identity.app_group,
        &storage.ledger().record.state_path,
        &storage.ledger().record.id,
        &storage.ledger().record.management_sha256,
    )?;
    let mut next = storage.ledger().clone();
    next.job_operation = Some(JobOperation::Bootstrap);
    next.job_operation_boot = Some(inspection::current_boot()?);
    storage.save(next)?;
    owned::move_exclusive(
        &lease
            .directory()?
            .join(PENDING)
            .join("upgrade-service.plist"),
        storage.ledger().files.helper_plist,
        Path::new(launchd::PLIST),
    )?;
    // The root preparation process still holds the maintenance lease. launchd
    // bootstrap success proves registration, not listener or provider health.
    let confirmed = job.bootstrap(
        &storage.ledger().job,
        Path::new(launchd::PLIST),
        &job.plist_bytes(),
    )?;
    let mut next = storage.ledger().clone();
    next.job = confirmed;
    next.job_confirmed_boot = Some(inspection::current_boot()?);
    next.job_operation = None;
    next.job_operation_boot = None;
    storage.save(next)
}

pub fn recover(state: &Path) -> Result<()> {
    owned::require_state(state)?;
    let lease = owned::Lease::acquire()?;
    let mut storage = Storage::open(&lease)?;
    let (_, config) = configuration(state)?;
    let _maintenance = update::network_upgrade_maintenance(state, &config, &lease)?;
    launchd::require_management_unloaded()?;
    // Acquiring the global lease establishes that the old broker no longer
    // owns it. Its already submitted SDK request may still be unresolved.
    if storage.ledger().record.phase == Phase::MayBePending {
        let previous = storage
            .ledger()
            .record
            .attempt
            .as_ref()
            .ok_or("Network upgrade attempt is missing")?
            .owner
            .clone();
        let mut next = storage.ledger().clone();
        next.record = next.record.owner_lost(&previous)?;
        storage.save(next)?;
    }
    if storage.ledger().record.phase == Phase::OsFailed
        && storage.ledger().rollback_intent.is_some()
    {
        return storage.recover_rollback();
    }
    if storage.ledger().record.attempt.is_none()
        && matches!(
            storage.ledger().record.phase,
            Phase::Prepared | Phase::CandidatePlaced
        )
        && storage.ledger().record.original_boot != inspection::current_boot()?
    {
        return Err("Unclaimed network preparation crossed a reboot; abort and finish before preparing again".into());
    }
    if storage.ledger().job.state == launchd::JobState::Prepared
        && storage.ledger().job_operation == Some(JobOperation::Bootstrap)
        && !exists(Path::new(launchd::PLIST))?
    {
        let private = lease
            .directory()?
            .join(PENDING)
            .join("upgrade-service.plist");
        storage.ledger().files.helper_plist.verify(&private)?;
        launchd::require_helper_unloaded()?;
        let mut next = storage.ledger().clone();
        next.job_operation = None;
        next.job_operation_boot = None;
        storage.save(next)?;
    }
    match storage.ledger().record.phase {
        Phase::Prepared if storage.ledger().record.original_boot == inspection::current_boot()? => place(&lease, &mut storage),
        Phase::CandidatePlaced if storage.ledger().record.original_boot == inspection::current_boot()?
            && storage.ledger().job.state == launchd::JobState::Prepared
            && storage.ledger().job_operation.is_none() => bootstrap(&lease, &mut storage),
        _ => Err("Use the authenticated container to reconcile this upgrade; an uncertain request may require reboot".into()),
    }
}

pub fn serve(state: &Path, transaction: &str) -> Result<()> {
    owned::require_state(state)?;
    let lease = owned::Lease::acquire()?;
    let mut storage = Storage::open(&lease)?;
    let record = &storage.ledger().record;
    if record.id != transaction
        || std::env::current_exe()?.canonicalize()? != Path::new(launchd::PROGRAM)
        || crate::file_hash(Path::new(launchd::PROGRAM))? != record.management_sha256
    {
        return Err("Network helper executable or transaction differs".into());
    }
    let (_, config) = configuration(state)?;
    let _maintenance = update::network_upgrade_maintenance(state, &config, &lease)?;
    launchd::require_management_unloaded()?;
    storage.verify_apps()?;
    if !storage.ledger().management_parked || storage.ledger().helper_plist_parked_boot.is_some() {
        return Err("Network helper registration is not available".into());
    }
    owned::publish_guard(&storage.ledger().record.id)?;
    let record = &storage.ledger().record;
    let mut server = UpgradeServer::start(&UpgradeServerConfig {
        transaction_id: record.id.clone(),
        generation: record.plan.generation,
        operator_uid: record.operator_uid,
        identity: record.plan.identity.clone(),
        container_cdhashes: record.plan.container_cdhashes.clone(),
    })?;
    let deadline = Instant::now() + Duration::from_secs(600);
    let result = (|| -> Result<()> {
        let first = loop {
            if Instant::now() >= deadline {
                return Err("Network upgrade operator connection expired".into());
            }
            if let Some(incoming) = server.poll(Duration::from_millis(250))? {
                break incoming;
            }
        };
        if first.peer_euid != storage.ledger().record.operator_uid
            || !matches!(
                first.event,
                UpgradeEvent::Request {
                    request: UpgradeRequest::Plan
                }
            )
        {
            return Err("Network helper requires an authenticated plan request".into());
        }
        // A request delivered to this exact snapshot through its privileged
        // Mach service establishes a live registration. Matching plist bytes
        // or a PID alone cannot perform this recovery transition.
        match (storage.ledger().job.state, storage.ledger().job_operation) {
            (launchd::JobState::BootstrapConfirmed, None) => {
                let mut next = storage.ledger().clone();
                next.job_confirmed_boot = Some(inspection::current_boot()?);
                storage.save(next)?;
            }
            (
                launchd::JobState::Prepared | launchd::JobState::Uncertain,
                Some(JobOperation::Bootstrap),
            ) => {
                let mut next = storage.ledger().clone();
                next.job.state = launchd::JobState::BootstrapConfirmed;
                next.job_confirmed_boot = Some(inspection::current_boot()?);
                next.job_operation = None;
                next.job_operation_boot = None;
                storage.save(next)?;
            }
            _ => return Err("Network helper has no owned registration".into()),
        }
        let mut owner = Owner::new(
            storage.ledger().record.clone(),
            storage,
            inspection::current_boot()?,
            owner::nonce()?,
        )?;
        let mut incoming = first;
        loop {
            let result = owner.handle(&incoming).and_then(|reply| {
                if let Some(reply) = reply {
                    server.reply(incoming.request_token, &reply)?;
                }
                Ok(())
            });
            if let Err(error) = result {
                owner.lost()?;
                return Err(error);
            }
            if matches!(owner.record.phase, Phase::ConfigCommitted | Phase::Aborted) {
                return Ok(());
            }
            if matches!(incoming.event, UpgradeEvent::Disconnected) {
                owner.lost()?;
                return Ok(());
            }
            incoming = loop {
                if Instant::now() >= deadline {
                    owner.lost()?;
                    return Err("Network upgrade session expired".into());
                }
                match server.poll(Duration::from_millis(250)) {
                    Ok(Some(next)) => break next,
                    Ok(None) => (),
                    Err(error) => {
                        owner.lost()?;
                        return Err(error.into());
                    }
                }
            };
        }
    })();
    let closed: Result<()> = server.close().map_err(Into::into);
    result.and(closed)
}

/// Cancel only before a permit was durably issued. An issued request must be
/// reconciled through the authenticated container; restoring a file cannot
/// roll back an OS-managed provider.
pub fn abort(state: &Path) -> Result<()> {
    owned::require_state(state)?;
    let lease = owned::Lease::acquire()?;
    let mut storage = Storage::open(&lease)?;
    let (_, config) = configuration(state)?;
    let _maintenance = update::network_upgrade_maintenance(state, &config, &lease)?;
    launchd::require_management_unloaded()?;
    let before = storage.ledger().record.clone();
    let aborted = before.abort_before_claim()?;
    let pending = lease.directory()?.join(PENDING);
    if !storage.ledger().stage_placed {
        let source = storage.ledger().staging_path.clone();
        if exists(&source)? {
            owned::move_exclusive(&source, storage.ledger().staging_identity, &pending)?;
        } else {
            owned::confirm_move(&source, storage.ledger().staging_identity, &pending)?;
        }
        let mut next = storage.ledger().clone();
        next.stage_placed = true;
        storage.save(next)?;
    }
    owned::publish_guard(&before.id)?;
    storage.verify_apps()?;
    let intent = super::storage::RollbackIntent {
        from_phase: before.phase,
        record_sha256: protocol::hash(&serde_json::to_vec(&before)?),
        proof: None,
    };
    if let Some(previous) = &storage.ledger().rollback_intent {
        if serde_json::to_vec(previous)? != serde_json::to_vec(&intent)? {
            return Err("Network cancellation intent changed".into());
        }
    } else {
        let mut next = storage.ledger().clone();
        next.rollback_intent = Some(intent);
        storage.save(next)?;
    }
    if object(Path::new(INSTALL_PATH))? == storage.ledger().files.new_app {
        owned::exchange(
            Path::new(INSTALL_PATH),
            storage.ledger().files.new_app,
            &pending.join(bundle::APP),
            storage.ledger().files.old_app,
        )?;
    }
    owned::confirm_exchange(
        Path::new(INSTALL_PATH),
        storage.ledger().files.old_app,
        &pending.join(bundle::APP),
        storage.ledger().files.new_app,
    )?;
    storage.verify_apps()?;
    let mut next = storage.ledger().clone();
    next.record = aborted;
    storage.save(next)
}

fn settle_management_move(storage: &mut Storage<'_>) -> Result<()> {
    let operation = storage.ledger().job_operation;
    if !matches!(
        operation,
        Some(JobOperation::ParkManagement | JobOperation::RestoreManagement)
    ) {
        return Ok(());
    }
    let public = Path::new(launchd::MANAGEMENT_PLIST);
    let private = storage.directory()?.join("management-registration.plist");
    let id = storage
        .ledger()
        .files
        .original_management_plist
        .ok_or("Network management registration missing")?;
    let parked = !exists(public)?;
    if parked {
        owned::confirm_move(public, id, &private)?;
    } else {
        owned::confirm_move(&private, id, public)?;
    }
    let mut next = storage.ledger().clone();
    next.management_parked = parked;
    next.job_operation = None;
    next.job_operation_boot = None;
    storage.save(next)
}

fn stop_helper(lease: &owned::Lease, storage: &mut Storage<'_>) -> Result<()> {
    use launchd::JobState;
    let public = Path::new(launchd::PLIST);
    let private = lease
        .directory()?
        .join(PENDING)
        .join("upgrade-service.plist");
    let id = storage.ledger().files.helper_plist;
    let boot = inspection::current_boot()?;
    match storage.ledger().job.state {
        JobState::BootoutConfirmed | JobState::NotRegistered | JobState::RetiredAfterBoot => {
            owned::confirm_move(public, id, &private)?;
            launchd::require_helper_unloaded()?;
            return Ok(());
        }
        JobState::Prepared
            if !exists(public)?
                && matches!(
                    storage.ledger().job_operation,
                    None | Some(JobOperation::Bootstrap)
                ) =>
        {
            // Bootstrap can only be called after this very inode has moved to
            // the public path. No later transition can return it here while
            // retaining Prepared/Bootstrap, so this operation never started.
            id.verify(&private)?;
            launchd::require_helper_unloaded()?;
            let mut next = storage.ledger().clone();
            next.job.state = JobState::NotRegistered;
            next.job_operation = None;
            next.job_operation_boot = None;
            storage.save(next)?;
            return Ok(());
        }
        _ => (),
    }
    let fresh_stop = storage.ledger().job.state == JobState::BootstrapConfirmed
        && storage.ledger().job_operation.is_none()
        && storage.ledger().job_confirmed_boot.as_deref() == Some(boot.as_str());
    if storage.ledger().job_operation != Some(JobOperation::Bootout) {
        if !matches!(
            storage.ledger().job_operation,
            None | Some(JobOperation::Bootstrap)
        ) {
            return Err("Network helper operation must be reconciled first".into());
        }
        let mut next = storage.ledger().clone();
        if !fresh_stop {
            next.job.state = JobState::Uncertain;
        }
        next.job_operation = Some(JobOperation::Bootout);
        next.job_operation_boot = Some(boot.clone());
        storage.save(next)?;
    }
    if exists(public)? {
        owned::move_exclusive(public, id, &private)?;
    } else {
        owned::confirm_move(public, id, &private)?;
    }
    if storage.ledger().helper_plist_parked_boot.is_none() {
        let mut next = storage.ledger().clone();
        next.helper_plist_parked_boot = Some(boot.clone());
        storage.save(next)?;
    }
    if fresh_stop {
        let record = &storage.ledger().record;
        let job = launchd::Job::new(
            &record.plan.identity.app_group,
            &record.state_path,
            &record.id,
            &record.management_sha256,
        )?;
        let confirmed = job.bootout(&storage.ledger().job, &private, &job.plist_bytes())?;
        let mut next = storage.ledger().clone();
        next.job = confirmed;
        next.job_operation = None;
        next.job_operation_boot = None;
        storage.save(next)?;
        return Ok(());
    }
    // An interrupted command may already have completed. Never retry bootout
    // against a label that could now identify a different job. A durable prior
    // boot parking receipt plus actual absence establishes safe retirement.
    if storage.ledger().helper_plist_parked_boot.as_deref() == Some(boot.as_str()) {
        return Err("Network helper retirement is uncertain; reboot with its registration parked, then finish".into());
    }
    launchd::require_helper_unloaded()?;
    let mut next = storage.ledger().clone();
    next.job.state = JobState::RetiredAfterBoot;
    next.job_operation = None;
    next.job_operation_boot = None;
    storage.save(next)
}

fn restore_management(storage: &mut Storage<'_>) -> Result<()> {
    launchd::require_management_unloaded()?;
    if !storage.ledger().management_parked {
        return Ok(());
    }
    if storage.ledger().job_operation.is_some() {
        return Err("Network service operation must finish before restoration".into());
    }
    let public = Path::new(launchd::MANAGEMENT_PLIST);
    let private = storage.directory()?.join("management-registration.plist");
    let id = storage
        .ledger()
        .files
        .original_management_plist
        .ok_or("Network management registration missing")?;
    let mut next = storage.ledger().clone();
    next.job_operation = Some(JobOperation::RestoreManagement);
    storage.save(next)?;
    owned::move_exclusive(&private, id, public)?;
    let mut next = storage.ledger().clone();
    next.management_parked = false;
    next.job_operation = None;
    storage.save(next)
}

fn seal_candidate(storage: &mut Storage<'_>) -> Result<()> {
    if storage.ledger().record.phase != Phase::ConfigCommitted {
        return Ok(());
    }
    let record = &storage.ledger().record;
    let observed = storage
        .ledger()
        .last_observation
        .as_ref()
        .ok_or("Network candidate has no retained observation")?;
    let now = crate::now_ms();
    if observed.target != super::storage::ObservationTarget::Candidate
        || observed.boot != inspection::current_boot()?
        || observed.checked_ms > now.saturating_add(1000)
        || now.saturating_sub(observed.checked_ms) > 30_000
        || observed.plan_sha256 != record.plan_sha256()?
        || record
            .reconciliation
            .as_ref()
            .is_none_or(|p| p.candidate != observed.inspection)
    {
        return Err("Reconcile the candidate again in the container before finishing".into());
    }
    storage.verify_apps()?;
    let mut next = storage.ledger().clone();
    next.record = record.complete(&observed.boot)?;
    storage.save(next)
}

/// Stops only the owned helper, restores the original standard management
/// registration, and deletes only the bound private snapshot. Management can
/// restart after the durable fence is retired; no event history is rewritten.
pub fn finish(state: &Path) -> Result<()> {
    owned::require_state(state)?;
    let lease = owned::Lease::acquire()?;
    let ledger = Ledger::load(&lease)?;
    if ledger.retired {
        // Reconcile a prior terminal-record rename whose parent fsync failed.
        fs::File::open(lease.directory()?.join(CURRENT))?.sync_all()?;
        fs::File::open(lease.directory()?)?.sync_all()?;
        return require_settled();
    }
    let (_, config) = configuration(state)?;
    let _maintenance = update::network_upgrade_maintenance(state, &config, &lease)?;
    let ledger = if ledger.retirement_started {
        launchd::require_management_unloaded()?;
        launchd::require_helper_unloaded()?;
        ledger
    } else {
        let mut storage = Storage::open(&lease)?;
        seal_candidate(&mut storage)?;
        if !matches!(
            storage.ledger().record.phase,
            Phase::Complete | Phase::Aborted
        ) {
            return Err("The network upgrade has not reached a reconciled terminal state".into());
        }
        settle_management_move(&mut storage)?;
        stop_helper(&lease, &mut storage)?;
        restore_management(&mut storage)?;
        storage.verify_apps()?;
        let _plan = super::retirement::prepare(&lease, storage.ledger())?;
        let mut next = storage.ledger().clone();
        next.retirement_started = true;
        storage.save(next)?;
        storage.ledger().clone()
    };
    let plan = super::retirement::load(&lease, &ledger)?;
    super::retirement::execute(&lease, &ledger, &plan)?;
    let marker = Path::new(owned::GUARD_DIRECTORY).join("upgrade-state.json");
    if exists(&marker)? {
        owned::remove_guard(&ledger.record.id)?;
    } else {
        fs::File::open(owned::GUARD_DIRECTORY)?.sync_all()?;
    }
    // The cleanup executor verifies its persisted plan and terminal ledger.
    // Ordinary Storage intentionally cannot reopen partially retired objects.
    let current = lease.directory()?.join(CURRENT);
    let actual = Ledger::load(&lease)?;
    if serde_json::to_vec(&actual)? != serde_json::to_vec(&ledger)? {
        return Err("Network retirement ledger changed".into());
    }
    let mut retired = ledger;
    retired.retired = true;
    retired.validate()?;
    owned::write_owned(&current, &serde_json::to_vec(&retired)?, 0o600)?;
    require_settled()
}
