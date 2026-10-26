//! Platform-owned storage under the global lease. Durable intent admits only
//! already recorded object positions after a crash; matching contents never
//! adopt an unknown file or OS job. No function submits an OS extension request.
use super::{
    filesystem as fs, inspection,
    journal::{Inspection, Phase, Record},
    launchd,
    owner::{Backend, InspectTarget},
};
use crate::{macos_network_bundle::INSTALL_PATH, Result};
use athernex_endpoint_protocol as protocol;
use athernex_macos_network::{
    upgrade::{ExtensionProperty, FilterState},
    Status,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(super) const MAX_LEDGER_BYTES: usize = 131_072;
const CONFIG_LIMIT: usize = 65_536;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnedFiles {
    pub old_app: fs::Identity,
    pub new_app: fs::Identity,
    pub management_binary: fs::Identity,
    pub original_config_snapshot: fs::Identity,
    pub candidate_config_snapshot: fs::Identity,
    pub helper_plist: fs::Identity,
    pub original_management_plist: Option<fs::Identity>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum JobOperation {
    StopManagement,
    StartManagement,
    ParkManagement,
    RestoreManagement,
    Bootstrap,
    Bootout,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RollbackIntent {
    pub from_phase: Phase,
    pub record_sha256: String,
    pub proof: Option<Inspection>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ObservationTarget {
    Original,
    Candidate,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub plan_sha256: String,
    pub boot: String,
    pub checked_ms: u64,
    pub target: ObservationTarget,
    pub inspection: Inspection,
    pub source_status: Option<Status>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    pub schema: u32,
    pub record: Record,
    pub staging_path: PathBuf,
    pub staging_identity: fs::Identity,
    pub files: OwnedFiles,
    pub job: launchd::OwnedJobRecord,
    pub stage_placed: bool,
    pub app_exchange_started: bool,
    pub management_parked: bool,
    pub original_management_plist_sha256: String,
    pub retirement_started: bool,
    pub retired: bool,
    pub job_operation: Option<JobOperation>,
    pub job_operation_boot: Option<String>,
    pub job_confirmed_boot: Option<String>,
    pub helper_plist_parked_boot: Option<String>,
    pub rollback_intent: Option<RollbackIntent>,
    pub last_observation: Option<Observation>,
}
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(protocol::hash(&serde_json::to_vec(value)?))
}
impl Ledger {
    /// Retirement recovery validates the closed record under the lease without
    /// requiring already removed members. The caller must separately validate
    /// its durable cleanup plan; this function grants no deletion authority.
    pub fn load(lease: &fs::Lease) -> Result<Self> {
        let bytes = fs::read_owned(
            &lease.directory()?.join("current.json"),
            MAX_LEDGER_BYTES,
            0o600,
        )?;
        let ledger: Self =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid network upgrade ledger")?;
        ledger.validate()?;
        Ok(ledger)
    }
    pub fn validate(&self) -> Result<()> {
        self.record.validate()?;
        let stage_name = self
            .staging_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("Upgrade staging name is invalid")?;
        if self.schema != 1
            || self.record.state_path != Path::new(fs::STATE)
            || self.staging_path.parent() != Some(Path::new("/Library/AthernexEndpoint"))
            || !stage_name.starts_with(".network-")
            || stage_name.len() > 128
            || !stage_name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
            || self.files.old_app == self.files.new_app
            || self.files.original_management_plist.is_none()
            || (self.app_exchange_started && !self.stage_placed)
            || (!matches!(self.record.phase, Phase::Prepared | Phase::Aborted)
                && (!self.stage_placed || !self.app_exchange_started))
            || (self.retired && !self.retirement_started)
            || (self.retirement_started
                && !matches!(self.record.phase, Phase::Complete | Phase::Aborted))
            || self.original_management_plist_sha256
                != protocol::hash(launchd::management_plist_bytes())
            || serde_json::to_vec(self)?.len() > MAX_LEDGER_BYTES
        {
            return Err("Invalid network upgrade storage binding".into());
        }
        let job = launchd::Job::new(
            &self.record.plan.identity.app_group,
            &self.record.state_path,
            &self.record.id,
            &self.record.management_sha256,
        )?;
        let mut expected = job.prepared_record();
        expected.state = self.job.state;
        if self.job != expected {
            return Err("Network upgrade job binding differs".into());
        }
        if self
            .job_operation_boot
            .as_ref()
            .is_some_and(|boot| !valid_boot(boot))
            || self
                .job_confirmed_boot
                .as_ref()
                .is_some_and(|boot| !valid_boot(boot))
            || self
                .helper_plist_parked_boot
                .as_ref()
                .is_some_and(|boot| !valid_boot(boot))
            || (self.job_operation.is_none() && self.job_operation_boot.is_some())
            || (matches!(
                self.job_operation,
                Some(
                    JobOperation::Bootstrap
                        | JobOperation::Bootout
                        | JobOperation::StopManagement
                        | JobOperation::StartManagement
                )
            ) && self.job_operation_boot.is_none())
        {
            return Err("Network upgrade job operation lacks its boot binding".into());
        }
        match self.job.state {
            launchd::JobState::NotRegistered
                if self.record.phase != Phase::Aborted
                    || self.record.attempt.is_some()
                    || !matches!(
                        self.job_operation,
                        None | Some(JobOperation::RestoreManagement)
                    )
                    || self.job_confirmed_boot.is_some()
                    || self.helper_plist_parked_boot.is_some() =>
            {
                return Err("Unregistered network helper has contradictory history".into());
            }
            launchd::JobState::BootoutConfirmed | launchd::JobState::RetiredAfterBoot
                if !matches!(self.record.phase, Phase::Complete | Phase::Aborted)
                    || self.helper_plist_parked_boot.is_none()
                    || !matches!(
                        self.job_operation,
                        None | Some(JobOperation::RestoreManagement)
                    ) =>
            {
                return Err("Retired network helper lacks terminal parking evidence".into());
            }
            launchd::JobState::Prepared
                if self.helper_plist_parked_boot.is_some() || self.job_confirmed_boot.is_some() =>
            {
                return Err("Prepared network helper has a retirement receipt".into());
            }
            launchd::JobState::BootstrapConfirmed if self.job_confirmed_boot.is_none() => {
                return Err("Confirmed network helper lacks its boot identity".into());
            }
            _ => (),
        }
        if let Some(intent) = &self.rollback_intent {
            let mut prior = self.record.clone();
            prior.phase = intent.from_phase;
            prior.rollback = None;
            prior.validate()?;
            if digest(&prior)? != intent.record_sha256 {
                return Err("Network upgrade rollback intent differs".into());
            }
            match (&intent.proof, intent.from_phase) {
                (Some(proof), Phase::OsFailed) => {
                    prior.abort_failed(proof.clone())?;
                }
                (None, Phase::Prepared | Phase::CandidatePlaced) => {
                    prior.abort_before_claim()?;
                }
                _ => return Err("Network upgrade rollback is not authorized".into()),
            }
            if self.record.phase != intent.from_phase && self.record.phase != Phase::Aborted {
                return Err("Network upgrade rollback phase changed".into());
            }
        }
        if let Some(observation) = &self.last_observation {
            let pin = match observation.target {
                ObservationTarget::Original => &self.record.plan.old,
                ObservationTarget::Candidate => &self.record.plan.new,
            };
            observation.inspection.property.validate()?;
            if observation.plan_sha256 != self.record.plan_sha256()?
                || observation.checked_ms == 0
                || !valid_boot(&observation.boot)
                || !observation
                    .inspection
                    .property
                    .matches(&self.record.plan.identity, pin)
                || observation.inspection.filter == FilterState::Foreign
            {
                return Err("Network upgrade observation binding differs".into());
            }
            if let Some(status) = &observation.source_status {
                status.health.validate()?;
                if !matches!(
                    observation.inspection.filter,
                    FilterState::Owned { enabled: true }
                ) || status.health.source_policy_sha256 != self.record.plan.source_policy_sha256
                    || !matches!(status.health.state.as_str(), "active" | "degraded")
                    || status.health.error == "Network source configuration failed"
                    || status.health.checked_ms < status.health.started_ms
                    || status.health.checked_ms > observation.checked_ms.saturating_add(1000)
                    || observation
                        .checked_ms
                        .saturating_sub(status.health.checked_ms)
                        > 30_000
                {
                    return Err("Network upgrade source observation differs".into());
                }
            }
        }
        Ok(())
    }
}

pub(super) struct Storage<'a> {
    lease: &'a fs::Lease,
    ledger: Ledger,
    disk_sha256: String,
    poisoned: bool,
}
impl<'a> Storage<'a> {
    pub fn open(lease: &'a fs::Lease) -> Result<Self> {
        let bytes = fs::read_owned(
            &lease.directory()?.join("current.json"),
            MAX_LEDGER_BYTES,
            0o600,
        )?;
        let ledger: Ledger =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid network upgrade ledger")?;
        ledger.validate()?;
        let storage = Self {
            lease,
            ledger,
            disk_sha256: protocol::hash(&bytes),
            poisoned: false,
        };
        storage.verify_disk()?;
        Ok(storage)
    }
    pub fn create(lease: &'a fs::Lease, ledger: Ledger) -> Result<Self> {
        ledger.validate()?;
        let bytes = serde_json::to_vec(&ledger)?;
        if ledger.record.phase != Phase::Prepared
            || ledger.record.attempt.is_some()
            || ledger.stage_placed
            || ledger.app_exchange_started
            || ledger.management_parked
            || ledger.retirement_started
            || ledger.job_operation.is_some()
            || ledger.rollback_intent.is_some()
            || ledger.last_observation.is_some()
            || ledger.helper_plist_parked_boot.is_some()
            || ledger.job_confirmed_boot.is_some()
            || ledger.job.state != launchd::JobState::Prepared
            || object(&ledger.staging_path)? != Some(ledger.staging_identity)
            || object(&lease.directory()?.join("pending"))?.is_some()
        {
            return Err(
                "Network upgrade storage does not start from an owned prepared snapshot".into(),
            );
        }
        let storage = Self {
            lease,
            ledger,
            disk_sha256: protocol::hash(&bytes),
            poisoned: false,
        };
        storage.verify_files()?;
        let root = lease.directory()?;
        let path = root.join("current.json");
        // Never make a partially written initial journal authoritative. A
        // failure retains the owned staged snapshot for explicit recovery.
        let mut file = tempfile::NamedTempFile::new_in(root)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(path)?;
        File::open(root)?.sync_all()?;
        Ok(storage)
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    /// Replay only a filesystem effect already authorized and durably bound
    /// before the prior process stopped. This is not a fresh OS observation,
    /// a new replacement permit, or a claim that the historical proof is fresh.
    pub(super) fn recover_rollback(&mut self) -> Result<()> {
        self.verify_disk()?;
        self.verify_apps()?;
        let intent = self
            .ledger
            .rollback_intent
            .clone()
            .ok_or("Network rollback has no durable authorization")?;
        if self.ledger.record.phase != Phase::OsFailed
            || intent.from_phase != Phase::OsFailed
            || intent.record_sha256 != digest(&self.ledger.record)?
        {
            return Err("Network rollback replay is outside its authorized phase".into());
        }
        let proof = intent
            .proof
            .ok_or("Network rollback lacks its saved native proof")?;
        let aborted = self.ledger.record.abort_failed(proof)?;
        self.apply_original_restoration()?;
        let mut next = self.ledger.clone();
        next.record = aborted;
        self.save(next)
    }
    pub fn save(&mut self, next: Ledger) -> Result<()> {
        self.verify_disk()?;
        next.validate()?;
        if immutable(&self.ledger)? != immutable(&next)?
            || next.retired
            || (self.ledger.stage_placed && !next.stage_placed)
            || (self.ledger.app_exchange_started && !next.app_exchange_started)
        {
            return Err("Immutable network upgrade approval changed".into());
        }
        if let Some(prior) = &self.ledger.rollback_intent {
            if next
                .rollback_intent
                .as_ref()
                .map(digest)
                .transpose()?
                .as_ref()
                != Some(&digest(prior)?)
            {
                return Err("Network rollback intent cannot be replaced".into());
            }
        }
        if !next.retirement_started {
            Self {
                lease: self.lease,
                ledger: next.clone(),
                disk_sha256: self.disk_sha256.clone(),
                poisoned: false,
            }
            .verify_files()?;
        }
        let bytes = serde_json::to_vec(&next)?;
        // The previous on-disk SHA is compared under the same held lease. Never
        // expose the old in-memory permission after an uncertain rename/fsync.
        self.poisoned = true;
        fs::write_owned(&self.lease.directory()?.join("current.json"), &bytes, 0o600)?;
        self.disk_sha256 = protocol::hash(&bytes);
        self.ledger = next;
        self.poisoned = false;
        Ok(())
    }
    fn verify_disk(&self) -> Result<()> {
        if self.poisoned {
            return Err("Network upgrade storage requires recovery".into());
        }
        let bytes = fs::read_owned(
            &self.lease.directory()?.join("current.json"),
            MAX_LEDGER_BYTES,
            0o600,
        )?;
        if protocol::hash(&bytes) != self.disk_sha256 {
            return Err("Network upgrade ledger changed concurrently".into());
        }
        self.ledger.validate()?;
        self.verify_files()
    }
    pub(super) fn directory(&self) -> Result<PathBuf> {
        if self.ledger.retirement_started || self.ledger.retired {
            return Err("Network upgrade retirement requires its owned cleanup plan".into());
        }
        let pending = self.lease.directory()?.join("pending");
        let before = object(&self.ledger.staging_path)?;
        let after = object(&pending)?;
        let path = match (before, after) {
            (Some(id), None) if id == self.ledger.staging_identity && !self.ledger.stage_placed => {
                self.ledger.staging_path.clone()
            }
            (None, Some(id)) if id == self.ledger.staging_identity => pending,
            _ => return Err("Network upgrade staging object is missing or changed".into()),
        };
        fs::protected_directory(&path, 0o700)?;
        Ok(path)
    }
    fn app_positions(&self, directory: &Path) -> Result<bool> {
        inspection::require_applications_parent()?;
        let installed = object(Path::new(INSTALL_PATH))?;
        let backup = object(&directory.join("AthernexNetwork.app"))?;
        let swapped = if installed == Some(self.ledger.files.old_app)
            && backup == Some(self.ledger.files.new_app)
        {
            false
        } else if installed == Some(self.ledger.files.new_app)
            && backup == Some(self.ledger.files.old_app)
        {
            true
        } else {
            return Err("Network upgrade app objects differ from the recorded pair".into());
        };
        if swapped && !self.ledger.app_exchange_started {
            return Err("Network app exchange lacks durable intent".into());
        }
        match self.ledger.record.phase {
            Phase::Prepared => (),
            Phase::Aborted if !swapped => (),
            Phase::Aborted => {
                return Err("Aborted network upgrade has not restored the original app".into());
            }
            _ if swapped => (),
            _ if self.ledger.rollback_intent.is_some() => (),
            _ => return Err("Network candidate is not in its recorded position".into()),
        }
        for path in [
            Path::new(INSTALL_PATH).to_path_buf(),
            directory.join("AthernexNetwork.app"),
        ] {
            let m = std::fs::symlink_metadata(path)?;
            if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o7022 != 0 {
                return Err("Network app root protection changed".into());
            }
        }
        Ok(swapped)
    }
    fn verify_files(&self) -> Result<()> {
        fs::require_state(&self.ledger.record.state_path)?;
        let directory = self.directory()?;
        self.app_positions(&directory)?;
        let allowed = [
            "AthernexNetwork.app",
            "management",
            "original-config.json",
            "candidate-config.json",
            "upgrade-service.plist",
            "management-registration.plist",
        ];
        for (index, entry) in std::fs::read_dir(&directory)?.enumerate() {
            let name = entry?.file_name();
            if index >= allowed.len() || !name.to_str().is_some_and(|n| allowed.contains(&n)) {
                return Err("Upgrade snapshot contains an unapproved entry".into());
            }
        }
        owned_file(
            &directory.join("management"),
            self.ledger.files.management_binary,
            0o700,
            protocol::update::MAX_BINARY as usize,
            &self.ledger.record.management_sha256,
        )?;
        self.snapshots(&directory)?;
        fs::protected_directory(Path::new("/Library/LaunchDaemons"), 0o755)?;
        let helper_private = directory.join("upgrade-service.plist");
        let helper_public = Path::new(launchd::PLIST);
        let helper_at_public = pair_location(
            &helper_private,
            helper_public,
            self.ledger.files.helper_plist,
        )?;
        let moving = matches!(
            self.ledger.job_operation,
            Some(JobOperation::Bootstrap | JobOperation::Bootout)
        );
        if !moving
            && match self.ledger.job.state {
                launchd::JobState::Prepared
                | launchd::JobState::BootoutConfirmed
                | launchd::JobState::NotRegistered
                | launchd::JobState::RetiredAfterBoot => helper_at_public,
                launchd::JobState::BootstrapConfirmed => !helper_at_public,
                launchd::JobState::Uncertain => false,
            }
        {
            return Err("Network upgrade helper registration position changed".into());
        }
        let helper_path = if helper_at_public {
            helper_public
        } else {
            helper_private.as_path()
        };
        owned_file(
            helper_path,
            self.ledger.files.helper_plist,
            0o644,
            16_384,
            &self.ledger.job.plist_sha256,
        )?;
        let original_id = self
            .ledger
            .files
            .original_management_plist
            .ok_or("Original management registration is absent")?;
        let parked = directory.join("management-registration.plist");
        let original_public =
            pair_location(&parked, Path::new(launchd::MANAGEMENT_PLIST), original_id)?;
        let moving = matches!(
            self.ledger.job_operation,
            Some(JobOperation::ParkManagement | JobOperation::RestoreManagement)
        );
        if !moving && original_public == self.ledger.management_parked {
            return Err("Original management registration position changed".into());
        }
        let original_path = if original_public {
            Path::new(launchd::MANAGEMENT_PLIST)
        } else {
            parked.as_path()
        };
        owned_file(
            original_path,
            original_id,
            0o644,
            16_384,
            &self.ledger.original_management_plist_sha256,
        )?;
        let config = fs::read_owned(
            &self.ledger.record.state_path.join("config.json"),
            CONFIG_LIMIT,
            0o600,
        )?;
        let hash = protocol::hash(&config);
        let record = &self.ledger.record;
        let candidate_allowed =
            record.reconciliation.is_some() && self.ledger.rollback_intent.is_none();
        if hash != record.original_config_sha256
            && !(candidate_allowed && hash == record.candidate_config_sha256)
        {
            return Err("Network policy changed outside the approved transaction".into());
        }
        if matches!(record.phase, Phase::ConfigCommitted | Phase::Complete)
            && hash != record.candidate_config_sha256
        {
            return Err("Network candidate config is not committed".into());
        }
        Ok(())
    }
    fn snapshots(&self, directory: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
        let original = owned_file(
            &directory.join("original-config.json"),
            self.ledger.files.original_config_snapshot,
            0o600,
            CONFIG_LIMIT,
            &self.ledger.record.original_config_sha256,
        )?;
        let candidate = owned_file(
            &directory.join("candidate-config.json"),
            self.ledger.files.candidate_config_snapshot,
            0o600,
            CONFIG_LIMIT,
            &self.ledger.record.candidate_config_sha256,
        )?;
        let mut old: crate::Config = serde_json::from_slice(&original)
            .map_err(|_| "Original network upgrade config is invalid")?;
        let new: crate::Config = serde_json::from_slice(&candidate)
            .map_err(|_| "Candidate network upgrade config is invalid")?;
        old.validate()
            .map_err(|_| "Original network upgrade policy is invalid")?;
        new.validate()
            .map_err(|_| "Candidate network upgrade policy is invalid")?;
        if serde_json::to_value(&old.telemetry.macos_network_deployment)?
            != serde_json::to_value(Some(&self.ledger.record.old))?
        {
            return Err("Original network deployment snapshot differs".into());
        }
        old.telemetry.macos_network_deployment = Some(self.ledger.record.candidate.clone());
        if serde_json::to_value(old)? != serde_json::to_value(new)? {
            return Err("Network upgrade changes unrelated policy".into());
        }
        Ok((original, candidate))
    }
    pub(super) fn verify_apps(&self) -> Result<()> {
        let directory = self.directory()?;
        let swapped = self.app_positions(&directory)?;
        let (installed, backup) = if swapped {
            (&self.ledger.record.candidate, &self.ledger.record.old)
        } else {
            (&self.ledger.record.old, &self.ledger.record.candidate)
        };
        inspection::verify_app(Path::new(INSTALL_PATH), installed)?;
        inspection::verify_app(&directory.join("AthernexNetwork.app"), backup)
    }
    fn same_record(&self, record: &Record) -> Result<()> {
        if digest(record)? != digest(&self.ledger.record)? {
            return Err("Network upgrade record changed concurrently".into());
        }
        Ok(())
    }
}

fn object(path: &Path) -> Result<Option<fs::Identity>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(fs::Identity::of(&m))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn valid_boot(boot: &str) -> bool {
    boot.len() == 36
        && boot.bytes().enumerate().all(|(index, b)| {
            if [8, 13, 18, 23].contains(&index) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn pair_location(private: &Path, public: &Path, id: fs::Identity) -> Result<bool> {
    match (object(private)?, object(public)?) {
        (Some(actual), None) if actual == id => Ok(false),
        (None, Some(actual)) if actual == id => Ok(true),
        _ => Err("Network registration object is missing or changed".into()),
    }
}
fn owned_file(
    path: &Path,
    id: fs::Identity,
    mode: u32,
    limit: usize,
    hash: &str,
) -> Result<Vec<u8>> {
    id.verify(path)?;
    let bytes = fs::read_owned(path, limit, mode)?;
    id.verify(path)?;
    if protocol::hash(&bytes) != hash {
        return Err("Network upgrade file content changed".into());
    }
    Ok(bytes)
}
fn immutable(ledger: &Ledger) -> Result<String> {
    let r = &ledger.record;
    digest(
        &serde_json::json!({"schema":ledger.schema,"id":r.id,"state":r.state_path,"boot":r.original_boot,"operator":r.operator_uid,
        "old":r.old,"candidate":r.candidate,"old_config":r.original_config_sha256,"new_config":r.candidate_config_sha256,
        "management":r.management_sha256,"old_container":r.old_container_cdhashes,"plan":r.plan,
        "staging":ledger.staging_path,"staging_id":ledger.staging_identity,"files":ledger.files,
        "original_management_plist":ledger.original_management_plist_sha256}),
    )
}

impl Backend for Storage<'_> {
    fn persist(&mut self, previous: &Record, next: &Record) -> Result<()> {
        self.same_record(previous)?;
        let mut ledger = self.ledger.clone();
        ledger.record = next.clone();
        self.save(ledger)
    }
    fn inspect(
        &mut self,
        record: &Record,
        target: InspectTarget,
        properties: &[ExtensionProperty],
        filter: &FilterState,
    ) -> Result<Inspection> {
        self.same_record(record)?;
        self.verify_disk()?;
        self.verify_apps()?;
        let target = match target {
            InspectTarget::Original => inspection::Target::Original,
            InspectTarget::Candidate => inspection::Target::Candidate,
        };
        let observed = inspection::verify_property(record, target, properties, filter)?;
        let running = matches!(filter, FilterState::Owned { enabled: true })
            && (target == inspection::Target::Candidate || record.phase == Phase::OsFailed);
        let deployment = if target == inspection::Target::Original {
            &record.old
        } else {
            &record.candidate
        };
        let source_status = if running {
            Some(inspection::verify_running_source(deployment)?)
        } else {
            None
        };
        let observation = Observation {
            plan_sha256: record.plan_sha256()?,
            boot: inspection::current_boot()?,
            checked_ms: crate::now_ms(),
            target: if target == inspection::Target::Original {
                ObservationTarget::Original
            } else {
                ObservationTarget::Candidate
            },
            inspection: observed.clone(),
            source_status,
        };
        let mut ledger = self.ledger.clone();
        ledger.last_observation = Some(observation);
        self.save(ledger)?;
        Ok(observed)
    }
    fn before_permit(&mut self, record: &Record, observed: &Inspection) -> Result<()> {
        self.same_record(record)?;
        self.verify_disk()?;
        if record.phase != Phase::CandidatePlaced
            || record.attempt.is_some()
            || !self.ledger.stage_placed
            || !self.ledger.app_exchange_started
            || !self.ledger.management_parked
            || self.ledger.job.state != launchd::JobState::BootstrapConfirmed
            || self.ledger.job_operation.is_some()
            || self.ledger.rollback_intent.is_some()
            || inspection::current_boot()? != record.original_boot
        {
            return Err("Network upgrade is not ready for its only claim".into());
        }
        self.verify_apps()?;
        if !observed
            .property
            .matches(&record.plan.identity, &record.plan.old)
            || observed.filter == FilterState::Foreign
        {
            return Err("Network original inspection changed before claim".into());
        }
        athernex_macos_network::upgrade::inspect_upgrade_property(
            &observed.property,
            &record.plan.identity,
            &record.plan.old,
        )?;
        Ok(())
    }
    fn commit_config(&mut self, record: &Record) -> Result<()> {
        self.same_record(record)?;
        self.verify_disk()?;
        self.verify_apps()?;
        record.config_committed(&inspection::current_boot()?)?;
        let proof = &record
            .reconciliation
            .as_ref()
            .ok_or("Network candidate lacks reconciliation")?
            .candidate;
        self.require_observation(record, ObservationTarget::Candidate, proof)?;
        let directory = self.directory()?;
        let (_, candidate) = self.snapshots(&directory)?;
        let path = record.state_path.join("config.json");
        let current = fs::read_owned(&path, CONFIG_LIMIT, 0o600)?;
        if current != candidate && protocol::hash(&current) != record.original_config_sha256 {
            return Err("Network policy changed before commit".into());
        }
        self.poisoned = true;
        if current != candidate {
            fs::write_owned(&path, &candidate, 0o600)?;
        }
        if fs::read_owned(&path, CONFIG_LIMIT, 0o600)? != candidate {
            return Err("Network candidate config was not retained".into());
        }
        // A prior rename may have reached disk before its parent fsync failed.
        // Observing candidate bytes is not proof that commit is durable.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let id = fs::Identity::of(&file.metadata()?);
        id.verify(&path)?;
        file.sync_all()?;
        File::open(&record.state_path)?.sync_all()?;
        id.verify(&path)?;
        self.poisoned = false;
        Ok(())
    }
    fn restore_original(&mut self, record: &Record, observed: &Inspection) -> Result<()> {
        self.same_record(record)?;
        self.verify_disk()?;
        self.verify_apps()?;
        record.abort_failed(observed.clone())?;
        self.require_observation(record, ObservationTarget::Original, observed)?;
        let expected = RollbackIntent {
            from_phase: record.phase,
            record_sha256: digest(record)?,
            proof: Some(observed.clone()),
        };
        if let Some(existing) = &self.ledger.rollback_intent {
            if digest(existing)? != digest(&expected)? {
                return Err("Network rollback intent changed".into());
            }
        } else {
            let mut next = self.ledger.clone();
            next.rollback_intent = Some(expected);
            self.save(next)?;
        }
        self.apply_original_restoration()
    }
}
impl Storage<'_> {
    fn apply_original_restoration(&mut self) -> Result<()> {
        let directory = self.directory()?;
        self.poisoned = true;
        if self.app_positions(&directory)? {
            fs::exchange(
                Path::new(INSTALL_PATH),
                self.ledger.files.new_app,
                &directory.join("AthernexNetwork.app"),
                self.ledger.files.old_app,
            )?;
        }
        self.verify_apps()?;
        // Also reestablish both namespace writes after a recovered completed
        // swap whose previous parent-directory fsync may have failed.
        fs::confirm_exchange(
            Path::new(INSTALL_PATH),
            self.ledger.files.old_app,
            &directory.join("AthernexNetwork.app"),
            self.ledger.files.new_app,
        )?;
        let (original, _) = self.snapshots(&directory)?;
        let config = self.ledger.record.state_path.join("config.json");
        if fs::read_owned(&config, CONFIG_LIMIT, 0o600)? != original {
            return Err("Network original policy changed during rollback".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&config)?;
        let identity = fs::Identity::of(&file.metadata()?);
        identity.verify(&config)?;
        file.sync_all()?;
        File::open(&self.ledger.record.state_path)?.sync_all()?;
        identity.verify(&config)?;
        self.poisoned = false;
        Ok(())
    }
}
impl Storage<'_> {
    fn require_observation(
        &self,
        record: &Record,
        target: ObservationTarget,
        proof: &Inspection,
    ) -> Result<()> {
        let observed = self
            .ledger
            .last_observation
            .as_ref()
            .ok_or("Network upgrade observation is absent")?;
        let now = crate::now_ms();
        if observed.target != target
            || &observed.inspection != proof
            || observed.plan_sha256 != record.plan_sha256()?
            || observed.boot != inspection::current_boot()?
            || observed.checked_ms > now.saturating_add(1000)
            || now.saturating_sub(observed.checked_ms) > 30_000
            || (matches!(proof.filter, FilterState::Owned { enabled: true })
                != observed.source_status.is_some())
        {
            return Err("Network upgrade observation is not current and bound".into());
        }
        Ok(())
    }
}
