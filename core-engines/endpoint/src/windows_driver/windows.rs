use super::*;
use athernex_endpoint_native::{
    windows_driver_lifecycle as native, windows_filter_package as trust,
    windows_state::{self, Directory, PinnedDirectory},
};
use protocol::installer::Artifact;
use std::{
    fs::File,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
const JOURNAL: &str = "deployment.json";
const LOCK: &str = "deployment.lock";
const WAIT: Duration = Duration::from_secs(180);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    schema: u32,
    value: String,
    confirmed: bool,
}
fn ensure_epoch(root: &Directory) -> Result<String> {
    let previous = match root.read_json::<Epoch>("kernel-epoch.json") {
        Ok(value) => Some(value),
        Err(e) if missing(e.as_ref()) => None,
        Err(e) => return Err(e),
    };
    if let Some(value) = &previous {
        if value.schema != 1 || !protocol::hex_id(&value.value) || !value.confirmed {
            return Err(
                "Kernel-lifetime epoch creation is unconfirmed; no registry key is adopted".into(),
            );
        }
        if native::epoch(&value.value)? {
            return Ok(value.value.clone());
        }
    }
    let mut next = Epoch {
        schema: 1,
        value: crate::secret()?,
        confirmed: false,
    };
    if previous.is_some() {
        root.write_maintenance_json("kernel-epoch.json", &next)?;
    } else {
        root.publish_maintenance("kernel-epoch.json", &serde_json::to_vec(&next)?)?;
    }
    native::create_epoch(&next.value)?;
    next.confirmed = true;
    root.write_maintenance_json("kernel-epoch.json", &next)?;
    Ok(next.value)
}
fn missing(e: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|v| v.kind() == std::io::ErrorKind::NotFound)
}
fn object(directory: &Directory) -> Result<ObjectIdentity> {
    let id = directory.identity()?;
    Ok(ObjectIdentity {
        volume: id.volume,
        file_id: id.file_id,
    })
}
fn global(create: bool) -> Result<Option<Directory>> {
    let path = native::global_path()?;
    let result = if create {
        Directory::maintenance_under(
            path.parent().ok_or("Global deployment parent missing")?,
            native::GLOBAL_DIRECTORY,
        )
    } else {
        Directory::open(&path)
    };
    match result {
        Ok(directory) => {
            directory.require_service_access()?;
            Ok(Some(directory))
        }
        Err(e) if !create && missing(e.as_ref()) => Ok(None),
        Err(e) => Err(e),
    }
}
fn read(directory: &Directory) -> Result<Option<Record>> {
    match directory.read_json::<Record>(JOURNAL) {
        Ok(record) => {
            record.validate()?;
            Ok(Some(record))
        }
        Err(e) if missing(e.as_ref()) => Ok(None),
        Err(e) => Err(e),
    }
}
fn snapshot(root: &Directory, record: &Record) -> Result<Directory> {
    let child = Directory::open(&root.path().join(&record.transaction))?;
    child.require_service_access()?;
    if Some(object(&child)?) != record.snapshot {
        return Err("Driver input snapshot identity changed".into());
    }
    let mut count = 0;
    for entry in std::fs::read_dir(child.path())? {
        count += 1;
        if count > INPUTS.len()
            || !record.inputs.contains_key(
                entry?
                    .file_name()
                    .to_str()
                    .ok_or("Invalid snapshot entry")?,
            )
        {
            return Err("Unexpected private driver input entry".into());
        }
    }
    Ok(child)
}
fn input_pins(child: &Directory, record: &Record) -> Result<Vec<File>> {
    record
        .inputs
        .iter()
        .map(|(name, input)| {
            let file = trust::pin(&child.path().join(name), &input.approved)?;
            let (v, id) = trust::identity(&file)?;
            if input.identity
                != Some(ObjectIdentity {
                    volume: v,
                    file_id: id,
                })
            {
                return Err("Driver snapshot member identity changed".into());
            }
            Ok(file)
        })
        .collect()
}
fn spec(root: &Directory, record: &Record) -> native::HelperSpec {
    native::HelperSpec {
        program: root.path().join(&record.transaction).join("management.exe"),
        transaction: record.transaction.clone(),
        nonce: record.nonce.clone(),
        binary: record.inputs["management.exe"].approved.clone(),
        owner_system: record.helper_owner_system,
    }
}
fn same_state(record: &Record, state: &Directory) -> Result<()> {
    if record.state_identity != object(state)?
        || !crate::protection::windows_evidence::prefix_equal(
            record.state.to_str().ok_or("Invalid recorded state")?,
            state.path().to_str().ok_or("Invalid state")?,
        )
    {
        return Err("Machine-global filter belongs to another endpoint state".into());
    }
    Ok(())
}
struct LockedFile(File);
impl Drop for LockedFile {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
/// Retained cooperative admission for machine/service-accessible operations.
/// Positively private non-administrator state has a separate per-user scope.
pub struct Admission {
    _file: Option<LockedFile>,
    _root: Option<Directory>,
    _user: Option<Directory>,
}
impl Admission {
    pub fn acquire(state: &Path) -> Result<Self> {
        if !windows_state::is_administrator()? {
            let directory = Directory::open(state)?;
            directory.require_private_user()?;
            return Ok(Self {
                _root: None,
                _file: None,
                _user: Some(directory),
            });
        }
        let root = global(true)?.ok_or("Machine admission directory unavailable")?;
        let file = LockedFile(root.maintenance_shared_lock(LOCK)?);
        require_settled(state)?;
        Ok(Self {
            _root: Some(root),
            _file: Some(file),
            _user: None,
        })
    }
}
/// Retains the exact exclusive global lock and ancestry in the internal
/// installer lease without reacquiring a conflicting ordinary shared lock.
pub(crate) struct Exclusive {
    _file: Arc<LockedFile>,
    _root: Arc<Directory>,
    state: PathBuf,
    identity: ObjectIdentity,
}
impl Exclusive {
    pub(crate) fn check(&self, state: &Directory) -> Result<()> {
        if object(state)? != self.identity || state.path() != self.state {
            return Err("Exclusive deployment lease belongs to another state".into());
        }
        Ok(())
    }
}
struct Owner {
    _lock: Arc<LockedFile>,
    root: Arc<Directory>,
    record: Record,
    poisoned: bool,
}
impl Owner {
    fn open() -> Result<Self> {
        let root = global(false)?.ok_or("No owned driver deployment")?;
        let lock = LockedFile(root.maintenance_lock(LOCK)?);
        let record = read(&root)?.ok_or("Missing driver deployment journal")?;
        Ok(Self {
            root: Arc::new(root),
            _lock: Arc::new(lock),
            record,
            poisoned: false,
        })
    }
    fn exclusive(&self) -> Result<Exclusive> {
        if self.poisoned {
            return Err("Driver journal durability is uncertain".into());
        }
        Ok(Exclusive {
            _root: self.root.clone(),
            _file: self._lock.clone(),
            state: self.record.state.clone(),
            identity: self.record.state_identity.clone(),
        })
    }
    fn save(&mut self, next: Record) -> Result<()> {
        if self.poisoned {
            return Err("Driver journal durability is uncertain".into());
        }
        next.validate()?;
        if read(&self.root)?.as_ref() != Some(&self.record) {
            return Err("Driver journal changed outside its owner".into());
        }
        self.poisoned = true;
        self.root.write_maintenance_json(JOURNAL, &next)?;
        self.record = next;
        self.poisoned = false;
        Ok(())
    }
    fn change(&mut self, f: impl FnOnce(&mut Record) -> Result<()>) -> Result<()> {
        let mut next = self.record.clone();
        f(&mut next)?;
        self.save(next)
    }
    fn verify(&self) -> Result<(Directory, Vec<File>, Directory)> {
        if self.poisoned {
            return Err("Driver journal durability is uncertain".into());
        }
        let (child, pins, state) = self.verify_files()?;
        if !native::epoch(&self.record.epoch)? {
            return Err(
                "Driver kernel-lifetime epoch expired; recorded native observations are stale"
                    .into(),
            );
        }
        Ok((child, pins, state))
    }
    fn verify_files(&self) -> Result<(Directory, Vec<File>, Directory)> {
        if self.poisoned {
            return Err("Driver journal durability is uncertain".into());
        }
        let state = Directory::open(&self.record.state)?;
        same_state(&self.record, &state)?;
        let child = snapshot(&self.root, &self.record)?;
        let pins = input_pins(&child, &self.record)?;
        Ok((child, pins, state))
    }
}
/// Unforgeable process-local capability: owns the machine-global lease and
/// exact transaction. Only the SCM LocalSystem entry constructs it.
pub(crate) struct Capability {
    _pins: Vec<File>,
    _snapshot: Directory,
    stop: Arc<AtomicBool>,
    owner: Owner,
}
impl Capability {
    pub(crate) fn exclusive(&self) -> Result<Exclusive> {
        self.owner.exclusive()
    }
    pub(crate) fn check(&self, state: &Path, binary: &Path) -> Result<()> {
        self.owner.verify()?;
        same_state(&self.owner.record, &Directory::open(state)?)?;
        if crate::file_hash(binary)? != self.owner.record.source_sha256 {
            return Err("Installer capability belongs to another executable".into());
        }
        if self.stop.load(Ordering::Acquire) {
            return Err("Coordinator stop requested; no new native effect is authorized".into());
        }
        Ok(())
    }
    pub(crate) fn before_complete(&mut self, state: &Directory) -> Result<()> {
        self.check(state.path(), &std::env::current_exe()?)?;
        if self.owner.record.phase == Phase::Claimed {
            self.owner.change(Record::endpoint)?;
        }
        if self.owner.record.phase == Phase::Endpoint {
            let descriptor = self.owner.record.descriptor.clone();
            let prepared = crate::windows_filter_package::prepared_directory(
                state.path(),
                &descriptor.sha256,
            )?;
            self.owner.change(Record::intent)?;
            let effect = native::install(prepared.path(), &descriptor)?;
            let registration = if effect.succeeded && !effect.need_reboot {
                Some(native::observe_registration(&descriptor)?)
            } else {
                None
            };
            self.owner
                .change(|r| r.result(effect, registration, None))?;
        }
        if self.owner.record.phase == Phase::Installed {
            self.check(state.path(), &std::env::current_exe()?)?;
            let registration = self
                .owner
                .record
                .registration
                .clone()
                .ok_or("Owned registration missing")?;
            self.owner.change(Record::intent)?;
            let effect = native::load(&self.owner.record.descriptor, &registration)?;
            let load = if effect.succeeded && !effect.need_reboot {
                Some(native::observe_load()?)
            } else {
                None
            };
            self.owner.change(|r| r.result(effect, None, load))?;
        }
        let load = native::observe_load()?;
        self.owner
            .record
            .authorize_complete(native::epoch(&self.owner.record.epoch)?, load.instance)
    }
    pub(crate) fn completed(&mut self) -> Result<()> {
        self.owner.change(Record::complete)
    }
}
/// All ordinary starts and maintenance paths fail closed for any pending global
/// transaction, including a different per-state directory. This is not a health
/// or cryptographic loaded-image claim.
pub fn require_settled(state: &Path) -> Result<()> {
    if !windows_state::is_administrator()? {
        Directory::open(state)?.require_private_user()?;
        return Ok(());
    }
    let Some(root) = global(false)? else {
        return Ok(());
    };
    let Some(record) = read(&root)? else {
        // An admission lock may exist before the first journal, but no native
        // effect is possible until the protected journal has been published.
        return Ok(());
    };
    if record.phase == Phase::Released {
        return Ok(());
    }
    if record.phase != Phase::Complete || record.publication.is_some() {
        return Err("Machine-global driver deployment is incomplete".into());
    }
    let directory = Directory::open(state)?;
    same_state(&record, &directory)?;
    if !native::epoch(&record.epoch)? {
        return Err("Driver load observation is stale after kernel-lifetime invalidation".into());
    }
    if native::observe_registration(&record.descriptor)?.ne(record
        .registration
        .as_ref()
        .ok_or("Owned registration missing")?)
    {
        return Err("Owned driver registration is no longer observed".into());
    }
    // This is durable transaction exclusion, not current load-instance proof.
    // Only the LocalSystem startup gate below can compare the port's live UUID.
    Ok(())
}
pub fn require_owned(state: &Path) -> Result<()> {
    require_settled(state)?;
    let root = global(false)?.ok_or("Required driver deployment ownership is missing")?;
    let record = read(&root)?.ok_or("Required driver deployment receipt is missing")?;
    if record.phase != Phase::Complete {
        return Err("Required driver deployment was not completed".into());
    }
    same_state(&record, &Directory::open(state)?)
}
pub fn require_live(state: &Path) -> Result<()> {
    if !windows_state::is_administrator()? {
        Directory::open(state)?.require_private_user()?;
        return Ok(());
    }
    let Some(root) = global(false)? else {
        return Ok(());
    };
    let Some(record) = read(&root)? else {
        return Ok(());
    };
    if record.phase == Phase::Released {
        return Ok(());
    }
    require_owned(state)?;
    let current = native::observe_load()?;
    record.authorize_complete(native::epoch(&record.epoch)?, current.instance)
}
fn read_input(bundle: &Path, name: &str, limit: u64) -> Result<Vec<u8>> {
    let actual = if name == "management.exe" {
        "athernex-endpoint.exe"
    } else {
        name
    };
    let path = bundle.join(actual);
    let bytes = crate::update::read_bounded(&path, limit)?;
    let approved = Member {
        bytes: bytes.len() as u64,
        sha256: protocol::hash(&bytes),
    };
    let _pin = trust::pin(&path, &approved)?;
    Ok(bytes)
}
fn start(owner: &mut Owner) -> Result<()> {
    let (snapshot, _pins, _state) = owner.verify()?;
    let expected = spec(&owner.root, &owner.record);
    let helper = if owner.record.phase == Phase::Ready {
        owner.change(Record::create_intent)?;
        let helper = native::Helper::create(&expected)?;
        owner.change(Record::created)?;
        helper
    } else {
        if !owner.record.helper_created {
            return Err("Unconfirmed coordinator creation cannot be adopted".into());
        }
        let helper = native::Helper::open_owned(&expected)?;
        if helper.status()?.state != windows_sys::Win32::System::Services::SERVICE_STOPPED {
            return Err("The previous coordinator still owns its operation".into());
        }
        if let Some((pid, created)) = owner.record.worker {
            if !athernex_endpoint_native::windows_filter::peer::original_process_ended(
                pid, created,
            )? {
                return Err("The original coordinator process has not exited".into());
            }
        }
        helper
    };
    owner.change(Record::start_intent)?;
    helper.start()?;
    owner.change(Record::started)?;
    drop(snapshot);
    Ok(())
}
fn wait(transaction: &str) -> Result<()> {
    let deadline = Instant::now() + WAIT;
    loop {
        let root = global(false)?.ok_or("Driver coordinator state disappeared")?;
        let record = read(&root)?.ok_or("Driver coordinator journal disappeared")?;
        if record.transaction != transaction {
            return Err("Driver coordinator transaction changed".into());
        }
        if matches!(record.phase, Phase::Complete | Phase::Retired) {
            return Ok(());
        }
        if matches!(record.phase, Phase::Uncertain | Phase::RebootPending) {
            return Err(
                "Driver native effect requires explicit reconciliation; services remain blocked"
                    .into(),
            );
        }
        if Instant::now() >= deadline {
            return Err("Driver coordinator remains owned or uncertain; timeout does not cancel native work".into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
/// Admin-side admission. It never acquires per-state installer/update/service
/// leases while waiting for the LocalSystem worker that owns those leases.
pub fn install(bundle: &Path, agent: &Path, state: &Path) -> Result<()> {
    windows_state::require_administrator()?;
    let _bundle = PinnedDirectory::open(bundle)?;
    let artifact: Artifact = serde_json::from_slice(&read_input(bundle, "release.json", 16384)?)?;
    let descriptor = artifact
        .filter()?
        .ok_or("Deployment package missing")?
        .clone();
    if descriptor.deployment != Some(Deployment::InstallAndObserveDisarmedV1)
        || artifact.signing != "native-signature-verified"
    {
        return Err("Explicit signed driver deployment is required".into());
    }
    crate::windows_filter_package::components(bundle, &artifact)?;
    let binary = read_input(bundle, "athernex-endpoint.exe", 64 * 1024 * 1024)?;
    if protocol::hash(&binary) != artifact.sha256
        || crate::file_hash(&std::env::current_exe()?)? != artifact.sha256
        || artifact.target != protocol::update::target()
    {
        return Err("Coordinator source differs from approved release".into());
    }
    trust::verify_executable(
        &bundle.join("athernex-endpoint.exe"),
        &Member {
            bytes: binary.len() as u64,
            sha256: artifact.sha256.clone(),
        },
    )?;
    // Existing release/config and quiet checks are repeated by the worker under
    // the real per-state leases. This parent check does not assert quiescence.
    crate::update::installer_check(state, &bundle.join("athernex-endpoint.exe"), false)?;
    let root = global(true)?.ok_or("Global driver state unavailable")?;
    let lock = LockedFile(root.maintenance_lock(LOCK)?);
    let previous = read(&root)?;
    if previous
        .as_ref()
        .is_some_and(|r| r.phase != Phase::Released)
    {
        return Err("Existing global deployment must be recovered or retired explicitly; no installer adoption".into());
    }
    if let Some(previous) = &previous {
        verify_archive(&root, previous)?;
    }
    let bootstrap = crate::setup::read_bootstrap(&bundle.join("bootstrap.json"))?;
    crate::installer::deployment_preflight(
        root.path(),
        bundle,
        state,
        agent,
        &artifact,
        &bootstrap,
    )?;
    let epoch = ensure_epoch(&root)?;
    let state = Directory::maintenance_under(
        state.parent().ok_or("State parent missing")?,
        state
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("State leaf missing")?,
    )?;
    state.require_service_access()?;
    let mut contents = BTreeMap::new();
    for name in INPUTS {
        let limit = match name {
            "bootstrap.json" => 65536,
            "release.json" => 16384,
            "windows-filter.required" => 2,
            _ => 64 * 1024 * 1024,
        };
        contents.insert(name.to_string(), read_input(bundle, name, limit)?);
    }
    let mut total = 0u64;
    for (name, bytes) in &contents {
        if name != "management.exe" {
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or("Snapshot budget overflow")?;
        }
    }
    if total > 64 * 1024 * 1024 + 65536 + 16384 + 2 {
        return Err("Driver installer snapshot exceeds aggregate budget".into());
    }
    let record = Record {
        schema: 1,
        transaction: crate::secret()?,
        nonce: crate::secret()?,
        source_sha256: artifact.sha256,
        state: state.path().to_path_buf(),
        state_identity: object(&state)?,
        agent: agent.to_path_buf(),
        descriptor,
        epoch,
        epoch_confirmed: true,
        refresh_epoch: None,
        previous_load: None,
        snapshot: None,
        inputs: contents
            .iter()
            .map(|(name, bytes)| {
                (
                    name.clone(),
                    Input {
                        approved: Member {
                            bytes: bytes.len() as u64,
                            sha256: protocol::hash(bytes),
                        },
                        identity: None,
                    },
                )
            })
            .collect(),
        phase: Phase::Snapshot,
        operation: Operation::Install,
        helper_created: false,
        helper_owner_system: windows_state::require_local_system().is_ok(),
        resume_phase: None,
        archive: None,
        publication: None,
        worker: None,
        registration: None,
        load: None,
        effect: None,
    };
    record.validate()?;
    if previous.is_some() {
        root.write_maintenance_json(JOURNAL, &record)?;
    } else {
        root.publish_maintenance(JOURNAL, &serde_json::to_vec(&record)?)?;
    }
    let mut owner = Owner {
        root: Arc::new(root),
        _lock: Arc::new(lock),
        record,
        poisoned: false,
    };
    let child = owner
        .root
        .fresh_maintenance_directory(&owner.record.transaction)?;
    owner.change(|r| {
        r.snapshot = Some(object(&child)?);
        Ok(())
    })?;
    for (name, bytes) in contents {
        child.publish_maintenance(&name, &bytes)?;
        let file = trust::pin(
            &child.path().join(&name),
            &owner.record.inputs[&name].approved,
        )?;
        let (volume, file_id) = trust::identity(&file)?;
        owner.change(|r| {
            r.inputs
                .get_mut(&name)
                .ok_or("Unknown snapshot input")?
                .identity = Some(ObjectIdentity { volume, file_id });
            Ok(())
        })?;
    }
    owner.change(Record::ready)?;
    start(&mut owner)?;
    let transaction = owner.record.transaction.clone();
    drop(owner);
    wait(&transaction)
}

pub fn coordinate(transaction: &str, nonce: &str) -> Result<()> {
    if !protocol::hex_id(transaction) || !protocol::hex_id(nonce) {
        return Err("Invalid coordinator transaction".into());
    }
    let transaction = transaction.to_owned();
    let nonce = nonce.to_owned();
    native::serve(move |stop| {
        // StartService can run the service main before the parent publishes its
        // successful start receipt. Wait only for the held admission lease.
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut owner = loop {
            match Owner::open() {
                Ok(owner) => break owner,
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        };
        if owner.record.transaction != transaction || owner.record.nonce != nonce {
            return Err("Coordinator transaction differs".into());
        }
        let (snapshot, pins, _state) = owner.verify()?;
        let helper = native::Helper::open_owned(&spec(&owner.root, &owner.record))?;
        let current = helper.status()?;
        if current.pid != std::process::id() {
            return Err("Coordinator is not the exact SCM process".into());
        }
        let created = current
            .created
            .ok_or("Coordinator process identity missing")?;
        owner.change(|r| r.claim(current.pid, created))?;
        let operation = owner.record.operation;
        let bundle = snapshot.path().to_path_buf();
        let agent = owner.record.agent.clone();
        let state = owner.record.state.clone();
        let mut capability = Capability {
            owner,
            stop,
            _snapshot: snapshot,
            _pins: pins,
        };
        match operation {
            Operation::Install => {
                crate::installer::install_owned(&bundle, &agent, &state, &mut capability)
            }
            Operation::Reload => reload_worker(&mut capability),
            Operation::Retire => retire_worker(&mut capability),
        }
    })
}
fn reload_worker(capability: &mut Capability) -> Result<()> {
    let state = Directory::open(&capability.owner.record.state)?;
    let lease = crate::installer::Lease::acquire_owned(state, capability.owner.exclusive()?)?;
    let _quiet = crate::update::InstallerGuard::acquire(&lease)?;
    // A completed endpoint is preserved; this operation performs no enrollment,
    // binary replacement, configuration rewrite or Driver Store installation.
    crate::installer::require_completed_driver(
        &lease,
        &capability.owner.record.source_sha256,
        &capability.owner.record.descriptor.sha256,
    )?;
    capability.before_complete(&Directory::open(lease.state())?)?;
    capability.completed()
}
fn retire_worker(capability: &mut Capability) -> Result<()> {
    let state = Directory::open(&capability.owner.record.state)?;
    let lease = crate::installer::Lease::acquire_owned(state, capability.owner.exclusive()?)?;
    let _quiet = crate::update::InstallerGuard::acquire(&lease)?;
    capability.check(lease.state(), &std::env::current_exe()?)?;
    let descriptor = capability.owner.record.descriptor.clone();
    let registration = capability
        .owner
        .record
        .registration
        .clone()
        .ok_or("Owned registration missing")?;
    if capability.owner.record.phase == Phase::Claimed {
        let load = capability
            .owner
            .record
            .load
            .clone()
            .ok_or("Owned load receipt missing")?;
        capability.owner.change(Record::intent)?;
        let effect = native::unload(&descriptor, &registration, &load)?;
        if effect.succeeded && native::filter_present()? {
            return Err("Filter remains present after unload".into());
        }
        capability.owner.change(|r| r.result(effect, None, None))?;
    }
    if capability.owner.record.phase == Phase::Unloaded {
        capability.check(lease.state(), &std::env::current_exe()?)?;
        capability.owner.change(Record::intent)?;
        let effect = native::uninstall(&descriptor, &registration)?;
        if effect.succeeded && !effect.need_reboot {
            let state = native::inspect()?;
            if state.service.is_some() || state.filter_present || !state.candidate_infs.is_empty() {
                return Err("Driver retirement has remaining native state".into());
            }
        }
        capability.owner.change(|r| r.result(effect, None, None))?;
    }
    if capability.owner.record.phase != Phase::Retired {
        return Err("Driver retirement is incomplete; no native effect is replayed".into());
    }
    Ok(())
}
fn publish_receipt(
    owner: &mut Owner,
    kind: ReceiptKind,
    destination: &str,
    bytes: &[u8],
) -> Result<Input> {
    let expected = Member {
        bytes: bytes.len() as u64,
        sha256: protocol::hash(bytes),
    };
    if owner.record.publication.is_none() {
        let temporary = crate::secret()?;
        let name = format!("receipt-{temporary}.tmp");
        owner.root.publish_maintenance(&name, bytes)?;
        let file = owner.root.read(&name)?;
        let (volume, file_id) = trust::identity(&file)?;
        owner.change(|r| {
            r.publish_intent(Publication {
                kind,
                temporary,
                receipt: Input {
                    approved: expected.clone(),
                    identity: Some(ObjectIdentity { volume, file_id }),
                },
            })
        })?;
    }
    let publication = owner
        .record
        .publication
        .as_ref()
        .ok_or("Receipt publication intent missing")?;
    if publication.kind != kind || publication.receipt.approved != expected {
        return Err("Receipt publication differs from the approved local transition".into());
    }
    let id = publication
        .receipt
        .identity
        .as_ref()
        .ok_or("Receipt object identity missing")?;
    owner.root.publish_recorded_receipt(
        &format!("receipt-{}.tmp", publication.temporary),
        destination,
        id.volume,
        id.file_id,
        &expected,
    )?;
    Ok(publication.receipt.clone())
}
fn completed_name(record: &Record, load: &LoadObserved) -> String {
    let instance: String = load.instance.iter().map(|v| format!("{v:02x}")).collect();
    format!("completed-{}-{instance}.json", record.transaction)
}
fn refresh_completed(owner: &mut Owner) -> Result<()> {
    let (_snapshot, _pins, state) = owner.verify_files()?;
    let lease = crate::installer::Lease::acquire_owned(state, owner.exclusive()?)?;
    let _quiet = crate::update::InstallerGuard::acquire(&lease)?;
    ended(&owner.record)?;
    let helper = native::Helper::open_owned(&spec(&owner.root, &owner.record))?;
    if helper.status()?.state != windows_sys::Win32::System::Services::SERVICE_STOPPED {
        return Err("Completed coordinator has not stopped".into());
    }
    let inventory = native::inspect()?;
    if inventory.filter_present
        || inventory
            .service
            .as_ref()
            .is_none_or(|s| s.state != windows_sys::Win32::System::Services::SERVICE_STOPPED)
        || Some(native::observe_registration(&owner.record.descriptor)?)
            != owner.record.registration
    {
        return Err("Completed registration is not exact and currently unloaded".into());
    }
    // State and immutable prepared package remain pinned while claiming reload.
    let _prepared = crate::windows_filter_package::prepared_directory(
        lease.state(),
        &owner.record.descriptor.sha256,
    )?;
    if owner.record.phase == Phase::Complete {
        let epoch = if native::epoch(&owner.record.epoch)? {
            owner.record.epoch.clone()
        } else {
            crate::secret()?
        };
        let load = owner
            .record
            .load
            .clone()
            .ok_or("Completed load receipt missing")?;
        let mut prior = owner.record.clone();
        prior.publication = None;
        let bytes = serde_json::to_vec(&prior)?;
        let name = completed_name(&owner.record, &load);
        let receipt = publish_receipt(owner, ReceiptKind::Completed, &name, &bytes)?;
        let previous = CompletedLoad {
            epoch: owner.record.epoch.clone(),
            load,
            receipt,
        };
        owner.change(|r| r.refresh_intent(epoch, previous))?;
    }
    let previous = owner
        .record
        .previous_load
        .as_ref()
        .ok_or("Previous completed load missing")?;
    let path = owner
        .root
        .path()
        .join(completed_name(&owner.record, &previous.load));
    let _history = trust::pin(&path, &previous.receipt.approved)?;
    let (volume, file_id) = trust::identity(&_history)?;
    if previous.receipt.identity != Some(ObjectIdentity { volume, file_id }) {
        return Err("Previous completed-load receipt identity changed".into());
    }
    let target = owner
        .record
        .refresh_epoch
        .clone()
        .ok_or("Epoch refresh claim missing")?;
    let mut epoch: Epoch = owner.root.read_json("kernel-epoch.json")?;
    if epoch.schema != 1
        || !epoch.confirmed
        || !protocol::hex_id(&epoch.value)
        || (epoch.value != previous.epoch && epoch.value != target)
    {
        return Err("Epoch refresh has unconfirmed or foreign ownership".into());
    }
    let present = native::epoch(&epoch.value)?;
    if present && epoch.value != target {
        return Err("Prior epoch reappeared during refresh".into());
    }
    if !present {
        epoch.value = target.clone();
        epoch.confirmed = false;
        owner
            .root
            .write_maintenance_json("kernel-epoch.json", &epoch)?;
        native::create_epoch(&target)?;
        epoch.confirmed = true;
        owner
            .root
            .write_maintenance_json("kernel-epoch.json", &epoch)?;
    }
    if !native::epoch(&target)? {
        return Err("Refreshed epoch is not present".into());
    }
    owner.change(|r| r.refreshed(&target))
}
pub fn recover(state: &Path) -> Result<()> {
    windows_state::require_administrator()?;
    let mut owner = Owner::open()?;
    same_state(&owner.record, &Directory::open(state)?)?;
    // Only boundaries with a durable completed native result can resume. Every
    // in-flight intent, unknown helper creation and reboot result remains refused.
    if matches!(
        owner.record.phase,
        Phase::Retired | Phase::DeleteIntent | Phase::HelperDeleted
    ) {
        return finish_retirement(owner);
    }
    if matches!(owner.record.phase, Phase::Complete | Phase::RefreshIntent) {
        refresh_completed(&mut owner)?;
    }
    if !matches!(
        owner.record.phase,
        Phase::Ready
            | Phase::HelperCreated
            | Phase::Claimed
            | Phase::Endpoint
            | Phase::Installed
            | Phase::Loaded
            | Phase::Unloaded
    ) {
        return Err("Deployment requires native reconciliation; unknown effects cannot be adopted or repeated".into());
    }
    start(&mut owner)?;
    let transaction = owner.record.transaction.clone();
    drop(owner);
    wait(&transaction)
}
pub fn retire(state: &Path) -> Result<()> {
    windows_state::require_administrator()?;
    let mut owner = Owner::open()?;
    same_state(&owner.record, &Directory::open(state)?)?;
    owner.verify()?;
    let helper = native::Helper::open_owned(&spec(&owner.root, &owner.record))?;
    if helper.status()?.state != windows_sys::Win32::System::Services::SERVICE_STOPPED {
        return Err("The original coordinator has not stopped".into());
    }
    if owner.record.phase == Phase::Uncertain
        && owner.record.registration.is_some()
        && owner.record.load.is_none()
    {
        let current = native::inspect()?;
        let absent = !current.filter_present
            && current
                .service
                .as_ref()
                .is_some_and(|s| s.state == windows_sys::Win32::System::Services::SERVICE_STOPPED);
        if native::observe_registration(&owner.record.descriptor)?.ne(owner
            .record
            .registration
            .as_ref()
            .ok_or("Owned registration missing")?)
        {
            return Err("Failed load registration differs from ownership".into());
        }
        owner.change(|r| r.failed_load_retirement(absent))?;
    } else {
        owner.change(Record::request_retirement)?;
    }
    start(&mut owner)?;
    let transaction = owner.record.transaction.clone();
    drop(owner);
    wait(&transaction)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match Owner::open() {
            Ok(owner) => match finish_retirement(owner) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                }
            },
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn require_native_absence() -> Result<()> {
    let current = native::inspect()?;
    if current.filter_present || current.service.is_some() || !current.candidate_infs.is_empty() {
        return Err("Driver retirement has remaining or foreign native state".into());
    }
    Ok(())
}
fn ended(record: &Record) -> Result<()> {
    let (pid, created) = record
        .worker
        .ok_or("Original coordinator process receipt missing")?;
    if !athernex_endpoint_native::windows_filter::peer::original_process_ended(pid, created)? {
        return Err("Original coordinator process is still active".into());
    }
    Ok(())
}
fn archive_name(record: &Record) -> String {
    format!("retired-{}.json", record.transaction)
}
fn verify_archive(root: &Directory, record: &Record) -> Result<()> {
    let file = root.read(&archive_name(record))?;
    let (volume, file_id) = trust::identity(&file)?;
    if record.archive != Some(ObjectIdentity { volume, file_id }) {
        return Err("Terminal driver archive identity changed".into());
    }
    let mut expected = record.clone();
    expected.archive = None;
    expected.phase = Phase::HelperDeleted;
    let bytes = serde_json::to_vec(&expected)?;
    let _pin = trust::pin(
        &root.path().join(archive_name(record)),
        &Member {
            bytes: bytes.len() as u64,
            sha256: protocol::hash(&bytes),
        },
    )?;
    Ok(())
}
fn finish_retirement(mut owner: Owner) -> Result<()> {
    if !matches!(
        owner.record.phase,
        Phase::Retired | Phase::DeleteIntent | Phase::HelperDeleted
    ) {
        return Err("Driver retirement is not terminal".into());
    }
    ended(&owner.record)?;
    require_native_absence()?;
    let state = Directory::open(&owner.record.state)?;
    same_state(&owner.record, &state)?;
    let lease = crate::installer::Lease::acquire_owned(state, owner.exclusive()?)?;
    let _quiet = crate::update::InstallerGuard::acquire(&lease)?;
    if owner.record.phase == Phase::Retired {
        let helper = native::Helper::open_owned(&spec(&owner.root, &owner.record))?;
        if helper.status()?.state != windows_sys::Win32::System::Services::SERVICE_STOPPED {
            return Err("Owned coordinator is not stopped".into());
        }
        owner.change(Record::delete_intent)?;
        helper.delete_stopped()?;
        drop(helper);
    }
    if owner.record.phase == Phase::DeleteIntent {
        // A successful absence observation can close an owned deletion intent;
        // an existing equal-looking service is never adopted or deleted again.
        if !native::helper_absent()? {
            return Err("Owned coordinator deletion is unconfirmed".into());
        }
        owner.change(Record::helper_deleted)?;
    }
    crate::installer::mark_driver_retired(
        &lease,
        &owner.record.source_sha256,
        &owner.record.descriptor.sha256,
    )?;
    require_native_absence()?;
    if owner.record.archive.is_none() {
        let name = archive_name(&owner.record);
        let mut prior = owner.record.clone();
        prior.publication = None;
        let bytes = serde_json::to_vec(&prior)?;
        publish_receipt(&mut owner, ReceiptKind::Retired, &name, &bytes)?;
        owner.change(Record::archived)?;
    }
    verify_archive(&owner.root, &owner.record)?;
    owner.change(Record::release)
}
pub fn status() -> Result<serde_json::Value> {
    let Some(root) = global(false)? else {
        return Ok(serde_json::json!({"owned":false}));
    };
    let Some(record) = read(&root)? else {
        return Ok(serde_json::json!({"owned":false}));
    };
    Ok(
        serde_json::json!({"owned":true,"phase":record.phase,"operation":record.operation,
        "epoch_matches":native::epoch(&record.epoch)?,"native":native::inspect()?,
        "loaded_image_attested":false,"production_protection_verified":false}),
    )
}
