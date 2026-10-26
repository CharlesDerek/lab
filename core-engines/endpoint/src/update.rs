//! Signed local update transactions. Staging can run online; replacement and
//! recovery require the management and prevention services to be stopped.
use crate::{
    now_ms, private_write, run_bounded, Config, Process as Command, Result, StateLock, Store,
};
use athernex_endpoint_protocol::{
    self as protocol,
    update::{self as wire, SignedRelease},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePolicy {
    #[serde(default)]
    pub automatic: bool,
    #[serde(default)]
    pub managed: bool,
    pub public_key: String,
    pub channel: String,
    pub install_path: Option<PathBuf>,
    /// A separate controller executable; configured locally, never by a release.
    #[serde(default)]
    pub controller_path: Option<PathBuf>,
    #[serde(default)]
    pub controller_automatic: bool,
    #[serde(default)]
    pub controller_managed: bool,
    /// Stable service entrypoint, maintained by the installer rather than by
    /// controller replacement. It must survive a broken controller candidate.
    #[serde(default)]
    pub launcher_path: Option<PathBuf>,
    #[serde(default)]
    pub minimum_sequence: u64,
    #[serde(default)]
    pub allow_unsigned_native: bool,
}
impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            automatic: false,
            managed: false,
            public_key: String::new(),
            channel: "stable".into(),
            install_path: None,
            controller_path: None,
            controller_automatic: false,
            controller_managed: false,
            launcher_path: None,
            minimum_sequence: 0,
            allow_unsigned_native: false,
        }
    }
}
impl UpdatePolicy {
    pub fn enabled(&self) -> bool {
        !self.public_key.is_empty()
    }
    pub fn validate(&self) -> Result<()> {
        if self.controller_managed && (!self.enabled() || self.controller_path.is_none()) {
            return Err(
                "Managed controller delivery requires a trusted key and controller path".into(),
            );
        }
        if self.controller_automatic
            && (!self.enabled()
                || self.controller_path.is_none()
                || self.launcher_path.is_none()
                || !cfg!(any(target_os = "linux", windows)))
        {
            return Err("Automatic controller replacement requires a trusted key, controller/launcher paths and a supported platform (Linux or Windows)".into());
        }
        if let Some(launcher) = &self.launcher_path {
            if !launcher.is_absolute()
                || launcher.file_name().is_none()
                || launcher.as_os_str().len() > 2048
                || self.install_path.as_ref() == Some(launcher)
                || self.controller_path.as_ref() == Some(launcher)
            {
                return Err("Launcher must have a distinct absolute installation path".into());
            }
        }
        if let Some(controller) = &self.controller_path {
            if !self.enabled()
                || !controller.is_absolute()
                || controller.file_name().is_none()
                || controller.as_os_str().len() > 2048
                || self.install_path.as_ref() == Some(controller)
            {
                return Err("Controller updates require a trusted key and a distinct absolute installation path".into());
            }
        }
        if self.automatic && (!self.managed || !cfg!(any(target_os = "linux", windows))) {
            return Err("Automatic installation requires managed delivery and a supported controller platform (Linux or Windows)".into());
        }
        if !self.enabled() {
            if self.managed {
                return Err("Managed updates require a locally pinned release key".into());
            }
            return Ok(());
        }
        wire::decode::<32>(&self.public_key)?;
        if !["stable", "preview"].contains(&self.channel.as_str())
            || self.minimum_sequence > i64::MAX as u64
            || self.install_path.as_ref().is_none_or(|p| {
                !p.is_absolute() || p.file_name().is_none() || p.as_os_str().len() > 2048
            })
        {
            return Err("Invalid local update policy".into());
        }
        Ok(())
    }
}

/// Agent and controller share release authorization, but retain independent
/// transaction journals and monotonic sequence histories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Agent,
    Controller,
}
impl Component {
    pub(crate) fn directory(self, state: &Path) -> PathBuf {
        state.join(match self {
            Self::Agent => "updates",
            Self::Controller => "updates/controller",
        })
    }
    fn config(self, state: &Path) -> Result<Config> {
        let mut configuration = config(state)?;
        if self == Self::Controller {
            if let (Some(agent), Some(controller)) = (
                &configuration.updates.install_path,
                &configuration.updates.controller_path,
            ) {
                if agent.try_exists()?
                    && controller.try_exists()?
                    && agent.canonicalize()? == controller.canonicalize()?
                {
                    return Err("Controller and agent must use distinct installation paths".into());
                }
            }
            configuration.updates.install_path = Some(
                configuration
                    .updates
                    .controller_path
                    .clone()
                    .ok_or("Controller updates require a locally configured controller_path")?,
            );
        }
        Ok(configuration)
    }
}
impl From<wire::Component> for Component {
    fn from(value: wire::Component) -> Self {
        match value {
            wire::Component::Agent => Self::Agent,
            wire::Component::Controller => Self::Controller,
        }
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateStatus {
    pub highwater: u64,
    pub staged: Option<SignedRelease>,
    pub installed: Option<SignedRelease>,
    pub transaction: Option<Transaction>,
    pub cleanup: Option<Backup>,
    pub last_result: String,
    pub last_error: String,
    pub updated_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    #[serde(default)]
    pub trial: Option<Trial>,
    pub release: SignedRelease,
    pub install_path: PathBuf,
    pub backup: Backup,
    pub next_path: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trial {
    pub nonce: String,
    pub expires_ms: u64,
}

pub(super) fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > max {
        return Err("Release file exceeds its size/type budget".into());
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("Release file grew beyond its byte budget".into());
    }
    Ok(bytes)
}
pub fn binary_target(bytes: &[u8]) -> Result<&'static str> {
    if bytes.len() < 64 {
        return Err("Truncated endpoint executable".into());
    }
    Ok(if bytes.starts_with(b"\x7fELF\x02\x01") {
        match u16::from_le_bytes(bytes[18..20].try_into()?) {
            62 => "linux-x86_64",
            183 => "linux-aarch64",
            _ => return Err("Unsupported ELF architecture".into()),
        }
    } else if bytes.starts_with(b"MZ") {
        let offset = u32::from_le_bytes(bytes[60..64].try_into()?) as usize;
        if bytes.get(offset..offset.saturating_add(6)) != Some(b"PE\0\0\x64\x86") {
            return Err("Unsupported PE executable".into());
        }
        "windows-x86_64"
    } else if bytes.starts_with(b"\xcf\xfa\xed\xfe") {
        match u32::from_le_bytes(bytes[4..8].try_into()?) {
            0x1000007 => "macos-x86_64",
            0x100000c => "macos-aarch64",
            _ => return Err("Unsupported Mach-O architecture".into()),
        }
    } else {
        return Err("Unsupported endpoint executable format".into());
    })
}
fn verify_binary(manifest: &SignedRelease, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 != manifest.release.bytes
        || protocol::hash(bytes) != manifest.release.sha256
        || binary_target(bytes)? != manifest.release.target
    {
        return Err("Endpoint release bytes do not match the signed manifest".into());
    }
    Ok(())
}
fn config(state: &Path) -> Result<Config> {
    let config: Config = serde_json::from_slice(&read_bounded(&state.join("config.json"), 65536)?)?;
    config.validate()?;
    if !config.updates.enabled() {
        return Err(
            "Updates require a locally configured release key and installation path".into(),
        );
    }
    Ok(config)
}
fn lock(state: &Path) -> Result<StateLock> {
    try_maintenance_lock(state)?.ok_or_else(|| "Another update transaction is running".into())
}
pub(crate) fn try_maintenance_lock(state: &Path) -> Result<Option<StateLock>> {
    #[cfg(windows)]
    crate::installer::require_complete(state)?;
    let lease = try_maintenance_lock_raw(state)?;
    // The first check could precede an installer that subsequently crashed.
    // Once this lease is held, an installer cannot advance its journal.
    #[cfg(windows)]
    if lease.is_some() {
        crate::installer::require_complete(state)?;
    }
    Ok(lease)
}
fn try_maintenance_lock_raw(state: &Path) -> Result<Option<StateLock>> {
    let directory = state.join("updates");
    if !directory.exists() {
        fs::create_dir(&directory)?;
    }
    if fs::symlink_metadata(&directory)?.file_type().is_symlink() {
        return Err("Update state cannot be a symlink".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("update.lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(StateLock(file))),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub(crate) fn maintenance_lock(state: &Path) -> Result<StateLock> {
    lock(state)
}
pub(crate) fn require_component_transactions_settled(state: &Path) -> Result<()> {
    for component in [Component::Agent, Component::Controller] {
        if status_component(state, component)?.transaction.is_some() {
            return Err(
                "Recover the interrupted executable update before engine maintenance".into(),
            );
        }
    }
    Ok(())
}
pub fn status(state: &Path) -> Result<UpdateStatus> {
    status_component(state, Component::Agent)
}
pub fn status_component(state: &Path, component: Component) -> Result<UpdateStatus> {
    match read_bounded(&component.directory(state).join("status.json"), 32768) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(UpdateStatus::default())
        }
        Err(e) => Err(e),
    }
}
pub fn require_recovered(state: &Path) -> Result<()> {
    #[cfg(windows)]
    crate::installer::require_complete(state)?;
    crate::engine_update::require_start_allowed(state)?;
    require_other_recovered(state, Component::Agent)?;
    if let Some(transaction) = status(state)?.transaction {
        if let Some(trial) = &transaction.trial {
            let config = config(state)?;
            transaction
                .release
                .authenticate(&config.updates.public_key)?;
            if now_ms() < trial.expires_ms
                && crate::supervisor::controller_active(state, &trial.nonce)
                && std::env::current_exe()?.canonicalize()?
                    == transaction.install_path.canonicalize()?
                && crate::file_hash(&transaction.install_path)?
                    == transaction.release.release.sha256
            {
                return Ok(());
            }
        }
        return Err("Recover the interrupted endpoint update before starting services".into());
    }
    Ok(())
}
fn require_other_recovered(state: &Path, component: Component) -> Result<()> {
    let other = match component {
        Component::Agent => Component::Controller,
        Component::Controller => Component::Agent,
    };
    if let Some(transaction) = status_component(state, other)?.transaction {
        if other == Component::Controller && crate::guardian::work_allowed(state, &transaction)? {
            return Ok(());
        }
        return Err("Recover the other component's interrupted update before starting work".into());
    }
    Ok(())
}
fn prepare_component(state: &Path, component: Component) -> Result<()> {
    let directory = std::path::absolute(component.directory(state))?;
    if !directory.try_exists()? {
        fs::create_dir(&directory)?;
    }
    no_links(&directory)?;
    if !fs::metadata(&directory)?.is_dir() {
        return Err("Update ledger must be a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
struct ControllerGuard {
    _controller: StateLock,
    _launcher: Option<StateLock>,
}
fn controller_quiescent(state: &Path, component: Component) -> Result<Option<ControllerGuard>> {
    if component == Component::Agent {
        return Ok(None);
    }
    let launcher = crate::guardian::quiescent(state)?;
    let directory = std::path::absolute(state.join("supervisor"))?;
    if !directory.try_exists()? {
        fs::create_dir(&directory)?;
    }
    no_links(&directory)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("controller.lock"))?;
    file.try_lock()
        .map_err(|_| "Stop the endpoint controller before replacing or recovering it")?;
    Ok(Some(ControllerGuard {
        _controller: StateLock(file),
        _launcher: launcher,
    }))
}
/// Called with the controller lock held, before launching any managed child.
pub(crate) fn controller_startup(state: &Path) -> Result<()> {
    #[cfg(windows)]
    crate::installer::require_complete(state)?;
    let record = status_component(state, Component::Controller)?;
    if let Some(transaction) = &record.transaction {
        if crate::guardian::controller_allowed(state, transaction)? {
            return Ok(());
        }
        return Err(
            "Recover the interrupted controller update using a separate trusted executable".into(),
        );
    }
    if let Some(release) = record.installed {
        let configuration = Component::Controller.config(state)?;
        release.authenticate(&configuration.updates.public_key)?;
        let destination = configuration.updates.install_path.as_ref().unwrap();
        check_destination(destination)?;
        if std::env::current_exe()?.canonicalize()? != destination.canonicalize()?
            || crate::file_hash(destination)? != release.release.sha256
        {
            return Err("Controller executable does not match its confirmed release ledger".into());
        }
    }
    Ok(())
}
#[cfg(test)]
fn save(state: &Path, status: &mut UpdateStatus) -> Result<()> {
    save_component(state, Component::Agent, status)
}
fn save_component(state: &Path, component: Component, status: &mut UpdateStatus) -> Result<()> {
    status.updated_ms = now_ms();
    private_write(
        &component.directory(state).join("status.json"),
        &serde_json::to_vec_pretty(status)?,
    )
}
fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path.parent().ok_or("Missing parent")?)?.sync_all()?;
    let _ = path;
    Ok(())
}
pub(crate) fn no_links(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("Installation paths must be absolute without parent traversal".into());
    }
    for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() {
            return Err("Installation paths cannot contain symlinks".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Installation paths cannot contain reparse points".into());
            }
        }
    }
    Ok(())
}
pub(crate) fn check_destination(path: &Path) -> Result<()> {
    no_links(path)?;
    if !fs::symlink_metadata(path)?.is_file() {
        return Err("Update installation must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let updater = unsafe { libc::geteuid() };
        for item in [path, path.parent().ok_or("Missing installation parent")?] {
            let m = fs::metadata(item)?;
            if m.uid() != updater || m.mode() & 0o022 != 0 {
                return Err("Installation file and directory must belong to the updater and reject group/other writes".into());
            }
        }
        for ancestor in path.ancestors().skip(2) {
            let m = fs::metadata(ancestor)?;
            let trusted_sticky = m.uid() == 0 && m.mode() & 0o1000 != 0;
            if (m.uid() != 0 && m.uid() != updater) || (m.mode() & 0o022 != 0 && !trusted_sticky) {
                return Err("Installation ancestors must belong to root or the updater and reject untrusted replacement".into());
            }
        }
    }
    Ok(())
}
fn transaction_paths(destination: &Path, release: &SignedRelease) -> Result<(PathBuf, PathBuf)> {
    let parent = destination.parent().ok_or("Missing installation parent")?;
    let identity = protocol::hash(&serde_json::to_vec(destination)?);
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    Ok((
        parent.join(format!(
            ".athernex-next-{identity}-{}{suffix}",
            release.release.sha256
        )),
        parent.join(format!(
            ".athernex-backup-{identity}-{}",
            release.release.sha256
        )),
    ))
}
fn validate_transaction(transaction: &Transaction) -> Result<()> {
    let (next, backup) = transaction_paths(&transaction.install_path, &transaction.release)?;
    if transaction.next_path != next
        || transaction.backup.path != backup
        || !protocol::hex_id(&transaction.backup.sha256)
    {
        return Err("Invalid update transaction file identities".into());
    }
    Ok(())
}
fn cleanup(
    state: &Path,
    component: Component,
    status: &mut UpdateStatus,
    config: &Config,
) -> Result<()> {
    if let Some(backup) = &status.cleanup {
        let release = status
            .installed
            .as_ref()
            .ok_or("Update cleanup requires a confirmed release")?;
        release.authenticate(&config.updates.public_key)?;
        let destination = config
            .updates
            .install_path
            .as_ref()
            .ok_or("Update cleanup requires its installation path")?;
        let (_, expected_backup) = transaction_paths(destination, release)?;
        if backup.path != expected_backup || !protocol::hex_id(&backup.sha256) {
            return Err("Invalid update cleanup file identity".into());
        }
        no_links(destination.parent().ok_or("Missing installation parent")?)?;
        if backup.path.exists() {
            if crate::file_hash(&backup.path)? != backup.sha256 {
                return Err("Update backup changed; retained for review".into());
            }
            fs::remove_file(&backup.path)?;
            sync_parent(&backup.path)?;
        }
        status.cleanup = None;
        save_component(state, component, status)?;
    }
    Ok(())
}
pub fn stage(state: &Path, manifest_path: &Path, binary: &Path) -> Result<UpdateStatus> {
    stage_component(state, Component::Agent, manifest_path, binary)
}
pub fn stage_component(
    state: &Path,
    component: Component,
    manifest_path: &Path,
    binary: &Path,
) -> Result<UpdateStatus> {
    let config = component.config(state)?;
    let _lock = lock(state)?;
    crate::engine_update::require_settled(state)?;
    prepare_component(state, component)?;
    if component == Component::Controller {
        crate::guardian::require_idle(state)?;
    }
    require_other_recovered(state, component)?;
    let mut status = status_component(state, component)?;
    if status.transaction.is_some() {
        return Err("Recover the interrupted update before staging another release".into());
    }
    cleanup(state, component, &mut status, &config)?;
    let manifest: SignedRelease =
        serde_json::from_slice(&read_bounded(manifest_path, wire::MAX_MANIFEST)?)?;
    let floor = if status.staged.as_ref() == Some(&manifest) {
        if manifest.release.sequence != status.highwater {
            return Err("Staged release sequence is inconsistent".into());
        }
        config.updates.minimum_sequence
    } else {
        status.highwater.max(config.updates.minimum_sequence)
    };
    manifest.admit(
        &config.updates.public_key,
        &wire::target(),
        &config.updates.channel,
        floor,
        now_ms(),
    )?;
    let bytes = read_bounded(binary, wire::MAX_BINARY)?;
    verify_binary(&manifest, &bytes)?;
    private_write(&component.directory(state).join("candidate.bin"), &bytes)?;
    status.highwater = manifest.release.sequence;
    status.staged = Some(manifest);
    status.last_result = "staged".into();
    status.last_error.clear();
    save_component(state, component, &mut status)?;
    Ok(status)
}
struct Quiescent {
    _store: Store,
    _protection: Option<StateLock>,
    #[cfg(windows)]
    _windows: crate::protection::windows::Quiescent,
    #[cfg(target_os = "macos")]
    _native: Option<athernex_endpoint_native::service::Quiescent>,
}
/// Installation retains all service and update leases across setup calls. Only
/// an installer that already owns the private installer lease may bypass its
/// pending journal gate; ordinary maintenance still requires a complete install.
#[cfg(windows)]
pub(crate) struct InstallerGuard<'a> {
    store: Store,
    _controller: Option<ControllerGuard>,
    _windows: crate::protection::windows::Quiescent,
    _update: StateLock,
    _lease: &'a crate::installer::Lease,
}
#[cfg(windows)]
impl<'a> InstallerGuard<'a> {
    pub(crate) fn acquire(lease: &'a crate::installer::Lease) -> Result<Self> {
        let state = lease.state();
        let controller = controller_quiescent(state, Component::Controller)?;
        let windows = crate::protection::windows::quiescent(state)?;
        let store = Store::open(state)?;
        let update =
            try_maintenance_lock_raw(state)?.ok_or("Another update transaction is running")?;
        require_component_transactions_settled(state)?;
        crate::engine_update::require_settled(state)?;
        crate::guardian::require_idle(state)?;
        Ok(Self {
            store,
            _controller: controller,
            _windows: windows,
            _update: update,
            _lease: lease,
        })
    }
    pub(crate) fn store(&self) -> &Store {
        &self.store
    }
}
pub(crate) struct OfflineMaintenance {
    _controller: Option<ControllerGuard>,
    quiet: Option<Quiescent>,
    _update: StateLock,
}
impl OfflineMaintenance {
    pub(crate) fn release_services(&mut self) {
        self.quiet.take();
    }
    pub(crate) fn reacquire(&mut self, state: &Path, config: &Config) -> Result<()> {
        if self.quiet.is_none() {
            self.quiet = Some(quiescent(state, config)?);
        }
        Ok(())
    }
}
pub(crate) fn offline_maintenance(state: &Path, config: &Config) -> Result<OfflineMaintenance> {
    let controller = controller_quiescent(state, Component::Controller)?;
    let quiet = quiescent(state, config)?;
    let update = lock(state)?;
    require_component_transactions_settled(state)?;
    Ok(OfflineMaintenance {
        _controller: controller,
        quiet: Some(quiet),
        _update: update,
    })
}
/// The live controller already owns its lock. Children must have stopped before
/// it acquires the same service/update exclusion used by offline maintenance.
pub(crate) fn controller_maintenance(
    state: &Path,
    config: &Config,
    token: &str,
) -> Result<OfflineMaintenance> {
    if !crate::supervisor::controller_owned(state, token) {
        return Err("Engine maintenance requires its owning live controller".into());
    }
    let quiet = quiescent(state, config)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let update = loop {
        if let Some(lock) = try_maintenance_lock(state)? {
            break lock;
        }
        if std::time::Instant::now() >= deadline {
            return Err("Another update still owns the engine maintenance window".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    require_component_transactions_settled(state)?;
    Ok(OfflineMaintenance {
        _controller: None,
        quiet: Some(quiet),
        _update: update,
    })
}
fn quiescent(state: &Path, config: &Config) -> Result<Quiescent> {
    #[cfg(windows)]
    crate::installer::require_complete(state)?;
    #[cfg(windows)]
    crate::windows_job::cleanup_ready()?;
    #[cfg(windows)]
    let windows = crate::protection::windows::quiescent(state)?;
    let store = Store::open(state)
        .map_err(|_| "Stop the endpoint service before applying or recovering an update")?;
    #[cfg(windows)]
    crate::installer::require_complete(state)?;
    let protected = config.protection.enabled;
    #[cfg(target_os = "macos")]
    let protected = protected || crate::protection::managed_native::has_plan(state)?;
    // Windows owns this lease in its native guard even when the public policy
    // is disabled; do not take the same lease twice.
    let protection = if protected && !cfg!(windows) {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("protection/supervisor.lock"))?;
        file.try_lock()
            .map_err(|_| "Stop native protection before replacing its executable")?;
        Some(StateLock(file))
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    let native = if protected {
        Some(crate::protection::managed_native::quiescent(
            &config.protection,
            state,
        )?)
    } else {
        None
    };
    Ok(Quiescent {
        _store: store,
        _protection: protection,
        #[cfg(windows)]
        _windows: windows,
        #[cfg(target_os = "macos")]
        _native: native,
    })
}
pub fn installer_native_hash(manifest: &Path) -> Result<Option<String>> {
    let artifact: athernex_endpoint_protocol::installer::Artifact =
        serde_json::from_slice(&read_bounded(manifest, 16384)?)?;
    if artifact.target != wire::target() {
        return Err("Installer build does not match this platform".into());
    }
    if let Some(component) = artifact.native()? {
        if crate::file_hash(&std::env::current_exe()?)? != artifact.sha256 {
            return Err("Installer management binary checksum mismatch".into());
        }
        return Ok(Some(component.sha256.clone()));
    }
    Ok(None)
}

pub fn installer_check(state: &Path, binary: &Path, stopped: bool) -> Result<()> {
    crate::macos_network_bundle::installer_components(binary)?;
    crate::engine_update::require_settled(state)?;
    #[cfg(target_os = "linux")]
    athernex_endpoint_native::child::check_lifetime_support()?;
    #[cfg(windows)]
    crate::windows_job::check_lifetime_support()?;
    #[cfg(windows)]
    if crate::installer::preflight(state, binary)? {
        return Ok(());
    }
    if !state.join("config.json").try_exists()? {
        if state.try_exists()? && fs::read_dir(state)?.next().transpose()?.is_some() {
            return Err("Existing endpoint state has no configuration; recover it or choose a new state directory".into());
        }
        return Ok(());
    }
    let configuration: Config =
        serde_json::from_slice(&read_bounded(&state.join("config.json"), 65536)?)?;
    configuration.validate()?;
    let controller = status_component(state, Component::Controller)?;
    if controller.transaction.is_some() {
        return Err("Recover the interrupted controller update before reinstalling".into());
    }
    if controller.installed.is_some() || controller.staged.is_some() {
        let destination = configuration
            .updates
            .controller_path
            .as_ref()
            .ok_or("Restore the controller update policy before reinstalling")?;
        let actual = crate::file_hash(destination)?;
        if crate::file_hash(binary)? != actual
            || controller
                .installed
                .as_ref()
                .is_some_and(|r| r.release.sha256 != actual)
        {
            return Err("Install the signed controller release before reinstalling; its ledger cannot be bypassed".into());
        }
    }
    let status = status(state)?;
    if status.transaction.is_some() {
        return Err(
            "Recover the interrupted update with the installed controller before reinstalling"
                .into(),
        );
    }
    if configuration.updates.enabled() || status.installed.is_some() || status.staged.is_some() {
        let installed = configuration
            .updates
            .install_path
            .as_ref()
            .ok_or("Restore the local update policy before reinstalling")?;
        let actual = crate::file_hash(installed)?;
        if crate::file_hash(binary)? != actual
            || status
                .installed
                .as_ref()
                .is_some_and(|r| r.release.sha256 != actual)
        {
            return Err("Install the signed agent release through the update workflow first; the installer cannot overwrite the update ledger".into());
        }
    }
    if stopped {
        let _controller = controller_quiescent(state, Component::Controller)?;
        let _quiet = quiescent(state, &configuration)?;
    }
    Ok(())
}
pub(crate) fn native_signature(path: &Path, policy: &UpdatePolicy) -> Result<()> {
    if policy.allow_unsigned_native {
        return Ok(());
    }
    #[cfg(windows)]
    {
        let (code, _) = run_bounded(Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            .env("ATHERNEX_RELEASE_BINARY", path).args(["-NoProfile", "-NonInteractive", "-Command", "if ((Get-AuthenticodeSignature -LiteralPath $env:ATHERNEX_RELEASE_BINARY).Status -ne 'Valid') { exit 1 }"]), 15)?;
        if code != 0 {
            return Err("Release Authenticode signature rejected".into());
        }
    }
    #[cfg(target_os = "macos")]
    {
        for (program, args) in [
            ("/usr/bin/codesign", vec!["--verify", "--strict"]),
            ("/usr/sbin/spctl", vec!["--assess", "--type", "execute"]),
        ] {
            if run_bounded(Command::new(program).args(args).arg(path), 15)?.0 != 0 {
                return Err("Release macOS signature/Gatekeeper check failed".into());
            }
        }
    }
    let _ = path;
    Ok(())
}
fn probe(path: &Path, release: &SignedRelease, component: Component) -> Result<()> {
    let challenge = crate::secret()?;
    let (code, output) = run_bounded(Command::new(path).arg("release-check").arg(&challenge), 10)?;
    let value: serde_json::Value = serde_json::from_str(&output)
        .map_err(|_| "Replacement did not return a valid readiness response")?;
    if code != 0
        || value["challenge"] != challenge
        || value["protocol"] != protocol::PROTOCOL
        || value["target"] != release.release.target
        || value["version"] != release.release.version
        || (component == Component::Controller && value["controller_protocol"] != 1)
    {
        return Err("Replacement executable failed its readiness contract".into());
    }
    Ok(())
}
fn rollback(
    state: &Path,
    component: Component,
    status: &mut UpdateStatus,
    error: &str,
) -> Result<()> {
    let transaction = status.transaction.as_ref().ok_or("No interrupted update")?;
    validate_transaction(transaction)?;
    no_links(
        transaction
            .install_path
            .parent()
            .ok_or("Missing installation parent")?,
    )?;
    let current_hash = match fs::symlink_metadata(&transaction.install_path) {
        Ok(_) => {
            check_destination(&transaction.install_path)?;
            Some(crate::file_hash(&transaction.install_path)?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    if transaction.backup.path.exists() {
        if crate::file_hash(&transaction.backup.path)? != transaction.backup.sha256 {
            return Err("Cannot recover: update backup integrity check failed".into());
        }
        if current_hash.as_deref() == Some(&transaction.backup.sha256) {
            fs::remove_file(&transaction.backup.path)?;
        } else {
            fs::rename(&transaction.backup.path, &transaction.install_path)?;
        }
        sync_parent(&transaction.install_path)?;
    } else if current_hash.as_deref() != Some(&transaction.backup.sha256) {
        return Err(
            "Cannot recover: backup is missing and the installed file was not restored".into(),
        );
    }
    match fs::symlink_metadata(&transaction.next_path) {
        Ok(m) if m.is_file() && m.len() <= wire::MAX_BINARY => {
            fs::remove_file(&transaction.next_path)?;
            sync_parent(&transaction.next_path)?;
        }
        Ok(_) => return Err("Unexpected file at interrupted update candidate path".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    status.transaction = None;
    status.staged = None;
    status.last_result = "rolled_back".into();
    status.last_error = error.chars().take(512).collect();
    save_component(state, component, status)
}
pub fn recover(state: &Path) -> Result<UpdateStatus> {
    recover_component(state, Component::Agent)
}
pub fn recover_component(state: &Path, component: Component) -> Result<UpdateStatus> {
    let config = component.config(state)?;
    if component == Component::Controller {
        let destination = config.updates.install_path.as_ref().unwrap();
        if destination.try_exists()?
            && std::env::current_exe()?.canonicalize()? == destination.canonicalize()?
        {
            return Err("Recover the controller from a separate trusted executable copy".into());
        }
    }
    let _controller = controller_quiescent(state, component)?;
    let _quiet = quiescent(state, &config)?;
    let _lock = lock(state)?;
    crate::engine_update::require_settled(state)?;
    prepare_component(state, component)?;
    require_other_recovered(state, component)?;
    let mut status = status_component(state, component)?;
    if let Some(transaction) = &status.transaction {
        if Some(&transaction.install_path) != config.updates.install_path.as_ref() {
            return Err("Local installation path changed during the update".into());
        }
        transaction
            .release
            .authenticate(&config.updates.public_key)?;
        rollback(
            state,
            component,
            &mut status,
            "Interrupted replacement recovered; failed release sequence remains reserved",
        )?;
    }
    cleanup(state, component, &mut status, &config)?;
    Ok(status)
}
pub fn apply(state: &Path) -> Result<UpdateStatus> {
    apply_component(state, Component::Agent)
}
pub fn apply_component(state: &Path, component: Component) -> Result<UpdateStatus> {
    if component == Component::Controller {
        crate::guardian::require_idle(state)?;
    }
    apply_inner(state, component, None)
}
pub(crate) fn begin_controller_trial(state: &Path, nonce: &str) -> Result<UpdateStatus> {
    if !crate::guardian::owned(state, nonce) {
        return Err("A live owning launcher is required for a controller trial".into());
    }
    apply_inner(
        state,
        Component::Controller,
        Some(Trial {
            nonce: nonce.into(),
            expires_ms: now_ms() + 360_000,
        }),
    )
}
pub(crate) fn begin_trial(state: &Path, nonce: &str) -> Result<UpdateStatus> {
    if !protocol::hex_id(nonce) || !crate::supervisor::controller_active(state, nonce) {
        return Err("A live controller is required for an installation trial".into());
    }
    apply_inner(
        state,
        Component::Agent,
        Some(Trial {
            nonce: nonce.into(),
            expires_ms: now_ms() + 360_000,
        }),
    )
}
fn apply_inner(state: &Path, component: Component, trial: Option<Trial>) -> Result<UpdateStatus> {
    let config = component.config(state)?;
    let _controller = controller_quiescent(state, component)?;
    let _quiet = quiescent(state, &config)?;
    let _lock = lock(state)?;
    crate::engine_update::require_settled(state)?;
    prepare_component(state, component)?;
    require_other_recovered(state, component)?;
    let mut status = status_component(state, component)?;
    if status.transaction.is_some() {
        return Err("Recover the interrupted update before applying a release".into());
    }
    cleanup(state, component, &mut status, &config)?;
    let release = status.staged.clone().ok_or("No staged release")?;
    release.admit(
        &config.updates.public_key,
        &wire::target(),
        &config.updates.channel,
        status
            .installed
            .as_ref()
            .map_or(config.updates.minimum_sequence, |r| {
                r.release.sequence.max(config.updates.minimum_sequence)
            }),
        now_ms(),
    )?;
    if release.release.sequence != status.highwater {
        return Err("Staged release does not match the reserved sequence".into());
    }
    let bytes = read_bounded(
        &component.directory(state).join("candidate.bin"),
        wire::MAX_BINARY,
    )?;
    verify_binary(&release, &bytes)?;
    let destination = config.updates.install_path.as_ref().unwrap();
    check_destination(destination)?;
    if std::env::current_exe()?.canonicalize()? == destination.canonicalize()? {
        return Err("Run the updater from a separate trusted executable copy".into());
    }
    let prior_hash = crate::file_hash(destination)?;
    if status
        .installed
        .as_ref()
        .is_some_and(|r| r.release.sha256 != prior_hash)
    {
        return Err("Installed executable changed outside the update ledger".into());
    }
    let (next_path, backup_path) = transaction_paths(destination, &release)?;
    let backup = Backup {
        path: backup_path,
        sha256: prior_hash,
    };
    if fs::symlink_metadata(&backup.path).is_ok() || fs::symlink_metadata(&next_path).is_ok() {
        return Err("Unexpected file at update candidate/backup path; retained for review".into());
    }
    status.transaction = Some(Transaction {
        trial: None,
        release: release.clone(),
        install_path: destination.clone(),
        backup: backup.clone(),
        next_path: next_path.clone(),
    });
    // Record ownership before creating a candidate: a crash during copying or
    // preflight must not strand an untracked executable on the installation disk.
    save_component(state, component, &mut status)?;
    let result = (|| -> Result<()> {
        let mut next = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&next_path)?;
        next.set_permissions(fs::metadata(destination)?.permissions())?;
        next.write_all(&bytes)?;
        next.sync_all()?;
        drop(next);
        sync_parent(&next_path)?;
        native_signature(&next_path, &config.updates)?;
        probe(&next_path, &release, component)?;
        fs::hard_link(destination, &backup.path)?;
        let mut backup_options = OpenOptions::new();
        backup_options.read(true);
        // Windows FlushFileBuffers requires GENERIC_WRITE even when this
        // handle only flushes existing bytes. Never truncate the backup.
        #[cfg(windows)]
        backup_options.write(true);
        backup_options.open(&backup.path)?.sync_all()?;
        sync_parent(&backup.path)?;
        fs::rename(&next_path, destination)?;
        sync_parent(destination)?;
        probe(destination, &release, component)?;
        Ok(())
    })();
    if let Err(error) = result {
        rollback(state, component, &mut status, &error.to_string())?;
        return Err(format!("Endpoint update failed and was rolled back: {error}").into());
    }
    if let Some(trial) = trial {
        status.transaction.as_mut().unwrap().trial = Some(trial);
        status.last_result = "verifying".into();
        save_component(state, component, &mut status)?;
        return Ok(status);
    }
    status.installed = Some(release);
    status.staged = None;
    status.transaction = None;
    status.cleanup = Some(backup);
    status.last_result = "installed".into();
    status.last_error.clear();
    save_component(state, component, &mut status)?;
    cleanup(state, component, &mut status, &config)?;
    Ok(status)
}
pub(crate) fn confirm_trial(state: &Path, nonce: &str) -> Result<()> {
    let component = Component::Agent;
    let config = config(state)?;
    let _lock = lock(state)?;
    prepare_component(state, component)?;
    require_other_recovered(state, component)?;
    let mut status = status_component(state, component)?;
    let transaction = status.transaction.clone().ok_or("No installation trial")?;
    validate_transaction(&transaction)?;
    let trial = transaction
        .trial
        .as_ref()
        .ok_or("Replacement has not reached runtime verification")?;
    if trial.nonce != nonce
        || now_ms() >= trial.expires_ms
        || !crate::supervisor::controller_active(state, nonce)
        || !crate::supervisor::runtime_ready(state, nonce, &transaction.release)?
        || config.updates.install_path.as_ref() != Some(&transaction.install_path)
        || crate::file_hash(&transaction.install_path)? != transaction.release.release.sha256
    {
        return Err("Installation trial did not satisfy its runtime health contract".into());
    }
    transaction
        .release
        .authenticate(&config.updates.public_key)?;
    status.installed = Some(transaction.release);
    status.staged = None;
    status.transaction = None;
    status.cleanup = Some(transaction.backup);
    status.last_result = "installed".into();
    status.last_error.clear();
    save_component(state, component, &mut status)?;
    cleanup(state, component, &mut status, &config)
}
pub(crate) fn confirm_controller_trial(state: &Path, nonce: &str) -> Result<()> {
    let component = Component::Controller;
    let config = component.config(state)?;
    let _lock = lock(state)?;
    let mut status = status_component(state, component)?;
    let transaction = status.transaction.clone().ok_or("No controller trial")?;
    validate_transaction(&transaction)?;
    let trial = transaction
        .trial
        .as_ref()
        .ok_or("Controller has not entered runtime verification")?;
    if trial.nonce != nonce
        || now_ms() >= trial.expires_ms
        || !crate::guardian::owned(state, nonce)
        || !crate::guardian::runtime_ready(state, &transaction)?
        || config.updates.install_path.as_ref() != Some(&transaction.install_path)
        || crate::file_hash(&transaction.install_path)? != transaction.release.release.sha256
    {
        return Err("Controller trial did not satisfy its runtime health contract".into());
    }
    transaction
        .release
        .authenticate(&config.updates.public_key)?;
    status.installed = Some(transaction.release);
    status.staged = None;
    status.transaction = None;
    status.cleanup = Some(transaction.backup);
    status.last_result = "installed".into();
    status.last_error.clear();
    save_component(state, component, &mut status)?;
    cleanup(state, component, &mut status, &config)
}
pub fn keygen(directory: &Path) -> Result<String> {
    #[cfg(not(windows))]
    {
        #[cfg(unix)]
        let mut builder = fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(directory)?;
    }
    #[cfg(windows)]
    let private_directory = {
        let absolute = std::path::absolute(directory)?;
        // Create the private ACL with the directory itself and retain its
        // pinned ancestry while writing keys. No shell or inherited module
        // search path participates in the signing-key boundary.
        athernex_endpoint_native::windows_state::Directory::create_under(
            absolute.parent().ok_or("Missing release key parent")?,
            absolute
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("Invalid release key directory name")?,
        )?
    };
    let (private, public) = wire::generate_key()?;
    #[cfg(windows)]
    {
        for (name, bytes) in [
            ("release.pk8", private.as_slice()),
            ("public-key.txt", public.as_bytes()),
        ] {
            let mut file = private_directory.create(name)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        private_directory.sync()?;
    }
    #[cfg(not(windows))]
    {
        private_write(&directory.join("release.pk8"), &private)?;
        private_write(&directory.join("public-key.txt"), public.as_bytes())?;
    }
    Ok(public)
}
pub fn sign(
    key: &Path,
    binary: &Path,
    version: &str,
    channel: &str,
    sequence: u64,
    expires: u64,
    output: &Path,
) -> Result<()> {
    let bytes = read_bounded(binary, wire::MAX_BINARY)?;
    let release = wire::Release {
        schema: 1,
        target: binary_target(&bytes)?.into(),
        version: version.into(),
        channel: channel.into(),
        sequence,
        issued_ms: now_ms(),
        expires_ms: expires,
        protocol: protocol::PROTOCOL,
        sha256: protocol::hash(&bytes),
        bytes: bytes.len() as u64,
    };
    if expires <= now_ms() {
        return Err("Release expiration must be in the future".into());
    }
    let signed = SignedRelease::sign(release, &read_bounded(key, 4096)?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&signed)?)?;
    file.sync_all()?;
    sync_parent(output)
}

/// Provision a local release catalog without placing the signing key online.
pub fn publish(manifest: &Path, binary: &Path, public_key: &str, root: &Path) -> Result<String> {
    let release: SignedRelease =
        serde_json::from_slice(&read_bounded(manifest, wire::MAX_MANIFEST)?)?;
    release.admit(
        public_key,
        &release.release.target,
        &release.release.channel,
        0,
        now_ms(),
    )?;
    let bytes = read_bounded(binary, wire::MAX_BINARY)?;
    verify_binary(&release, &bytes)?;
    fs::create_dir_all(root)?;
    let publisher = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(".publish.lock"))?;
    publisher
        .try_lock()
        .map_err(|_| "Another release publication is running")?;
    let _publisher = StateLock(publisher);
    let key_path = root.join("public-key.txt");
    if key_path.exists() {
        if read_bounded(&key_path, 128)? != public_key.as_bytes() {
            return Err(
                "Catalog release key differs; explicit trust-key migration is required".into(),
            );
        }
    } else {
        private_write(&key_path, public_key.as_bytes())?;
    }
    let id = release.id()?;
    let manifest_path = root.join(format!("{id}.json"));
    if !manifest_path.exists()
        && fs::read_dir(root)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
            .count()
            >= 32
    {
        return Err("Release catalog capacity reached; archive old releases explicitly".into());
    }
    private_write(
        &root.join(format!("{}.bin", release.release.sha256)),
        &bytes,
    )?;
    private_write(&manifest_path, &serde_json::to_vec_pretty(&release)?)?;
    Ok(id)
}
#[cfg(test)]
mod tests;
