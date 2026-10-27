use super::{Phase, Record, LOCK, RECORD};
use crate::{protection::windows_evidence as evidence, setup, update, Config, Process, Result};
use athernex_endpoint_native::windows_state::{self, Directory, PinnedDirectory};
use athernex_endpoint_protocol::{self as protocol, installer::Artifact};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};

const SOURCE: &str = "athernex-endpoint.exe";
const CONTROLLER: &str = "athernex-controller.exe";
const LAUNCHER: &str = "athernex-launcher.exe";
const MAX_BINARY: u64 = 128 * 1024 * 1024;
const REGISTER: &str = include_str!("register.ps1");
#[cfg(test)]
mod tests;

/// Its private constructor is the proof used to acquire maintenance while an
/// installation journal is pending. Keep the state ancestry pinned throughout.
pub(crate) struct Lease {
    _file: File,
    _service_host: crate::windows_service::ServiceLease,
    directory: Directory,
    _exclusive: Option<crate::windows_driver::Exclusive>,
    _admission: Option<crate::windows_driver::Admission>,
}
impl Lease {
    pub(crate) fn acquire(directory: Directory) -> Result<Self> {
        let admission = crate::windows_driver::Admission::acquire(directory.path())?;
        Self::acquire_inner(directory, Some(admission), None)
    }
    pub(crate) fn acquire_owned(
        directory: Directory,
        exclusive: crate::windows_driver::Exclusive,
    ) -> Result<Self> {
        exclusive.check(&directory)?;
        Self::acquire_inner(directory, None, Some(exclusive))
    }
    fn acquire_inner(
        directory: Directory,
        admission: Option<crate::windows_driver::Admission>,
        exclusive: Option<crate::windows_driver::Exclusive>,
    ) -> Result<Self> {
        let file = directory.maintenance_lock(LOCK)?;
        let service_host = crate::windows_service::lease(&directory)?;
        Ok(Self {
            _admission: admission,
            _exclusive: exclusive,
            _file: file,
            _service_host: service_host,
            directory,
        })
    }
    pub(crate) fn state(&self) -> &Path {
        self.directory.path()
    }
}
fn missing(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
fn optional(state: &Path) -> Result<Option<Directory>> {
    match Directory::open(&std::path::absolute(state)?) {
        Ok(directory) => Ok(Some(directory)),
        Err(e) if missing(e.as_ref()) => Ok(None),
        Err(e) => Err(e),
    }
}
fn record(directory: &Directory) -> Result<Option<Record>> {
    let record: Record = match directory.read_json(RECORD) {
        Ok(record) => record,
        Err(e) if missing(e.as_ref()) => return Ok(None),
        Err(e) => return Err(e),
    };
    record.validate()?;
    let identity = directory.identity()?;
    if record.state_volume != identity.volume || record.state_file_id != identity.file_id {
        return Err("Installation journal belongs to a different state directory".into());
    }
    Ok(Some(record))
}
/// Validate exact interrupted inputs while the coordinator retains global
/// exclusion, before it publishes a new transaction or creates an epoch.
pub(crate) fn deployment_preflight(
    global: &Path,
    bundle: &Path,
    state: &Path,
    agent: &Path,
    artifact: &Artifact,
    bootstrap: &protocol::Bootstrap,
) -> Result<()> {
    disjoint(&[global, bundle, agent, state])?;
    let Some(directory) = optional(state)? else {
        return Ok(());
    };
    let configuration = setup::configuration(bootstrap, state)?;
    destinations(&configuration, agent)?;
    if let Some(saved) = record(&directory)? {
        saved.require_resume(
            &artifact.sha256,
            protocol::server_url(&bootstrap.server)?.as_str(),
            local(agent)?,
            artifact.filter()?.map(|d| d.sha256.as_str()),
            artifact.filter()?.and_then(|d| d.deployment),
        )?;
    }
    Ok(())
}
pub(crate) fn require_completed_driver(lease: &Lease, source: &str, package: &str) -> Result<()> {
    let saved = record(&lease.directory)?.ok_or("Completed installer record missing")?;
    if saved.phase != Phase::Complete
        || saved.source_sha256 != source
        || saved.windows_filter_sha256.as_deref() != Some(package)
        || saved.windows_filter_deployment
            != Some(protocol::windows_filter_package::Deployment::InstallAndObserveDisarmedV1)
    {
        return Err("Fresh load requires the existing completed endpoint selection".into());
    }
    Ok(())
}
pub fn require_complete(state: &Path) -> Result<()> {
    crate::windows_driver::require_settled(state)?;
    if let Some(directory) = optional(state)? {
        let saved = record(&directory)?;
        if saved.as_ref().is_some_and(|r| r.phase != Phase::Complete) {
            return Err("Windows installation is incomplete; rerun its original installer bundle before starting services or maintenance".into());
        }
        if saved
            .as_ref()
            .is_some_and(|r| r.windows_filter_deployment.is_some())
        {
            crate::windows_driver::require_owned(state)?;
        }
        if let Some(hash) = saved
            .as_ref()
            .and_then(|r| r.windows_filter_sha256.as_deref())
        {
            crate::windows_filter_package::require_prepared(state, hash)?;
        }
    }
    Ok(())
}
/// A true result is only the fresh/preparing path with no configuration. Every
/// configured endpoint must still pass installer_check's signed release ledgers.
pub fn preflight(state: &Path, binary: &Path) -> Result<bool> {
    let Some(directory) = optional(state)? else {
        return Ok(true);
    };
    let saved = record(&directory)?;
    if let Some(saved) = &saved {
        let release = binary
            .parent()
            .ok_or("Missing installer directory")?
            .join("release.json");
        if release.try_exists()? {
            let artifact: Artifact =
                serde_json::from_slice(&update::read_bounded(&release, 16384)?)?;
            saved.require_filter_selection(artifact.filter()?.map(|d| d.sha256.as_str()))?;
            saved.require_deployment_selection(artifact.filter()?.and_then(|d| d.deployment))?;
        }
        if saved.phase != Phase::Complete && crate::file_hash(binary)? != saved.source_sha256 {
            return Err("Resume interrupted installation with its original executable".into());
        }
    }
    if directory.path().join("config.json").try_exists()? {
        return Ok(false);
    }
    if let Some(saved) = saved {
        if saved.phase == Phase::Preparing {
            return Ok(true);
        }
        return Err(
            "Installed endpoint configuration is missing; restore it before reinstalling".into(),
        );
    }
    for entry in fs::read_dir(directory.path())? {
        let name = entry?.file_name();
        if ![
            std::ffi::OsStr::new(LOCK),
            std::ffi::OsStr::new(crate::windows_service::LOCK),
        ]
        .contains(&name.as_os_str())
            || directory
                .read(name.to_str().ok_or("Invalid installation lock name")?)?
                .metadata()?
                .len()
                != 0
        {
            return Err("Existing endpoint state has no configuration or installation journal; recover it or choose a new state directory".into());
        }
    }
    Ok(true)
}
fn local(path: &Path) -> Result<&str> {
    let name = path
        .to_str()
        .ok_or("Windows installation paths must be Unicode")?;
    if !evidence::drive_path(name) {
        return Err(
            "Windows installation needs absolute local drive paths without traversal".into(),
        );
    }
    Ok(name)
}
fn disjoint(paths: &[&Path]) -> Result<()> {
    for (index, path) in paths.iter().enumerate() {
        let a = local(path)?;
        for other in &paths[index + 1..] {
            let b = local(other)?;
            if evidence::suffix(a, b).is_some() || evidence::suffix(b, a).is_some() {
                return Err(
                    "Installer bundle, executable directory and state directory must be separate"
                        .into(),
                );
            }
        }
    }
    Ok(())
}
fn pinned_disjoint(bundle: &PinnedDirectory, agent: &Directory, state: &Directory) -> Result<()> {
    let names = [bundle.nt()?, agent.nt()?, state.nt()?];
    for (index, a) in names.iter().enumerate() {
        for b in &names[index + 1..] {
            if evidence::suffix(a, b).is_some() || evidence::suffix(b, a).is_some() {
                return Err(
                    "Installer directories resolve to overlapping filesystem locations".into(),
                );
            }
        }
    }
    Ok(())
}
fn private_directory(path: &Path) -> Result<Directory> {
    local(path)?;
    let directory = Directory::maintenance_under(
        path.parent().ok_or("Missing installation parent")?,
        path.file_name()
            .and_then(|v| v.to_str())
            .ok_or("Invalid installation directory")?,
    )?;
    directory.require_service_access()?;
    Ok(directory)
}
fn source(path: &Path) -> Result<(File, Vec<u8>)> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > MAX_BINARY
    {
        return Err("Installer source must be a bounded regular executable".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_BINARY + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BINARY {
        return Err("Installer executable exceeds its byte budget".into());
    }
    Ok((file, bytes))
}
fn destinations(config: &Config, agent: &Path) -> Result<()> {
    for (configured, leaf) in [
        (&config.updates.install_path, SOURCE),
        (&config.updates.controller_path, CONTROLLER),
        (&config.updates.launcher_path, LAUNCHER),
    ] {
        if let Some(configured) = configured {
            if !evidence::prefix_equal(local(configured)?, local(&agent.join(leaf))?) {
                return Err("Installer destination differs from the local update policy".into());
            }
        }
    }
    Ok(())
}
fn register(state: &Directory, agent: &Directory) -> Result<()> {
    let root = crate::protection::windows::system_root()?;
    let shell_directory = Path::new(&root).join(r"System32\WindowsPowerShell\v1.0");
    let _shell = PinnedDirectory::open(&shell_directory)?;
    let temporary = state.maintenance_directory("installer-temp")?;
    let mut command = Process::new(shell_directory.join("powershell.exe"));
    command
        .env_clear()
        .env("SystemRoot", &root)
        .env("PATH", Path::new(&root).join("System32"))
        .env("PSModulePath", shell_directory.join("Modules"))
        .env("TEMP", temporary.path())
        .env("TMP", temporary.path())
        .env("ATHERNEX_INSTALL_STATE", state.path())
        .env("ATHERNEX_INSTALL_AGENT", agent.path().join(SOURCE))
        .env("ATHERNEX_INSTALL_CONTROLLER", agent.path().join(CONTROLLER))
        .env("ATHERNEX_INSTALL_LAUNCHER", agent.path().join(LAUNCHER))
        .current_dir(state.path())
        .args(["-NoProfile", "-NonInteractive", "-Command", REGISTER]);
    let (code, _) = crate::windows_job::run(&command, Duration::from_secs(60), 8192)?;
    if code != 0 {
        return Err(
            "Windows service registration failed; rerun the retained installer bundle".into(),
        );
    }
    Ok(())
}

pub fn install(bundle: &Path, agent: &Path, state: &Path) -> Result<()> {
    let artifact: Artifact =
        serde_json::from_slice(&update::read_bounded(&bundle.join("release.json"), 16384)?)?;
    if artifact.filter()?.is_some_and(|d| d.deployment.is_some()) {
        return crate::windows_driver::install(bundle, agent, state);
    }
    let _admission = crate::windows_driver::Admission::acquire(state)?;
    install_inner(bundle, agent, state, None)
}
pub(crate) fn install_owned(
    bundle: &Path,
    agent: &Path,
    state: &Path,
    capability: &mut crate::windows_driver::Capability,
) -> Result<()> {
    install_inner(bundle, agent, state, Some(capability))
}
fn install_check(
    state: &Path,
    binary: &Path,
    capability: Option<&crate::windows_driver::Capability>,
) -> Result<()> {
    match capability {
        Some(capability) => update::installer_check_owned(state, binary, capability),
        None => update::installer_check(state, binary, false),
    }
}
fn install_inner(
    bundle: &Path,
    agent: &Path,
    state: &Path,
    mut capability: Option<&mut crate::windows_driver::Capability>,
) -> Result<()> {
    windows_state::require_administrator()?;
    disjoint(&[bundle, agent, state])?;
    let bundle_pin = PinnedDirectory::open(bundle)?;
    let binary = bundle.join(SOURCE);
    let (_source, bytes) = source(&binary)?;
    let digest = protocol::hash(&bytes);
    let artifact: Artifact =
        serde_json::from_slice(&update::read_bounded(&bundle.join("release.json"), 16384)?)?;
    if artifact.target != protocol::update::target()
        || update::binary_target(&bytes)? != artifact.target
        || artifact.version != env!("CARGO_PKG_VERSION")
        || artifact.sha256 != digest
        || !["development-unsigned", "native-signature-verified"]
            .contains(&artifact.signing.as_str())
        || artifact.native()?.is_some()
        || crate::file_hash(&std::env::current_exe()?)? != digest
    {
        return Err(
            "Installer source does not match this executable and its release metadata".into(),
        );
    }
    crate::windows_filter_package::components(bundle, &artifact)?;
    artifact.network()?;
    let filter_hash = artifact.filter()?.map(|d| d.sha256.clone());
    let deployment = artifact.filter()?.and_then(|d| d.deployment);
    if artifact.filter()?.is_some_and(|d| {
        (bytes.len() as u64)
            .checked_add(d.bytes)
            .is_none_or(|n| n > 64 * 1024 * 1024)
    }) {
        return Err("Combined installer and driver package exceed budget".into());
    }
    if artifact.signing == "native-signature-verified" {
        update::native_signature(&binary, &update::UpdatePolicy::default())?;
    }
    let bootstrap = setup::read_bootstrap(&bundle.join("bootstrap.json"))?;
    let server = protocol::server_url(&bootstrap.server)?.to_string();
    install_check(state, &binary, capability.as_deref())?;
    let lease = if let Some(capability) = capability.as_deref() {
        Lease::acquire_owned(private_directory(state)?, capability.exclusive()?)?
    } else {
        Lease::acquire(private_directory(state)?)?
    };
    install_check(state, &binary, capability.as_deref())?;
    let previous = record(&lease.directory)?;
    if let Some(saved) = &previous {
        saved.require_filter_selection(filter_hash.as_deref())?;
        saved.require_deployment_selection(deployment)?;
    }
    let mut journal = if let Some(saved) = previous.filter(|r| r.phase != Phase::Complete) {
        saved.require_resume(
            &digest,
            &server,
            local(agent)?,
            filter_hash.as_deref(),
            deployment,
        )?;
        saved
    } else {
        let identity = lease.directory.identity()?;
        Record {
            schema: 1,
            id: crate::secret()?,
            source_sha256: digest,
            server,
            agent_directory: local(agent)?.into(),
            state_volume: identity.volume,
            state_file_id: identity.file_id,
            phase: Phase::Preparing,
            windows_filter_sha256: filter_hash.clone(),
            windows_filter_deployment: deployment,
        }
    };
    let configuration = setup::configuration(&bootstrap, state)?;
    destinations(&configuration, agent)?;
    // Prepare fresh state before locks/SQLite create any children. Configured
    // installs wait until service exclusion succeeds before becoming pending.
    if !state.join("config.json").try_exists()? {
        lease.directory.write_maintenance_json(RECORD, &journal)?;
    }
    let guard = update::InstallerGuard::acquire(&lease)?;
    // Recheck ledgers after acquiring their leases; preflight was only a snapshot.
    install_check(state, &binary, capability.as_deref())?;
    let configuration = setup::configuration(&bootstrap, state)?;
    destinations(&configuration, agent)?;
    let agent = private_directory(agent)?;
    pinned_disjoint(&bundle_pin, &agent, &lease.directory)?;
    // Preparing permits creation of a not-yet-enrolled identity. An existing
    // identity must never enter that state: loss of its config requires restore.
    if state.join("config.json").try_exists()? {
        journal.phase = Phase::Installing;
    }
    lease.directory.write_maintenance_json(RECORD, &journal)?;
    if let Some(component) = artifact.filter()? {
        crate::windows_filter_package::prepare(
            &lease.directory,
            bundle,
            &journal.source_sha256,
            component,
        )?;
    }
    setup::save(state, &configuration)?;
    journal.phase = Phase::Installing;
    lease.directory.write_maintenance_json(RECORD, &journal)?;
    for leaf in [SOURCE, CONTROLLER, LAUNCHER] {
        agent.write_maintenance(leaf, &bytes)?;
    }
    setup::enroll(&bootstrap, guard.store())?;
    setup::provision(&bootstrap, state)?;
    crate::windows_job::cleanup_ready()?;
    register(&lease.directory, &agent)?;
    crate::windows_job::cleanup_ready()?;
    if let Some(hash) = &journal.windows_filter_sha256 {
        crate::windows_filter_package::require_prepared(state, hash)?;
    }
    if let Some(capability) = capability.as_deref_mut() {
        capability.before_complete(&lease.directory)?;
    } else {
        crate::windows_driver::require_settled(state)?;
    }
    journal.phase = Phase::Complete;
    lease.directory.write_maintenance_json(RECORD, &journal)?;
    if let Some(capability) = capability {
        capability.completed()?;
    }
    Ok(())
}

/// Explicit owned driver retirement changes only the deployment requirement.
/// It neither completes an interrupted endpoint installation nor removes the
/// immutable prepared package or any endpoint configuration/history.
pub(crate) fn mark_driver_retired(lease: &Lease, source: &str, package: &str) -> Result<()> {
    let mut saved =
        record(&lease.directory)?.ok_or("Installation receipt missing during driver retirement")?;
    saved.driver_retired(source, package)?;
    lease.directory.write_maintenance_json(RECORD, &saved)
}
