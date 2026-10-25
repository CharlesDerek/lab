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
}
impl Lease {
    fn acquire(directory: Directory) -> Result<Self> {
        let file = directory.maintenance_lock(LOCK)?;
        let service_host = crate::windows_service::lease(&directory)?;
        Ok(Self {
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
pub fn require_complete(state: &Path) -> Result<()> {
    if let Some(directory) = optional(state)? {
        if record(&directory)?.is_some_and(|r| r.phase != Phase::Complete) {
            return Err("Windows installation is incomplete; rerun its original installer bundle before starting services or maintenance".into());
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
    if artifact.signing == "native-signature-verified" {
        update::native_signature(&binary, &update::UpdatePolicy::default())?;
    }
    let bootstrap = setup::read_bootstrap(&bundle.join("bootstrap.json"))?;
    let server = protocol::server_url(&bootstrap.server)?.to_string();
    update::installer_check(state, &binary, false)?;
    let lease = Lease::acquire(private_directory(state)?)?;
    update::installer_check(state, &binary, false)?;
    let previous = record(&lease.directory)?;
    let mut journal = if let Some(saved) = previous.filter(|r| r.phase != Phase::Complete) {
        if saved.source_sha256 != digest
            || saved.server != server
            || !evidence::prefix_equal(&saved.agent_directory, local(agent)?)
        {
            return Err(
                "Interrupted installation must resume with the same source, server and destination"
                    .into(),
            );
        }
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
    update::installer_check(state, &binary, false)?;
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
    journal.phase = Phase::Complete;
    lease.directory.write_maintenance_json(RECORD, &journal)?;
    Ok(())
}
