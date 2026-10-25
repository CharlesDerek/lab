//! Engine releases live beside one another. Admission copies only signed files;
//! activation changes local paths under the same service/update exclusion as an
//! agent replacement. Package-manager scripts are never a rollback mechanism.
use crate::{now_ms, private_write, update, Config, Process, Result};
use athernex_endpoint_protocol::{
    self as protocol,
    engine::{self as wire, SignedRelease},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub mod automatic;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub automatic: bool,
    #[serde(default)]
    pub public_key: String,
    #[serde(default = "stable")]
    pub channel: String,
    pub root: Option<PathBuf>,
    #[serde(default)]
    pub minimum_sequence: u64,
    #[serde(default)]
    pub allow_unsigned_native: bool,
    /// Written with activation; each path must remain inside the managed root.
    #[serde(default)]
    pub active_libraries: Vec<PathBuf>,
    #[serde(default)]
    pub active_certificates: Option<PathBuf>,
}
fn stable() -> String {
    "stable".into()
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            managed: false,
            automatic: false,
            public_key: String::new(),
            channel: stable(),
            root: None,
            minimum_sequence: 0,
            allow_unsigned_native: false,
            active_libraries: Vec::new(),
            active_certificates: None,
        }
    }
}
impl Policy {
    pub fn enabled(&self) -> bool {
        !self.public_key.is_empty()
    }
    pub fn validate(&self) -> Result<()> {
        if self.managed && !self.enabled() {
            return Err("Fleet engine delivery requires a locally trusted release key".into());
        }
        if self.automatic && (!self.enabled() || !cfg!(any(target_os = "linux", windows))) {
            return Err("Automatic engine maintenance requires a locally trusted key and a supported controller platform (Linux or Windows)".into());
        }
        if !self.enabled() {
            if self.root.is_some()
                || !self.active_libraries.is_empty()
                || self.active_certificates.is_some()
            {
                return Err("Engine management requires a locally trusted release key".into());
            }
            return Ok(());
        }
        protocol::update::decode::<32>(&self.public_key)?;
        let root = self
            .root
            .as_ref()
            .ok_or("Engine management requires an installation root")?;
        absolute(root)?;
        if root.parent().is_none()
            || !["stable", "preview"].contains(&self.channel.as_str())
            || self.minimum_sequence > i64::MAX as u64
            || self.active_libraries.len() > 4
        {
            return Err("Invalid engine management policy".into());
        }
        for path in self
            .active_libraries
            .iter()
            .chain(self.active_certificates.iter())
        {
            absolute(path)?;
            if path == root || !path.starts_with(root) {
                return Err(
                    "Managed engine libraries must remain inside the installation root".into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub root: Option<PathBuf>,
    pub highwater: u64,
    pub staged: Option<SignedRelease>,
    pub installed: Option<SignedRelease>,
    pub retired: Vec<SignedRelease>,
    pub transaction: Option<Activation>,
    pub phase: String,
    pub error: String,
    pub updated_ms: u64,
    #[serde(default)]
    pub maintenance: Option<automatic::Request>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub release: SignedRelease,
    // Kept only in the private journal; status output never includes credentials.
    pub before: String,
    pub after_sha256: String,
    pub token: String,
    pub owner_pid: u32,
    pub expires_ms: u64,
}
pub fn status(state: &Path) -> Result<Status> {
    match update::read_bounded(&state.join("engine-updates/status.json"), 1024 * 1024) {
        Ok(bytes) => {
            let value: Status = serde_json::from_slice(&bytes)?;
            if value.retired.len() > 4 || value.highwater > i64::MAX as u64 {
                return Err("Engine ledger exceeds its budget".into());
            }
            if let Some(request) = &value.maintenance {
                request.validate()?;
            }
            Ok(value)
        }
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(Status::default())
        }
        Err(e) => Err(e),
    }
}
pub fn summary(state: &Path) -> Result<serde_json::Value> {
    let value = status(state)?;
    Ok(
        serde_json::json!({"highwater":value.highwater,"phase":value.phase,"error":value.error,"updated_ms":value.updated_ms,
        "staged":value.staged.as_ref().map(SignedRelease::id).transpose()?,
        "installed":value.installed.as_ref().map(SignedRelease::id).transpose()?,
        "retired":value.retired.len(),"recovery_required":value.transaction.is_some(),"maintenance":value.maintenance}),
    )
}
fn save(state: &Path, value: &mut Status) -> Result<()> {
    value.updated_ms = now_ms();
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 1024 * 1024 {
        return Err("Engine ledger exceeds its byte budget".into());
    }
    private_write(&state.join("engine-updates/status.json"), &bytes)
}
fn configuration(state: &Path) -> Result<(Config, String)> {
    let absolute_state = state.canonicalize()?;
    let state = absolute_state.as_path();
    let state_guard = RootGuard::open(state, false)?;
    state_guard.check_file(&state.join("config.json"))?;
    let bytes = update::read_bounded(&state.join("config.json"), 65536)?;
    let config: Config = serde_json::from_slice(&bytes)?;
    config.validate()?;
    if !config.engine_updates.enabled() {
        return Err("Engine updates are not enabled by local policy".into());
    }
    Ok((config, String::from_utf8(bytes)?))
}
fn bind_root(config: &Config, state: &Path, status: &mut Status) -> Result<PathBuf> {
    let root = config.engine_updates.root.as_ref().unwrap();
    if root.starts_with(state)
        || state.starts_with(root)
        || config
            .protection
            .roots
            .iter()
            .any(|p| root.starts_with(p) || p.starts_with(root))
    {
        return Err(
            "Engine releases must be separate from private state and native prevention roots"
                .into(),
        );
    }
    if status.root.as_ref().is_some_and(|saved| saved != root) {
        return Err("Engine root changed outside its release ledger".into());
    }
    status.root = Some(root.clone());
    Ok(root.clone())
}

fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().len() > 2048
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("Engine paths must be absolute without traversal".into());
    }
    Ok(())
}
fn no_link(path: &Path) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink() {
        return Err("Engine paths cannot contain links".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err("Engine paths cannot contain reparse points".into());
        }
    }
    Ok(m)
}
fn ancestry(path: &Path) -> Result<()> {
    absolute(path)?;
    for item in path.ancestors() {
        no_link(item)?;
    }
    Ok(())
}
struct RootGuard {
    #[cfg(windows)]
    guard: athernex_endpoint_native::mutation::PrivateDirectory,
}
impl RootGuard {
    fn open(root: &Path, create: bool) -> Result<Self> {
        absolute(root)?;
        #[cfg(windows)]
        {
            let guard = if create {
                athernex_endpoint_native::mutation::PrivateDirectory::create(root)?
            } else {
                athernex_endpoint_native::mutation::PrivateDirectory::open(root)?
            };
            Ok(Self { guard })
        }
        #[cfg(not(windows))]
        {
            if create && !root.try_exists()? {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
                    fs::DirBuilder::new().mode(0o755).create(root)?;
                    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
                }
                #[cfg(not(unix))]
                fs::create_dir(root)?;
            }
            ancestry(root)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let owner = unsafe { libc::geteuid() };
                for (index, path) in root.ancestors().enumerate() {
                    let m = no_link(path)?;
                    let sticky_ancestor = index != 0 && m.uid() == 0 && m.mode() & 0o1000 != 0;
                    if !m.is_dir()
                        || (m.uid() != owner && (index == 0 || m.uid() != 0))
                        || (m.mode() & 0o022 != 0 && !sticky_ancestor)
                    {
                        return Err(
                            "Engine root and its ancestors must prevent untrusted replacement"
                                .into(),
                        );
                    }
                }
            }
            Ok(Self {})
        }
    }
    fn check(&self) -> Result<()> {
        #[cfg(windows)]
        self.guard.check()?;
        Ok(())
    }
    fn check_file(&self, path: &Path) -> Result<()> {
        #[cfg(windows)]
        {
            let directory = athernex_endpoint_native::mutation::PrivateDirectory::open(
                path.parent().ok_or("Missing file parent")?,
            )?;
            directory.check_file(
                path.file_name()
                    .and_then(|p| p.to_str())
                    .ok_or("Invalid private file name")?,
            )?;
        }
        #[cfg(unix)]
        update::check_destination(path)?;
        let _ = path;
        self.check()
    }
}
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
}
fn claim_root(root: &Path, state: &Path, config: &Config) -> Result<()> {
    let path = root.join(".athernex-owner.json");
    let expected = serde_json::to_vec(
        &serde_json::json!({"schema":1,"state":state.canonicalize()?,"endpoint_id":config.endpoint_id}),
    )?;
    if !path.try_exists()? {
        let mut temporary = tempfile::NamedTempFile::new_in(root)?;
        temporary.write_all(&expected)?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => sync_directory(root)?,
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    no_link(&path)?;
    if update::read_bounded(&path, 4096)? != expected {
        return Err("Engine installation root belongs to another endpoint state".into());
    }
    Ok(())
}
fn open_regular(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    let m = file.metadata()?;
    if !m.is_file() {
        return Err("Engine input must be a regular file".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err("Engine input is a reparse point".into());
        }
    }
    Ok(file)
}
fn hash_file(path: &Path, size: u64) -> Result<String> {
    let mut file = open_regular(path)?;
    if file.metadata()?.len() != size {
        return Err("Engine file size differs from its manifest".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > size {
            return Err("Engine file grew beyond its budget".into());
        }
        hash.update(&buffer[..n]);
    }
    if count != size {
        return Err("Engine file changed while being read".into());
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn expected_directories(release: &SignedRelease) -> std::collections::BTreeSet<String> {
    let mut directories = std::collections::BTreeSet::new();
    for file in &release.release.files {
        let mut path = file.path.as_str();
        while let Some((parent, _)) = path.rsplit_once('/') {
            directories.insert(parent.into());
            path = parent;
        }
    }
    directories
}
fn check_layout(root: &Path, release: &SignedRelease, partial: bool) -> Result<()> {
    let _guard = RootGuard::open(root, false)?;
    let directories = expected_directories(release);
    let files: std::collections::BTreeSet<&str> = release
        .release
        .files
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0;
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let m = no_link(&entry.path())?;
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .ok_or("Engine path must be UTF-8")?
                .replace('\\', "/");
            count += 1;
            if count > wire::MAX_FILES * 8 {
                return Err("Engine tree has too many entries".into());
            }
            if m.is_dir() && directories.contains(&relative) {
                let _directory = RootGuard::open(&entry.path(), false)?;
                pending.push(entry.path());
            } else if !m.is_file() || !files.contains(relative.as_str()) {
                return Err("Unexpected entry in managed engine tree".into());
            }
        }
    }
    for file in &release.release.files {
        let path = root.join(&file.path);
        if partial && !path.try_exists()? {
            continue;
        }
        ancestry(&path)?;
        _guard.check_file(&path)?;
        if !partial && hash_file(&path, file.bytes)? != file.sha256 {
            return Err("Engine file checksum differs from the signed release".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = fs::metadata(&path)?;
            if m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o022 != 0
                || m.mode() & 0o6000 != 0
                || (file.executable && m.mode() & 0o111 == 0)
            {
                return Err("Managed engine file has unsafe ownership or mode".into());
            }
        }
    }
    Ok(())
}
fn copy_tree(source: &Path, pending: &Path, release: &SignedRelease) -> Result<()> {
    if !pending.try_exists()? {
        fs::create_dir(pending)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(pending, fs::Permissions::from_mode(0o755))?;
        }
    }
    ancestry(pending)?;
    check_layout(pending, release, true)?;
    for directory in expected_directories(release) {
        let path = pending.join(directory);
        if !path.try_exists()? {
            fs::create_dir(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
            }
        }
        no_link(&path)?;
    }
    for item in &release.release.files {
        let destination = pending.join(&item.path);
        if destination.try_exists()? {
            if hash_file(&destination, item.bytes).is_ok_and(|hash| hash == item.sha256) {
                continue;
            }
            // This path belongs to the journaled pending copy, never an active
            // release. Replace an interrupted owned file before publication.
            fs::remove_file(&destination)?;
        }
        let input = source.join(&item.path);
        ancestry(&input)?;
        let mut input = open_regular(&input)?;
        if input.metadata()?.len() != item.bytes {
            return Err("Engine source file size mismatch".into());
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if item.executable { 0o755 } else { 0o644 });
        }
        let mut output = options.open(&destination)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            output.set_permissions(fs::Permissions::from_mode(if item.executable {
                0o755
            } else {
                0o644
            }))?;
        }
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count += n as u64;
            if count > item.bytes {
                return Err("Engine input grew during staging".into());
            }
            hash.update(&buffer[..n]);
            output.write_all(&buffer[..n])?;
        }
        output.sync_all()?;
        if count != item.bytes || format!("{:x}", hash.finalize()) != item.sha256 {
            return Err("Engine source changed or has an incorrect checksum".into());
        }
    }
    check_layout(pending, release, false)?;
    for directory in expected_directories(release).iter().rev() {
        sync_directory(&pending.join(directory))?;
    }
    sync_directory(pending)
}
pub fn stage(state: &Path, manifest: &Path, source: &Path) -> Result<()> {
    let state = state.canonicalize()?;
    let _state_guard = RootGuard::open(&state, false)?;
    let source = source.canonicalize()?;
    let (config, _) = configuration(&state)?;
    let _lock = update::maintenance_lock(&state)?;
    update::require_component_transactions_settled(&state)?;
    let mut record = status(&state)?;
    automatic::require_idle(&record)?;
    if record.transaction.is_some() {
        return Err("Recover the interrupted engine activation before staging".into());
    }
    if record.retired.len() >= 2 {
        return Err("Prune retired engine releases before staging another".into());
    }
    let root = bind_root(&config, &state, &mut record)?;
    let guard = RootGuard::open(&root, true)?;
    claim_root(&root, &state, &config)?;
    let release: SignedRelease =
        serde_json::from_slice(&update::read_bounded(manifest, wire::MAX_MANIFEST)?)?;
    let floor = if record.staged.as_ref() == Some(&release) {
        if record.highwater != release.release.sequence {
            return Err("Inconsistent staged engine sequence".into());
        }
        config.engine_updates.minimum_sequence
    } else {
        if record.staged.is_some() {
            return Err("Discard the existing staged engine before changing releases".into());
        }
        record.highwater.max(config.engine_updates.minimum_sequence)
    };
    release.admit(
        &config.engine_updates.public_key,
        &protocol::update::target(),
        &config.engine_updates.channel,
        floor,
        now_ms(),
    )?;
    let id = release.id()?;
    let pending = root.join(format!(".pending-{id}"));
    let destination = root.join(&id);
    // Reserve ownership before the first file write. Interrupted copies retain
    // their sequence and explicit paths; admission never overwrites active bytes.
    record.staged = Some(release.clone());
    record.highwater = release.release.sequence;
    record.phase = "staging".into();
    record.error.clear();
    save(&state, &mut record)?;
    let result = (|| -> Result<()> {
        if destination.try_exists()? {
            check_layout(&destination, &release, false)?;
        } else {
            copy_tree(&source, &pending, &release)?;
            fs::rename(&pending, &destination)?;
            sync_directory(&root)?;
        }
        guard.check()?;
        Ok(())
    })();
    if let Err(error) = result {
        record.error = error.to_string().chars().take(512).collect();
        save(&state, &mut record)?;
        return Err(error);
    }
    record.phase = "staged".into();
    save(&state, &mut record)
}

/// Remove only paths authorized by a retained signed manifest. Unknown content
/// and links are retained for review; no recursive deletion follows a link.
fn remove_tree(root: &Path, release: &SignedRelease, partial: bool) -> Result<()> {
    if !root.try_exists()? {
        return Ok(());
    }
    ancestry(root)?;
    // Partial copies can contain incomplete owned files; check their names/types
    // before deletion, without requiring the copy to have finished hashing.
    let expected = expected_directories(release);
    let files: std::collections::BTreeSet<_> = release
        .release
        .files
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = no_link(&entry.path())?;
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .ok_or("Invalid engine path")?
                .replace('\\', "/");
            if metadata.is_dir() && expected.contains(&relative) {
                pending.push(entry.path());
            } else if !metadata.is_file() || !files.contains(relative.as_str()) {
                return Err("Unexpected engine content retained for review".into());
            }
        }
    }
    if !partial {
        check_layout(root, release, false)?;
    }
    for file in &release.release.files {
        let path = root.join(&file.path);
        if path.try_exists()? {
            fs::remove_file(path)?;
        }
    }
    for directory in expected.iter().rev() {
        let path = root.join(directory);
        if path.try_exists()? {
            fs::remove_dir(path)?;
        }
    }
    fs::remove_dir(root)?;
    sync_directory(root.parent().ok_or("Missing engine parent")?)
}
pub fn discard(state: &Path) -> Result<()> {
    let state = state.canonicalize()?;
    let _state_guard = RootGuard::open(&state, false)?;
    let (config, _) = configuration(&state)?;
    let _lock = update::maintenance_lock(&state)?;
    update::require_component_transactions_settled(&state)?;
    let mut record = status(&state)?;
    automatic::require_idle(&record)?;
    if record.transaction.is_some() {
        return Err("Recover engine activation before discarding its candidate".into());
    }
    let root = bind_root(&config, &state, &mut record)?;
    let guard = RootGuard::open(&root, false)?;
    claim_root(&root, &state, &config)?;
    if let Some(release) = &record.staged {
        release.authenticate(&config.engine_updates.public_key)?;
        if record
            .installed
            .as_ref()
            .is_some_and(|r| r.id().ok() == release.id().ok())
        {
            return Err("Cannot discard the active engine".into());
        }
        let id = release.id()?;
        remove_tree(&root.join(format!(".pending-{id}")), release, true)?;
        remove_tree(&root.join(id), release, false)?;
    }
    guard.check()?;
    record.staged = None;
    record.phase = "discarded".into();
    record.error.clear();
    save(&state, &mut record)
}

pub fn require_settled(state: &Path) -> Result<()> {
    let record = status(state)?;
    if record.transaction.is_some() {
        return Err("Recover the interrupted engine activation before starting services or other maintenance".into());
    }
    automatic::require_idle(&record)
}

const TRIAL_TOKEN: &str = "ATHERNEX_ENGINE_TRIAL";
fn candidate_config(before: &str, root: &Path, release: &SignedRelease) -> Result<Config> {
    let mut config: Config = serde_json::from_str(before)?;
    config.validate()?;
    let directory = root.join(release.id()?);
    config.scanner = directory.join(&release.release.roles.scanner);
    config.updater = directory.join(&release.release.roles.updater);
    config.protection.daemon = Some(directory.join(&release.release.roles.daemon));
    if let Some(monitor) = &release.release.roles.monitor {
        config.protection.monitor = Some(directory.join(monitor));
    }
    config.engine_updates.active_libraries = release
        .release
        .roles
        .library_dirs
        .iter()
        .map(|p| directory.join(p))
        .collect();
    config.engine_updates.active_certificates =
        Some(directory.join(&release.release.roles.certificates));
    config.validate()?;
    Ok(config)
}
fn selected_paths(config: &Config, expected: &Config) -> bool {
    config.scanner == expected.scanner
        && config.updater == expected.updater
        && config.protection.daemon == expected.protection.daemon
        && (!cfg!(target_os = "linux") || config.protection.monitor == expected.protection.monitor)
        && config.engine_updates.active_libraries == expected.engine_updates.active_libraries
        && config.engine_updates.active_certificates == expected.engine_updates.active_certificates
}
fn held(path: &Path) -> Result<bool> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    match file.try_lock() {
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(e) => Err(e.into()),
        Ok(()) => {
            file.unlock()?;
            Ok(false)
        }
    }
}
/// A pending transaction admits only its bounded owned prevention trial. Normal
/// management/controller startup stays blocked until commit or explicit recovery.
pub(crate) fn require_start_allowed(state: &Path) -> Result<()> {
    let mut record = status(state)?;
    if let Some(transaction) = record.transaction.clone() {
        let (config, current) = configuration(state)?;
        let root = bind_root(&config, state, &mut record)?;
        validate_activation(&config, &root, &transaction)?;
        if std::env::var(TRIAL_TOKEN).ok().as_deref() != Some(&transaction.token)
            || !protocol::hex_id(&transaction.token)
            || now_ms() >= transaction.expires_ms
            || protocol::hash(current.as_bytes()) != transaction.after_sha256
            || !held(&state.join("updates/update.lock"))?
            || !held(&state.join("supervisor/controller.lock"))?
        {
            return Err(
                "Recover the interrupted engine activation before starting services".into(),
            );
        }
        #[cfg(unix)]
        if unsafe { libc::getppid() } as u32 != transaction.owner_pid {
            return Err("Engine trial owner changed".into());
        }
        let guard = RootGuard::open(&root, false)?;
        claim_root(&root, state, &config)?;
        check_layout(
            &root.join(transaction.release.id()?),
            &transaction.release,
            false,
        )?;
        guard.check()?;
        return Ok(());
    }
    if let Some(release) = record.installed.clone() {
        let (config, raw) = configuration(state)?;
        let root = bind_root(&config, state, &mut record)?;
        release.authenticate(&config.engine_updates.public_key)?;
        let expected = candidate_config(&raw, &root, &release)?;
        if !selected_paths(&config, &expected) {
            return Err("Configured engine differs from its signed release ledger".into());
        }
        let guard = RootGuard::open(&root, false)?;
        claim_root(&root, state, &config)?;
        check_layout(&root.join(release.id()?), &release, false)?;
        guard.check()?;
    }
    Ok(())
}
fn validate_activation(config: &Config, root: &Path, transaction: &Activation) -> Result<Config> {
    transaction
        .release
        .authenticate(&config.engine_updates.public_key)?;
    let before: Config = serde_json::from_str(&transaction.before)?;
    before.validate()?;
    if before.engine_updates.root.as_deref() != Some(root)
        || before.engine_updates.public_key != config.engine_updates.public_key
        || !protocol::hex_id(&transaction.token)
        || transaction.owner_pid == 0
    {
        return Err("Invalid engine recovery configuration or authority".into());
    }
    let after = candidate_config(&transaction.before, root, &transaction.release)?;
    if protocol::hash(&serde_json::to_vec_pretty(&after)?) != transaction.after_sha256 {
        return Err("Engine recovery journal does not describe the signed activation".into());
    }
    Ok(after)
}
fn supports_target(path: &Path, target: &str) -> Result<bool> {
    use std::io::{Seek, SeekFrom};
    let mut file = open_regular(path)?;
    let length = file.metadata()?.len();
    let mut header = [0; 4096];
    let count = file.read(&mut header)?;
    if let Ok(actual) = update::binary_target(&header[..count]) {
        return Ok(actual == target);
    }
    let cpu = match target {
        "macos-x86_64" => 0x01000007u32,
        "macos-aarch64" => 0x0100000cu32,
        _ => return Ok(false),
    };
    // Apple's fat records are big-endian. Inspect the selected member's own
    // header as well as the wrapper; a claimed CPU without a valid slice fails.
    if count < 8 {
        return Ok(false);
    }
    let wide = match &header[..4] {
        b"\xca\xfe\xba\xbe" => false,
        b"\xca\xfe\xba\xbf" => true,
        _ => return Ok(false),
    };
    let members = u32::from_be_bytes(header[4..8].try_into()?) as usize;
    let width = if wide { 32 } else { 20 };
    if members == 0 || members > 16 || count < 8 + members * width {
        return Ok(false);
    }
    for index in 0..members {
        let entry = 8 + index * width;
        if u32::from_be_bytes(header[entry..entry + 4].try_into()?) != cpu {
            continue;
        }
        let (offset, size) = if wide {
            (
                u64::from_be_bytes(header[entry + 8..entry + 16].try_into()?),
                u64::from_be_bytes(header[entry + 16..entry + 24].try_into()?),
            )
        } else {
            (
                u32::from_be_bytes(header[entry + 8..entry + 12].try_into()?) as u64,
                u32::from_be_bytes(header[entry + 12..entry + 16].try_into()?) as u64,
            )
        };
        if offset < (8 + members * width) as u64
            || size < 64
            || offset.checked_add(size).is_none_or(|end| end > length)
        {
            return Ok(false);
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut slice = [0; 64];
        file.read_exact(&mut slice)?;
        return Ok(update::binary_target(&slice).is_ok_and(|actual| actual == target));
    }
    Ok(false)
}
fn probe(config: &Config, root: &Path, release: &SignedRelease, state: &Path) -> Result<()> {
    let directory = root.join(release.id()?);
    check_layout(&directory, release, false)?;
    let current_database = config
        .signature_database
        .as_ref()
        .or(config.protection.database.as_ref())
        .ok_or("Engine activation requires an explicit existing signature database")?;
    let database_path = current_database
        .to_str()
        .filter(|value| {
            current_database.is_absolute() && !value.chars().any(|c| c == '"' || c.is_control())
        })
        .ok_or(
            "Engine signature database path cannot be represented safely in ClamAV configuration",
        )?;
    let fixture = tempfile::Builder::new()
        .prefix("engine-probe-")
        .tempdir_in(state)?;
    // freshclam and clamd parse their configuration even for --version. Use a
    // local, minimal file so readiness never depends on global vendor settings.
    let version_config = fixture.path().join("version.conf");
    fs::write(
        &version_config,
        format!("DatabaseDirectory \"{database_path}\"\n"),
    )?;
    let signature_policy = update::UpdatePolicy {
        allow_unsigned_native: config.engine_updates.allow_unsigned_native,
        ..Default::default()
    };
    for file in &release.release.files {
        #[cfg(target_os = "macos")]
        if file.path.ends_with(".dylib") && !file.executable {
            if !config.engine_updates.allow_unsigned_native
                && crate::run_bounded(
                    Process::new("/usr/bin/codesign")
                        .args(["--verify", "--strict"])
                        .arg(directory.join(&file.path)),
                    15,
                )?
                .0 != 0
            {
                return Err("Engine library code signature rejected".into());
            }
            continue;
        }
        if file.executable
            || file.path.to_ascii_lowercase().ends_with(".dll")
            || file.path.ends_with(".dylib")
        {
            update::native_signature(&directory.join(&file.path), &signature_policy)?;
        }
    }
    for role in [
        &release.release.roles.scanner,
        &release.release.roles.updater,
        &release.release.roles.daemon,
    ]
    .into_iter()
    .chain(release.release.roles.monitor.iter())
    {
        let path = directory.join(role);
        if !supports_target(&path, &release.release.target)? {
            return Err("Engine executable architecture differs from the signed target".into());
        }
        // clamonacc --version also connects to clamd and initializes fanotify.
        // Its signed bytes and architecture are checked here; the prevention
        // trial below verifies the monitor with its candidate daemon running.
        if release.release.roles.monitor.as_ref() == Some(role) {
            continue;
        }
        let mut command = crate::antivirus::command(config, &path)?;
        if role != &release.release.roles.scanner {
            command.arg("--config-file").arg(&version_config);
        }
        let (code, output) = crate::run_bounded(command.arg("--version"), 10)?;
        if code != 0
            || output.split_whitespace().next() != Some("ClamAV")
            || output
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.split('/').next())
                != Some(release.release.version.as_str())
        {
            return Err(format!(
                "Engine role {role} did not report the signed ClamAV version (exit {code}): {}",
                output.chars().take(160).collect::<String>()
            )
            .into());
        }
    }
    let clean = fixture.path().join("clean.txt");
    let detected = fixture.path().join("matched.txt");
    let database = fixture.path().join("probe.ndb");
    let marker = format!("Athernex benign engine readiness {}", crate::secret()?);
    fs::write(&clean, b"Unrelated public clean engine control\n")?;
    fs::write(&detected, marker.as_bytes())?;
    fs::write(
        &database,
        format!(
            "AthernexEngineReadiness:0:*:{}\n",
            protocol::update::encode(marker.as_bytes())
        ),
    )?;
    for (path, expected) in [(&clean, 0), (&detected, 1)] {
        let (code, output) = crate::run_bounded(
            crate::antivirus::command(config, &config.scanner)?
                .arg("--database")
                .arg(&database)
                .args([
                    "--no-summary",
                    "--max-filesize=1M",
                    "--max-scansize=2M",
                    "--",
                ])
                .arg(path),
            30,
        )?;
        if code != expected
            || (expected == 1 && !output.contains("AthernexEngineReadiness.UNOFFICIAL FOUND"))
        {
            return Err(
                "Engine did not distinguish the clean and signature-matched controls".into(),
            );
        }
    }
    let (code, _) = crate::run_bounded(
        crate::antivirus::command(config, &config.scanner)?
            .arg("--database")
            .arg(current_database)
            .args([
                "--no-summary",
                "--max-filesize=1M",
                "--max-scansize=2M",
                "--",
            ])
            .arg(&clean),
        120,
    )?;
    if code != 0 {
        return Err("Candidate engine could not scan with the existing signature database".into());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn prevention_trial(state: &Path, config: &Config, transaction: &Activation) -> Result<()> {
    use std::{
        thread,
        time::{Duration, Instant},
    };
    let mut command = Process::new(std::env::current_exe()?);
    #[cfg(unix)]
    command
        .arg("controller-owned")
        .arg(std::process::id().to_string());
    command
        .arg("protect")
        .arg(state)
        .env(TRIAL_TOKEN, &transaction.token);
    let started = now_ms();
    #[cfg(unix)]
    let mut service = athernex_endpoint_native::child::Service::start(&mut command, 8192)?;
    #[cfg(windows)]
    let mut service = command.spawn()?;
    let result = (|| -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if let Some(code) = service.poll()? {
                return Err(format!("Candidate prevention process exited ({code})").into());
            }
            let health = crate::protection::health(config, state);
            if health.state == "active" && health.checked_ms >= started {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "Candidate engine did not establish native blocking within its trial budget"
                        .into(),
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    })();
    // Cleanup uncertainty keeps the transaction pending for later recovery.
    service.stop()?;
    result
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn prevention_trial(_: &Path, _: &Config, _: &Activation) -> Result<()> {
    Err("Native engine trial is unsupported on this platform".into())
}

fn rollback(
    state: &Path,
    config: &Config,
    root: &Path,
    record: &mut Status,
    error: &str,
) -> Result<()> {
    let transaction = record
        .transaction
        .as_ref()
        .ok_or("No engine transaction to recover")?;
    validate_activation(config, root, transaction)?;
    let current = update::read_bounded(&state.join("config.json"), 65536)?;
    let current_hash = protocol::hash(&current);
    if current_hash != protocol::hash(transaction.before.as_bytes())
        && current_hash != transaction.after_sha256
    {
        return Err(
            "Configuration changed outside the engine transaction; retained for review".into(),
        );
    }
    if let Some(previous) = &record.installed {
        previous.authenticate(&config.engine_updates.public_key)?;
        check_layout(&root.join(previous.id()?), previous, false)?;
    }
    private_write(&state.join("config.json"), transaction.before.as_bytes())?;
    let failed = transaction.release.clone();
    if !record.retired.contains(&failed) {
        record.retired.push(failed);
    }
    record.transaction = None;
    record.staged = None;
    record.phase = "rolled_back".into();
    record.error = error.chars().take(512).collect();
    automatic::finished(record, automatic::Phase::RolledBack, error)?;
    save(state, record)
}
pub fn apply(state: &Path) -> Result<()> {
    apply_inner(state, None)
}
fn apply_inner(state: &Path, controller: Option<&str>) -> Result<()> {
    let state = state.canonicalize()?;
    let _state_guard = RootGuard::open(&state, false)?;
    let (config, before) = configuration(&state)?;
    let mut maintenance = match controller {
        Some(token) => update::controller_maintenance(&state, &config, token)?,
        None => update::offline_maintenance(&state, &config)?,
    };
    let mut record = status(&state)?;
    if controller.is_none() {
        automatic::require_idle(&record)?;
    }
    if record.transaction.is_some() {
        return Err("Recover the interrupted engine activation first".into());
    }
    if record.phase != "staged" {
        return Err("Engine has not completed staging".into());
    }
    let root = bind_root(&config, &state, &mut record)?;
    let guard = RootGuard::open(&root, false)?;
    claim_root(&root, &state, &config)?;
    let release = record.staged.clone().ok_or("No staged engine release")?;
    release.admit(
        &config.engine_updates.public_key,
        &protocol::update::target(),
        &config.engine_updates.channel,
        record
            .installed
            .as_ref()
            .map_or(config.engine_updates.minimum_sequence, |r| {
                r.release
                    .sequence
                    .max(config.engine_updates.minimum_sequence)
            }),
        now_ms(),
    )?;
    if release.release.sequence != record.highwater {
        return Err("Staged engine does not match its reserved sequence".into());
    }
    require_start_allowed(&state)?;
    if controller.is_some() {
        automatic::admit(&config, &record, &release)?;
        automatic::authorize(&config, record.maintenance.as_ref().unwrap())?;
    }
    let candidate = candidate_config(&before, &root, &release)?;
    let after = serde_json::to_vec_pretty(&candidate)?;
    record.transaction = Some(Activation {
        release: release.clone(),
        before,
        after_sha256: protocol::hash(&after),
        token: crate::secret()?,
        owner_pid: std::process::id(),
        expires_ms: now_ms() + 600_000,
    });
    record.phase = "preflight".into();
    if controller.is_some() {
        record.maintenance.as_mut().unwrap().phase = automatic::Phase::Applying;
    }
    save(&state, &mut record)?;
    let result = (|| -> Result<()> {
        probe(&candidate, &root, &release, &state)?;
        guard.check()?;
        // The same before/after hashes make a crash on either side recoverable.
        if update::read_bounded(&state.join("config.json"), 65536)?
            != record.transaction.as_ref().unwrap().before.as_bytes()
        {
            return Err("Configuration changed during engine preflight".into());
        }
        record.transaction.as_mut().unwrap().expires_ms = now_ms() + 240_000;
        record.phase = "verifying".into();
        save(&state, &mut record)?;
        private_write(&state.join("config.json"), &after)?;
        if candidate.protection.enabled {
            maintenance.release_services();
            let trial = prevention_trial(&state, &candidate, record.transaction.as_ref().unwrap());
            maintenance.reacquire(&state, &candidate)?;
            trial?;
        }
        if protocol::hash(&update::read_bounded(&state.join("config.json"), 65536)?)
            != record.transaction.as_ref().unwrap().after_sha256
        {
            return Err("Engine configuration changed during runtime verification".into());
        }
        check_layout(&root.join(release.id()?), &release, false)?;
        guard.check()?;
        Ok(())
    })();
    if let Err(error) = result {
        maintenance.reacquire(&state, &candidate)?;
        rollback(&state, &config, &root, &mut record, &error.to_string())?;
        return Err(format!("Engine activation failed and was rolled back: {error}").into());
    }
    if let Some(previous) = record.installed.replace(release) {
        record.retired.push(previous);
    }
    record.staged = None;
    record.transaction = None;
    record.phase = "installed".into();
    record.error.clear();
    automatic::finished(
        &mut record,
        automatic::Phase::Installed,
        "Signed engine passed scanner, database and configured native protection checks",
    )?;
    save(&state, &mut record)
}
pub fn recover(state: &Path) -> Result<()> {
    recover_inner(state, None)
}
fn recover_inner(state: &Path, controller: Option<&str>) -> Result<()> {
    let state = state.canonicalize()?;
    let _state_guard = RootGuard::open(&state, false)?;
    let (config, _) = configuration(&state)?;
    let _maintenance = match controller {
        Some(token) => update::controller_maintenance(&state, &config, token)?,
        None => update::offline_maintenance(&state, &config)?,
    };
    let mut record = status(&state)?;
    let root = bind_root(&config, &state, &mut record)?;
    let guard = RootGuard::open(&root, false)?;
    claim_root(&root, &state, &config)?;
    if record.transaction.is_some() {
        rollback(
            &state,
            &config,
            &root,
            &mut record,
            "Interrupted engine activation recovered; failed sequence remains reserved",
        )?;
    }
    guard.check()
}
pub fn prune(state: &Path) -> Result<()> {
    let state = state.canonicalize()?;
    let _state_guard = RootGuard::open(&state, false)?;
    let (config, _) = configuration(&state)?;
    let _maintenance = update::offline_maintenance(&state, &config)?;
    let mut record = status(&state)?;
    automatic::require_idle(&record)?;
    if record.transaction.is_some() {
        return Err("Recover engine activation before pruning".into());
    }
    let root = bind_root(&config, &state, &mut record)?;
    let guard = RootGuard::open(&root, false)?;
    claim_root(&root, &state, &config)?;
    for release in &record.retired {
        release.authenticate(&config.engine_updates.public_key)?;
        if record.installed.as_ref() == Some(release) || record.staged.as_ref() == Some(release) {
            return Err("Engine retirement record refers to an active release".into());
        }
        remove_tree(&root.join(release.id()?), release, false)?;
    }
    guard.check()?;
    record.retired.clear();
    save(&state, &mut record)
}

pub fn environment(command: &mut Process, config: &Config) -> Result<()> {
    let policy = &config.engine_updates;
    if !policy.enabled() {
        return Ok(());
    }
    policy.validate()?;
    for name in [
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
    ] {
        command.env_remove(name);
    }
    if !policy.active_libraries.is_empty() {
        #[cfg(target_os = "linux")]
        command.env(
            "LD_LIBRARY_PATH",
            std::env::join_paths(&policy.active_libraries)?,
        );
        #[cfg(target_os = "macos")]
        command.env(
            "DYLD_LIBRARY_PATH",
            std::env::join_paths(&policy.active_libraries)?,
        );
    }
    Ok(())
}

pub struct Signing<'a> {
    pub target: &'a str,
    pub version: &'a str,
    pub channel: &'a str,
    pub sequence: u64,
    pub expires: u64,
}
pub fn sign(
    key: &Path,
    source: &Path,
    roles: &Path,
    metadata: Signing<'_>,
    output: &Path,
) -> Result<()> {
    let Signing {
        target,
        version,
        channel,
        sequence,
        expires,
    } = metadata;
    let source = source.canonicalize()?;
    let roles: wire::Roles = serde_json::from_slice(&update::read_bounded(roles, 4096)?)?;
    let mut files = Vec::new();
    let mut pending = vec![source.clone()];
    let mut total = 0u64;
    let mut entries = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            entries += 1;
            if entries > wire::MAX_FILES * 8 {
                return Err("Engine signing tree exceeds entry budget".into());
            }
            let entry = entry?;
            let path = entry.path();
            let m = no_link(&path)?;
            let relative = path
                .strip_prefix(&source)?
                .to_str()
                .ok_or("Engine path must be UTF-8")?
                .replace('\\', "/");
            if !wire::relative_path(&relative) {
                return Err("Engine signing tree contains an invalid path".into());
            }
            if m.is_dir() {
                pending.push(path);
                continue;
            }
            total += m.len();
            if !m.is_file()
                || files.len() >= wire::MAX_FILES
                || m.len() == 0
                || m.len() > wire::MAX_FILE
                || total > wire::MAX_TOTAL
            {
                return Err("Engine signing tree exceeds file/type budgets".into());
            }
            let executable = [&roles.scanner, &roles.updater, &roles.daemon]
                .into_iter()
                .chain(roles.monitor.iter())
                .any(|role| role == &relative);
            files.push(wire::File {
                path: relative,
                sha256: hash_file(&path, m.len())?,
                bytes: m.len(),
                executable,
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    if !supports_target(&source.join(&roles.scanner), target)? {
        return Err("Engine scanner does not contain the requested native target".into());
    }
    let release = wire::Release {
        schema: 1,
        protocol: protocol::PROTOCOL,
        engine: "clamav".into(),
        target: target.into(),
        version: version.into(),
        channel: channel.into(),
        sequence,
        issued_ms: now_ms(),
        expires_ms: expires,
        roles,
        files,
    };
    let signed = SignedRelease::sign(release, &update::read_bounded(key, 4096)?)?;
    if expires <= now_ms() {
        return Err("Engine expiration must be in the future".into());
    }
    let bytes = serde_json::to_vec_pretty(&signed)?;
    if bytes.len() as u64 > wire::MAX_MANIFEST {
        return Err("Engine manifest exceeds its byte budget".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_directory(output.parent().ok_or("Missing manifest parent")?)
}

#[cfg(test)]
mod tests;
