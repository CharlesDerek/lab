//! Prepare the Mac scanner without claiming authorization or blocking success.
//! Shared filesystem work is exercised by the Linux lifecycle fixture.
mod account;
use super::{managed_native, ProtectionConfig};
use crate::{private_write, update, Config, Result, Store};
use athernex_endpoint_native::{scanner, service};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const ENGINE: &str = "/Library/AthernexEndpointAV";
const SIGNATURE_BUDGET: u64 = 1024 * 1024 * 1024;

fn directory(path: &Path, mode: u32) -> Result<()> {
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(mode))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != mode || path.canonicalize()? != path {
        return Err("Native setup directory has unexpected ownership, mode or path".into());
    }
    Ok(())
}
fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.nlink() != 1 || m.len() != 0 {
        return Err("Invalid native setup lock".into());
    }
    file.try_lock()
        .map_err(|_| "Stop endpoint management and protection before native setup")?;
    Ok(file)
}
fn write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or("Missing setup directory")?;
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    pending.write_all(bytes)?;
    pending
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    pending.as_file().sync_all()?;
    pending.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    schema: u32,
    endpoint_id: String,
    state: PathBuf,
    uid: u32,
    gid: u32,
}

/// Configure only after the signed installer has verified and placed the adapter.
/// No test command or environment override can redirect directory-service tools.
pub fn configure(state: &Path, adapter: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Native protection setup requires root".into());
    }
    // The account name is machine-wide even when callers select different state
    // directories. Serialize all of our account creators before reading records.
    let global = Path::new("/Library/AthernexEndpointAV.setup.lock");
    let _setup = lock(global)?;
    update::check_destination(global)?;
    let mut directory_service = account::MacDirectory;
    prepare(state, adapter, Path::new(ENGINE), |state, endpoint| {
        account::prepare(&mut directory_service, state, endpoint)
    })
}

/// The explicit Linux fixture supplies numeric identities in an isolated container;
/// the production Mac path always creates/verifies its Directory Service account.
#[cfg(target_os = "linux")]
pub fn configure_fixture(
    state: &Path,
    adapter: &Path,
    engine: &Path,
    uid: u32,
    gid: u32,
) -> Result<()> {
    prepare(state, adapter, engine, |_, _| Ok((uid, gid)))
}

fn prepare(
    state: &Path,
    adapter: &Path,
    engine: &Path,
    identity: impl FnOnce(&Path, &str) -> Result<(u32, u32)>,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Native protection setup requires root".into());
    }
    let state = state.canonicalize()?;
    directory(&state, 0o700)?;
    update::check_destination(&state.join("config.json"))?;
    directory(&state.join("supervisor"), 0o700)?;
    let _controller = lock(&state.join("supervisor/controller.lock"))?;
    let _store = Store::open(&state)?;
    directory(&state.join("protection"), 0o700)?;
    let _protection = lock(&state.join("protection/supervisor.lock"))?;
    update::require_recovered(&state)?;
    let mut config: Config =
        serde_json::from_slice(&update::read_bounded(&state.join("config.json"), 65536)?)?;
    config.validate()?;
    let adapter = adapter.canonicalize()?;
    update::check_destination(&adapter)?;
    if fs::metadata(&adapter)?.mode() & 0o111 == 0 {
        return Err("Native adapter is not executable".into());
    }
    let _previous = if managed_native::has_plan(&state)? {
        Some(managed_native::quiescent(&config.protection, &state)?)
    } else {
        None
    };
    // Preserve an intentionally prepared local policy, including a disabled one.
    // Reinstallation must not silently re-enable a locally disabled adapter.
    if !config.protection.roots.is_empty() {
        if config.protection.monitor.as_ref() != Some(&adapter) {
            return Err(
                "Existing native policy uses another adapter; reconcile it before reinstalling"
                    .into(),
            );
        }
        if config.protection.enabled && _previous.is_none() {
            directory(&state.join("protection/native"), 0o700)?;
            let _quiet = service::quiescent(&managed_native::configured_plan(
                &config.protection,
                &state,
            )?)?;
        }
        if state.join("protection/setup-account.json").try_exists()? {
            let (uid, gid) = identity(&state, &config.endpoint_id)?;
            if config.protection.engine_uid != Some(uid)
                || config.protection.engine_gid != Some(gid)
            {
                return Err(
                    "Prepared native policy no longer matches its dedicated account".into(),
                );
            }
        }
        return Ok(());
    }
    let source = config
        .signature_database
        .as_ref()
        .ok_or("Provision signatures before native setup")?
        .canonicalize()?;
    update::check_destination(&config.scanner.canonicalize()?)?;
    let daemon = config
        .scanner
        .parent()
        .and_then(Path::parent)
        .ok_or("Invalid scanner prefix")?
        .join("sbin/clamd")
        .canonicalize()?;
    update::check_destination(&daemon)?;
    if fs::metadata(&daemon)?.mode() & 0o111 == 0 {
        return Err("Scanner daemon is not executable".into());
    }
    let roots: Vec<PathBuf> = config
        .scan_roots
        .iter()
        .map(|p| p.canonicalize())
        .collect::<std::io::Result<_>>()?;
    for root in &roots {
        if !root.is_dir()
            || [engine, &state, &adapter, &daemon, &source]
                .iter()
                .any(|excluded| root.starts_with(excluded) || excluded.starts_with(root))
        {
            return Err("Native scope overlaps trusted setup paths or is not a directory".into());
        }
    }
    if !engine.is_absolute()
        || engine
            .parent()
            .ok_or("Missing engine parent")?
            .canonicalize()?
            != engine.parent().unwrap()
    {
        return Err("Engine parent must be canonical".into());
    }
    // The scanner must traverse all ancestors without weakening private endpoint state.
    for p in engine.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.mode() & 0o001 == 0 {
            return Err("Scanner engine ancestors must be root-owned, traversable and not writable by others".into());
        }
    }
    if fs::symlink_metadata(engine).is_ok() {
        directory(engine, 0o755)?;
        let marker = engine.join("setup-owner.json");
        update::check_destination(&marker)?;
        let owner: Owner = serde_json::from_slice(&update::read_bounded(&marker, 8192)?)?;
        if owner.schema != 1 || owner.endpoint_id != config.endpoint_id || owner.state != state {
            return Err("Scanner engine directory is already owned by another endpoint".into());
        }
    }
    let (uid, gid) = identity(&state, &config.endpoint_id)?;
    if [0, u32::MAX].contains(&uid) || [0, u32::MAX].contains(&gid) {
        return Err("Invalid dedicated scanner identity".into());
    }
    let owner = Owner {
        schema: 1,
        endpoint_id: config.endpoint_id.clone(),
        state: state.clone(),
        uid,
        gid,
    };
    let marker = engine.join("setup-owner.json");
    match fs::symlink_metadata(engine) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            directory(engine, 0o755)?;
            write(&marker, &serde_json::to_vec(&owner)?, 0o600)?;
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {
            directory(engine, 0o755)?;
            update::check_destination(&marker)?;
            if serde_json::from_slice::<Owner>(&update::read_bounded(&marker, 8192)?)? != owner {
                return Err(
                    "Scanner engine directory belongs to another endpoint or identity".into(),
                );
            }
        }
    }
    let database = engine.join("db");
    directory(&database, 0o755)?;
    let runtime = engine.join("runtime");
    match DirBuilder::new().mode(0o700).create(&runtime) {
        Ok(()) => {
            let raw = std::ffi::CString::new(runtime.as_os_str().as_encoded_bytes())?;
            if unsafe { libc::chown(raw.as_ptr(), uid, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    directory(&state.join("protection/native"), 0o700)?;
    let policy = ProtectionConfig {
        enabled: true,
        roots,
        daemon: Some(daemon),
        monitor: Some(adapter),
        database: Some(database.clone()),
        runtime: Some(runtime),
        engine_uid: Some(uid),
        engine_gid: Some(gid),
    };
    let plan = managed_native::configured_plan(&policy, &state)?;
    let _quiet = service::quiescent(&plan)?;
    let mut total = 0u64;
    let mut count = 0;
    for entry in fs::read_dir(&source)? {
        let path = entry?.path();
        if !path.extension().is_some_and(|e| {
            [
                "cvd", "cld", "ndb", "ldb", "hdb", "hsb", "cbc", "ign", "ign2", "fp", "sfp",
            ]
            .iter()
            .any(|v| e == *v)
        }) {
            continue;
        }
        update::check_destination(&path)?;
        let mut input = scanner::open_file(&path)?;
        let before = scanner::identity(&input.metadata()?);
        total = total
            .checked_add(before.size)
            .ok_or("Signature size overflow")?;
        count += 1;
        if total > SIGNATURE_BUDGET || count > 128 {
            return Err("Signature bootstrap exceeds its file or byte budget".into());
        }
        let mut output = tempfile::NamedTempFile::new_in(&database)?;
        if std::io::copy(&mut (&mut input).take(before.size + 1), &mut output)? != before.size
            || scanner::identity(&input.metadata()?) != before
        {
            return Err("Signatures changed while preparing native protection".into());
        }
        output
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
        output.as_file().sync_all()?;
        output.persist(database.join(path.file_name().ok_or("Missing signature filename")?))?;
    }
    if count == 0 {
        return Err("No signature files are available for native protection".into());
    }
    File::open(&database)?.sync_all()?;
    // A dedicated configuration avoids redirecting an existing maintenance policy
    // if setup fails before the final atomic endpoint configuration commit.
    let fresh = state.join("av/native-freshclam.conf");
    private_write(&fresh, format!("DatabaseDirectory \"{}\"\nDatabaseMirror database.clamav.net\nDatabaseOwner root\nConnectTimeout 15\nReceiveTimeout 120\n", database.display()).as_bytes())?;
    config.signature_database = Some(database);
    config.signature_config = Some(fresh);
    config.protection = policy;
    config.validate()?;
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    Ok(())
}
