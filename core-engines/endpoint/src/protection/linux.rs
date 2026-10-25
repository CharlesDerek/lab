use super::*;
use crate::{now_ms, private_write, run_bounded};
use athernex_endpoint_protocol::{self as protocol, EndpointEvent};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream, process::CommandExt},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const USER: &str = "athernex-av";
const PROBE: &[u8] = b"ATHERNEX NATIVE PROTECTION SELF TEST 2026 010203040506";
const SIGNATURE: &str = "AthernexProtectionSelfTest";
const QUEUE_LIMIT: u64 = 2048;
mod probe;
mod reader;
use probe::{DirectoryIdentity, Probe};
pub use reader::mutation_hash_worker;
pub(crate) use reader::{mutation_hash, prepare_reader};
mod scan;
pub(crate) use scan::execute_scan;
pub use scan::scan_worker;

#[derive(Serialize, Deserialize)]
struct Status {
    policy_hash: String,
    boot: String,
    processes: Vec<(u32, u64)>,
    watched: Vec<DirectoryIdentity>,
    health: ProtectionHealth,
}
fn policy_hash(policy: &ProtectionConfig) -> Result<String> {
    Ok(protocol::hash(&serde_json::to_vec(policy)?))
}
fn birth(pid: u32) -> Option<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = raw.rsplit_once(')')?.1.split_ascii_whitespace().collect();
    if ["Z", "X", "T", "t"].contains(fields.first()?) {
        return None;
    }
    fields.get(19)?.parse().ok()
}
fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
fn base_health(policy: &ProtectionConfig) -> ProtectionHealth {
    ProtectionHealth {
        state: "starting".into(),
        backend: "clamav-linux-fanotify".into(),
        roots: policy
            .roots
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        excluded_uid: policy.engine_uid,
        ..Default::default()
    }
}
pub fn health(policy: &ProtectionConfig, state: &Path) -> ProtectionHealth {
    let result = (|| -> Result<ProtectionHealth> {
        let file = File::open(state.join("protection/health.json"))?;
        if file.metadata()?.len() > 65536 {
            return Err("Protection status exceeds budget".into());
        }
        let status: Status = serde_json::from_reader(file)?;
        status.health.validate()?;
        if status.policy_hash != policy_hash(policy)? || status.boot != boot()? {
            return Err("Protection policy or boot identity changed".into());
        }
        if status.health.checked_ms > now_ms().saturating_add(60_000)
            || now_ms().saturating_sub(status.health.checked_ms) > 90_000
        {
            return Err("Native protection status is stale".into());
        }
        if status.health.state == "active"
            && (status.processes.len() != 3
                || status
                    .processes
                    .iter()
                    .any(|(pid, start)| birth(*pid) != Some(*start)))
        {
            return Err("Native protection process stopped or changed identity".into());
        }
        if status.health.state == "active"
            && (status.watched.len() != 2 * policy.roots.len()
                || status.watched.iter().any(|d| !d.matches()))
        {
            return Err("Native protection directory identity changed".into());
        }
        Ok(status.health)
    })();
    result.unwrap_or_else(|e| {
        let mut h = base_health(policy);
        h.state = "degraded".into();
        h.error = e.to_string().chars().take(120).collect();
        h
    })
}
fn publish(
    state: &Path,
    policy: &ProtectionConfig,
    processes: Vec<(u32, u64)>,
    health: ProtectionHealth,
    watched: &[DirectoryIdentity],
) -> Result<()> {
    private_write(
        &state.join("protection/health.json"),
        &serde_json::to_vec(&Status {
            policy_hash: policy_hash(policy)?,
            boot: boot()?,
            processes,
            health,
            watched: watched.to_vec(),
        })?,
    )
}
fn queue(state: &Path) -> Result<Connection> {
    let dir = state.join("protection");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let path = dir.join("events.sqlite3");
    // Opening/closing a separate descriptor to a live SQLite database can release
    // POSIX locks held by other connections in this process. Let SQLite own the
    // descriptors; the already-private parent protects creation until chmod.
    let c = Connection::open(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    c.busy_timeout(Duration::from_secs(2))?;
    c.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA max_page_count=8192;PRAGMA wal_autocheckpoint=128;
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
        INSERT OR IGNORE INTO counters VALUES('dropped',0);")?;
    Ok(c)
}
fn counts(c: &Connection) -> Result<(u64, u64)> {
    Ok((
        c.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?,
        c.query_row("SELECT value FROM counters WHERE name='dropped'", [], |r| {
            r.get(0)
        })?,
    ))
}
fn log_event(line: &str, policy: &ProtectionConfig) -> Option<EndpointEvent> {
    let (path, detection) = line.trim().strip_suffix(" FOUND")?.rsplit_once(": ")?;
    if detection == format!("{SIGNATURE}.UNOFFICIAL")
        && Path::new(path)
            .file_name()
            .is_some_and(|n| n == "blocked-probe")
        && path.contains("/.athernex-protection-check-")
    {
        return None;
    }
    if path.len() > 1024
        || path.contains(char::is_control)
        || detection.is_empty()
        || detection.len() > 256
        || detection.contains(char::is_control)
        || !Path::new(path).is_absolute()
        || Path::new(path).components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || !policy.roots.iter().any(|r| Path::new(path).starts_with(r))
    {
        return None;
    }
    let now = now_ms();
    Some(EndpointEvent {id:protocol::hash(format!("onaccess:{}:{path}:{detection}",now/60_000).as_bytes()),time_ms:now/60_000*60_000,kind:"malware".into(),path:path.into(),sha256:String::new(),detection:detection.into(),telemetry:None,
        detail:"ClamAV on-access log observation, deduplicated within its collection minute. Original detection time and file content hash are unavailable. The log path is unverified. Automatic hash-bound quarantine is not authorized by this observation.".into()})
}
fn record(c: &Connection, event: &EndpointEvent) -> Result<()> {
    // Reserve the writer before reading admission state. A deferred read-to-write
    // upgrade can fail immediately when the collector deletes a queued record.
    let tx = rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM events WHERE id=?1)",
        [&event.id],
        |r| r.get(0),
    )?;
    if !exists
        && tx.query_row("SELECT count(*) FROM events", [], |r| r.get::<_, u64>(0))? >= QUEUE_LIMIT
    {
        tx.execute("UPDATE counters SET value=value+1 WHERE name='dropped'", [])?;
        tx.commit()?;
        return Err("Native detection queue is full; evidence collection has gaps".into());
    }
    tx.execute(
        "INSERT OR IGNORE INTO events VALUES(?1,?2)",
        params![event.id, serde_json::to_string(event)?],
    )?;
    tx.commit()?;
    Ok(())
}
pub fn collect(store: &Store) -> Result<()> {
    if !store.directory.join("protection/events.sqlite3").is_file() {
        return Ok(());
    }
    let c = queue(&store.directory)?;
    let rows = c
        .prepare("SELECT id,payload FROM events ORDER BY rowid LIMIT 64")?
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (id, raw) in rows {
        // The background telemetry collector also writes this destination.
        let tx = rusqlite::Transaction::new_unchecked(
            &store.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let existing: Option<String> = tx
            .query_row("SELECT payload FROM outbox WHERE id=?1", [&id], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(existing) = existing {
            if existing != raw {
                return Err("Native detection replay conflicts with durable observation".into());
            }
        } else {
            store.enqueue(&serde_json::from_str(&raw)?)?;
        }
        tx.commit()?;
        c.execute("DELETE FROM events WHERE id=?1", [id])?;
    }
    Ok(())
}

fn account() -> Result<(u32, u32)> {
    fn id(flag: &str) -> Result<u32> {
        let output = Command::new("/usr/bin/id").args([flag, USER]).output()?;
        if !output.status.success() {
            return Err("Dedicated scanner account is unavailable".into());
        }
        Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
    }
    Ok((id("-u")?, id("-g")?))
}
fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let raw = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    if unsafe { libc::chown(raw.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn directory(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir_all(path)?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err("Protection directory must not be a symlink".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn write_config(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    // Unlike private_write, this preserves the deliberately traversable AV data directory.
    let mut file = tempfile::NamedTempFile::new_in(path.parent().ok_or("Missing parent")?)?;
    file.write_all(content)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}
pub fn configure(state: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Native protection setup requires root".into());
    }
    let state = state.canonicalize()?;
    let mut config: Config = serde_json::from_slice(&fs::read(state.join("config.json"))?)?;
    config.validate()?;
    if account().is_err() {
        let status = Command::new("/usr/sbin/useradd")
            .args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                USER,
            ])
            .status()?;
        if !status.success() {
            return Err("Could not create dedicated scanner account".into());
        }
    }
    let (uid, gid) = account()?;
    if uid == 0 || gid == 0 || uid >= 1000 {
        return Err("Scanner account must be a dedicated system identity".into());
    }
    let base = state.with_extension("av");
    let marker = base.join("athernex-owner");
    if base.exists() && fs::read_to_string(&marker).ok().as_deref() != Some(&config.endpoint_id) {
        return Err("AV data directory is not owned by this endpoint".into());
    }
    directory(&base, 0o755)?;
    write_config(&marker, config.endpoint_id.as_bytes(), 0o600)?;
    let database = base.join("db");
    directory(&database, 0o755)?;
    let existing = config
        .signature_database
        .as_ref()
        .ok_or("Provision signatures before enabling native protection")?;
    if existing != &database {
        for entry in fs::read_dir(existing)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().is_some_and(|e| {
                    [
                        "cvd", "cld", "ndb", "ldb", "hdb", "hsb", "cbc", "ign", "ign2", "fp", "sfp",
                    ]
                    .iter()
                    .any(|v| e == *v)
                })
            {
                let destination = database.join(entry.file_name());
                let mut source = File::open(&path)?;
                let mut target = tempfile::NamedTempFile::new_in(&database)?;
                std::io::copy(&mut source, &mut target)?;
                target
                    .as_file()
                    .set_permissions(fs::Permissions::from_mode(0o644))?;
                target.as_file().sync_all()?;
                target.persist(destination)?;
            }
        }
    }
    // Whole-file matching avoids detecting the canary literal embedded in the
    // agent executable, source code, logs or documentation.
    write_config(
        &database.join("athernex-protection.hsb"),
        format!("{}:{}:{SIGNATURE}\n", protocol::hash(PROBE), PROBE.len()).as_bytes(),
        0o644,
    )?;
    let legacy = database.join("athernex-protection.ndb");
    let pattern = PROBE.iter().map(|b| format!("{b:02x}")).collect::<String>();
    if fs::read_to_string(&legacy).ok().as_deref() == Some(&format!("{SIGNATURE}:0:*:{pattern}\n"))
    {
        fs::remove_file(legacy)?;
    }
    let runtime = base.join("runtime");
    directory(&runtime, 0o700)?;
    chown(&runtime, uid, gid)?;
    let prefix = config
        .scanner
        .parent()
        .and_then(Path::parent)
        .ok_or("Invalid scanner prefix")?;
    let daemon = prefix.join("sbin/clamd");
    let monitor = prefix.join("sbin/clamonacc");
    if !daemon.is_file() || !monitor.is_file() {
        return Err("This ClamAV package does not provide clamd and clamonacc".into());
    }
    let policy = ProtectionConfig {
        enabled: true,
        roots: config
            .scan_roots
            .iter()
            .map(|r| r.canonicalize())
            .collect::<std::io::Result<_>>()?,
        daemon: Some(daemon),
        monitor: Some(monitor),
        database: Some(database.clone()),
        runtime: Some(runtime),
        engine_uid: Some(uid),
        engine_gid: Some(gid),
    };
    validate_paths(&policy, &state)?;
    let fresh = state.join("av/freshclam.conf");
    private_write(&fresh,format!("DatabaseDirectory \"{}\"\nDatabaseMirror database.clamav.net\nDatabaseOwner root\nConnectTimeout 15\nReceiveTimeout 120\n",database.display()).as_bytes())?;
    config.signature_database = Some(database);
    config.signature_config = Some(fresh);
    config.protection = policy;
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    Ok(())
}
fn validate_paths(policy: &ProtectionConfig, state: &Path) -> Result<()> {
    policy.validate()?;
    if account()? != (policy.engine_uid.unwrap(), policy.engine_gid.unwrap()) {
        return Err("Dedicated scanner identity changed".into());
    }
    for root in &policy.roots {
        if root.canonicalize()? != *root || !root.is_dir() {
            return Err("Protection roots must be canonical directories".into());
        }
        for excluded in [
            state,
            policy.database.as_ref().unwrap().as_path(),
            policy.runtime.as_ref().unwrap().as_path(),
            Path::new("/proc"),
            Path::new("/sys"),
            Path::new("/dev"),
        ] {
            if root.starts_with(excluded) || excluded.starts_with(root) {
                return Err(
                    "Protection scope overlaps runtime state or a kernel filesystem".into(),
                );
            }
        }
    }
    Ok(())
}
fn daemon_config(policy: &ProtectionConfig) -> String {
    let mut text=format!("DatabaseDirectory \"{}\"\nLocalSocket \"{}/clamd.sock\"\nLocalSocketMode 600\nUser {USER}\nForeground yes\nFixStaleSocket yes\nMaxThreads 4\nMaxQueue 16\nMaxFileSize 128M\nStreamMaxLength 128M\nMaxScanSize 256M\nAlertExceedsMax yes\nOnAccessPrevention yes\nOnAccessDenyOnError yes\nOnAccessMaxFileSize 0\nOnAccessMaxThreads 2\nOnAccessCurlTimeout 10000\nOnAccessExcludeUID {}\nSelfCheck 60\n",policy.database.as_ref().unwrap().display(),policy.runtime.as_ref().unwrap().display(),policy.engine_uid.unwrap());
    for root in &policy.roots {
        text.push_str(&format!("OnAccessIncludePath \"{}\"\n", root.display()));
    }
    text
}
fn ping(policy: &ProtectionConfig) -> Result<()> {
    let mut socket = UnixStream::connect(policy.runtime.as_ref().unwrap().join("clamd.sock"))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    socket.write_all(b"zPING\0")?;
    let mut result = [0; 5];
    socket.read_exact(&mut result)?;
    if &result != b"PONG\0" {
        return Err("Scanner did not answer its health probe".into());
    }
    Ok(())
}
struct Processes(Vec<Child>);
impl Drop for Processes {
    fn drop(&mut self) {
        for c in self.0.iter_mut().rev() {
            crate::kill_tree(c);
        }
    }
}
fn child(command: &mut Command, identity: Option<(u32, u32)>) -> Result<Child> {
    command.stdin(Stdio::null()).process_group(0);
    let parent = std::process::id();
    unsafe {
        command.pre_exec(move || {
            if let Some((uid, gid)) = identity {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Credential changes clear PDEATHSIG; set it after dropping privileges.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent as i32 {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    Ok(command.spawn()?)
}
fn alive(processes: &mut Processes) -> Result<Vec<(u32, u64)>> {
    let mut ids = vec![(
        std::process::id(),
        birth(std::process::id()).ok_or("Supervisor identity unavailable")?,
    )];
    for c in &mut processes.0 {
        if c.try_wait()?.is_some() {
            return Err("Native protection process exited".into());
        }
        ids.push((
            c.id(),
            birth(c.id()).ok_or("Native protection process stopped")?,
        ));
    }
    Ok(ids)
}
pub fn probe_read(path: &Path) -> i32 {
    match File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            match file.take(257).read_to_end(&mut bytes) {
                Ok(_) if bytes.len() <= 256 => 0,
                Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => 10,
                _ => 1,
            }
        }
        Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => 10,
        Err(_) => 1,
    }
}
fn verify_probes(probes: &[Probe]) -> Result<()> {
    for dir in probes {
        if dir.identities.iter().any(|d| !d.matches()) {
            return Err("Native protection directory identity changed".into());
        }
        for (name, expected) in [("clean-probe", 0), ("blocked-probe", 10)] {
            let (code, _) = run_bounded(
                Command::new(std::env::current_exe()?)
                    .arg("protection-probe-read")
                    .arg(dir.path_for_reader(name)),
                4,
            )?;
            if code != expected {
                return Err(format!(
                    "Native prevention probe failed for {} ({name}, status {code})",
                    dir.identities[0].path.display()
                )
                .into());
            }
        }
    }
    Ok(())
}
pub fn supervise(state: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Native protection supervisor requires root".into());
    }
    let state = state.canonicalize()?;
    let config: Config = serde_json::from_slice(&fs::read(state.join("config.json"))?)?;
    if !config.protection.enabled {
        return Err("Native protection is disabled".into());
    }
    let policy = &config.protection;
    validate_paths(policy, &state)?;
    directory(&state.join("protection"), 0o700)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("protection/supervisor.lock"))?;
    lock.try_lock()
        .map_err(|_| "Native protection supervisor is already running")?;
    let _lock = crate::StateLock(lock);
    crate::update::require_recovered(&state)?;
    let c = queue(&state)?;
    let (pending, dropped) = counts(&c)?;
    let mut status = base_health(policy);
    status.pending_events = pending;
    status.dropped_events = dropped;
    status.checked_ms = now_ms();
    publish(&state, policy, vec![], status.clone(), &[])?;
    let result = (|| -> Result<()> {
        let path = policy
            .database
            .as_ref()
            .unwrap()
            .parent()
            .ok_or("Missing AV directory")?
            .join("clamd.conf");
        write_config(&path, daemon_config(policy).as_bytes(), 0o644)?;
        let mut probes = Vec::new();
        for root in &policy.roots {
            let identity =
                protocol::hash(format!("{}:{}", config.endpoint_id, root.display()).as_bytes());
            probes.push(probe::prepare(root, &identity[..24], 0)?);
        }
        let watched: Vec<_> = probes
            .iter()
            .flat_map(|p| p.identities.iter().cloned())
            .collect();
        let daemon_log = tempfile::tempfile()?;
        let mut processes = Processes(vec![child(
            crate::antivirus::command(&config, policy.daemon.as_ref().unwrap())?
                .arg(format!("--config-file={}", path.display()))
                .arg("--foreground=true")
                .stdout(daemon_log.try_clone()?)
                .stderr(daemon_log.try_clone()?),
            Some((policy.engine_uid.unwrap(), policy.engine_gid.unwrap())),
        )?]);
        let startup = Instant::now();
        while ping(policy).is_err() {
            alive(&mut processes)?;
            if startup.elapsed() > Duration::from_secs(300) {
                return Err("Scanner startup exceeded five minutes".into());
            }
            status.checked_ms = now_ms();
            publish(&state, policy, vec![], status.clone(), &watched)?;
            thread::sleep(Duration::from_secs(1));
        }
        use std::os::unix::{ffi::OsStrExt, fs::FileTypeExt};
        let fifo = state.join("protection/monitor.fifo");
        if let Ok(meta) = fs::symlink_metadata(&fifo) {
            if !meta.file_type().is_fifo() {
                return Err("Unexpected file at native monitor pipe path".into());
            }
            fs::remove_file(&fifo)?;
        }
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes())?;
        if unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let reader = OpenOptions::new().read(true).write(true).open(&fifo)?;
        let monitor = child(
            crate::antivirus::command(&config, policy.monitor.as_ref().unwrap())?
                .arg(format!("--config-file={}", path.display()))
                .args(["--foreground", "--fdpass"])
                .arg(format!("--log={}", fifo.display()))
                .stdout(daemon_log.try_clone()?)
                .stderr(daemon_log.try_clone()?),
            None,
        )?;
        processes.0.push(monitor);
        let log_error = Arc::new(Mutex::new(String::new()));
        let errors = log_error.clone();
        let log_state = state.clone();
        let log_policy = policy.clone();
        thread::spawn(move || {
            let run = (|| -> Result<()> {
                let c = queue(&log_state)?;
                let mut reader = BufReader::new(reader);
                loop {
                    let mut line = Vec::new();
                    let n = reader.by_ref().take(8193).read_until(b'\n', &mut line)?;
                    if n == 0 {
                        break;
                    }
                    if n > 8192 || line.last() != Some(&b'\n') {
                        return Err("Native monitor emitted an oversized or partial record".into());
                    }
                    let line = std::str::from_utf8(&line)?;
                    if let Some(event) = log_event(line, &log_policy) {
                        if let Err(e) = record(&c, &event) {
                            *errors.lock().unwrap() = e.to_string();
                        }
                    } else if line.starts_with("ERROR:")
                        || line.starts_with("WARNING:")
                        || line.contains("ERROR:")
                    {
                        *errors.lock().unwrap() =
                            "Native monitor reported a collection or scanning error".into();
                    }
                }
                Err("Native monitor output closed".into())
            })();
            if let Err(e) = run {
                *errors.lock().unwrap() = e.to_string();
            }
        });
        thread::sleep(Duration::from_secs(2));
        loop {
            let ids = alive(&mut processes)?;
            ping(policy)?;
            verify_probes(&probes)?;
            let (pending, dropped) = counts(&c)?;
            status.pending_events = pending;
            status.dropped_events = dropped;
            let error = log_error
                .lock()
                .map_err(|_| "Native logging worker unavailable")?
                .clone();
            status.state = if error.is_empty() && dropped == 0 {
                "active"
            } else {
                "degraded"
            }
            .into();
            status.error = if !error.is_empty() {
                error.chars().take(120).collect()
            } else if dropped != 0 {
                "Native detection records were dropped; inspect collection capacity".into()
            } else {
                String::new()
            };
            status.checked_ms = now_ms();
            publish(&state, policy, ids, status.clone(), &watched)?;
            // Treat excessive vendor diagnostics as an explicit protection failure.
            if daemon_log.metadata()?.len() > 1024 * 1024 {
                return Err("Scanner diagnostics exceeded budget".into());
            }
            thread::sleep(Duration::from_secs(30));
        }
    })();
    if let Err(e) = &result {
        status.state = "degraded".into();
        status.error = e.to_string().chars().take(120).collect();
        status.checked_ms = now_ms();
        let _ = publish(&state, policy, vec![], status, &[]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(root: &Path) -> ProtectionConfig {
        ProtectionConfig {
            enabled: true,
            roots: vec![root.into()],
            daemon: Some("/usr/sbin/clamd".into()),
            monitor: Some("/usr/sbin/clamonacc".into()),
            database: Some("/private/db".into()),
            runtime: Some("/private/runtime".into()),
            engine_uid: Some(999),
            engine_gid: Some(999),
        }
    }
    #[test]
    fn native_records_recover_across_both_durable_queues() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let p = policy(Path::new("/public/watch"));
        let event = log_event("/public/watch/fixture: Fixture.UNOFFICIAL FOUND\n", &p).unwrap();
        assert!(event.sha256.is_empty());
        assert_eq!(event.time_ms % 60_000, 0);
        let c = queue(dir.path()).unwrap();
        record(&c, &event).unwrap();
        record(&c, &event).unwrap();
        assert_eq!(counts(&c).unwrap().0, 1);
        store.connection.execute_batch("CREATE TRIGGER fixture_full BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture full'); END;").unwrap();
        assert!(collect(&store).is_err());
        assert_eq!(counts(&c).unwrap().0, 1);
        store
            .connection
            .execute_batch("DROP TRIGGER fixture_full")
            .unwrap();
        collect(&store).unwrap();
        assert_eq!(counts(&c).unwrap().0, 0);
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
        // Reproduce a crash after the destination committed but before source deletion.
        record(&c, &event).unwrap();
        collect(&store).unwrap();
        assert_eq!(counts(&c).unwrap().0, 0);
        let raw: String = store
            .connection
            .query_row("SELECT payload FROM outbox WHERE id=?1", [&event.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(serde_json::to_string(&event).unwrap(), raw);
    }
    #[test]
    fn capacity_and_self_probe_boundaries_are_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let c = queue(dir.path()).unwrap();
        let p = policy(Path::new("/public/watch"));
        assert!(log_event("/public/watch/.athernex-protection-check-test/blocked-probe: AthernexProtectionSelfTest.UNOFFICIAL FOUND",&p).is_none());
        assert!(log_event("/public/watch/.athernex-protection-check-test/blocked-probe: OtherMalware.UNOFFICIAL FOUND",&p).is_some());
        assert!(log_event("/other/fixture: Fixture FOUND", &p).is_none());
        assert!(log_event("/public/watch/../other: Fixture FOUND", &p).is_none());
        c.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<2048) INSERT INTO events SELECT printf('%064x',x),'{}' FROM n").unwrap();
        let event = log_event("/public/watch/fixture: Fixture.UNOFFICIAL FOUND", &p).unwrap();
        assert!(record(&c, &event).is_err());
        assert_eq!(counts(&c).unwrap(), (2048, 1));
    }
    #[test]
    fn native_record_waits_for_collector_deletion_before_admission() {
        let dir = tempfile::tempdir().unwrap();
        let collector = queue(dir.path()).unwrap();
        let producer = queue(dir.path()).unwrap();
        let p = policy(Path::new("/public/watch"));
        let prior = log_event("/public/watch/prior: Fixture FOUND", &p).unwrap();
        let next = log_event("/public/watch/next: Fixture FOUND", &p).unwrap();
        record(&collector, &prior).unwrap();
        let deleting = rusqlite::Transaction::new_unchecked(
            &collector,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        deleting
            .execute("DELETE FROM events WHERE id=?1", [&prior.id])
            .unwrap();
        let expected = next.clone();
        complete_after_writer_releases(deleting, move || record(&producer, &next));
        assert_eq!(counts(&collector).unwrap(), (1, 0));
        let raw: String = collector
            .query_row(
                "SELECT payload FROM events WHERE id=?1",
                [&expected.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(raw, serde_json::to_string(&expected).unwrap());
    }
    #[test]
    fn native_transfer_waits_for_background_outbox_writer_without_losing_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let transfer = store.collector_connection().unwrap();
        let c = queue(dir.path()).unwrap();
        let p = policy(Path::new("/public/watch"));
        let event = log_event("/public/watch/fixture: Fixture FOUND", &p).unwrap();
        record(&c, &event).unwrap();
        let background = rusqlite::Transaction::new_unchecked(
            &store.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        complete_after_writer_releases(background, move || collect(&transfer));
        assert_eq!(counts(&c).unwrap(), (0, 0));
        let raw: String = store
            .connection
            .query_row("SELECT payload FROM outbox WHERE id=?1", [&event.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(raw, serde_json::to_string(&event).unwrap());
    }
    fn complete_after_writer_releases(
        writer: rusqlite::Transaction<'_>,
        operation: impl FnOnce() -> Result<()> + Send + 'static,
    ) {
        let (started, ready) = std::sync::mpsc::sync_channel(0);
        let (finished, result) = std::sync::mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            started.send(()).unwrap();
            finished
                .send(operation().map_err(|error| error.to_string()))
                .unwrap();
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        // A deferred read-to-write upgrade fails immediately under this lock,
        // even though the configured busy timeout could wait for its release.
        let early = result.recv_timeout(Duration::from_millis(100));
        writer.commit().unwrap();
        worker.join().unwrap();
        early
            .unwrap_or_else(|_| result.recv_timeout(Duration::from_secs(5)).unwrap())
            .unwrap();
    }
    #[test]
    fn active_health_requires_fresh_policy_and_live_process_identities() {
        let dir = tempfile::tempdir().unwrap();
        let watch = dir.path().join("watch");
        fs::create_dir(&watch).unwrap();
        let p = policy(&watch);
        let probe = probe::prepare(&watch, "ab", unsafe { libc::geteuid() }).unwrap();
        let mut processes = Processes(vec![
            child(Command::new("/bin/sleep").arg("60"), None).unwrap(),
            child(Command::new("/bin/sleep").arg("60"), None).unwrap(),
        ]);
        let ids = alive(&mut processes).unwrap();
        let mut status = base_health(&p);
        status.state = "active".into();
        status.checked_ms = now_ms();
        publish(
            dir.path(),
            &p,
            ids.clone(),
            status.clone(),
            &probe.identities,
        )
        .unwrap();
        assert_eq!(health(&p, dir.path()).state, "active");
        let mut changed = p.clone();
        changed.roots.push("/different".into());
        assert_eq!(health(&changed, dir.path()).state, "degraded");
        status.checked_ms = now_ms() - 100_000;
        publish(
            dir.path(),
            &p,
            ids.clone(),
            status.clone(),
            &probe.identities,
        )
        .unwrap();
        assert_eq!(health(&p, dir.path()).state, "degraded");
        status.checked_ms = now_ms();
        publish(dir.path(), &p, ids, status, &probe.identities).unwrap();
        processes.0[0].kill().unwrap();
        processes.0[0].wait().unwrap();
        assert_eq!(health(&p, dir.path()).state, "degraded");
    }
}
