//! Owned scanner/authorization service pair. On Mac, healthy status requires
//! fresh operation-specific blocking evidence for every configured root.
use crate::{broker, child, receipt, scanner, Policy, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub policy: Policy,
    pub daemon: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_libraries: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_certificates: Option<PathBuf>,
    pub database: PathBuf,
    pub scanner_gid: u32,
    pub startup_secs: u64,
}
impl Plan {
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        if self.schema != 1
            || [0, u32::MAX].contains(&self.scanner_gid)
            || self.policy.scanner_uid == u32::MAX
            || !(1..=300).contains(&self.startup_secs)
            || self.engine_libraries.len() > 4
        {
            return Err("Invalid native service plan".into());
        }
        for path in [
            self.daemon.as_path(),
            self.database.as_path(),
            self.policy.socket.as_path(),
        ]
        .into_iter()
        .chain(self.engine_libraries.iter().map(PathBuf::as_path))
        .chain(self.engine_certificates.iter().map(PathBuf::as_path))
        {
            if !path.is_absolute()
                || path.as_os_str().len() > 1024
                || path
                    .to_str()
                    .is_none_or(|p| p.chars().any(char::is_control) || p.contains('"'))
                || path.components().any(|p| {
                    matches!(
                        p,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err("Invalid native service path".into());
            }
        }
        if self
            .policy
            .socket
            .file_name()
            .is_none_or(|n| n != "clamd.sock")
        {
            return Err("Native service requires its private clamd.sock".into());
        }
        let runtime = self
            .policy
            .socket
            .parent()
            .ok_or("Missing scanner runtime")?;
        if runtime.parent() != self.database.parent() {
            return Err(
                "Scanner database and runtime must share a dedicated service directory".into(),
            );
        }
        for root in &self.policy.roots {
            for excluded in [&self.policy.state, &self.database, &self.daemon, runtime]
                .into_iter()
                .chain(self.engine_libraries.iter().map(PathBuf::as_path))
                .chain(self.engine_certificates.iter().map(PathBuf::as_path))
            {
                if root.starts_with(excluded) || excluded.starts_with(root) {
                    return Err("Native service scope overlaps trusted runtime paths".into());
                }
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        digest(self)
    }
    fn check_host(&self) -> Result<()> {
        self.validate()?;
        if unsafe { libc::geteuid() } != 0 {
            return Err("Native services require the root service identity".into());
        }
        broker::trusted(&self.policy.state, true)?;
        broker::trusted(&self.database, false)?;
        broker::trusted(&self.daemon, false)?;
        for directory in self
            .engine_libraries
            .iter()
            .chain(self.engine_certificates.iter())
        {
            broker::trusted(directory, false)?;
            if !directory.is_dir() || directory.canonicalize()? != *directory {
                return Err("Native engine libraries require canonical trusted directories".into());
            }
        }
        if !scanner::open_file(&self.daemon)?.metadata()?.is_file() || !self.database.is_dir() {
            return Err("Native scanner executable or database is unavailable".into());
        }
        for root in &self.policy.roots {
            if root.canonicalize()? != *root || !fs::symlink_metadata(root)?.is_dir() {
                return Err("Native service roots must be canonical directories".into());
            }
        }
        let runtime = self
            .policy
            .socket
            .parent()
            .ok_or("Missing scanner runtime")?;
        broker::trusted(runtime.parent().ok_or("Missing runtime parent")?, false)?;
        let m = fs::symlink_metadata(runtime)?;
        if !m.is_dir()
            || m.uid() != self.policy.scanner_uid
            || m.gid() != self.scanner_gid
            || m.mode() & 0o077 != 0
        {
            return Err("Scanner runtime must be private to its dedicated identity".into());
        }
        if self.database.canonicalize()? != self.database
            || self.daemon.canonicalize()? != self.daemon
        {
            return Err("Native scanner paths must be canonical".into());
        }
        Ok(())
    }
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub(crate) fn read<T: serde::de::DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    broker::trusted(path, true)?;
    let mut bytes = Vec::new();
    scanner::open_file(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("Native service record exceeds its byte budget".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn read_plan(path: &Path) -> Result<Plan> {
    let plan: Plan = read(path, 16384)?;
    plan.check_host()?;
    Ok(plan)
}
pub(crate) fn write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    write_bounded(path, bytes, mode, 262144)
}
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn write_health_image(path: &Path, bytes: &[u8]) -> Result<()> {
    write_bounded(path, bytes, 0o700, 16 * 1024 * 1024)
}
fn write_bounded(path: &Path, bytes: &[u8], mode: u32, limit: usize) -> Result<()> {
    if bytes.len() > limit
        || fs::read_dir(path.parent().ok_or("Missing service directory")?)?
            .take(4097)
            .collect::<std::io::Result<Vec<_>>>()?
            .len()
            > 4096
    {
        return Err(
            "Native service write exceeds its byte or directory budget; review required".into(),
        );
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random)?;
    let pending = path.with_extension(format!("{:032x}.pending", u128::from_le_bytes(random)));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&pending)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&pending, path)?;
        File::open(path.parent().ok_or("Missing service directory")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(pending);
    }
    result
}
pub(crate) fn boot() -> Result<String> {
    #[cfg(target_os = "linux")]
    let raw = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    #[cfg(target_os = "macos")]
    let raw = {
        let mut bytes = [0u8; 128];
        let mut length = bytes.len();
        if unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if length == 0 || length > bytes.len() {
            return Err("Invalid boot identity length".into());
        }
        std::str::from_utf8(&bytes[..length])?
            .trim_end_matches('\0')
            .to_string()
    };
    let value = raw.trim().to_ascii_lowercase();
    if value.len() != 36 || !value.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-') {
        return Err("Invalid native boot identity".into());
    }
    Ok(value)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    schema: u32,
    boot: String,
    pgid: u32,
    plan_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    record: Group,
    sha256: String,
}
fn group_exists(pgid: u32) -> Result<bool> {
    if pgid <= 1 || pgid > i32::MAX as u32 {
        return Err("Invalid service process group".into());
    }
    if unsafe { libc::kill(-(pgid as i32), 0) } == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(std::io::Error::last_os_error().into()),
    }
}
fn previous_group(state: &Path, role: &str) -> Result<()> {
    let path = state.join(format!("service-{role}.json"));
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let saved: Journal = read(&path, 4096)?;
    if saved.record.schema != 1
        || !receipt::hex_id(&saved.record.plan_sha256)
        || saved.sha256 != digest(&saved.record)?
    {
        return Err("Native service group journal is damaged; review required".into());
    }
    if saved.record.boot == boot()? && group_exists(saved.record.pgid)? {
        // Never signal a group recovered from disk: its leader may have been
        // recycled. Refuse overlap until the group is gone or reviewed locally.
        return Err("Earlier native service group still exists; cleanup requires review".into());
    }
    Ok(())
}
fn lock(state: &Path, role: &str) -> Result<File> {
    let path = state.join(format!("service-{role}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    broker::trusted(&path, true)?;
    let m = file.metadata()?;
    if !m.is_file() || m.len() != 0 || m.nlink() != 1 {
        return Err("Invalid native service lock".into());
    }
    file.try_lock()
        .map_err(|_| "Native service is already owned")?;
    Ok(file)
}
fn register_group(plan: &Plan, role: &str) -> Result<File> {
    let lease = lock(&plan.policy.state, role)?;
    previous_group(&plan.policy.state, role)?;
    let pgid = std::process::id();
    if unsafe { libc::getpgrp() } != pgid as i32 {
        return Err("Native service worker must own its process group".into());
    }
    let record = Group {
        schema: 1,
        boot: boot()?,
        pgid,
        plan_sha256: plan.digest()?,
    };
    let journal = Journal {
        sha256: digest(&record)?,
        record,
    };
    write(
        &plan.policy.state.join(format!("service-{role}.json")),
        &serde_json::to_vec(&journal)?,
        0o600,
    )?;
    Ok(lease)
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EngineOwner {
    schema: u32,
    state: PathBuf,
    uid: u32,
    gid: u32,
}
fn claim_engine(plan: &Plan) -> Result<File> {
    let directory = plan.database.parent().ok_or("Missing engine directory")?;
    let lease = lock(directory, "engine")?;
    let path = directory.join("athernex-native-owner.json");
    let expected = EngineOwner {
        schema: 1,
        state: plan.policy.state.clone(),
        uid: plan.policy.scanner_uid,
        gid: plan.scanner_gid,
    };
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if read::<EngineOwner>(&path, 4096)? != expected {
                return Err(
                    "Scanner runtime belongs to a different endpoint state or identity".into(),
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write(&path, &serde_json::to_vec(&expected)?, 0o600)?
        }
        Err(e) => return Err(e.into()),
    }
    Ok(lease)
}
/// Retain exclusion while replacing management files. Existing worker groups
/// must already be gone; disk records never authorize sending them a signal.
pub struct Quiescent {
    _supervisor: File,
    _engine: File,
}
pub fn quiescent(plan: &Plan) -> Result<Quiescent> {
    plan.check_host()?;
    let supervisor = lock(&plan.policy.state, "supervisor")?;
    let engine = claim_engine(plan)?;
    previous_group(&plan.policy.state, "scanner")?;
    previous_group(&plan.policy.state, "adapter")?;
    Ok(Quiescent {
        _supervisor: supervisor,
        _engine: engine,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: u32,
    pub phase: String,
    pub runtime_protection_verified: bool,
    #[serde(default)]
    pub verification: Option<crate::health::Reference>,
    pub plan_sha256: String,
    pub boot: String,
    pub supervisor_pid: u32,
    pub checked_ms: u64,
    pub scanner_group: Option<u32>,
    pub adapter_group: Option<u32>,
    pub error: String,
    pub output_tail: String,
    pub dropped_output_bytes: u64,
}
pub fn observe(plan: &Plan) -> Result<Observation> {
    plan.validate()?;
    let status: Observation = read(&plan.policy.state.join("service-status.json"), 65536)?;
    if status.schema != 1
        || status.plan_sha256 != plan.digest()?
        || status.boot != boot()?
        || ![
            "starting",
            "running-unverified",
            "running-verified",
            "failed",
        ]
        .contains(&status.phase.as_str())
        || status.runtime_protection_verified != (status.phase == "running-verified")
        || status.runtime_protection_verified != status.verification.is_some()
        || status.supervisor_pid <= 1
        || status.supervisor_pid > i32::MAX as u32
        || status.checked_ms > now_ms().saturating_add(1000)
        || now_ms().saturating_sub(status.checked_ms) > 10_000
        || status.error.len() > 4096
        || status.output_tail.len() > 32768
    {
        return Err("Native service status is stale, changed or invalid".into());
    }
    if status.phase != "failed" {
        if unsafe { libc::kill(status.supervisor_pid as i32, 0) } != 0 {
            return Err("Native supervisor is unavailable".into());
        }
        let file = scanner::open_file(&plan.policy.state.join("service-supervisor.lock"))?;
        match file.try_lock() {
            Err(std::fs::TryLockError::WouldBlock) => {}
            Ok(()) => {
                file.unlock()?;
                return Err("Native supervisor lease is not held".into());
            }
            Err(e) => return Err(e.into()),
        }
        if status.phase.starts_with("running-")
            && (status.scanner_group.is_none() || status.adapter_group.is_none())
        {
            return Err("Native service group identity is incomplete".into());
        }
        if let Some(reference) = &status.verification {
            crate::health::observe(
                plan,
                reference,
                status.supervisor_pid,
                status
                    .adapter_group
                    .ok_or("Missing native adapter identity")?,
            )?;
        }
        for pid in [status.scanner_group, status.adapter_group]
            .into_iter()
            .flatten()
        {
            if !group_exists(pid)? {
                return Err("Native service group stopped".into());
            }
        }
    }
    Ok(status)
}
fn owned_plan(parent: u32, expected: &str, path: &Path) -> Result<Plan> {
    child::guard_parent(parent)?;
    let plan = read_plan(path)?;
    if !receipt::hex_id(expected) || plan.digest()? != expected {
        return Err("Native service plan changed before startup".into());
    }
    let status: serde_json::Value = read(&plan.policy.state.join("service-status.json"), 65536)?;
    let current_boot = boot()?;
    if status["supervisor_pid"].as_u64() != Some(parent as u64)
        || status["plan_sha256"].as_str() != Some(expected)
        || status["boot"].as_str() != Some(current_boot.as_str())
    {
        return Err("Native worker does not match its supervisor status".into());
    }
    // The status alone is not a lease. A worker must also observe both live
    // locks; direct calls cannot start an unowned pair from a stale status file.
    for (directory, role) in [
        (plan.policy.state.as_path(), "supervisor"),
        (
            plan.database.parent().ok_or("Missing engine directory")?,
            "engine",
        ),
    ] {
        let file = scanner::open_file(&directory.join(format!("service-{role}.lock")))?;
        match file.try_lock() {
            Ok(()) => {
                file.unlock()?;
                return Err("Native worker supervisor lease is not held".into());
            }
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(plan)
}
/// The wrapper retains the root-owned group journal and lock while the scanner
/// runs under its dedicated UID/GID. The scanner deliberately shares its group.
pub fn scanner_worker(parent: u32, expected: &str, path: &Path) -> Result<()> {
    let plan = owned_plan(parent, expected, path)?;
    let _lease = register_group(&plan, "scanner")?;
    let config = plan
        .database
        .parent()
        .ok_or("Missing scanner database parent")?
        .join("athernex-native-clamd.conf");
    broker::trusted(
        config
            .parent()
            .ok_or("Missing scanner configuration parent")?,
        false,
    )?;
    let text = format!("Foreground yes\nDatabaseDirectory \"{}\"\nTemporaryDirectory \"{}\"\nLocalSocket \"{}\"\nLocalSocketMode 600\nFixStaleSocket yes\nMaxThreads 4\nMaxQueue 16\nStreamMaxLength 128M\nMaxFileSize 128M\nMaxScanSize 256M\nAlertExceedsMax yes\nSelfCheck 60\n",plan.database.display(),plan.policy.socket.parent().unwrap().display(),plan.policy.socket.display());
    write(&config, text.as_bytes(), 0o644)?;
    let mut command = Command::new(&plan.daemon);
    if let Some(path) = &plan.engine_certificates {
        command.arg("--cvdcertsdir").arg(path);
    }
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
    if !plan.engine_libraries.is_empty() {
        #[cfg(target_os = "linux")]
        command.env(
            "LD_LIBRARY_PATH",
            std::env::join_paths(&plan.engine_libraries)?,
        );
        #[cfg(target_os = "macos")]
        command.env(
            "DYLD_LIBRARY_PATH",
            std::env::join_paths(&plan.engine_libraries)?,
        );
    }
    command
        .arg(format!("--config-file={}", config.display()))
        .arg("--foreground=true")
        .stdin(Stdio::null());
    let parent = std::process::id();
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(plan.scanner_gid) != 0
                || libc::setuid(plan.policy.scanner_uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent as i32 {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let status = command.spawn()?.wait()?;
    eprintln!("Native scanner exited: {status}");
    // The wrapper is the live group leader, so this cannot target a recycled PID.
    unsafe {
        libc::kill(-libc::getpgrp(), libc::SIGKILL);
    }
    Err("Native scanner group could not be terminated".into())
}
pub fn adapter_worker(parent: u32, expected: &str, path: &Path) -> Result<()> {
    let plan = owned_plan(parent, expected, path)?;
    let _lease = register_group(&plan, "adapter")?;
    #[cfg(target_os = "macos")]
    {
        crate::macos::run(plan.policy)
    }
    #[cfg(target_os = "linux")]
    {
        let _broker = broker::Broker::start(
            plan.policy,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )?;
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
}
fn ping(plan: &Plan) -> Result<()> {
    let m = fs::symlink_metadata(&plan.policy.socket)?;
    if !m.file_type().is_socket() || m.uid() != plan.policy.scanner_uid || m.mode() & 0o077 != 0 {
        return Err("Scanner socket identity changed".into());
    }
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    let timeout = Duration::from_millis(250);
    socket.connect_timeout(&socket2::SockAddr::unix(&plan.policy.socket)?, timeout)?;
    let fd: OwnedFd = socket.into();
    let mut stream = UnixStream::from(fd);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"zPING\0")?;
    let mut response = [0; 5];
    stream.read_exact(&mut response)?;
    if &response != b"PONG\0" {
        return Err("Scanner health response is invalid".into());
    }
    Ok(())
}
#[derive(Serialize)]
struct Status<'a> {
    schema: u32,
    phase: &'a str,
    runtime_protection_verified: bool,
    verification: Option<crate::health::Reference>,
    plan_sha256: String,
    boot: String,
    supervisor_pid: u32,
    checked_ms: u64,
    scanner_group: Option<u32>,
    adapter_group: Option<u32>,
    error: &'a str,
    output_tail: String,
    dropped_output_bytes: u64,
}
fn publish(
    plan: &Plan,
    phase: &str,
    scanner: Option<&child::Service>,
    adapter: Option<&child::Service>,
    error: &str,
) -> Result<()> {
    publish_status(plan, phase, scanner, adapter, error, None)
}
fn publish_status(
    plan: &Plan,
    phase: &str,
    scanner: Option<&child::Service>,
    adapter: Option<&child::Service>,
    error: &str,
    verification: Option<crate::health::Reference>,
) -> Result<()> {
    let children = [scanner, adapter];
    let output = children
        .iter()
        .flatten()
        .flat_map(|s| s.output().iter().copied())
        .collect::<Vec<_>>();
    let status = Status {
        schema: 1,
        phase,
        runtime_protection_verified: verification.is_some(),
        verification,
        plan_sha256: plan.digest()?,
        boot: boot()?,
        supervisor_pid: std::process::id(),
        checked_ms: now_ms(),
        scanner_group: scanner.and_then(child::Service::pid),
        adapter_group: adapter.and_then(child::Service::pid),
        error,
        output_tail: String::from_utf8_lossy(&output)
            .chars()
            .take(8192)
            .collect(),
        dropped_output_bytes: children
            .iter()
            .flatten()
            .fold(0u64, |n, s| n.saturating_add(s.dropped_output())),
    };
    write(
        &plan.policy.state.join("service-status.json"),
        &serde_json::to_vec(&status)?,
        0o600,
    )
}
pub fn supervise(path: &Path, parent: Option<u32>) -> Result<()> {
    if let Some(parent) = parent {
        child::guard_parent(parent)?;
    }
    let plan = read_plan(path)?;
    let _lease = lock(&plan.policy.state, "supervisor")?;
    let _engine = claim_engine(&plan)?;
    publish(&plan, "starting", None, None, "")?;
    let result = (|| -> Result<()> {
        previous_group(&plan.policy.state, "scanner")?;
        previous_group(&plan.policy.state, "adapter")?;
        let executable = std::env::current_exe()?;
        let hash = plan.digest()?;
        #[cfg(target_os = "macos")]
        let prepared = {
            let prepared = crate::health::prepare(&plan, &executable)?;
            crate::health::baseline(&prepared, &plan.policy, &executable)?;
            prepared
        };
        let mut scanner = child::Service::start(
            Command::new(&executable)
                .arg("scanner-owned")
                .arg(std::process::id().to_string())
                .arg(&hash)
                .arg(path),
            4096,
        )?;
        let startup = Instant::now();
        while let Err(ping_error) = ping(&plan) {
            if scanner.poll()?.is_some() {
                return Err(format!(
                    "Native scanner exited during startup: {}",
                    String::from_utf8_lossy(scanner.output())
                )
                .into());
            }
            if startup.elapsed() > Duration::from_secs(plan.startup_secs) {
                return Err(format!(
                    "Native scanner startup deadline elapsed: {ping_error}; {}",
                    String::from_utf8_lossy(scanner.output())
                )
                .into());
            }
            publish(&plan, "starting", Some(&scanner), None, "")?;
            thread::sleep(Duration::from_millis(100));
        }
        let mut adapter = child::Service::start(
            Command::new(&executable)
                .arg("adapter-owned")
                .arg(std::process::id().to_string())
                .arg(&hash)
                .arg(path),
            4096,
        )?;
        #[cfg(target_os = "macos")]
        let health = crate::health::Watch::start(
            prepared,
            plan.clone(),
            executable,
            adapter.pid().ok_or("Missing adapter process")?,
            vec![_lease.try_clone()?, _engine.try_clone()?],
        )?;
        loop {
            if scanner.poll()?.is_some() || adapter.poll()?.is_some() {
                return Err(format!(
                    "Native service child exited; scanner: {}; adapter: {}",
                    String::from_utf8_lossy(scanner.output()),
                    String::from_utf8_lossy(adapter.output())
                )
                .into());
            }
            ping(&plan)?;
            #[cfg(target_os = "macos")]
            let verification = health.current().and_then(|reference| {
                crate::health::observe(
                    &plan,
                    &reference,
                    std::process::id(),
                    adapter.pid().unwrap_or(0),
                )
                .map(|()| reference)
                .map_err(|e| e.to_string())
            });
            #[cfg(target_os = "linux")]
            let verification: std::result::Result<crate::health::Reference, String> =
                Err("Linux lifecycle fixture does not execute Apple authorization".into());
            let (phase, proof, error) = match verification {
                Ok(reference) => ("running-verified", Some(reference), String::new()),
                Err(error) => (
                    "running-unverified",
                    None,
                    error.chars().take(512).collect(),
                ),
            };
            publish_status(&plan, phase, Some(&scanner), Some(&adapter), &error, proof)?;
            thread::sleep(Duration::from_secs(1));
        }
    })();
    if let Err(error) = &result {
        publish(
            &plan,
            "failed",
            None,
            None,
            &error.to_string().chars().take(512).collect::<String>(),
        )?;
    }
    result
}

#[cfg(test)]
mod tests;
