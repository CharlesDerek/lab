//! Development Windows protection supervisor. Production activation stays gated
//! until native blocking, scanner isolation and installation are verified.
mod maintenance;
mod recovery;
pub(crate) mod response;
mod scratch;
mod workspaces;
use super::windows_evidence::{self as evidence, Queue, Receipt, Root, Scope};
use crate::{
    now_ms, secret,
    windows_job::{self, Service},
    Process, Result, Store,
};
use athernex_endpoint_native::{
    windows_filter::{
        client::{self, Counters, Scanner, Snapshot},
        engine,
        peer::{self, EngineConnection},
    },
    windows_network::{Engine as NetworkEngine, Policy as NetworkPolicy},
    windows_scanner::Token,
    windows_state::{Directory, PinnedDirectory, ScannerDirectory},
};
pub use maintenance::recover;
pub(crate) use maintenance::{quiescent, Quiescent};
pub use scratch::Health as ScratchHealth;
pub use scratch::{cleanup_worker as scratch_cleanup_worker, worker_main as scratch_worker};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};
pub use workspaces::worker_main as workspace_cleanup_worker;
fn default_scratch_mib() -> u32 {
    2048
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub roots: Vec<PathBuf>,
    /// Existing endpoint state; the private service spool lives below protection/windows.
    pub state: PathBuf,
    pub daemon: PathBuf,
    pub daemon_sha256: String,
    pub database: PathBuf,
    pub port: u16,
    pub timeout_ms: u32,
    pub startup_secs: u64,
    /// Required reduced identity; native isolation validation remains a release gate.
    pub scanner_isolation: String,
    #[serde(default = "default_scratch_mib")]
    pub scratch_mib: u32,
}
impl Plan {
    fn validate(&self) -> Result<()> {
        if self.schema != 1
            || !(1..=16).contains(&self.roots.len())
            || self.port == 0
            || !(100..=5000).contains(&self.timeout_ms)
            || !(5..=120).contains(&self.startup_secs)
            || !athernex_endpoint_protocol::hex_id(&self.daemon_sha256)
            || self.scanner_isolation != "restricted-local-service"
            || !(256..=4096).contains(&self.scratch_mib)
            || self
                .roots
                .iter()
                .chain([&self.state, &self.daemon, &self.database])
                .any(|p| p.to_str().is_none_or(|p| !evidence::drive_path(p)))
        {
            return Err("Invalid development Windows protection plan".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    schema: u32,
    session: String,
    state: PathBuf,
    scope: Scope,
    port: u16,
    scanner_pid: u32,
    scanner_created: u64,
    scanner_logon: String,
    network: NetworkPolicy,
    scratch_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub schema: u32,
    pub session: String,
    pub checked_ms: u64,
    pub worker_pid: u32,
    pub worker_created: u64,
    pub scanner_pid: u32,
    pub scanner_created: u64,
    pub policy_sha256: String,
    pub kernel: Option<Snapshot>,
    pub pending_events: u64,
    pub lost_events: u64,
    pub coverage: evidence::Coverage,
    pub coverage_incomplete: bool,
    pub scan_errors: u64,
    pub reply_errors: u64,
    pub live_blocking_verified: bool,
    pub scanner_isolated: bool,
    pub scanner_identity_verified: bool,
    pub scanner_logon: String,
    pub network_policy: String,
    pub network_checked_ms: u64,
    pub scratch: ScratchHealth,
    pub error: String,
}
fn leaf(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "Invalid Windows service filename".into())
}
fn checked_plan(path: &Path) -> Result<Plan> {
    let parent = Directory::open(path.parent().ok_or("Plan has no parent")?)?;
    let plan: Plan = parent.read_json(leaf(path)?)?;
    plan.validate()?;
    Ok(plan)
}
fn hash(file: &mut File) -> Result<String> {
    if file.metadata()?.len() > 128 * 1024 * 1024 {
        return Err("Scanner executable exceeds its byte budget".into());
    }
    let mut hash = Sha256::new();
    let mut read = 0u64;
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > 128 * 1024 * 1024 {
            return Err("Scanner executable grew beyond its byte budget".into());
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn overlaps(a: &str, b: &str) -> bool {
    evidence::suffix(a, b).is_some() || evidence::suffix(b, a).is_some()
}
pub(crate) fn system_root() -> Result<String> {
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    let mut buffer = [0; 1024];
    let len = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 || len as usize >= buffer.len() {
        return Err("Windows system directory is unavailable".into());
    }
    let path = String::from_utf16(&buffer[..len as usize])?;
    if !evidence::drive_path(&path) {
        return Err("Invalid Windows system directory".into());
    }
    Ok(path)
}
fn command(executable: &Path, temporary: &Path) -> Result<Process> {
    let mut command = Process::new(executable);
    let parent = executable.parent().ok_or("Executable has no parent")?;
    command
        .env_clear()
        .env("SystemRoot", system_root()?)
        .env("PATH", parent)
        .env("TEMP", temporary)
        .env("TMP", temporary)
        .current_dir(parent);
    Ok(command)
}
fn check_running(service: &mut Service, role: &str) -> Result<()> {
    if let Some(code) = service.poll()? {
        return Err(format!(
            "Windows {role} exited ({code}): {}",
            String::from_utf8_lossy(service.output())
                .chars()
                .take(1024)
                .collect::<String>()
        )
        .into());
    }
    Ok(())
}

fn stage_files(
    source: &Directory,
    target: &ScannerDirectory,
    executable: Option<&str>,
    budget: &mut u64,
) -> Result<()> {
    let mut count = 0;
    for entry in std::fs::read_dir(source.path())? {
        count += 1;
        if count > 256 {
            return Err("Scanner staging directory exceeds its file budget".into());
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Scanner staging requires Unicode filenames")?;
        if let Some(executable) = executable {
            if !name.eq_ignore_ascii_case(executable)
                && !name.to_ascii_lowercase().ends_with(".dll")
            {
                continue;
            }
        }
        // Handle-relative, no-reparse private reads. Nested database directories
        // are refused; there is no recursive copy through an untrusted alias.
        let mut file = source.read(&name)?;
        target.copy(&name, &mut file, budget)?;
    }
    if count == 0 {
        return Err("Scanner staging source is empty".into());
    }
    Ok(())
}

pub fn supervise_preview(path: &Path) -> Result<()> {
    athernex_endpoint_native::windows_state::require_local_system()?;
    let plan = checked_plan(path)?;
    let _admission = crate::windows_driver::Admission::acquire(&plan.state)?;
    crate::windows_driver::require_live(&plan.state)?;
    let endpoint = Directory::open(&plan.state)?;
    let protection = endpoint.directory("protection")?;
    let _protection_lease = protection.lock("supervisor.lock")?;
    let state = protection.directory("windows")?;
    let _lease = state.lock("supervisor.lock")?;
    // Maintenance holds the same leases even with protection disabled. Read
    // configuration and settled transactions only after excluding replacement.
    let endpoint_config: crate::Config = endpoint.read_json("config.json")?;
    endpoint_config.validate()?;
    crate::update::require_component_transactions_settled(&plan.state)?;
    crate::engine_update::require_settled(&plan.state)?;
    crate::update::require_recovered(&plan.state)?;
    maintenance::recover_retired(&state)?;
    let journal = state.directory("network")?;
    let runtime = state.directory("runtime")?;
    let database = Directory::open(&plan.database)?;
    let daemon_directory = Directory::open(plan.daemon.parent().ok_or("Scanner has no parent")?)?;
    let mut daemon_image = daemon_directory.read(leaf(&plan.daemon)?)?;
    if hash(&mut daemon_image)? != plan.daemon_sha256 {
        return Err("Scanner executable differs from its locally pinned digest".into());
    }
    let executable = std::env::current_exe()?;
    let agent_directory = Directory::open(executable.parent().ok_or("Agent has no parent")?)?;
    let _agent_image = agent_directory.read(leaf(&executable)?)?;
    // Pin every protected directory and derive both names from the same handle.
    let pins = plan
        .roots
        .iter()
        .map(|r| PinnedDirectory::open(r))
        .collect::<Result<Vec<_>>>()?;
    let scope = Scope {
        roots: pins
            .iter()
            .map(|p| {
                Ok(Root {
                    nt: p.nt()?,
                    dos: p.dos()?,
                })
            })
            .collect::<Result<_>>()?,
        timeout_ms: plan.timeout_ms,
    };
    scope.config()?;
    let excluded = [
        endpoint.nt()?,
        database.nt()?,
        daemon_directory.nt()?,
        agent_directory.nt()?,
    ];
    if scope
        .roots
        .iter()
        .any(|root| excluded.iter().any(|path| overlaps(&root.nt, path)))
    {
        return Err(
            "Windows protection scope overlaps its scanner, agent, signatures or private state"
                .into(),
        );
    }
    let queue = Queue::open(&state.database_path("evidence.sqlite3")?)?;
    queue.register(&scope)?;
    // The identity record precedes every staged file and scanner launch.
    // Failure before this commit can leave only an empty workspace orphan.
    let token = Token::new()?;
    let workspace_id = secret()?;
    let workspace = runtime.scanner_workspace(&format!("scanner-{workspace_id}"), &token)?;
    workspaces::record(&state, &workspace_id, workspace.identity()?)?;
    let engine_files = workspace.directory("engine", false)?;
    let signatures = workspace.directory("signatures", false)?;
    let mut temporary = scratch::Scratch::start(
        &state,
        &workspace_id,
        u64::from(plan.scratch_mib) * 1024 * 1024,
        &token,
    )?;
    let mut budget = 768 * 1024 * 1024;
    stage_files(
        &daemon_directory,
        &engine_files,
        Some(leaf(&plan.daemon)?),
        &mut budget,
    )?;
    stage_files(&database, &signatures, None, &mut budget)?;
    let mut staged_image = engine_files.pin(leaf(&plan.daemon)?)?;
    if hash(&mut staged_image)? != plan.daemon_sha256 {
        return Err("Staged scanner differs from its locally pinned digest".into());
    }
    // No unbounded logfile. stdout/stderr are drained into a fixed memory budget.
    let config = format!("Foreground yes\nDatabaseDirectory \"{}\"\nTemporaryDirectory \"{}\"\nTCPAddr 127.0.0.1\nTCPSocket {}\nMaxThreads 4\nMaxQueue 8\nStreamMaxLength 128M\nMaxFileSize 128M\nMaxScanSize 256M\nAlertExceedsMax yes\nReadTimeout 5\nCommandReadTimeout 5\n", signatures.path().display(), temporary.path().display(), plan.port);
    workspace.write("clamd.conf", config.as_bytes())?;
    let network = NetworkPolicy::new(&staged_image, plan.port)?;
    // Launch using the same canonical name used to derive the WFP application
    // ID, rather than an installer-supplied drive/short-name alias.
    let mut invocation = command(Path::new(&network.application), temporary.path())?;
    invocation
        .arg("--config-file")
        .arg(workspace.path().join("clamd.conf"));
    let network_record = format!("{}.json", network.id);
    let mut launch = recovery::Record::prepared(network.clone())?;
    launch.save(&journal)?;
    let network_engine = NetworkEngine::open()?;
    network_engine.install(&network)?;
    temporary.check()?;
    // A launch/verification failure retains the committed policy and journal.
    // Persistent rules also survive abrupt supervisor death independently of
    // job-handle closure; no destructor can create a temporary network escape.
    let mut daemon = Service::start_scanner(&invocation, &token, 8192, |pid, created| {
        launch
            .own(&journal, pid, created, token.logon_sid())
            .map_err(std::io::Error::other)
    })?;
    let result = (|| -> Result<()> {
        daemon.verify_scanner(token.logon_sid())?;
        let scanner_pid = daemon.id();
        let scanner_created = daemon.creation_time()?;
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, plan.port);
        let startup = Instant::now() + Duration::from_secs(plan.startup_secs);
        loop {
            temporary.check()?;
            check_running(&mut daemon, "scanner")?;
            let ready = (|| -> Result<()> {
                let deadline = Instant::now() + Duration::from_secs(1);
                let mut connection =
                    EngineConnection::connect(address, scanner_pid, scanner_created, deadline)?;
                let verdict = engine::scan(&mut connection.stream, 0, deadline, |_, _| Ok(()))?;
                connection.alive()?;
                if verdict.detection.is_some() {
                    return Err("Scanner refused the empty readiness stream".into());
                }
                Ok(())
            })();
            if ready.is_ok() {
                break;
            }
            if Instant::now() >= startup {
                return Err(
                    "Owned Windows scanner did not become ready before its deadline".into(),
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
        let request = WorkerRequest {
            schema: 1,
            session: secret()?,
            state: state.path().into(),
            scope,
            port: plan.port,
            scanner_pid,
            scanner_created,
            scanner_logon: token.logon_sid().into(),
            network: network.clone(),
            scratch_id: workspace_id.clone(),
        };
        let worker_temporary = state.directory("worker-temporary")?;
        let mut invocation = command(&executable, worker_temporary.path())?;
        invocation
            .arg("windows-filter-worker")
            .arg(std::process::id().to_string());
        let mut worker = Service::start(&invocation, Some(&serde_json::to_vec(&request)?), 8192)?;
        let worker_created = worker.creation_time()?;
        let started = Instant::now();
        loop {
            temporary.check()?;
            check_running(&mut daemon, "scanner")?;
            daemon.verify_scanner(token.logon_sid())?;
            check_running(&mut worker, "filter worker")?;
            match state.read_json::<Status>("client-health.json") {
                Ok(status)
                    if status.session == request.session && status.worker_pid == worker.id() =>
                {
                    status.coverage.validate()?;
                    if status.schema != 2
                        || status.coverage_incomplete != status.coverage.incomplete()
                        || status.coverage.session != request.session
                        || status.coverage.policy != request.scope.digest()?
                        || status.worker_created != worker_created
                        || status.scanner_pid != scanner_pid
                        || status.scanner_created != scanner_created
                        || !status.scanner_identity_verified
                        || status.scanner_logon != request.scanner_logon
                        || status.scratch.id != request.scratch_id
                        || status.network_policy != request.network.id
                        || status.network_checked_ms > now_ms().saturating_add(1000)
                        || now_ms().saturating_sub(status.network_checked_ms) > 5000
                        || status.policy_sha256 != request.scope.digest()?
                        || status.checked_ms > now_ms().saturating_add(1000)
                        || now_ms().saturating_sub(status.checked_ms) > 15_000
                    {
                        return Err("Windows filter worker health is stale or belongs to another process/policy".into());
                    }
                    if !status.error.is_empty() {
                        return Err(
                            format!("Windows filter worker failed: {}", status.error).into()
                        );
                    }
                }
                _ if started.elapsed() < Duration::from_secs(15) => (),
                _ => return Err("Windows filter worker did not publish current health".into()),
            }
            thread::sleep(Duration::from_millis(250));
        }
    })();
    // The worker is already dropped here. Never remove network rules while
    // scanner cleanup is pending in the independent process-tree reaper.
    if let Err(cleanup) = daemon.stop() {
        return Err(format!("Scanner cleanup is pending; network policy retained: {cleanup}; service result: {result:?}").into());
    }
    if let Err(cleanup) = temporary.stop() {
        return Err(format!("Scratch cleanup is pending; network policy retained: {cleanup}; service result: {result:?}").into());
    }
    if let Err(cleanup) = network_engine.remove_after_job_exit(&network) {
        return Err(format!("Scanner stopped, but network policy cleanup failed: {cleanup}; service result: {result:?}").into());
    }
    journal.remove(&network_record)?;
    journal.sync()?;
    drop(staged_image);
    drop(temporary);
    drop(signatures);
    drop(engine_files);
    drop(workspace);
    scratch::reclaim(&state)?;
    workspaces::reclaim(&state)?;
    result
}

pub fn worker_main(parent: u32) -> Result<()> {
    windows_job::guard_parent(parent)?;
    athernex_endpoint_native::windows_state::require_local_system()?;
    let worker_created = peer::identify(std::process::id())?;
    let mut bytes = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("Windows filter worker request exceeds its budget".into());
    }
    let request: WorkerRequest = serde_json::from_slice(&bytes)?;
    if request.schema != 1
        || !athernex_endpoint_protocol::hex_id(&request.session)
        || request.port == 0
        || request.scanner_pid == 0
        || request.scanner_created == 0
        || request.scanner_logon.len() > 256
        || !athernex_endpoint_protocol::hex_id(&request.scratch_id)
    {
        return Err("Invalid Windows filter worker request".into());
    }
    athernex_endpoint_native::windows_scanner::verify_process(
        request.scanner_pid,
        request.scanner_created,
        &request.scanner_logon,
    )?;
    // The private worker namespace is fixed by supervise_preview. Retain a
    // separate shared holder so parent death cannot release machine admission
    // before this process closes its driver connection.
    if request.state.file_name().and_then(|v| v.to_str()) != Some("windows")
        || request
            .state
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|v| v.to_str())
            != Some("protection")
    {
        return Err("Windows filter worker state is outside its fixed namespace".into());
    }
    let endpoint = request
        .state
        .parent()
        .and_then(|p| p.parent())
        .ok_or("Windows worker endpoint state missing")?;
    let _admission = crate::windows_driver::Admission::acquire(endpoint)?;
    request.network.validate()?;
    if request.network.port != request.port {
        return Err("Windows scanner network policy uses a different port".into());
    }
    let network = NetworkEngine::open()?;
    network.verify(&request.network)?;
    let config = request.scope.config()?;
    let state = Directory::open(&request.state)?;
    let _lock = state.lock("client.lock")?;
    let queue = Queue::open(&state.database_path("evidence.sqlite3")?)?;
    queue.register(&request.scope)?;
    queue.begin_session(&request.session, &request.scope.digest()?)?;
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Counters::default());
    let (events, received) = mpsc::sync_channel(64);
    let scanner = Scanner {
        address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, request.port),
        pid: request.scanner_pid,
        created: request.scanner_created,
    };
    thread::scope(|scope| -> Result<()> {
        let (worker_stop, worker_counters) = (stop.clone(), counters.clone());
        let worker =
            scope.spawn(move || client::run(config, scanner, events, worker_stop, worker_counters));
        let mut observed_drops = 0;
        let mut network_checked_ms = now_ms();
        let mut network_checked = Instant::now();
        let started = Instant::now();
        let result = (|| -> Result<()> {
            loop {
                if network_checked.elapsed() >= Duration::from_secs(1) {
                    network.verify(&request.network)?;
                    network_checked_ms = now_ms();
                    network_checked = Instant::now();
                }
                for observation in received.try_iter().take(64) {
                    if observation.outcome != "allowed" {
                        if let Err(error) = queue.record(&Receipt {
                            session: request.session.clone(),
                            observation,
                        }) {
                            queue.lost(1)?;
                            return Err(error);
                        }
                    }
                }
                let dropped = counters.dropped.load(Ordering::Relaxed);
                if dropped != observed_drops {
                    queue.lost(dropped.saturating_sub(observed_drops))?;
                }
                observed_drops = dropped;
                let kernel = counters
                    .kernel
                    .lock()
                    .map_err(|_| "Windows filter snapshot lock poisoned")?
                    .clone();
                let coverage = match &kernel {
                    Some(snapshot) => queue.observe_kernel(
                        &request.session,
                        snapshot.checked_ms,
                        &snapshot.status,
                    )?,
                    None => queue
                        .coverage()?
                        .ok_or("Windows evidence coverage is unavailable")?,
                };
                if coverage.state == "failed" {
                    return Err(coverage.reason.into());
                }
                let (pending_events, lost_events) = queue.counts()?;
                let status = Status {
                    schema: 2,
                    session: request.session.clone(),
                    checked_ms: now_ms(),
                    worker_pid: std::process::id(),
                    worker_created,
                    scanner_pid: request.scanner_pid,
                    scanner_created: request.scanner_created,
                    policy_sha256: request.scope.digest()?,
                    kernel,
                    pending_events,
                    lost_events,
                    coverage_incomplete: coverage.incomplete(),
                    coverage,
                    scan_errors: counters.scan_errors.load(Ordering::Relaxed),
                    reply_errors: counters.reply_errors.load(Ordering::Relaxed),
                    live_blocking_verified: false,
                    scanner_isolated: false,
                    scanner_identity_verified: true,
                    scanner_logon: request.scanner_logon.clone(),
                    network_policy: request.network.id.clone(),
                    network_checked_ms,
                    scratch: scratch::health(&state, &request.scratch_id, &request.scanner_logon)?,
                    error: String::new(),
                };
                if status
                    .kernel
                    .as_ref()
                    .is_none_or(|k| now_ms().saturating_sub(k.checked_ms) > 5000)
                    && started.elapsed() > Duration::from_secs(10)
                {
                    return Err("Windows filter stopped publishing current kernel status".into());
                }
                state.write_json("client-health.json", &status)?;
                if worker.is_finished() {
                    return Err("Windows filter client stopped".into());
                }
                thread::sleep(Duration::from_millis(250));
            }
        })();
        stop.store(true, Ordering::Release);
        // The independent parent job enforces the deadline if native I/O cannot
        // finish cancellation. No thread drops pending I/O storage prematurely.
        let ended = worker
            .join()
            .map_err(|_| "Windows filter client panicked")?;
        // Retain already-applied denials even when stopping after a client or
        // spool failure. A full/broken spool remains a visible loss condition.
        let mut lost = 0;
        for observation in received.try_iter() {
            if observation.outcome != "allowed"
                && queue
                    .record(&Receipt {
                        session: request.session.clone(),
                        observation,
                    })
                    .is_err()
            {
                lost += 1;
            }
        }
        lost += counters
            .dropped
            .load(Ordering::Relaxed)
            .saturating_sub(observed_drops);
        if lost != 0 {
            queue.lost(lost)?;
        }
        let result = ended.and(result);
        queue.end_session(
            &request.session,
            &result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "Windows client stopped; unsampled tail is unknown".into()),
        )?;
        result
    })
}

pub fn status(state: &Path) -> Result<Status> {
    let directory = Directory::open(state)?;
    let mut status: Status = directory.read_json("client-health.json")?;
    let queue = Queue::open(&directory.database_path("evidence.sqlite3")?)?;
    status.coverage = queue
        .coverage()?
        .ok_or("Windows evidence coverage is unavailable")?;
    status.coverage.validate()?;
    status.coverage_incomplete = status.coverage.incomplete();
    if status.coverage.session != status.session || status.coverage.policy != status.policy_sha256 {
        return Err("Windows evidence coverage belongs to another live session or policy".into());
    }
    if status.schema != 2
        || !athernex_endpoint_protocol::hex_id(&status.session)
        || status.checked_ms > now_ms().saturating_add(1000)
        || now_ms().saturating_sub(status.checked_ms) > 5000
        || status.live_blocking_verified
        || status.scanner_isolated
        || !status.scanner_identity_verified
        || status.scanner_logon.len() > 256
        || !athernex_endpoint_protocol::hex_id(&status.network_policy)
        || status.network_checked_ms > now_ms().saturating_add(1000)
        || now_ms().saturating_sub(status.network_checked_ms) > 5000
    {
        return Err("Windows development protection status is invalid or stale".into());
    }
    if peer::identify(status.worker_pid)? != status.worker_created
        || peer::identify(status.scanner_pid)? != status.scanner_created
    {
        return Err("Windows protection process identity changed".into());
    }
    athernex_endpoint_native::windows_scanner::verify_process(
        status.scanner_pid,
        status.scanner_created,
        &status.scanner_logon,
    )?;
    let journal = Directory::open(&state.join("network"))?;
    let record = recovery::read(&journal, &status.network_policy)?;
    if !record.matches_scanner(
        status.scanner_pid,
        status.scanner_created,
        &status.scanner_logon,
    ) {
        return Err("Windows scanner recovery owner differs from live status".into());
    }
    NetworkEngine::open()?.verify(&record.network)?;
    scratch::validate_observation(&directory, &status.scratch, &status.scanner_logon)?;
    Ok(status)
}
pub fn collect(store: &Store) -> Result<()> {
    let path = store.directory.join("protection/windows");
    if !path.try_exists()? {
        return Ok(());
    }
    let directory = Directory::open(&path)?;
    Queue::open(&directory.database_path("evidence.sqlite3")?)?.collect(store)
}
