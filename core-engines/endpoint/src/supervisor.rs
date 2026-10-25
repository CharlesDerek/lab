//! A stable executable supervises management/protection and owns update recovery.
use crate::{
    now_ms, private_write, secret, update, Client, Config, Process as Command, Result, StateLock,
    Store,
};
use athernex_endpoint_protocol::{
    self as protocol,
    update::{Deployment, InstallationReceipt, SignedRelease},
};
use serde::{Deserialize, Serialize};
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
use std::process::Child;
#[cfg(not(windows))]
use std::process::Stdio;
use std::{
    fs::{self, OpenOptions},
    path::Path,
    thread,
    time::{Duration, Instant},
};

const UPDATE_EXIT: i32 = 75;
const ENV_TOKEN: &str = "ATHERNEX_SUPERVISION";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    token: String,
    controller_pid: u32,
    child_pid: Option<u32>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    token: String,
    pid: u32,
    sha256: String,
    version: String,
    time_ms: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Maintenance {
    deployment: Deployment,
    phase: String,
    receipt: Option<InstallationReceipt>,
    acknowledged: bool,
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match update::read_bounded(path, 16384) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
fn load_config(state: &Path) -> Result<Config> {
    let config: Config =
        serde_json::from_slice(&update::read_bounded(&state.join("config.json"), 65536)?)?;
    config.validate()?;
    Ok(config)
}
fn record(state: &Path) -> Result<Option<Maintenance>> {
    read(&state.join("updates/maintenance.json"))
}
fn save(state: &Path, record: &Maintenance) -> Result<()> {
    private_write(
        &state.join("updates/maintenance.json"),
        &serde_json::to_vec(record)?,
    )
}
fn lease(state: &Path, token: &str, pid: Option<u32>) -> Result<()> {
    private_write(
        &state.join("supervisor/lease.json"),
        &serde_json::to_vec(&Lease {
            token: token.into(),
            controller_pid: std::process::id(),
            child_pid: pid,
        })?,
    )
}
pub(crate) fn controller_active(state: &Path, token: &str) -> bool {
    let result = (|| -> Result<bool> {
        let Some(lease) = read::<Lease>(&state.join("supervisor/lease.json"))? else {
            return Ok(false);
        };
        if lease.token != token || !protocol::hex_id(token) {
            return Ok(false);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(state.join("supervisor/controller.lock"))?;
        match file.try_lock() {
            Ok(()) => {
                file.unlock()?;
                Ok(false)
            }
            Err(std::fs::TryLockError::WouldBlock) => Ok(true),
            Err(e) => Err(e.into()),
        }
    })();
    result.unwrap_or(false)
}
pub(crate) fn controller_owned(state: &Path, token: &str) -> bool {
    read::<Lease>(&state.join("supervisor/lease.json"))
        .ok()
        .flatten()
        .is_some_and(|lease| lease.controller_pid == std::process::id())
        && controller_active(state, token)
}
pub(crate) fn controller_is(state: &Path, pid: u32) -> Result<bool> {
    Ok(read::<Lease>(&state.join("supervisor/lease.json"))?
        .is_some_and(|l| l.controller_pid == pid && controller_active(state, &l.token)))
}
pub(crate) fn controller_ready(
    state: &Path,
    pid: u32,
    agent_hash: &str,
    started_ms: u64,
) -> Result<bool> {
    let Some(lease) = read::<Lease>(&state.join("supervisor/lease.json"))? else {
        return Ok(false);
    };
    let Some(ready) = read::<Ready>(&state.join("supervisor/ready.json"))? else {
        return Ok(false);
    };
    let config = load_config(state)?;
    let health = crate::protection::health(&config, state);
    Ok(lease.controller_pid == pid
        && controller_active(state, &lease.token)
        && lease.child_pid == Some(ready.pid)
        && ready.token == lease.token
        && ready.sha256 == agent_hash
        && ready.time_ms >= started_ms
        && ready.time_ms <= now_ms().saturating_add(60_000)
        && now_ms().saturating_sub(ready.time_ms) <= 90_000
        && (!config.protection.enabled
            || (health.state == "active" && health.checked_ms >= started_ms)))
}
pub fn child_context(state: &Path) -> Option<String> {
    let token = std::env::var(ENV_TOKEN).ok()?;
    let lease = read::<Lease>(&state.join("supervisor/lease.json")).ok()??;
    if lease.child_pid != Some(std::process::id())
        || lease.token != token
        || !controller_active(state, &token)
    {
        return None;
    }
    #[cfg(unix)]
    if lease.controller_pid != unsafe { libc::getppid() } as u32 {
        return None;
    }
    Some(token)
}
pub fn enter(state: &Path) -> Result<Option<String>> {
    if std::env::var_os(ENV_TOKEN).is_none() {
        return Ok(None);
    }
    let start = Instant::now();
    let token = loop {
        if let Some(token) = child_context(state) {
            break token;
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err("Supervision lease was not established".into());
        }
        thread::sleep(Duration::from_millis(25));
    };
    let directory = state.to_path_buf();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(500));
        if child_context(&directory).is_none() {
            std::process::exit(86);
        }
    });
    Ok(Some(token))
}
pub fn notify_ready(state: &Path, token: &str) -> Result<()> {
    if child_context(state).as_deref() != Some(token) {
        return Err("Controller lease changed".into());
    }
    private_write(
        &state.join("supervisor/ready.json"),
        &serde_json::to_vec(&Ready {
            token: token.into(),
            pid: std::process::id(),
            sha256: crate::file_hash(&std::env::current_exe()?)?,
            version: env!("CARGO_PKG_VERSION").into(),
            time_ms: now_ms(),
        })?,
    )
}
pub(crate) fn runtime_ready(state: &Path, token: &str, release: &SignedRelease) -> Result<bool> {
    let Some(ready) = read::<Ready>(&state.join("supervisor/ready.json"))? else {
        return Ok(false);
    };
    let Some(lease) = read::<Lease>(&state.join("supervisor/lease.json"))? else {
        return Ok(false);
    };
    let config = load_config(state)?;
    Ok(ready.token == token
        && lease.token == token
        && lease.child_pid == Some(ready.pid)
        && ready.sha256 == release.release.sha256
        && ready.version == release.release.version
        && now_ms().saturating_sub(ready.time_ms) <= 90_000
        && ready.time_ms <= now_ms().saturating_add(60_000)
        && (!config.protection.enabled
            || crate::protection::health(&config, state).state == "active"))
}
pub fn in_trial(state: &Path) -> Result<bool> {
    Ok(controller_trial(state)?
        || update::status(state)?
            .transaction
            .is_some_and(|t| t.trial.is_some()))
}
fn controller_trial(state: &Path) -> Result<bool> {
    Ok(
        update::status_component(state, update::Component::Controller)?
            .transaction
            .is_some_and(|t| t.trial.is_some()),
    )
}
pub fn requested(state: &Path) -> Result<bool> {
    Ok(record(state)?.is_some_and(|r| r.phase == "requested"))
}
pub fn update_exit_code() -> i32 {
    UPDATE_EXIT
}

fn finish(state: &Path, record: &mut Maintenance, outcome: &str, detail: &str) -> Result<()> {
    record.phase = outcome.into();
    record.receipt = Some(InstallationReceipt {
        deployment_id: record.deployment.id.clone(),
        release_id: record.deployment.release_id.clone(),
        outcome: outcome.into(),
        detail: detail.chars().take(128).collect(),
        finished_ms: now_ms(),
    });
    record.acknowledged = false;
    save(state, record)
}
impl Client {
    pub(crate) fn installation_receipts(&self, state: &Path) -> Result<()> {
        if let Some(mut record) = record(state)? {
            if let Some(receipt) = &record.receipt {
                if !record.acknowledged {
                    if self.post("updates/install-receipt", receipt)?["committed"] != true {
                        return Err("Server did not commit the installation receipt".into());
                    }
                    record.acknowledged = true;
                    save(state, &record)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn prepare_installation(&self, state: &Path, deployment: &Deployment) -> Result<()> {
        if deployment.component != athernex_endpoint_protocol::update::Component::Agent {
            return Err("Agent maintenance cannot accept a controller deployment".into());
        }
        if !deployment.install {
            return Ok(());
        }
        if let Some(record) = record(state)? {
            if record.deployment.id == deployment.id {
                return Ok(());
            }
            if record.receipt.is_none() || !record.acknowledged {
                return Err("Previous maintenance result is still pending".into());
            }
        }
        let mut record = Maintenance {
            deployment: deployment.clone(),
            phase: "requested".into(),
            receipt: None,
            acknowledged: false,
        };
        let authorized = (|| -> Result<()> {
            if !self.config.updates.automatic || child_context(state).is_none() {
                return Err(
                    "Automatic installation is not enabled under a live local controller".into(),
                );
            }
            self.authorize_installation(deployment)
        })();
        if let Err(error) = authorized {
            finish(state, &mut record, "refused", &error.to_string())
        } else {
            save(state, &record)
        }
    }
    pub(crate) fn authorize_installation(&self, deployment: &Deployment) -> Result<()> {
        deployment.validate(&self.config.endpoint_id, now_ms())?;
        let approved: Deployment = serde_json::from_value(self.post(
            &format!("updates/{}/install", deployment.id),
            &serde_json::json!({}),
        )?)?;
        if &approved != deployment {
            return Err("Installation authorization changed".into());
        }
        Ok(())
    }
}

struct ManagedChild {
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    child: Child,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    child: athernex_endpoint_native::child::Service,
    #[cfg(windows)]
    child: crate::windows_job::Child,
}
impl ManagedChild {
    fn start(binary: &Path, state: &Path, mode: &str, token: Option<&str>) -> Result<Self> {
        let mut command = Command::new(binary);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        command
            .arg("controller-owned")
            .arg(std::process::id().to_string());
        command.arg(mode).arg(state).env_remove(ENV_TOKEN);
        #[cfg(not(windows))]
        command
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if let Some(token) = token {
            command.env(ENV_TOKEN, token);
        }
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
            #[cfg(target_os = "linux")]
            unsafe {
                let parent = std::process::id();
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent as i32 {
                        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                    }
                    Ok(())
                });
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let mut child = command.spawn()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let mut child = athernex_endpoint_native::child::Service::start(&mut command, 8192)?;
        if let Some(token) = token {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let pid = child.pid().ok_or("Management cleanup is pending")?;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let pid = child.id();
            if let Err(e) = lease(state, token, Some(pid)) {
                #[cfg(any(target_os = "linux", target_os = "macos", windows))]
                let _ = child.stop();
                #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
                crate::kill_tree(&mut child);
                return Err(e);
            }
        }
        Ok(Self { child })
    }
    fn exited(&mut self) -> Result<Option<i32>> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let status = self.child.poll()?;
            if status.is_some() && !self.child.output().is_empty() {
                eprintln!(
                    "Endpoint child output: {}",
                    String::from_utf8_lossy(self.child.output())
                );
            }
            Ok(status)
        }
        #[cfg(windows)]
        {
            Ok(self.child.poll()?)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        Ok(self.child.try_wait()?.map(|s| s.code().unwrap_or(-1)))
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        if let Err(error) = self.child.stop() {
            eprintln!("Endpoint child cleanup: {error}");
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        crate::kill_tree(&mut self.child);
    }
}
struct Children {
    agent: ManagedChild,
    protection: Option<ManagedChild>,
}
fn start_children(binary: &Path, state: &Path, config: &Config, token: &str) -> Result<Children> {
    lease(state, token, None)?;
    let protection = if config.protection.enabled {
        Some(ManagedChild::start(binary, state, "protect", None)?)
    } else {
        None
    };
    let agent = ManagedChild::start(binary, state, "run", Some(token))?;
    Ok(Children { agent, protection })
}
fn quiet(state: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        #[cfg(windows)]
        let cleanup_ready = crate::windows_job::cleanup_ready().is_ok();
        #[cfg(not(windows))]
        let cleanup_ready = true;
        if cleanup_ready && Store::open(state).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("Another management process remains active; replacement refused".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}
fn reconcile(state: &Path) -> Result<()> {
    let mut status = update::status(state)?;
    let interrupted = status.transaction.is_some();
    if interrupted {
        status = update::recover(state)?;
    }
    if let Some(mut record) = record(state)? {
        if record.receipt.is_none() && record.phase != "requested" {
            if status
                .installed
                .as_ref()
                .is_some_and(|r| r.id().ok().as_deref() == Some(&record.deployment.release_id))
                && status.transaction.is_none()
            {
                finish(
                    state,
                    &mut record,
                    "installed",
                    "Confirmed replacement recovered after controller interruption",
                )?;
            } else if interrupted || status.last_result == "rolled_back" {
                finish(
                    state,
                    &mut record,
                    "rolled_back",
                    "Unconfirmed replacement recovered after controller interruption",
                )?;
            } else {
                finish(
                    state,
                    &mut record,
                    "refused",
                    "Maintenance interrupted before a confirmed replacement",
                )?;
            }
        }
    }
    Ok(())
}
fn maintain(binary: &Path, state: &Path, config: &Config) -> Result<Option<Children>> {
    let Some(mut record) = record(state)? else {
        return Ok(None);
    };
    if record.phase != "requested" {
        return Ok(None);
    }
    let client = Client::new(config.clone())?;
    let admitted = (|| -> Result<()> {
        if !config.updates.automatic || config.updates.install_path.as_deref() != Some(binary) {
            return Err("Local automatic-installation policy changed".into());
        }
        client.authorize_installation(&record.deployment)?;
        if update::status(state)?.staged.as_ref() != Some(&record.deployment.release) {
            return Err("Staged release differs from approved installation".into());
        }
        Ok(())
    })();
    if let Err(error) = admitted {
        finish(state, &mut record, "refused", &error.to_string())?;
        return Ok(None);
    }
    record.phase = "applying".into();
    save(state, &record)?;
    let token = secret()?;
    lease(state, &token, None)?;
    let mut candidate = None;
    let result = (|| -> Result<()> {
        update::begin_trial(state, &token)?;
        record.phase = "verifying".into();
        save(state, &record)?;
        candidate = Some(start_children(binary, state, config, &token)?);
        let started = Instant::now();
        loop {
            let children = candidate.as_mut().unwrap();
            if children.agent.exited()?.is_some()
                || children
                    .protection
                    .as_mut()
                    .map(|p| p.exited())
                    .transpose()?
                    .flatten()
                    .is_some()
            {
                return Err(
                    "Replacement management/protection process exited before confirmation".into(),
                );
            }
            if started.elapsed() >= Duration::from_secs(2)
                && runtime_ready(state, &token, &record.deployment.release)?
            {
                update::confirm_trial(state, &token)?;
                return Ok(());
            }
            if started.elapsed() >= Duration::from_secs(350) {
                return Err(
                    "Replacement did not become healthy within its verification window".into(),
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    })();
    if let Err(error) = result {
        let status = update::status(state)?;
        if status.transaction.is_none()
            && status.installed.as_ref() == Some(&record.deployment.release)
        {
            finish(
                state,
                &mut record,
                "installed",
                &format!("Runtime confirmed; cleanup requires review: {error}"),
            )?;
            return Ok(candidate);
        }
        drop(candidate.take());
        quiet(state)?;
        if status.transaction.is_some() {
            update::recover(state)?;
        }
        let outcome = if update::status(state)?.last_result == "rolled_back" {
            "rolled_back"
        } else {
            "refused"
        };
        finish(state, &mut record, outcome, &error.to_string())?;
        return Ok(None);
    }
    finish(
        state,
        &mut record,
        "installed",
        "Replacement completed a server cycle and configured protection health checks",
    )?;
    Ok(candidate)
}

pub fn supervise(state: &Path, binary: &Path) -> Result<()> {
    let state = state.canonicalize()?;
    crate::guardian::enter(&state)?;
    // Windows canonicalize adds an extended-path prefix. Retain the absolute
    // spelling used by the configured update policy and its transaction ledger.
    #[cfg(windows)]
    let binary = std::path::absolute(binary)?;
    #[cfg(not(windows))]
    let binary = binary.canonicalize()?;
    update::check_destination(&binary)?;
    if std::env::current_exe()?.canonicalize()? == binary.canonicalize()? {
        return Err("Controller must be a separate trusted executable copy".into());
    }
    let directory = state.join("supervisor");
    fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("controller.lock"))?;
    lock.try_lock()
        .map_err(|_| "Another endpoint controller is running")?;
    let _lock = StateLock(lock);
    update::controller_startup(&state)?;
    let mut engine_token = secret()?;
    lease(&state, &engine_token, None)?;
    quiet(&state)?;
    crate::engine_update::automatic::reconcile(&state, &engine_token)?;
    reconcile(&state)?;
    let mut config = load_config(&state)?;
    if config.updates.enabled() && config.updates.install_path.as_deref() != Some(&binary) {
        return Err("Controller binary path does not match local update policy".into());
    }
    let mut children = if controller_trial(&state)? {
        None
    } else {
        maintain(&binary, &state, &config)?
    };
    loop {
        // Engine requests are explicit and local. Management does not need a
        // working server connection to complete an already authorized request.
        if !controller_trial(&state)? && crate::engine_update::automatic::queued(&state)? {
            // Renew our lease only after stopping children: changing its token
            // while management lives would make its ownership watcher exit.
            if crate::engine_update::automatic::eligible(&state)? {
                drop(children.take());
                quiet(&state)?;
                engine_token = secret()?;
                lease(&state, &engine_token, None)?;
                crate::engine_update::automatic::maintain(&state, &engine_token)?;
            }
        }
        if children.is_none() {
            config = load_config(&state)?;
            children = Some(start_children(&binary, &state, &config, &secret()?)?);
        }
        let running = children.as_mut().unwrap();
        if let Some(protection) = &mut running.protection {
            if protection.exited()?.is_some() {
                running.protection = None;
                thread::sleep(Duration::from_secs(5));
                running.protection = Some(ManagedChild::start(&binary, &state, "protect", None)?);
            }
        }
        if let Some(code) = running.agent.exited()? {
            if code == UPDATE_EXIT && requested(&state)? && !controller_trial(&state)? {
                drop(children.take());
                quiet(&state)?;
                config = load_config(&state)?;
                children = maintain(&binary, &state, &config)?;
            } else {
                // Keep prevention running while only management restarts.
                thread::sleep(Duration::from_secs(5));
                let token = secret()?;
                lease(&state, &token, None)?;
                running.agent = ManagedChild::start(&binary, &state, "run", Some(&token))?;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}
