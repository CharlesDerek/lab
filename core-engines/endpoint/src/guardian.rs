//! Stable service entrypoint. The launcher owns controller lifetime and keeps
//! recovery available when an authorized controller candidate cannot run.
use crate::{
    now_ms, private_write, secret,
    update::{self, Component, Transaction},
    Config, Process, Result, StateLock,
};
use athernex_endpoint_protocol as protocol;
use protocol::update::{Component as WireComponent, Deployment, InstallationReceipt};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const ENV_TOKEN: &str = "ATHERNEX_LAUNCHER";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    token: String,
    launcher_pid: u32,
    controller_pid: Option<u32>,
    controller: PathBuf,
    controller_sha256: String,
    agent: PathBuf,
    agent_sha256: String,
    config_sha256: String,
    started_ms: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Queued,
    Applying,
    Installed,
    RolledBack,
    Refused,
    Cancelled,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub release_id: String,
    pub deadline_ms: u64,
    pub phase: Phase,
    pub detail: String,
    pub updated_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<Deployment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<InstallationReceipt>,
    #[serde(default)]
    pub acknowledged: bool,
}
impl Request {
    fn pending(&self) -> bool {
        matches!(self.phase, Phase::Queued | Phase::Applying)
    }
    fn retained(&self) -> bool {
        self.pending() || (self.receipt.is_some() && !self.acknowledged)
    }
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
fn configuration(state: &Path) -> Result<(Config, String)> {
    let path = state.join("config.json");
    update::check_destination(&path)?;
    let raw = update::read_bounded(&path, 65536)?;
    let config: Config = serde_json::from_slice(&raw)?;
    config.validate()?;
    Ok((config, protocol::hash(&raw)))
}
fn lease(state: &Path) -> Result<Option<Lease>> {
    read(&state.join("supervisor/launcher.json"))
}
fn save_lease(state: &Path, value: &Lease) -> Result<()> {
    private_write(
        &state.join("supervisor/launcher.json"),
        &serde_json::to_vec(value)?,
    )
}
pub fn status(state: &Path) -> Result<Option<Request>> {
    let value: Option<Request> = read(&state.join("updates/controller/maintenance.json"))?;
    if let Some(r) = &value {
        if !protocol::hex_id(&r.release_id)
            || r.deadline_ms == 0
            || r.deadline_ms > i64::MAX as u64
            || r.detail.len() > 2048
        {
            return Err("Invalid controller maintenance request".into());
        }
        if let Some(d) = &r.deployment {
            if d.component != WireComponent::Controller
                || !d.install
                || d.release_id != r.release_id
                || d.release.id()? != r.release_id
                || d.expires_ms != r.deadline_ms
            {
                return Err("Controller request differs from its reviewed deployment".into());
            }
        }
        if let Some(receipt) = &r.receipt {
            receipt.validate()?;
            if r.deployment
                .as_ref()
                .is_none_or(|d| d.id != receipt.deployment_id || d.release_id != receipt.release_id)
                || r.pending()
            {
                return Err("Controller receipt has no matching terminal deployment".into());
            }
        } else if r.acknowledged {
            return Err("Controller receipt acknowledgement has no receipt".into());
        }
    }
    Ok(value)
}
fn save(state: &Path, r: &mut Request) -> Result<()> {
    r.updated_ms = now_ms();
    private_write(
        &state.join("updates/controller/maintenance.json"),
        &serde_json::to_vec(r)?,
    )
}
fn finish(state: &Path, r: &mut Request, phase: Phase, detail: &str) -> Result<()> {
    r.phase = phase;
    r.detail = detail.chars().take(512).collect();
    if let Some(deployment) = &r.deployment {
        let outcome = match phase {
            Phase::Installed => "installed",
            Phase::RolledBack => "rolled_back",
            Phase::Refused | Phase::Cancelled => "refused",
            _ => return Err("Cannot issue a nonterminal controller receipt".into()),
        };
        if r.receipt.is_some() {
            return Err("Controller installation receipts are immutable".into());
        }
        r.receipt = Some(InstallationReceipt {
            deployment_id: deployment.id.clone(),
            release_id: r.release_id.clone(),
            outcome: outcome.into(),
            detail: detail.chars().take(120).collect(),
            finished_ms: now_ms(),
        });
    }
    save(state, r)
}
pub(crate) fn require_idle(state: &Path) -> Result<()> {
    if status(state)?.is_some_and(|r| r.retained()) {
        return Err(
            "Cancel or recover pending controller maintenance and deliver its receipt first".into(),
        );
    }
    Ok(())
}
fn held(state: &Path) -> Result<bool> {
    let path = state.join("supervisor/launcher.lock");
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    match file.try_lock() {
        Ok(()) => {
            file.unlock()?;
            Ok(false)
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(e) => Err(e.into()),
    }
}
pub(crate) fn owned(state: &Path, token: &str) -> bool {
    protocol::hex_id(token)
        && lease(state)
            .ok()
            .flatten()
            .is_some_and(|l| l.token == token && l.launcher_pid == std::process::id())
        && held(state).unwrap_or(false)
}
fn own_lease(state: &Path) -> bool {
    lease(state)
        .ok()
        .flatten()
        .is_some_and(|l| owned(state, &l.token))
}
fn acquire(state: &Path) -> Result<StateLock> {
    let directory = std::path::absolute(state.join("supervisor"))?;
    fs::create_dir_all(&directory)?;
    update::no_links(&directory)?;
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
        .open(directory.join("launcher.lock"))?;
    file.try_lock()
        .map_err(|_| "Stop the endpoint launcher before replacing or recovering its controller")?;
    Ok(StateLock(file))
}
/// Offline controller maintenance also excludes launcher restart. The owning
/// launcher already holds this lock and retains it through its replacement.
pub(crate) fn quiescent(state: &Path) -> Result<Option<StateLock>> {
    if own_lease(state) {
        return Ok(None);
    }
    Ok(Some(acquire(state)?))
}
fn paths(config: &Config, controller: &Path, agent: &Path) -> Result<()> {
    update::check_destination(controller)?;
    update::check_destination(agent)?;
    let controller_image = controller.canonicalize()?;
    let agent_image = agent.canonicalize()?;
    let current_image = std::env::current_exe()?.canonicalize()?;
    if controller_image == agent_image
        || current_image == controller_image
        || current_image == agent_image
    {
        return Err("Launcher, controller and agent must be distinct executable copies".into());
    }
    if config.updates.enabled()
        && (config.updates.install_path.as_deref() != Some(agent)
            || config
                .updates
                .controller_path
                .as_deref()
                .is_some_and(|path| path != controller))
    {
        return Err("Launcher paths differ from local agent/controller update policy".into());
    }
    if let Some(path) = &config.updates.launcher_path {
        update::check_destination(path)?;
        if std::env::current_exe()?.canonicalize()? != path.canonicalize()? {
            return Err("Launcher executable differs from its locally configured path".into());
        }
    }
    Ok(())
}
fn current_image_is(path: &Path) -> Result<bool> {
    // Keep policy/lease spellings intact, but compare both process images in
    // canonical form (Windows adds a verbatim prefix). Reject links first.
    update::no_links(path)?;
    Ok(std::env::current_exe()?.canonicalize()? == path.canonicalize()?)
}
fn admit(config: &Config, r: &Request, state: &Path) -> Result<()> {
    if let Some(d) = &r.deployment {
        d.validate(&config.endpoint_id, now_ms())?;
        if !config.updates.controller_managed
            || d.component != WireComponent::Controller
            || !d.install
            || d.release_id != r.release_id
            || d.expires_ms != r.deadline_ms
        {
            return Err("Local controller delivery policy or reviewed deployment changed".into());
        }
    }
    let staged = update::status_component(state, Component::Controller)?;
    let release = staged
        .staged
        .as_ref()
        .ok_or("No staged controller release")?;
    if !config.updates.controller_automatic
        || r.phase != Phase::Queued
        || now_ms() >= r.deadline_ms
        || r.release_id != release.id()?
        || staged.transaction.is_some()
        || staged.highwater != release.release.sequence
    {
        return Err("Automatic controller policy or exact request changed or expired".into());
    }
    release.admit(
        &config.updates.public_key,
        &protocol::update::target(),
        &config.updates.channel,
        config
            .updates
            .minimum_sequence
            .max(staged.installed.as_ref().map_or(0, |r| r.release.sequence)),
        now_ms(),
    )?;
    Ok(())
}
pub fn request(state: &Path, release_id: &str, deadline_ms: u64) -> Result<()> {
    request_inner(state, release_id, deadline_ms, None)
}
pub(crate) fn request_fleet(state: &Path, deployment: &Deployment) -> Result<()> {
    if deployment.component != WireComponent::Controller || !deployment.install {
        return Err("Controller maintenance requires a controller installation approval".into());
    }
    request_inner(
        state,
        &deployment.release_id,
        deployment.expires_ms,
        Some(deployment),
    )
}
fn request_inner(
    state: &Path,
    release_id: &str,
    deadline_ms: u64,
    deployment: Option<&Deployment>,
) -> Result<()> {
    let state = state.canonicalize()?;
    let (config, _) = configuration(&state)?;
    let _lock = update::maintenance_lock(&state)?;
    if let Some(existing) = status(&state)? {
        if deployment.is_some() && existing.deployment.as_ref() == deployment {
            return Ok(());
        }
        if existing.retained() {
            if existing.phase == Phase::Queued
                && existing.release_id == release_id
                && existing.deadline_ms == deadline_ms
                && existing.deployment.as_ref() == deployment
            {
                return Ok(());
            }
            return Err("Controller maintenance is already pending".into());
        }
    }
    let mut r = Request {
        release_id: release_id.into(),
        deadline_ms,
        phase: Phase::Queued,
        detail: String::new(),
        updated_ms: now_ms(),
        deployment: deployment.cloned(),
        receipt: None,
        acknowledged: false,
    };
    if let Err(error) = admit(&config, &r, &state) {
        if deployment.is_some() {
            return finish(&state, &mut r, Phase::Refused, &error.to_string());
        }
        return Err(error);
    }
    let release = update::status_component(&state, Component::Controller)?
        .staged
        .unwrap();
    if deadline_ms > now_ms().saturating_add(900_000) || deadline_ms > release.release.expires_ms {
        return Err(
            "Controller request deadline exceeds 15 minutes or signed release validity".into(),
        );
    }
    save(&state, &mut r)
}
pub fn cancel(state: &Path, id: &str) -> Result<()> {
    let state = state.canonicalize()?;
    configuration(&state)?;
    let _lock = update::maintenance_lock(&state)?;
    let mut r = status(&state)?.ok_or("No controller request")?;
    if r.release_id != id {
        return Err("Cancellation must name the exact controller release".into());
    }
    if r.phase == Phase::Cancelled {
        return Ok(());
    }
    if r.phase != Phase::Queued {
        return Err("Controller replacement already began or ended".into());
    }
    finish(
        &state,
        &mut r,
        Phase::Cancelled,
        "Local request cancelled before controller replacement",
    )
}
fn eligible(state: &Path, controller: &Path, agent: &Path) -> Result<bool> {
    let Some(mut r) = status(state)? else {
        return Ok(false);
    };
    if r.phase != Phase::Queued {
        return Ok(false);
    }
    let Some(_lock) = update::try_maintenance_lock(state)? else {
        return Ok(false);
    };
    // Read again under the lock so a concurrent cancellation cannot be undone.
    r = status(state)?.ok_or("Controller request disappeared")?;
    if r.phase != Phase::Queued {
        return Ok(false);
    }
    if update::status(state)?.transaction.is_some()
        || crate::engine_update::status(state)?.transaction.is_some()
    {
        return Ok(false);
    }
    let result = (|| -> Result<()> {
        let (config, _) = configuration(state)?;
        admit(&config, &r, state)?;
        paths(&config, controller, agent)?;
        authorize(&config, &r)
    })();
    if let Err(e) = result {
        finish(state, &mut r, Phase::Refused, &e.to_string())?;
        return Ok(false);
    }
    Ok(true)
}
pub fn guard_parent(parent: u32) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        athernex_endpoint_native::child::guard_parent(parent)?;
    }
    #[cfg(windows)]
    {
        crate::windows_job::guard_parent(parent)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = parent;
        return Err("Owned launcher processes are unsupported".into());
    }
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Ok(())
}
fn context(state: &Path) -> Result<Option<Lease>> {
    let Some(token) = std::env::var_os(ENV_TOKEN) else {
        return Ok(None);
    };
    let Some(l) = lease(state)? else {
        return Ok(None);
    };
    if token != l.token.as_str() || !protocol::hex_id(&l.token) || !held(state)? {
        return Ok(None);
    }
    Ok(Some(l))
}
pub(crate) fn supervised(state: &Path) -> bool {
    let check = || -> Result<bool> {
        let Some(l) = context(state)? else {
            return Ok(false);
        };
        let Some(parent) = l.controller_pid else {
            return Ok(false);
        };
        Ok(crate::supervisor::child_context(state).is_some()
            && crate::supervisor::controller_is(state, parent)?
            && current_image_is(&l.agent)?
            && guard_parent(parent).is_ok())
    };
    check().unwrap_or(false)
}
fn authorize(config: &Config, request: &Request) -> Result<()> {
    if let Some(deployment) = &request.deployment {
        let client = crate::Client::new(config.clone())?;
        client.authorize_installation(deployment)?;
    }
    Ok(())
}
impl crate::Client {
    pub(crate) fn controller_installation_receipts(&self, state: &Path) -> Result<()> {
        let Some(record) = status(state)? else {
            return Ok(());
        };
        let Some(receipt) = &record.receipt else {
            return Ok(());
        };
        if record.acknowledged {
            return Ok(());
        }
        if self.post("updates/install-receipt", receipt)?["committed"] != true {
            return Err("Server did not commit the controller installation receipt".into());
        }
        let _lock = update::maintenance_lock(state)?;
        let mut current = status(state)?.ok_or("Controller request disappeared")?;
        if current.receipt.as_ref() != Some(receipt) || current.deployment != record.deployment {
            return Err("Controller receipt changed while being acknowledged".into());
        }
        crate::managed_update::finish_controller_delivery(
            state,
            current.deployment.as_ref().unwrap(),
        )?;
        current.acknowledged = true;
        save(state, &mut current)
    }
}
pub(crate) fn enter(state: &Path) -> Result<()> {
    if std::env::var_os(ENV_TOKEN).is_none() {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(l) = context(state)? {
            if l.controller_pid == Some(std::process::id())
                && current_image_is(&l.controller)?
                && crate::file_hash(&l.controller)? == l.controller_sha256
            {
                guard_parent(l.launcher_pid)?;
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("Launcher ownership lease was not established".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}
fn trial_context(state: &Path, t: &Transaction) -> Result<Option<Lease>> {
    let Some(trial) = &t.trial else {
        return Ok(None);
    };
    let Some(l) = context(state)? else {
        return Ok(None);
    };
    let (config, hash) = configuration(state)?;
    t.release.authenticate(&config.updates.public_key)?;
    if trial.nonce != l.token
        || now_ms() >= trial.expires_ms
        || l.controller != t.install_path
        || l.controller_sha256 != t.release.release.sha256
        || hash != l.config_sha256
        || config.updates.install_path.as_ref() != Some(&l.agent)
        || crate::file_hash(&l.agent)? != l.agent_sha256
    {
        return Ok(None);
    }
    Ok(Some(l))
}
pub(crate) fn controller_allowed(state: &Path, t: &Transaction) -> Result<bool> {
    let Some(l) = trial_context(state, t)? else {
        return Ok(false);
    };
    Ok(l.controller_pid == Some(std::process::id())
        && current_image_is(&l.controller)?
        && crate::file_hash(&l.controller)? == t.release.release.sha256
        && guard_parent(l.launcher_pid).is_ok())
}
pub(crate) fn work_allowed(state: &Path, t: &Transaction) -> Result<bool> {
    let Some(l) = trial_context(state, t)? else {
        return Ok(false);
    };
    let Some(parent) = l.controller_pid else {
        return Ok(false);
    };
    Ok(current_image_is(&l.agent)?
        && crate::supervisor::controller_is(state, parent)?
        && guard_parent(parent).is_ok())
}
pub(crate) fn runtime_ready(state: &Path, t: &Transaction) -> Result<bool> {
    let Some(trial) = &t.trial else {
        return Ok(false);
    };
    if !owned(state, &trial.nonce) || now_ms() >= trial.expires_ms {
        return Ok(false);
    }
    let Some(l) = lease(state)? else {
        return Ok(false);
    };
    let Some(pid) = l.controller_pid else {
        return Ok(false);
    };
    let (config, hash) = configuration(state)?;
    Ok(hash == l.config_sha256
        && config.updates.controller_path.as_ref() == Some(&t.install_path)
        && config.updates.install_path.as_ref() == Some(&l.agent)
        && crate::file_hash(&l.controller)? == t.release.release.sha256
        && crate::file_hash(&l.agent)? == l.agent_sha256
        && crate::supervisor::controller_ready(state, pid, &l.agent_sha256, l.started_ms)?)
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct Controller {
    #[cfg(unix)]
    child: athernex_endpoint_native::child::Service,
    #[cfg(windows)]
    child: crate::windows_job::Child,
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl Controller {
    fn start(state: &Path, l: &mut Lease) -> Result<Self> {
        #[cfg(target_os = "macos")]
        crate::macos_network_bundle::upgrade::require_settled()?;
        let mut command = Process::new(&l.controller);
        command
            .args([
                "launcher-owned",
                &std::process::id().to_string(),
                "supervise",
            ])
            .arg(state)
            .arg(&l.agent)
            .env(ENV_TOKEN, &l.token);
        l.started_ms = now_ms();
        l.controller_pid = None;
        l.controller_sha256 = verified_controller(state, &l.controller, &l.token)?;
        save_lease(state, l)?;
        #[cfg(target_os = "macos")]
        crate::macos_network_bundle::upgrade::require_settled()?;
        #[cfg(unix)]
        let child = athernex_endpoint_native::child::Service::start(&mut command, 8192)?;
        #[cfg(windows)]
        let child = command.spawn()?;
        let mut owned = Self { child };
        #[cfg(unix)]
        {
            l.controller_pid = owned.child.pid();
        }
        #[cfg(windows)]
        {
            l.controller_pid = Some(owned.child.id());
        }
        if let Err(error) = save_lease(state, l) {
            owned.stop()?;
            return Err(error);
        }
        Ok(owned)
    }
    fn poll(&mut self) -> Result<Option<i32>> {
        #[cfg(unix)]
        {
            self.child.poll()
        }
        #[cfg(windows)]
        {
            Ok(self.child.poll()?)
        }
    }
    fn stop(&mut self) -> Result<()> {
        self.child.stop()?;
        Ok(())
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
fn verified_controller(state: &Path, path: &Path, token: &str) -> Result<String> {
    update::check_destination(path)?;
    let (config, _) = configuration(state)?;
    let record = update::status_component(state, Component::Controller)?;
    let actual = crate::file_hash(path)?;
    let expected = if let Some(t) = record.transaction {
        if t.install_path != path
            || !t
                .trial
                .as_ref()
                .is_some_and(|trial| trial.nonce == token && now_ms() < trial.expires_ms)
            || !owned(state, token)
        {
            return Err("Controller startup requires its owning bounded installation trial".into());
        }
        Some(t.release)
    } else {
        record.installed
    };
    if let Some(release) = expected {
        release.authenticate(&config.updates.public_key)?;
        if release.release.sha256 != actual {
            return Err("Controller bytes changed outside the signed release ledger".into());
        }
    }
    Ok(actual)
}
fn recover_agent(state: &Path) -> Result<()> {
    if update::status(state)?.transaction.is_some() {
        // The ordinary controller already recovers agent transactions at
        // startup. Do it before opening its agent path, which may be absent at
        // an interrupted replacement boundary. No controller trial may overlap.
        update::recover(state)?;
    }
    Ok(())
}
fn verified_agent(state: &Path, config: &Config, agent: &Path) -> Result<String> {
    update::check_destination(agent)?;
    let agent_sha256 = crate::file_hash(agent)?;
    if let Some(release) = update::status(state)?.installed {
        release.authenticate(&config.updates.public_key)?;
        if release.release.sha256 != agent_sha256 {
            return Err("Agent bytes changed outside the signed release ledger".into());
        }
    }
    Ok(agent_sha256)
}
fn new_lease(state: &Path, controller: &Path, agent: &Path) -> Result<Lease> {
    let (config, config_sha256) = configuration(state)?;
    paths(&config, controller, agent)?;
    let agent_sha256 = verified_agent(state, &config, agent)?;
    Ok(Lease {
        token: secret()?,
        launcher_pid: std::process::id(),
        controller_pid: None,
        controller: controller.into(),
        controller_sha256: crate::file_hash(controller)?,
        agent: agent.into(),
        agent_sha256,
        config_sha256,
        started_ms: now_ms(),
    })
}
fn quiet(state: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let (config, _) = configuration(state)?;
        if update::offline_maintenance(state, &config).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("Controller or managed child cleanup remains pending".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}
fn reconcile(state: &Path) -> Result<()> {
    let mut status = update::status_component(state, Component::Controller)?;
    let Some(mut r) = self::status(state)? else {
        if status.transaction.is_some() {
            return Err("Recover the manually interrupted controller replacement first".into());
        }
        return Ok(());
    };
    if r.phase != Phase::Applying {
        if status.transaction.is_some() {
            return Err("Controller recovery has no matching automatic request".into());
        }
        return Ok(());
    }
    if let Some(t) = &status.transaction {
        if t.release.id()? != r.release_id {
            return Err("Controller recovery request differs from its transaction".into());
        }
        status = update::recover_component(state, Component::Controller)?;
        if status.last_result != "rolled_back" {
            return Err("Controller recovery did not restore a confirmed executable".into());
        }
        return finish(state,&mut r,Phase::RolledBack,"Launcher recovered an interrupted controller replacement; failed sequence remains reserved");
    }
    if status
        .installed
        .as_ref()
        .is_some_and(|v| v.id().ok().as_deref() == Some(&r.release_id))
    {
        finish(
            state,
            &mut r,
            Phase::Installed,
            "Runtime-confirmed controller recovered after launcher interruption",
        )
    } else {
        finish(
            state,
            &mut r,
            Phase::Refused,
            "Controller maintenance interrupted before a confirmed replacement",
        )
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn maintain(state: &Path, controller: &Path, agent: &Path) -> Result<Option<Controller>> {
    let mut r;
    let mut l = new_lease(state, controller, agent)?;
    save_lease(state, &l)?;
    {
        let _lock = update::maintenance_lock(state)?;
        r = status(state)?.ok_or("Controller request disappeared")?;
        let (config, _) = configuration(state)?;
        if let Err(e) = admit(&config, &r, state).and_then(|()| authorize(&config, &r)) {
            if r.phase == Phase::Queued {
                finish(state, &mut r, Phase::Refused, &e.to_string())?;
            }
            return Ok(None);
        }
        r.phase = Phase::Applying;
        save(state, &mut r)?;
    }
    let mut candidate = None;
    let result = (|| -> Result<()> {
        update::begin_controller_trial(state, &l.token)?;
        candidate = Some(Controller::start(state, &mut l)?);
        let start = Instant::now();
        loop {
            if let Some(code) = candidate.as_mut().unwrap().poll()? {
                return Err(format!(
                    "Candidate controller exited before runtime confirmation ({code})"
                )
                .into());
            }
            let t = update::status_component(state, Component::Controller)?
                .transaction
                .ok_or("Controller trial disappeared")?;
            if start.elapsed() >= Duration::from_secs(2) && runtime_ready(state, &t)? {
                update::confirm_controller_trial(state, &l.token)?;
                return Ok(());
            }
            if start.elapsed() >= Duration::from_secs(350) {
                return Err("Controller did not establish managed server connectivity and configured protection within its trial budget".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    })();
    if let Err(e) = result {
        let state_record = update::status_component(state, Component::Controller)?;
        if state_record.transaction.is_none()
            && state_record
                .installed
                .as_ref()
                .is_some_and(|v| v.id().ok().as_deref() == Some(&r.release_id))
        {
            finish(
                state,
                &mut r,
                Phase::Installed,
                &format!("Runtime confirmed; cleanup requires review: {e}"),
            )?;
            return Ok(candidate);
        }
        if let Some(mut child) = candidate.take() {
            child.stop()?;
        }
        // Recovery acquires all service locks and refuses incomplete cleanup.
        if state_record.transaction.is_some() {
            update::recover_component(state, Component::Controller)?;
            finish(state, &mut r, Phase::RolledBack, &e.to_string())?;
        } else {
            finish(state, &mut r, Phase::Refused, &e.to_string())?;
        }
        return Ok(None);
    }
    finish(state,&mut r,Phase::Installed,"Candidate controller completed a managed server cycle and configured protection health checks")?;
    Ok(candidate)
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub fn launch(state: &Path, controller: &Path, agent: &Path) -> Result<()> {
    #[cfg(windows)]
    let _admission = crate::windows_driver::Admission::acquire(state)?;
    #[cfg(windows)]
    crate::windows_driver::require_live(state)?;
    #[cfg(target_os = "macos")]
    crate::macos_network_bundle::upgrade::require_settled()?;
    #[cfg(windows)]
    crate::installer::require_complete(state)?;
    let state = state.canonicalize()?;
    let controller = std::path::absolute(controller)?;
    let agent = std::path::absolute(agent)?;
    // Do not require the controller file before recovery: interrupted Windows
    // replacement may legitimately have left only its recorded backup.
    let _owner = acquire(&state)?;
    #[cfg(target_os = "macos")]
    crate::macos_network_bundle::upgrade::require_settled()?;
    #[cfg(windows)]
    crate::installer::require_complete(&state)?;
    let (config, config_sha256) = configuration(&state)?;
    if config.updates.enabled()
        && (config
            .updates
            .controller_path
            .as_ref()
            .is_some_and(|path| path != &controller)
            || config.updates.install_path.as_ref() != Some(&agent))
    {
        return Err("Launcher paths differ from local update policy".into());
    }
    if let Some(expected) = &config.updates.launcher_path {
        update::check_destination(expected)?;
        if std::env::current_exe()?.canonicalize()? != expected.canonicalize()? {
            return Err("Wrong configured launcher executable".into());
        }
    }
    let initial = Lease {
        token: secret()?,
        launcher_pid: std::process::id(),
        controller_pid: None,
        controller: controller.clone(),
        controller_sha256: String::new(),
        agent: agent.clone(),
        agent_sha256: String::new(),
        config_sha256,
        started_ms: now_ms(),
    };
    save_lease(&state, &initial)?;
    reconcile(&state)?;
    recover_agent(&state)?;
    let mut child = None;
    loop {
        if eligible(&state, &controller, &agent)? {
            if let Some(mut current) = child.take() {
                Controller::stop(&mut current)?;
            }
            quiet(&state)?;
            child = maintain(&state, &controller, &agent)?;
        }
        if child.is_none() {
            recover_agent(&state)?;
            let mut l = new_lease(&state, &controller, &agent)?;
            child = Some(Controller::start(&state, &mut l)?);
        }
        if child.as_mut().unwrap().poll()?.is_some() {
            child.take();
            thread::sleep(Duration::from_secs(5));
        }
        thread::sleep(Duration::from_millis(100));
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn launch(_: &Path, _: &Path, _: &Path) -> Result<()> {
    Err("Launcher is unsupported on this platform".into())
}

#[cfg(test)]
mod tests;
