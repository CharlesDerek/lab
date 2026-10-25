//! Owned scratch worker. Durable ownership precedes creation; the image-ready
//! commit precedes attachment. Cleanup never reattaches or initializes an image.
mod formatter;
mod recovery;
#[cfg(test)]
mod tests;
use super::{check_running, command, evidence, Directory, PinnedDirectory, Result};
use crate::{
    now_ms, secret,
    windows_job::{self, Service},
};
use athernex_endpoint_native::{
    windows_filter::peer,
    windows_scanner::Token,
    windows_scratch::{self as native, FormatTarget, FreshDisk, Space, Spec},
    windows_state::WorkspaceIdentity,
};
pub use recovery::worker_main as cleanup_worker;
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
pub(super) fn reclaim(state: &Directory) -> Result<()> {
    recovery::reclaim(state)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    pid: u32,
    created: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    spec: Spec,
    directory: WorkspaceIdentity,
    logon: String,
    owner: Option<Owner>,
    image_ready: bool,
}
impl Record {
    fn validate(&self, id: &str) -> Result<()> {
        self.spec.validate()?;
        native::validate_logon(&self.logon)?;
        if self.schema != 1
            || self.spec.id != id
            || self
                .owner
                .as_ref()
                .is_some_and(|p| p.pid <= 4 || p.created == 0)
            || (self.image_ready && self.owner.is_none())
        {
            return Err("Invalid scratch worker journal".into());
        }
        Ok(())
    }
    fn save(&self, journal: &Directory) -> Result<()> {
        self.validate(&self.spec.id)?;
        journal.write_json(&format!("{}.json", self.spec.id), self)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u32,
    state: PathBuf,
    id: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub schema: u32,
    pub id: String,
    pub worker_pid: u32,
    pub worker_created: u64,
    pub checked_ms: u64,
    pub logon: String,
    pub target: FormatTarget,
    pub path: PathBuf,
    pub directory: WorkspaceIdentity,
    pub space: Space,
}
impl Health {
    fn same_storage(&self, other: &Self) -> bool {
        self.id == other.id
            && self.worker_pid == other.worker_pid
            && self.worker_created == other.worker_created
            && self.logon == other.logon
            && self.target == other.target
            && self.path == other.path
            && self.directory == other.directory
            && self.space.total_bytes == other.space.total_bytes
    }
}
pub(super) fn validate_observation(
    state: &Directory,
    observation: &Health,
    logon: &str,
) -> Result<()> {
    valid_id(&observation.id)?;
    let record: Record = state
        .directory("scratch-journal")?
        .read_json(&format!("{}.json", observation.id))?;
    validate_health(observation, &record)?;
    if !observation.same_storage(&health(state, &observation.id, logon)?) {
        return Err("Observed scratch storage differs from the live helper".into());
    }
    Ok(())
}
fn names(directory: &Directory) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory.path())? {
        if names.len() == 64 {
            return Err("Scratch recovery exceeds its entry budget".into());
        }
        names.push(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| "Unknown scratch recovery filename")?,
        );
    }
    Ok(names)
}
fn valid_id(id: &str) -> Result<()> {
    if !athernex_endpoint_protocol::hex_id(id) {
        return Err("Invalid scratch session identity".into());
    }
    Ok(())
}
fn read_request() -> Result<Request> {
    let mut input = Vec::new();
    std::io::stdin().take(16385).read_to_end(&mut input)?;
    if input.len() > 16384 {
        return Err("Scratch worker request exceeds its budget".into());
    }
    let request: Request = serde_json::from_slice(&input)?;
    valid_id(&request.id)?;
    if request.schema != 1
        || request
            .state
            .to_str()
            .is_none_or(|s| !evidence::drive_path(s))
    {
        return Err("Invalid scratch worker request".into());
    }
    Ok(request)
}
fn validate_health(health: &Health, record: &Record) -> Result<()> {
    record.validate(&health.id)?;
    health.target.validate_for(&record.spec)?;
    let owner = record
        .owner
        .as_ref()
        .ok_or("Scratch worker has no committed owner")?;
    if health.schema != 1
        || health.id != record.spec.id
        || !record.image_ready
        || health.worker_pid != owner.pid
        || health.worker_created != owner.created
        || health.logon != record.logon
        || health.path != Path::new(&format!("{}scratch", health.target.volume))
        || health.space.total_bytes > health.target.bytes
        || health.space.total_bytes < 64 * 1024 * 1024
        || health.space.free_bytes > health.space.total_bytes
        || health.checked_ms > now_ms().saturating_add(1000)
        || now_ms().saturating_sub(health.checked_ms) > 5000
    {
        return Err(
            "Scratch worker health is stale or does not match its committed session".into(),
        );
    }
    Ok(())
}
pub(super) fn health(state: &Directory, id: &str, logon: &str) -> Result<Health> {
    valid_id(id)?;
    let record: Record = state
        .directory("scratch-journal")?
        .read_json(&format!("{id}.json"))?;
    let health: Health = state
        .directory("scratch-health")?
        .read_json(&format!("{id}.json"))?;
    validate_health(&health, &record)?;
    if health.logon != logon || peer::identify(health.worker_pid)? != health.worker_created {
        return Err("Scratch helper process or scanner logon changed".into());
    }
    Ok(health)
}
pub(super) struct Scratch {
    service: Service,
    state: Directory,
    spec: Spec,
    logon: String,
    ready: Health,
}
impl Scratch {
    pub(super) fn start(state: &Directory, id: &str, bytes: u64, token: &Token) -> Result<Self> {
        token.verify()?;
        let spec = Spec {
            schema: 1,
            id: id.into(),
            bytes,
        };
        spec.validate()?;
        let runtime = state.directory("scratch-runtime")?;
        let directory = Directory::create_under(runtime.path(), &format!("scanner-{id}"))?;
        let record = Record {
            schema: 1,
            spec: spec.clone(),
            directory: directory.identity()?,
            logon: token.logon_sid().into(),
            owner: None,
            image_ready: false,
        };
        record.save(&state.directory("scratch-journal")?)?;
        drop(directory);
        let temporary = state.directory("worker-temporary")?;
        let mut invocation = command(&std::env::current_exe()?, temporary.path())?;
        invocation
            .arg("windows-scratch-worker")
            .arg(std::process::id().to_string());
        let request = Request {
            schema: 1,
            state: state.path().into(),
            id: id.into(),
        };
        let mut service = Service::start(&invocation, Some(&serde_json::to_vec(&request)?), 8192)?;
        let created = service.creation_time()?;
        let deadline = Instant::now() + Duration::from_secs(180);
        let ready = loop {
            check_running(&mut service, "scratch worker")?;
            if let Ok(ready) = health(state, id, token.logon_sid()) {
                if ready.worker_pid != service.id() || ready.worker_created != created {
                    return Err("Scratch health belongs to another process".into());
                }
                ready.target.validate_for(&spec)?;
                break ready;
            }
            if Instant::now() >= deadline {
                return Err("Scratch worker did not become ready before its deadline".into());
            }
            thread::sleep(Duration::from_millis(100));
        };
        Ok(Self {
            service,
            state: Directory::open(state.path())?,
            spec,
            logon: token.logon_sid().into(),
            ready,
        })
    }
    pub(super) fn check(&mut self) -> Result<()> {
        check_running(&mut self.service, "scratch worker")?;
        let ready = health(&self.state, &self.spec.id, &self.logon)?;
        ready.target.validate_for(&self.spec)?;
        if ready.worker_pid != self.service.id()
            || ready.worker_created != self.service.creation_time()?
            || !ready.same_storage(&self.ready)
        {
            return Err("Scratch worker identity or capacity changed".into());
        }
        Ok(())
    }
    pub(super) fn path(&self) -> &Path {
        &self.ready.path
    }
    pub(super) fn stop(&mut self) -> Result<()> {
        self.service.stop()?;
        Ok(())
    }
}

pub fn worker_main(parent: u32) -> Result<()> {
    windows_job::guard_parent(parent)?;
    athernex_endpoint_native::windows_state::require_local_system()?;
    let request = read_request()?;
    let state = Directory::open(&request.state)?;
    let _lease = state.lock("scratch-worker.lock")?;
    let journal = state.directory("scratch-journal")?;
    let mut record: Record = journal.read_json(&format!("{}.json", request.id))?;
    record.validate(&request.id)?;
    if record.owner.is_some() || record.image_ready {
        return Err("Scratch worker refuses to adopt an earlier session".into());
    }
    let runtime = state.directory("scratch-runtime")?;
    let directory = Directory::open(&runtime.path().join(format!("scanner-{}", request.id)))?;
    if directory.identity()? != record.directory {
        return Err("Scratch container identity changed".into());
    }
    let worker_created = peer::identify(std::process::id())?;
    record.owner = Some(Owner {
        pid: std::process::id(),
        created: worker_created,
    });
    record.save(&journal)?;
    let disk = FreshDisk::create(directory, record.spec.clone())?;
    // Attachment is impossible before this commit. A pre-commit failure can
    // leave only an unmounted partial/new image for exclusive reclamation.
    record.image_ready = true;
    record.save(&journal)?;
    let volume = disk.attach()?.initialize()?.discover()?;
    let temporary = state.directory("worker-temporary")?;
    let ready = formatter::run(volume, &record.logon, temporary.path())?;
    let health_directory = state.directory("scratch-health")?;
    loop {
        let space = ready.verify()?;
        let report = Health {
            schema: 1,
            id: request.id.clone(),
            worker_pid: std::process::id(),
            worker_created,
            checked_ms: now_ms(),
            logon: record.logon.clone(),
            target: ready.target().clone(),
            path: ready.path().into(),
            directory: ready.identity().clone(),
            space,
        };
        validate_health(&report, &record)?;
        health_directory.write_json(&format!("{}.json", request.id), &report)?;
        thread::sleep(Duration::from_secs(1));
    }
}
