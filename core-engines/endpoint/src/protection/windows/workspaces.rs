//! Workspace identity is committed before staging any file or launching a
//! scanner. Recovery runs only after every launch/network journal is retired.
use super::{command, evidence, Directory, Result};
use crate::{secret, windows_job};
use athernex_endpoint_native::windows_state::WorkspaceIdentity;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::PathBuf,
    time::Duration,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    id: String,
    identity: WorkspaceIdentity,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u32,
    state: PathBuf,
    nonce: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    schema: u32,
    nonce: String,
    removed: usize,
}
fn valid_id(id: &str) -> Result<()> {
    if !athernex_endpoint_protocol::hex_id(id) {
        return Err("Invalid scanner workspace journal identity".into());
    }
    Ok(())
}
fn names(directory: &Directory) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(directory.path())? {
        if result.len() == 64 {
            return Err("Scanner workspace recovery exceeds its entry budget".into());
        }
        result.push(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| "Unknown scanner workspace filename")?,
        );
    }
    Ok(result)
}
pub(super) fn record(state: &Directory, id: &str, identity: WorkspaceIdentity) -> Result<()> {
    valid_id(id)?;
    state.directory("workspaces")?.write_json(
        &format!("{id}.json"),
        &Record {
            schema: 1,
            id: id.into(),
            identity,
        },
    )
}
/// Parent holds both service leases and has reconciled network ownership first.
/// A timeout leaves the bounded worker in the existing job reaper and blocks
/// further admission; the next start can resume partially completed deletion.
pub(super) fn reclaim(state: &Directory) -> Result<()> {
    windows_job::cleanup_ready()?;
    let runtime = state.directory("runtime")?;
    let journal = state.directory("workspaces")?;
    if names(&runtime)?.is_empty() && names(&journal)?.is_empty() {
        return Ok(());
    }
    let temporary = state.directory("worker-temporary")?;
    let mut invocation = command(&std::env::current_exe()?, temporary.path())?;
    invocation
        .arg("windows-workspace-cleanup")
        .arg(std::process::id().to_string());
    let request = Request {
        schema: 1,
        state: state.path().into(),
        nonce: secret()?,
    };
    let (code, output) = windows_job::run_with_input(
        &invocation,
        Duration::from_secs(30),
        8192,
        &serde_json::to_vec(&request)?,
    )?;
    windows_job::cleanup_ready()?;
    if code != 0 {
        return Err(format!(
            "Windows workspace cleanup retained its journal ({code}): {}",
            String::from_utf8_lossy(&output)
        )
        .into());
    }
    let response: Completion = serde_json::from_slice(&output)?;
    if response.schema != 1 || response.nonce != request.nonce || response.removed > 128 {
        return Err("Windows workspace cleanup acknowledgement changed".into());
    }
    Ok(())
}
pub fn worker_main(parent: u32) -> Result<Completion> {
    windows_job::guard_parent(parent)?;
    athernex_endpoint_native::windows_state::require_local_system()?;
    let mut input = Vec::new();
    std::io::stdin().take(16385).read_to_end(&mut input)?;
    if input.len() > 16384 {
        return Err("Windows workspace cleanup request exceeds its budget".into());
    }
    let request: Request = serde_json::from_slice(&input)?;
    if request.schema != 1
        || !athernex_endpoint_protocol::hex_id(&request.nonce)
        || request
            .state
            .to_str()
            .is_none_or(|s| !evidence::worker_state_path(s))
    {
        return Err("Invalid Windows workspace cleanup request".into());
    }
    let state = Directory::open(&request.state)?;
    let removed = clean(&state)?;
    Ok(Completion {
        schema: 1,
        nonce: request.nonce,
        removed,
    })
}
fn clean(state: &Directory) -> Result<usize> {
    // A stale launch record, including an unfinished temporary write, keeps
    // every workspace intact. No PID-based inference happens in this worker.
    if !names(&state.directory("network")?)?.is_empty() {
        return Err("Scanner launch/network recovery must finish before workspace cleanup".into());
    }
    let runtime = state.directory("runtime")?;
    let journal = state.directory("workspaces")?;
    let mut records = BTreeMap::new();
    let mut temporary = Vec::new();
    for name in names(&journal)? {
        if let Some(id) = name.strip_suffix(".json") {
            valid_id(id)?;
            let record: Record = journal.read_json(&name)?;
            if record.schema != 1 || record.id != id {
                return Err("Scanner workspace journal identity changed".into());
            }
            records.insert(id.to_owned(), record.identity);
        } else if let Some(id) = name
            .strip_prefix('.')
            .and_then(|n| n.strip_suffix(".json.new"))
        {
            valid_id(id)?;
            if journal.read(&name)?.metadata()?.len() > 65536 {
                return Err("Scanner workspace temporary journal exceeds its budget".into());
            }
            temporary.push(name);
        } else {
            return Err("Unknown scanner workspace journal entry".into());
        }
    }
    let mut identities: BTreeSet<_> = records.keys().cloned().collect();
    for name in names(&runtime)? {
        let id = name
            .strip_prefix("scanner-")
            .ok_or("Unknown scanner runtime entry")?;
        valid_id(id)?;
        identities.insert(id.into());
    }
    let removed = identities.len();
    for id in identities {
        runtime.remove_scanner_workspace(&format!("scanner-{id}"), records.get(&id))?;
        if records.contains_key(&id) {
            journal.remove(&format!("{id}.json"))?;
        }
    }
    for name in temporary {
        journal.remove(&name)?;
    }
    journal.sync()?;
    Ok(removed)
}
