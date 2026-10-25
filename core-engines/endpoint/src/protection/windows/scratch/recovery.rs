use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    schema: u32,
    nonce: String,
    removed: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    schema: u32,
    state: PathBuf,
    nonce: String,
}
pub(super) fn reclaim(state: &Directory) -> Result<()> {
    windows_job::cleanup_ready()?;
    if names(&state.directory("scratch-journal")?)?.is_empty()
        && names(&state.directory("scratch-runtime")?)?.is_empty()
        && names(&state.directory("scratch-health")?)?.is_empty()
    {
        return Ok(());
    }
    let temporary = state.directory("worker-temporary")?;
    let mut invocation = command(&std::env::current_exe()?, temporary.path())?;
    invocation
        .arg("windows-scratch-cleanup")
        .arg(std::process::id().to_string());
    let request = Cleanup {
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
            "Scratch recovery retained its journal ({code}): {}",
            String::from_utf8_lossy(&output)
        )
        .into());
    }
    let reply: Completion = serde_json::from_slice(&output)?;
    if reply.schema != 1 || reply.nonce != request.nonce || reply.removed > 128 {
        return Err("Scratch recovery acknowledgement changed".into());
    }
    Ok(())
}
pub fn worker_main(parent: u32) -> Result<Completion> {
    windows_job::guard_parent(parent)?;
    athernex_endpoint_native::windows_state::require_local_system()?;
    let mut input = Vec::new();
    std::io::stdin().take(16385).read_to_end(&mut input)?;
    if input.len() > 16384 {
        return Err("Scratch recovery request exceeds its budget".into());
    }
    let request: Cleanup = serde_json::from_slice(&input)?;
    valid_id(&request.nonce)?;
    if request.schema != 1
        || request
            .state
            .to_str()
            .is_none_or(|s| !evidence::drive_path(s))
    {
        return Err("Invalid scratch recovery request".into());
    }
    let removed = clean(&Directory::open(&request.state)?)?;
    Ok(Completion {
        schema: 1,
        nonce: request.nonce,
        removed,
    })
}
fn temporary_id(name: &str) -> Option<&str> {
    name.strip_prefix('.')
        .and_then(|n| n.strip_suffix(".json.new"))
}
pub(super) fn clean(state: &Directory) -> Result<usize> {
    let _lease = state.lock("scratch-worker.lock")?;
    if !names(&state.directory("network")?)?.is_empty() {
        return Err(
            "Scanner launch/network recovery must finish before scratch reclamation".into(),
        );
    }
    let journal = state.directory("scratch-journal")?;
    let runtime = state.directory("scratch-runtime")?;
    let health = state.directory("scratch-health")?;
    let mut records = BTreeMap::new();
    let mut pending = Vec::new();
    for name in names(&journal)? {
        if let Some(id) = name.strip_suffix(".json") {
            valid_id(id)?;
            let record: Record = journal.read_json(&name)?;
            record.validate(id)?;
            if let Some(owner) = &record.owner {
                if !peer::original_process_ended(owner.pid, owner.created)? {
                    return Err(
                        "Scratch helper is still alive; retain its image and journal".into(),
                    );
                }
            }
            records.insert(id.to_owned(), record);
        } else if let Some(id) = temporary_id(&name) {
            valid_id(id)?;
            if journal.read(&name)?.metadata()?.len() > 65536 {
                return Err("Scratch temporary journal exceeds its budget".into());
            }
            pending.push(name);
        } else {
            return Err("Unknown scratch journal entry".into());
        }
    }
    let mut ids: BTreeSet<_> = records.keys().cloned().collect();
    for name in names(&runtime)? {
        let id = name
            .strip_prefix("scanner-")
            .ok_or("Unknown scratch runtime entry")?;
        valid_id(id)?;
        ids.insert(id.into());
    }
    let health_names = names(&health)?;
    for name in &health_names {
        valid_id(
            name.strip_suffix(".json")
                .or_else(|| temporary_id(name))
                .ok_or("Unknown scratch health entry")?,
        )?;
        if health.read(name)?.metadata()?.len() > 65536 {
            return Err("Scratch health entry exceeds its budget".into());
        }
    }
    let mut removed = 0;
    for id in ids {
        let leaf = format!("scanner-{id}");
        if let Some(record) = records.get(&id) {
            let path = runtime.path().join(&leaf);
            match Directory::open(&path) {
                Ok(directory) => {
                    if directory.identity()? != record.directory {
                        return Err("Retired scratch container identity changed".into());
                    }
                    drop(directory);
                    if record.image_ready {
                        // A genuine attachment can take time to disappear after
                        // owner exit. Each query is read-only; no detach by PID or
                        // disk number, and no corrupt-image initialization.
                        let deadline = Instant::now() + Duration::from_secs(3);
                        loop {
                            match native::require_detached(
                                Directory::open(&path)?,
                                record.spec.clone(),
                            ) {
                                Ok(()) => break,
                                Err(error) if Instant::now() >= deadline => return Err(error),
                                Err(_) => thread::sleep(Duration::from_millis(100)),
                            }
                        }
                    }
                }
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
                Err(error) => return Err(error),
            }
            runtime.remove_scanner_workspace(&leaf, Some(&record.directory))?;
            journal.remove(&format!("{id}.json"))?;
        } else {
            runtime.remove_scanner_workspace(&leaf, None)?;
        }
        removed += 1;
    }
    for name in pending {
        journal.remove(&name)?;
    }
    for name in health_names {
        health.remove(&name)?;
    }
    Ok(removed)
}
