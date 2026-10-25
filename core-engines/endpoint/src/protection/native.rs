//! Transfer immutable native receipts into the agent outbox before unlinking them.
//! The small transfer journal survives a crash even if the server already ACKed
//! the outbox row before the source receipt could be removed.
use crate::{now_ms, Result, Store};
use athernex_endpoint_native::{
    receipt::{self, Receipt, MAX_RECEIPT},
    scanner, Policy,
};
use athernex_endpoint_protocol::{self as protocol, EndpointEvent};
use rusqlite::{params, OptionalExtension};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const LIMIT: usize = 2048;
mod coverage;

fn private_path(path: &Path, directory: bool) -> Result<()> {
    let owner = unsafe { libc::geteuid() };
    for (index, component) in path.ancestors().enumerate() {
        let m = fs::symlink_metadata(component)?;
        let sticky = index > 0 && m.is_dir() && m.uid() == 0 && m.mode() & 0o1000 != 0;
        if m.file_type().is_symlink()
            || ![0, owner].contains(&m.uid())
            || (m.mode() & 0o022 != 0 && !sticky)
            || (index == 0 && (m.mode() & 0o077 != 0 || m.is_dir() != directory))
        {
            return Err(format!("Native receipt storage must be private and owned by the service identity: {} (mode {:o}, uid {})",component.display(),m.mode() & 0o7777,m.uid()).into());
        }
    }
    Ok(())
}

fn read_private(path: &Path, limit: usize) -> Result<(Vec<u8>, (u64, u64))> {
    private_path(path, false)?;
    let file = scanner::open_file(path)?;
    let m = file.metadata()?;
    if m.len() > limit as u64
        || m.mode() & 0o077 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&m.uid())
    {
        return Err("Native receipt or scope exceeds its storage contract".into());
    }
    let identity = (m.dev(), m.ino());
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("Native evidence exceeds its byte budget".into());
    }
    Ok((bytes, identity))
}

pub fn event(receipt: &Receipt) -> Result<EndpointEvent> {
    receipt.validate(now_ms())?;
    let detection = receipt.verdict.as_ref().and_then(|v| v.detection.clone());
    let event = EndpointEvent {
        id: protocol::hash(format!("native-authorization-v1:{}", receipt.id).as_bytes()),
        time_ms: receipt.time_ms,
        kind: if detection.is_some() {
            "malware"
        } else {
            "agent_error"
        }
        .into(),
        path: receipt.path.clone(),
        sha256: receipt
            .verdict
            .as_ref()
            .map(|v| v.sha256.clone())
            .unwrap_or_default(),
        detection: detection.unwrap_or_default(),
        detail: serde_json::to_string(receipt)?,
        telemetry: None,
    };
    event.validate(now_ms())?;
    Ok(event)
}

fn cleanup_committed(store: &Store, directory: &Path) -> Result<()> {
    let ids = store
        .connection
        .prepare("SELECT id FROM native_receipt_transfers ORDER BY rowid LIMIT 64")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for id in ids {
        if !receipt::hex_id(&id) {
            return Err("Invalid durable native transfer identity".into());
        }
        match fs::symlink_metadata(directory.join(format!("{id}.json"))) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                File::open(directory)?.sync_all()?;
                store
                    .connection
                    .execute("DELETE FROM native_receipt_transfers WHERE id=?1", [id])?;
            }
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
    }
    Ok(())
}

pub fn collect(store: &Store) -> Result<()> {
    let native = store.directory.join("protection/native");
    coverage::collect(store, &native)?;
    let directory = native.join("verdicts");
    match fs::symlink_metadata(&directory) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    // Canonicalize the already-checked parent only after rejecting substitutions.
    private_path(&directory, true)?;
    let native = native.canonicalize()?;
    let directory = native.join("verdicts");
    store.connection.execute_batch("CREATE TABLE IF NOT EXISTS native_receipt_transfers(id TEXT PRIMARY KEY,sha256 TEXT NOT NULL);")?;
    cleanup_committed(store, &directory)?;
    let mut paths = Vec::<PathBuf>::new();
    for (index, entry) in fs::read_dir(&directory)?.enumerate() {
        if index >= LIMIT {
            return Err("Native receipt directory exceeds its record budget".into());
        }
        let path = entry?.path();
        if path.extension().is_some_and(|s| s == "pending") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("Invalid native receipt name")?;
        if path.extension().is_none_or(|s| s != "json") || !receipt::hex_id(id) {
            return Err("Invalid native receipt name or unsupported legacy receipt".into());
        }
        paths.push(path);
    }
    paths.sort();
    for path in paths.into_iter().take(64) {
        let (bytes, identity) = read_private(&path, MAX_RECEIPT)?;
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        receipt.validate(now_ms())?;
        if path.file_stem().and_then(|s| s.to_str()) != Some(receipt.id.as_str()) {
            return Err("Native receipt identity differs from its file name".into());
        }
        let (policy, _) = read_private(
            &native
                .join("policies")
                .join(format!("{}.json", receipt.policy_sha256)),
            65536,
        )?;
        let policy: Policy = serde_json::from_slice(&policy)?;
        if policy.state != native {
            return Err("Native policy belongs to another endpoint state".into());
        }
        receipt.validate_policy(&policy, now_ms())?;
        let event = event(&receipt)?;
        let raw = serde_json::to_string(&event)?;
        let digest = protocol::hash(&bytes);
        let tx = store.connection.unchecked_transaction()?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT sha256 FROM native_receipt_transfers WHERE id=?1",
                [&receipt.id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            if previous != digest {
                return Err("Native receipt changed after its durable transfer".into());
            }
        } else {
            let count: usize =
                tx.query_row("SELECT count(*) FROM native_receipt_transfers", [], |r| {
                    r.get(0)
                })?;
            if count >= LIMIT {
                return Err("Native transfer journal is full".into());
            }
            let existing: Option<String> = tx
                .query_row("SELECT payload FROM outbox WHERE id=?1", [&event.id], |r| {
                    r.get(0)
                })
                .optional()?;
            if let Some(existing) = existing {
                if existing != raw {
                    return Err("Native receipt conflicts with an outbox observation".into());
                }
            } else {
                store.enqueue(&event)?;
            }
            tx.execute(
                "INSERT INTO native_receipt_transfers VALUES(?1,?2)",
                params![receipt.id, digest],
            )?;
        }
        tx.commit()?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || (metadata.dev(), metadata.ino()) != identity {
            return Err("Native receipt was replaced during transfer".into());
        }
        fs::remove_file(&path)?;
        File::open(&directory)?.sync_all()?;
        store.connection.execute(
            "DELETE FROM native_receipt_transfers WHERE id=?1",
            [receipt.id],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
