//! The producer keeps a cumulative checkpoint; the endpoint atomically records
//! each observed immutable revision and its outbox event. Intermediate revisions
//! may be coalesced, but a full outbox cannot consume/reset the producer's totals.
use super::*;
use athernex_endpoint_native::coverage::{self, Evidence, Snapshot};

pub(super) fn collect(store: &Store, native: &Path) -> Result<()> {
    store.connection.execute_batch("CREATE TABLE IF NOT EXISTS native_coverage_transfer(singleton INTEGER PRIMARY KEY CHECK(singleton=1),payload TEXT NOT NULL);")?;
    let source = native.join(coverage::FILE);
    let bytes = match fs::symlink_metadata(&source) {
        Ok(_) => Some(read_private(&source, coverage::MAX_BYTES)?.0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    let previous: Option<String> = tx
        .query_row(
            "SELECT payload FROM native_coverage_transfer WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let Some(bytes) = bytes else {
        if previous.is_some() {
            return Err("Previously observed native coverage checkpoint is missing".into());
        }
        return Ok(());
    };
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    snapshot.validate(now_ms())?;
    let evidence = &snapshot.evidence;
    let (policy, _) = read_private(
        &native
            .join("policies")
            .join(format!("{}.json", evidence.policy_sha256)),
        65536,
    )?;
    let policy: Policy = serde_json::from_slice(&policy)?;
    policy.validate()?;
    if policy.state != native.canonicalize()?
        || receipt::policy_hash(&policy)? != evidence.policy_sha256
    {
        return Err("Native coverage belongs to another policy or endpoint".into());
    }
    if let Some(previous) = previous {
        let previous: Evidence = serde_json::from_str(&previous)?;
        previous.validate(now_ms())?;
        evidence.follows(&previous)?;
        if evidence == &previous {
            return Ok(());
        }
    }
    let event = EndpointEvent {
        id: protocol::hash(
            format!(
                "native-coverage-v1:{}:{}",
                evidence.lineage, evidence.revision
            )
            .as_bytes(),
        ),
        time_ms: evidence.changed_ms,
        kind: if evidence.incomplete() {
            "agent_error"
        } else {
            "inventory"
        }
        .into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        telemetry: None,
        detail: serde_json::to_string(&serde_json::json!({
            "native_authorization_coverage": evidence,
            "coverage_incomplete": evidence.incomplete(),
            "scope": "Sampled cumulative lineage totals can include earlier policies; the policy hash binds the current session. Intermediate revisions may be coalesced. Restart tails and subscription intervals are unobserved. This is not proof of prevention."
        }))?,
    };
    event.validate(now_ms())?;
    let raw = serde_json::to_string(&event)?;
    let existing: Option<String> = tx
        .query_row("SELECT payload FROM outbox WHERE id=?1", [&event.id], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(existing) = existing {
        if existing != raw {
            return Err("Native coverage conflicts with a queued observation".into());
        }
    } else {
        store.enqueue(&event)?;
    }
    tx.execute("INSERT INTO native_coverage_transfer VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET payload=excluded.payload", [serde_json::to_string(evidence)?])?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests;
