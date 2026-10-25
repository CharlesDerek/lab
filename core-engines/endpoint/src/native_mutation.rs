//! The management process owns durable intent and receipt admission. Filesystem
//! mutations run in an independently bounded worker with no database credentials.
#[cfg(windows)]
use crate::windows_job as child;
use crate::{now_ms, secret, Config, Process, Result, Store};
#[cfg(not(windows))]
use athernex_endpoint_native::child;
use athernex_endpoint_native::mutation::Verifier;
use athernex_endpoint_native::mutation::{self, Intent, Operation, Outcome, Report};
use athernex_endpoint_protocol::{hex_id, Action, Command, EndpointEvent, Receipt};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
    time::Duration,
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    nonce: String,
    intent: Intent,
    recover: bool,
    timeout_secs: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    nonce: String,
    report: Report,
}
fn invoke(intent: &Intent, recover: bool, timeout: u64) -> Result<Report> {
    let request = Request {
        nonce: secret()?,
        intent: intent.clone(),
        recover,
        timeout_secs: timeout,
    };
    let input = serde_json::to_vec(&request)?;
    let (code, output) = child::run_with_input(
        Process::new(std::env::current_exe()?)
            .arg("native-mutation-worker")
            .arg(std::process::id().to_string()),
        Duration::from_secs(timeout),
        65536,
        &input,
    )?;
    if code != 0 {
        return Err(format!(
            "Native mutation worker failed ({code}): {}",
            String::from_utf8_lossy(&output)
                .chars()
                .take(1024)
                .collect::<String>()
        )
        .into());
    }
    let reply: Reply = serde_json::from_slice(&output)?;
    if reply.nonce != request.nonce
        || reply.report.intent_sha256 != intent.digest()?
        || !reply.report.path.is_absolute()
        || reply.report.detail.len() > 4096
        || reply.report.finished_ms > now_ms().saturating_add(60000)
    {
        return Err("Invalid native mutation worker result".into());
    }
    Ok(reply.report)
}
pub fn require_resolved(store: &Store) -> Result<()> {
    let pending: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_mutations WHERE state='pending')",
        [],
        |r| r.get(0),
    )?;
    if pending {
        return Err(
            "An earlier native mutation still requires recovery; filesystem response is paused"
                .into(),
        );
    }
    Ok(())
}
fn output(intent: &Intent, report: &Report) -> String {
    if report.outcome != Outcome::Completed {
        return format!("Native mutation interrupted: {}", report.detail);
    }
    let result = match intent.operation {
        Operation::Quarantine => format!(
            "Quarantined {}; restore reference {}",
            intent.sha256, intent.quarantine_id
        ),
        Operation::Restore => format!("Restored {}", report.path.display()),
    };
    if report.cleanup_pending {
        format!("{result}; private cleanup needs review")
    } else {
        result
    }
}
fn admit(store: &Store, intent: &Intent, report: &Report, recovery: bool) -> Result<String> {
    let result = output(intent, report);
    let tx = store.connection.unchecked_transaction()?;
    let state = match (&intent.operation, &report.outcome) {
        (Operation::Quarantine, Outcome::Completed) => "quarantined",
        (Operation::Restore, Outcome::Completed) => "restored",
        (Operation::Restore, Outcome::Unconfirmed) => "quarantined",
        (_, Outcome::Unconfirmed) => "failed",
        (_, Outcome::Review) => "review",
    };
    tx.execute(
        "UPDATE quarantine SET path=?1,state=?2 WHERE id=?3",
        params![report.path.to_string_lossy(), state, intent.quarantine_id],
    )?;
    tx.execute(
        "UPDATE native_mutations SET state='finished',report=?1 WHERE command_id=?2",
        params![serde_json::to_string(report)?, intent.command_id],
    )?;
    let prior: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT payload,receipt FROM work WHERE id=?1",
            [&intent.command_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((payload, prior)) = prior {
        if prior.is_none() {
            let command: Command = serde_json::from_str(&payload)?;
            let receipt = Receipt {
                command_id: command.id,
                action_hash: command.action_hash,
                outcome: if report.outcome == Outcome::Completed {
                    "succeeded"
                } else {
                    "interrupted"
                }
                .into(),
                output: result.clone(),
                finished_ms: now_ms(),
            };
            store.save_receipt(&receipt)?;
        } else if recovery {
            // Keep any already-issued execution receipt immutable. The later
            // filesystem observation is separately visible in durable evidence.
            store.enqueue(&EndpointEvent {id:secret()?,telemetry:None,time_ms:now_ms(),kind:"agent_error".into(),path:report.path.to_string_lossy().into(),sha256:String::new(),detection:String::new(),detail:serde_json::json!({"native_mutation_recovery":intent.command_id,"quarantine_id":intent.quarantine_id,"outcome":report.outcome,"detail":report.detail}).to_string()})?;
        }
    }
    tx.commit()?;
    Ok(result)
}
pub fn execute(config: &Config, store: &Store, command: &Command, timeout: u64) -> Result<String> {
    let (operation, id, path, sha) = match &command.action {
        Action::Quarantine { path, sha256 } => (
            Operation::Quarantine,
            command.id.clone(),
            path.clone(),
            sha256.clone(),
        ),
        Action::Restore { quarantine_id } => {
            let (path, sha): (String, String) = store.connection.query_row(
                "SELECT path,sha256 FROM quarantine WHERE id=?1 AND state='quarantined'",
                [quarantine_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            (Operation::Restore, quarantine_id.clone(), path, sha)
        }
        _ => return Err("Unsupported native mutation".into()),
    };
    let verifier = if operation == Operation::Restore {
        Some(Verifier::Retained)
    } else {
        Some(Verifier::Local)
    };
    #[cfg(windows)]
    let verifier = if operation == Operation::Quarantine {
        Some(crate::protection::windows::response::verifier(
            &store.directory,
        )?)
    } else {
        verifier
    };
    #[cfg(not(windows))]
    let verifier = if operation == Operation::Quarantine
        && ((cfg!(target_os = "macos") && config.protection.enabled)
            || crate::protection::native_response::configured(store)?)
    {
        None
    } else {
        verifier
    };
    #[cfg(target_os = "linux")]
    let verifier = if operation == Operation::Quarantine && config.protection.enabled {
        config.protection.validate()?;
        Some(Verifier::LinuxProtected {
            uid: config.protection.engine_uid.ok_or("Missing scanner UID")?,
            gid: config.protection.engine_gid.ok_or("Missing scanner GID")?,
        })
    } else {
        verifier
    };
    let intent = Intent {
        verifier,
        schema: 1,
        command_id: command.id.clone(),
        quarantine_id: id,
        operation,
        state: store.directory.canonicalize()?,
        path: Path::new(&path).into(),
        roots: config.scan_roots.clone(),
        sha256: sha,
    };
    intent.validate()?;
    let tx = store.connection.unchecked_transaction()?;
    let count: u64 = tx.query_row("SELECT count(*) FROM native_mutations", [], |r| r.get(0))?;
    if count >= 2048 {
        return Err("Native mutation history capacity exhausted; archive requires review".into());
    }
    tx.execute("INSERT INTO native_mutations(command_id,quarantine_id,intent,state) VALUES(?1,?2,?3,'pending')",params![intent.command_id,intent.quarantine_id,serde_json::to_string(&intent)?])?;
    if intent.operation == Operation::Quarantine {
        tx.execute(
            "INSERT INTO quarantine VALUES(?1,?2,?3,'preparing')",
            params![intent.quarantine_id, path, intent.sha256],
        )?;
    } else {
        tx.execute(
            "UPDATE quarantine SET state='restoring' WHERE id=?1",
            [&intent.quarantine_id],
        )?;
    }
    tx.commit()?;
    let report = invoke(&intent, false, timeout)?;
    let result = admit(store, &intent, &report, false)?;
    if report.outcome != Outcome::Completed {
        return Err(result.into());
    }
    Ok(result)
}
pub fn recover(store: &Store) -> Result<()> {
    let rows = store
        .connection
        .prepare(
            "SELECT intent FROM native_mutations WHERE state='pending' ORDER BY rowid LIMIT 4",
        )?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for raw in rows {
        let intent: Intent = serde_json::from_str(&raw)?;
        intent.validate()?;
        if intent.state != store.directory.canonicalize()? {
            return Err("Mutation intent belongs to another endpoint state".into());
        }
        let report = invoke(&intent, true, 5)?;
        admit(store, &intent, &report, true)?;
    }
    Ok(())
}
pub fn worker_main(parent: u32) -> Result<()> {
    child::guard_parent(parent)?;
    let mut input = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut input)?;
    if input.len() > 65536 {
        return Err("Native mutation request exceeds its byte budget".into());
    }
    let request: Request = serde_json::from_slice(&input)?;
    if !hex_id(&request.nonce) || !(1..=600).contains(&request.timeout_secs) {
        return Err("Invalid native mutation request".into());
    }
    let timeout = Duration::from_secs(request.timeout_secs);
    let report = match &request.intent.verifier {
        None | Some(Verifier::Local | Verifier::Retained) => {
            mutation::apply(&request.intent, request.recover, timeout)?
        }
        #[cfg(target_os = "linux")]
        Some(Verifier::LinuxProtected { uid, gid }) => mutation::apply_with_verifier(
            &request.intent,
            request.recover,
            timeout,
            |path, identity, remaining, lease| {
                crate::protection::mutation_hash(*uid, *gid, path, identity, remaining, lease)
            },
        )?,
        #[cfg(windows)]
        Some(Verifier::WindowsProtected { session, policy }) => mutation::apply_with_verifier(
            &request.intent,
            request.recover,
            timeout,
            |path, identity, remaining, _lease| {
                crate::protection::windows::response::verify(
                    &request.intent.state,
                    session,
                    policy,
                    path,
                    identity,
                    remaining,
                )
            },
        )?,
        Some(_) => return Err("Protected reader is unavailable on this platform".into()),
    };
    let output = serde_json::to_vec(&Reply {
        nonce: request.nonce,
        report,
    })?;
    if output.len() > 65536 {
        return Err("Native mutation response exceeds its byte budget".into());
    }
    std::io::stdout().write_all(&output)?;
    Ok(())
}
