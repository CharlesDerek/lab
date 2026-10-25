//! Approved response work uses a supervised helper and the private native broker.
use crate::{now_ms, secret, Config, Result, Store};
use athernex_endpoint_native::{broker, child, health, scanner};
use athernex_endpoint_protocol::{hash, hex_id, EndpointEvent};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const MAX_REPORT: usize = 1024 * 1024;
const MAX_BYTES: u64 = 1024 * 1024 * 1024;
#[derive(Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Scan,
    Hash,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: u32,
    nonce: String,
    operation: Operation,
    state: PathBuf,
    roots: Vec<PathBuf>,
    path: PathBuf,
    timeout_secs: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Detection {
    path: PathBuf,
    sha256: String,
    detection: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: u32,
    nonce: String,
    request_sha256: String,
    path: PathBuf,
    files: u64,
    bytes: u64,
    skipped: u64,
    #[serde(default)]
    health_samples: u64,
    sha256: Option<String>,
    detections: Vec<Detection>,
}
fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|p| !p.is_empty() && p.len() <= 4096 && !p.contains(char::is_control))
        && !path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}
impl Plan {
    fn validate(&self) -> Result<()> {
        if self.schema != 1
            || !hex_id(&self.nonce)
            || !(1..=600).contains(&self.timeout_secs)
            || self.roots.is_empty()
            || self.roots.len() > 16
            || !self
                .roots
                .iter()
                .chain([&self.path, &self.state])
                .all(|p| valid_path(p))
        {
            return Err("Invalid native response worker request".into());
        }
        Ok(())
    }
}
fn state(store: &Store) -> Result<PathBuf> {
    Ok(store.directory.canonicalize()?.join("protection/native"))
}
pub fn configured(store: &Store) -> Result<bool> {
    broker::configured(&state(store)?)
}
fn run(
    config: &Config,
    store: &Store,
    path: &Path,
    timeout: u64,
    operation: Operation,
) -> Result<Report> {
    let plan = Plan {
        schema: 1,
        nonce: secret()?,
        operation,
        state: state(store)?,
        roots: config.scan_roots.clone(),
        path: path.into(),
        timeout_secs: timeout,
    };
    plan.validate()?;
    let input = serde_json::to_vec(&plan)?;
    let (code, output) = child::run_with_input(
        Command::new(std::env::current_exe()?)
            .arg("native-response-worker")
            .arg(std::process::id().to_string()),
        Duration::from_secs(timeout),
        MAX_REPORT,
        &input,
    )?;
    if code != 0 {
        return Err(format!(
            "Native response helper failed ({code}): {}",
            String::from_utf8_lossy(&output)
                .chars()
                .take(1024)
                .collect::<String>()
        )
        .into());
    }
    let report: Report = serde_json::from_slice(&output)?;
    validate_report(&plan, &input, &report)?;
    Ok(report)
}
fn validate_report(plan: &Plan, input: &[u8], report: &Report) -> Result<()> {
    if report.schema != 1
        || report.nonce != plan.nonce
        || report.request_sha256 != hash(input)
        || !valid_path(&report.path)
        || report.files.saturating_add(report.skipped) > 4096
        || report.bytes > MAX_BYTES
        || (report.detections.len() as u64).saturating_add(report.health_samples) > report.files
        || report.detections.iter().any(|d| {
            !valid_path(&d.path)
                || !d.path.starts_with(&report.path)
                || !hex_id(&d.sha256)
                || !athernex_endpoint_protocol::text(&d.detection, 256)
        })
        || match plan.operation {
            Operation::Scan => report.sha256.is_some(),
            Operation::Hash => {
                report.files != 1
                    || report.skipped != 0
                    || report.health_samples != 0
                    || !report.detections.is_empty()
                    || report.sha256.as_ref().is_none_or(|s| !hex_id(s))
            }
        }
    {
        return Err("Native response helper returned an invalid or unrelated result".into());
    }
    Ok(())
}
pub fn hash_file(config: &Config, store: &Store, path: &Path, timeout: u64) -> Result<String> {
    run(config, store, path, timeout, Operation::Hash)?
        .sha256
        .ok_or_else(|| "Native helper omitted its file hash".into())
}
pub fn execute_scan(config: &Config, store: &Store, path: &Path, timeout: u64) -> Result<String> {
    let report = run(config, store, path, timeout, Operation::Scan)?;
    let summary = serde_json::to_string(
        &serde_json::json!({"files":report.files,"bytes":report.bytes,"skipped_special":report.skipped,"health_samples":report.health_samples,"detections":report.detections.len(),"backend":"native-response-broker"}),
    )?;
    let mut events = Vec::new();
    for d in report.detections {
        events.push(EndpointEvent { telemetry: None, id: secret()?, time_ms: now_ms(), kind: "malware".into(), path: d.path.to_str().ok_or("Native scan paths must be UTF-8")?.into(), sha256: d.sha256, detection: d.detection,
            detail: "The local native response broker scanned and hashed these exact bytes. Quarantine rechecks the current file against that hash.".into() });
    }
    events.push(EndpointEvent {
        telemetry: None,
        id: secret()?,
        time_ms: now_ms(),
        kind: "scan".into(),
        path: report
            .path
            .to_str()
            .ok_or("Native scan paths must be UTF-8")?
            .into(),
        sha256: String::new(),
        detection: String::new(),
        detail: summary.clone(),
    });
    let tx = store.connection.unchecked_transaction()?;
    for event in &events {
        store.enqueue(event)?;
    }
    tx.commit()?;
    Ok(summary)
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "Native response scan deadline elapsed".into())
}
fn scoped(path: &Path, roots: &[PathBuf]) -> Result<PathBuf> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err("Native response cannot follow a target symlink".into());
    }
    let canonical = path.canonicalize()?;
    if !roots.iter().any(|r| canonical.starts_with(r)) {
        return Err("Native response path is outside the current local action roots".into());
    }
    Ok(canonical)
}
fn work(plan: &Plan, input: &[u8]) -> Result<Report> {
    let deadline = Instant::now() + Duration::from_secs(plan.timeout_secs);
    let roots = plan
        .roots
        .iter()
        .map(|p| p.canonicalize())
        .collect::<std::io::Result<Vec<_>>>()?;
    let path = scoped(&plan.path, &roots)?;
    let mut report = Report {
        schema: 1,
        nonce: plan.nonce.clone(),
        request_sha256: hash(input),
        path: path.clone(),
        files: 0,
        bytes: 0,
        skipped: 0,
        health_samples: 0,
        sha256: None,
        detections: Vec::new(),
    };
    if plan.operation == Operation::Hash {
        let verdict = broker::query(&plan.state, &path, remaining(deadline)?)?;
        report.files = 1;
        report.bytes = verdict.bytes;
        report.sha256 = Some(verdict.sha256);
        return Ok(report);
    }
    let mut stack = vec![(path, 0usize)];
    let health = health::scan_manifest(&plan.state)?;
    let mut visited = 0;
    let mut detection_bytes = 0;
    while let Some((path, depth)) = stack.pop() {
        remaining(deadline)?;
        visited += 1;
        if visited > 4096 || depth > 32 {
            return Err("Native response scan exceeds 4096 entries or 32 directory levels".into());
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !(metadata.is_dir() || metadata.is_file()) {
            report.skipped += 1;
            continue;
        }
        let path = scoped(&path, &roots)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                if visited + stack.len() >= 4096 {
                    return Err("Native response scan exceeds its entry budget".into());
                }
                stack.push((entry?.path(), depth + 1));
            }
            continue;
        }
        let verdict = broker::query_limited(
            &plan.state,
            &path,
            remaining(deadline)?,
            MAX_BYTES.saturating_sub(report.bytes),
        )?;
        report.files += 1;
        report.bytes += verdict.bytes;
        if health
            .as_ref()
            .is_some_and(|h| h.is_scan_probe(&path, &scanner::identity(&metadata), &verdict))
        {
            report.health_samples += 1;
            continue;
        }
        if let Some(detection) = verdict.detection {
            let observation = Detection {
                path,
                sha256: verdict.sha256,
                detection,
            };
            detection_bytes += serde_json::to_vec(&observation)?.len() + 1;
            if detection_bytes > MAX_REPORT - 32768 {
                return Err("Native scan detections exceed the report budget".into());
            }
            report.detections.push(observation);
        }
    }
    remaining(deadline)?;
    Ok(report)
}
/// Internal executable entry point. It receives no server credentials or SQLite
/// handle, and emits a complete read-only result only after successful work.
pub fn worker_main(parent: u32) -> Result<()> {
    child::guard_parent(parent)?;
    let mut input = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut input)?;
    if input.len() > 65536 {
        return Err("Native response request exceeds its input budget".into());
    }
    let plan: Plan = serde_json::from_slice(&input)?;
    plan.validate()?;
    let report = work(&plan, &input)?;
    let output = serde_json::to_vec(&report)?;
    if output.len() > MAX_REPORT {
        return Err("Native response result exceeds its output budget".into());
    }
    std::io::stdout().write_all(&output)?;
    Ok(())
}
