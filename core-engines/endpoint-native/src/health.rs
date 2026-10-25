//! Live native prevention health. No syscall error or running process alone can
//! establish health: every root needs clean controls and delivered, exact native
//! detection evidence for open, exec and mapping through a preopened descriptor.
use crate::{
    broker, child,
    probe::{self, Attempt, Operation},
    receipt::{self, Receipt},
    scanner,
    service::{self, now_ms},
    Identity, Policy, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
mod files;
pub use files::{prepare, Manifest, Prepared};

const CYCLE_MS: u64 = 15_000;
const MAX_AGE_MS: u64 = 45_000;
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn nonce() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn operations() -> [Operation; 3] {
    [Operation::Open, Operation::Exec, Operation::Mmap]
}
fn name(op: &Operation) -> &'static str {
    match op {
        Operation::Open => "open",
        Operation::Exec => "exec",
        Operation::Mmap => "mmap",
    }
}
fn indices(op: &Operation) -> (usize, usize) {
    if *op == Operation::Exec {
        (2, 3)
    } else {
        (0, 1)
    }
}

pub fn load_manifest(policy: &Policy) -> Result<Option<Manifest>> {
    let path = policy.state.join("health/manifest.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let manifest: Manifest = service::read(&path, 262144)?;
    manifest.validate(policy)?;
    Ok(Some(manifest))
}
/// Cache known harmless sample identities for an approved scan. Other changed
/// samples must not prevent scanning real threats. Each candidate still needs
/// its own exact metadata and actual broker hash/verdict match.
pub fn scan_manifest(state: &Path) -> Result<Option<Manifest>> {
    let path = state.join("health/manifest.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let manifest: Manifest = service::read(&path, 262144)?;
    if manifest.schema != 1
        || !receipt::hex_id(&manifest.session)
        || !receipt::hex_id(&manifest.plan_sha256)
        || manifest.policy_sha256 != broker::bound_policy_hash(state)?
        || manifest.roots.is_empty()
        || manifest.roots.len() > 16
    {
        return Err("Native scan health manifest does not match the current broker".into());
    }
    let folder = format!(
        ".athernex-native-check-{}",
        hash(state.as_os_str().as_encoded_bytes())
    );
    for root in &manifest.roots {
        if !root.root.path.is_absolute() || root.directory.path != root.root.path.join(&folder) {
            return Err("Invalid native health scan scope".into());
        }
        for (i, sample) in root.samples.iter().enumerate() {
            let detection = match i {
                1 => Some(files::TEXT_DETECTION),
                3 => Some(files::IMAGE_DETECTION),
                _ => None,
            };
            if sample.path != root.directory.path.join(files::NAMES[i])
                || !receipt::hex_id(&sample.sha256)
                || sample.detection.as_deref() != detection
                || sample.identity.size == 0
                || sample.identity.size > 16 * 1024 * 1024
            {
                return Err("Invalid native health scan sample".into());
            }
        }
    }
    Ok(Some(manifest))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    schema: u32,
    nonce: String,
    outcome: String,
    errno: Option<i32>,
}
fn attempt(
    helper: &Path,
    sample: &files::Sample,
    descriptor: &File,
    op: &Operation,
    denied: bool,
    deadline: Instant,
) -> Result<Attempt> {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(3));
    if remaining.is_zero() {
        return Err("Native health cycle deadline elapsed".into());
    }
    let nonce = nonce()?;
    let mut command = Command::new(helper);
    command.env_clear();
    let fd = if *op == Operation::Mmap {
        child::inherit_lease(&mut command, descriptor)?.to_string()
    } else {
        "-".into()
    };
    command
        .args(["probe-owned", &std::process::id().to_string(), name(op)])
        .arg(&sample.path)
        .args([&fd, &nonce]);
    let (code, output) = child::run(&mut command, remaining, 8192)?;
    let lines = std::str::from_utf8(&output)?.lines().collect::<Vec<_>>();
    if code != if denied { 10 } else { 0 } || lines.is_empty() {
        return Err(format!("Native {} health probe returned {code}", name(op)).into());
    }
    let attempt: Attempt = serde_json::from_str(lines[0])?;
    if attempt.schema != 1
        || attempt.nonce != nonce
        || attempt.path != sample.path
        || attempt.identity != sample.identity
        || attempt.operation != *op
        || attempt.actor.uid != unsafe { libc::geteuid() }
        || attempt.actor.pid == 0
    {
        return Err("Native health probe changed its request identity".into());
    }
    if !denied && *op == Operation::Exec {
        if lines.len() != 1 {
            return Err("Unexpected executable health output".into());
        }
    } else {
        if lines.len() != 2 {
            return Err("Incomplete native health outcome".into());
        }
        let outcome: Outcome = serde_json::from_str(lines[1])?;
        if outcome.schema != 1
            || outcome.nonce != nonce
            || outcome.outcome != if denied { "denied" } else { "allowed" }
            || (denied && !matches!(outcome.errno, Some(libc::EACCES | libc::EPERM)))
            || (!denied && outcome.errno.is_some())
        {
            return Err("Native health outcome does not match the operation".into());
        }
    }
    Ok(attempt)
}
pub fn baseline(prepared: &Prepared, policy: &Policy, helper: &Path) -> Result<()> {
    prepared.manifest.validate(policy)?;
    // A blocked synthetic file must also work before this adapter activates;
    // noexec mounts, another AV, signing failures and ACLs cannot prove health.
    let deadline = Instant::now() + Duration::from_secs(60);
    for (root, handles) in prepared.manifest.roots.iter().zip(&prepared.descriptors) {
        for op in operations() {
            let (clean, blocked) = indices(&op);
            for index in [clean, blocked] {
                attempt(
                    helper,
                    &root.samples[index],
                    &handles[index],
                    &op,
                    false,
                    deadline,
                )?;
            }
        }
    }
    prepared.manifest.validate(policy)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub checked_ms: u64,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    root: usize,
    operation: Operation,
    clean: Attempt,
    blocked: Attempt,
    receipt: Receipt,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    schema: u32,
    manifest_sha256: String,
    started_ms: u64,
    checked_ms: u64,
    supervisor_pid: u32,
    adapter_pid: u32,
    boot: String,
    checks: Vec<Check>,
}
fn validate_proof(
    proof: &Proof,
    manifest: &Manifest,
    plan: &service::Plan,
    supervisor: u32,
    adapter: u32,
    now: u64,
) -> Result<()> {
    manifest.validate(&plan.policy)?;
    if manifest.plan_sha256 != plan.digest()?
        || proof.schema != 1
        || proof.manifest_sha256 != hash(&serde_json::to_vec(manifest)?)
        || proof.supervisor_pid != supervisor
        || proof.adapter_pid != adapter
        || proof.boot != service::boot()?
        || proof.started_ms == 0
        || proof.checked_ms < proof.started_ms
        || proof.checked_ms - proof.started_ms > CYCLE_MS
        || proof.checked_ms > now.saturating_add(1000)
        || now.saturating_sub(proof.checked_ms) > MAX_AGE_MS
        || proof.checks.len() != manifest.roots.len() * 3
    {
        return Err(
            "Native blocking proof is stale, incomplete or belongs to another service".into(),
        );
    }
    for (i, check) in proof.checks.iter().enumerate() {
        let root = i / 3;
        let operation = &operations()[i % 3];
        let (clean, bad) = indices(operation);
        let samples = &manifest.roots[root].samples;
        if check.root != root || check.operation != *operation {
            return Err("Native blocking proof omitted or repeated an operation".into());
        }
        for (attempt, sample) in [
            (&check.clean, &samples[clean]),
            (&check.blocked, &samples[bad]),
        ] {
            if attempt.schema != 1
                || !receipt::hex_id(&attempt.nonce)
                || attempt.actor.pid == 0
                || attempt.actor.uid != manifest.owner_uid
                || attempt.path != sample.path
                || attempt.identity != sample.identity
                || attempt.operation != *operation
                || attempt.time_ms < proof.started_ms
                || attempt.time_ms > proof.checked_ms
            {
                return Err("Native blocking proof changed a sample, actor or operation".into());
            }
        }
        probe::validate_denial_at(
            &check.blocked,
            &check.receipt,
            &plan.policy,
            &samples[bad].sha256,
            samples[bad]
                .detection
                .as_deref()
                .ok_or("Missing probe detection")?,
            proof.checked_ms,
        )?;
    }
    Ok(())
}
fn native_status(plan: &service::Plan, adapter: u32) -> Result<()> {
    let status: serde_json::Value =
        service::read(&plan.policy.state.join("native-status.json"), 65536)?;
    let checked = status["checked_ms"]
        .as_u64()
        .ok_or("Missing native status time")?;
    let coverage = crate::coverage::load(&plan.policy.state)?;
    coverage.check_live(&plan.policy, adapter, now_ms())?;
    if status["schema"] != 1
        || status["coverage_current"] != true
        || status["coverage_session"] != coverage.evidence.session
        || status["pidversion"].as_i64() != Some(coverage.evidence.pidversion as i64)
        || coverage.sample != crate::coverage::Loss::default()
        || status["coverage_revision"]
            .as_u64()
            .is_none_or(|revision| revision > coverage.evidence.revision)
        || status["pid"].as_u64() != Some(adapter as u64)
        || status["scope_valid"] != true
        || status["roots"] != serde_json::to_value(&plan.policy.roots)?
        || status["scanner_uid"] != plan.policy.scanner_uid
        || checked > now_ms().saturating_add(1000)
        || now_ms().saturating_sub(checked) > 3000
        || ["response_errors", "event_gaps", "evidence_dropped"]
            .iter()
            .any(|key| status[*key].as_u64() != Some(0))
    {
        return Err("Native authorization status has changed, expired or lost evidence".into());
    }
    Ok(())
}
fn diagnostic_paths(state: &Path) -> Result<Vec<PathBuf>> {
    let directory = state.join("probe-verdicts");
    broker::trusted(&directory, true)?;
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(&directory)?.enumerate() {
        if index >= 512 {
            return Err("Native health diagnostic journal is full".into());
        }
        let path = entry?.path();
        if path.extension().is_some_and(|s| s == "pending") {
            continue;
        }
        if path.extension().is_none_or(|s| s != "json")
            || !path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(receipt::hex_id)
        {
            return Err("Invalid native health diagnostic filename".into());
        }
        paths.push(path);
    }
    Ok(paths)
}
fn receipt_for(
    plan: &service::Plan,
    attempt: &Attempt,
    sample: &files::Sample,
    deadline: Instant,
) -> Result<Receipt> {
    let until = deadline.min(Instant::now() + Duration::from_secs(2));
    loop {
        for path in diagnostic_paths(&plan.policy.state)? {
            let receipt: Receipt = service::read(&path, receipt::MAX_RECEIPT as u64)?;
            receipt.validate(now_ms())?;
            if path.file_stem().and_then(|s| s.to_str()) != Some(receipt.id.as_str()) {
                return Err("Native health receipt filename mismatch".into());
            }
            if receipt.actor.pid == attempt.actor.pid
                && receipt.actor.pidversion == attempt.actor.pidversion
                && receipt.path == attempt.path.to_string_lossy()
                && receipt.operation == name(&attempt.operation)
            {
                probe::validate_denial(
                    attempt,
                    &receipt,
                    &plan.policy,
                    &sample.sha256,
                    sample
                        .detection
                        .as_deref()
                        .ok_or("Missing native probe signature")?,
                )?;
                fs::remove_file(&path)?;
                File::open(path.parent().unwrap())?.sync_all()?;
                return Ok(receipt);
            }
            // This separate journal contains only manifest-matched harmless
            // probes. Old interrupted attempts can expire without touching the
            // durable malware inbox or its receipt transfer contract.
            if now_ms().saturating_sub(receipt.time_ms) > 60_000 {
                fs::remove_file(path)?;
            }
        }
        if Instant::now() >= until {
            return Err("Native denial has no matching delivered detection receipt".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}
fn cycle(prepared: &Prepared, plan: &service::Plan, helper: &Path, adapter: u32) -> Result<Proof> {
    prepared.manifest.validate(&plan.policy)?;
    native_status(plan, adapter)?;
    let started_ms = now_ms();
    let deadline = Instant::now() + Duration::from_millis(CYCLE_MS);
    let mut checks = Vec::new();
    for (index, (root, handles)) in prepared
        .manifest
        .roots
        .iter()
        .zip(&prepared.descriptors)
        .enumerate()
    {
        for operation in operations() {
            let (good, bad) = indices(&operation);
            let clean = attempt(
                helper,
                &root.samples[good],
                &handles[good],
                &operation,
                false,
                deadline,
            )?;
            let blocked = attempt(
                helper,
                &root.samples[bad],
                &handles[bad],
                &operation,
                true,
                deadline,
            )?;
            let receipt = receipt_for(plan, &blocked, &root.samples[bad], deadline)?;
            checks.push(Check {
                root: index,
                operation,
                clean,
                blocked,
                receipt,
            });
        }
    }
    native_status(plan, adapter)?;
    let proof = Proof {
        schema: 1,
        manifest_sha256: hash(&serde_json::to_vec(&prepared.manifest)?),
        started_ms,
        checked_ms: now_ms(),
        supervisor_pid: std::process::id(),
        adapter_pid: adapter,
        boot: service::boot()?,
        checks,
    };
    validate_proof(
        &proof,
        &prepared.manifest,
        plan,
        std::process::id(),
        adapter,
        now_ms(),
    )?;
    Ok(proof)
}
pub fn observe(
    plan: &service::Plan,
    reference: &Reference,
    supervisor: u32,
    adapter: u32,
) -> Result<()> {
    if !receipt::hex_id(&reference.sha256) {
        return Err("Invalid native proof reference".into());
    }
    let manifest = load_manifest(&plan.policy)?.ok_or("Native health manifest is missing")?;
    let proof: Proof = service::read(
        &plan
            .policy
            .state
            .join("health/proofs")
            .join(format!("{}.json", reference.sha256)),
        262144,
    )?;
    if proof.checked_ms != reference.checked_ms
        || hash(&serde_json::to_vec(&proof)?) != reference.sha256
    {
        return Err("Native health proof changed since publication".into());
    }
    validate_proof(&proof, &manifest, plan, supervisor, adapter, now_ms())?;
    native_status(plan, adapter)
}
fn publish_proof(state: &Path, proof: &Proof) -> Result<Reference> {
    let directory = state.join("health/proofs");
    broker::trusted(&directory, true)?;
    let mut retained = 0;
    for (index, entry) in fs::read_dir(&directory)?.enumerate() {
        if index >= 64 {
            return Err("Native health proof retention budget exhausted".into());
        }
        let path = entry?.path();
        if path.extension().is_some_and(|s| s == "pending") {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or("Invalid pending health proof")?;
            let (id, nonce) = stem
                .rsplit_once('.')
                .ok_or("Invalid pending health proof")?;
            broker::trusted(&path, true)?;
            let metadata = scanner::open_file(&path)?.metadata()?;
            use std::os::unix::fs::MetadataExt;
            if !receipt::hex_id(id)
                || nonce.len() != 32
                || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
                || metadata.nlink() != 1
                || metadata.len() > 262144
            {
                return Err("Invalid pending health proof".into());
            }
            // The retained service lease excludes another proof writer. This
            // is an uncommitted file left by an interrupted publication.
            fs::remove_file(path)?;
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("Invalid native proof filename")?;
        if path.extension().is_none_or(|s| s != "json") || !receipt::hex_id(id) {
            return Err("Invalid native proof filename".into());
        }
        let previous: Proof = service::read(&path, 262144)?;
        if hash(&serde_json::to_vec(&previous)?) != id {
            return Err("Retained native health proof changed".into());
        }
        if now_ms().saturating_sub(previous.checked_ms) > MAX_AGE_MS + 30_000 {
            fs::remove_file(path)?;
        } else {
            retained += 1;
        }
    }
    if retained >= 63 {
        return Err("Native health proof retention budget exhausted".into());
    }
    let bytes = serde_json::to_vec(proof)?;
    let sha256 = hash(&bytes);
    // Readers may still hold the previous status reference. Immutable names
    // keep it valid while a new proof and then its status are published.
    service::write(&directory.join(format!("{sha256}.json")), &bytes, 0o600)?;
    Ok(Reference {
        checked_ms: proof.checked_ms,
        sha256,
    })
}
pub struct Watch {
    stopped: Arc<AtomicBool>,
    result: Arc<Mutex<std::result::Result<Reference, String>>>,
}
impl Watch {
    pub fn start(
        prepared: Prepared,
        plan: service::Plan,
        helper: PathBuf,
        adapter: u32,
        leases: Vec<File>,
    ) -> Result<Self> {
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let result = Arc::new(Mutex::new(Err(
            "Awaiting complete native blocking proof".into()
        )));
        let output = result.clone();
        thread::Builder::new()
            .name("athernex-native-health".into())
            .spawn(move || {
                // Retain service/engine ownership if a filesystem operation stalls;
                // the main loop can still publish degraded/stale health.
                let _leases = leases;
                while !stop.load(Ordering::Relaxed) {
                    let checked = (|| -> Result<Reference> {
                        let proof = cycle(&prepared, &plan, &helper, adapter)?;
                        if stop.load(Ordering::Relaxed) {
                            return Err("Native health stopped".into());
                        }
                        publish_proof(&plan.policy.state, &proof)
                    })()
                    .map_err(|e| e.to_string().chars().take(512).collect());
                    let delay = if checked.is_ok() { 30 } else { 5 };
                    if let Ok(mut value) = output.lock() {
                        *value = checked;
                    } else {
                        return;
                    }
                    let next = Instant::now() + Duration::from_secs(delay);
                    while Instant::now() < next && !stop.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            })?;
        Ok(Self { stopped, result })
    }
    pub fn current(&self) -> std::result::Result<Reference, String> {
        self.result
            .lock()
            .map_err(|_| "Native health worker failed".to_string())?
            .clone()
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
