//! macOS 12+ authorization transport. OS callbacks only enqueue bounded work;
//! the creating thread owns Client and answers every retained message. File I/O
//! and journal I/O never run on either authorization response path.
use crate::{
    coverage::{self, Loss, Snapshot},
    receipt::{self, Actor, Receipt},
    scanner, Identity, Policy, Result, Scan, Verdict, CAPACITY, WORKERS,
};
use endpoint_sec::{
    sys::{es_auth_result_t, es_event_type_t},
    AuditToken, Client, Event, Message,
};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, SyncSender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
struct Counters {
    admitted: AtomicU64,
    allowed: AtomicU64,
    malware: AtomicU64,
    errors: AtomicU64,
    capacity_denials: AtomicU64,
    late_denials: AtomicU64,
    response_errors: AtomicU64,
    event_gaps: AtomicU64,
    evidence_dropped: AtomicU64,
    probe_receipts: AtomicU64,
    outstanding: AtomicUsize,
}
struct Context {
    policy: Policy,
    policy_sha256: String,
    counters: Counters,
    scope_valid: Arc<AtomicBool>,
    last_sequence: AtomicU64,
    subscribed: AtomicBool,
}
struct Pending {
    message: Message,
    scan: Scan,
    open: bool,
}
struct Work {
    id: u64,
    scan: Scan,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn respond(
    client: &mut Client<'_>,
    message: &Message,
    open: bool,
    allow: bool,
    context: &Context,
) -> bool {
    let result = if open {
        client.respond_flags_result(message, if allow { u32::MAX } else { 0 }, false)
    } else {
        client.respond_auth_result(
            message,
            if allow {
                es_auth_result_t::ES_AUTH_RESULT_ALLOW
            } else {
                es_auth_result_t::ES_AUTH_RESULT_DENY
            },
            false,
        )
    };
    if result.is_err() {
        context
            .counters
            .response_errors
            .fetch_add(1, Ordering::Relaxed);
    }
    result.is_ok()
}
// Immediate denials cannot queue a complete file receipt. Keep that evidence
// gap visible even when the authorization queue itself is exhausted.
fn deny_callback(client: &mut Client<'_>, message: &Message, open: bool, context: &Context) {
    respond(client, message, open, false, context);
    context
        .counters
        .evidence_dropped
        .fetch_add(1, Ordering::Relaxed);
}
fn bounded_identity(file: &endpoint_sec::File<'_>) -> Result<Identity> {
    let stat = file.stat();
    Ok(Identity {
        device: stat.st_dev as u64,
        inode: stat.st_ino,
        size: stat.st_size.try_into()?,
        modified_sec: stat.st_mtime,
        modified_nsec: stat.st_mtime_nsec,
        changed_sec: stat.st_ctime,
        changed_nsec: stat.st_ctime_nsec,
    })
}
fn callback(
    client: &mut Client<'_>,
    message: Message,
    context: &Context,
    sender: &SyncSender<Pending>,
) {
    if let Some(sequence) = message.global_seq_num() {
        let previous = context.last_sequence.swap(sequence, Ordering::Relaxed);
        if previous != u64::MAX && sequence != previous.saturating_add(1) {
            context.counters.event_gaps.fetch_add(
                sequence.saturating_sub(previous).saturating_sub(1).max(1),
                Ordering::Relaxed,
            );
        }
    }
    let open = message.event_type() == es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN;
    let file = match message.event() {
        Some(Event::AuthOpen(event)) => event.file(),
        Some(Event::AuthExec(event)) => event.target().executable(),
        Some(Event::AuthMmap(event)) => event.source(),
        _ => {
            deny_callback(client, &message, open, context);
            context.counters.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let path = Path::new(file.path());
    if !context
        .policy
        .contains_observed_path(path, file.path_truncated())
        || message.process().audit_token().euid() == context.policy.scanner_uid
        || file.stat().st_mode & libc::S_IFMT != libc::S_IFREG
    {
        respond(client, &message, open, true, context);
        return;
    }
    if file.path_truncated() || path.as_os_str().len() > 1024 || path.to_str().is_none() {
        deny_callback(client, &message, open, context);
        context.counters.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !context.scope_valid.load(Ordering::Relaxed) {
        deny_callback(client, &message, open, context);
        context.counters.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let deadline = message
        .deadline()
        .ok()
        .and_then(|d| d.checked_sub(Duration::from_millis(50)))
        .map(|d| d.min(Instant::now() + Duration::from_millis(context.policy.scan_timeout_ms)));
    let Some(deadline) = deadline.filter(|d| *d > Instant::now()) else {
        deny_callback(client, &message, open, context);
        context
            .counters
            .late_denials
            .fetch_add(1, Ordering::Relaxed);
        return;
    };
    let Ok(identity) = bounded_identity(&file) else {
        deny_callback(client, &message, open, context);
        context.counters.errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if context
        .counters
        .outstanding
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < CAPACITY).then_some(n + 1)
        })
        .is_err()
    {
        deny_callback(client, &message, open, context);
        context
            .counters
            .capacity_denials
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    let scan = Scan {
        path: path.to_path_buf(),
        identity,
        deadline,
    };
    let request = Pending {
        message,
        scan,
        open,
    };
    if let Err(error) = sender.try_send(request) {
        let request = match error {
            mpsc::TrySendError::Full(request) | mpsc::TrySendError::Disconnected(request) => {
                request
            }
        };
        context.counters.outstanding.fetch_sub(1, Ordering::Relaxed);
        deny_callback(client, &request.message, open, context);
        context
            .counters
            .capacity_denials
            .fetch_add(1, Ordering::Relaxed);
    } else {
        context.counters.admitted.fetch_add(1, Ordering::Relaxed);
    }
}

fn trusted_path(path: &Path, owner: u32, private: bool) -> Result<()> {
    for (index, item) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(item)?;
        let sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0 && index > 0;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || (metadata.mode() & 0o022 != 0 && !sticky)
            || (index == 0 && private && metadata.mode() & 0o077 != 0)
        {
            return Err("Native policy, state and scanner socket must be owned and protected from other users".into());
        }
    }
    Ok(())
}
pub fn read_policy_file(path: &Path) -> Result<Policy> {
    use std::io::Read;
    trusted_path(path, 0, true)?;
    // Descriptor traversal rejects symlinks and special files without blocking
    // on a FIFO, and the descriptor's ownership is checked before any read.
    let file = scanner::open_file(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.len() > 65536 {
        return Err("Native policy must be a private root-owned file below 64 KiB".into());
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("Native policy exceeds 64 KiB".into());
    }
    let policy: Policy = serde_json::from_slice(&bytes)?;
    policy.validate()?;
    Ok(policy)
}
fn initialize(policy: &Policy) -> Result<Vec<(PathBuf, u64, u64)>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Endpoint Security authorization must run as root".into());
    }
    policy.validate()?;
    if !fs::metadata(&policy.state)?.is_dir() {
        return Err("Create the private native state directory before starting".into());
    }
    trusted_path(&policy.state, 0, true)?;
    if !fs::symlink_metadata(&policy.socket)?
        .file_type()
        .is_socket()
    {
        return Err("Native scanner path must be a Unix socket".into());
    }
    trusted_path(&policy.socket, policy.scanner_uid, true)?;
    let mut roots = Vec::new();
    for root in &policy.roots {
        if root.canonicalize()? != *root {
            return Err("Native watched roots must be canonical and contain no symlinks".into());
        }
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() {
            return Err("Native watched roots must be directories".into());
        }
        roots.push((root.clone(), metadata.dev(), metadata.ino()));
    }
    let version = std::process::Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()?;
    if !version.status.success() {
        return Err("Cannot verify the macOS runtime version".into());
    }
    let fields = std::str::from_utf8(&version.stdout)?
        .trim()
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if fields.first().copied().unwrap_or(0) < 12 {
        return Err("Native authorization requires macOS 12 or later".into());
    }
    endpoint_sec::version::set_runtime_version(
        fields[0],
        fields.get(1).copied().unwrap_or(0),
        fields.get(2).copied().unwrap_or(0),
    );
    Ok(roots)
}
fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)?;
    let pending = path.with_extension(format!("{:032x}.pending", u128::from_be_bytes(nonce)));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&pending)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            fs::rename(&pending, path)?;
        } else {
            fs::hard_link(&pending, path)?;
            fs::remove_file(&pending)?;
        }
        fs::File::open(path.parent().ok_or("Missing native state parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}
fn journal(
    context: Arc<Context>,
    receiver: mpsc::Receiver<Receipt>,
    roots: Vec<(PathBuf, u64, u64)>,
    audit: AuditToken,
    default_muted_paths: Vec<serde_json::Value>,
    mut coverage: Snapshot,
) -> Result<()> {
    let directory = context.policy.state.join("verdicts");
    fs::create_dir_all(&directory)?;
    trusted_path(&directory, 0, false)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let probes = crate::health::load_manifest(&context.policy)?;
    let probe_directory = context.policy.state.join("probe-verdicts");
    if probes.is_some() {
        trusted_path(&probe_directory, 0, true)?;
    }
    let mut written = Instant::now() - Duration::from_secs(2);
    loop {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(mut evidence) => {
                let synthetic = probes.as_ref().is_some_and(|p| p.is_probe(&evidence));
                let destination = if synthetic {
                    &probe_directory
                } else {
                    &directory
                };
                let limit = if synthetic { 512 } else { 2048 };
                if fs::read_dir(destination)?.take(limit + 1).count() >= limit {
                    context
                        .counters
                        .evidence_dropped
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    let mut nonce = [0u8; 32];
                    getrandom::fill(&mut nonce)?;
                    evidence.id = nonce.iter().map(|b| format!("{b:02x}")).collect();
                    let path = destination.join(format!("{}.json", evidence.id));
                    if evidence.validate_policy(&context.policy, now_ms()).is_err()
                        || atomic_write(&path, &serde_json::to_vec(&evidence)?, false).is_err()
                    {
                        context
                            .counters
                            .evidence_dropped
                            .fetch_add(1, Ordering::Relaxed);
                    } else if synthetic {
                        context
                            .counters
                            .probe_receipts
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
        if written.elapsed() >= Duration::from_secs(1) {
            let valid = roots.iter().all(|(path, dev, ino)| {
                fs::symlink_metadata(path)
                    .is_ok_and(|m| m.is_dir() && m.dev() == *dev && m.ino() == *ino)
            });
            if !valid {
                context.scope_valid.store(false, Ordering::Relaxed);
            }
            let c = &context.counters;
            let checkpoint = coverage
                .observe(
                    Loss {
                        evidence_dropped: c.evidence_dropped.load(Ordering::Relaxed),
                        event_gaps: c.event_gaps.load(Ordering::Relaxed),
                        response_errors: c.response_errors.load(Ordering::Relaxed),
                    },
                    context.subscribed.load(Ordering::Acquire),
                    context.scope_valid.load(Ordering::Relaxed),
                    now_ms(),
                )
                .and_then(|next| {
                    // Retain the new revision even if fsync reports an error after
                    // rename: readers may already have observed those exact bytes.
                    coverage = next;
                    coverage.save(&context.policy.state)
                });
            let coverage_current = checkpoint.is_ok();
            if let Err(error) = checkpoint {
                eprintln!("Native coverage checkpoint unavailable: {error}");
            }
            // Subscription is not proof of effective protection. Fleet health
            // must not treat this development transport status as realtime AV.
            let status = serde_json::json!({"schema":1,"backend":"macos-endpoint-security","runtime_protection_verified":false,"pid":std::process::id(),"pidversion":audit.pidversion(),"checked_ms":now_ms(),"roots":context.policy.roots,"scope_valid":context.scope_valid.load(Ordering::Relaxed),"scanner_uid":context.policy.scanner_uid,"default_muted_paths":default_muted_paths,"outstanding":c.outstanding.load(Ordering::Relaxed),"admitted":c.admitted.load(Ordering::Relaxed),"allowed":c.allowed.load(Ordering::Relaxed),"malware":c.malware.load(Ordering::Relaxed),"probe_receipts":c.probe_receipts.load(Ordering::Relaxed),"errors":c.errors.load(Ordering::Relaxed),"capacity_denials":c.capacity_denials.load(Ordering::Relaxed),"deadline_denials":c.late_denials.load(Ordering::Relaxed),"response_errors":c.response_errors.load(Ordering::Relaxed),"event_gaps":c.event_gaps.load(Ordering::Relaxed),"evidence_dropped":c.evidence_dropped.load(Ordering::Relaxed),"coverage_session":coverage.evidence.session,"coverage_revision":coverage.evidence.revision,"coverage_current":coverage_current});
            if atomic_write(
                &context.policy.state.join("native-status.json"),
                &serde_json::to_vec(&status)?,
                true,
            )
            .is_err()
            {
                context
                    .counters
                    .evidence_dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
            written = Instant::now();
        }
    }
}
fn finish(
    client: &mut Client<'_>,
    pending: Pending,
    result: Result<Verdict>,
    context: &Context,
    journal: &SyncSender<Receipt>,
) {
    let result = if Instant::now() >= pending.scan.deadline {
        context
            .counters
            .late_denials
            .fetch_add(1, Ordering::Relaxed);
        Err("Authorization deadline elapsed before verdict delivery".into())
    } else if !context.scope_valid.load(Ordering::Relaxed) {
        Err("Monitored directory identity changed".into())
    } else {
        result
    };
    let allow = result.as_ref().is_ok_and(|v| v.detection.is_none());
    let response_delivered = respond(client, &pending.message, pending.open, allow, context);
    context.counters.outstanding.fetch_sub(1, Ordering::Relaxed);
    if allow {
        context.counters.allowed.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let (verdict, error) = match result {
        Ok(v) => {
            context.counters.malware.fetch_add(1, Ordering::Relaxed);
            (Some(v), String::new())
        }
        Err(e) => {
            context.counters.errors.fetch_add(1, Ordering::Relaxed);
            let mut error = String::new();
            for c in e
                .to_string()
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
            {
                if error.len() + c.len_utf8() > 256 {
                    break;
                }
                error.push(c);
            }
            (None, error)
        }
    };
    let audit = pending.message.process().audit_token();
    let event = Receipt {
        schema: 1,
        id: String::new(), // Allocated by the journal, outside the response loop.
        policy_sha256: context.policy_sha256.clone(),
        time_ms: now_ms(),
        response_delivered,
        operation: match pending.message.event_type() {
            es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN => "open",
            es_event_type_t::ES_EVENT_TYPE_AUTH_EXEC => "exec",
            _ => "mmap",
        }
        .into(),
        actor: Actor {
            pid: audit.pid() as u32,
            uid: audit.euid(),
            pidversion: audit.pidversion(),
        },
        path: pending.scan.path.display().to_string(),
        identity: pending.scan.identity,
        verdict,
        error,
    };
    if journal.try_send(event).is_err() {
        context
            .counters
            .evidence_dropped
            .fetch_add(1, Ordering::Relaxed);
    }
}
pub fn run(policy: Policy) -> Result<()> {
    let roots = initialize(&policy)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(policy.state.join("native.lock"))?;
    if !lock.metadata()?.is_file() {
        return Err("Native authorization lock must be a regular file".into());
    }
    trusted_path(&policy.state.join("native.lock"), 0, true)?;
    lock.try_lock()
        .map_err(|_| "Native authorization is already running for this state")?;
    let policy_sha256 = receipt::policy_hash(&policy)?;
    let policies = policy.state.join("policies");
    fs::create_dir_all(&policies)?;
    trusted_path(&policies, 0, false)?;
    fs::set_permissions(&policies, fs::Permissions::from_mode(0o700))?;
    let policy_path = policies.join(format!("{policy_sha256}.json"));
    let bytes = serde_json::to_vec(&policy)?;
    if policy_path.exists() {
        let saved = read_policy_file(&policy_path)?;
        if serde_json::to_vec(&saved)? != bytes {
            return Err("Native policy history conflicts with its hash".into());
        }
    } else {
        if fs::read_dir(&policies)?.take(65).count() >= 64 {
            return Err("Native policy history is full; retain pending receipt scopes before archiving old policies".into());
        }
        atomic_write(&policy_path, &bytes, false)?;
    }
    let audit = AuditToken::from_pid(std::process::id() as i32)
        .map_err(|e| format!("Cannot identify native scanner process: {e}"))?;
    let coverage = coverage::begin(&policy, audit.pidversion())?;
    let context = Arc::new(Context {
        policy,
        policy_sha256,
        counters: Counters::default(),
        scope_valid: Arc::new(AtomicBool::new(true)),
        last_sequence: AtomicU64::new(u64::MAX),
        subscribed: AtomicBool::new(false),
    });
    let (incoming, requests) = mpsc::sync_channel(CAPACITY);
    let callback_context = context.clone();
    let mut client=Client::new(move|client,message|callback(client,message,&callback_context,&incoming)).map_err(|e|format!("Endpoint Security client unavailable (root, entitlement and Full Disk Access required): {e:?}"))?;
    let muted = client
        .muted_paths_events()
        .map_err(|e| format!("Cannot inspect default authorization exclusions: {e:?}"))?;
    if muted.len() > 512 {
        return Err("Native default exclusion list exceeds its budget".into());
    }
    let mut default_muted_paths = Vec::new();
    for entry in muted {
        if entry.path.len() > 4096 || entry.events.len() > 512 {
            return Err("Native default exclusion exceeds its byte budget".into());
        }
        default_muted_paths.push(serde_json::json!({"path":entry.path.to_string_lossy(),"type":format!("{:?}",entry.ty),"events":entry.events.iter().map(|e|format!("{e:?}")).collect::<Vec<_>>() }));
    }
    if serde_json::to_vec(&default_muted_paths)?.len() > 256 * 1024 {
        return Err("Native default exclusions exceed the status byte budget".into());
    }
    client
        .mute_process(&audit)
        .map_err(|e| format!("Cannot mute the exact scanner process: {e:?}"))?;
    client
        .clear_cache()
        .map_err(|e| format!("Cannot clear Endpoint Security authorization cache: {e:?}"))?;
    let (journal_sender, journal_receiver) = mpsc::sync_channel(128);
    let logger = context.clone();
    thread::spawn(move || {
        if let Err(error) = journal(
            logger.clone(),
            journal_receiver,
            roots,
            audit,
            default_muted_paths,
            coverage,
        ) {
            logger
                .counters
                .evidence_dropped
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("Native evidence journal stopped: {error}");
        }
    });
    let (jobs, work) = mpsc::sync_channel::<Work>(CAPACITY);
    let work = Arc::new(Mutex::new(work));
    let (completed, results) = mpsc::sync_channel(CAPACITY + WORKERS);
    for _ in 0..WORKERS {
        let work = work.clone();
        let completed = completed.clone();
        let socket = context.policy.socket.clone();
        thread::spawn(move || loop {
            let job = match work.lock() {
                Ok(queue) => queue.recv(),
                Err(_) => return,
            };
            let Ok(job) = job else {
                return;
            };
            let result = scanner::scan(&job.scan, &socket);
            let _ = completed.try_send((job.id, result));
        });
    }
    client
        .subscribe(&[
            es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN,
            es_event_type_t::ES_EVENT_TYPE_AUTH_EXEC,
            es_event_type_t::ES_EVENT_TYPE_AUTH_MMAP,
        ])
        .map_err(|e| format!("Cannot subscribe to native authorization: {e:?}"))?;
    context.subscribed.store(true, Ordering::Release);
    let _response_broker =
        crate::broker::Broker::start(context.policy.clone(), context.scope_valid.clone())?;
    let mut pending = HashMap::<u64, Pending>::new();
    let mut next = 0u64;
    loop {
        // Drain a bounded number before checking deadlines: an event flood
        // cannot starve already admitted authorization responses.
        for request in requests.try_iter().take(CAPACITY) {
            next = next
                .checked_add(1)
                .ok_or("Native authorization sequence exhausted")?;
            let job = Work {
                id: next,
                scan: Scan {
                    path: request.scan.path.clone(),
                    identity: request.scan.identity.clone(),
                    deadline: request.scan.deadline,
                },
            };
            if jobs.try_send(job).is_ok() {
                pending.insert(next, request);
            } else {
                context
                    .counters
                    .capacity_denials
                    .fetch_add(1, Ordering::Relaxed);
                finish(
                    &mut client,
                    request,
                    Err("Native scan worker queue is full".into()),
                    &context,
                    &journal_sender,
                );
            }
        }
        for (id, result) in results.try_iter().take(CAPACITY + WORKERS) {
            if let Some(request) = pending.remove(&id) {
                finish(&mut client, request, result, &context, &journal_sender);
            }
        }
        let expired = pending
            .iter()
            .filter(|(_, r)| Instant::now() >= r.scan.deadline)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(request) = pending.remove(&id) {
                finish(
                    &mut client,
                    request,
                    Err("Native scan worker did not answer before its deadline".into()),
                    &context,
                    &journal_sender,
                );
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
}
