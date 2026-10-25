//! Journaled native response mutations. Run only in a supervised worker.
//! Recovery may finish private evidence retention, but never repeats a source
//! rename or publishes a restore that was not already visible before interruption.
#[cfg(not(windows))]
use crate::Identity;
use crate::{Result, MAX_FILE};
#[cfg(windows)]
pub use fs::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(not(windows))]
mod fs;
#[cfg(windows)]
#[path = "mutation/windows.rs"]
pub(crate) mod fs;
use fs::{copy_verified, hash_file, same_node, Dir};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Quarantine,
    Restore,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Verifier {
    LinuxProtected { uid: u32, gid: u32 },
    WindowsProtected { session: String, policy: String },
    Local,
    Retained,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    // Omitted for original broker intents, preserving their journal digests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<Verifier>,
    pub schema: u32,
    pub command_id: String,
    pub quarantine_id: String,
    pub operation: Operation,
    pub state: PathBuf,
    pub path: PathBuf,
    pub roots: Vec<PathBuf>,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    Unconfirmed,
    Review,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub intent_sha256: String,
    pub path: PathBuf,
    pub outcome: Outcome,
    pub cleanup_pending: bool,
    pub finished_ms: u64,
    pub detail: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Captured,
    Ready,
    Complete,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    intent_sha256: String,
    path: PathBuf,
    parent: Identity,
    source: Identity,
    copy: Option<Identity>,
    phase: Phase,
    finished_ms: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    record: Record,
    sha256: String,
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn valid_path(p: &Path) -> bool {
    p.is_absolute()
        && p.to_str()
            .is_some_and(|s| s.len() <= 4096 && !s.contains(char::is_control))
        && !p.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}
fn remaining(d: Instant) -> Result<Duration> {
    d.checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "Mutation deadline elapsed".into())
}
impl Intent {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || !hex(&self.command_id)
            || !hex(&self.quarantine_id)
            || !hex(&self.sha256)
            || (self.operation == Operation::Quarantine && self.command_id != self.quarantine_id)
            || self.roots.is_empty()
            || self.roots.len() > 16
            || !self
                .roots
                .iter()
                .chain([&self.path, &self.state])
                .all(|p| valid_path(p))
            || self.roots.iter().any(|r| self.state.starts_with(r))
        {
            return Err("Invalid native mutation intent".into());
        }
        if let Some(Verifier::LinuxProtected { uid, gid }) = self.verifier {
            if !cfg!(target_os = "linux")
                || [0, u32::MAX].contains(&uid)
                || [0, u32::MAX].contains(&gid)
            {
                return Err("Invalid protected Linux reader identity".into());
            }
        }
        if matches!(self.verifier, Some(Verifier::Retained)) && self.operation != Operation::Restore
        {
            return Err("Retained evidence verification is restricted to restore".into());
        }
        if let Some(Verifier::WindowsProtected { session, policy }) = &self.verifier {
            if !cfg!(windows)
                || self.operation != Operation::Quarantine
                || !hex(session)
                || !hex(policy)
            {
                return Err("Invalid protected Windows verifier binding".into());
            }
        }
        // Leave room for the nonce, recovery mode and timeout wrapper. Reject
        // before the agent journals an intent that its worker pipe cannot carry.
        if serde_json::to_vec(self)?.len() > 60000 {
            return Err("Native mutation intent exceeds its request budget".into());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}
struct Context<'a> {
    intent: &'a Intent,
    q: Dir,
    journal: Dir,
    _lock: File,
    record_name: String,
    captured: String,
    copy: String,
    deadline: Instant,
    lease_shared: bool,
}
impl Drop for Context<'_> {
    fn drop(&mut self) {
        // A concurrent fork may briefly inherit this open file description.
        // A broker-only operation can release explicitly. A protected reader
        // intentionally shares the open-file description: close our descriptor
        // without unlocking so that an outstanding reader retains ownership.
        if !self.lease_shared {
            let _ = self._lock.unlock();
        }
    }
}
impl<'a> Context<'a> {
    fn open(intent: &'a Intent, timeout: Duration) -> Result<Self> {
        intent.validate()?;
        if timeout.is_zero() || timeout > Duration::from_secs(600) {
            return Err("Invalid mutation deadline".into());
        }
        let deadline = Instant::now() + timeout;
        fs::trusted(intent)?;
        let state = Dir::open(&intent.state)?;
        state.private()?;
        let q = state.directory("quarantine")?;
        let journal = q.directory("operations")?;
        let lock = if journal.exists("worker.lock")? {
            journal.read("worker.lock")?
        } else {
            journal.create("worker.lock")?
        };
        lock.try_lock().map_err(|_| {
            "Another native mutation still owns the filesystem; cleanup may be pending"
        })?;
        let c = Self {
            intent,
            q,
            journal,
            _lock: lock,
            record_name: format!("{}.json", intent.command_id),
            captured: format!(".capture-{}", intent.quarantine_id),
            copy: format!(".copy-{}", intent.command_id),
            deadline,
            lease_shared: false,
        };
        let mut count = 0;
        for entry in std::fs::read_dir(&c.journal.path)? {
            let _ = entry?;
            count += 1;
            if count > 4096 {
                return Err("Mutation journal capacity exhausted".into());
            }
        }
        Ok(c)
    }
    fn save(&self, r: &Record) -> Result<()> {
        let sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(r)?));
        self.journal.write_json(
            &self.record_name,
            &Journal {
                record: r.clone(),
                sha256,
            },
        )
    }
    fn report(&self, r: &Record, outcome: Outcome, cleanup_pending: bool, detail: &str) -> Report {
        Report {
            intent_sha256: r.intent_sha256.clone(),
            path: r.path.clone(),
            outcome,
            cleanup_pending,
            finished_ms: r.finished_ms,
            detail: detail.into(),
        }
    }
    fn scope(&self, path: &Path) -> Result<(Dir, String)> {
        fs::scope(self.intent, path, &self.q)
    }
    fn capacity(&self, additional: u64) -> Result<()> {
        let mut bytes = 0u64;
        let mut count = 0;
        for entry in std::fs::read_dir(&self.q.path)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "operations" {
                continue;
            }
            let name = name.to_str().ok_or("Invalid quarantine entry")?;
            if let Some(id) = self.q.stat(name)? {
                bytes = bytes.saturating_add(id.size)
            }
            count += 1;
            if count > 4096 {
                return Err("Quarantine entry capacity exhausted".into());
            }
        }
        if bytes.saturating_add(additional) > 1024 * 1024 * 1024 {
            return Err("Quarantine storage exceeds its 1 GiB budget".into());
        }
        let available = fs::available(&self.q)?;
        if available < additional.saturating_add(16 * 1024 * 1024) {
            return Err("Quarantine requires 16 MiB of remaining disk headroom".into());
        }
        Ok(())
    }
    fn cleanup(&self, r: &Record) -> Result<()> {
        let remove = |leaf: &str, expected: &Identity| -> Result<()> {
            if let Some(id) = self.q.stat(leaf)? {
                if !same_node(&id, expected) {
                    return Err("Private cleanup identity changed; retained for review".into());
                }
                self.q.unlink(leaf)?;
            }
            Ok(())
        };
        match self.intent.operation {
            Operation::Quarantine => remove(&self.captured, &r.source)?,
            Operation::Restore => {
                remove(&self.intent.quarantine_id, &r.source)?;
                if let Some(copy) = &r.copy {
                    remove(&self.copy, copy)?;
                }
            }
        }
        Ok(())
    }
    fn complete(
        &self,
        r: &mut Record,
        checkpoint: &mut impl FnMut(&str) -> Result<()>,
    ) -> Result<Report> {
        r.phase = Phase::Complete;
        r.finished_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        self.save(r)?;
        checkpoint("complete")?;
        let cleanup = self.cleanup(r).is_err();
        Ok(self.report(
            r,
            Outcome::Completed,
            cleanup,
            if cleanup {
                "Filesystem operation committed; private cleanup needs review"
            } else {
                "Filesystem operation committed and synced"
            },
        ))
    }
    fn retain(
        &self,
        r: &mut Record,
        checkpoint: &mut impl FnMut(&str) -> Result<()>,
    ) -> Result<Report> {
        let target = &self.intent.quarantine_id;
        if self.q.exists(target)? {
            let (sha, id) = hash_file(self.q.read(target)?, self.deadline)?;
            if sha != self.intent.sha256 || r.copy.as_ref().is_none_or(|copy| !same_node(copy, &id))
            {
                return Err("Retained quarantine content or identity changed".into());
            }
            fs::sync_file(&self.q, target)?;
            self.q.sync()?;
            return self.complete(r, checkpoint);
        }
        if r.phase == Phase::Ready && self.q.exists(&self.copy)? {
            let (sha, id) = hash_file(self.q.read(&self.copy)?, self.deadline)?;
            if sha != self.intent.sha256 || r.copy.as_ref().is_none_or(|copy| !same_node(copy, &id))
            {
                return Err("Private retained copy changed".into());
            }
            self.q.move_new(&self.copy, &self.q, target)?;
            self.q.sync()?;
            return self.complete(r, checkpoint);
        }
        let raw = self
            .q
            .stat(&self.captured)?
            .ok_or("Captured evidence is missing")?;
        if !same_node(&raw, &r.source) {
            return Err(
                "Captured file differs from the approved source; retained for review".into(),
            );
        }
        // A partial private copy is never published. Recovery can discard it and
        // repeat only private retention, without touching the original pathname.
        if self.q.exists(&self.copy)? {
            self.q.unlink(&self.copy)?;
        }
        self.capacity(raw.size)?;
        r.copy = Some(copy_verified(
            &self.q,
            &self.captured,
            &self.q,
            &self.copy,
            &self.intent.sha256,
            self.deadline,
        )?);
        r.phase = Phase::Ready;
        self.save(r)?;
        checkpoint("ready")?;
        self.q.move_new(&self.copy, &self.q, target)?;
        checkpoint("retained")?;
        self.q.sync()?;
        self.complete(r, checkpoint)
    }
}
pub fn apply(intent: &Intent, recover: bool, timeout: Duration) -> Result<Report> {
    apply_inner(intent, recover, timeout, &mut |_| Ok(()))
}
fn apply_inner(
    intent: &Intent,
    recover: bool,
    timeout: Duration,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<Report> {
    apply_using(intent, recover, timeout, checkpoint, None)
}

/// The embedding endpoint supplies its protected reader or applied-denial
/// verifier. An external reader must retain the supplied mutation lease until
/// its read work has stopped. The Windows verifier runs inside this same worker.
pub fn apply_with_verifier(
    intent: &Intent,
    recover: bool,
    timeout: Duration,
    mut verifier: impl FnMut(&Path, &Identity, Duration, &File) -> Result<crate::Verdict>,
) -> Result<Report> {
    apply_using(
        intent,
        recover,
        timeout,
        &mut |_| Ok(()),
        Some(&mut verifier),
    )
}

/// Attempt an ordinary, no-reparse source read. A minifilter denial is left
/// intact; the embedding worker may correlate its own applied denial receipt.
#[cfg(windows)]
pub fn windows_source_verdict(
    path: &Path,
    expected: &Identity,
    timeout: Duration,
) -> Result<crate::Verdict> {
    if timeout.is_zero() || timeout > Duration::from_secs(600) {
        return Err("Invalid Windows verification deadline".into());
    }
    let parent = Dir::open(path.parent().ok_or("Missing source parent")?)?;
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid source leaf")?;
    fs::local_verdict(
        Path::new(""),
        &parent,
        leaf,
        expected,
        Instant::now() + timeout,
    )
}
type Verify<'a> = dyn FnMut(&Path, &Identity, Duration, &File) -> Result<crate::Verdict> + 'a;
fn apply_using(
    intent: &Intent,
    recover: bool,
    timeout: Duration,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
    mut verifier: Option<&mut Verify<'_>>,
) -> Result<Report> {
    let mut c = Context::open(intent, timeout)?;
    let digest = intent.digest()?;
    if c.journal.exists(&c.record_name)? {
        if !recover {
            return Err("Mutation already has a durable journal; reconcile before retrying".into());
        }
        let journal: Journal = c.journal.read_json(&c.record_name)?;
        if journal.sha256 != format!("{:x}", Sha256::digest(serde_json::to_vec(&journal.record)?)) {
            return Err("Mutation journal checksum mismatch".into());
        }
        let mut r = journal.record;
        if r.schema != 1
            || r.intent_sha256 != digest
            || !valid_path(&r.path)
            || r.path != intent.path
            || (r.phase == Phase::Complete && (r.finished_ms == 0 || r.copy.is_none()))
            || r.source.size > MAX_FILE
        {
            return Err("Mutation journal does not match its durable intent".into());
        }
        if r.phase == Phase::Complete {
            let pending = c.cleanup(&r).is_err();
            return Ok(c.report(
                &r,
                Outcome::Completed,
                pending,
                "Recovered committed filesystem operation",
            ));
        }
        if intent.operation == Operation::Quarantine {
            let (parent, _) = c.scope(&r.path)?;
            if !same_node(&fs::identity(&parent.file)?, &r.parent) {
                return Err(
                    "Original quarantine directory changed; evidence retained for review".into(),
                );
            }
            parent.sync()?;
            if c.q.exists(&c.captured)? || c.q.exists(&intent.quarantine_id)? {
                return c.retain(&mut r, checkpoint);
            }
            return Ok(c.report(
                &r,
                Outcome::Unconfirmed,
                false,
                "No captured file; the source rename is not repeated",
            ));
        }
        let (parent, leaf) = c.scope(&r.path)?;
        if !same_node(&fs::identity(&parent.file)?, &r.parent) {
            return Err("Original restore directory changed; evidence retained for review".into());
        }
        let published = parent.stat(&leaf)?;
        if let (Some(copy), Some(target)) = (&r.copy, published.as_ref()) {
            if same_node(copy, target) {
                let (sha, current) = hash_file(c.q.read(&c.copy)?, c.deadline)?;
                if sha != intent.sha256 || !same_node(copy, &current) {
                    return Err("Restore staging evidence changed".into());
                }
                parent.still_bound()?;
                parent.sync()?;
                return c.complete(&mut r, checkpoint);
            }
        }
        let (sha, current) = hash_file(c.q.read(&intent.quarantine_id)?, c.deadline)?;
        if sha != intent.sha256 || !same_node(&r.source, &current) {
            return Err("Unfinished restore lost its retained original".into());
        }
        Ok(c.report(&r,Outcome::Unconfirmed,false,"Restore was not proven published; retained original preserved and destination left untouched"))
    } else if recover {
        let r = Record {
            schema: 1,
            intent_sha256: digest,
            path: intent.path.clone(),
            parent: fs::zero_identity(),
            source: fs::zero_identity(),
            copy: None,
            phase: Phase::Prepared,
            finished_ms: 0,
        };
        if c.q.exists(&c.captured)?
            || c.q.exists(&c.copy)?
            || (intent.operation == Operation::Quarantine && c.q.exists(&intent.quarantine_id)?)
        {
            return Err(
                "Private evidence exists without its mutation journal; review required".into(),
            );
        }
        Ok(c.report(
            &r,
            Outcome::Unconfirmed,
            false,
            "Worker did not establish a mutation journal; no action replayed",
        ))
    } else {
        let (parent, leaf) = c.scope(&intent.path)?;
        let path = parent.path.join(&leaf);
        let source = match intent.operation {
            Operation::Quarantine => {
                if c.q.exists(&intent.quarantine_id)? || c.q.exists(&c.captured)? {
                    return Err("Quarantine destination already exists".into());
                }
                let before = parent.stat(&leaf)?.ok_or("Quarantine source is missing")?;
                if before.size > MAX_FILE {
                    return Err("Mutation file exceeds 128 MiB".into());
                }
                let verdict = match intent.verifier {
                    None => fs::broker_query(&intent.state, &path, remaining(c.deadline)?)?,
                    Some(Verifier::Local) => {
                        fs::local_verdict(&intent.state, &parent, &leaf, &before, c.deadline)?
                    }
                    Some(_) => {
                        let verify = verifier
                            .as_mut()
                            .ok_or("Protected reader implementation is unavailable")?;
                        c.lease_shared = true;
                        verify(&path, &before, remaining(c.deadline)?, &c._lock)?
                    }
                };
                if verdict.sha256 != intent.sha256
                    || verdict.bytes != before.size
                    || parent.stat(&leaf)?.as_ref() != Some(&before)
                {
                    return Err("File changed since approval".into());
                }
                before
            }
            Operation::Restore => {
                if parent.exists(&leaf)? {
                    return Err("Restore destination already exists".into());
                }
                let (sha, id) = hash_file(c.q.read(&intent.quarantine_id)?, c.deadline)?;
                if sha != intent.sha256 {
                    return Err("Quarantine integrity check failed".into());
                }
                id
            }
        };
        c.capacity(source.size.saturating_mul(2))?;
        parent.still_bound()?;
        c.q.still_bound()?;
        let mut r = Record {
            schema: 1,
            intent_sha256: digest,
            path,
            parent: fs::identity(&parent.file)?,
            source,
            copy: None,
            phase: Phase::Prepared,
            finished_ms: 0,
        };
        c.save(&r)?;
        checkpoint("prepared")?;
        remaining(c.deadline)?;
        match intent.operation {
            Operation::Quarantine => {
                fs::capture(&parent, &leaf, &c.q, &c.captured, &r.source)?;
                checkpoint("captured")?;
                parent.sync()?;
                c.q.sync()?;
                parent.still_bound()?;
                r.phase = Phase::Captured;
                c.save(&r)?;
                c.retain(&mut r, checkpoint)
            }
            Operation::Restore => {
                r.copy = Some(copy_verified(
                    &c.q,
                    &intent.quarantine_id,
                    &c.q,
                    &c.copy,
                    &intent.sha256,
                    c.deadline,
                )?);
                r.phase = Phase::Ready;
                c.save(&r)?;
                checkpoint("ready")?;
                remaining(c.deadline)?;
                parent.still_bound()?;
                c.q.link_new(&c.copy, &parent, &leaf)?;
                checkpoint("published")?;
                parent.sync()?;
                parent.still_bound()?;
                if parent
                    .stat(&leaf)?
                    .as_ref()
                    .zip(r.copy.as_ref())
                    .is_none_or(|(a, b)| !same_node(a, b))
                {
                    return Err("Restore destination changed during publication".into());
                }
                c.complete(&mut r, checkpoint)
            }
        }
    }
}
#[cfg(all(test, not(windows)))]
mod tests;

/// Pins a local Windows directory and its ancestry while an adjacent engine
/// bundle is prepared. The inherited ACL admits only this identity/SYSTEM/admins.
#[cfg(windows)]
pub struct PrivateDirectory(fs::Dir);
#[cfg(windows)]
impl PrivateDirectory {
    pub fn create(path: &Path) -> Result<Self> {
        let parent = fs::Dir::open(path.parent().ok_or("Missing private directory parent")?)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid private directory name")?;
        let directory = parent.directory(name)?;
        directory.private()?;
        Ok(Self(directory))
    }
    pub fn open(path: &Path) -> Result<Self> {
        let directory = fs::Dir::open(path)?;
        directory.private()?;
        Ok(Self(directory))
    }
    pub fn check(&self) -> Result<()> {
        self.0.still_bound()?;
        self.0.private()
    }
    pub fn check_file(&self, name: &str) -> Result<()> {
        self.0.read_private(name)?;
        self.check()
    }
}
#[cfg(all(test, windows))]
#[path = "mutation/windows_tests.rs"]
mod tests;
