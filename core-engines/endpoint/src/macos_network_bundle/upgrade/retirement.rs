//! Exact owned-tree retirement after the OS request and helper have settled.
//! A durable postorder plan precedes any deletion. Missing recorded entries
//! are replayable; unknown or changed objects never become deletion authority.
use crate::Result;
use athernex_endpoint_protocol as protocol;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PLAN: usize = 131_072;
const MAX_ENTRIES: usize = 544;
const APP_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectId {
    device: u64,
    inode: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Kind {
    Directory,
    File { size: u64, sha256: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    identity: ObjectId,
    mode: u32,
    kind: Kind,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    schema: u32,
    transaction_id: String,
    ledger_sha256: String,
    provider_identifier: String,
    entries: Vec<Entry>,
}

fn parent(path: &str) -> Option<&str> {
    if path.is_empty() {
        None
    } else {
        Some(path.rsplit_once('/').map_or("", |(p, _)| p))
    }
}
fn directories(provider: &str) -> BTreeSet<String> {
    let app = "AthernexNetwork.app";
    let nested = format!("{app}/Contents/Library/SystemExtensions/{provider}.systemextension");
    [
        String::new(),
        app.to_owned(),
        format!("{app}/Contents"),
        format!("{app}/Contents/MacOS"),
        format!("{app}/Contents/_CodeSignature"),
        format!("{app}/Contents/Library"),
        format!("{app}/Contents/Library/SystemExtensions"),
        nested.clone(),
        format!("{nested}/Contents"),
        format!("{nested}/Contents/MacOS"),
        format!("{nested}/Contents/_CodeSignature"),
    ]
    .into_iter()
    .collect()
}
fn app_file(path: &str, provider: &str) -> bool {
    let app = "AthernexNetwork.app";
    let nested = format!("{app}/Contents/Library/SystemExtensions/{provider}.systemextension");
    [app, nested.as_str()].into_iter().any(|base| {
        [
            "Contents/Info.plist",
            "Contents/PkgInfo",
            "Contents/embedded.provisionprofile",
            "Contents/_CodeSignature/CodeResources",
        ]
        .into_iter()
        .any(|suffix| path == format!("{base}/{suffix}"))
    }) || path == format!("{app}/Contents/MacOS/AthernexNetwork")
        || path == format!("{nested}/Contents/MacOS/AthernexNetworkProvider")
}
impl Plan {
    fn validate(&self) -> Result<()> {
        if self.schema != 1
            || !protocol::hex_id(&self.transaction_id)
            || !protocol::hex_id(&self.ledger_sha256)
            || self.provider_identifier.len() > 255
            || !self.provider_identifier.contains('.')
            || self.provider_identifier.split('.').any(|part| {
                part.is_empty()
                    || part.len() > 63
                    || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || self.entries.is_empty()
            || self.entries.len() > MAX_ENTRIES
            || serde_json::to_vec(self)?.len() > MAX_PLAN
        {
            return Err("Network cleanup plan binding is invalid".into());
        }
        let dirs = directories(&self.provider_identifier);
        let mut paths = BTreeMap::new();
        let mut ids = BTreeSet::new();
        let mut app_bytes = 0u64;
        let mut app_files = 0usize;
        for (index, entry) in self.entries.iter().enumerate() {
            if paths.insert(entry.path.as_str(), index).is_some()
                || !ids.insert((entry.identity.device, entry.identity.inode))
                || entry.mode & !0o777 != 0
                || entry.mode & 0o022 != 0
            {
                return Err("Network cleanup plan repeats or weakens an object".into());
            }
            match &entry.kind {
                Kind::Directory if dirs.contains(&entry.path) => {
                    if entry.path.is_empty() && entry.mode != 0o700 {
                        return Err("Network cleanup root protection differs".into());
                    }
                }
                Kind::File { size, sha256 } if protocol::hex_id(sha256) => {
                    let (mode_ok, limit) = match entry.path.as_str() {
                        "management" => (entry.mode == 0o700, APP_LIMIT),
                        "original-config.json" | "candidate-config.json" => {
                            (entry.mode == 0o600, 65_536)
                        }
                        "upgrade-service.plist" => (entry.mode == 0o644, 16_384),
                        path if app_file(path, &self.provider_identifier) => {
                            app_bytes = app_bytes
                                .checked_add(*size)
                                .ok_or("Cleanup size overflow")?;
                            app_files += 1;
                            ([0o644, 0o755].contains(&entry.mode), APP_LIMIT)
                        }
                        _ => {
                            return Err(
                                "Network cleanup file is outside the owned namespace".into()
                            );
                        }
                    };
                    if !mode_ok || *size > limit {
                        return Err("Network cleanup file bounds differ".into());
                    }
                }
                _ => return Err("Network cleanup object type is invalid".into()),
            }
        }
        if app_bytes > APP_LIMIT || app_files > 512 {
            return Err("Network cleanup app exceeds its bound".into());
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if let Some(p) = parent(&entry.path) {
                let parent_index = *paths.get(p).ok_or("Cleanup parent is absent")?;
                if parent_index <= index || self.entries[parent_index].kind != Kind::Directory {
                    return Err("Network cleanup order is not postorder".into());
                }
            } else if index + 1 != self.entries.len() || entry.kind != Kind::Directory {
                return Err("Network cleanup root is not last".into());
            }
        }
        if self.entries.last().map(|e| e.path.as_str()) != Some("") {
            return Err("Network cleanup root is missing".into());
        }
        Ok(())
    }
}

/// This is the production cleanup transition algorithm. The platform adapter
/// opens every remaining ancestor without following links and checks its
/// recorded identity before removal. `sync_parent` also handles an entry
/// already absent after a crash; it must sync the nearest remaining ancestor.
trait TreeOps {
    fn inventory(&mut self) -> Result<Vec<Entry>>;
    fn remove(&mut self, expected: &Entry, plan: &Plan) -> Result<()>;
    fn sync_parent(&mut self, path: &str, plan: &Plan) -> Result<()>;
}
fn cleanup(plan: &Plan, ops: &mut impl TreeOps) -> Result<()> {
    plan.validate()?;
    let expected: BTreeMap<_, _> = plan.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let actual = ops.inventory()?;
    let mut seen = BTreeSet::new();
    for entry in &actual {
        if !seen.insert(entry.path.as_str()) || expected.get(entry.path.as_str()) != Some(&entry) {
            return Err("Network cleanup found an unrecorded or changed object".into());
        }
    }
    for entry in &actual {
        if parent(&entry.path).is_some_and(|p| !seen.contains(p)) {
            return Err("Network cleanup inventory has no owned parent".into());
        }
    }
    for entry in &plan.entries {
        ops.remove(entry, plan)?;
        ops.sync_parent(&entry.path, plan)?;
    }
    if !ops.inventory()?.is_empty() {
        return Err("Network cleanup retained unexpected objects".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use crate::macos_network_bundle::upgrade::{
        filesystem as owned,
        journal::Phase,
        launchd,
        storage::{Ledger, Storage},
    };
    use sha2::{Digest, Sha256};
    use std::{
        ffi::{CStr, CString},
        fs::{self, File, OpenOptions},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
    };

    fn io_error() -> Box<dyn std::error::Error + Send + Sync> {
        std::io::Error::last_os_error().into()
    }
    fn object(metadata: &fs::Metadata) -> ObjectId {
        ObjectId {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    fn check(metadata: &fs::Metadata, directory: bool) -> Result<()> {
        if metadata.uid() != 0
            || metadata.mode() & 0o7022 != 0
            || (directory && !metadata.is_dir())
            || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Err("Network cleanup object is not protected".into());
        }
        Ok(())
    }
    fn open_at(parent: &File, name: &str, directory: bool) -> Result<Option<File>> {
        let name = CString::new(name).map_err(|_| "Invalid cleanup component")?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if directory { libc::O_DIRECTORY } else { 0 };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error.into())
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        check(&file.metadata()?, directory)?;
        Ok(Some(file))
    }
    fn names(directory: &File) -> Result<Vec<String>> {
        // fdopendir owns its descriptor; opening '.' creates an independent
        // directory position so repeated inventories cannot skip old entries.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io_error());
        }
        let ptr = unsafe { libc::fdopendir(fd) };
        if ptr.is_null() {
            unsafe {
                libc::close(fd);
            }
            return Err(io_error());
        }
        struct Dir(*mut libc::DIR);
        impl Drop for Dir {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let dir = Dir(ptr);
        let mut result = Vec::new();
        loop {
            unsafe {
                *libc::__error() = 0;
            }
            let entry = unsafe { libc::readdir(dir.0) };
            if entry.is_null() {
                if unsafe { *libc::__error() } != 0 {
                    return Err(io_error());
                }
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if bytes.len() > 255 || result.len() >= MAX_ENTRIES {
                return Err("Network cleanup directory exceeds its bound".into());
            }
            result.push(
                std::str::from_utf8(bytes)
                    .map_err(|_| "Cleanup filename encoding differs")?
                    .to_owned(),
            );
        }
        result.sort();
        Ok(result)
    }
    fn stat_at(parent: &File, name: &str) -> Result<Option<libc::stat>> {
        let name = CString::new(name).map_err(|_| "Invalid cleanup component")?;
        let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                value.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error.into())
            };
        }
        Ok(Some(unsafe { value.assume_init() }))
    }
    fn entry(file: &mut File, path: &str, directory: bool) -> Result<Entry> {
        let before = file.metadata()?;
        check(&before, directory)?;
        let kind = if directory {
            Kind::Directory
        } else {
            if before.len() > APP_LIMIT {
                return Err("Network cleanup file exceeds its bound".into());
            }
            let mut hash = Sha256::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 65_536];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                total = total.checked_add(n as u64).ok_or("Cleanup size overflow")?;
                if total > before.len() {
                    return Err("Network cleanup file grew during inspection".into());
                }
                hash.update(&buffer[..n]);
            }
            let after = file.metadata()?;
            if total != before.len()
                || object(&before) != object(&after)
                || before.len() != after.len()
                || before.mode() != after.mode()
                || before.nlink() != after.nlink()
                || before.uid() != after.uid()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err("Network cleanup file changed during inspection".into());
            }
            Kind::File {
                size: total,
                sha256: format!("{:x}", hash.finalize()),
            }
        };
        Ok(Entry {
            path: path.to_owned(),
            identity: object(&before),
            mode: before.mode() & 0o7777,
            kind,
        })
    }
    struct NativeTree {
        root: File,
    }
    impl NativeTree {
        fn new(lease: &owned::Lease) -> Result<Self> {
            let path = lease.directory()?;
            let root = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let id = owned::Identity::of(&root.metadata()?);
            id.verify(path)?;
            check(&root.metadata()?, true)?;
            Ok(Self { root })
        }
        fn verify_directory(file: &File, path: &str, plan: &Plan) -> Result<()> {
            let expected = plan
                .entries
                .iter()
                .find(|e| e.path == path)
                .ok_or("Cleanup parent is not recorded")?;
            let metadata = file.metadata()?;
            check(&metadata, true)?;
            if expected.kind != Kind::Directory
                || object(&metadata) != expected.identity
                || metadata.mode() & 0o7777 != expected.mode
            {
                return Err("Network cleanup parent identity changed".into());
            }
            Ok(())
        }
        /// Return the parent, or its nearest remaining ancestor for fsync
        /// replay. A missing path is never followed through another object.
        fn parent(&self, path: &str, plan: &Plan) -> Result<(File, bool)> {
            let mut current = self.root.try_clone()?;
            let Some(parent_path) = parent(path) else {
                return Ok((current, true));
            };
            let Some(pending) = open_at(&current, "pending", true)? else {
                return Ok((current, false));
            };
            Self::verify_directory(&pending, "", plan)?;
            current = pending;
            let mut relative = String::new();
            for component in parent_path.split('/').filter(|s| !s.is_empty()) {
                let Some(next) = open_at(&current, component, true)? else {
                    return Ok((current, false));
                };
                if !relative.is_empty() {
                    relative.push('/');
                }
                relative.push_str(component);
                Self::verify_directory(&next, &relative, plan)?;
                current = next;
            }
            Ok((current, true))
        }
    }
    impl TreeOps for NativeTree {
        fn inventory(&mut self) -> Result<Vec<Entry>> {
            fn walk(
                file: &mut File,
                path: &str,
                entries: &mut Vec<Entry>,
                bytes: &mut u64,
            ) -> Result<()> {
                let here = entry(file, path, true)?;
                for name in names(file)? {
                    if entries.len() >= MAX_ENTRIES {
                        return Err("Network cleanup entry bound exceeded".into());
                    }
                    let full = if path.is_empty() {
                        name.clone()
                    } else {
                        format!("{path}/{name}")
                    };
                    if full.len() > 512 || full.split('/').count() > 12 {
                        return Err("Network cleanup depth exceeded".into());
                    }
                    let metadata = stat_at(file, &name)?
                        .ok_or("Cleanup object disappeared during planning")?;
                    let is_dir = metadata.st_mode & libc::S_IFMT == libc::S_IFDIR;
                    if !is_dir {
                        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_size < 0
                        {
                            return Err("Network cleanup contains an unsupported object".into());
                        }
                        *bytes = bytes
                            .checked_add(metadata.st_size as u64)
                            .ok_or("Cleanup size overflow")?;
                        if *bytes > 2 * APP_LIMIT + 147_456 {
                            return Err("Network cleanup total byte bound exceeded".into());
                        }
                    }
                    let mut child = open_at(file, &name, is_dir)?
                        .ok_or("Cleanup object disappeared during planning")?;
                    if is_dir {
                        walk(&mut child, &full, entries, bytes)?;
                    } else {
                        entries.push(entry(&mut child, &full, false)?);
                    }
                    if entries.len() >= MAX_ENTRIES {
                        return Err("Network cleanup entry bound exceeded".into());
                    }
                }
                entries.push(here);
                Ok(())
            }
            let Some(mut pending) = open_at(&self.root, "pending", true)? else {
                return Ok(Vec::new());
            };
            let mut result = Vec::new();
            walk(&mut pending, "", &mut result, &mut 0)?;
            Ok(result)
        }
        fn remove(&mut self, expected: &Entry, plan: &Plan) -> Result<()> {
            let (parent, present) = self.parent(&expected.path, plan)?;
            if !present {
                return Ok(());
            }
            let name = expected
                .path
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("pending");
            let directory = expected.kind == Kind::Directory;
            let Some(mut file) = open_at(&parent, name, directory)? else {
                return Ok(());
            };
            if entry(&mut file, &expected.path, directory)? != *expected {
                return Err("Network cleanup object changed before removal".into());
            }
            if directory && !names(&file)?.is_empty() {
                return Err("Network cleanup directory has unrecorded children".into());
            }
            let metadata =
                stat_at(&parent, name)?.ok_or("Cleanup object disappeared before removal")?;
            if metadata.st_dev as u64 != expected.identity.device
                || metadata.st_ino != expected.identity.inode
            {
                return Err("Network cleanup entry was replaced".into());
            }
            let name = CString::new(name).map_err(|_| "Invalid cleanup component")?;
            if unsafe {
                libc::unlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    if directory { libc::AT_REMOVEDIR } else { 0 },
                )
            } != 0
            {
                return Err(io_error());
            }
            Ok(())
        }
        fn sync_parent(&mut self, path: &str, plan: &Plan) -> Result<()> {
            self.parent(path, plan)?.0.sync_all()?;
            Ok(())
        }
    }
    fn binding(ledger: &Ledger) -> Result<String> {
        let mut stable = ledger.clone();
        stable.retirement_started = false;
        stable.retired = false;
        Ok(protocol::hash(&serde_json::to_vec(&stable)?))
    }
    fn gate(lease: &owned::Lease, ledger: &Ledger) -> Result<()> {
        ledger.validate()?;
        if !ledger.stage_placed
            || ledger.retired
            || ledger.management_parked
            || ledger.job_operation.is_some()
            || !matches!(ledger.record.phase, Phase::Complete | Phase::Aborted)
            || !matches!(
                ledger.job.state,
                launchd::JobState::BootoutConfirmed
                    | launchd::JobState::NotRegistered
                    | launchd::JobState::RetiredAfterBoot
            )
            || serde_json::to_vec(&Ledger::load(lease)?)? != serde_json::to_vec(ledger)?
        {
            return Err("Network cleanup requires a settled owned transaction".into());
        }
        match fs::symlink_metadata(launchd::PLIST) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err("Network helper registration remains public or unknown".into()),
        }
        owned::protected_directory(Path::new("/Library/LaunchDaemons"), 0o755)?;
        let id = ledger
            .files
            .original_management_plist
            .ok_or("Original management registration is missing")?;
        id.verify(Path::new(launchd::MANAGEMENT_PLIST))?;
        let bytes = owned::read_owned(Path::new(launchd::MANAGEMENT_PLIST), 16_384, 0o644)?;
        if protocol::hash(&bytes) != ledger.original_management_plist_sha256 {
            return Err("Original management registration changed".into());
        }
        Ok(())
    }
    fn path(lease: &owned::Lease, ledger: &Ledger) -> Result<std::path::PathBuf> {
        Ok(lease
            .directory()?
            .join(format!("cleanup-{}.json", ledger.record.id)))
    }
    fn validate_binding(plan: &Plan, ledger: &Ledger) -> Result<()> {
        plan.validate()?;
        let root = plan.entries.last().ok_or("Cleanup root absent")?;
        if plan.transaction_id != ledger.record.id
            || plan.ledger_sha256 != binding(ledger)?
            || plan.provider_identifier != ledger.record.plan.identity.provider_identifier
            || root.identity
                != (ObjectId {
                    device: ledger.staging_identity.device,
                    inode: ledger.staging_identity.inode,
                })
        {
            return Err("Network cleanup plan belongs to another transaction".into());
        }
        Ok(())
    }
    pub(in crate::macos_network_bundle::upgrade) fn prepare(
        lease: &owned::Lease,
        ledger: &Ledger,
    ) -> Result<Plan> {
        gate(lease, ledger)?;
        if ledger.retirement_started {
            return Err("Network cleanup has already started".into());
        }
        launchd::require_management_unloaded()?;
        launchd::require_helper_unloaded()?;
        Storage::open(lease)?.verify_apps()?;
        let entries = NativeTree::new(lease)?.inventory()?;
        let plan = Plan {
            schema: 1,
            transaction_id: ledger.record.id.clone(),
            ledger_sha256: binding(ledger)?,
            provider_identifier: ledger.record.plan.identity.provider_identifier.clone(),
            entries,
        };
        validate_binding(&plan, ledger)?;
        let bytes = serde_json::to_vec(&plan)?;
        let path = path(lease, ledger)?;
        match fs::symlink_metadata(&path) {
            Ok(_) if owned::read_owned(&path, MAX_PLAN, 0o600)? != bytes => {
                return Err("Existing cleanup plan differs".into());
            }
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        // Rewriting identical bytes also reconciles a previous rename whose
        // parent-directory durability was not confirmed before failure.
        owned::write_owned(&path, &bytes, 0o600)?;
        Ok(plan)
    }
    pub(in crate::macos_network_bundle::upgrade) fn load(
        lease: &owned::Lease,
        ledger: &Ledger,
    ) -> Result<Plan> {
        gate(lease, ledger)?;
        let plan: Plan =
            serde_json::from_slice(&owned::read_owned(&path(lease, ledger)?, MAX_PLAN, 0o600)?)
                .map_err(|_| "Invalid network cleanup plan")?;
        validate_binding(&plan, ledger)?;
        Ok(plan)
    }
    pub(in crate::macos_network_bundle::upgrade) fn execute(
        lease: &owned::Lease,
        ledger: &Ledger,
        plan: &Plan,
    ) -> Result<()> {
        gate(lease, ledger)?;
        if !ledger.retirement_started {
            return Err("Network cleanup lacks durable intent".into());
        }
        validate_binding(plan, ledger)?;
        if serde_json::to_vec(&load(lease, ledger)?)? != serde_json::to_vec(plan)? {
            return Err("Network cleanup plan changed".into());
        }
        launchd::require_management_unloaded()?;
        launchd::require_helper_unloaded()?;
        cleanup(plan, &mut NativeTree::new(lease)?)
    }
}
#[cfg(target_os = "macos")]
pub(super) use platform::{execute, load, prepare};
#[cfg(test)]
mod tests;
