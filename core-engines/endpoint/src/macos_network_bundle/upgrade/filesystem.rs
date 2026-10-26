//! Root-owned storage and the nonsecret, denial-only GUI maintenance marker.
//! The marker never authorizes an OS request; that requires the lifecycle IPC.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(super) const STATE: &str = "/Library/AthernexEndpoint/state";
pub(super) const ROOT: &str = "/Library/AthernexEndpoint/network-upgrade";
pub(super) const GUARD_DIRECTORY: &str = "/Library/Application Support/AthernexNetwork";
const GUARD_NAME: &str = "upgrade-state.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub device: u64,
    pub inode: u64,
}
impl Identity {
    pub fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    pub fn verify(&self, path: &Path) -> Result<()> {
        if Self::of(&fs::symlink_metadata(path)?) != *self {
            return Err("Network upgrade object identity changed".into());
        }
        Ok(())
    }
}

pub(super) fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Network upgrade requires root".into());
    }
    Ok(())
}

pub(super) fn protected_directory(path: &Path, mode: u32) -> Result<Identity> {
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err("Network upgrade directory must be absolute and canonical".into());
    }
    for (index, ancestor) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (index == 0 && metadata.mode() & 0o7777 != mode)
        {
            return Err("Network upgrade directory protection differs".into());
        }
    }
    Ok(Identity::of(&fs::symlink_metadata(path)?))
}

fn create_directory(path: &Path, mode: u32) -> Result<()> {
    if ![0o700, 0o755].contains(&mode) {
        return Err("Network upgrade directory mode is invalid".into());
    }
    let parent = path.parent().ok_or("Network upgrade parent is missing")?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err("Network upgrade parent is not protected".into());
        }
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            protected_directory(path, mode)?;
            // A previous exclusive rename may have succeeded before its
            // parent fsync failed. Reconcile that durability before success.
            File::open(parent)?.sync_all()?;
            protected_directory(path, mode)?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    // Umask must not leave a mis-mode directory at the final name, including
    // after a crash. Publish only after exact permissions and inode durability
    // have been established on the held, private temporary directory.
    let temporary = tempfile::Builder::new()
        .prefix(".network-upgrade-directory-")
        .tempdir_in(parent)?;
    publish_directory(temporary.path(), path, mode)?;
    protected_directory(path, mode)?;
    Ok(())
}

fn publish_directory(temporary: &Path, destination: &Path, mode: u32) -> Result<()> {
    if ![0o700, 0o755].contains(&mode)
        || temporary.parent().is_none()
        || temporary.parent() != destination.parent()
        || temporary == destination
    {
        return Err("Network upgrade directory publication differs".into());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(temporary)?;
    let before = directory.metadata()?;
    if !before.is_dir()
        || before.uid() != unsafe { libc::geteuid() }
        || before.mode() & 0o7777 != 0o700
    {
        return Err("Network upgrade temporary directory protection differs".into());
    }
    let identity = Identity::of(&before);
    identity.verify(temporary)?;
    directory.set_permissions(fs::Permissions::from_mode(mode))?;
    let prepared = directory.metadata()?;
    if Identity::of(&prepared) != identity || prepared.mode() & 0o7777 != mode {
        return Err("Network upgrade directory preparation differs".into());
    }
    directory.sync_all()?;
    identity.verify(temporary)?;
    move_exclusive(temporary, identity, destination)?;
    identity.verify(destination)?;
    if directory.metadata()?.mode() & 0o7777 != mode {
        return Err("Network upgrade published directory protection differs".into());
    }
    Ok(())
}

pub(super) fn prepare_guard_directory() -> Result<()> {
    require_root()?;
    create_directory(Path::new(GUARD_DIRECTORY), 0o755)
}

pub(super) fn require_state(state: &Path) -> Result<()> {
    require_root()?;
    if state != Path::new(STATE) {
        return Err("Network upgrades require the installed system state".into());
    }
    protected_directory(state, 0o700)?;
    Ok(())
}

/// One global owner, including across process restart and alternative callers.
pub(crate) struct Lease {
    directory: PathBuf,
    directory_identity: Identity,
    _file: File,
}
impl Lease {
    pub fn acquire() -> Result<Self> {
        require_root()?;
        super::super::protected_staging_root()?;
        let directory = PathBuf::from(ROOT);
        create_directory(&directory, 0o700)?;
        let directory_identity = protected_directory(&directory, 0o700)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("owner.lock"))?;
        check_file(&file.metadata()?, 0o600, 0)?;
        file.try_lock()
            .map_err(|_| "Another network upgrade owns the transaction")?;
        directory_identity.verify(&directory)?;
        Ok(Self {
            directory,
            directory_identity,
            _file: file,
        })
    }
    pub fn directory(&self) -> Result<&Path> {
        self.directory_identity.verify(&self.directory)?;
        protected_directory(&self.directory, 0o700)?;
        Ok(&self.directory)
    }
}

fn check_file(metadata: &fs::Metadata, mode: u32, owner: u32) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != mode
    {
        return Err("Network upgrade file protection differs".into());
    }
    Ok(())
}

pub(super) fn read_owned(path: &Path, limit: usize, mode: u32) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    check_file(&before, mode, 0)?;
    if before.len() > limit as u64 {
        return Err("Network upgrade record exceeds its bound".into());
    }
    let mut bytes = Vec::new();
    (&file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > limit
        || bytes.len() as u64 != before.len()
        || Identity::of(&before) != Identity::of(&after)
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("Network upgrade record changed during reading".into());
    }
    Identity::of(&after).verify(path)?;
    Ok(bytes)
}

/// Caller owns the global lease and has reconciled the previous record first.
/// A successful return includes file and parent-directory durability.
pub(super) fn write_owned(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if ![0o600, 0o644, 0o700].contains(&mode) {
        return Err("Network upgrade file mode is invalid".into());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => check_file(&metadata, mode, 0)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .ok_or("Network upgrade record parent is missing")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn guard_bytes(transaction: &str) -> Result<Vec<u8>> {
    if !athernex_endpoint_protocol::hex_id(transaction) {
        return Err("Invalid network upgrade marker binding".into());
    }
    Ok(serde_json::to_vec(&serde_json::json!({
        "schema": 1, "transaction_id": transaction, "pending": true
    }))?)
}

pub(super) fn publish_guard(transaction: &str) -> Result<()> {
    prepare_guard_directory()?;
    let path = Path::new(GUARD_DIRECTORY).join(GUARD_NAME);
    let bytes = guard_bytes(transaction)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if read_owned(&path, 256, 0o644)? != bytes {
                return Err("Another network upgrade marker is present".into());
            }
            // Also reconcile a previous rename whose directory fsync failed.
            File::open(&path)?.sync_all()?;
            File::open(GUARD_DIRECTORY)?.sync_all()?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    write_owned(&path, &bytes, 0o644)
}

pub(super) fn remove_guard(transaction: &str) -> Result<()> {
    protected_directory(Path::new(GUARD_DIRECTORY), 0o755)?;
    let path = Path::new(GUARD_DIRECTORY).join(GUARD_NAME);
    if read_owned(&path, 256, 0o644)? != guard_bytes(transaction)? {
        return Err("Network upgrade marker ownership differs".into());
    }
    fs::remove_file(path)?;
    File::open(GUARD_DIRECTORY)?.sync_all()?;
    Ok(())
}

pub(super) fn sync_tree(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("Network upgrade snapshot protection differs".into());
    }
    if metadata.is_dir() {
        for (index, entry) in fs::read_dir(path)?.enumerate() {
            if index >= 512 {
                return Err("Network upgrade snapshot entry bound exceeded".into());
            }
            sync_tree(&entry?.path())?;
        }
    } else if !metadata.is_file() || metadata.nlink() != 1 {
        return Err("Network upgrade snapshot contains an unapproved object".into());
    }
    File::open(path)?.sync_all()?;
    Ok(())
}

pub(super) fn exchange(
    left: &Path,
    left_id: Identity,
    right: &Path,
    right_id: Identity,
) -> Result<()> {
    left_id.verify(left)?;
    right_id.verify(right)?;
    if left_id.device != right_id.device {
        return Err("Network upgrade exchange requires one filesystem".into());
    }
    let a = std::ffi::CString::new(left.as_os_str().as_encoded_bytes())?;
    let b = std::ffi::CString::new(right.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_SWAP) } != 0 {
        return Err("Network upgrade app exchange failed".into());
    }
    confirm_exchange(left, right_id, right, left_id)
}

/// Move a previously bound object into an absent destination. An intent record
/// must precede this call so either post-crash location can be reconciled.
pub(super) fn move_exclusive(from: &Path, identity: Identity, to: &Path) -> Result<()> {
    identity.verify(from)?;
    match fs::symlink_metadata(to) {
        Ok(_) => return Err("Network upgrade destination already exists".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let a = std::ffi::CString::new(from.as_os_str().as_encoded_bytes())?;
    let b = std::ffi::CString::new(to.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_EXCL) } != 0 {
        return Err("Network upgrade exclusive move failed".into());
    }
    confirm_move(from, identity, to)
}

fn sync_parents(left: &Path, right: &Path) -> Result<()> {
    File::open(
        left.parent()
            .ok_or("Network upgrade source parent is missing")?,
    )?
    .sync_all()?;
    File::open(
        right
            .parent()
            .ok_or("Network upgrade destination parent is missing")?,
    )?
    .sync_all()?;
    Ok(())
}

/// Reconcile an exclusive move that may have succeeded before either parent
/// fsync failed. Matching contents never substitute for the recorded inode.
pub(super) fn confirm_move(from: &Path, identity: Identity, to: &Path) -> Result<()> {
    let verify = || -> Result<()> {
        match fs::symlink_metadata(from) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Ok(_) => return Err("Network upgrade move source is still present".into()),
            Err(error) => return Err(error.into()),
        }
        identity.verify(to)
    };
    verify()?;
    sync_parents(from, to)?;
    verify()
}

/// IDs describe the expected current locations, after the exchange. Re-sync
/// both parents even when the prior rename is already visible on recovery.
pub(super) fn confirm_exchange(
    left: &Path,
    left_now_id: Identity,
    right: &Path,
    right_now_id: Identity,
) -> Result<()> {
    if left_now_id == right_now_id || left_now_id.device != right_now_id.device {
        return Err("Network upgrade exchanged pair is invalid".into());
    }
    left_now_id.verify(left)?;
    right_now_id.verify(right)?;
    sync_parents(left, right)?;
    left_now_id.verify(left)?;
    right_now_id.verify(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These run on macOS against real filesystem syscalls in an owned temporary
    // tree. They do not create /Library state or assert entitled/live upgrade
    // acceptance. Production entrypoints separately require root/parent guards.
    fn pair() -> (tempfile::TempDir, PathBuf, Identity, PathBuf, Identity) {
        let tree = tempfile::tempdir().unwrap();
        let a = tree.path().join("first");
        let b = tree.path().join("second");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        let left = a.join("object");
        let right = b.join("object");
        fs::write(&left, b"original").unwrap();
        fs::write(&right, b"candidate").unwrap();
        let left_id = Identity::of(&fs::symlink_metadata(&left).unwrap());
        let right_id = Identity::of(&fs::symlink_metadata(&right).unwrap());
        (tree, left, left_id, right, right_id)
    }

    #[test]
    fn actual_exclusive_move_and_recovery_require_exact_owned_positions() {
        let (_tree, from, id, other, _) = pair();
        let to = other.with_file_name("moved");
        move_exclusive(&from, id, &to).unwrap();
        confirm_move(&from, id, &to).unwrap();
        assert!(!from.exists() && id.verify(&to).is_ok());
        fs::write(&from, b"unrelated").unwrap();
        assert!(confirm_move(&from, id, &to).is_err());
        assert!(fs::read(&from).unwrap() == b"unrelated");
        assert!(fs::read(&to).unwrap() == b"original");
    }

    #[test]
    fn existing_destination_or_wrong_inode_cannot_be_adopted() {
        let (_tree, from, from_id, to, to_id) = pair();
        assert!(move_exclusive(&from, from_id, &to).is_err());
        assert!(from_id.verify(&from).is_ok() && to_id.verify(&to).is_ok());
        assert!(confirm_move(&from.with_file_name("absent"), from_id, &to).is_err());
        assert!(fs::read(&from).unwrap() == b"original");
        assert!(fs::read(&to).unwrap() == b"candidate");
    }

    #[test]
    fn actual_exchange_and_recovery_refuse_wrong_or_aliased_pairs() {
        let (_tree, left, old_id, right, new_id) = pair();
        exchange(&left, old_id, &right, new_id).unwrap();
        confirm_exchange(&left, new_id, &right, old_id).unwrap();
        assert!(fs::read(&left).unwrap() == b"candidate");
        assert!(fs::read(&right).unwrap() == b"original");
        assert!(confirm_exchange(&left, old_id, &right, new_id).is_err());
        assert!(confirm_exchange(&left, new_id, &left, new_id).is_err());
    }

    #[test]
    fn actual_file_checks_refuse_links_modes_and_nonregular_records() {
        let (tree, path, _, _, _) = pair();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        check_file(&fs::symlink_metadata(&path).unwrap(), 0o600, uid).unwrap();
        let link = tree.path().join("hardlink");
        fs::hard_link(&path, &link).unwrap();
        assert!(check_file(&fs::symlink_metadata(&path).unwrap(), 0o600, uid).is_err());
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(check_file(&fs::symlink_metadata(&path).unwrap(), 0o600, uid).is_err());
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_owned(&link, 256, 0o600).is_err());
        let fifo = tree.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) } == 0);
        assert!(read_owned(&fifo, 256, 0o600).is_err());
    }

    #[test]
    fn directory_publication_sets_exact_mode_before_exclusive_visibility() {
        let tree = tempfile::tempdir().unwrap();
        let temporary = tempfile::tempdir_in(tree.path()).unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = Identity::of(&fs::symlink_metadata(temporary.path()).unwrap());
        let destination = tree.path().join("published");
        publish_directory(temporary.path(), &destination, 0o755).unwrap();
        assert!(!temporary.path().exists());
        identity.verify(&destination).unwrap();
        assert_eq!(
            fs::symlink_metadata(&destination).unwrap().mode() & 0o7777,
            0o755
        );
        confirm_move(temporary.path(), identity, &destination).unwrap();

        let another = tempfile::tempdir_in(tree.path()).unwrap();
        fs::set_permissions(another.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let another_id = Identity::of(&fs::symlink_metadata(another.path()).unwrap());
        assert!(publish_directory(another.path(), &destination, 0o700).is_err());
        identity.verify(&destination).unwrap();
        another_id.verify(another.path()).unwrap();
        assert_eq!(
            fs::symlink_metadata(&destination).unwrap().mode() & 0o7777,
            0o755
        );

        fs::set_permissions(another.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let absent = tree.path().join("absent");
        assert!(publish_directory(another.path(), &absent, 0o755).is_err());
        assert!(!absent.exists());
    }
}
