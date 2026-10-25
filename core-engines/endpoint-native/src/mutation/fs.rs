use super::*;
use crate::{broker, scanner};
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
};

pub(super) struct Dir {
    pub file: File,
    pub path: PathBuf,
}
fn checked(fd: i32) -> Result<File> {
    if fd < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn name(s: &str) -> Result<CString> {
    if s.is_empty() || s.contains('/') || [".", ".."].contains(&s) {
        return Err("Invalid mutation leaf name".into());
    }
    Ok(CString::new(s)?)
}
impl Dir {
    pub fn open(path: &Path) -> Result<Self> {
        if !valid_path(path) {
            return Err("Invalid mutation directory".into());
        }
        let mut file = File::open("/")?;
        for part in path.components() {
            if let std::path::Component::Normal(part) = part {
                let part = CString::new(part.as_bytes())?;
                file = checked(unsafe {
                    libc::openat(
                        file.as_raw_fd(),
                        part.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })?;
            }
        }
        Ok(Self {
            file,
            path: path.into(),
        })
    }
    pub fn private(&self) -> Result<()> {
        let m = self.file.metadata()?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err("Mutation storage must be private to the service identity".into());
        }
        Ok(())
    }
    pub fn directory(&self, leaf: &str) -> Result<Self> {
        let n = name(leaf)?;
        if unsafe { libc::mkdirat(self.file.as_raw_fd(), n.as_ptr(), 0o700) } != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(std::io::Error::last_os_error().into());
        }
        self.sync()?;
        let file = checked(unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                n.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        let d = Self {
            file,
            path: self.path.join(leaf),
        };
        d.private()?;
        Ok(d)
    }
    pub fn sync(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
    pub fn still_bound(&self) -> Result<()> {
        let now = Self::open(&self.path)?;
        if node(&now.file.metadata()?) != node(&self.file.metadata()?) {
            return Err("Mutation parent directory was replaced".into());
        }
        Ok(())
    }
    pub fn read(&self, leaf: &str) -> Result<File> {
        let n = name(leaf)?;
        let f = checked(unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                n.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        })?;
        if !f.metadata()?.is_file() {
            return Err("Mutation evidence is not a regular file".into());
        }
        Ok(f)
    }
    pub fn create(&self, leaf: &str) -> Result<File> {
        let n = name(leaf)?;
        checked(unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                n.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })
    }
    pub fn exists(&self, leaf: &str) -> Result<bool> {
        Ok(self.stat(leaf)?.is_some())
    }
    // stat field widths differ across the supported Unix ABIs.
    #[allow(clippy::unnecessary_cast)]
    pub fn stat(&self, leaf: &str) -> Result<Option<Identity>> {
        let n = name(leaf)?;
        let mut s: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                n.as_ptr(),
                &mut s,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(e.into());
        }
        if s.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err("Mutation target must be a regular file".into());
        }
        #[cfg(target_os = "linux")]
        let (mn, cn) = (s.st_mtime_nsec, s.st_ctime_nsec);
        #[cfg(target_os = "macos")]
        let (mn, cn) = (s.st_mtime_nsec, s.st_ctime_nsec);
        Ok(Some(Identity {
            device: s.st_dev as u64,
            inode: s.st_ino as u64,
            size: s.st_size as u64,
            modified_sec: s.st_mtime,
            modified_nsec: mn,
            changed_sec: s.st_ctime,
            changed_nsec: cn,
        }))
    }
    pub fn unlink(&self, leaf: &str) -> Result<()> {
        let n = name(leaf)?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), n.as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        self.sync()
    }
    pub fn move_new(&self, leaf: &str, to: &Dir, new: &str) -> Result<()> {
        let (a, b) = (name(leaf)?, name(new)?);
        #[cfg(target_os = "linux")]
        let code = unsafe {
            libc::renameat2(
                self.file.as_raw_fd(),
                a.as_ptr(),
                to.file.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let code = unsafe {
            libc::renameatx_np(
                self.file.as_raw_fd(),
                a.as_ptr(),
                to.file.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if code != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    pub fn link_new(&self, leaf: &str, to: &Dir, new: &str) -> Result<()> {
        let (a, b) = (name(leaf)?, name(new)?);
        if unsafe {
            libc::linkat(
                self.file.as_raw_fd(),
                a.as_ptr(),
                to.file.as_raw_fd(),
                b.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    pub fn write_json(&self, leaf: &str, value: &impl Serialize) -> Result<()> {
        let temp = format!(".{leaf}.new");
        // The directory is private and a live process holds the mutation lock.
        // An interrupted replacement can leave only this bounded private temp.
        self.unlink(&temp)?;
        let mut f = self.create(&temp)?;
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > 65536 {
            return Err("Mutation journal exceeds its byte budget".into());
        }
        f.write_all(&bytes)?;
        f.sync_all()?;
        let (a, b) = (name(&temp)?, name(leaf)?);
        if unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                a.as_ptr(),
                self.file.as_raw_fd(),
                b.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        self.sync()
    }
    pub fn read_json<T: serde::de::DeserializeOwned>(&self, leaf: &str) -> Result<T> {
        let f = self.read(leaf)?;
        let m = f.metadata()?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 || m.len() > 65536 {
            return Err("Untrusted mutation journal".into());
        }
        let mut bytes = Vec::new();
        f.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("Mutation journal exceeds its byte budget".into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}
pub(super) fn node(m: &std::fs::Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}
pub(super) fn same_node(a: &Identity, b: &Identity) -> bool {
    a.device == b.device && a.inode == b.inode
}
pub(super) fn hash_file(mut f: File, deadline: Instant) -> Result<(String, Identity)> {
    let before = scanner::identity(&f.metadata()?);
    if before.size > MAX_FILE {
        return Err("Mutation file exceeds 128 MiB".into());
    }
    let mut h = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0; 65536];
    loop {
        remaining(deadline)?;
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_FILE {
            return Err("Mutation file exceeds 128 MiB".into());
        }
        h.update(&buf[..n]);
    }
    if before != scanner::identity(&f.metadata()?) || count != before.size {
        return Err("Mutation content changed during verification".into());
    }
    Ok((format!("{:x}", h.finalize()), before))
}
pub(super) fn copy_verified(
    from: &Dir,
    source: &str,
    to: &Dir,
    dest: &str,
    sha: &str,
    deadline: Instant,
) -> Result<Identity> {
    let mut input = from.read(source)?;
    let before = scanner::identity(&input.metadata()?);
    if before.size > MAX_FILE {
        return Err("Mutation file exceeds 128 MiB".into());
    }
    let mut output = to.create(dest)?;
    let mut h = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0; 65536];
    loop {
        remaining(deadline)?;
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_FILE {
            return Err("Mutation file exceeds 128 MiB".into());
        }
        h.update(&buf[..n]);
        output.write_all(&buf[..n])?;
    }
    if count != before.size
        || before != scanner::identity(&input.metadata()?)
        || format!("{:x}", h.finalize()) != sha
    {
        return Err("Mutation copy does not match the approved hash".into());
    }
    output.sync_all()?;
    to.sync()?;
    Ok(scanner::identity(&output.metadata()?))
}

pub(super) fn trusted(intent: &Intent) -> Result<()> {
    broker::trusted(&intent.state, true)?;
    if intent.verifier.is_none() && !broker::configured(&intent.state.join("protection/native"))? {
        return Err("Native mutation requires its persistent broker binding".into());
    }
    Ok(())
}
pub(super) fn scope(intent: &Intent, path: &Path, quarantine: &Dir) -> Result<(Dir, String)> {
    let parent_path = path
        .parent()
        .ok_or("Mutation target has no parent")?
        .to_path_buf();
    let roots = intent
        .roots
        .iter()
        .map(|r| r.canonicalize())
        .collect::<std::io::Result<Vec<_>>>()?;
    if !roots.iter().any(|r| parent_path.starts_with(r)) {
        return Err("Mutation path is outside the current action roots".into());
    }
    let parent = Dir::open(&parent_path)?;
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid mutation filename")?
        .to_string();
    if node(&parent.file.metadata()?).0 != node(&quarantine.file.metadata()?).0 {
        return Err("Mutation requires the same filesystem as quarantine".into());
    }
    Ok((parent, leaf))
}
pub(super) fn available(directory: &Dir) -> Result<u64> {
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(directory.file.as_raw_fd(), &mut v) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    #[allow(clippy::unnecessary_cast)]
    Ok((v.f_bavail as u64).saturating_mul(v.f_frsize as u64))
}
pub(super) fn identity(file: &File) -> Result<Identity> {
    Ok(scanner::identity(&file.metadata()?))
}
pub(super) fn zero_identity() -> Identity {
    Identity {
        device: 0,
        inode: 0,
        size: 0,
        modified_sec: 0,
        modified_nsec: 0,
        changed_sec: 0,
        changed_nsec: 0,
    }
}
pub(super) fn broker_query(state: &Path, path: &Path, timeout: Duration) -> Result<crate::Verdict> {
    broker::query(&state.join("protection/native"), path, timeout)
}
pub(super) fn local_verdict(
    state: &Path,
    parent: &Dir,
    leaf: &str,
    before: &Identity,
    deadline: Instant,
) -> Result<crate::Verdict> {
    // A stopped broker remains authoritative; never bypass its binding.
    if broker::configured(&state.join("protection/native"))? {
        return Err("Local source reads cannot bypass a native broker binding".into());
    }
    scanner::hash_bound(&crate::Scan {
        path: parent.path.join(leaf),
        identity: before.clone(),
        deadline,
    })
}

pub(super) fn sync_file(directory: &Dir, leaf: &str) -> Result<()> {
    directory.read(leaf)?.sync_all()?;
    Ok(())
}
pub(super) fn capture(
    parent: &Dir,
    leaf: &str,
    to: &Dir,
    new: &str,
    _expected: &Identity,
) -> Result<()> {
    parent.move_new(leaf, to, new)
}
