//! Probe writes use directory descriptors so user-controlled renames or symlinks
//! cannot redirect a root write/chmod outside the selected directory.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, File},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DirectoryIdentity {
    pub path: PathBuf,
    device: u64,
    inode: u64,
}
impl DirectoryIdentity {
    fn new(path: PathBuf, file: &File) -> Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            path,
            device: m.dev(),
            inode: m.ino(),
        })
    }
    pub fn matches(&self) -> bool {
        fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.is_dir() && m.dev() == self.device && m.ino() == self.inode)
    }
}
pub(super) struct Probe {
    _root: File,
    directory: File,
    pub identities: [DirectoryIdentity; 2],
}
impl Probe {
    pub fn path_for_reader(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}/{name}",
            std::process::id(),
            self.directory.as_raw_fd()
        ))
    }
}
fn open_dir(parent: &File, name: &CString) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_root(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err("Native probe root must be absolute".into());
    }
    let mut dir = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => dir = open_dir(&dir, &CString::new(name.as_bytes())?)?,
            _ => return Err("Invalid native probe root component".into()),
        }
    }
    Ok(dir)
}
pub(super) fn prepare(root: &Path, suffix: &str, owner: u32) -> Result<Probe> {
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid native probe identity".into());
    }
    let root_fd = open_root(root)?;
    let name = format!(".athernex-protection-check-{suffix}");
    let raw = CString::new(name.as_bytes())?;
    if unsafe { libc::mkdirat(root_fd.as_raw_fd(), raw.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let directory = open_dir(&root_fd, &raw)?;
    let meta = directory.metadata()?;
    if meta.uid() != owner || meta.mode() & 0o777 != 0o700 {
        return Err("Native probe directory identity changed".into());
    }
    for (name, content) in [
        (
            "clean-probe",
            b"Ordinary Athernex protection self test".as_slice(),
        ),
        ("blocked-probe", super::PROBE),
    ] {
        let name = CString::new(name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            let stat = unsafe { stat.assume_init() };
            if stat.st_uid != owner
                || stat.st_mode & libc::S_IFMT != libc::S_IFREG
                || stat.st_mode & 0o077 != 0
                || stat.st_size != content.len() as i64
            {
                return Err("Native probe file identity changed".into());
            }
        } else {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                return Err(std::io::Error::last_os_error().into());
            }
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600 as libc::mode_t,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            file.write_all(content)?;
            file.sync_all()?;
        }
    }
    directory.sync_all()?;
    Ok(Probe {
        identities: [
            DirectoryIdentity::new(root.into(), &root_fd)?,
            DirectoryIdentity::new(root.join(name), &directory)?,
        ],
        _root: root_fd,
        directory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_writes_reject_symlinks_and_reuse_only_owned_probes() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        std::os::unix::fs::symlink(
            outside.path(),
            root.path().join(".athernex-protection-check-ab"),
        )
        .unwrap();
        assert!(prepare(root.path(), "ab", uid).is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
        let probe = prepare(root.path(), "cd", uid).unwrap();
        assert!(probe.identities.iter().all(DirectoryIdentity::matches));
        let again = prepare(root.path(), "cd", uid).unwrap();
        assert_eq!(
            fs::read(again.path_for_reader("blocked-probe")).unwrap(),
            super::super::PROBE
        );
        let original = root.path().join(".athernex-protection-check-cd");
        let moved = root.path().join("moved");
        fs::rename(&original, &moved).unwrap();
        assert!(!probe.identities[1].matches());
        assert_eq!(
            fs::read(probe.path_for_reader("blocked-probe")).unwrap(),
            super::super::PROBE
        );
        std::os::unix::fs::symlink(outside.path(), &original).unwrap();
        assert!(prepare(root.path(), "cd", uid).is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }
}
