//! Owned, descriptor-relative samples. Code signing happens only in trusted
//! native state, never through a user-controlled watched directory pathname.
use super::*;
use std::{
    ffi::CString,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::Component,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
}
impl Directory {
    fn capture(path: PathBuf, file: &File) -> Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            path,
            device: m.dev(),
            inode: m.ino(),
        })
    }
    fn check(&self, owner: Option<u32>) -> Result<()> {
        let m = fs::symlink_metadata(&self.path)?;
        if !m.is_dir()
            || m.dev() != self.device
            || m.ino() != self.inode
            || owner.is_some_and(|u| m.uid() != u || m.mode() & 0o7777 != 0o700)
            || self.path.canonicalize()? != self.path
        {
            return Err("Native health directory identity changed".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub path: PathBuf,
    pub identity: Identity,
    pub sha256: String,
    pub detection: Option<String>,
}
impl Sample {
    fn check(&self, owner: u32) -> Result<()> {
        let m = fs::symlink_metadata(&self.path)?;
        if !m.is_file()
            || m.uid() != owner
            || m.nlink() != 1
            || m.mode() & 0o077 != 0
            || scanner::identity(&m) != self.identity
            || !receipt::hex_id(&self.sha256)
        {
            return Err("Native health sample identity changed".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub root: Directory,
    pub directory: Directory,
    pub samples: [Sample; 4],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub session: String,
    pub plan_sha256: String,
    pub policy_sha256: String,
    pub owner_uid: u32,
    pub roots: Vec<Root>,
}
pub(super) const NAMES: [&str; 4] = ["clean-text", "blocked-text", "clean-image", "blocked-image"];
pub(super) const TEXT_DETECTION: &str = "AthernexNativeHealthText.UNOFFICIAL";
pub(super) const IMAGE_DETECTION: &str = "AthernexNativeHealthImage.UNOFFICIAL";
impl Manifest {
    pub fn validate(&self, policy: &Policy) -> Result<()> {
        policy.validate()?;
        let folder = format!(
            ".athernex-native-check-{}",
            hash(policy.state.as_os_str().as_encoded_bytes())
        );
        if self.schema != 1
            || !receipt::hex_id(&self.session)
            || !receipt::hex_id(&self.plan_sha256)
            || self.policy_sha256 != receipt::policy_hash(policy)?
            || self.owner_uid == policy.scanner_uid
            || self.roots.len() != policy.roots.len()
        {
            return Err("Native health manifest does not match its scope".into());
        }
        for (root, expected) in self.roots.iter().zip(&policy.roots) {
            if root.root.path != *expected || root.directory.path != expected.join(&folder) {
                return Err("Native health probe is outside its exact owned directory".into());
            }
            root.root.check(None)?;
            root.directory.check(Some(self.owner_uid))?;
            for (i, sample) in root.samples.iter().enumerate() {
                let expected_detection = match i {
                    1 => Some(TEXT_DETECTION),
                    3 => Some(IMAGE_DETECTION),
                    _ => None,
                };
                if sample.path != root.directory.path.join(NAMES[i])
                    || sample.detection.as_deref() != expected_detection
                    || sample.identity.size == 0
                    || sample.identity.size > 16 * 1024 * 1024
                {
                    return Err("Invalid native health sample contract".into());
                }
                sample.check(self.owner_uid)?;
            }
        }
        Ok(())
    }
    /// Only known harmless bytes with their original file identity belong in
    /// the diagnostic journal. A signature name or directory prefix is never
    /// sufficient to suppress ordinary detection evidence.
    pub fn is_probe(&self, event: &Receipt) -> bool {
        event.policy_sha256 == self.policy_sha256
            && event.actor.uid == self.owner_uid
            && event
                .verdict
                .as_ref()
                .is_some_and(|v| self.is_scan_probe(Path::new(&event.path), &event.identity, v))
    }
    pub fn is_scan_probe(
        &self,
        path: &Path,
        identity: &Identity,
        verdict: &crate::Verdict,
    ) -> bool {
        self.roots.iter().flat_map(|r| r.samples.iter()).any(|s| {
            s.detection.is_some()
                && s.path == path
                && s.identity == *identity
                && s.sha256 == verdict.sha256
                && s.detection == verdict.detection
                && s.identity.size == verdict.bytes
        })
    }
}
fn open_dir(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
    let name = CString::new(name.as_bytes())?;
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
        return Err("Native health root must be absolute".into());
    }
    let mut file = File::open("/")?;
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => file = open_dir(&file, n)?,
            _ => return Err("Invalid health root".into()),
        }
    }
    Ok(file)
}
fn owned_dir(parent: &File, name: &str, owner: u32) -> Result<File> {
    let raw = CString::new(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), raw.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let dir = open_dir(parent, std::ffi::OsStr::new(name))?;
    let m = dir.metadata()?;
    if m.uid() != owner || m.mode() & 0o7777 != 0o700 {
        return Err("Native health directory is not privately owned".into());
    }
    Ok(dir)
}
fn store_sample(
    dir: &File,
    name: &str,
    bytes: &[u8],
    executable: bool,
    owner: u32,
) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    // Check before truncation, including hard links and special files.
    if !m.is_file() || m.uid() != owner || m.nlink() != 1 || m.mode() & 0o077 != 0 {
        return Err("Refusing an unowned native health sample".into());
    }
    file.set_len(0)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(if executable {
        0o700
    } else {
        0o600
    }))?;
    file.sync_all()?;
    // A separate read-only description is deliberately retained before native
    // authorization starts. It cannot acquire new read permission afterward.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let read = unsafe { File::from_raw_fd(fd) };
    if scanner::identity(&read.metadata()?) != scanner::identity(&file.metadata()?) {
        return Err("Native health sample changed during preparation".into());
    }
    Ok(read)
}
fn bounded_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    scanner::open_file(path)?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
        return Err("Native health image exceeds its byte budget".into());
    }
    Ok(bytes)
}
fn signed_images(state: &Path, session: &str, helper: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    // Use our native helper on macOS: re-signing Apple's arm64e system images
    // does not establish that they can execute as ordinary third-party code.
    #[cfg(target_os = "macos")]
    let source = helper.canonicalize()?;
    #[cfg(target_os = "linux")]
    let source = {
        let _ = helper;
        Path::new("/usr/bin/true").canonicalize()?
    };
    broker::trusted(&source, false)?;
    let original = bounded_bytes(&source)?;
    #[cfg(target_os = "macos")]
    {
        // Distinct signing identifiers produce separate clean/blocked bytes.
        let sign = |label: &str| -> Result<Vec<u8>> {
            let path = state.join(format!("image-template-{label}"));
            service::write(&path, &original, 0o700)?;
            let (code, output) = child::run(
                Command::new("/usr/bin/codesign")
                    .args([
                        "--force",
                        "--sign",
                        "-",
                        "--identifier",
                        &format!("com.athernex.health.{session}.{label}"),
                        "--options",
                        "0",
                    ])
                    .arg(&path),
                Duration::from_secs(10),
                4096,
            )?;
            if code != 0 {
                return Err(format!(
                    "Cannot prepare native health executable: {}",
                    String::from_utf8_lossy(&output)
                )
                .into());
            }
            let (code, _) = child::run(
                Command::new("/usr/bin/codesign")
                    .args(["--verify", "--strict"])
                    .arg(&path),
                Duration::from_secs(5),
                4096,
            )?;
            if code != 0 {
                return Err("Native health executable signature is invalid".into());
            }
            let changed = bounded_bytes(&path)?;
            if changed == original {
                return Err("Native health executable must have unique bytes".into());
            }
            Ok(changed)
        };
        Ok((sign("clean")?, sign("blocked")?))
    }
    #[cfg(target_os = "linux")]
    {
        // Tests exercise actual ELF execution. This branch is never selected by
        // production macOS supervision and does not imitate Apple signing.
        let _ = state;
        let mut changed = original.clone();
        changed.extend_from_slice(session.as_bytes());
        Ok((original, changed))
    }
}

pub struct Prepared {
    pub manifest: Manifest,
    pub(super) descriptors: Vec<[File; 4]>,
    _directories: Vec<(File, File)>,
}
/// On macOS, helper is the trusted native adapter executable. Its copied health
/// entry point exits successfully without starting services or authorization.
pub fn prepare(plan: &service::Plan, helper: &Path) -> Result<Prepared> {
    plan.validate()?;
    broker::trusted(&plan.policy.state, true)?;
    broker::trusted(&plan.database, false)?;
    let owner = unsafe { libc::geteuid() };
    let native = open_root(&plan.policy.state)?;
    let private_fd = owned_dir(&native, "health", owner)?;
    let _proofs = owned_dir(&private_fd, "proofs", owner)?;
    let _verdicts = owned_dir(&native, "probe-verdicts", owner)?;
    let private = plan.policy.state.join("health");
    let session = nonce()?;
    let (image, bad_image) = signed_images(&private, &session, helper)?;
    let clean = b"Ordinary Athernex native health check".to_vec();
    let blocked = format!("ATHERNEX HARMLESS NATIVE HEALTH CHECK {session}").into_bytes();
    let contents = [clean, blocked, image, bad_image];
    let folder = format!(
        ".athernex-native-check-{}",
        hash(plan.policy.state.as_os_str().as_encoded_bytes())
    );
    let mut manifest = Manifest {
        schema: 1,
        session,
        plan_sha256: plan.digest()?,
        policy_sha256: receipt::policy_hash(&plan.policy)?,
        owner_uid: owner,
        roots: Vec::new(),
    };
    let mut descriptors = Vec::new();
    let mut directories = Vec::new();
    for root in &plan.policy.roots {
        let root_fd = open_root(root)?;
        let dir = owned_dir(&root_fd, &folder, owner)?;
        let mut entries = Vec::new();
        let mut handles = Vec::new();
        for (i, bytes) in contents.iter().enumerate() {
            let file = store_sample(&dir, NAMES[i], bytes, i >= 2, owner)?;
            entries.push(Sample {
                path: root.join(&folder).join(NAMES[i]),
                identity: scanner::identity(&file.metadata()?),
                sha256: hash(bytes),
                detection: match i {
                    1 => Some(TEXT_DETECTION.into()),
                    3 => Some(IMAGE_DETECTION.into()),
                    _ => None,
                },
            });
            handles.push(file);
        }
        dir.sync_all()?;
        root_fd.sync_all()?;
        manifest.roots.push(Root {
            root: Directory::capture(root.clone(), &root_fd)?,
            directory: Directory::capture(root.join(&folder), &dir)?,
            samples: entries
                .try_into()
                .map_err(|_| "Incomplete health samples")?,
        });
        descriptors.push(
            handles
                .try_into()
                .map_err(|_| "Incomplete health descriptors")?,
        );
        directories.push((root_fd, dir));
    }
    manifest.validate(&plan.policy)?;
    let signatures = format!(
        "{}:{}:AthernexNativeHealthText\n{}:{}:AthernexNativeHealthImage\n",
        hash(&contents[1]),
        contents[1].len(),
        hash(&contents[3]),
        contents[3].len()
    );
    service::write(
        &plan.database.join("athernex-health.hsb"),
        signatures.as_bytes(),
        0o644,
    )?;
    service::write(
        &private.join("manifest.json"),
        &serde_json::to_vec(&manifest)?,
        0o600,
    )?;
    Ok(Prepared {
        manifest,
        descriptors,
        _directories: directories,
    })
}
