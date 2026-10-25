//! Windows filesystem implementation for the shared mutation journal. Directory
//! handles pin ancestry; every descendant open/move/link uses one relative leaf.
//! All failures leave the journal/evidence for reconciliation, never path replay.
use super::*;
use std::{
    io,
    mem::{offset_of, size_of},
    os::windows::io::AsRawHandle,
    path::{Component, Prefix},
    ptr::null_mut,
};
use windows_sys::{
    Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
    },
    Win32::{
        Foundation::ERROR_HANDLE_EOF,
        Storage::FileSystem::{
            FileBasicInfo, FileDispositionInfoEx, FileIdInfo, FileStandardInfo, FileStreamInfo,
            GetDiskFreeSpaceExW, GetDriveTypeW, GetFileInformationByHandleEx, GetFileType,
            GetVolumeInformationByHandleW, SetFileInformationByHandle, DELETE, FILE_ADD_FILE,
            FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO_EX, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO,
            FILE_INFO_BY_HANDLE_CLASS, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
            FILE_STANDARD_INFO, FILE_STREAM_INFO, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES,
            FILE_WRITE_EA, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
        },
        System::SystemServices::{FILE_PERSISTENT_ACLS, FILE_SUPPORTS_HARD_LINKS},
    },
};
#[path = "windows/acl.rs"]
mod acl;
#[path = "windows/raw.rs"]
mod raw;

pub(crate) fn require_administrator() -> Result<()> {
    acl::require_administrator()
}

// Never truncate a Windows file ID to a Unix inode number. ReFS and NTFS expose
// a 128-bit file ID together with the full volume serial through FileIdInfo.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub device: u64,
    pub file_id: [u8; 16],
    pub size: u64,
    pub modified: i64,
    pub changed: i64,
}
pub(super) fn zero_identity() -> Identity {
    Identity::default()
}
fn information<T: Default>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T> {
    let mut value = T::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(value)
}
fn metadata(file: &File) -> Result<(FILE_BASIC_INFO, FILE_STANDARD_INFO)> {
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err("Mutation target must be a disk file".into());
    }
    let basic: FILE_BASIC_INFO = information(file, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = information(file, FileStandardInfo)?;
    if basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || standard.DeletePending {
        return Err("Mutation path is a reparse point or pending deletion".into());
    }
    Ok((basic, standard))
}
pub(super) fn identity(file: &File) -> Result<Identity> {
    let (basic, standard) = metadata(file)?;
    let id: FILE_ID_INFO = information(file, FileIdInfo)?;
    if standard.EndOfFile < 0 {
        return Err("Invalid Windows file size".into());
    }
    Ok(Identity {
        device: id.VolumeSerialNumber,
        file_id: id.FileId.Identifier,
        size: standard.EndOfFile as u64,
        modified: basic.LastWriteTime,
        changed: basic.ChangeTime,
    })
}
pub(super) fn same_node(a: &Identity, b: &Identity) -> bool {
    a.device == b.device && a.file_id == b.file_id
}
fn regular(file: &File) -> Result<()> {
    let (basic, standard) = metadata(file)?;
    if basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 || standard.Directory {
        return Err("Mutation evidence is not a regular file".into());
    }
    Ok(())
}
fn leaf_name(leaf: &str) -> Result<()> {
    if leaf.is_empty()
        || leaf.len() > 1024
        || leaf.ends_with(['.', ' '])
        || leaf
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
        || [".", ".."].contains(&leaf)
    {
        return Err("Invalid Windows mutation leaf name".into());
    }
    let base = leaf.split('.').next().unwrap().to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"].contains(&base.as_str())
        || ["COM", "LPT"].iter().any(|p| {
            base.strip_prefix(p).is_some_and(|n| {
                ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"].contains(&n)
            })
        })
    {
        return Err("Windows device aliases are not mutation filenames".into());
    }
    Ok(())
}
fn parts(path: &Path) -> Result<(String, Vec<String>)> {
    if !valid_path(path)
        || path
            .to_str()
            .is_none_or(|s| s.split(['\\', '/']).any(|s| [".", ".."].contains(&s)))
    {
        return Err("Invalid Windows mutation path".into());
    }
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => return Err("Mutation requires an absolute local drive path".into()),
        },
        _ => return Err("Mutation requires an absolute local drive path".into()),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err("Mutation path must start at the drive root".into());
    }
    let mut names = Vec::new();
    for part in components {
        let Component::Normal(name) = part else {
            return Err("Mutation path contains traversal".into());
        };
        let name = name.to_str().ok_or("Mutation path must be Unicode")?;
        leaf_name(name)?;
        names.push(name.into());
    }
    if names.len() > 128 {
        return Err("Mutation path exceeds its directory-depth budget".into());
    }
    Ok((format!("{}:\\", drive as char), names))
}
const DIRECTORY_READ: u32 = READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE;
const DIRECTORY_WRITE: u32 =
    DIRECTORY_READ | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
pub(crate) struct Dir {
    pub file: File,
    pub path: PathBuf,
    // Denying delete sharing on every ancestor prevents namespace replacement.
    ancestors: Vec<File>,
}
impl Dir {
    pub fn open(path: &Path) -> Result<Self> {
        let (root, names) = parts(path)?;
        let root_wide: Vec<u16> = root.encode_utf16().chain([0]).collect();
        // Reject network/device roots. 2=removable, 3=fixed, 6=RAM disk.
        if ![2, 3, 6].contains(&unsafe { GetDriveTypeW(root_wide.as_ptr()) }) {
            return Err("Mutation storage and scope require a local disk".into());
        }
        let mut file = raw::open(
            None,
            &format!("\\??\\{root}"),
            if names.is_empty() {
                DIRECTORY_WRITE
            } else {
                DIRECTORY_READ
            },
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            null_mut(),
        )?;
        metadata(&file)?;
        let mut ancestors = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let next = raw::open(
                Some(&file),
                name,
                if index + 1 == names.len() {
                    DIRECTORY_WRITE
                } else {
                    DIRECTORY_READ
                },
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                null_mut(),
            )?;
            metadata(&next)?;
            ancestors.push(file);
            file = next;
        }
        let mut flags = 0;
        if unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut flags,
                null_mut(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if flags & (FILE_PERSISTENT_ACLS | FILE_SUPPORTS_HARD_LINKS)
            != FILE_PERSISTENT_ACLS | FILE_SUPPORTS_HARD_LINKS
        {
            return Err(
                "Mutation filesystem must support persistent ACLs and atomic hard links".into(),
            );
        }
        Ok(Self {
            file,
            path: path.into(),
            ancestors,
        })
    }
    pub fn private(&self) -> Result<()> {
        acl::private(&self.file)
    }
    pub(crate) fn service_private(&self) -> Result<()> {
        acl::service_private(&self.file)
    }
    pub fn directory(&self, leaf: &str) -> Result<Self> {
        self.make_directory(leaf, false, false)
    }
    pub(crate) fn maintenance_directory(&self, leaf: &str) -> Result<Self> {
        self.make_directory(leaf, false, true)
    }
    /// A new scanner workspace must never adopt an existing, possibly shared
    /// directory. ACL-edit rights apply only to the object just created.
    pub(crate) fn fresh_directory(&self, leaf: &str) -> Result<Self> {
        self.make_directory(leaf, true, false)
    }
    fn make_directory(&self, leaf: &str, fresh: bool, maintenance: bool) -> Result<Self> {
        leaf_name(leaf)?;
        let descriptor = if maintenance {
            acl::maintenance_descriptor()?
        } else {
            acl::descriptor()?
        };
        let file = raw::open(
            Some(&self.file),
            leaf,
            DIRECTORY_WRITE | if fresh { WRITE_DAC | WRITE_OWNER } else { 0 },
            if fresh { FILE_CREATE } else { FILE_OPEN_IF },
            FILE_DIRECTORY_FILE,
            descriptor.0,
        )?;
        metadata(&file)?;
        acl::private(&file)?;
        self.sync()?;
        let mut ancestors = self
            .ancestors
            .iter()
            .map(File::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        ancestors.push(self.file.try_clone()?);
        Ok(Self {
            file,
            path: self.path.join(leaf),
            ancestors,
        })
    }
    pub fn sync(&self) -> Result<()> {
        raw::flush(&self.file)
    }
    pub fn still_bound(&self) -> Result<()> {
        let now = Self::open(&self.path)?;
        if !same_node(&identity(&now.file)?, &identity(&self.file)?) {
            return Err("Mutation parent directory was replaced".into());
        }
        Ok(())
    }
    fn open_file(&self, leaf: &str, access: u32) -> Result<File> {
        leaf_name(leaf)?;
        let f = raw::open(
            Some(&self.file),
            leaf,
            access | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            null_mut(),
        )?;
        regular(&f)?;
        Ok(f)
    }
    pub fn read(&self, leaf: &str) -> Result<File> {
        self.open_file(leaf, FILE_GENERIC_READ)
    }
    pub fn read_private(&self, leaf: &str) -> Result<File> {
        let file = self.read(leaf)?;
        acl::private(&file)?;
        Ok(file)
    }
    pub(crate) fn state_file(&self, leaf: &str) -> Result<File> {
        self.state_file_for(leaf, false)
    }
    pub(crate) fn maintenance_file(&self, leaf: &str) -> Result<File> {
        self.state_file_for(leaf, true)
    }
    fn state_file_for(&self, leaf: &str, maintenance: bool) -> Result<File> {
        leaf_name(leaf)?;
        let descriptor = if maintenance {
            acl::maintenance_descriptor()?
        } else {
            acl::descriptor()?
        };
        let file = raw::open(
            Some(&self.file),
            leaf,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE,
            descriptor.0,
        )?;
        regular(&file)?;
        acl::private(&file)?;
        let info: FILE_STANDARD_INFO = information(&file, FileStandardInfo)?;
        if info.NumberOfLinks != 1 {
            return Err("Private state file has multiple links".into());
        }
        Ok(file)
    }
    pub fn create(&self, leaf: &str) -> Result<File> {
        self.create_with_acl_rights(leaf, false, false)
    }
    pub(crate) fn create_maintenance(&self, leaf: &str) -> Result<File> {
        self.create_with_acl_rights(leaf, false, true)
    }
    pub(crate) fn create_for_scanner(&self, leaf: &str) -> Result<File> {
        self.create_with_acl_rights(leaf, true, false)
    }
    fn create_with_acl_rights(&self, leaf: &str, scanner: bool, maintenance: bool) -> Result<File> {
        leaf_name(leaf)?;
        let descriptor = if maintenance {
            acl::maintenance_descriptor()?
        } else {
            acl::descriptor()?
        };
        let f = raw::open(
            Some(&self.file),
            leaf,
            FILE_GENERIC_READ
                | FILE_GENERIC_WRITE
                | DELETE
                | if scanner { WRITE_DAC | WRITE_OWNER } else { 0 },
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
            descriptor.0,
        )?;
        regular(&f)?;
        acl::private(&f)?;
        Ok(f)
    }
    pub(super) fn stat(&self, leaf: &str) -> Result<Option<Identity>> {
        match self.open_file(leaf, FILE_READ_ATTRIBUTES) {
            Ok(f) => Ok(Some(identity(&f)?)),
            Err(e)
                if e.downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    pub fn exists(&self, leaf: &str) -> Result<bool> {
        Ok(self.stat(leaf)?.is_some())
    }
    pub fn unlink(&self, leaf: &str) -> Result<()> {
        let file = match self.open_file(leaf, DELETE | FILE_READ_ATTRIBUTES) {
            Ok(f) => f,
            Err(e)
                if e.downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(())
            }
            Err(e) => return Err(e),
        };
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfoEx,
                (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        drop(file);
        self.sync()
    }
    pub fn move_new(&self, leaf: &str, to: &Dir, new: &str) -> Result<()> {
        leaf_name(new)?;
        let file = self.open_file(leaf, DELETE | FILE_READ_ATTRIBUTES)?;
        raw::rename(&file, &to.file, new, false)
    }
    pub fn link_new(&self, leaf: &str, to: &Dir, new: &str) -> Result<()> {
        leaf_name(new)?;
        let file = self.open_file(leaf, DELETE | FILE_GENERIC_READ | FILE_GENERIC_WRITE)?;
        raw::link(&file, &to.file, new)
    }
    pub fn write_json(&self, leaf: &str, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > 65536 {
            return Err("Mutation journal exceeds its byte budget".into());
        }
        self.write_atomic(leaf, &bytes, false)
    }
    pub(crate) fn write_maintenance(&self, leaf: &str, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 128 * 1024 * 1024 {
            return Err("Maintenance file exceeds its byte budget".into());
        }
        self.write_atomic(leaf, bytes, true)
    }
    fn write_atomic(&self, leaf: &str, bytes: &[u8], maintenance: bool) -> Result<()> {
        leaf_name(leaf)?;
        let temp = format!(".{leaf}.new");
        self.unlink(&temp)?;
        let mut file = self.create_with_acl_rights(&temp, false, maintenance)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        raw::rename(&file, &self.file, leaf, true)?;
        self.sync()
    }
    pub fn read_json<T: serde::de::DeserializeOwned>(&self, leaf: &str) -> Result<T> {
        let file = self.read(leaf)?;
        Self::decode_private(file, false)
    }
    pub(crate) fn snapshot_json<T: serde::de::DeserializeOwned>(&self, leaf: &str) -> Result<T> {
        leaf_name(leaf)?;
        let file = raw::snapshot(&self.file, leaf, FILE_GENERIC_READ | SYNCHRONIZE)?;
        let basic: FILE_BASIC_INFO = information(&file, FileBasicInfo)?;
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
            || basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        {
            return Err("Private snapshot is not a regular disk file".into());
        }
        // Atomic replacement can unlink an already-open snapshot. Its handle
        // still refers to the verified old bytes; it need not retain a name.
        Self::decode_private(file, true)
    }
    fn decode_private<T: serde::de::DeserializeOwned>(file: File, snapshot: bool) -> Result<T> {
        acl::private(&file)?;
        let standard: FILE_STANDARD_INFO = information(&file, FileStandardInfo)?;
        if (standard.NumberOfLinks != 1 && !(snapshot && standard.NumberOfLinks == 0))
            || standard.EndOfFile > 65536
        {
            return Err("Untrusted mutation journal".into());
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("Mutation journal exceeds its byte budget".into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}
pub(super) fn sync_file(directory: &Dir, leaf: &str) -> Result<()> {
    directory
        .open_file(leaf, FILE_GENERIC_READ | FILE_GENERIC_WRITE)?
        .sync_all()?;
    Ok(())
}
pub(super) fn capture(
    parent: &Dir,
    leaf: &str,
    to: &Dir,
    new: &str,
    expected: &Identity,
) -> Result<()> {
    leaf_name(new)?;
    // Capture needs a rename-capable metadata handle, not content access. A
    // protected source has already been verified by this worker's scan receipt.
    let file = parent.open_file(leaf, DELETE | FILE_READ_ATTRIBUTES)?;
    unnamed_stream_only(&file)?;
    if identity(&file)? != *expected {
        return Err("File changed before atomic capture".into());
    }
    // No delete sharing keeps this exact source name bound until rename finishes.
    raw::rename(&file, &to.file, new, false)
}
pub(super) fn scope(intent: &Intent, path: &Path, quarantine: &Dir) -> Result<(Dir, String)> {
    let parent = Dir::open(path.parent().ok_or("Mutation target has no parent")?)?;
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid mutation filename")?
        .to_string();
    leaf_name(&leaf)?;
    let ids = parent
        .ancestors
        .iter()
        .chain([&parent.file])
        .map(identity)
        .collect::<Result<Vec<_>>>()?;
    let mut matched = false;
    for root in &intent.roots {
        let root = Dir::open(root)?;
        let id = identity(&root.file)?;
        matched |= ids.iter().any(|ancestor| same_node(ancestor, &id));
    }
    if !matched {
        return Err("Mutation path is outside the current action roots".into());
    }
    if identity(&parent.file)?.device != identity(&quarantine.file)?.device {
        return Err("Mutation requires the same filesystem as quarantine".into());
    }
    Ok((parent, leaf))
}
pub(super) fn available(directory: &Dir) -> Result<u64> {
    let path: Vec<u16> = directory
        .path
        .to_str()
        .ok_or("Invalid mutation directory")?
        .encode_utf16()
        .chain([0])
        .collect();
    let mut available = 0;
    if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut available, null_mut(), null_mut()) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(available)
}
pub(super) fn trusted(intent: &Intent) -> Result<()> {
    if !matches!(
        intent.verifier,
        Some(Verifier::Local | Verifier::Retained | Verifier::WindowsProtected { .. })
    ) {
        return Err("Windows mutations require their local, protected or retained verifier".into());
    }
    let state = Dir::open(&intent.state)?;
    state.private()?;
    let state_ids = state
        .ancestors
        .iter()
        .chain([&state.file])
        .map(identity)
        .collect::<Result<Vec<_>>>()?;
    for root in &intent.roots {
        let root = Dir::open(root)?;
        let root_id = identity(&root.file)?;
        if state_ids.iter().any(|id| same_node(id, &root_id)) {
            return Err(
                "Mutation state must be outside action roots, including Windows aliases".into(),
            );
        }
    }
    // Verify the metadata flush primitive before any source can be moved.
    state.sync()
}
pub(super) fn broker_query(_: &Path, _: &Path, _: Duration) -> Result<crate::Verdict> {
    Err("A Unix native broker cannot authorize a Windows mutation".into())
}
fn unnamed_stream_only(file: &File) -> Result<()> {
    let mut buffer = vec![0usize; 65536 / size_of::<usize>()];
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStreamInfo,
            buffer.as_mut_ptr().cast(),
            65536,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) && identity(file)?.size == 0 {
            return Ok(());
        }
        return Err(error.into());
    }
    let info = unsafe { &*buffer.as_ptr().cast::<FILE_STREAM_INFO>() };
    let offset = offset_of!(FILE_STREAM_INFO, StreamName);
    let length = info.StreamNameLength as usize;
    if info.NextEntryOffset != 0 || length > 65536 - offset || !length.is_multiple_of(2) {
        return Err(
            "Mutation refuses alternate data streams until complete stream retention is available"
                .into(),
        );
    }
    let name = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!(info.StreamName).cast::<u16>(),
            length / 2,
        )
    };
    if name != "::$DATA".encode_utf16().collect::<Vec<_>>() {
        return Err(
            "Mutation refuses alternate data streams until complete stream retention is available"
                .into(),
        );
    }
    Ok(())
}
pub(super) fn hash_file(mut file: File, deadline: Instant) -> Result<(String, Identity)> {
    unnamed_stream_only(&file)?;
    let before = identity(&file)?;
    if before.size > MAX_FILE {
        return Err("Mutation file exceeds 128 MiB".into());
    }
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0; 65536];
    loop {
        remaining(deadline)?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_FILE {
            return Err("Mutation file exceeds 128 MiB".into());
        }
        hash.update(&buffer[..n]);
    }
    unnamed_stream_only(&file)?;
    if identity(&file)? != before || count != before.size {
        return Err("Mutation content changed during verification".into());
    }
    Ok((format!("{:x}", hash.finalize()), before))
}
pub(super) fn local_verdict(
    _: &Path,
    parent: &Dir,
    leaf: &str,
    expected: &Identity,
    deadline: Instant,
) -> Result<crate::Verdict> {
    // Reject unsupported streams before a denied content open could be replaced
    // by a receipt for only the unnamed stream.
    let metadata = parent.open_file(leaf, FILE_READ_ATTRIBUTES)?;
    unnamed_stream_only(&metadata)?;
    if identity(&metadata)? != *expected {
        return Err("File changed before source verification".into());
    }
    let (sha256, id) = hash_file(parent.read(leaf)?, deadline)?;
    if id != *expected {
        return Err("File changed during source verification".into());
    }
    Ok(crate::Verdict {
        sha256,
        bytes: id.size,
        detection: None,
    })
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
    unnamed_stream_only(&input)?;
    let before = identity(&input)?;
    if before.size > MAX_FILE {
        return Err("Mutation file exceeds 128 MiB".into());
    }
    let mut output = to.create(dest)?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0; 65536];
    loop {
        remaining(deadline)?;
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_FILE {
            return Err("Mutation file exceeds 128 MiB".into());
        }
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    unnamed_stream_only(&input)?;
    if count != before.size
        || identity(&input)? != before
        || format!("{:x}", hash.finalize()) != sha
    {
        return Err("Mutation copy does not match the approved hash".into());
    }
    output.sync_all()?;
    to.sync()?;
    identity(&output)
}
