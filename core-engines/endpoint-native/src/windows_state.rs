//! Private Windows state uses the same handle-relative ancestry and ACL checks
//! as journaled response. Keep this guard alive for path-based SQLite access.
use crate::{mutation::fs::Dir, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::File,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, VOLUME_NAME_DOS, VOLUME_NAME_NT,
};
mod cleanup;
mod scanner;
#[cfg(test)]
mod tests;
pub use cleanup::WorkspaceIdentity;
pub use scanner::ScannerDirectory;

pub struct Directory(Dir);
pub struct PinnedDirectory(Dir);
pub fn is_administrator() -> Result<bool> {
    crate::mutation::fs::is_administrator()
}
pub fn require_administrator() -> Result<()> {
    crate::mutation::fs::require_administrator()
}
pub fn require_local_system() -> Result<()> {
    use std::{
        mem::size_of,
        os::windows::io::{FromRawHandle, OwnedHandle},
        ptr::null_mut,
    };
    use windows_sys::Win32::{
        Security::{
            GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut handle = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut bytes = 0;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut bytes);
    }
    if bytes == 0 || bytes > 65536 {
        return Err("Invalid Windows service token size".into());
    }
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    if unsafe { IsWellKnownSid(user.User.Sid, WinLocalSystemSid) } == 0 {
        return Err("Windows protection requires the LocalSystem service identity".into());
    }
    Ok(())
}
pub(crate) fn name(file: &File, flags: u32) -> Result<String> {
    let mut buffer = [0u16; 1024];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            flags,
        )
    };
    if length == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length as usize >= buffer.len() {
        return Err("Windows directory name exceeds its budget".into());
    }
    Ok(String::from_utf16(&buffer[..length as usize])?)
}
impl PinnedDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self(Dir::open(path)?))
    }
    pub fn nt(&self) -> Result<String> {
        name(&self.0.file, VOLUME_NAME_NT)
    }
    pub fn dos(&self) -> Result<String> {
        let name = name(&self.0.file, VOLUME_NAME_DOS)?;
        Ok(name
            .strip_prefix("\\\\?\\")
            .ok_or("Expected a canonical local Windows drive path")?
            .into())
    }
}
impl Directory {
    /// Create a new private child without adopting or relaxing an existing
    /// directory. The parent ancestry remains pinned for this guard's lifetime.
    pub fn create_under(parent: &Path, leaf: &str) -> Result<Self> {
        Ok(Self(Dir::open(parent)?.fresh_directory(leaf)?))
    }
    /// Create shared administrator/SYSTEM state, or validate an existing private
    /// child. Never changes the permissions of an existing directory.
    pub fn maintenance_under(parent: &Path, leaf: &str) -> Result<Self> {
        Ok(Self(Dir::open(parent)?.maintenance_directory(leaf)?))
    }
    pub fn open(path: &Path) -> Result<Self> {
        let directory = Dir::open(path)?;
        directory.private()?;
        Ok(Self(directory))
    }
    pub fn path(&self) -> &Path {
        &self.0.path
    }
    /// A machine-wide installation must remain usable by both LocalSystem and
    /// elevated maintenance accounts, independent of the current user's SID.
    pub fn require_private_user(&self) -> Result<()> {
        self.0.user_private()
    }
    pub fn require_service_access(&self) -> Result<()> {
        self.0.service_private()
    }
    pub fn nt(&self) -> Result<String> {
        name(&self.0.file, VOLUME_NAME_NT)
    }
    pub fn directory(&self, leaf: &str) -> Result<Self> {
        Ok(Self(self.0.directory(leaf)?))
    }
    /// Shared service/maintenance objects created by administrators use only
    /// SYSTEM/admin ownership and grants. Existing ACLs are never relaxed.
    pub fn maintenance_directory(&self, leaf: &str) -> Result<Self> {
        Ok(Self(self.0.maintenance_directory(leaf)?))
    }
    /// Exact create-only maintenance child; a competing existing object is refused.
    pub fn fresh_maintenance_directory(&self, leaf: &str) -> Result<Self> {
        Ok(Self(self.0.fresh_maintenance_directory(leaf)?))
    }
    /// Atomic no-replace publication, including the initial transaction receipt.
    pub fn publish_maintenance(&self, leaf: &str, bytes: &[u8]) -> Result<()> {
        self.0.publish_maintenance(leaf, bytes)
    }
    /// User-private catalog publication; no administrator requirement or ACL relaxation.
    pub fn write_private_bytes(&self, leaf: &str, bytes: &[u8]) -> Result<()> {
        self.0.write_private_bytes(leaf, bytes)
    }
    pub fn publish_recorded_receipt(
        &self,
        staged: &str,
        destination: &str,
        volume: u64,
        id: [u8; 16],
        expected: &athernex_endpoint_protocol::windows_filter_package::Member,
    ) -> Result<()> {
        self.0
            .publish_recorded_receipt(staged, destination, volume, id, expected)
    }
    pub fn read_json<T: DeserializeOwned>(&self, leaf: &str) -> Result<T> {
        self.0.snapshot_json(leaf)
    }
    pub fn write_json(&self, leaf: &str, value: &impl Serialize) -> Result<()> {
        self.0.write_json(leaf, value)
    }
    pub fn write_maintenance_json(&self, leaf: &str, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > 65536 {
            return Err("Maintenance journal exceeds its byte budget".into());
        }
        self.0.write_maintenance(leaf, &bytes)
    }
    /// Atomic replacement with explicit administrator/SYSTEM permissions.
    /// The caller must retain exclusive ownership of the target namespace.
    pub fn write_maintenance(&self, leaf: &str, bytes: &[u8]) -> Result<()> {
        self.0.write_maintenance(leaf, bytes)
    }
    pub fn read(&self, leaf: &str) -> Result<File> {
        self.0.read_private(leaf)
    }
    pub fn create(&self, leaf: &str) -> Result<File> {
        self.0.create(leaf)
    }
    pub fn create_maintenance(&self, leaf: &str) -> Result<File> {
        self.0.create_maintenance(leaf)
    }
    pub fn remove(&self, leaf: &str) -> Result<()> {
        self.0.unlink(leaf)
    }
    pub fn sync(&self) -> Result<()> {
        self.0.sync()
    }
    pub fn database_path(&self, leaf: &str) -> Result<PathBuf> {
        let file = self.0.state_file(leaf)?;
        if file.metadata()?.len() > 32 * 1024 * 1024 {
            return Err("Windows state database exceeds its byte budget".into());
        }
        drop(file);
        self.0.sync()?;
        Ok(self.path().join(leaf))
    }
    pub fn lock(&self, leaf: &str) -> Result<File> {
        let file = self.0.state_file(leaf)?;
        Self::lock_file(file)
    }
    pub fn maintenance_lock(&self, leaf: &str) -> Result<File> {
        Self::lock_file(self.0.maintenance_file(leaf)?)
    }
    /// Retained shared admission for ordinary privileged operations. Native
    /// deployment takes the same empty protected file exclusively.
    pub fn maintenance_shared_lock(&self, leaf: &str) -> Result<File> {
        let file = self.0.maintenance_file(leaf)?;
        if file.metadata()?.len() != 0 {
            return Err("Windows admission lock is not empty".into());
        }
        file.try_lock_shared()
            .map_err(|_| "A native deployment owns machine admission")?;
        Ok(file)
    }
    fn lock_file(file: File) -> Result<File> {
        if file.metadata()?.len() != 0 {
            return Err("Windows service lock is not empty".into());
        }
        file.try_lock()
            .map_err(|_| "Windows service is already running")?;
        Ok(file)
    }
}
