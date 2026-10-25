//! A consuming fresh-volume transition validates the formatter's result, pins
//! its filesystem namespace, and creates a logon-scoped scratch child by handle.
use super::*;
use crate::windows_state::{name, WorkspaceIdentity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileFsSizeInformation, NtCreateFile, NtFlushBuffersFileEx,
            NtQueryVolumeInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        },
        System::SystemServices::FILE_FS_SIZE_INFORMATION,
    },
    Win32::{
        Foundation::{RtlNtStatusToDosError, OBJ_DONT_REPARSE, UNICODE_STRING},
        System::{SystemServices::FILE_PERSISTENT_ACLS, IO::IO_STATUS_BLOCK},
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Space {
    pub total_bytes: u64,
    pub free_bytes: u64,
}
pub struct ReadyVolume {
    // Drop filesystem pins before the underlying virtual-disk attachment.
    scratch: File,
    root: File,
    volume: UnformattedVolume,
    path: PathBuf,
    logon: String,
    root_id: WorkspaceIdentity,
    scratch_id: WorkspaceIdentity,
}
fn nt_status(value: i32) -> Result<()> {
    if value != 0 {
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(value) } as i32).into(),
        );
    }
    Ok(())
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
fn identity(file: &File, expected: &str) -> Result<WorkspaceIdentity> {
    let basic: FILE_BASIC_INFO = information(file, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = information(file, FileStandardInfo)?;
    if !standard.Directory
        || standard.DeletePending
        || basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !name(file, VOLUME_NAME_GUID)?.eq_ignore_ascii_case(expected)
    {
        return Err("Scratch filesystem namespace is redirected or changed".into());
    }
    let id: FILE_ID_INFO = information(file, FileIdInfo)?;
    Ok(WorkspaceIdentity {
        volume: id.VolumeSerialNumber,
        file_id: id.FileId.Identifier,
    })
}
fn space(file: &File, maximum: u64) -> Result<Space> {
    let mut fs_name = [0u16; 16];
    let mut flags = 0;
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let end = fs_name
        .iter()
        .position(|&c| c == 0)
        .ok_or("Unterminated scratch filesystem name")?;
    if String::from_utf16(&fs_name[..end])? != "NTFS" || flags & FILE_PERSISTENT_ACLS == 0 {
        return Err("Scratch volume must use NTFS with persistent permissions".into());
    }
    let mut size = FILE_FS_SIZE_INFORMATION::default();
    let mut status = IO_STATUS_BLOCK::default();
    nt_status(unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&mut size as *mut FILE_FS_SIZE_INFORMATION).cast(),
            size_of::<FILE_FS_SIZE_INFORMATION>() as u32,
            FileFsSizeInformation,
        )
    })?;
    if status.Information != size_of::<FILE_FS_SIZE_INFORMATION>() {
        return Err("Invalid scratch capacity response size".into());
    }
    let (total_bytes, free_bytes) = crate::windows_scratch_spec::capacity(
        size.TotalAllocationUnits,
        size.AvailableAllocationUnits,
        size.SectorsPerAllocationUnit,
        size.BytesPerSector,
        maximum,
    )?;
    Ok(Space {
        total_bytes,
        free_bytes,
    })
}
fn flush(file: &File) -> Result<()> {
    let mut status = IO_STATUS_BLOCK::default();
    nt_status(unsafe { NtFlushBuffersFileEx(file.as_raw_handle(), 0, null(), 0, &mut status) })
}
fn create_scratch(root: &File, logon: &str) -> Result<File> {
    let descriptor = security::scratch(logon)?;
    let mut leaf: Vec<_> = "scratch".encode_utf16().chain([0]).collect();
    let mut name = UNICODE_STRING {
        Length: 14,
        MaximumLength: 16,
        Buffer: leaf.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root.as_raw_handle(),
        ObjectName: &mut name,
        Attributes: OBJ_DONT_REPARSE,
        SecurityDescriptor: descriptor.0.cast(),
        SecurityQualityOfService: null_mut(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut raw = null_mut();
    nt_status(unsafe {
        NtCreateFile(
            &mut raw,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC | WRITE_OWNER,
            &attributes,
            &mut status,
            null(),
            0,
            // Keep the scratch root from being reopened for writes, including
            // FSCTL_SET_REPARSE_POINT. Child-file creation still uses its ACL.
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    })?;
    let file = unsafe { File::from_raw_handle(raw) };
    security::verify(&file, &descriptor)?;
    flush(&file)?;
    flush(root)?;
    Ok(file)
}
impl UnformattedVolume {
    /// Only call after the owned formatter succeeded. This type exists solely
    /// for a disk created and initialized in the current process; there is no
    /// existing-volume or recovery route that can change root permissions.
    pub fn prepare(self, logon: &str) -> Result<ReadyVolume> {
        crate::windows_state::require_local_system()?;
        validate_logon(logon)?;
        self.verify()?;
        let wide: Vec<_> = self.target.volume.encode_utf16().chain([0]).collect();
        // Exclusive root access rejects existing ordinary read/write handles.
        // The guard remains pinned; children are created relative to this handle.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC | WRITE_OWNER,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        let root = unsafe { File::from_raw_handle(raw) };
        let root_id = identity(&root, &self.target.volume)?;
        space(&root, self.target.bytes)?;
        self.verify()?;
        security::set_root(&root, logon)?;
        flush(&root)?;
        let scratch = create_scratch(&root, logon)?;
        let path = PathBuf::from(format!("{}scratch", self.target.volume));
        let scratch_id = identity(&scratch, path.to_str().ok_or("Non-Unicode scratch path")?)?;
        if scratch_id.volume != root_id.volume {
            return Err("Scratch child is on another volume".into());
        }
        let result = ReadyVolume {
            scratch,
            root,
            volume: self,
            path,
            logon: logon.into(),
            root_id,
            scratch_id,
        };
        result.verify()?;
        Ok(result)
    }
}
impl ReadyVolume {
    pub fn verify(&self) -> Result<Space> {
        self.volume.verify()?;
        if identity(&self.root, &self.volume.target.volume)? != self.root_id
            || identity(
                &self.scratch,
                self.path.to_str().ok_or("Non-Unicode scratch path")?,
            )? != self.scratch_id
        {
            return Err("Scratch root or directory identity changed".into());
        }
        security::verify(&self.root, &security::root(&self.logon)?)?;
        security::verify(&self.scratch, &security::scratch(&self.logon)?)?;
        space(&self.root, self.volume.target.bytes)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn spec(&self) -> &Spec {
        self.volume.spec()
    }
    pub fn target(&self) -> &FormatTarget {
        self.volume.target()
    }
    pub fn identity(&self) -> &WorkspaceIdentity {
        &self.scratch_id
    }
    pub fn detach(self) -> Result<()> {
        let Self {
            scratch,
            root,
            volume,
            ..
        } = self;
        drop(scratch);
        drop(root);
        volume.detach()
    }
}
