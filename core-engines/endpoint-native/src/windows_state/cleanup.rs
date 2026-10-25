//! Retired scanner workspace deletion. Every lookup is one UTF-16 leaf relative
//! to a pinned handle, and deletion operates on that same opened object. Reparse
//! leaves are unlinked without traversal; hard links never cause data writes.
use super::*;
use crate::windows_directory::{self as wire, Entry};
use serde::Deserialize;
use std::{
    io,
    mem::{offset_of, size_of},
    os::windows::io::FromRawHandle,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            NtCreateFile, NtFlushBuffersFileEx, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
            FILE_OPEN, FILE_OPEN_NO_RECALL, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        },
    },
    Win32::{
        Foundation::{
            RtlNtStatusToDosError, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, UNICODE_STRING,
        },
        Storage::FileSystem::*,
        System::IO::IO_STATUS_BLOCK,
    },
};
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceIdentity {
    pub volume: u64,
    pub file_id: [u8; 16],
}
fn information<T: Default>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T> {
    let mut info = T::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&mut info as *mut T).cast(),
            size_of::<T>() as u32,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        #[cfg(test)]
        eprintln!("Cleanup GetFileInformationByHandleEx class {class}: {error}");
        return Err(error.into());
    }
    Ok(info)
}
pub(super) fn identity(file: &File) -> Result<WorkspaceIdentity> {
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err("Scanner workspace must be a disk object".into());
    }
    let info: FILE_ID_INFO = information(file, FileIdInfo)?;
    Ok(WorkspaceIdentity {
        volume: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}
fn status(code: i32, _operation: &str) -> Result<()> {
    if code != 0 {
        #[cfg(test)]
        eprintln!("Cleanup {_operation}: NTSTATUS 0x{:08x}", code as u32);
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(code) } as i32).into(),
        );
    }
    Ok(())
}
fn open(parent: &File, leaf: &[u16], directory: bool) -> Result<File> {
    wire::leaf(leaf)?;
    let mut name = leaf.to_vec();
    let mut unicode = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut unicode,
        // Exact enumerated case, no Win32 device/stream/path normalization.
        // OPEN_REPARSE_POINT opens the leaf itself. There is no intermediate
        // component to resolve, and no OBJ_DONT_REPARSE rejection of the leaf.
        ..Default::default()
    };
    let mut io = IO_STATUS_BLOCK::default();
    let mut raw = null_mut();
    let access = DELETE
        | FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if directory {
            FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_WRITE_ATTRIBUTES
                | FILE_WRITE_EA
        } else {
            0
        };
    status(
        unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut io,
                null(),
                0,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT
                    | FILE_OPEN_REPARSE_POINT
                    | FILE_OPEN_NO_RECALL
                    | if directory {
                        FILE_DIRECTORY_FILE
                    } else {
                        FILE_NON_DIRECTORY_FILE
                    },
                null(),
                0,
            )
        },
        "NtCreateFile",
    )?;
    if raw.is_null() {
        return Err("Windows cleanup returned no file handle".into());
    }
    Ok(unsafe { File::from_raw_handle(raw) })
}
struct Budget {
    operations: usize,
    deadline: Instant,
}
impl Budget {
    fn step(&mut self, depth: usize) -> Result<()> {
        if depth > 32 || self.operations >= 16384 || Instant::now() >= self.deadline {
            return Err(
                "Scanner workspace cleanup reached its budget; journal retained for retry".into(),
            );
        }
        self.operations += 1;
        Ok(())
    }
}
fn batch(directory: &File, restart: bool) -> Result<Option<Vec<Entry>>> {
    // Compile-time ABI checks back the decoder that is tested on every host.
    const {
        assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, FileName) == wire::HEADER);
    }
    const {
        assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, FileId) == 72);
    }
    const {
        assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, FileNameLength) == 60);
    }
    const {
        assert!(offset_of!(FILE_ID_EXTD_DIR_INFO, FileAttributes) == 56);
    }
    let mut buffer = vec![0u64; wire::BUFFER / 8];
    if unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle(),
            if restart {
                FileIdExtdDirectoryRestartInfo
            } else {
                FileIdExtdDirectoryInfo
            },
            buffer.as_mut_ptr().cast(),
            wire::BUFFER as u32,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(code) if code == ERROR_NO_MORE_FILES as i32 || code == ERROR_FILE_NOT_FOUND as i32)
        {
            return Ok(None);
        }
        #[cfg(test)]
        eprintln!("Cleanup directory enumeration: {error}");
        return Err(error.into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), wire::BUFFER) };
    Ok(Some(wire::decode(bytes)?))
}
fn unlink(file: File, parent: &File) -> Result<()> {
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
        let error = io::Error::last_os_error();
        #[cfg(test)]
        eprintln!("Cleanup SetFileInformationByHandle FileDispositionInfoEx: {error}");
        return Err(error.into());
    }
    drop(file);
    let mut io = IO_STATUS_BLOCK::default();
    status(
        unsafe { NtFlushBuffersFileEx(parent.as_raw_handle(), 0, null(), 0, &mut io) },
        "NtFlushBuffersFileEx",
    )
}
fn clear(directory: &File, volume: u64, depth: usize, budget: &mut Budget) -> Result<()> {
    let mut restart = true;
    loop {
        budget.step(depth)?;
        let Some(entries) = batch(directory, restart)? else {
            return Ok(());
        };
        restart = !entries.is_empty();
        for entry in entries {
            budget.step(depth)?;
            let is_dir = entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let child = open(directory, &entry.name, is_dir)?;
            if identity(&child)?
                != (WorkspaceIdentity {
                    volume,
                    file_id: entry.id,
                })
            {
                return Err("Scanner cleanup entry identity changed".into());
            }
            let basic: FILE_BASIC_INFO = information(&child, FileBasicInfo)?;
            let standard: FILE_STANDARD_INFO = information(&child, FileStandardInfo)?;
            if standard.DeletePending || standard.Directory != is_dir {
                return Err("Scanner cleanup entry type changed".into());
            }
            if is_dir && basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                clear(&child, volume, depth + 1, budget)?;
            }
            unlink(child, directory)?;
        }
    }
}
impl ScannerDirectory {
    pub fn identity(&self) -> Result<WorkspaceIdentity> {
        identity(&self.directory.file)
    }
}
impl Directory {
    pub fn identity(&self) -> Result<WorkspaceIdentity> {
        identity(&self.0.file)
    }
    /// Caller must first reconcile all scanner launch/network journals, hold
    /// both supervisor leases, and release workspace pins. Run in an owned
    /// worker: OS I/O can outlive the cooperative deadline. None permits only
    /// an empty orphan left before its first workspace journal was committed.
    pub fn remove_scanner_workspace(
        &self,
        leaf: &str,
        expected: Option<&WorkspaceIdentity>,
    ) -> Result<()> {
        let id = leaf
            .strip_prefix("scanner-")
            .ok_or("Invalid scanner workspace name")?;
        if id.len() != 64
            || !id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("Invalid scanner workspace identity".into());
        }
        let directory = match open(&self.0.file, &leaf.encode_utf16().collect::<Vec<_>>(), true) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32)) =>
            {
                return self.sync()
            }
            Err(error) => return Err(error),
        };
        let actual = identity(&directory)?;
        let basic: FILE_BASIC_INFO = information(&directory, FileBasicInfo)?;
        let standard: FILE_STANDARD_INFO = information(&directory, FileStandardInfo)?;
        if basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !standard.Directory
            || standard.DeletePending
        {
            return Err("Scanner workspace root is not an ordinary directory".into());
        }
        if let Some(expected) = expected {
            if &actual != expected {
                return Err("Scanner workspace root identity changed".into());
            }
            clear(
                &directory,
                actual.volume,
                0,
                &mut Budget {
                    operations: 0,
                    deadline: Instant::now() + Duration::from_secs(20),
                },
            )?;
        }
        // For an unrecorded orphan the filesystem itself enforces emptiness.
        // No child enumeration or deletion is authorized in that case.
        unlink(directory, &self.0.file)
    }
}
