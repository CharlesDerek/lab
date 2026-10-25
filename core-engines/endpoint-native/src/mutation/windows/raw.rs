//! Documented NT handle-relative opens plus Win32 handle-based metadata changes.
//! No mutation resolves a multi-component name after its parent has been opened.
use crate::Result;
use std::{
    fs::File,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr::{null, null_mut},
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileLinkInformation, NtCreateFile, NtFlushBuffersFileEx, NtSetInformationFile,
            FILE_LINK_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
            FILE_SYNCHRONOUS_IO_NONALERT,
        },
    },
    Win32::{
        Foundation::{
            RtlNtStatusToDosError, HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING,
        },
        Storage::FileSystem::{
            FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

pub(super) fn status(code: i32) -> Result<()> {
    if code < 0 {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(code) } as i32
        )
        .into());
    }
    Ok(())
}
pub(super) fn open(
    parent: Option<&File>,
    name: &str,
    access: u32,
    disposition: u32,
    options: u32,
    descriptor: *mut std::ffi::c_void,
) -> Result<File> {
    open_mode(
        parent,
        name,
        access,
        descriptor,
        OpenMode {
            disposition,
            options,
            sharing: FILE_SHARE_READ | FILE_SHARE_WRITE,
        },
    )
}
struct OpenMode {
    disposition: u32,
    options: u32,
    sharing: u32,
}
pub(super) fn snapshot(parent: &File, name: &str, access: u32) -> Result<File> {
    open_mode(
        Some(parent),
        name,
        access,
        null_mut(),
        OpenMode {
            disposition: FILE_OPEN,
            options: FILE_NON_DIRECTORY_FILE,
            sharing: FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        },
    )
}
fn open_mode(
    parent: Option<&File>,
    name: &str,
    access: u32,
    descriptor: *mut std::ffi::c_void,
    mode: OpenMode,
) -> Result<File> {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    if wide.contains(&0) || wide.len() > 16382 {
        return Err("Invalid Windows mutation name".into());
    }
    let length = (wide.len() * 2) as u16;
    wide.push(0);
    let mut name = UNICODE_STRING {
        Length: length,
        MaximumLength: length + 2,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.map_or(null_mut(), |f| f.as_raw_handle()),
        ObjectName: &mut name,
        // The absolute drive root necessarily resolves the DOS device mapping.
        // Every filesystem component below it is a single, no-reparse open.
        Attributes: OBJ_CASE_INSENSITIVE
            | if parent.is_some() {
                OBJ_DONT_REPARSE
            } else {
                0
            },
        SecurityDescriptor: descriptor.cast(),
        SecurityQualityOfService: null_mut(),
    };
    let mut io: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut handle: HANDLE = null_mut();
    status(unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut io,
            null(),
            0,
            mode.sharing,
            mode.disposition,
            mode.options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    })?;
    // Mutation opens omit FILE_SHARE_DELETE to pin their names. Private status
    // snapshots permit atomic replacement while retaining the opened old file.
    Ok(unsafe { File::from_raw_handle(handle) })
}
pub(super) fn flush(file: &File) -> Result<()> {
    let mut io: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // Flags=0 includes metadata and the storage cache; never DATA_ONLY/NO_SYNC.
    status(unsafe { NtFlushBuffersFileEx(file.as_raw_handle(), 0, null(), 0, &mut io) })
}
pub(super) fn rename(file: &File, directory: &File, leaf: &str, replace: bool) -> Result<()> {
    let wide: Vec<u16> = leaf.encode_utf16().collect();
    let bytes = offset_of!(FILE_RENAME_INFO, FileName) + (wide.len() + 1) * 2;
    let mut buffer = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = directory.as_raw_handle();
        (*info).FileNameLength = (wide.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast(),
            wide.len(),
        );
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            bytes as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}
pub(super) fn link(file: &File, directory: &File, leaf: &str) -> Result<()> {
    let wide: Vec<u16> = leaf.encode_utf16().collect();
    let bytes = offset_of!(FILE_LINK_INFORMATION, FileName) + (wide.len() + 1) * 2;
    let mut buffer = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_LINK_INFORMATION>();
    let mut io: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = directory.as_raw_handle();
        (*info).FileNameLength = (wide.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast(),
            wide.len(),
        );
        status(NtSetInformationFile(
            file.as_raw_handle(),
            &mut io,
            info.cast(),
            bytes as u32,
            FileLinkInformation,
        ))
    }
}
