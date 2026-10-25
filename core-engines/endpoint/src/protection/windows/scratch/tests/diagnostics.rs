//! Bounded diagnostics on this fixture's checked objects. No raw data is read or
//! written, no permissions change, and reports contain no paths or identities.
use super::*;
use std::{
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr::{null, null_mut},
};
use windows_sys::{
    core::GUID,
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileFsDeviceInformation, NtCreateFile, NtQueryVolumeInformationFile,
            FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        },
        System::SystemServices::{FILE_DEVICE_SECURE_OPEN, FILE_FS_DEVICE_INFORMATION},
    },
    Win32::{
        Foundation::{LocalFree, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING},
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::{Ioctl::*, IO::*},
    },
};

fn metadata_handle(path: impl AsRef<Path>) -> File {
    std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap()
}

struct Descriptor(*mut std::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn descriptor(file: &File) -> Descriptor {
    let mut raw = null_mut();
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut raw,
            )
        },
        0
    );
    assert!(!raw.is_null());
    Descriptor(raw)
}
fn aces(descriptor: &Descriptor) -> Vec<Vec<u8>> {
    let (mut acl, mut present, mut defaulted) = (null_mut(), 0, 0);
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) },
        0
    );
    assert!(present != 0 && !acl.is_null());
    assert_ne!(unsafe { IsValidAcl(acl) }, 0);
    let count = unsafe { (*acl).AceCount };
    let bytes = unsafe { (*acl).AclSize } as usize;
    assert!(count <= 16 && bytes <= 4096);
    (0..count)
        .map(|index| {
            let mut raw = null_mut();
            assert_ne!(unsafe { GetAce(acl, index as u32, &mut raw) }, 0);
            let offset = (raw as usize).checked_sub(acl as usize).unwrap();
            assert!(offset + size_of::<ACE_HEADER>() <= bytes);
            let len = unsafe { (*raw.cast::<ACE_HEADER>()).AceSize } as usize;
            assert!(len >= size_of::<ACE_HEADER>() && offset + len <= bytes);
            let mut bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), len) }.to_vec();
            // Attachment input uses generic GA, whereas the installed file
            // security can contain its mapped rights. Compare equivalent masks.
            let offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, Mask);
            assert!(offset + 4 <= bytes.len());
            let mut mask = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            let mapping = GENERIC_MAPPING {
                GenericRead: FILE_GENERIC_READ,
                GenericWrite: FILE_GENERIC_WRITE,
                GenericExecute: FILE_GENERIC_EXECUTE,
                GenericAll: FILE_ALL_ACCESS,
            };
            unsafe {
                MapGenericMask(&mut mask, &mapping);
            }
            bytes[offset..offset + 4].copy_from_slice(&mask.to_le_bytes());
            bytes
        })
        .collect()
}

pub(super) fn inspect(ready: &Health, token: &Token) {
    let scratch = metadata_handle(&ready.path);
    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtQueryVolumeInformationFile(
            scratch.as_raw_handle(),
            &mut iosb,
            (&mut device as *mut FILE_FS_DEVICE_INFORMATION).cast(),
            size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(iosb.Information, size_of::<FILE_FS_DEVICE_INFORMATION>());
    eprintln!(
        "scratch device type={:#x}, characteristics={:#x}, secure_open={}",
        device.DeviceType,
        device.Characteristics,
        device.Characteristics & FILE_DEVICE_SECURE_OPEN != 0
    );

    let root = descriptor(&metadata_handle(&ready.target.volume));
    let volume = descriptor(&metadata_handle(ready.target.volume.trim_end_matches('\\')));
    // This is an expected-descriptor comparison, not an authority for access:
    // the actual device behavior is checked independently by native open calls.
    let sddl = format!(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x1000a0;;;{})",
        token.logon_sid()
    );
    let wide: Vec<_> = sddl.encode_utf16().chain([0]).collect();
    let mut raw = null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut raw,
                null_mut(),
            )
        },
        0
    );
    let attach = Descriptor(raw);
    let actual = aces(&volume);
    eprintln!(
        "scratch volume DACL equals root={}, equals attach={}",
        actual == aces(&root),
        actual == aces(&attach)
    );
}

fn query<T: Default>(file: &File, control: u32) -> T {
    let mut value = T::default();
    let mut bytes = 0;
    assert_ne!(
        unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                control,
                null(),
                0,
                (&mut value as *mut T).cast(),
                size_of::<T>() as u32,
                &mut bytes,
                null_mut(),
            )
        },
        0
    );
    assert_eq!(bytes as usize, size_of::<T>());
    value
}
fn guid_text(id: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id.data1,
        id.data2,
        id.data3,
        id.data4[0],
        id.data4[1],
        id.data4[2],
        id.data4[3],
        id.data4[4],
        id.data4[5],
        id.data4[6],
        id.data4[7]
    )
}
fn partition(file: &File, ready: &Health) -> u32 {
    let device: STORAGE_DEVICE_NUMBER = query(file, IOCTL_STORAGE_GET_DEVICE_NUMBER);
    let part: PARTITION_INFORMATION_EX = query(file, IOCTL_DISK_GET_PARTITION_INFO_EX);
    assert_eq!(device.DeviceType, FILE_DEVICE_DISK);
    assert!(device.DeviceNumber == ready.target.disk_number);
    assert!((1..=128).contains(&device.PartitionNumber));
    assert!(part.PartitionNumber == device.PartitionNumber);
    assert_eq!(part.PartitionStyle, PARTITION_STYLE_GPT);
    assert!(part.StartingOffset == ready.target.offset as i64);
    assert!(part.PartitionLength == ready.target.bytes as i64);
    let gpt = unsafe { part.Anonymous.Gpt };
    assert!(guid_text(&gpt.PartitionId) == ready.target.partition_id);
    assert_eq!(
        guid_text(&gpt.PartitionType),
        guid_text(&PARTITION_BASIC_DATA_GUID)
    );
    assert_eq!(gpt.Attributes, GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER);
    part.PartitionNumber
}
pub(super) fn raw_devices(ready: &Health) -> [String; 3] {
    let volume = ready.target.volume.trim_end_matches('\\').to_owned();
    let checked = File::open(&volume).unwrap();
    let number = partition(&checked, ready);
    let alias = format!(
        r"\\?\Harddisk{}Partition{}",
        ready.target.disk_number, number
    );
    // Only read access is used while proving the alias reaches the same owned
    // data partition. Never derive a writable target from an unchecked number.
    assert!(partition(&File::open(&alias).unwrap(), ready) == number);
    [
        volume,
        format!(r"\\.\PhysicalDrive{}", ready.target.disk_number),
        alias,
    ]
}

fn native_open(path: &Path, access: u32, directory: bool) -> std::result::Result<File, i32> {
    let text = path.to_str().unwrap();
    let nt = if let Some(value) = text.strip_prefix(r"\\?\GLOBALROOT") {
        assert!(value.starts_with(r"\Device\HarddiskVolume"));
        value.to_owned()
    } else {
        let tail = text
            .strip_prefix(r"\\?\")
            .or_else(|| text.strip_prefix(r"\\.\"))
            .unwrap();
        format!(r"\??\{tail}")
    };
    let mut wide: Vec<_> = std::ffi::OsStr::new(&nt).encode_wide().chain([0]).collect();
    assert!(wide.len() > 1 && wide.len() <= 32767);
    let mut name = UNICODE_STRING {
        Length: ((wide.len() - 1) * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        ObjectName: &mut name,
        Attributes: OBJ_CASE_INSENSITIVE,
        ..Default::default()
    };
    let mut raw = null_mut();
    let mut iosb = IO_STATUS_BLOCK::default();
    // Deliberately omit both SYNCHRONIZE and synchronous create options. This
    // native call requests exactly `access`, unlike the Win32 CreateFile wrapper.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &attributes,
            &mut iosb,
            null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | if directory { FILE_DIRECTORY_FILE } else { 0 },
            null(),
            0,
        )
    };
    let file = if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        None
    } else {
        Some(unsafe { File::from_raw_handle(raw) })
    };
    if status == 0 {
        Ok(file.expect("Successful native open returned no handle"))
    } else {
        drop(file);
        Err(status)
    }
}
pub(super) fn native_raw_control(path: &str) {
    let status = native_open(Path::new(path), FILE_READ_DATA, false)
        .err()
        .unwrap_or(0);
    assert_eq!(
        status, 0,
        "SYSTEM native raw-read open control status={:#x}",
        status as u32
    );
}
pub(super) fn native_raw_denied(devices: &[String; 3]) {
    let mut cases = 0;
    for (index, path) in devices.iter().enumerate() {
        for access in [
            FILE_READ_DATA,
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_ATTRIBUTES,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            let status = native_open(Path::new(path), access, false)
                .err()
                .unwrap_or(0);
            assert_eq!(
                status as u32, 0xc0000022,
                "native raw access device={index}, mask={access:#x}, status={:#x}",
                status as u32
            );
            cases += 1;
        }
    }
    eprintln!("native raw data/mutation access refusals passed cases={cases}");
}
pub(super) fn native_file_access(path: &Path) {
    for access in [
        0,
        FILE_TRAVERSE,
        FILE_READ_ATTRIBUTES,
        READ_CONTROL,
        FILE_LIST_DIRECTORY,
        FILE_ADD_FILE,
    ] {
        let status = native_open(path, access, true).err().unwrap_or(0);
        eprintln!(
            "native scratch directory mask={access:#x}, status={:#x}",
            status as u32
        );
    }
    for access in [
        FILE_READ_ATTRIBUTES,
        READ_CONTROL,
        FILE_READ_DATA,
        FILE_WRITE_DATA,
    ] {
        let status = native_open(&path.join("existing-proof"), access, false)
            .err()
            .unwrap_or(0);
        eprintln!(
            "native existing scratch file mask={access:#x}, status={:#x}",
            status as u32
        );
    }
}
