//! Dedicated fixed VHDX storage for scanner scratch data. Only an image created
//! by this constructor can obtain the writable attachment/initialization type.
//! Recovery never initializes an existing image or an arbitrary disk number.
//! These native operations must run in an independently owned worker process.
mod filesystem;
mod layout;
mod privilege;
mod security;
#[cfg(test)]
mod tests;
mod volume;
pub use crate::windows_scratch_spec::{validate_logon, Spec};
use crate::windows_scratch_spec::{Identifier, MAX_OVERHEAD, MIB};
use crate::{windows_scanner, windows_state::Directory, Result};
pub use filesystem::{ReadyVolume, Space};
pub use layout::PartitionedDisk;
use std::{
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{null, null_mut},
};
pub use volume::{FormatTarget, UnformattedVolume};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Storage::{FileSystem::*, Vhd::*},
        System::{Ioctl::*, IO::DeviceIoControl},
    },
};

pub const IMAGE: &str = "scratch.vhdx";
fn guid(spec: &Spec, kind: Identifier) -> GUID {
    GUID::from_u128(u128::from_be_bytes(spec.identifier(kind)))
}
fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn check(code: u32) -> Result<()> {
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32).into());
    }
    Ok(())
}
fn storage() -> VIRTUAL_STORAGE_TYPE {
    VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    }
}
struct Image {
    // Closing the non-permanent attachment precedes releasing file/name pins.
    handle: OwnedHandle,
    file: File,
    directory: Directory,
    spec: Spec,
}
impl Image {
    fn inspect(directory: Directory, spec: Spec) -> Result<Self> {
        crate::windows_state::require_local_system()?;
        spec.validate()?;
        // Pin the private, non-reparse backing file and all directory ancestors
        // before passing its name to the virtual-disk provider. Inspection can
        // neither attach nor initialize this image and never follows parents.
        let file = directory.read(IMAGE)?;
        let path: Vec<_> = directory
            .path()
            .join(IMAGE)
            .as_os_str()
            .encode_wide()
            .chain([0])
            .collect();
        let parameters = OPEN_VIRTUAL_DISK_PARAMETERS {
            Version: OPEN_VIRTUAL_DISK_VERSION_2,
            Anonymous: OPEN_VIRTUAL_DISK_PARAMETERS_0 {
                Version2: OPEN_VIRTUAL_DISK_PARAMETERS_0_1 {
                    GetInfoOnly: 1,
                    ReadOnly: 1,
                    ..Default::default()
                },
            },
        };
        let mut raw = null_mut();
        check(unsafe {
            OpenVirtualDisk(
                &storage(),
                path.as_ptr(),
                VIRTUAL_DISK_ACCESS_NONE,
                OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS,
                &parameters,
                &mut raw,
            )
        })?;
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err("Windows returned no scratch inspection handle".into());
        }
        let result = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw) },
            file,
            directory,
            spec,
        };
        result.verify()?;
        Ok(result)
    }
    fn query(&self, version: GET_VIRTUAL_DISK_INFO_VERSION) -> Result<GET_VIRTUAL_DISK_INFO> {
        let mut value = GET_VIRTUAL_DISK_INFO {
            Version: version,
            ..Default::default()
        };
        let mut size = size_of::<GET_VIRTUAL_DISK_INFO>() as u32;
        let mut used = 0;
        check(unsafe {
            GetVirtualDiskInformation(
                self.handle.as_raw_handle(),
                &mut size,
                &mut value,
                &mut used,
            )
        })?;
        let payload = match version {
            GET_VIRTUAL_DISK_INFO_SIZE => size_of::<GET_VIRTUAL_DISK_INFO_0_0>(),
            GET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID => size_of::<GUID>(),
            GET_VIRTUAL_DISK_INFO_VIRTUAL_STORAGE_TYPE => size_of::<VIRTUAL_STORAGE_TYPE>(),
            GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE | GET_VIRTUAL_DISK_INFO_IS_LOADED => 4,
            _ => return Err("Unsupported scratch information query".into()),
        };
        if value.Version != version
            || used as usize > size_of::<GET_VIRTUAL_DISK_INFO>()
            || (used as usize) < offset_of!(GET_VIRTUAL_DISK_INFO, Anonymous) + payload
        {
            return Err("Invalid scratch virtual disk information".into());
        }
        Ok(value)
    }
    fn verify(&self) -> Result<()> {
        self.spec.validate()?;
        let identifier = unsafe {
            self.query(GET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID)?
                .Anonymous
                .VirtualDiskId
        };
        let kind = unsafe {
            self.query(GET_VIRTUAL_DISK_INFO_VIRTUAL_STORAGE_TYPE)?
                .Anonymous
                .VirtualStorageType
        };
        let subtype = unsafe {
            self.query(GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE)?
                .Anonymous
                .ProviderSubtype
        };
        let size = unsafe { self.query(GET_VIRTUAL_DISK_INFO_SIZE)?.Anonymous.Size };
        let identity_matches = same_guid(&identifier, &guid(&self.spec, Identifier::Image));
        let storage_matches = kind.DeviceId == VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
            && same_guid(&kind.VendorId, &VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT);
        let file_bytes = self.file.metadata()?.len();
        // Provider subtype 2 is fixed; dynamic/differencing images are refused.
        if !identity_matches
            || !storage_matches
            || subtype != 2
            || size.VirtualSize != self.spec.bytes
            // Fixed VHDX reports no dynamic allocation block size.
            || size.BlockSize != 0
            || size.SectorSize != 512
            || size.PhysicalSize < self.spec.bytes
            || size.PhysicalSize > self.spec.bytes + MAX_OVERHEAD
            || file_bytes > self.spec.bytes + MAX_OVERHEAD
        {
            // Numeric metadata and match results diagnose provider differences
            // without exposing the image path or its random identifiers.
            return Err(format!(
                "Scratch image identity, fixed allocation or capacity changed: identity={identity_matches}, storage={storage_matches}, subtype={subtype}, virtual={}/{}, block={}, sector={}, physical={}, file={file_bytes}",
                size.VirtualSize, self.spec.bytes, size.BlockSize, size.SectorSize, size.PhysicalSize
            ).into());
        }
        Ok(())
    }
    fn loaded(&self) -> Result<bool> {
        Ok(unsafe {
            self.query(GET_VIRTUAL_DISK_INFO_IS_LOADED)?
                .Anonymous
                .IsLoaded
        } != 0)
    }
    fn physical_path(&self) -> Result<String> {
        let mut path = [0u16; 128];
        let mut bytes = (path.len() * 2) as u32;
        check(unsafe {
            GetVirtualDiskPhysicalPath(self.handle.as_raw_handle(), &mut bytes, path.as_mut_ptr())
        })?;
        if bytes < 2 || bytes > (path.len() * 2) as u32 || !bytes.is_multiple_of(2) {
            return Err("Scratch physical path exceeds its bounds".into());
        }
        let end = path[..bytes as usize / 2]
            .iter()
            .position(|&c| c == 0)
            .ok_or("Unterminated scratch physical path")?;
        let path = String::from_utf16(&path[..end])?;
        physical_number(&path)?;
        Ok(path)
    }
}
fn physical_number(path: &str) -> Result<u32> {
    let number = path
        .strip_prefix(r"\\.\PhysicalDrive")
        .ok_or("Unexpected scratch physical device name")?;
    if number.is_empty() || number.len() > 10 || !number.bytes().all(|c| c.is_ascii_digit()) {
        return Err("Invalid scratch physical disk number".into());
    }
    Ok(number.parse()?)
}
/// Owns a newly created image. There is deliberately no public open/adopt method.
pub struct FreshDisk(Image);
/// The raw device is opened only from the owned virtual-disk handle's reported
/// physical path. No caller-supplied raw device name or disk number is accepted.
pub struct AttachedDisk {
    physical: File,
    image: Image,
    number: u32,
}
/// Read-only recovery evidence. This never detaches, adopts, initializes or
/// deletes an image. Callers must also establish worker/scanner termination and
/// use identity-bound, exclusive deletion; a successful query is not a lease.
pub fn require_detached(directory: Directory, spec: Spec) -> Result<()> {
    let image = Image::inspect(directory, spec)?;
    if image.loaded()? {
        return Err("Scratch image is still attached; retain its journal".into());
    }
    Ok(())
}
impl FreshDisk {
    /// The caller persists the container/spec journal before this call. A
    /// failed creation may leave a partial image, never an attachment to adopt.
    pub fn create(directory: Directory, spec: Spec) -> Result<Self> {
        crate::windows_state::require_local_system()?;
        spec.validate()?;
        if std::fs::read_dir(directory.path())?
            .next()
            .transpose()?
            .is_some()
        {
            return Err("Scratch creation requires an empty private container".into());
        }
        let parent: Vec<_> = directory
            .path()
            .as_os_str()
            .encode_wide()
            .chain([0])
            .collect();
        let mut available = 0;
        if unsafe { GetDiskFreeSpaceExW(parent.as_ptr(), &mut available, null_mut(), null_mut()) }
            == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if available < spec.bytes + MAX_OVERHEAD + 128 * MIB {
            return Err("Insufficient space to reserve bounded scanner scratch storage".into());
        }
        let path: Vec<_> = directory
            .path()
            .join(IMAGE)
            .as_os_str()
            .encode_wide()
            .chain([0])
            .collect();
        let security = windows_scanner::descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)")?;
        let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_2,
            Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
                    UniqueId: guid(&spec, Identifier::Image),
                    MaximumSize: spec.bytes,
                    BlockSizeInBytes: CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_BLOCK_SIZE,
                    SectorSizeInBytes: 512,
                    PhysicalSectorSizeInBytes: 4096,
                    ..Default::default()
                },
            },
        };
        let mut handle = null_mut();
        check(unsafe {
            CreateVirtualDisk(
                &storage(),
                path.as_ptr(),
                VIRTUAL_DISK_ACCESS_NONE,
                security.0,
                CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION,
                0,
                &parameters,
                null(),
                &mut handle,
            )
        })?;
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err("Windows returned no scratch virtual disk handle".into());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let file = directory.read(IMAGE)?;
        directory.sync()?;
        let image = Image {
            handle,
            file,
            directory,
            spec,
        };
        if image.loaded()? {
            return Err("New scratch image is unexpectedly attached".into());
        }
        // VHDX's generic Identifier changes with payload writes. Bind its
        // stable VirtualDiskId instead, only on this newly created, unattached
        // image. Inspection/recovery never sets or repairs an existing ID.
        let identity = SET_VIRTUAL_DISK_INFO {
            Version: SET_VIRTUAL_DISK_INFO_VIRTUAL_DISK_ID,
            Anonymous: SET_VIRTUAL_DISK_INFO_0 {
                VirtualDiskId: guid(&image.spec, Identifier::Image),
            },
        };
        check(unsafe { SetVirtualDiskInformation(image.handle.as_raw_handle(), &identity) })?;
        image.verify()?;
        Ok(Self(image))
    }
    pub fn attach(self) -> Result<AttachedDisk> {
        self.attach_with_security(windows_scanner::descriptor(
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",
        )?)
    }
    /// Permit this logon to traverse the attached device's namespace. Raw
    /// device data, attributes and security remain restricted to SYSTEM/admins;
    /// the freshly formatted filesystem grants its own separate scratch rights.
    pub fn attach_for_scanner(self, logon: &str) -> Result<AttachedDisk> {
        validate_logon(logon)?;
        self.attach_with_security(windows_scanner::descriptor(&format!(
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x20;;;{logon})"
        ))?)
    }
    fn attach_with_security(self, security: windows_scanner::Allocation) -> Result<AttachedDisk> {
        let _privilege = privilege::ManageVolume::acquire()?;
        self.0.verify()?;
        if self.0.loaded()? {
            return Err("Scratch image was already attached".into());
        }
        let parameters = ATTACH_VIRTUAL_DISK_PARAMETERS {
            Version: ATTACH_VIRTUAL_DISK_VERSION_1,
            ..Default::default()
        };
        // Lifetime remains bound to this handle; there are no drive letters,
        // permanent attachments, global quota edits, or boot configuration edits.
        check(unsafe {
            AttachVirtualDisk(
                self.0.handle.as_raw_handle(),
                security.0,
                ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
                0,
                &parameters,
                null(),
            )
        })?;
        let path = self.0.physical_path()?;
        let number = physical_number(&path)?;
        let wide: Vec<_> = path.encode_utf16().chain([0]).collect();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        let physical = unsafe { File::from_raw_handle(raw) };
        let disk = AttachedDisk {
            physical,
            image: self.0,
            number,
        };
        disk.verify()?;
        Ok(disk)
    }
}
fn output<T: Default>(file: &File, control: u32) -> Result<T> {
    let mut result = T::default();
    let mut bytes = 0;
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            control,
            null(),
            0,
            (&mut result as *mut T).cast(),
            size_of::<T>() as u32,
            &mut bytes,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if bytes as usize != size_of::<T>() {
        return Err("Unexpected scratch device response size".into());
    }
    Ok(result)
}
impl AttachedDisk {
    pub fn verify(&self) -> Result<()> {
        self.image.verify()?;
        if !self.image.loaded()? || physical_number(&self.image.physical_path()?)? != self.number {
            return Err("Scratch virtual disk attachment changed".into());
        }
        let device: STORAGE_DEVICE_NUMBER =
            output(&self.physical, IOCTL_STORAGE_GET_DEVICE_NUMBER)?;
        let length: GET_LENGTH_INFORMATION = output(&self.physical, IOCTL_DISK_GET_LENGTH_INFO)?;
        if device.DeviceType != FILE_DEVICE_DISK
            || device.DeviceNumber != self.number
            || length.Length < 0
            || length.Length as u64 != self.image.spec.bytes
        {
            return Err("Scratch device does not match its owned image".into());
        }
        Ok(())
    }
    pub fn spec(&self) -> &Spec {
        &self.image.spec
    }
    pub fn container(&self) -> &Directory {
        &self.image.directory
    }
    /// Explicit shutdown is fallible; callers retain the journal on errors.
    /// Drop still closes the non-permanent attachment handle on process death.
    pub fn detach(self) -> Result<()> {
        let _privilege = privilege::ManageVolume::acquire()?;
        self.verify()?;
        let AttachedDisk {
            physical, image, ..
        } = self;
        drop(physical);
        check(unsafe {
            DetachVirtualDisk(
                image.handle.as_raw_handle(),
                DETACH_VIRTUAL_DISK_FLAG_NONE,
                0,
            )
        })?;
        if image.loaded()? {
            return Err("Scratch image remains attached after detach".into());
        }
        image.directory.sync()
    }
}
