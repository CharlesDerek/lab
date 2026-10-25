//! All partition mutations use the physical handle obtained from the newly
//! created VHDX. Read-only partition queries establish MSR arrival before adding
//! a data partition; they never confer authority to mutate another device.
use super::*;
use crate::windows_scratch_spec::Ranges;
use std::{
    mem::offset_of,
    os::windows::fs::FileExt,
    time::{Duration, Instant},
};

const PARTITIONS: usize = 128;
#[repr(C)]
struct Layout {
    style: u32,
    count: u32,
    header: DRIVE_LAYOUT_INFORMATION_EX_0,
    entries: [PARTITION_INFORMATION_EX; PARTITIONS],
}
const _: () =
    assert!(offset_of!(Layout, entries) == offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry));
impl Layout {
    fn empty() -> Self {
        Self {
            style: 0,
            count: 0,
            header: Default::default(),
            entries: [Default::default(); PARTITIONS],
        }
    }
    fn get(file: &File) -> Result<Self> {
        let mut value = Self::empty();
        let mut bytes = 0;
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                null(),
                0,
                (&mut value as *mut Self).cast(),
                size_of::<Self>() as u32,
                &mut bytes,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if value.count as usize > PARTITIONS {
            return Err("Scratch drive layout exceeds its partition budget".into());
        }
        let needed = offset_of!(Self, entries)
            + value.count as usize * size_of::<PARTITION_INFORMATION_EX>();
        if (bytes as usize) < needed || bytes as usize > size_of::<Self>() {
            return Err("Scratch drive layout exceeds its response budget".into());
        }
        Ok(value)
    }
    fn gpt(&self, spec: &Spec) -> Result<DRIVE_LAYOUT_INFORMATION_GPT> {
        if self.style != PARTITION_STYLE_GPT as u32 {
            return Err("Scratch disk is not GPT".into());
        }
        let gpt = unsafe { self.header.Gpt };
        if !same_guid(&gpt.DiskId, &guid(spec, Identifier::Disk))
            || gpt.MaxPartitionCount != PARTITIONS as u32
            || gpt.StartingUsableOffset <= 0
            || gpt.UsableLength <= 0
        {
            return Err("Scratch GPT identity or usable geometry changed".into());
        }
        spec.ranges(gpt.StartingUsableOffset as u64, gpt.UsableLength as u64)?;
        Ok(gpt)
    }
}
fn input<T>(file: &File, control: u32, value: &T, bytes: usize) -> Result<()> {
    if bytes > size_of::<T>() {
        return Err("Scratch IOCTL input exceeds its allocation".into());
    }
    let mut returned = 0;
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            control,
            (value as *const T).cast(),
            bytes as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if returned != 0 {
        return Err("Unexpected scratch mutation response".into());
    }
    Ok(())
}
fn update(file: &File) -> Result<()> {
    input(file, IOCTL_DISK_UPDATE_PROPERTIES, &(), 0)
}

fn entry(
    spec: &Spec,
    kind: Identifier,
    start: u64,
    length: u64,
    number: u32,
) -> PARTITION_INFORMATION_EX {
    let data = matches!(kind, Identifier::Data);
    PARTITION_INFORMATION_EX {
        PartitionStyle: PARTITION_STYLE_GPT,
        StartingOffset: start as i64,
        PartitionLength: length as i64,
        PartitionNumber: number,
        RewritePartition: true,
        Anonymous: PARTITION_INFORMATION_EX_0 {
            Gpt: PARTITION_INFORMATION_GPT {
                PartitionType: if data {
                    PARTITION_BASIC_DATA_GUID
                } else {
                    PARTITION_MSFT_RESERVED_GUID
                },
                PartitionId: guid(spec, kind),
                Attributes: if data {
                    GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER
                } else {
                    0
                },
                ..Default::default()
            },
        },
        ..Default::default()
    }
}
pub(super) fn same_partition(a: &PARTITION_INFORMATION_EX, b: &PARTITION_INFORMATION_EX) -> bool {
    if a.PartitionStyle != PARTITION_STYLE_GPT || b.PartitionStyle != PARTITION_STYLE_GPT {
        return false;
    }
    let (a_gpt, b_gpt) = unsafe { (a.Anonymous.Gpt, b.Anonymous.Gpt) };
    a.StartingOffset == b.StartingOffset
        && a.PartitionLength == b.PartitionLength
        && a.PartitionNumber == b.PartitionNumber
        && a.PartitionNumber != 0
        && same_guid(&a_gpt.PartitionType, &b_gpt.PartitionType)
        && same_guid(&a_gpt.PartitionId, &b_gpt.PartitionId)
        && a_gpt.Attributes == b_gpt.Attributes
}

/// Query only the partition number from our held disk's checked layout. The
/// resulting device handle is read-only and must independently match both disk
/// number and complete GPT identity/extent. It never grants mutation authority.
fn msr_arrived(
    disk: &AttachedDisk,
    expected: &PARTITION_INFORMATION_EX,
) -> Result<(bool, Option<i32>)> {
    disk.verify()?;
    if expected.PartitionNumber == 0 || expected.PartitionNumber > PARTITIONS as u32 {
        return Err("Scratch MSR partition number exceeds its bounds".into());
    }
    // Windows need not expose an MSR through partition-interface enumeration.
    // This is the partition-device form used by Microsoft's WSL disk helper.
    let path = format!(
        r"\\?\Harddisk{}Partition{}",
        disk.number, expected.PartitionNumber
    );
    let wide: Vec<_> = path.encode_utf16().chain([0]).collect();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Ok((false, io::Error::last_os_error().raw_os_error()));
    }
    let file = unsafe { File::from_raw_handle(raw) };
    let device = output::<STORAGE_DEVICE_NUMBER>(&file, IOCTL_STORAGE_GET_DEVICE_NUMBER)?;
    let partition = output::<PARTITION_INFORMATION_EX>(&file, IOCTL_DISK_GET_PARTITION_INFO_EX)?;
    if device.DeviceType != FILE_DEVICE_DISK
        || device.DeviceNumber != disk.number
        || device.PartitionNumber != expected.PartitionNumber
        || !same_partition(&partition, expected)
    {
        return Err("Scratch MSR device does not match its owned disk layout".into());
    }
    disk.verify()?;
    Ok((true, None))
}

/// Initialization is a consuming transition. An existing image has no route
/// to this capability, and a successfully initialized disk cannot be reset.
pub struct PartitionedDisk {
    pub(super) disk: AttachedDisk,
    header: DRIVE_LAYOUT_INFORMATION_GPT,
    ranges: Ranges,
}
impl AttachedDisk {
    pub fn initialize(self) -> Result<PartitionedDisk> {
        let _privilege = privilege::ManageVolume::acquire()?;
        self.verify()?;
        let before = Layout::get(&self.physical)?;
        // A newly created, uninitialized VHDX can be reported as MBR with no
        // entries. Accept no partitions in either empty representation, then
        // independently inspect the disk headers before granting mutation.
        if ![PARTITION_STYLE_RAW as u32, PARTITION_STYLE_MBR as u32].contains(&before.style)
            || before.count != 0
        {
            // Report only shape/range metadata, never disk/partition IDs or
            // device paths. Preserve refusal until the exact layout is known.
            let first = before.entries[0];
            let first_type = if first.PartitionStyle == PARTITION_STYLE_MBR {
                u32::from(unsafe { first.Anonymous.Mbr }.PartitionType)
            } else {
                0
            };
            return Err(format!(
                "New scratch disk already contains a partition layout: style={}, count={}, first_style={}, first_start={}, first_length={}, first_number={}, first_mbr_type={first_type}",
                before.style, before.count, first.PartitionStyle, first.StartingOffset,
                first.PartitionLength, first.PartitionNumber
            ).into());
        }
        // Cover the MBR and both GPT header/table regions on this owned disk.
        // No existing image can obtain AttachedDisk; nonzero headers still
        // refuse initialization instead of erasing even an empty old layout.
        let mut header = [0u8; 64 * 1024];
        for offset in [0, self.spec().bytes - header.len() as u64] {
            let read = self
                .physical
                .seek_read(&mut header, offset)
                .map_err(|error| {
                    format!("Scratch partition header read at byte {offset}: {error}")
                })?;
            if read != header.len() || header.iter().any(|&byte| byte != 0) {
                return Err("Scratch partition headers are not empty".into());
            }
        }
        let create = CREATE_DISK {
            PartitionStyle: PARTITION_STYLE_GPT,
            Anonymous: CREATE_DISK_0 {
                Gpt: CREATE_DISK_GPT {
                    DiskId: guid(self.spec(), Identifier::Disk),
                    MaxPartitionCount: PARTITIONS as u32,
                },
            },
        };
        input(
            &self.physical,
            IOCTL_DISK_CREATE_DISK,
            &create,
            size_of::<CREATE_DISK>(),
        )?;
        update(&self.physical)?;
        let initial = Layout::get(&self.physical)?;
        let initial_header = initial.gpt(self.spec())?;
        let ranges = self.spec().ranges(
            initial_header.StartingUsableOffset as u64,
            initial_header.UsableLength as u64,
        )?;
        let mut desired = Layout::empty();
        desired.style = PARTITION_STYLE_GPT as u32;
        desired.count = 1;
        desired.header.Gpt = initial_header;
        desired.entries[0] = entry(
            self.spec(),
            Identifier::Reserved,
            ranges.reserved_start,
            ranges.reserved_length,
            1,
        );
        // CREATE_DISK can leave an empty GPT. Create only our MSR first and
        // establish its arrival before adding any data partition. An existing
        // initial MSR follows the same arrival checks without this mutation.
        let created_reserved = initial.count == 0;
        if created_reserved {
            self.verify()?;
            input(
                &self.physical,
                IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
                &desired,
                offset_of!(Layout, entries) + size_of::<PARTITION_INFORMATION_EX>(),
            )?;
            update(&self.physical)?;
            self.physical.sync_all()?;
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        let header = loop {
            self.verify()?;
            let layout = Layout::get(&self.physical)?;
            let header = layout.gpt(self.spec())?;
            if header.StartingUsableOffset != initial_header.StartingUsableOffset
                || header.UsableLength != initial_header.UsableLength
            {
                return Err("Scratch GPT usable geometry changed during MSR arrival".into());
            }
            if layout.count > 1 {
                return Err("Unexpected partitions on new scratch GPT disk".into());
            }
            let mut arrival = None;
            if layout.count == 1 {
                let msr = &layout.entries[0];
                if created_reserved && !same_partition(msr, &desired.entries[0]) {
                    return Err("Created scratch MSR differs from its owned specification".into());
                }
                if msr.PartitionStyle != PARTITION_STYLE_GPT
                    || !same_guid(
                        &unsafe { msr.Anonymous.Gpt }.PartitionType,
                        &PARTITION_MSFT_RESERVED_GUID,
                    )
                    || msr.StartingOffset < header.StartingUsableOffset
                    || msr.PartitionLength <= 0
                    || msr
                        .StartingOffset
                        .checked_add(msr.PartitionLength)
                        .is_none_or(|end| end > header.StartingUsableOffset + header.UsableLength)
                {
                    return Err("Unexpected initial scratch MSR geometry".into());
                }
                let (arrived, error) = msr_arrived(&self, msr)?;
                if arrived {
                    break header;
                }
                arrival = error;
            }
            if Instant::now() >= deadline {
                // Bounded shape/error metadata distinguishes absent layouts
                // from inaccessible partition devices, without paths or IDs.
                let first = layout.entries[0];
                return Err(format!(
                    "Scratch MSR did not arrive before its deadline: count={}, first_number={}, first_start={}, first_length={}, usable_start={}, usable_length={}, partition_open_error={arrival:?}",
                    layout.count, first.PartitionNumber, first.StartingOffset,
                    first.PartitionLength, header.StartingUsableOffset, header.UsableLength
                ).into());
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        desired.count = 2;
        desired.entries[1] = entry(
            self.spec(),
            Identifier::Data,
            ranges.data_start,
            ranges.data_length,
            2,
        );
        self.verify()?;
        input(
            &self.physical,
            IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
            &desired,
            offset_of!(Layout, entries) + 2 * size_of::<PARTITION_INFORMATION_EX>(),
        )?;
        update(&self.physical)?;
        self.physical.sync_all()?;
        let disk = PartitionedDisk {
            disk: self,
            header,
            ranges,
        };
        disk.verify()?;
        Ok(disk)
    }
}
impl PartitionedDisk {
    pub fn spec(&self) -> &Spec {
        self.disk.spec()
    }
    pub(super) fn data(&self) -> PARTITION_INFORMATION_EX {
        entry(
            self.spec(),
            Identifier::Data,
            self.ranges.data_start,
            self.ranges.data_length,
            2,
        )
    }
    pub fn verify(&self) -> Result<()> {
        self.disk.verify()?;
        let layout = Layout::get(&self.disk.physical)?;
        let header = layout.gpt(self.spec())?;
        if header.StartingUsableOffset != self.header.StartingUsableOffset
            || header.UsableLength != self.header.UsableLength
            || layout.count != 2
            || !same_partition(
                &layout.entries[0],
                &entry(
                    self.spec(),
                    Identifier::Reserved,
                    self.ranges.reserved_start,
                    self.ranges.reserved_length,
                    1,
                ),
            )
            || !same_partition(&layout.entries[1], &self.data())
        {
            return Err("Scratch disk partition layout changed".into());
        }
        Ok(())
    }
    pub fn detach(self) -> Result<()> {
        self.disk.detach()
    }
}
