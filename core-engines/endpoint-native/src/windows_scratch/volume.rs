//! A formatter receives only a fresh volume GUID whose extent and GPT identity
//! have been checked against our still-held image and physical-disk handles.
use super::*;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_FILES};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatTarget {
    pub schema: u32,
    pub volume: String,
    pub partition_id: String,
    pub disk_number: u32,
    pub offset: u64,
    pub bytes: u64,
}
impl FormatTarget {
    pub fn validate_for(&self, spec: &Spec) -> Result<()> {
        spec.validate()?;
        crate::windows_scratch_spec::volume_name(&self.volume)?;
        if self.schema != 1
            || self.partition_id != text_guid(&guid(spec, Identifier::Data))
            || self.offset < 17 * MIB
            || !self.offset.is_multiple_of(MIB)
            || self.bytes < 64 * MIB
            || !self.bytes.is_multiple_of(MIB)
            || self
                .offset
                .checked_add(self.bytes)
                .is_none_or(|end| end > spec.bytes)
        {
            return Err("Scratch formatter target differs from its disk specification".into());
        }
        Ok(())
    }
}
pub struct UnformattedVolume {
    pub(super) disk: PartitionedDisk,
    pub(super) target: FormatTarget,
}
fn text_guid(id: &GUID) -> String {
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
struct Enumeration(windows_sys::Win32::Foundation::HANDLE);
impl Drop for Enumeration {
    fn drop(&mut self) {
        unsafe {
            FindVolumeClose(self.0);
        }
    }
}
fn query_volume(path: &str) -> Result<File> {
    crate::windows_scratch_spec::volume_name(path)?;
    let wide: Vec<_> = path
        .trim_end_matches('\\')
        .encode_utf16()
        .chain([0])
        .collect();
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
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn matches(disk: &PartitionedDisk, file: &File) -> Result<bool> {
    // A fixed one-extent response intentionally excludes multi-extent volumes.
    // Unrelated, offline volumes may also reject this read-only control code.
    let Ok(extents) = output::<VOLUME_DISK_EXTENTS>(file, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS)
    else {
        return Ok(false);
    };
    if extents.NumberOfDiskExtents != 1 || extents.Extents[0].DiskNumber != disk.disk.number {
        return Ok(false);
    }
    let data = disk.data();
    if extents.Extents[0].StartingOffset != data.StartingOffset
        || extents.Extents[0].ExtentLength != data.PartitionLength
        || !layout::same_partition(&output(file, IOCTL_DISK_GET_PARTITION_INFO_EX)?, &data)
    {
        return Err("Scratch volume extent or GPT partition identity changed".into());
    }
    disk.verify()?;
    Ok(true)
}
impl PartitionedDisk {
    pub fn discover(self) -> Result<UnformattedVolume> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.verify()?;
            let mut buffer = [0u16; 128];
            let raw = unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
            if raw == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error().into());
            }
            let enumeration = Enumeration(raw);
            let mut found = None;
            let mut count = 0;
            loop {
                count += 1;
                if count > 1024 {
                    return Err("Scratch volume discovery exceeds its budget".into());
                }
                let end = buffer
                    .iter()
                    .position(|&c| c == 0)
                    .ok_or("Unterminated volume GUID path")?;
                let path = String::from_utf16(&buffer[..end])?;
                // Other volumes may be offline, inaccessible, or multi-extent.
                // None of these read-only observations permits formatting them.
                if let Ok(file) = query_volume(&path) {
                    if matches(&self, &file)? && found.replace(path).is_some() {
                        return Err("More than one volume claims the scratch partition".into());
                    }
                }
                buffer.fill(0);
                if unsafe {
                    FindNextVolumeW(enumeration.0, buffer.as_mut_ptr(), buffer.len() as u32)
                } == 0
                {
                    if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                        return Err(io::Error::last_os_error().into());
                    }
                    break;
                }
            }
            if let Some(volume) = found {
                let target = FormatTarget {
                    schema: 1,
                    volume,
                    partition_id: text_guid(&guid(self.spec(), Identifier::Data)),
                    disk_number: self.disk.number,
                    offset: self.data().StartingOffset as u64,
                    bytes: self.data().PartitionLength as u64,
                };
                let result = UnformattedVolume { disk: self, target };
                result.verify()?;
                return Ok(result);
            }
            if Instant::now() >= deadline {
                return Err("Scratch volume did not arrive before its deadline".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
impl UnformattedVolume {
    pub fn verify(&self) -> Result<()> {
        self.disk.verify()?;
        if !matches(&self.disk, &query_volume(&self.target.volume)?)? {
            return Err("Scratch volume no longer belongs to its owned disk".into());
        }
        Ok(())
    }
    /// This descriptor alone conveys no native initialization capability. It is
    /// intended for the trusted Storage formatter while this guard remains live.
    pub fn target(&self) -> &FormatTarget {
        &self.target
    }
    pub fn spec(&self) -> &Spec {
        self.disk.spec()
    }
    pub fn detach(self) -> Result<()> {
        self.disk.detach()
    }
}
