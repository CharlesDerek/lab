//! Portable limits and identifiers for a dedicated Windows scanner scratch disk.
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MIB: u64 = 1024 * 1024;
pub const MAX_OVERHEAD: u64 = 64 * MIB;
pub fn validate_logon(logon: &str) -> Result<()> {
    let (high, low) = logon
        .strip_prefix("S-1-5-5-")
        .and_then(|s| s.split_once('-'))
        .ok_or("Invalid scratch logon SID")?;
    if [high, low].iter().any(|part| {
        part.len() > 10
            || match part.parse::<u32>() {
                Ok(n) => n.to_string() != *part,
                Err(_) => true,
            }
    }) {
        return Err("Invalid scratch logon SID".into());
    }
    Ok(())
}
pub(crate) fn capacity(
    total: i64,
    free: i64,
    sectors: u32,
    sector_bytes: u32,
    partition: u64,
) -> Result<(u64, u64)> {
    if total <= 0
        || free < 0
        || free > total
        || sectors != 8
        || sector_bytes != 512
        || !(64 * MIB..=4096 * MIB).contains(&partition)
    {
        return Err("Invalid scratch filesystem capacity or allocation unit".into());
    }
    let total_bytes = (total as u64)
        .checked_mul(4096)
        .ok_or("Scratch capacity overflow")?;
    let free_bytes = (free as u64)
        .checked_mul(4096)
        .ok_or("Scratch free space overflow")?;
    if total_bytes > partition || total_bytes < partition.saturating_sub(64 * MIB).max(64 * MIB) {
        return Err("Scratch filesystem capacity differs from its owned partition".into());
    }
    Ok((total_bytes, free_bytes))
}
pub(crate) fn volume_name(value: &str) -> Result<()> {
    let id = value
        .strip_prefix(r"\\?\Volume{")
        .and_then(|s| s.strip_suffix("}\\"))
        .ok_or("Scratch path is not a volume GUID root")?;
    if id.len() != 36
        || !id.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        return Err("Invalid scratch volume GUID".into());
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub schema: u32,
    pub id: String,
    pub bytes: u64,
}
#[derive(Clone, Copy)]
pub(crate) enum Identifier {
    Image = 0,
    Disk = 1,
    Reserved = 2,
    Data = 3,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ranges {
    pub reserved_start: u64,
    pub reserved_length: u64,
    pub data_start: u64,
    pub data_length: u64,
}
impl Spec {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.id.len() != 64
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || !(256 * MIB..=4096 * MIB).contains(&self.bytes)
            || !self.bytes.is_multiple_of(MIB)
        {
            return Err("Invalid bounded Windows scratch disk specification".into());
        }
        Ok(())
    }
    pub(crate) fn identifier(&self, kind: Identifier) -> [u8; 16] {
        let mut hash = Sha256::new();
        hash.update(b"athernex.windows.scratch.v1\0");
        hash.update(self.id.as_bytes());
        hash.update(self.bytes.to_le_bytes());
        hash.update([kind as u8]);
        let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
        // Version 8 UUID: application-defined, with the standard UUID variant.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        bytes
    }
    pub(crate) fn ranges(&self, start: u64, length: u64) -> Result<Ranges> {
        self.validate()?;
        let end = start
            .checked_add(length)
            .ok_or("Scratch GPT range overflow")?;
        if start == 0 || end > self.bytes || length == 0 {
            return Err("Scratch GPT usable range exceeds the owned image".into());
        }
        let reserved_start = start
            .div_ceil(MIB)
            .checked_mul(MIB)
            .ok_or("Scratch GPT alignment overflow")?;
        let reserved_length = 16 * MIB;
        let data_start = reserved_start
            .checked_add(reserved_length)
            .ok_or("Scratch partition overflow")?;
        let data_length = (end / MIB * MIB)
            .checked_sub(data_start)
            .ok_or("Scratch GPT range is too small")?;
        if data_length < 64 * MIB {
            return Err("Scratch data partition is too small".into());
        }
        Ok(Ranges {
            reserved_start,
            reserved_length,
            data_start,
            data_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> Spec {
        Spec {
            schema: 1,
            id: "a".repeat(64),
            bytes: 256 * MIB,
        }
    }
    #[test]
    fn disk_authority_is_bounded_and_partition_ranges_cannot_escape_it() {
        let s = spec();
        s.validate().unwrap();
        assert_eq!(
            s.ranges(34 * 512, s.bytes - 67 * 512).unwrap(),
            Ranges {
                reserved_start: MIB,
                reserved_length: 16 * MIB,
                data_start: 17 * MIB,
                data_length: 238 * MIB,
            }
        );
        for (start, length) in [
            (0, s.bytes),
            (1, u64::MAX),
            (1, s.bytes),
            (1, 1024),
            (u64::MAX, 1),
        ] {
            assert!(s.ranges(start, length).is_err());
        }
        for bytes in [0, 255 * MIB, 256 * MIB + 1, 4097 * MIB, u64::MAX] {
            let mut s = spec();
            s.bytes = bytes;
            assert!(s.validate().is_err());
        }
        assert_eq!(MAX_OVERHEAD, 64 * MIB);
    }
    #[test]
    fn identifiers_bind_session_size_and_object_role() {
        let mut s = spec();
        let ids = [
            Identifier::Image,
            Identifier::Disk,
            Identifier::Reserved,
            Identifier::Data,
        ]
        .map(|kind| s.identifier(kind));
        for (index, id) in ids.iter().enumerate() {
            assert_eq!(id[6] >> 4, 8);
            assert_eq!(id[8] >> 6, 2);
            assert!(!ids[..index].contains(id));
        }
        s.bytes += MIB;
        assert_ne!(s.identifier(Identifier::Image), ids[0]);
        s = spec();
        s.id = "b".repeat(64);
        assert_ne!(s.identifier(Identifier::Image), ids[0]);
        for id in ["../image".into(), "A".repeat(64), "a".repeat(63)] {
            s.id = id;
            assert!(s.validate().is_err());
        }
    }
    #[test]
    fn formatting_names_accept_only_one_volume_guid_root() {
        let root = r"\\?\Volume{01234567-89ab-cdef-8123-456789abcdef}\";
        volume_name(root).unwrap();
        for value in [
            r"C:\",
            r"\\.\PhysicalDrive1",
            r"\\server\share\",
            "",
            r"\\?\Volume{01234567-89ab-cdef-8123-456789abcdeg}\",
            r"\\?\Volume{01234567-89ab-cdef-8123-456789abcdef}\\",
            r"\\?\Volume{01234567-89ab-cdef-8123-456789abcdef}\scratch",
            r"\\?\Volume{0123456789ab-cdef-8123-456789abcdef}\",
        ] {
            assert!(volume_name(value).is_err(), "{value}");
        }
        assert!(volume_name(&format!("{root}\0")).is_err());
    }
    #[test]
    fn scratch_acl_input_is_one_canonical_logon_sid() {
        for sid in ["S-1-5-5-0-1", "S-1-5-5-4294967295-4294967295"] {
            validate_logon(sid).unwrap();
        }
        for sid in [
            "S-1-5-18",
            "S-1-5-19",
            "S-1-5-5-0-1)(A;;FA;;;WD)",
            "S-1-5-5-01-2",
            "S-1-5-5-0-1-2",
            "S-1-5-5-0-4294967296",
            "S-1-5-5-0-+1",
            "S-1-5-5--1",
            "S-1-5-5-0-1\0",
        ] {
            assert!(validate_logon(sid).is_err(), "{sid}");
        }
    }
    #[test]
    fn filesystem_capacity_checks_overflow_bounds_and_actual_allocation_units() {
        let units = (238 * MIB / 4096) as i64;
        assert_eq!(
            capacity(units, units / 2, 8, 512, 238 * MIB).unwrap(),
            (238 * MIB, 119 * MIB)
        );
        assert_eq!(capacity(units, 0, 8, 512, 238 * MIB).unwrap().1, 0);
        for (total, free, sectors, bytes, limit) in [
            (i64::MAX, 0, 8, 512, 238 * MIB),
            (-1, 0, 8, 512, 238 * MIB),
            (units, -1, 8, 512, 238 * MIB),
            (units, units + 1, 8, 512, 238 * MIB),
            (units + 1, 0, 8, 512, 238 * MIB),
            (units, 0, 1, 4096, 238 * MIB),
            (units, 0, 8, 512, 4097 * MIB),
            (1, 0, 8, 512, 238 * MIB),
        ] {
            assert!(capacity(total, free, sectors, bytes, limit).is_err());
        }
    }
}
