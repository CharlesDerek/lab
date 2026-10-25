//! Bounded decoder for FILE_ID_EXTD_DIR_INFO. Names stay UTF-16 so cleanup never
//! replaces an unpaired surrogate or applies Win32 path normalization.
use crate::Result;

pub(crate) const HEADER: usize = 88;
pub(crate) const BUFFER: usize = 16 * 1024;
pub(crate) struct Entry {
    pub name: Vec<u16>,
    pub id: [u8; 16],
    pub attributes: u32,
}
pub(crate) fn leaf(name: &[u16]) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == [46]
        || name == [46, 46]
        || name.iter().any(|c| [0, 47, 58, 92].contains(c))
    {
        return Err("Invalid Windows cleanup directory entry".into());
    }
    Ok(())
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<Entry>> {
    if bytes.len() < HEADER || bytes.len() > BUFFER {
        return Err("Windows directory buffer exceeds its bounds".into());
    }
    let mut entries = Vec::new();
    let mut offset = 0;
    loop {
        let data = bytes
            .get(offset..)
            .ok_or("Invalid directory entry offset")?;
        if data.len() < HEADER {
            return Err("Truncated Windows directory entry".into());
        }
        let next = u32::from_le_bytes(data[..4].try_into()?) as usize;
        let size = u32::from_le_bytes(data[60..64].try_into()?) as usize;
        if size == 0 || size > 510 || !size.is_multiple_of(2) || HEADER + size > data.len() {
            return Err("Invalid Windows directory filename length".into());
        }
        let name: Vec<_> = data[HEADER..HEADER + size]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        if name != [46] && name != [46, 46] {
            leaf(&name)?;
            entries.push(Entry {
                name,
                id: data[72..88].try_into()?,
                attributes: u32::from_le_bytes(data[56..60].try_into()?),
            });
        }
        if next == 0 {
            return Ok(entries);
        }
        if next < HEADER + size || !next.is_multiple_of(8) || next > data.len() - HEADER {
            return Err("Invalid Windows directory entry chain".into());
        }
        offset += next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(name: &[u16], next: u32) -> Vec<u8> {
        let mut b = vec![0; (HEADER + name.len() * 2).next_multiple_of(8)];
        b[..4].copy_from_slice(&next.to_le_bytes());
        b[56..60].copy_from_slice(&16u32.to_le_bytes());
        b[60..64].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        b[72..88].copy_from_slice(&[0xab; 16]);
        for (target, value) in b[HEADER..].chunks_exact_mut(2).zip(name) {
            target.copy_from_slice(&value.to_le_bytes());
        }
        b
    }
    #[test]
    fn retains_exact_names_ids_and_skips_only_dot_entries() {
        let mut data = entry(&[46], 96);
        data.extend(entry(&[46, 46], 96));
        data.extend(entry(&[0xd800, 32, 46], 0));
        let result = decode(&data).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, [0xd800, 32, 46]);
        assert_eq!(result[0].id, [0xab; 16]);
        assert_eq!(result[0].attributes, 16);
    }
    #[test]
    fn rejects_truncation_traversal_aliases_and_malformed_chains() {
        for name in [&[][..], &[0], &[47], &[58], &[92]] {
            assert!(decode(&entry(name, 0)).is_err());
        }
        for next in [1, 88, 95, 97, u32::MAX] {
            assert!(decode(&entry(&[65], next)).is_err());
        }
        let mut valid = entry(&[65], 0);
        for size in [0u32, 1, 511, u32::MAX] {
            valid[60..64].copy_from_slice(&size.to_le_bytes());
            assert!(decode(&valid).is_err());
        }
        assert!(decode(&vec![0; BUFFER + 1]).is_err());
        assert!(decode(&[0; HEADER - 1]).is_err());
    }
}
