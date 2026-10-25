//! Preserve Windows case-insensitive names, explicit env_clear, and inherited
//! hidden drive-directory entries. Never reconstruct a std::process::Command:
//! its public accessors do not expose whether inheritance was disabled.
use super::Command;
use std::{cmp::Ordering, io, os::windows::ffi::OsStrExt};
use windows_sys::Win32::{
    Globalization::CompareStringOrdinal,
    System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW},
};
const MAX_UNITS: usize = 65536;
const MAX_ENTRIES: usize = 4096;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Invalid or oversized Windows environment",
    )
}
fn compare(a: &[u16], b: &[u16]) -> Ordering {
    // Lengths have been bounded well below i32::MAX; neither pointer is null.
    match unsafe { CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1) }
    {
        1 => Ordering::Less,
        2 => Ordering::Equal,
        3 => Ordering::Greater,
        _ => unreachable!("CompareStringOrdinal received validated parameters"),
    }
}
struct Inherited(*mut u16);
impl Drop for Inherited {
    fn drop(&mut self) {
        unsafe {
            FreeEnvironmentStringsW(self.0);
        }
    }
}
pub(super) fn block(command: &Command) -> io::Result<Vec<u16>> {
    let mut entries: Vec<(Vec<u16>, Vec<u16>)> = Vec::new();
    if !command.clear_env {
        let raw = unsafe { GetEnvironmentStringsW() };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let inherited = Inherited(raw);
        let mut offset = 0;
        loop {
            // GetEnvironmentStringsW owns a double-NUL terminated block. Stop
            // at the terminator; the extra budget bounds malformed huge input.
            if offset >= MAX_UNITS {
                return Err(invalid());
            }
            if unsafe { *inherited.0.add(offset) } == 0 {
                break;
            }
            let mut entry = Vec::new();
            loop {
                if offset >= MAX_UNITS {
                    return Err(invalid());
                }
                let unit = unsafe { *inherited.0.add(offset) };
                offset += 1;
                if unit == 0 {
                    break;
                }
                entry.push(unit);
            }
            // The first '=' is part of the name for hidden entries such as =C:.
            let split = entry
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, c)| **c == 61)
                .map(|(i, _)| i)
                .ok_or_else(invalid)?;
            entries.push((entry[..split].to_vec(), entry[split + 1..].to_vec()));
            if entries.len() > MAX_ENTRIES {
                return Err(invalid());
            }
        }
    }
    for (key, value) in &command.environment {
        let key: Vec<u16> = key.encode_wide().collect();
        if key.is_empty() || key.len() >= MAX_UNITS || key.contains(&0) || key.contains(&61) {
            return Err(invalid());
        }
        entries.retain(|(name, _)| compare(name, &key) != Ordering::Equal);
        if let Some(value) = value {
            let value: Vec<u16> = value.encode_wide().collect();
            if value.len() >= MAX_UNITS || value.contains(&0) {
                return Err(invalid());
            }
            entries.push((key, value));
        }
    }
    if entries.len() > MAX_ENTRIES {
        return Err(invalid());
    }
    entries.sort_by(|(a, _), (b, _)| compare(a, b));
    if entries
        .windows(2)
        .any(|pair| compare(&pair[0].0, &pair[1].0) == Ordering::Equal)
    {
        return Err(invalid());
    }
    let mut block = Vec::new();
    for (key, value) in entries {
        if block.len() + key.len() + value.len() + 3 > MAX_UNITS {
            return Err(invalid());
        }
        block.extend(key);
        block.push(61);
        block.extend(value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}
