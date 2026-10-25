//! Layout evidence pinned to Microsoft's TraceEvent implementation:
//! https://github.com/microsoft/perfview/blob/4ae8d85b25043a21e6cb65bda340a620d691ac62/src/TraceEvent/Parsers/KernelTraceEventParser.cs
//! (`ProcessTraceData`, `GetKernelImageNameOffset`, exact v2/v3/v4 lengths), and
//! https://github.com/microsoft/perfview/blob/4ae8d85b25043a21e6cb65bda340a620d691ac62/src/TraceEvent/TraceEvent.cs
//! (`SkipSID`: null DWORD, otherwise two pointer-width TOKEN_USER words + SID).
//! Microsoft Process_V2_TypeGroup1 documents the reported fields/opcodes:
//! https://learn.microsoft.com/en-us/windows/win32/etw/process-v2-typegroup1
//! Only v4/64-bit has native acceptance evidence; other supported layouts have
//! portable synthetic tests. Unknown versions/trailing fields are refused.
//! The SDK defines TERMINATE (11) separately from END (2). Its observed v2
//! single-ProcessId schema is admitted only with an exact four-byte payload;
//! native payload/PID agreement must still be established by the native gate.
//! Opcode semantics (not payload-layout evidence) are pinned to Microsoft's SDK:
//! https://github.com/microsoft/win32metadata/blob/2f767671802301cf043c717d66bf004ed7863487/generation/WinSDK/RecompiledIdlHeaders/shared/evntrace.h#L331-L334
use super::*;

fn hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() > MAX_ORIGINAL_BYTES * 2
        || !input.len().is_multiple_of(2)
        || !input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid Windows process original byte encoding".into());
    }
    let digit = |v: u8| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
    Ok(input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
        .collect())
}
pub(super) fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn guid(value: &str) -> bool {
    value.len() == 38
        && value.bytes().enumerate().all(|(i, b)| match i {
            0 => b == b'{',
            37 => b == b'}',
            9 | 14 | 19 | 24 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or("Truncated Windows process original")?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn pointer(&mut self, width: usize) -> Result<u64, String> {
        if width == 4 {
            Ok(u64::from(self.u32()?))
        } else {
            Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
        }
    }
    fn sid(&mut self, width: usize) -> Result<Option<String>, String> {
        let token_start = self.offset;
        if self.u32()? == 0 {
            return Ok(None);
        }
        self.offset = token_start;
        self.take(width * 2)?;
        let header = self.take(8)?;
        if header[0] != 1 || header[1] > 15 {
            return Err("Unsupported Windows process SID layout".into());
        }
        let authority = header[2..]
            .iter()
            .fold(0u64, |n, b| (n << 8) | u64::from(*b));
        let mut result = format!("S-1-{authority}");
        for _ in 0..header[1] {
            result.push_str(&format!("-{}", self.u32()?));
        }
        Ok(Some(result))
    }
    fn ansi(&mut self) -> Result<Vec<u8>, String> {
        let length = self.bytes[self.offset..]
            .iter()
            .take(4097)
            .position(|b| *b == 0)
            .ok_or("Windows process image bytes exceed bounds or lack termination")?;
        let value = self.take(length)?.to_vec();
        self.take(1)?;
        Ok(value)
    }
    fn unicode(&mut self, max_units: usize) -> Result<String, String> {
        let mut units = Vec::new();
        loop {
            let value = u16::from_le_bytes(self.take(2)?.try_into().unwrap());
            if value == 0 {
                return String::from_utf16(&units)
                    .map_err(|_| "Invalid Windows process UTF-16 original".into());
            }
            if units.len() >= max_units {
                return Err("Windows process text exceeds bounds".into());
            }
            units.push(value);
        }
    }
}

pub(super) fn decode(original: WindowsProcessOriginal) -> Result<WindowsProcessEvent, String> {
    let header = &original.header;
    let version = header.descriptor.version;
    if !crate::hex_id(&original.stream_id)
        || original.receipt_sequence == 0
        || header.provider_id != PROCESS_PROVIDER
        || !guid(&header.activity_id)
        || header.flags & 0x100 == 0 // EVENT_HEADER_FLAG_CLASSIC_HEADER
        || header.flags & 0x0c != 0 // String-only and trace-message payloads differ.
        || !matches!(version, 2..=4)
        || original.extended_data.len() > MAX_EXTENDED_ITEMS
    {
        return Err("Unsupported Windows process provenance or layout".into());
    }
    // Size describes the original ETW record, not this pointer-free transport;
    // HeaderType is reserved. Preserve both without inventing a sizeof check.
    let width = match header.flags & 0x60 {
        0x20 => 4,
        0x40 => 8,
        _ => return Err("Ambiguous Windows process pointer width".into()),
    };
    let change = match header.descriptor.opcode {
        1 => WindowsProcessChange::Start,
        2 => WindowsProcessChange::End,
        3 => WindowsProcessChange::RundownStart,
        4 => WindowsProcessChange::RundownEnd,
        39 => WindowsProcessChange::Defunct,
        11 if version == 2 => WindowsProcessChange::Terminate,
        _ => return Err("Unsupported Windows process opcode".into()),
    };
    let bytes = hex(&original.user_data_hex)?;
    let mut total = bytes.len();
    for extension in &original.extended_data {
        total = total
            .checked_add(hex(&extension.data_hex)?.len())
            .filter(|total| *total <= MAX_ORIGINAL_BYTES)
            .ok_or("Windows process originals exceed their byte budget")?;
    }
    let (time_ms, time_uncertainty_ms) = original.clock.estimate(header.timestamp_qpc)?;
    let mut reader = Reader {
        bytes: &bytes,
        offset: 0,
    };
    if change == WindowsProcessChange::Terminate {
        let pid = reader.u32()?;
        if reader.offset != bytes.len() {
            return Err("Unrecognized trailing Windows process termination bytes".into());
        }
        return Ok(WindowsProcessEvent {
            original,
            change,
            pointer_bits: (width * 8) as u8,
            pid,
            parent_pid: None,
            session_id: None,
            exit_status: None,
            unique_process_key: None,
            process_flags: None,
            user_sid: None,
            image_name_bytes_hex: None,
            command_line: None,
            package_full_name: None,
            application_id: None,
            time_ms,
            time_uncertainty_ms,
            time_basis: WindowsProcessTimeBasis::CollectorQpcEstimate,
        });
    }
    let unique_process_key = reader.pointer(width)?;
    let pid = reader.u32()?;
    let parent_pid = reader.u32()?;
    let session_id = reader.u32()?;
    let exit_status = reader.u32()? as i32;
    if version >= 3 {
        // Preserve this directory-table address only in exact original bytes.
        reader.pointer(width)?;
    }
    let process_flags = (version >= 4).then(|| reader.u32()).transpose()?;
    let user_sid = reader.sid(width)?;
    let image_name_bytes_hex = encode(&reader.ansi()?);
    let command_line = reader.unicode(16_384)?;
    let (package_full_name, application_id) = if version >= 4 {
        (Some(reader.unicode(4096)?), Some(reader.unicode(4096)?))
    } else {
        (None, None)
    };
    if reader.offset != bytes.len() {
        return Err("Unrecognized trailing Windows process original bytes".into());
    }
    Ok(WindowsProcessEvent {
        original,
        change,
        pointer_bits: (width * 8) as u8,
        pid,
        parent_pid: Some(parent_pid),
        session_id: Some(session_id),
        exit_status: Some(exit_status),
        unique_process_key: Some(unique_process_key),
        process_flags,
        user_sid,
        image_name_bytes_hex: Some(image_name_bytes_hex),
        command_line: Some(command_line),
        package_full_name,
        application_id,
        time_ms,
        time_uncertainty_ms,
        time_basis: WindowsProcessTimeBasis::CollectorQpcEstimate,
    })
}
