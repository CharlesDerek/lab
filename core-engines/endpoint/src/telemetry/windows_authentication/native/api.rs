use crate::Result;
use std::{mem::size_of, ptr::null};
use windows_sys::{
    core::GUID,
    Win32::{Foundation::*, System::EventLog::*},
};
#[cfg(test)]
pub(super) mod tests;

pub(super) struct Handle(pub EVT_HANDLE);
impl Handle {
    pub fn checked(raw: EVT_HANDLE, operation: &str) -> Result<Self> {
        if raw == 0 {
            Err(failure(operation))
        } else {
            Ok(Self(raw))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            EvtClose(self.0);
        }
    }
}
pub(super) fn failure(operation: &str) -> Box<dyn std::error::Error + Send + Sync> {
    let code = unsafe { GetLastError() };
    failure_code(operation, code)
}
fn failure_code(operation: &str, code: u32) -> Box<dyn std::error::Error + Send + Sync> {
    #[cfg(test)]
    super::super::diagnostics::native("source_api", code);
    format!("{operation} failed with Windows error {code}").into()
}
pub(super) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
pub(super) fn next(query: &Handle) -> Result<Option<Handle>> {
    let (mut event, mut count) = (0, 0);
    if unsafe { EvtNext(query.0, 1, &mut event, 0, 0, &mut count) } == 0 {
        let code = unsafe { GetLastError() };
        // Close even an unexpected partially returned handle.
        if event != 0 {
            drop(Handle(event));
        }
        if code == ERROR_NO_MORE_ITEMS {
            return Ok(None);
        }
        #[cfg(test)]
        super::super::diagnostics::native("source_next", code);
        return Err(
            format!("Windows Security enumeration failed with Windows error {code}").into(),
        );
    }
    let event = Handle::checked(event, "Windows Security event handle")?;
    if count != 1 {
        return Err("Unexpected Windows Security enumeration count".into());
    }
    Ok(Some(event))
}
pub(super) fn text(event: &Handle, flags: u32, max_bytes: usize) -> Result<String> {
    if flags != EvtRenderEventXml && flags != EvtRenderBookmark {
        return Err("Unsupported Windows Security text rendering mode".into());
    }
    let (mut required, mut count) = (0, 0);
    let rendered = unsafe {
        EvtRender(
            0,
            event.0,
            flags,
            0,
            std::ptr::null_mut(),
            &mut required,
            &mut count,
        )
    };
    let code = unsafe { GetLastError() };
    #[cfg(test)]
    let probe = (rendered != 0, required, count);
    #[cfg(test)]
    if rendered == 0 && code != ERROR_INSUFFICIENT_BUFFER {
        super::super::diagnostics::native("source_render_probe", code);
    }
    if rendered != 0
        || code != ERROR_INSUFFICIENT_BUFFER
        || required < 2
        || required as usize > max_bytes * 2 + 2
        || required % 2 != 0
    {
        #[cfg(test)]
        super::super::diagnostics::render("bookmark_probe", flags, probe.0, probe.1, 0, probe.2);
        return Err("Windows Security text exceeds its rendering budget".into());
    }
    let mut buffer = vec![0u16; required as usize / 2];
    let capacity = required;
    let rendered = unsafe {
        EvtRender(
            0,
            event.0,
            flags,
            capacity,
            buffer.as_mut_ptr().cast(),
            &mut required,
            &mut count,
        )
    };
    let code = unsafe { GetLastError() };
    #[cfg(test)]
    let diagnose = || {
        super::super::diagnostics::render("bookmark_probe", flags, probe.0, probe.1, 0, probe.2);
        super::super::diagnostics::render(
            "bookmark_result",
            flags,
            rendered != 0,
            required,
            capacity,
            count,
        );
    };
    if rendered == 0 {
        #[cfg(test)]
        diagnose();
        return Err(failure_code("Windows Security text rendering", code));
    }
    // PropertyCount describes EVT_VARIANT arrays, not text. Windows Server 2022
    // returns 1 for a successful bookmark render, despite the documented zero.
    // Use only the bounded byte count and terminated UTF-16 buffer for text.
    if required < 2 || required > capacity || required % 2 != 0 {
        #[cfg(test)]
        diagnose();
        return Err("Invalid Windows Security rendered text size".into());
    }
    let words = &buffer[..required as usize / 2];
    if words.last() != Some(&0) || words[..words.len() - 1].contains(&0) {
        #[cfg(test)]
        diagnose();
        return Err("Invalid Windows Security text termination".into());
    }
    let value = String::from_utf16(&words[..words.len() - 1])?;
    if value.len() > max_bytes {
        #[cfg(test)]
        diagnose();
        return Err("Windows Security text exceeds its UTF-8 budget".into());
    }
    Ok(value)
}

pub(super) struct Values {
    buffer: Vec<u64>,
    used: usize,
    count: usize,
}
impl Values {
    pub fn render(context: &Handle, event: &Handle, count: usize) -> Result<Self> {
        let (mut required, mut actual) = (0, 0);
        let rendered = unsafe {
            EvtRender(
                context.0,
                event.0,
                EvtRenderEventValues,
                0,
                std::ptr::null_mut(),
                &mut required,
                &mut actual,
            )
        };
        let code = unsafe { GetLastError() };
        #[cfg(test)]
        if rendered == 0 && code != ERROR_INSUFFICIENT_BUFFER {
            super::super::diagnostics::native("source_render_probe", code);
        }
        if rendered != 0
            || code != ERROR_INSUFFICIENT_BUFFER
            || required as usize > 16_384
            || (required as usize) < count * size_of::<EVT_VARIANT>()
        {
            return Err("Invalid Windows Security property rendering size".into());
        }
        let capacity = required;
        let mut buffer = vec![0u64; (required as usize).div_ceil(8)];
        if unsafe {
            EvtRender(
                context.0,
                event.0,
                EvtRenderEventValues,
                capacity,
                buffer.as_mut_ptr().cast(),
                &mut required,
                &mut actual,
            )
        } == 0
        {
            return Err(failure("Windows Security property rendering"));
        }
        if required > capacity
            || actual as usize != count
            || (required as usize) < count * size_of::<EVT_VARIANT>()
        {
            return Err("Windows Security property count changed".into());
        }
        Ok(Self {
            buffer,
            used: required as usize,
            count,
        })
    }
    fn value(&self, index: i32, kind: i32) -> Result<EVT_VARIANT> {
        if index < 0 || index as usize >= self.count {
            return Err("Invalid Windows Security property index".into());
        }
        let value = unsafe {
            *self
                .buffer
                .as_ptr()
                .cast::<EVT_VARIANT>()
                .add(index as usize)
        };
        if value.Type != kind as u32 {
            return Err("Unexpected Windows Security property type".into());
        }
        Ok(value)
    }
    fn contains(&self, pointer: usize, bytes: usize) -> bool {
        let start = self.buffer.as_ptr() as usize;
        pointer >= start
            && pointer
                .checked_add(bytes)
                .is_some_and(|end| end <= start + self.used)
    }
    pub fn string(&self, index: i32, maximum: usize) -> Result<String> {
        let value = self.value(index, EvtVarTypeString)?;
        let pointer = unsafe { value.Anonymous.StringVal };
        if pointer.is_null() || !(pointer as usize).is_multiple_of(2) {
            return Err("Invalid Windows Security string pointer".into());
        }
        let mut words = Vec::new();
        for offset in 0..=maximum {
            let location = (pointer as usize)
                .checked_add(offset * 2)
                .ok_or("Windows Security pointer overflow")?;
            if !self.contains(location, 2) {
                return Err("Windows Security string exceeds its buffer".into());
            }
            let word = unsafe { *(location as *const u16) };
            if word == 0 {
                let value = String::from_utf16(&words)?;
                if value.len() > maximum || value.chars().any(char::is_control) {
                    return Err("Windows Security property exceeds its text budget".into());
                }
                return Ok(value);
            }
            words.push(word);
        }
        Err("Windows Security string is unterminated".into())
    }
    pub fn guid(&self, index: i32) -> Result<Option<String>> {
        if self.value(index, EvtVarTypeNull).is_ok() {
            return Ok(None);
        }
        let value = self.value(index, EvtVarTypeGuid)?;
        let pointer = unsafe { value.Anonymous.GuidVal };
        if pointer.is_null() || !self.contains(pointer as usize, size_of::<GUID>()) {
            return Err("Invalid Windows Security GUID pointer".into());
        }
        let guid = unsafe { std::ptr::read_unaligned(pointer) };
        Ok(Some(guid_text(&guid)))
    }
    pub fn required_guid(&self, index: i32) -> Result<String> {
        // XPath event values retain their native type. Accept a scalar GUID,
        // or a bounded string only when it has the complete braced GUID shape.
        // Arrays and other types must not become a known unrelated policy.
        if self.value(index, EvtVarTypeString).is_ok() {
            let value = self.string(index, 38)?;
            if value.len() != 38
                || !value
                    .bytes()
                    .enumerate()
                    .all(|(offset, byte)| match offset {
                        0 => byte == b'{',
                        37 => byte == b'}',
                        9 | 14 | 19 | 24 => byte == b'-',
                        _ => byte.is_ascii_hexdigit(),
                    })
            {
                return Err("Invalid Windows Security GUID text".into());
            }
            Ok(value.to_ascii_lowercase())
        } else {
            self.guid(index)?
                .ok_or_else(|| "Required Windows Security GUID is missing".into())
        }
    }
    #[cfg(test)]
    pub fn diagnostic_kind(&self, index: usize) -> &'static str {
        if index >= self.count {
            return "other";
        }
        let kind = unsafe { (*self.buffer.as_ptr().cast::<EVT_VARIANT>().add(index)).Type };
        match kind {
            value if value == EvtVarTypeGuid as u32 => "guid",
            value if value == EvtVarTypeString as u32 => "string",
            value if value == EvtVarTypeNull as u32 => "null",
            value if value & EVT_VARIANT_TYPE_ARRAY != 0 => "array",
            _ => "other",
        }
    }
    #[cfg(test)]
    pub fn local_system_sid(&self, index: i32) -> Result<bool> {
        let value = self.value(index, EvtVarTypeSid)?;
        let pointer = unsafe { value.Anonymous.SidVal };
        // The fixture expects exactly S-1-5-18. Compare its complete bounded
        // binary representation without an API following an untrusted count.
        const LOCAL_SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        if pointer.is_null() || !self.contains(pointer as usize, LOCAL_SYSTEM.len()) {
            return Err("Invalid Windows Security subject SID pointer".into());
        }
        Ok(
            unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), LOCAL_SYSTEM.len()) }
                == LOCAL_SYSTEM,
        )
    }
    pub fn record_id(&self) -> Result<u64> {
        Ok(unsafe {
            self.value(EvtSystemEventRecordId, EvtVarTypeUInt64)?
                .Anonymous
                .UInt64Val
        })
    }
    pub fn filetime(&self) -> Result<u64> {
        Ok(unsafe {
            self.value(EvtSystemTimeCreated, EvtVarTypeFileTime)?
                .Anonymous
                .FileTimeVal
        })
    }
    pub fn code(&self) -> Result<u32> {
        Ok(unsafe {
            self.value(EvtSystemEventID, EvtVarTypeUInt16)?
                .Anonymous
                .UInt16Val
        } as u32)
    }
    pub fn version(&self) -> Result<Option<u8>> {
        if self.value(EvtSystemVersion, EvtVarTypeNull).is_ok() {
            return Ok(None);
        }
        Ok(Some(unsafe {
            self.value(EvtSystemVersion, EvtVarTypeByte)?
                .Anonymous
                .ByteVal
        }))
    }
}
pub(super) fn guid_text(guid: &GUID) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    )
}
pub(super) fn system_context() -> Result<Handle> {
    Handle::checked(
        unsafe { EvtCreateRenderContext(0, null(), EvtRenderContextSystem) },
        "Windows Security system context",
    )
}
