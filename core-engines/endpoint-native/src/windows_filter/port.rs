//! Actual Filter Manager I/O. The hosting process must have independent job
//! ownership: cancelling an I/O request does not prove that it has completed.
use super::wire;
use crate::Result;
use std::{
    io,
    mem::{size_of, size_of_val},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use windows_sys::Win32::{
    Foundation::{ERROR_IO_PENDING, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Storage::InstallableFileSystems::{
        FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FilterSendMessage,
        FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER,
    },
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS},
        Threading::{CreateEventW, GetCurrentProcess, ResetEvent, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};
fn hresult(result: i32) -> Result<()> {
    if result != 0 {
        return Err(format!("Windows Filter Manager failed: 0x{:08x}", result as u32).into());
    }
    Ok(())
}
pub struct Port(OwnedHandle);
impl Port {
    pub fn connect() -> Result<Self> {
        let name: Vec<u16> = "\\AthernexScanV2".encode_utf16().chain([0]).collect();
        let mut handle = null_mut();
        hresult(unsafe {
            FilterConnectCommunicationPort(name.as_ptr(), 0, null(), 0, null(), &mut handle)
        })?;
        if handle.is_null() || handle as isize == -1 {
            return Err("Filter Manager returned an invalid port".into());
        }
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(handle) }))
    }
    fn handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
    // Only the integer-only, padding-free wire types are passed to this helper.
    fn send<T, U>(&self, request: &T, output: Option<&mut U>) -> Result<()> {
        let (pointer, bytes) = output.map_or((null_mut(), 0), |p| {
            (p as *mut U as *mut _, size_of::<U>() as u32)
        });
        let mut returned = 0;
        hresult(unsafe {
            FilterSendMessage(
                self.handle(),
                (request as *const T).cast(),
                size_of_val(request) as u32,
                pointer,
                bytes,
                &mut returned,
            )
        })?;
        if returned != bytes {
            return Err("Filter Manager returned an unexpected message length".into());
        }
        Ok(())
    }
    pub fn configure(&self, config: &wire::Configuration) -> Result<()> {
        config.validate()?;
        self.send::<_, u8>(config, None)
    }
    pub fn disarm(&self) -> Result<()> {
        self.send::<_, u8>(&wire::Header::new::<wire::Header>(wire::DISARM), None)
    }
    pub fn status(&self) -> Result<wire::Status> {
        let mut status = wire::Status::default();
        self.send(
            &wire::Header::new::<wire::Header>(wire::GET_STATUS),
            Some(&mut status),
        )?;
        status.validate()?;
        Ok(status)
    }
    pub fn mapping(&self, message: &wire::Notification) -> Result<Section> {
        let request = wire::MapRequest {
            header: wire::Header::new::<wire::MapRequest>(wire::MAP_SCAN),
            request_id: message.request_id,
        };
        let mut response = wire::Mapping::default();
        self.send(&request, Some(&mut response))?;
        // Own any returned handle before validation so error paths close it.
        let handle = if response.section_handle != 0 && response.section_handle != u64::MAX {
            Some(unsafe { OwnedHandle::from_raw_handle(response.section_handle as HANDLE) })
        } else {
            None
        };
        response.validate(message)?;
        let view = if let Some(handle) = &handle {
            let view = unsafe {
                MapViewOfFile(
                    handle.as_raw_handle(),
                    FILE_MAP_READ,
                    0,
                    0,
                    response.bytes as usize,
                )
            };
            if view.Value.is_null() {
                return Err(io::Error::last_os_error().into());
            }
            Some(view)
        } else {
            None
        };
        Ok(Section {
            _handle: handle,
            view,
            bytes: response.bytes,
        })
    }
    pub fn reply(&self, message_id: u64, reply: wire::Reply) -> Result<()> {
        // Initialize raw aligned storage: moving a Rust repr(C) value may leave
        // the Windows header's four padding bytes uninitialized again.
        let mut response =
            [0u64; (size_of::<FILTER_REPLY_HEADER>() + size_of::<wire::Reply>()) / 8];
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                response.as_mut_ptr().cast::<u8>(),
                size_of_val(&response),
            )
        };
        bytes[8..16].copy_from_slice(&message_id.to_le_bytes());
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&reply as *const wire::Reply).cast::<u8>(),
                bytes.as_mut_ptr().add(size_of::<FILTER_REPLY_HEADER>()),
                size_of::<wire::Reply>(),
            );
        }
        hresult(unsafe {
            FilterReplyMessage(
                self.handle(),
                response.as_ptr().cast(),
                (size_of::<FILTER_REPLY_HEADER>() + size_of::<wire::Reply>()) as u32,
            )
        })
    }
}
pub struct Section {
    _handle: Option<OwnedHandle>,
    view: Option<MEMORY_MAPPED_VIEW_ADDRESS>,
    bytes: u64,
}
impl Drop for Section {
    fn drop(&mut self) {
        if let Some(view) = self.view {
            unsafe {
                UnmapViewOfFile(view);
            }
        }
    }
}
impl Section {
    pub fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .ok_or("Section read overflow")?;
        if end > self.bytes {
            return Err("Read exceeds the kernel-approved section".into());
        }
        if buffer.is_empty() {
            return Ok(());
        }
        let view = self.view.ok_or("Empty section cannot provide file bytes")?;
        let address = (view.Value as usize)
            .checked_add(offset as usize)
            .ok_or("Section address overflow")?;
        let mut read = 0;
        // ReadProcessMemory handles invalid/in-page reads as errors. Do not
        // expose a Rust slice backed by potentially faulting mapped file pages.
        if unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const _,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut read,
            )
        } == 0
            || read != buffer.len()
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
}
#[repr(C)]
struct Buffer {
    header: FILTER_MESSAGE_HEADER,
    data: [u8; size_of::<wire::Applied>()],
}
pub enum Message {
    Scan {
        id: u64,
        file: Box<wire::Notification>,
    },
    Applied(Box<wire::Applied>),
}
pub struct Receiver {
    port: Arc<Port>,
    event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    buffer: Box<Buffer>,
    pending: bool,
}
impl Receiver {
    pub fn new(port: Arc<Port>) -> Result<Self> {
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut overlapped: Box<OVERLAPPED> = Box::default();
        overlapped.hEvent = event.as_raw_handle();
        Ok(Self {
            port,
            event,
            overlapped,
            buffer: Box::new(unsafe { std::mem::zeroed() }),
            pending: false,
        })
    }
    fn cancel(&mut self) {
        if self.pending {
            // The buffers remain owned until the actual completion. A parent
            // job is the independent deadline if the OS cannot complete this.
            unsafe {
                CancelIoEx(self.port.handle(), &*self.overlapped);
                let mut ignored = 0;
                GetOverlappedResult(self.port.handle(), &*self.overlapped, &mut ignored, 1);
            }
            self.pending = false;
        }
    }
    pub fn receive(&mut self, stop: &AtomicBool) -> Result<Option<Message>> {
        // Reuse only a completed operation. Reset both the manual-reset event
        // and the I/O status so a previous delivery cannot wake this receive.
        if self.pending {
            return Err("Windows filter receive is already pending".into());
        }
        if unsafe { ResetEvent(self.event.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        *self.overlapped = OVERLAPPED::default();
        self.overlapped.hEvent = self.event.as_raw_handle();
        let result = unsafe {
            FilterGetMessage(
                self.port.handle(),
                &mut self.buffer.header,
                size_of::<Buffer>() as u32,
                &mut *self.overlapped,
            )
        };
        if result != 0 && result as u32 != (0x80070000 | ERROR_IO_PENDING) {
            hresult(result)?;
        }
        self.pending = true;
        loop {
            if stop.load(Ordering::Acquire) {
                self.cancel();
                return Ok(None);
            }
            match unsafe { WaitForSingleObject(self.event.as_raw_handle(), 250) } {
                WAIT_OBJECT_0 => break,
                WAIT_TIMEOUT => continue,
                _ => return Err(io::Error::last_os_error().into()),
            }
        }
        let mut bytes = 0;
        let success =
            unsafe { GetOverlappedResult(self.port.handle(), &*self.overlapped, &mut bytes, 0) };
        if success == 0 {
            return Err(io::Error::last_os_error().into());
        }
        self.pending = false;
        let length = (bytes as usize)
            .checked_sub(size_of::<FILTER_MESSAGE_HEADER>())
            .ok_or("Short filter message")?;
        if length > self.buffer.data.len() {
            return Err("Oversized filter message".into());
        }
        if length == size_of::<wire::Notification>() {
            let file = unsafe {
                self.buffer
                    .data
                    .as_ptr()
                    .cast::<wire::Notification>()
                    .read_unaligned()
            };
            file.validate()?;
            if file.operation != wire::SCAN
                || self.buffer.header.ReplyLength as usize
                    != size_of::<FILTER_REPLY_HEADER>() + size_of::<wire::Reply>()
            {
                return Err("Unexpected filter scan envelope".into());
            }
            Ok(Some(Message::Scan {
                id: self.buffer.header.MessageId,
                file: Box::new(file),
            }))
        } else if length == size_of::<wire::Applied>() {
            let event = unsafe {
                self.buffer
                    .data
                    .as_ptr()
                    .cast::<wire::Applied>()
                    .read_unaligned()
            };
            event.file.validate()?;
            event.decision.detection(event.file.request_id)?;
            if event.file.operation != wire::APPLIED
                || event.reserved != 0
                || self.buffer.header.ReplyLength != 0
                || (event.decision.verdict == wire::CLEAN) != (event.status == 0)
                || (event.status != 0 && event.status as u32 != 0xc0000022)
            {
                return Err("Unexpected filter decision envelope".into());
            }
            Ok(Some(Message::Applied(Box::new(event))))
        } else {
            Err("Unknown filter message length".into())
        }
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.cancel();
    }
}
