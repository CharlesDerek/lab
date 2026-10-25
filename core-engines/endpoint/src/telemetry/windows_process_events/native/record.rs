use crate::Result;
use athernex_endpoint_protocol::windows_process_events::{
    BufferContext, EventDescriptor, EventHeader, ExtendedData, QpcClock, WindowsProcessOriginal,
};
#[cfg(test)]
use std::ptr::null_mut;
use std::{
    fmt::Write,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
};
use windows_sys::{core::GUID, Win32::System::Diagnostics::Etw::*};
const MAX_BYTES: usize = 48 * 1024;
const QUEUE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const QUEUE_RECORDS: usize = 2048;
pub(in super::super) const PROCESS_GUID: GUID =
    GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
pub(in super::super) fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
pub(super) fn guid(value: GUID) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        value.data1,
        value.data2,
        value.data3,
        value.data4[0],
        value.data4[1],
        value.data4[2],
        value.data4[3],
        value.data4[4],
        value.data4[5],
        value.data4[6],
        value.data4[7]
    )
}
pub(super) fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}
struct Extra {
    header: EVENT_HEADER_EXTENDED_DATA_ITEM,
    bytes: Vec<u8>,
}
pub(in super::super) struct Record {
    pub header: EVENT_HEADER,
    context: ETW_BUFFER_CONTEXT,
    sequence: u64,
    extra: Vec<Extra>,
    data: Vec<u8>,
}
impl Record {
    unsafe fn copy(record: &EVENT_RECORD, sequence: u64) -> Result<Self> {
        if record.UserDataLength == 0
            || record.UserDataLength as usize > MAX_BYTES
            || record.UserData.is_null()
            || record.ExtendedDataCount > 16
            || (record.ExtendedDataCount != 0 && record.ExtendedData.is_null())
        {
            return Err("Invalid Windows process record bounds".into());
        }
        let mut total = record.UserDataLength as usize;
        let mut extra = Vec::new();
        for index in 0..record.ExtendedDataCount as usize {
            let mut header = record.ExtendedData.add(index).read();
            let size = header.DataSize as usize;
            total = total
                .checked_add(size)
                .ok_or("Windows process record size overflow")?;
            let pointer = usize::try_from(header.DataPtr)
                .map_err(|_| "Windows process extended pointer exceeds address width")?;
            if total > MAX_BYTES || (size != 0 && pointer == 0) {
                return Err("Windows process record exceeds admission bounds".into());
            }
            let bytes = if size == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(pointer as *const u8, size).to_vec()
            };
            header.DataPtr = 0;
            extra.push(Extra { header, bytes });
        }
        Ok(Self {
            header: record.EventHeader,
            context: record.BufferContext,
            sequence,
            extra,
            data: std::slice::from_raw_parts(
                record.UserData.cast::<u8>(),
                record.UserDataLength as usize,
            )
            .to_vec(),
        })
    }
    pub(super) fn bytes(&self) -> usize {
        self.data.len()
            + self
                .extra
                .iter()
                .map(|item| item.bytes.len())
                .sum::<usize>()
    }
    pub fn original(self, stream: &str, clock: QpcClock) -> WindowsProcessOriginal {
        let h = self.header;
        let d = h.EventDescriptor;
        WindowsProcessOriginal {
            stream_id: stream.into(),
            receipt_sequence: self.sequence,
            clock,
            header: EventHeader {
                size: h.Size,
                header_type: h.HeaderType,
                flags: h.Flags,
                event_property: h.EventProperty,
                thread_id: h.ThreadId,
                process_id: h.ProcessId,
                timestamp_qpc: h.TimeStamp,
                provider_id: guid(h.ProviderId),
                descriptor: EventDescriptor {
                    id: d.Id,
                    version: d.Version,
                    channel: d.Channel,
                    level: d.Level,
                    opcode: d.Opcode,
                    task: d.Task,
                    keyword: d.Keyword,
                },
                processor_time: unsafe { h.Anonymous.ProcessorTime },
                activity_id: guid(h.ActivityId),
            },
            buffer_context: BufferContext {
                processor_index: unsafe { self.context.Anonymous.ProcessorIndex },
                logger_id: self.context.LoggerId,
            },
            extended_data: self
                .extra
                .into_iter()
                .map(|item| ExtendedData {
                    reserved1: item.header.Reserved1,
                    ext_type: item.header.ExtType,
                    linkage: item.header.Anonymous._bitfield,
                    data_hex: hex(&item.bytes),
                })
                .collect(),
            user_data_hex: hex(&self.data),
        }
    }
    #[cfg(test)]
    pub fn with_record<T, E>(
        &self,
        consume: impl FnOnce(&EVENT_RECORD) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let mut extra: Vec<_> = self
            .extra
            .iter()
            .map(|item| {
                let mut header = item.header;
                header.DataPtr = item.bytes.as_ptr() as u64;
                header
            })
            .collect();
        let record = EVENT_RECORD {
            EventHeader: self.header,
            BufferContext: self.context,
            ExtendedDataCount: extra.len() as u16,
            UserDataLength: self.data.len() as u16,
            ExtendedData: extra.as_mut_ptr(),
            UserData: self.data.as_ptr().cast_mut().cast(),
            UserContext: null_mut(),
        };
        consume(&record)
    }
}
pub(super) struct State {
    pub queue: mpsc::SyncSender<Record>,
    pub bytes: AtomicUsize,
    pub received: AtomicU64,
    pub rejected: AtomicU64,
    pub dropped: AtomicU64,
    pub fatal: AtomicU64,
}
pub(super) unsafe extern "system" fn callback(record: *mut EVENT_RECORD) {
    if record.is_null() || (*record).UserContext.is_null() {
        return;
    }
    let state = &*(*record).UserContext.cast::<State>();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        let record = &*record;
        if !same_guid(record.EventHeader.ProviderId, PROCESS_GUID) {
            return Ok(());
        }
        let previous = state
            .received
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "Windows process receipt sequence exhausted")?;
        let owned = match Record::copy(record, previous + 1) {
            Ok(value) => value,
            Err(_) => {
                state.rejected.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };
        let bytes = owned.bytes();
        let queued = state.bytes.fetch_add(bytes, Ordering::AcqRel);
        if queued + bytes > QUEUE_BYTES || state.queue.try_send(owned).is_err() {
            state.bytes.fetch_sub(bytes, Ordering::AcqRel);
            state.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }));
    if !matches!(result, Ok(Ok(()))) {
        state.fatal.fetch_add(1, Ordering::Release);
    }
}
