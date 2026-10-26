use crate::Result;
use athernex_endpoint_protocol::windows_network_events::{
    BufferContext, EventDescriptor, EventHeader, ExtendedData, QpcClock, WindowsNetworkOriginal,
};
use std::{
    fmt::Write,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
};
use windows_sys::{core::GUID, Win32::System::Diagnostics::Etw::*};
const MAX_BYTES: usize = athernex_endpoint_protocol::windows_network_events::MAX_ORIGINAL_BYTES;
const QUEUE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const QUEUE_RECORDS: usize = 2048;
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
#[cfg_attr(test, derive(Clone))]
struct Extra {
    header: EVENT_HEADER_EXTENDED_DATA_ITEM,
    bytes: Vec<u8>,
}
#[cfg_attr(test, derive(Clone))]
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
            || record.ExtendedDataCount as usize
                > athernex_endpoint_protocol::windows_network_events::MAX_EXTENDED_ITEMS
            || (record.ExtendedDataCount != 0 && record.ExtendedData.is_null())
        {
            return Err("Invalid Windows network record bounds".into());
        }
        let mut total = record.UserDataLength as usize;
        let mut extra = Vec::new();
        for index in 0..record.ExtendedDataCount as usize {
            let mut header = record.ExtendedData.add(index).read();
            let size = header.DataSize as usize;
            total = total
                .checked_add(size)
                .ok_or("Windows network record size overflow")?;
            let pointer = usize::try_from(header.DataPtr)
                .map_err(|_| "Windows network extended pointer exceeds address width")?;
            if total > MAX_BYTES || (size != 0 && pointer == 0) {
                return Err("Windows network record exceeds admission bounds".into());
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
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn original(self, stream: &str, clock: QpcClock) -> WindowsNetworkOriginal {
        let h = self.header;
        let d = h.EventDescriptor;
        WindowsNetworkOriginal {
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
    pub fn data(&self) -> &[u8] {
        &self.data
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
            UserContext: std::ptr::null_mut(),
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
        if !same_guid(record.EventHeader.ProviderId, TcpIpGuid)
            && !same_guid(record.EventHeader.ProviderId, UdpIpGuid)
        {
            return Ok(());
        }
        let previous = state
            .received
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "Windows network receipt sequence exhausted")?;
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

#[cfg(test)]
#[test]
pub(in super::super) fn copied_record_bounds_and_lifetime() {
    let mut payload = vec![1u8, 2, 3, 4];
    let mut extra = vec![5u8; 8];
    let mut extension = EVENT_HEADER_EXTENDED_DATA_ITEM {
        Reserved1: 7,
        ExtType: 1,
        DataSize: 8,
        DataPtr: extra.as_mut_ptr() as u64,
        ..Default::default()
    };
    extension.Anonymous._bitfield = 3;
    let mut record = EVENT_RECORD {
        UserData: payload.as_mut_ptr().cast(),
        UserDataLength: 4,
        ExtendedData: &mut extension,
        ExtendedDataCount: 1,
        ..Default::default()
    };
    record.EventHeader.ProviderId = TcpIpGuid;
    record.EventHeader.Flags = 0x140;
    record.EventHeader.ProcessId = 42;
    record.EventHeader.ThreadId = 11;
    record.EventHeader.TimeStamp = 123;
    record.EventHeader.EventDescriptor.Version = 2;
    record.EventHeader.EventDescriptor.Opcode = 11;
    record.BufferContext.Anonymous.ProcessorIndex = 7;
    record.BufferContext.LoggerId = 12;
    let owned = unsafe { Record::copy(&record, 19) }.expect("Synthetic copy refused");
    payload.fill(0);
    extra.fill(0);
    drop(payload);
    drop(extra);
    record.EventHeader = EVENT_HEADER::default();
    record.BufferContext = ETW_BUFFER_CONTEXT::default();
    extension.DataPtr = 0;
    // The native scalar source is overwritten and its pointed-to buffers have
    // been destroyed. TDH must receive only relocated pointers into owned bytes.
    assert!(owned
        .with_record(|copy| -> std::result::Result<(), ()> {
            if copy.UserDataLength as usize != owned.data.len()
                || copy.UserData.cast::<u8>() != owned.data.as_ptr().cast_mut()
                || copy.ExtendedDataCount != 1
                || copy.ExtendedData.is_null()
            {
                return Err(());
            }
            let item = unsafe { &*copy.ExtendedData };
            if item.DataSize as usize != owned.extra[0].bytes.len()
                || item.DataPtr != owned.extra[0].bytes.as_ptr() as u64
            {
                return Err(());
            }
            let header = &copy.EventHeader;
            let data = unsafe {
                std::slice::from_raw_parts(copy.UserData.cast::<u8>(), copy.UserDataLength as usize)
            };
            let extra = unsafe {
                std::slice::from_raw_parts(item.DataPtr as *const u8, item.DataSize as usize)
            };
            let correct = same_guid(header.ProviderId, TcpIpGuid)
                && header.Flags == 0x140
                && header.ProcessId == 42
                && header.ThreadId == 11
                && header.TimeStamp == 123
                && header.EventDescriptor.Version == 2
                && header.EventDescriptor.Opcode == 11
                && unsafe { copy.BufferContext.Anonymous.ProcessorIndex } == 7
                && copy.BufferContext.LoggerId == 12
                && data == [1, 2, 3, 4]
                && copy.ExtendedDataCount == 1
                && extra == [5; 8]
                && item.Reserved1 == 7
                && item.ExtType == 1
                && item.Anonymous._bitfield == 3;
            if correct {
                Ok(())
            } else {
                Err(())
            }
        })
        .is_ok());
    let original = owned.original(
        &"a".repeat(64),
        QpcClock {
            frequency_hz: 10_000_000,
            before_qpc: 100,
            after_qpc: 120,
            utc_filetime_100ns: 116444736000000000,
        },
    );
    assert!(
        original.receipt_sequence == 19
            && original.user_data_hex == "01020304"
            && original.extended_data.len() == 1
            && original.extended_data[0].data_hex == "05".repeat(8)
            && original.extended_data[0].reserved1 == 7
            && original.extended_data[0].linkage == 3
    );

    // Each intentionally invalid pointer is protected by a preceding refusal.
    let dangling = std::ptr::dangling_mut::<u8>();
    let mut invalid = EVENT_RECORD {
        UserData: dangling.cast(),
        ..Default::default()
    };
    assert!(unsafe { Record::copy(&invalid, 1) }.is_err());
    invalid.UserDataLength = (MAX_BYTES + 1) as u16;
    assert!(unsafe { Record::copy(&invalid, 1) }.is_err());
    invalid.UserDataLength = 4;
    invalid.UserData = std::ptr::null_mut();
    assert!(unsafe { Record::copy(&invalid, 1) }.is_err());
    invalid.UserData = dangling.cast();
    invalid.ExtendedDataCount = 17;
    invalid.ExtendedData = std::ptr::dangling_mut();
    assert!(unsafe { Record::copy(&invalid, 1) }.is_err());
    invalid.ExtendedDataCount = 1;
    invalid.ExtendedData = std::ptr::null_mut();
    assert!(unsafe { Record::copy(&invalid, 1) }.is_err());
    let mut oversized = EVENT_HEADER_EXTENDED_DATA_ITEM {
        DataSize: (MAX_BYTES - 3) as u16,
        DataPtr: 1,
        ..Default::default()
    };
    invalid.ExtendedData = &mut oversized;
    assert!(unsafe { Record::copy(&invalid, 1) }.is_err());
    oversized.DataSize = 1;
    oversized.DataPtr = 0;
    assert!(unsafe { Record::copy(&invalid, 1) }.is_err());

    let mut payload = vec![1u8; 4];
    let mut exact = vec![2u8; MAX_BYTES - 4];
    oversized.DataSize = exact.len() as u16;
    oversized.DataPtr = exact.as_mut_ptr() as u64;
    invalid.UserData = payload.as_mut_ptr().cast();
    assert!(unsafe { Record::copy(&invalid, 1) }.is_ok());
    let mut empty = [EVENT_HEADER_EXTENDED_DATA_ITEM::default(); 16];
    invalid.ExtendedData = empty.as_mut_ptr();
    invalid.ExtendedDataCount = 16;
    assert!(unsafe { Record::copy(&invalid, 1) }.is_ok());
}
