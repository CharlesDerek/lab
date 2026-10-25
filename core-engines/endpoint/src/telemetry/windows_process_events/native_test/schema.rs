//! TDH supplies the actual installed schema; no unknown version is guessed.
use super::{
    api,
    native::{same_guid, Record as Original, PROCESS_GUID},
    require, Result,
};
use std::{
    collections::BTreeMap,
    mem::{offset_of, size_of},
    ptr::null_mut,
};
use windows_sys::Win32::{Foundation::ERROR_INSUFFICIENT_BUFFER, System::Diagnostics::Etw::*};

pub(super) struct Report {
    pub pid: u32,
    pub parent: Option<u32>,
    pub session: Option<u32>,
    pub exit: Option<i32>,
    pub key: Option<u64>,
    pub pointer_bits: u8,
    pub property_count: u32,
    pub schema_hash: String,
}
fn name(bytes: &[u8], offset: u32) -> Result<String> {
    let offset = offset as usize;
    require(
        offset >= offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
            && offset.is_multiple_of(2)
            && offset < bytes.len(),
        "Invalid schema property name offset",
    )?;
    let mut units = Vec::new();
    for pair in bytes[offset..].chunks_exact(2).take(129) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            require(!units.is_empty(), "Schema property name empty")?;
            return String::from_utf16(&units).map_err(|_| "Schema property name encoding invalid");
        }
        require(
            unit <= 127 && (unit as u8).is_ascii_graphic(),
            "Schema property name invalid",
        )?;
        units.push(unit);
    }
    Err("Schema property name unterminated")
}
fn property(
    record: &EVENT_RECORD,
    context: &TDH_CONTEXT,
    field: &str,
    expected: usize,
) -> Result<Vec<u8>> {
    let wide: Vec<u16> = field.encode_utf16().chain([0]).collect();
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wide.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut bytes = 0;
    api("tdh_size", unsafe {
        TdhGetPropertySize(record, 1, context, 1, &descriptor, &mut bytes)
    })?;
    require(
        bytes as usize == expected && expected <= 8,
        "TDH scalar property size differs",
    )?;
    let mut value = vec![0; expected];
    api("tdh_property", unsafe {
        TdhGetProperty(
            record,
            1,
            context,
            1,
            &descriptor,
            bytes,
            value.as_mut_ptr(),
        )
    })?;
    Ok(value)
}
fn scalar_type(
    properties: &BTreeMap<String, EVENT_PROPERTY_INFO>,
    field: &str,
    expected: &[i32],
) -> Result<()> {
    let info = properties
        .get(field)
        .ok_or("Required process schema property missing")?;
    require(
        info.Flags & !(PropertyParamFixedCount | PropertyParamFixedLength | PropertyHasTags) == 0
            && unsafe { info.Anonymous2.count } == 1,
        "Process schema property is not scalar",
    )?;
    let input = unsafe { info.Anonymous1.nonStructType.InType } as i32;
    require(
        expected.contains(&input),
        "Process schema property type differs",
    )
}
fn property_label(field: &str) -> Option<&'static str> {
    match field {
        "ProcessId" => Some("process_id"),
        "ParentId" => Some("parent_id"),
        "SessionId" => Some("session_id"),
        "ExitStatus" => Some("exit_status"),
        "UniqueProcessKey" => Some("unique_process_key"),
        _ => None,
    }
}
fn scalar_property(
    record: &EVENT_RECORD,
    context: &TDH_CONTEXT,
    properties: &BTreeMap<String, EVENT_PROPERTY_INFO>,
    field: &str,
    expected: &[i32],
    width: usize,
) -> Result<Vec<u8>> {
    let result = scalar_type(properties, field, expected)
        .and_then(|()| property(record, context, field, width));
    if result.is_err() {
        // These fields describe an installed structural schema. All payload
        // values and arbitrary native property names remain private.
        let descriptor = record.EventHeader.EventDescriptor;
        println!(
            "\nATHERNEX_PROCESS_EVENTS_SCHEMA={}:{}:{}:{}",
            descriptor.Opcode,
            descriptor.Version,
            context.ParameterValue * 8,
            properties.len()
        );
        if let Some(label) = property_label(field) {
            println!("\nATHERNEX_PROCESS_EVENTS_TDH_PROPERTY={label}");
        }
    }
    result
}
fn scalar32(
    record: &EVENT_RECORD,
    context: &TDH_CONTEXT,
    properties: &BTreeMap<String, EVENT_PROPERTY_INFO>,
    field: &str,
    expected: &[i32],
) -> Result<u32> {
    let value = scalar_property(record, context, properties, field, expected, 4)?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| "Invalid scalar bytes")?,
    ))
}
pub(super) fn decode(original: &Original) -> Result<Report> {
    original.with_record(|record| {
        let flags = record.EventHeader.Flags as u32;
        require(
            flags & EVENT_HEADER_FLAG_CLASSIC_HEADER != 0
                && same_guid(record.EventHeader.ProviderId, PROCESS_GUID)
                && record.EventHeader.TimeStamp > 0,
            "Invalid native process provenance",
        )?;
        let pointer_bits =
            match flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER) {
                EVENT_HEADER_FLAG_32_BIT_HEADER => 32,
                EVENT_HEADER_FLAG_64_BIT_HEADER => 64,
                _ => return Err("Native process pointer width is ambiguous"),
            };
        let context = TDH_CONTEXT {
            ParameterValue: pointer_bits as u64 / 8,
            ParameterType: TDH_CONTEXT_POINTERSIZE,
            ParameterSize: 0,
        };
        let mut required = 0;
        let code =
            unsafe { TdhGetEventInformation(record, 1, &context, null_mut(), &mut required) };
        if code != ERROR_INSUFFICIENT_BUFFER {
            api("tdh_information", code)?;
            return Err("TDH metadata size probe invalid");
        }
        require(
            (size_of::<TRACE_EVENT_INFO>() as u32..=65_536).contains(&required),
            "TDH metadata exceeds bounds",
        )?;
        let capacity = required;
        let mut buffer = vec![0u64; (capacity as usize).div_ceil(8)];
        api("tdh_information", unsafe {
            TdhGetEventInformation(
                record,
                1,
                &context,
                buffer.as_mut_ptr().cast(),
                &mut required,
            )
        })?;
        require(
            required <= capacity && required as usize >= size_of::<TRACE_EVENT_INFO>(),
            "TDH metadata result invalid",
        )?;
        let info = unsafe { &*buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };
        require(
            info.DecodingSource == DecodingSourceWbem && same_guid(info.EventGuid, PROCESS_GUID),
            "TDH schema provenance differs",
        )?;
        require(
            info.EventDescriptor.Version == record.EventHeader.EventDescriptor.Version
                && info.EventDescriptor.Opcode == record.EventHeader.EventDescriptor.Opcode,
            "TDH schema event identity differs",
        )?;
        require(
            (1..=64).contains(&info.PropertyCount)
                && info.PropertyCount == info.TopLevelPropertyCount,
            "TDH property count exceeds flat schema budget",
        )?;
        let end = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
            + info.PropertyCount as usize * size_of::<EVENT_PROPERTY_INFO>();
        require(
            end <= required as usize,
            "TDH property array exceeds buffer",
        )?;
        let bytes =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), required as usize) };
        let entries = unsafe {
            std::slice::from_raw_parts(
                info.EventPropertyInfoArray.as_ptr(),
                info.PropertyCount as usize,
            )
        };
        let mut properties = BTreeMap::new();
        let mut layout = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            require(
                entry.Flags & (PropertyStruct | PropertyHasCustomSchema) == 0,
                "Unsupported structured process schema",
            )?;
            require(
                entry.NameOffset as usize >= end,
                "Schema property name overlaps metadata array",
            )?;
            let field = name(bytes, entry.NameOffset)?;
            require(
                properties.insert(field.clone(), *entry).is_none(),
                "Duplicate process property",
            )?;
            let native_type = unsafe { entry.Anonymous1.nonStructType };
            // Only canonical structural metadata enters this public hash. No
            // property values, addresses, provider message text or raw payload.
            layout.push((
                index,
                field,
                entry.Flags,
                native_type.InType,
                native_type.OutType,
                unsafe { entry.Anonymous2.count },
                unsafe { entry.Anonymous3.length },
            ));
        }
        let descriptor = record.EventHeader.EventDescriptor;
        let canonical = serde_json::to_vec(&(
            pointer_bits,
            descriptor.Version,
            descriptor.Opcode,
            info.DecodingSource,
            &layout,
        ))
        .map_err(|_| "Schema fingerprint failed")?;
        let schema_hash = athernex_endpoint_protocol::hash(&canonical);
        let pid = scalar32(
            record,
            &context,
            &properties,
            "ProcessId",
            &[TDH_INTYPE_UINT32, TDH_INTYPE_HEXINT32],
        )?;
        if record.EventHeader.EventDescriptor.Opcode == 11 {
            // Native62 established a separate one-property installed schema.
            // This run must additionally prove the exact native payload width.
            require(
                record.EventHeader.EventDescriptor.Version == 2
                    && info.PropertyCount == 1
                    && record.UserDataLength == 4,
                "TDH schema event identity differs",
            )?;
            return Ok(Report {
                pid,
                parent: None,
                session: None,
                exit: None,
                key: None,
                pointer_bits,
                property_count: info.PropertyCount,
                schema_hash,
            });
        }
        let parent = scalar32(
            record,
            &context,
            &properties,
            "ParentId",
            &[TDH_INTYPE_UINT32, TDH_INTYPE_HEXINT32],
        )?;
        let session = scalar32(
            record,
            &context,
            &properties,
            "SessionId",
            &[TDH_INTYPE_UINT32, TDH_INTYPE_HEXINT32],
        )?;
        let exit = scalar32(
            record,
            &context,
            &properties,
            "ExitStatus",
            &[TDH_INTYPE_INT32],
        )? as i32;
        let key_bytes = scalar_property(
            record,
            &context,
            &properties,
            "UniqueProcessKey",
            &[TDH_INTYPE_POINTER],
            pointer_bits as usize / 8,
        )?;
        let key = if pointer_bits == 32 {
            u32::from_le_bytes(
                key_bytes
                    .try_into()
                    .map_err(|_| "Invalid pointer scalar bytes")?,
            ) as u64
        } else {
            u64::from_le_bytes(
                key_bytes
                    .try_into()
                    .map_err(|_| "Invalid pointer scalar bytes")?,
            )
        };
        Ok(Report {
            pid,
            parent: Some(parent),
            session: Some(session),
            exit: Some(exit),
            key: Some(key),
            pointer_bits,
            property_count: info.PropertyCount,
            schema_hash,
        })
    })
}

#[test]
pub(super) fn property_names_and_scalar_metadata_are_bounded_and_typed() {
    let offset = size_of::<TRACE_EVENT_INFO>();
    let mut bytes = vec![0; offset];
    bytes.extend(
        "ProcessId"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes),
    );
    assert!(name(&bytes, offset as u32).is_ok_and(|value| value == "ProcessId"));
    assert!(name(&bytes, offset as u32 + 1).is_err());
    assert!(name(&bytes, bytes.len() as u32).is_err());
    bytes.truncate(bytes.len() - 2);
    assert!(name(&bytes, offset as u32).is_err());
    let mut info = EVENT_PROPERTY_INFO::default();
    info.Anonymous1.nonStructType.InType = TDH_INTYPE_UINT32 as u16;
    info.Anonymous2.count = 1;
    let mut fields = BTreeMap::from([("ProcessId".into(), info)]);
    assert!(scalar_type(&fields, "ProcessId", &[TDH_INTYPE_UINT32]).is_ok());
    assert!(scalar_type(&fields, "Missing", &[TDH_INTYPE_UINT32]).is_err());
    assert!(scalar_type(&fields, "ProcessId", &[TDH_INTYPE_POINTER]).is_err());
    fields.get_mut("ProcessId").unwrap().Flags = PropertyStruct;
    assert!(scalar_type(&fields, "ProcessId", &[TDH_INTYPE_UINT32]).is_err());
    fields.get_mut("ProcessId").unwrap().Flags = 0;
    fields.get_mut("ProcessId").unwrap().Anonymous2.count = 2;
    assert!(scalar_type(&fields, "ProcessId", &[TDH_INTYPE_UINT32]).is_err());
}

#[test]
fn property_diagnostics_use_only_fixed_requested_labels() {
    for (field, label) in [
        ("ProcessId", "process_id"),
        ("ParentId", "parent_id"),
        ("SessionId", "session_id"),
        ("ExitStatus", "exit_status"),
        ("UniqueProcessKey", "unique_process_key"),
    ] {
        assert_eq!(property_label(field), Some(label));
    }
    for field in [
        "",
        "PrivateNativeField",
        "ProcessId\nprivate",
        "ProcessId suffix",
        "processid",
    ] {
        assert!(property_label(field).is_none());
    }
}
