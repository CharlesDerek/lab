//! Installed TDH metadata and bytes are checked independently against owned records.
//! Microsoft TcpIp/UdpIp MOF pages define operation semantics, not an assumed layout.
mod template;
use super::{
    api,
    native::{same_guid, Original},
    require, Result,
};
use std::{
    collections::BTreeMap,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr::null_mut,
};
pub(super) use template::context_hypothesis_requires_exact_v2_template;
use windows_sys::Win32::{Foundation::ERROR_INSUFFICIENT_BUFFER, System::Diagnostics::Etw::*};

pub(super) struct Report {
    pub pid: u32,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub size: u32,
    // Original EVENT_HEADER architecture, not the selected property context.
    pub pointer_bits: u8,
    pub property_count: u32,
    pub schema_hash: String,
}
struct Metadata {
    context: TDH_CONTEXT,
    properties: BTreeMap<String, EVENT_PROPERTY_INFO>,
    order: Vec<String>,
    pointer_bits: u8,
    schema_hash: String,
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
fn property_raw(
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
    api("tdh_property_size", unsafe {
        TdhGetPropertySize(record, 1, context, 1, &descriptor, &mut bytes)
    })?;
    require(
        bytes as usize == expected && expected <= 16,
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
// Formatting has no side effects; only the failed native property path below
// publishes it. This is an attempted schema, never accepted controlled evidence.
fn attempt_line(
    record: &EVENT_RECORD,
    metadata: &Metadata,
    field: &str,
    expected: usize,
) -> Option<String> {
    let kind = super::kind_header(&record.EventHeader)?;
    let count = metadata.properties.len();
    let index = metadata.order.iter().position(|name| name == field)?;
    let info = metadata.properties.get(field)?;
    let flags = record.EventHeader.Flags as u32;
    let width = match flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER) {
        EVENT_HEADER_FLAG_32_BIT_HEADER => 32,
        EVENT_HEADER_FLAG_64_BIT_HEADER => 64,
        _ => return None,
    };
    if flags & EVENT_HEADER_FLAG_CLASSIC_HEADER == 0
        || record.EventHeader.TimeStamp <= 0
        || metadata.pointer_bits != width
        || !(1..=64).contains(&count)
        || metadata.order.len() != count
        || index >= count
        || !matches!(expected, 1 | 2 | 4 | 8 | 16)
        || !(1..=49_152).contains(&record.UserDataLength)
        || metadata.schema_hash.len() != 64
        || !metadata
            .schema_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let types = unsafe { info.Anonymous1.nonStructType };
    Some(format!(
        "ATHERNEX_NETWORK_SOURCE_SCHEMA_ATTEMPT={}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        kind.label,
        record.EventHeader.EventDescriptor.Version,
        metadata.pointer_bits,
        count,
        metadata.schema_hash,
        index,
        types.InType,
        types.OutType,
        expected,
        record.UserDataLength
    ))
}
fn property(
    record: &EVENT_RECORD,
    metadata: &Metadata,
    field: &str,
    expected: usize,
) -> Result<Vec<u8>> {
    let result = property_raw(record, &metadata.context, field, expected);
    if result.is_err() {
        if let Some(line) = attempt_line(record, metadata, field, expected) {
            println!("\n{line}");
        }
    }
    result
}
fn scalar_type(
    properties: &BTreeMap<String, EVENT_PROPERTY_INFO>,
    field: &str,
    expected: &[i32],
) -> Result<()> {
    let info = properties
        .get(field)
        .ok_or("Required network schema property missing")?;
    require(
        info.Flags & !(PropertyParamFixedCount | PropertyParamFixedLength | PropertyHasTags) == 0
            && unsafe { info.Anonymous2.count } == 1,
        "Network schema property is not scalar",
    )?;
    let input = unsafe { info.Anonymous1.nonStructType.InType } as i32;
    require(
        expected.contains(&input),
        "Network schema property type differs",
    )
}
fn scalar32(
    record: &EVENT_RECORD,
    metadata: &Metadata,
    field: &str,
    expected: &[i32],
) -> Result<u32> {
    scalar_type(&metadata.properties, field, expected)?;
    let value = property(record, metadata, field, 4)?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| "Invalid scalar bytes")?,
    ))
}
fn metadata(record: &EVENT_RECORD) -> Result<Metadata> {
    let flags = record.EventHeader.Flags as u32;
    require(
        flags & EVENT_HEADER_FLAG_CLASSIC_HEADER != 0
            && (same_guid(record.EventHeader.ProviderId, TcpIpGuid)
                || same_guid(record.EventHeader.ProviderId, UdpIpGuid))
            && record.EventHeader.TimeStamp > 0,
        "Invalid native network provenance",
    )?;
    let pointer_bits =
        match flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER) {
            EVENT_HEADER_FLAG_32_BIT_HEADER => 32,
            EVENT_HEADER_FLAG_64_BIT_HEADER => 64,
            _ => return Err("Native network pointer width is ambiguous"),
        };
    let context = TDH_CONTEXT {
        ParameterValue: pointer_bits as u64 / 8,
        ParameterType: TDH_CONTEXT_POINTERSIZE,
        ParameterSize: 0,
    };
    let mut required = 0;
    let code = unsafe { TdhGetEventInformation(record, 1, &context, null_mut(), &mut required) };
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
        info.DecodingSource == DecodingSourceWbem
            && same_guid(info.EventGuid, record.EventHeader.ProviderId),
        "TDH schema provenance differs",
    )?;
    require(
        info.EventDescriptor.Version == record.EventHeader.EventDescriptor.Version
            && info.EventDescriptor.Opcode == record.EventHeader.EventDescriptor.Opcode,
        "TDH schema event identity differs",
    )?;
    require(
        (1..=64).contains(&info.PropertyCount) && info.PropertyCount == info.TopLevelPropertyCount,
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
    let mut order = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        require(
            entry.Flags & (PropertyStruct | PropertyHasCustomSchema) == 0,
            "Unsupported structured network schema",
        )?;
        require(
            entry.NameOffset as usize >= end,
            "Schema property name overlaps metadata array",
        )?;
        let field = name(bytes, entry.NameOffset)?;
        require(
            properties.insert(field.clone(), *entry).is_none(),
            "Duplicate network property",
        )?;
        let native_type = unsafe { entry.Anonymous1.nonStructType };
        // Only canonical structural metadata enters this public hash. No
        // property values, addresses, provider message text or raw payload.
        order.push(field.clone());
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
    let fingerprint = |context_bytes| -> Result<String> {
        let canonical = serde_json::to_vec(&(
            ("event_header_pointer_bits", pointer_bits),
            ("tdh_property_context_bytes", context_bytes),
            descriptor.Version,
            descriptor.Opcode,
            info.DecodingSource,
            &layout,
        ))
        .map_err(|_| "Schema fingerprint failed")?;
        Ok(athernex_endpoint_protocol::hash(&canonical))
    };
    let mut metadata = Metadata {
        context,
        properties,
        order,
        pointer_bits,
        schema_hash: fingerprint(context.ParameterValue)?,
    };
    // Select the source-only hypothesis only after exact v2 template metadata
    // and length validation, before any property call. The header is untouched.
    match template::property_context_bytes(record, &metadata.properties, &metadata.order) {
        Ok(bytes) => {
            metadata.context.ParameterValue = bytes;
            metadata.schema_hash = fingerprint(bytes)?;
        }
        Err(refusal) => {
            if let Some((field, expected)) = refusal.field {
                if let Some(line) = attempt_line(record, &metadata, field, expected) {
                    println!("\n{line}");
                }
            }
            return Err("tdh_schema");
        }
    }
    Ok(metadata)
}

fn typed(
    properties: &BTreeMap<String, EVENT_PROPERTY_INFO>,
    field: &str,
    input: i32,
    output: i32,
) -> Result<()> {
    scalar_type(properties, field, &[input])?;
    let info = properties.get(field).ok_or("tdh_property")?;
    require(
        unsafe { info.Anonymous1.nonStructType.OutType } as i32 == output,
        "tdh_property",
    )
}
fn socket(
    record: &EVENT_RECORD,
    metadata: &Metadata,
    ipv6: bool,
    address: &str,
    port: &str,
) -> Result<SocketAddr> {
    let input = if ipv6 {
        TDH_INTYPE_BINARY
    } else {
        TDH_INTYPE_UINT32
    };
    let output = if ipv6 {
        TDH_OUTTYPE_IPV6
    } else {
        TDH_OUTTYPE_IPV4
    };
    typed(&metadata.properties, address, input, output)?;
    typed(
        &metadata.properties,
        port,
        TDH_INTYPE_UINT16,
        TDH_OUTTYPE_PORT,
    )?;
    let bytes = property(record, metadata, address, if ipv6 { 16 } else { 4 })?;
    let ip = if ipv6 {
        IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| "tdh_property")?,
        ))
    } else {
        IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| "tdh_property")?,
        ))
    };
    let bytes = property(record, metadata, port, 2)?;
    let port = u16::from_be_bytes(bytes.try_into().map_err(|_| "tdh_property")?);
    Ok(SocketAddr::new(ip, port))
}

// Check every field, not just the controlled tuple: TDH values must match a
// complete sequential partition of the original packed MOF payload. Metadata
// supplies types; the exact-template hypothesis supplies connid's context width.
fn layout(record: &EVENT_RECORD, original: &Original, metadata: &Metadata) -> Result<()> {
    let mut offset = 0usize;
    for field in &metadata.order {
        let info = metadata.properties.get(field).ok_or("tdh_schema")?;
        let input = unsafe { info.Anonymous1.nonStructType.InType } as i32;
        scalar_type(&metadata.properties, field, &[input])?;
        let size = match input {
            TDH_INTYPE_UINT8 | TDH_INTYPE_INT8 => 1,
            TDH_INTYPE_UINT16 | TDH_INTYPE_INT16 => 2,
            TDH_INTYPE_UINT32 | TDH_INTYPE_INT32 | TDH_INTYPE_HEXINT32 => 4,
            TDH_INTYPE_UINT64 | TDH_INTYPE_INT64 | TDH_INTYPE_HEXINT64 => 8,
            TDH_INTYPE_POINTER => metadata.context.ParameterValue as usize,
            TDH_INTYPE_BINARY
                if unsafe { info.Anonymous1.nonStructType.OutType } as i32 == TDH_OUTTYPE_IPV6 =>
            {
                16
            }
            _ => return Err("tdh_schema"),
        };
        let value = property(record, metadata, field, size)?;
        let end = offset.checked_add(size).ok_or("tdh_schema")?;
        require(
            original.data().get(offset..end) == Some(value.as_slice()),
            "tdh_schema",
        )?;
        offset = end;
    }
    require(offset == original.data().len(), "tdh_schema")
}

pub(super) fn decode(original: &Original, ipv6: bool) -> Result<Report> {
    original.with_record(|record| {
        let metadata = metadata(record)?;
        layout(record, original, &metadata)?;
        let pid = scalar32(record, &metadata, "PID", &[TDH_INTYPE_UINT32])?;
        let size = scalar32(record, &metadata, "size", &[TDH_INTYPE_UINT32])?;
        let source = socket(record, &metadata, ipv6, "saddr", "sport")?;
        let destination = socket(record, &metadata, ipv6, "daddr", "dport")?;
        // Pointer-qualified connid is retained as an original field only. It
        // never becomes a process incarnation or globally stable connection ID.
        scalar_type(&metadata.properties, "connid", &[TDH_INTYPE_POINTER])?;
        Ok(Report {
            pid,
            source,
            destination,
            size,
            pointer_bits: metadata.pointer_bits,
            property_count: metadata.properties.len() as u32,
            schema_hash: metadata.schema_hash,
        })
    })
}

#[test]
pub(super) fn property_names_and_scalar_metadata_are_bounded_and_typed() {
    let offset = size_of::<TRACE_EVENT_INFO>();
    let mut bytes = vec![0; offset];
    bytes.extend(
        "NetworkId"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes),
    );
    assert!(name(&bytes, offset as u32).is_ok_and(|value| value == "NetworkId"));
    assert!(name(&bytes, offset as u32 + 1).is_err());
    assert!(name(&bytes, bytes.len() as u32).is_err());
    bytes.truncate(bytes.len() - 2);
    assert!(name(&bytes, offset as u32).is_err());
    let mut info = EVENT_PROPERTY_INFO::default();
    info.Anonymous1.nonStructType.InType = TDH_INTYPE_UINT32 as u16;
    info.Anonymous2.count = 1;
    let mut fields = BTreeMap::from([("NetworkId".into(), info)]);
    assert!(scalar_type(&fields, "NetworkId", &[TDH_INTYPE_UINT32]).is_ok());
    assert!(scalar_type(&fields, "Missing", &[TDH_INTYPE_UINT32]).is_err());
    assert!(scalar_type(&fields, "NetworkId", &[TDH_INTYPE_POINTER]).is_err());
    fields.get_mut("NetworkId").unwrap().Flags = PropertyStruct;
    assert!(scalar_type(&fields, "NetworkId", &[TDH_INTYPE_UINT32]).is_err());
    fields.get_mut("NetworkId").unwrap().Flags = 0;
    fields.get_mut("NetworkId").unwrap().Anonymous2.count = 2;
    assert!(scalar_type(&fields, "NetworkId", &[TDH_INTYPE_UINT32]).is_err());
}

#[test]
pub(super) fn failed_property_context_never_contains_private_values() {
    let mut record = EVENT_RECORD::default();
    record.EventHeader.ProviderId = TcpIpGuid;
    record.EventHeader.EventDescriptor.Opcode = 12;
    record.EventHeader.EventDescriptor.Version = 2;
    record.EventHeader.Flags =
        (EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER) as u16;
    record.EventHeader.TimeStamp = 1;
    record.UserDataLength = 48;
    let mut info = EVENT_PROPERTY_INFO::default();
    info.Anonymous1.nonStructType.InType = TDH_INTYPE_UINT32 as u16;
    info.Anonymous2.count = 1;
    // Deliberately private-looking metadata names are never projected.
    let field = "private_field_name";
    let mut metadata = Metadata {
        context: TDH_CONTEXT::default(),
        properties: BTreeMap::from([(field.into(), info)]),
        order: vec![field.into()],
        pointer_bits: 64,
        schema_hash: "0".repeat(64),
    };
    let line = attempt_line(&record, &metadata, field, 4).expect("Synthetic diagnostic absent");
    assert!(
        line == format!(
            "ATHERNEX_NETWORK_SOURCE_SCHEMA_ATTEMPT=tcp4_connect:2:64:1:{}:0:8:0:4:48",
            "0".repeat(64)
        )
    );
    assert!(!line.contains(field));
    assert!(attempt_line(&record, &metadata, "missing", 4).is_none());
    assert!(attempt_line(&record, &metadata, field, 3).is_none());
    metadata.schema_hash = "private_value".into();
    assert!(attempt_line(&record, &metadata, field, 4).is_none());
    metadata.schema_hash = "0".repeat(64);
    metadata.order.push(field.into());
    assert!(attempt_line(&record, &metadata, field, 4).is_none());
    metadata.order.pop();
    for length in [0, 49_153, u16::MAX] {
        record.UserDataLength = length;
        assert!(attempt_line(&record, &metadata, field, 4).is_none());
    }
    record.UserDataLength = 48;
    record.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER as u16;
    assert!(attempt_line(&record, &metadata, field, 4).is_none());
    record.EventHeader.Flags =
        (EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER) as u16;
    record.EventHeader.EventDescriptor.Opcode = 255;
    assert!(attempt_line(&record, &metadata, field, 4).is_none());
}
