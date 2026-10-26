//! Sequential native formatting is independently checked against every raw field.
//! https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty
use super::*;

const MAX_TEXT_BYTES: u32 = 512;

fn field_size(info: &EVENT_PROPERTY_INFO) -> Result<usize> {
    let types = unsafe { info.Anonymous1.nonStructType };
    match (types.InType as i32, types.OutType as i32) {
        (TDH_INTYPE_UINT32, TDH_OUTTYPE_NULL | TDH_OUTTYPE_IPV4) => Ok(4),
        (TDH_INTYPE_UINT16, TDH_OUTTYPE_NULL | TDH_OUTTYPE_PORT)
        | (TDH_INTYPE_INT16, TDH_OUTTYPE_NULL) => Ok(2),
        (TDH_INTYPE_POINTER, TDH_OUTTYPE_NULL) => Ok(4),
        (TDH_INTYPE_BINARY, TDH_OUTTYPE_IPV6) => Ok(16),
        _ => Err("tdh_schema"),
    }
}

fn property_length(info: &EVENT_PROPERTY_INFO, expected: usize) -> Result<u16> {
    let types = unsafe { info.Anonymous1.nonStructType };
    let length = unsafe { info.Anonymous3.length };
    require(field_size(info)? == expected, "tdh_schema")?;
    if types.InType as i32 == TDH_INTYPE_BINARY
        && types.OutType as i32 == TDH_OUTTYPE_IPV6
        && length == 0
    {
        // Microsoft's documented exception is specifically Binary/IPv6 with
        // zero length and no explicit/parameterized length. No other override.
        require(
            info.Flags & (PropertyParamLength | PropertyParamFixedLength) == 0,
            "tdh_schema",
        )?;
        return Ok(16);
    }
    Ok(length)
}

fn text_capacity(bytes: u32) -> Result<usize> {
    require(
        (2..=MAX_TEXT_BYTES).contains(&bytes) && bytes.is_multiple_of(2),
        "tdh_property",
    )?;
    Ok(bytes as usize / 2)
}
fn probe_capacity(code: u32, bytes: u32) -> Result<usize> {
    require(
        code == 0 || code == ERROR_INSUFFICIENT_BUFFER,
        "tdh_property",
    )?;
    text_capacity(bytes)
}
fn text(buffer: &[u16], used_bytes: u32) -> Result<String> {
    let units = text_capacity(used_bytes)?;
    let value = buffer.get(..units).ok_or("tdh_property")?;
    require(
        value.last() == Some(&0) && !value[..units - 1].contains(&0),
        "tdh_property",
    )?;
    let value = String::from_utf16(&value[..units - 1]).map_err(|_| "tdh_property")?;
    require(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic()),
        "tdh_property",
    )?;
    Ok(value)
}
fn unsigned(value: &str) -> Result<u64> {
    require(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "tdh_property",
    )?;
    value.parse().map_err(|_| "tdh_property")
}
fn signed(value: &str) -> Result<i64> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    require(
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()),
        "tdh_property",
    )?;
    value.parse().map_err(|_| "tdh_property")
}
fn hexadecimal(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    require(
        (1..=16).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "tdh_property",
    )?;
    u64::from_str_radix(digits, 16).map_err(|_| "tdh_property")
}

fn equal_raw(info: &EVENT_PROPERTY_INFO, raw: &[u8], formatted: &str) -> Result<()> {
    require(raw.len() == field_size(info)?, "tdh_property")?;
    let types = unsafe { info.Anonymous1.nonStructType };
    let equal = match (types.InType as i32, types.OutType as i32) {
        (TDH_INTYPE_UINT32, TDH_OUTTYPE_NULL) => {
            u64::from(u32::from_le_bytes(
                raw.try_into().map_err(|_| "tdh_property")?,
            )) == unsigned(formatted)?
        }
        (TDH_INTYPE_UINT16, TDH_OUTTYPE_NULL) => {
            u64::from(u16::from_le_bytes(
                raw.try_into().map_err(|_| "tdh_property")?,
            )) == unsigned(formatted)?
        }
        (TDH_INTYPE_INT16, TDH_OUTTYPE_NULL) => {
            i64::from(i16::from_le_bytes(
                raw.try_into().map_err(|_| "tdh_property")?,
            )) == signed(formatted)?
        }
        (TDH_INTYPE_UINT16, TDH_OUTTYPE_PORT) => {
            u64::from(u16::from_be_bytes(
                raw.try_into().map_err(|_| "tdh_property")?,
            )) == unsigned(formatted)?
        }
        (TDH_INTYPE_UINT32, TDH_OUTTYPE_IPV4) => {
            let raw = Ipv4Addr::from(<[u8; 4]>::try_from(raw).map_err(|_| "tdh_property")?);
            raw == formatted.parse::<Ipv4Addr>().map_err(|_| "tdh_property")?
        }
        (TDH_INTYPE_BINARY, TDH_OUTTYPE_IPV6) => {
            let raw = Ipv6Addr::from(<[u8; 16]>::try_from(raw).map_err(|_| "tdh_property")?);
            raw == formatted.parse::<Ipv6Addr>().map_err(|_| "tdh_property")?
        }
        (TDH_INTYPE_POINTER, TDH_OUTTYPE_NULL) => {
            // This is only the opaque connid in the exact v2 template. Its
            // hexadecimal display never becomes an address or stable identity.
            u64::from(u32::from_le_bytes(
                raw.try_into().map_err(|_| "tdh_property")?,
            )) == hexadecimal(formatted)?
        }
        _ => return Err("tdh_schema"),
    };
    require(equal, "tdh_property")
}

fn consumed_end(total: usize, offset: usize, expected: usize, consumed: u16) -> Result<usize> {
    require(
        expected > 0 && usize::from(consumed) == expected,
        "tdh_property",
    )?;
    let end = offset.checked_add(expected).ok_or("tdh_property")?;
    require(end <= total, "tdh_property")?;
    Ok(end)
}

fn property(
    metadata: &Metadata,
    info: &EVENT_PROPERTY_INFO,
    remaining: &[u8],
    expected: usize,
) -> Result<(String, u16)> {
    require(
        metadata.context.ParameterValue == 4
            && metadata.native_info_bytes >= size_of::<TRACE_EVENT_INFO>()
            && metadata.native_info_bytes <= metadata.native_info.len() * size_of::<u64>()
            && remaining.len() >= expected
            && remaining.len() <= 49_152,
        "tdh_schema",
    )?;
    let types = unsafe { info.Anonymous1.nonStructType };
    let length = property_length(info, expected)?;
    let mut required = 0;
    let mut consumed = 0;
    // The installed metadata allocation and exact original bytes stay alive
    // across both synchronous calls. No fields in either allocation are edited.
    let code = unsafe {
        TdhFormatProperty(
            metadata.native_info.as_ptr().cast(),
            std::ptr::null(),
            4,
            types.InType,
            types.OutType,
            length,
            remaining.len() as u16,
            remaining.as_ptr(),
            &mut required,
            null_mut(),
            &mut consumed,
        )
    };
    if code != 0 && code != ERROR_INSUFFICIENT_BUFFER {
        api("tdh_format_property", code)?;
    }
    let mut buffer = vec![0u16; probe_capacity(code, required)?];
    let capacity = required;
    consumed = 0;
    api("tdh_format_property", unsafe {
        TdhFormatProperty(
            metadata.native_info.as_ptr().cast(),
            std::ptr::null(),
            4,
            types.InType,
            types.OutType,
            length,
            remaining.len() as u16,
            remaining.as_ptr(),
            &mut required,
            buffer.as_mut_ptr(),
            &mut consumed,
        )
    })?;
    require(required <= capacity, "tdh_property")?;
    Ok((text(&buffer, required)?, consumed))
}

pub(super) fn layout(
    record: &EVENT_RECORD,
    original: &Original,
    metadata: &Metadata,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let raw = original.data();
    require(raw.len() == record.UserDataLength as usize, "tdh_schema")?;
    let mut offset = 0usize;
    let mut checked = BTreeMap::new();
    for field in &metadata.order {
        let info = metadata.properties.get(field).ok_or("tdh_schema")?;
        let expected = field_size(info)?;
        let result: Result<()> = (|| {
            let remaining = raw.get(offset..).ok_or("tdh_property")?;
            let (formatted, consumed) = property(metadata, info, remaining, expected)?;
            let end = consumed_end(raw.len(), offset, expected, consumed)?;
            let bytes = raw.get(offset..end).ok_or("tdh_property")?;
            equal_raw(info, bytes, &formatted)?;
            require(
                checked.insert(field.clone(), bytes.to_vec()).is_none(),
                "tdh_schema",
            )?;
            offset = end;
            Ok(())
        })();
        if result.is_err() {
            if let Some(line) = attempt_line(record, metadata, field, expected) {
                println!("\n{line}");
            }
        }
        result?;
    }
    require(offset == raw.len(), "tdh_schema")?;
    Ok(checked)
}

#[test]
pub(in super::super) fn formatter_values_and_bounds_are_checked() {
    fn info(input: i32, output: i32) -> EVENT_PROPERTY_INFO {
        let mut info = EVENT_PROPERTY_INFO::default();
        info.Anonymous1.nonStructType.InType = input as u16;
        info.Anonymous1.nonStructType.OutType = output as u16;
        info
    }
    let uint32 = info(TDH_INTYPE_UINT32, TDH_OUTTYPE_NULL);
    let uint16 = info(TDH_INTYPE_UINT16, TDH_OUTTYPE_NULL);
    let int16 = info(TDH_INTYPE_INT16, TDH_OUTTYPE_NULL);
    let port = info(TDH_INTYPE_UINT16, TDH_OUTTYPE_PORT);
    let ipv4 = info(TDH_INTYPE_UINT32, TDH_OUTTYPE_IPV4);
    let mut ipv6 = info(TDH_INTYPE_BINARY, TDH_OUTTYPE_IPV6);
    let mut pointer = info(TDH_INTYPE_POINTER, TDH_OUTTYPE_NULL);
    for value in [0, 1, u32::MAX] {
        assert!(equal_raw(&uint32, &value.to_le_bytes(), &value.to_string()).is_ok());
    }
    for value in [0, 1, u16::MAX] {
        assert!(equal_raw(&uint16, &value.to_le_bytes(), &value.to_string()).is_ok());
        assert!(equal_raw(&port, &value.to_be_bytes(), &value.to_string()).is_ok());
    }
    for value in [i16::MIN, -1, 0, 1, i16::MAX] {
        assert!(equal_raw(&int16, &value.to_le_bytes(), &value.to_string()).is_ok());
    }
    assert!(equal_raw(&int16, &(-1i16).to_le_bytes(), "65535").is_err());
    assert!(equal_raw(&port, &443u16.to_le_bytes(), "443").is_err());
    assert!(equal_raw(&ipv4, &[203, 0, 113, 8], "203.0.113.8").is_ok());
    assert!(equal_raw(&ipv4, &[203, 0, 113, 8], "8.113.0.203").is_err());
    let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    assert!(equal_raw(&ipv6, &address.octets(), "2001:db8::1").is_ok());
    assert!(equal_raw(&ipv6, &address.octets(), "2001:db8::2").is_err());
    for rendered in ["0x00ABCDEF", "0Xabcdef", "0000000000abcdef"] {
        assert!(equal_raw(&pointer, &0xabcdefu32.to_le_bytes(), rendered).is_ok());
    }
    for rendered in ["0x100000000", "-1", "0x", "g", "0xabcdef extra"] {
        assert!(equal_raw(&pointer, &0xabcdefu32.to_le_bytes(), rendered).is_err());
    }
    for rendered in [
        "+1",
        "-1",
        " 1",
        "1 ",
        "1\0",
        "1.0",
        "18446744073709551616",
        "１",
    ] {
        assert!(equal_raw(&uint32, &1u32.to_le_bytes(), rendered).is_err());
    }
    assert!(equal_raw(&uint32, &[1, 0, 0], "1").is_err());
    assert!(equal_raw(&info(TDH_INTYPE_UNICODESTRING, TDH_OUTTYPE_NULL), &[0], "0").is_err());
    assert!(property_length(&ipv6, 16).is_ok_and(|length| length == 16));
    ipv6.Flags = PropertyParamFixedLength;
    assert!(property_length(&ipv6, 16).is_err());
    ipv6.Flags = PropertyParamLength;
    assert!(property_length(&ipv6, 16).is_err());
    ipv6.Flags = 0;
    ipv6.Anonymous3.length = 16;
    assert!(property_length(&ipv6, 16).is_ok_and(|length| length == 16));
    pointer.Anonymous3.length = 8;
    // PointerSize is the explicit wire4 hypothesis; the native Length argument
    // remains unchanged. Only documented zero-length IPv6 receives an override.
    assert!(property_length(&pointer, 4).is_ok_and(|length| length == 8));
    assert!(unsafe { pointer.Anonymous3.length } == 8);
    assert!(property_length(&pointer, 8).is_err());
    assert!(consumed_end(8, 0, 4, 4).is_ok_and(|end| end == 4));
    assert!(consumed_end(8, 4, 4, 4).is_ok_and(|end| end == 8));
    for (total, offset, expected, consumed) in [
        (8, 0, 4, 0),
        (8, 0, 4, 3),
        (8, 0, 4, 8),
        (8, 6, 4, 4),
        (8, 0, 0, 0),
        (usize::MAX, usize::MAX, 4, 4),
    ] {
        assert!(consumed_end(total, offset, expected, consumed).is_err());
    }
    for bytes in [0, 1, 3, MAX_TEXT_BYTES + 2, u32::MAX] {
        assert!(text_capacity(bytes).is_err());
        for code in [0, ERROR_INSUFFICIENT_BUFFER] {
            assert!(probe_capacity(code, bytes).is_err());
        }
    }
    for code in [0, ERROR_INSUFFICIENT_BUFFER] {
        assert!(probe_capacity(code, 4).is_ok_and(|units| units == 2));
        assert!(probe_capacity(code, MAX_TEXT_BYTES)
            .is_ok_and(|units| units == MAX_TEXT_BYTES as usize / 2));
    }
    assert!(probe_capacity(5, 4).is_err());
    assert!(text(&[b'1' as u16, 0], 4).is_ok_and(|value| value == "1"));
    for (buffer, used) in [
        (vec![0], 2),
        (vec![49], 2),
        (vec![49, 0, 50, 0], 8),
        (vec![0xd800, 0], 4),
        (vec![49, 0], 6),
        (vec![49, 0], 3),
        (vec![32, 0], 4),
    ] {
        assert!(text(&buffer, used).is_err());
    }
}
