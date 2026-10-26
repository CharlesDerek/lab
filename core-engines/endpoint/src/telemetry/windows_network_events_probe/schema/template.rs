//! Test-only wire-width hypothesis, not a production network parser.
//!
//! Microsoft's pinned manifest declares connid as UInt32 in these v2 templates:
//! https://github.com/microsoft/perfview/blob/4ae8d85b25043a21e6cb65bda340a620d691ac62/src/TraceEvent/Parsers/kerneltraceeventparser.man.xml
//! Its handwritten decoder instead uses header pointer width. The native source
//! probe observed the connect template's 44-byte payload with a 64-bit header
//! and TDH POINTER metadata. Only an exact template match selects the four-byte
//! property context for this experiment. Native TDH/raw/controlled-flow checks
//! must still independently succeed; no failed-call retry or inferred remainder.
use super::*;

pub(super) struct Refusal {
    // A fixed template field may identify a bounded diagnostic; no values.
    pub field: Option<(&'static str, usize)>,
}
impl From<&'static str> for Refusal {
    fn from(_: &'static str) -> Self {
        Self { field: None }
    }
}

struct Field {
    name: &'static str,
    input: i32,
    output: i32,
    bytes: u16,
}
impl Field {
    fn scalar(name: &'static str, input: i32, bytes: u16) -> Self {
        Self {
            name,
            input,
            output: TDH_OUTTYPE_NULL,
            bytes,
        }
    }
}

fn expected(record: &EVENT_RECORD) -> Result<Vec<Field>> {
    let header = &record.EventHeader;
    let flags = header.Flags as u32;
    require(
        flags & EVENT_HEADER_FLAG_CLASSIC_HEADER != 0
            && matches!(
                flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER),
                EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER
            )
            && header.EventDescriptor.Version == 2,
        "tdh_schema",
    )?;
    let tcp = same_guid(header.ProviderId, TcpIpGuid);
    require(tcp || same_guid(header.ProviderId, UdpIpGuid), "tdh_schema")?;
    // These are only the existing fourteen controlled source-proof kinds.
    let (ipv6, send, connect) = match (tcp, header.EventDescriptor.Opcode) {
        (true, 10) => (false, true, false),
        (true, 11 | 13) | (false, 10 | 11) => (false, false, false),
        (true, 12 | 15) => (false, false, true),
        (true, 26) => (true, true, false),
        (true, 27 | 29) | (false, 26 | 27) => (true, false, false),
        (true, 28 | 31) => (true, false, true),
        _ => return Err("tdh_schema"),
    };
    let mut fields = vec![
        Field::scalar("PID", TDH_INTYPE_UINT32, 4),
        Field::scalar("size", TDH_INTYPE_UINT32, 4),
    ];
    for name in ["daddr", "saddr"] {
        fields.push(Field {
            name,
            input: if ipv6 {
                TDH_INTYPE_BINARY
            } else {
                TDH_INTYPE_UINT32
            },
            output: if ipv6 {
                TDH_OUTTYPE_IPV6
            } else {
                TDH_OUTTYPE_IPV4
            },
            bytes: if ipv6 { 16 } else { 4 },
        });
    }
    for name in ["dport", "sport"] {
        fields.push(Field {
            name,
            input: TDH_INTYPE_UINT16,
            output: TDH_OUTTYPE_PORT,
            bytes: 2,
        });
    }
    if send {
        for name in ["startime", "endtime"] {
            fields.push(Field::scalar(name, TDH_INTYPE_UINT32, 4));
        }
    }
    if connect {
        for name in ["mss", "sackopt", "tsopt", "wsopt"] {
            fields.push(Field::scalar(name, TDH_INTYPE_UINT16, 2));
        }
        fields.push(Field::scalar("rcvwin", TDH_INTYPE_UINT32, 4));
        for name in ["rcvwinscale", "sndwinscale"] {
            fields.push(Field::scalar(name, TDH_INTYPE_INT16, 2));
        }
    }
    fields.push(Field::scalar("seqnum", TDH_INTYPE_UINT32, 4));
    // Preserve the installed POINTER metadata; context controls its wire width.
    fields.push(Field::scalar("connid", TDH_INTYPE_POINTER, 4));
    Ok(fields)
}

pub(super) fn property_context_bytes(
    record: &EVENT_RECORD,
    properties: &BTreeMap<String, EVENT_PROPERTY_INFO>,
    order: &[String],
) -> std::result::Result<u64, Refusal> {
    let fields = expected(record)?;
    require(
        properties.len() == fields.len() && order.len() == fields.len(),
        "tdh_schema",
    )?;
    let mut bytes = 0u16;
    // Bind the complete template before any field-qualified diagnostic. An
    // earlier scalar error must not conceal a later name/order/length mismatch.
    for (field, name) in fields.iter().zip(order) {
        require(
            name == field.name && properties.contains_key(name),
            "tdh_schema",
        )?;
        bytes = bytes.checked_add(field.bytes).ok_or("tdh_schema")?;
    }
    require(record.UserDataLength == bytes, "tdh_schema")?;
    for (field, name) in fields.iter().zip(order) {
        let info = properties.get(name).ok_or("tdh_schema")?;
        let types = unsafe { info.Anonymous1.nonStructType };
        let length = unsafe { info.Anonymous3.length };
        if !(info.Flags & !(PropertyParamFixedCount | PropertyParamFixedLength | PropertyHasTags)
            == 0
            && unsafe { info.Anonymous2.count } == 1
            && types.InType as i32 == field.input
            && types.OutType as i32 == field.output
            && (length == field.bytes
                || (length == 0 && info.Flags & PropertyParamFixedLength == 0)))
        {
            return Err(Refusal {
                field: Some((field.name, field.bytes as usize)),
            });
        }
    }
    Ok(4)
}

#[test]
pub(in super::super) fn context_hypothesis_requires_exact_v2_template() {
    fn sample(
        tcp: bool,
        opcode: u8,
        bits: u32,
    ) -> (
        EVENT_RECORD,
        BTreeMap<String, EVENT_PROPERTY_INFO>,
        Vec<String>,
    ) {
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProviderId = if tcp { TcpIpGuid } else { UdpIpGuid };
        record.EventHeader.Flags = (EVENT_HEADER_FLAG_CLASSIC_HEADER | bits) as u16;
        record.EventHeader.EventDescriptor.Version = 2;
        record.EventHeader.EventDescriptor.Opcode = opcode;
        let fields = expected(&record).expect("Synthetic template absent");
        let mut properties = BTreeMap::new();
        let mut order = Vec::new();
        for field in fields {
            let mut info = EVENT_PROPERTY_INFO::default();
            info.Anonymous1.nonStructType.InType = field.input as u16;
            info.Anonymous1.nonStructType.OutType = field.output as u16;
            info.Anonymous2.count = 1;
            record.UserDataLength += field.bytes;
            order.push(field.name.to_owned());
            properties.insert(field.name.to_owned(), info);
        }
        (record, properties, order)
    }
    // Explicit manifest counts/lengths independently check the template builder.
    for (tcp, opcode, count, length) in [
        (true, 10, 10, 36),
        (true, 11, 8, 28),
        (true, 12, 15, 44),
        (true, 13, 8, 28),
        (true, 15, 15, 44),
        (true, 26, 10, 60),
        (true, 27, 8, 52),
        (true, 28, 15, 68),
        (true, 29, 8, 52),
        (true, 31, 15, 68),
        (false, 10, 8, 28),
        (false, 11, 8, 28),
        (false, 26, 8, 52),
        (false, 27, 8, 52),
    ] {
        for bits in [
            EVENT_HEADER_FLAG_32_BIT_HEADER,
            EVENT_HEADER_FLAG_64_BIT_HEADER,
        ] {
            let (record, properties, order) = sample(tcp, opcode, bits);
            let original_flags = record.EventHeader.Flags;
            assert!(properties.len() == count && record.UserDataLength == length);
            assert!(
                property_context_bytes(&record, &properties, &order).is_ok_and(|size| size == 4)
            );
            assert!(record.EventHeader.Flags == original_flags);
        }
    }
    let (mut record, properties, order) = sample(true, 12, EVENT_HEADER_FLAG_64_BIT_HEADER);
    // Mutations are independent refusal controls, with no native calls/output.
    assert!(record.UserDataLength == 44 && properties.len() == 15);
    for version in 0..=u8::MAX {
        record.EventHeader.EventDescriptor.Version = version;
        assert!(property_context_bytes(&record, &properties, &order).is_ok() == (version == 2));
    }
    record.EventHeader.EventDescriptor.Version = 2;
    for opcode in [0, 10, 11, 13, 14, 16, 18, 26, 28, 255] {
        record.EventHeader.EventDescriptor.Opcode = opcode;
        assert!(property_context_bytes(&record, &properties, &order).is_err());
    }
    record.EventHeader.EventDescriptor.Opcode = 12;
    for provider in [UdpIpGuid, windows_sys::core::GUID::from_u128(0)] {
        record.EventHeader.ProviderId = provider;
        assert!(property_context_bytes(&record, &properties, &order).is_err());
    }
    record.EventHeader.ProviderId = TcpIpGuid;
    for flags in [
        0,
        EVENT_HEADER_FLAG_CLASSIC_HEADER,
        EVENT_HEADER_FLAG_64_BIT_HEADER,
        EVENT_HEADER_FLAG_CLASSIC_HEADER
            | EVENT_HEADER_FLAG_32_BIT_HEADER
            | EVENT_HEADER_FLAG_64_BIT_HEADER,
    ] {
        record.EventHeader.Flags = flags as u16;
        assert!(property_context_bytes(&record, &properties, &order).is_err());
    }
    record.EventHeader.Flags =
        (EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER) as u16;
    for length in [0, 43, 45, 48, u16::MAX] {
        record.UserDataLength = length;
        assert!(property_context_bytes(&record, &properties, &order).is_err());
    }
    record.UserDataLength = 44;
    let mut changed_order = order.clone();
    changed_order.swap(0, 1);
    assert!(property_context_bytes(&record, &properties, &changed_order).is_err());
    changed_order = order.clone();
    changed_order[0] = "pid".into();
    assert!(property_context_bytes(&record, &properties, &changed_order).is_err());
    changed_order = order.clone();
    changed_order.pop();
    assert!(property_context_bytes(&record, &properties, &changed_order).is_err());
    let mut changed = properties.clone();
    changed.remove("PID");
    assert!(property_context_bytes(&record, &changed, &order).is_err());
    changed = properties.clone();
    changed.insert("extra".into(), EVENT_PROPERTY_INFO::default());
    assert!(property_context_bytes(&record, &changed, &order).is_err());
    for field in &order {
        changed = properties.clone();
        changed
            .get_mut(field)
            .unwrap()
            .Anonymous1
            .nonStructType
            .InType = TDH_INTYPE_POINTER as u16;
        if field == "connid" {
            changed
                .get_mut(field)
                .unwrap()
                .Anonymous1
                .nonStructType
                .InType = TDH_INTYPE_UINT32 as u16;
        }
        assert!(property_context_bytes(&record, &changed, &order).is_err());
        changed = properties.clone();
        changed
            .get_mut(field)
            .unwrap()
            .Anonymous1
            .nonStructType
            .OutType = TDH_OUTTYPE_STRING as u16;
        assert!(property_context_bytes(&record, &changed, &order).is_err());
        for count in [0, 2, u16::MAX] {
            changed = properties.clone();
            changed.get_mut(field).unwrap().Anonymous2.count = count;
            assert!(property_context_bytes(&record, &changed, &order).is_err());
        }
        for flags in [
            PropertyStruct,
            PropertyParamCount,
            PropertyParamLength,
            PropertyHasCustomSchema,
        ] {
            changed = properties.clone();
            changed.get_mut(field).unwrap().Flags = flags;
            assert!(property_context_bytes(&record, &changed, &order).is_err());
        }
        changed = properties.clone();
        changed.get_mut(field).unwrap().Anonymous3.length = 3;
        assert!(property_context_bytes(&record, &changed, &order).is_err());
        changed = properties.clone();
        changed.get_mut(field).unwrap().Flags = PropertyParamFixedLength;
        assert!(property_context_bytes(&record, &changed, &order).is_err());
    }
    changed = properties.clone();
    changed
        .get_mut("PID")
        .unwrap()
        .Anonymous1
        .nonStructType
        .InType = TDH_INTYPE_POINTER as u16;
    assert!(property_context_bytes(&record, &changed, &order)
        .is_err_and(|refusal| refusal.field == Some(("PID", 4))));
    changed_order = order.clone();
    changed_order.last_mut().unwrap().push_str("_unknown");
    assert!(property_context_bytes(&record, &changed, &changed_order)
        .is_err_and(|refusal| refusal.field.is_none()));
    changed_order = order.clone();
    changed_order.swap(13, 14);
    assert!(property_context_bytes(&record, &changed, &changed_order)
        .is_err_and(|refusal| refusal.field.is_none()));
    record.UserDataLength = 43;
    assert!(property_context_bytes(&record, &changed, &order)
        .is_err_and(|refusal| refusal.field.is_none()));
    record.UserDataLength = 44;
    changed.remove("connid");
    assert!(property_context_bytes(&record, &changed, &order)
        .is_err_and(|refusal| refusal.field.is_none()));
}
