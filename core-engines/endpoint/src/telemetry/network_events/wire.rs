//! Bounded decoding of native-endian netlink headers and network-endian attrs.
use athernex_endpoint_protocol::network_events::{Change, Counters, NetworkEvent, Protocol, Tuple};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
type Result<T> = std::result::Result<T, String>;
pub(super) fn attributes(mut bytes: &[u8]) -> Result<BTreeMap<u16, &[u8]>> {
    let mut result = BTreeMap::new();
    let mut count = 0;
    while !bytes.is_empty() {
        if bytes.len() < 4 || count >= 64 {
            return Err("Malformed or excessive netlink attributes".into());
        }
        let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) & 0x3fff;
        let padded = (length + 3) & !3;
        if length < 4 || padded > bytes.len() {
            return Err("Truncated netlink attribute".into());
        }
        let value = &bytes[4..length];
        if let Some(old) = result.insert(kind, value) {
            // Alignment padding may repeat; values cannot silently replace facts.
            if !value.is_empty() || !old.is_empty() {
                return Err("Duplicate netlink attribute".into());
            }
        }
        bytes = &bytes[padded..];
        count += 1;
    }
    Ok(result)
}
fn required<'a>(attrs: &BTreeMap<u16, &'a [u8]>, kind: u16) -> Result<&'a [u8]> {
    attrs
        .get(&kind)
        .copied()
        .ok_or_else(|| format!("Missing tracker attribute {kind}"))
}
fn be16(bytes: &[u8]) -> Result<u16> {
    Ok(u16::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| "Invalid u16 tracker attribute")?,
    ))
}
pub(super) fn be32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| "Invalid u32 tracker attribute")?,
    ))
}
fn be64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| "Invalid u64 tracker attribute")?,
    ))
}
fn byte(bytes: &[u8]) -> Result<u8> {
    bytes
        .first()
        .copied()
        .filter(|_| bytes.len() == 1)
        .ok_or_else(|| "Invalid u8 tracker attribute".into())
}
fn ip(bytes: &[u8], family: u8) -> Result<IpAddr> {
    match family {
        2 => Ok(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| "Invalid tracker IPv4 address")?,
        )
        .into()),
        10 => Ok(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| "Invalid tracker IPv6 address")?,
        )
        .into()),
        _ => Err("Unsupported tracker family".into()),
    }
}
fn tuple(bytes: &[u8], family: u8) -> Result<(u8, Option<Tuple>)> {
    let attrs = attributes(bytes)?;
    let ports = attributes(required(&attrs, 2)?)?;
    let protocol = byte(required(&ports, 1)?)?;
    if ![6, 17].contains(&protocol) {
        return Ok((protocol, None));
    }
    let ips = attributes(required(&attrs, 1)?)?;
    let source = if family == 2 { 1 } else { 3 };
    Ok((
        protocol,
        Some(Tuple {
            source: SocketAddr::new(
                ip(required(&ips, source)?, family)?,
                be16(required(&ports, 2)?)?,
            ),
            destination: SocketAddr::new(
                ip(required(&ips, source + 1)?, family)?,
                be16(required(&ports, 3)?)?,
            ),
            zone: attrs.get(&3).map(|b| be16(b)).transpose()?,
        }),
    ))
}
fn counters(bytes: &[u8]) -> Result<Counters> {
    let a = attributes(bytes)?;
    Ok(Counters {
        packets: be64(required(&a, 1)?)?,
        bytes: be64(required(&a, 2)?)?,
    })
}
fn event(payload: &[u8], change: Change, origin_port: u32) -> Result<Option<NetworkEvent>> {
    if payload.len() < 4 || payload[1..4] != [0, 0, 0] {
        return Err("Unsupported tracker version or header".into());
    }
    let family = payload[0];
    if ![2, 10].contains(&family) {
        return Ok(None);
    }
    let a = attributes(&payload[4..])?;
    let (original_protocol, original) = tuple(required(&a, 1)?, family)?;
    let Some(original) = original else {
        return Ok(None);
    };
    let (reply_protocol, reply) = tuple(required(&a, 2)?, family)?;
    if original_protocol != reply_protocol {
        return Err("Tracker directions disagree on protocol".into());
    }
    let reply = reply.ok_or("Missing reply tuple")?;
    let protocol = if original_protocol == 6 {
        Protocol::Tcp
    } else {
        Protocol::Udp
    };
    let tcp_state = if protocol == Protocol::Tcp {
        a.get(&4)
            .map(|b| -> Result<Option<u8>> {
                let info = attributes(b)?;
                info.get(&1)
                    .map(|b| {
                        let tcp = attributes(b)?;
                        byte(required(&tcp, 1)?)
                    })
                    .transpose()
            })
            .transpose()?
            .flatten()
    } else {
        None
    };
    let timestamps = a
        .get(&20)
        .map(|b| attributes(b))
        .transpose()?
        .unwrap_or_default();
    let event = NetworkEvent {
        change,
        protocol,
        tracker_id: be32(required(&a, 12)?)?,
        status: be32(required(&a, 3)?)?,
        original,
        reply,
        zone: a.get(&18).map(|b| be16(b)).transpose()?,
        mark: a.get(&8).map(|b| be32(b)).transpose()?,
        timeout_seconds: a.get(&7).map(|b| be32(b)).transpose()?,
        tcp_state,
        original_counters: a.get(&9).map(|b| counters(b)).transpose()?,
        reply_counters: a.get(&10).map(|b| counters(b)).transpose()?,
        started_ns: timestamps.get(&1).map(|b| be64(b)).transpose()?,
        stopped_ns: timestamps.get(&2).map(|b| be64(b)).transpose()?,
        origin_port,
    };
    event.validate()?;
    Ok(Some(event))
}
pub(super) struct Decoded {
    pub events: Vec<NetworkEvent>,
    pub skipped: u64,
}
pub(super) fn decode(mut data: &[u8], group: u32) -> Result<Decoded> {
    if data.len() > 65536 {
        return Err("Tracker datagram exceeds budget".into());
    }
    let mut output = Decoded {
        events: Vec::new(),
        skipped: 0,
    };
    let mut count = 0;
    while !data.is_empty() {
        if data.len() < 20 || count >= 128 {
            return Err("Truncated or excessive tracker envelope".into());
        }
        let length = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
        if !(20..=data.len()).contains(&length) || length > 16384 {
            return Err("Invalid tracker message length".into());
        }
        let kind = u16::from_ne_bytes(data[4..6].try_into().unwrap());
        let flags = u16::from_ne_bytes(data[6..8].try_into().unwrap());
        let sequence = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        let port = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let change = match (kind, flags, sequence, group) {
            (0x100, 0x600, 0, 1) => Change::Created,
            (0x100, 0, 0, 2) => Change::Updated,
            (0x102, 0, 0, 4) => Change::Removed,
            _ => {
                return Err(
                    "Unexpected tracker event type, flags, sequence or multicast group".into(),
                )
            }
        };
        match event(&data[16..length], change, port)? {
            Some(event) => output.events.push(event),
            None => output.skipped += 1,
        }
        let padded = (length + 3) & !3;
        if padded > data.len() {
            return Err("Truncated tracker message padding".into());
        }
        data = &data[padded..];
        count += 1;
    }
    Ok(output)
}
