//! Read-only nfnetlink hook dumps: a subscribed socket alone proves no tracking.
use super::{
    linux::Socket,
    wire::{attributes, be32},
};
use crate::Result;
use std::time::{Duration, Instant};
fn string<'a>(bytes: Option<&&'a [u8]>) -> Result<Option<&'a str>> {
    bytes
        .map(|b| {
            if b.len() > 128 || b.last() != Some(&0) {
                return Err("Invalid netfilter hook name".into());
            }
            let value = std::str::from_utf8(&b[..b.len() - 1])?;
            if value.chars().any(char::is_control) {
                return Err("Invalid netfilter hook name".into());
            }
            Ok(value)
        })
        .transpose()
}
fn query(socket: &Socket, family: u8, hook: u32, sequence: u32, deadline: Instant) -> Result<bool> {
    let mut request = [0u8; 28];
    request[..4].copy_from_slice(&28u32.to_ne_bytes());
    request[4..6].copy_from_slice(&0xc00u16.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[12..16].copy_from_slice(&socket.port.to_ne_bytes());
    request[16] = family;
    request[20..22].copy_from_slice(&8u16.to_ne_bytes());
    request[22..24].copy_from_slice(&1u16.to_ne_bytes());
    request[24..28].copy_from_slice(&hook.to_be_bytes());
    socket.send(&request)?;
    let mut found = false;
    let mut count = 0;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("Netfilter hook inspection timed out")?;
        let Some((bytes, group)) = socket.receive(remaining.as_millis().clamp(1, 2000) as i32)?
        else {
            continue;
        };
        if group != 0 {
            return Err("Unexpected multicast response to hook inspection".into());
        }
        let mut data = bytes.as_slice();
        while !data.is_empty() {
            count += 1;
            if data.len() < 20 || count > 1024 {
                return Err("Netfilter hook response exceeds budget".into());
            }
            let length = u32::from_ne_bytes(data[..4].try_into()?) as usize;
            let padded = length
                .checked_add(3)
                .ok_or("Hook response length overflow")?
                & !3;
            if length < 20 || padded > data.len() {
                return Err("Truncated hook response".into());
            }
            let kind = u16::from_ne_bytes(data[4..6].try_into()?);
            let flags = u16::from_ne_bytes(data[6..8].try_into()?);
            // nfnetlink_hook emits data headers with port zero on kernels that
            // use the output skb's port. NLMSG_DONE still echoes our bound port.
            // The transport separately requires the sender sockaddr to be kernel.
            let port = u32::from_ne_bytes(data[12..16].try_into()?);
            let expected_port = port == socket.port || (kind == 0xc00 && port == 0);
            if u32::from_ne_bytes(data[8..12].try_into()?) != sequence
                || !expected_port
                || flags & 16 != 0
            {
                return Err("Interrupted or mismatched hook inspection".into());
            }
            if kind == 2 {
                return Err(format!(
                    "Netfilter hook inspection failed: {}",
                    i32::from_ne_bytes(data[16..20].try_into()?)
                )
                .into());
            }
            if kind == 3 {
                if i32::from_ne_bytes(data[16..20].try_into()?) != 0 || padded != data.len() {
                    return Err("Incomplete hook inspection".into());
                }
                return Ok(found);
            }
            if kind != 0xc00 || data[16..20] != [family, 0, 0, 0] {
                return Err("Unsupported hook response".into());
            }
            let attrs = attributes(&data[20..length])?;
            if attrs.get(&1).map(|b| be32(b)).transpose()? != Some(hook) {
                return Err("Hook response has wrong hook number".into());
            }
            let priority = attrs
                .get(&2)
                .map(|b| be32(b))
                .transpose()?
                .ok_or("Missing hook priority")? as i32;
            let name = string(attrs.get(&4))?;
            let module = string(attrs.get(&5))?;
            let name_matches = match (family, hook) {
                (2, 0) => name == Some("ipv4_conntrack_in"),
                (2, 3) => name == Some("ipv4_conntrack_local"),
                (10, 0) => name == Some("ipv6_conntrack_in"),
                (10, 3) => name == Some("ipv6_conntrack_local"),
                (_, 1 | 4) => matches!(name, Some("nf_confirm" | "ipv4_confirm" | "ipv6_confirm")),
                _ => false,
            };
            if name_matches
                && module.is_none_or(|m| m == "nf_conntrack")
                && if hook == 0 || hook == 3 {
                    priority == -200
                } else {
                    priority >= i32::MAX - 1
                }
            {
                found = true;
            }
            data = &data[padded..];
        }
    }
}
pub(super) fn source() -> Result<Vec<u8>> {
    let events = std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_events")?;
    if !["1", "2"].contains(&events.trim()) {
        return Err("Kernel connection-tracking event delivery is disabled".into());
    }
    let socket = Socket::new(0, 262144)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut result = Vec::new();
    let mut sequence = 0;
    for (family, label) in [(2, 4), (10, 6)] {
        let mut complete = true;
        for hook in [0, 1, 3, 4] {
            sequence += 1;
            complete &= query(&socket, family, hook, sequence, deadline)?;
        }
        if complete {
            result.push(label);
        }
    }
    Ok(result)
}
