//! AEF1: lossless encoding of a deliberately bounded normalized event schema.
//! Labels live in the SQLite dictionary; payload size alone is not storage cost.
use crate::model::{Event, Kind, Outcome};

pub fn encode(event: &Event) -> Vec<u8> {
    let mut bytes = b"AEF1".to_vec();
    for mut value in [
        event.id,
        event.time_ms,
        event.observed_ms,
        u64::from(event.source),
        u64::from(event.subject),
        u64::from(event.object),
        event.bytes,
        u64::from(event.trace),
    ] {
        while value >= 128 {
            bytes.push((value as u8 & 127) | 128);
            value >>= 7;
        }
        bytes.push(value as u8);
    }
    bytes.extend([event.kind as u8, event.outcome as u8, event.severity]);
    bytes
}

pub fn decode(bytes: &[u8]) -> Result<Event, &'static str> {
    if bytes.len() < 15 || bytes.len() > 87 || &bytes[..4] != b"AEF1" {
        return Err("invalid AEF1 frame");
    }
    let mut offset = 4;
    let mut values = [0u64; 8];
    for value in &mut values {
        let mut complete = false;
        for index in 0..10 {
            let byte = *bytes.get(offset).ok_or("truncated varint")?;
            offset += 1;
            if index == 9 && byte > 1 {
                return Err("overflow");
            }
            *value |= u64::from(byte & 127) << (index * 7);
            if byte < 128 {
                if index > 0 && byte == 0 {
                    return Err("noncanonical varint");
                }
                complete = true;
                break;
            }
        }
        if !complete {
            return Err("unterminated varint");
        }
    }
    if offset + 3 != bytes.len() || !(1..=5).contains(&bytes[offset + 2]) {
        return Err("invalid payload length or severity");
    }
    Ok(Event {
        id: values[0],
        time_ms: values[1],
        observed_ms: values[2],
        source: values[3].try_into().map_err(|_| "source overflow")?,
        subject: values[4].try_into().map_err(|_| "subject overflow")?,
        object: values[5].try_into().map_err(|_| "object overflow")?,
        bytes: values[6],
        trace: values[7].try_into().map_err(|_| "trace overflow")?,
        kind: Kind::from_byte(bytes[offset]).ok_or("unknown kind")?,
        outcome: Outcome::from_byte(bytes[offset + 1]).ok_or("unknown outcome")?,
        severity: bytes[offset + 2],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> Event {
        Event {
            id: u64::MAX,
            time_ms: 1_800_000_000_000,
            observed_ms: 1_800_000_000_003,
            source: u16::MAX,
            subject: u32::MAX,
            object: 7,
            kind: Kind::Authentication,
            outcome: Outcome::Deny,
            severity: 4,
            bytes: u64::MAX,
            trace: u32::MAX,
        }
    }
    #[test]
    fn preserves_all_fields_and_rejects_truncation() {
        let encoded = encode(&event());
        assert_eq!(decode(&encoded), Ok(event()));
        for end in 0..encoded.len() {
            assert!(decode(&encoded[..end]).is_err());
        }
        let mut extra = encoded;
        extra.push(0);
        assert!(decode(&extra).is_err());
    }
    #[test]
    fn rejects_unknown_version_and_enum() {
        let mut bytes = encode(&event());
        bytes[3] = b'2';
        assert!(decode(&bytes).is_err());
        let mut bytes = encode(&event());
        let end = bytes.len();
        bytes[end - 3] = 99;
        assert!(decode(&bytes).is_err());
    }
}
