//! Bounded, synthetic encoding experiment. This is not a production event format.
//! Run `make research-siem`; no Cargo dependencies or persisted datasets.

use std::fmt::Write as _;
use std::io::{self, Write};
use std::process::{Command, Stdio};

const LIMIT: usize = 4096;
const HEADER: usize = 32;
const SOURCE: u64 = 7;
const EPOCH: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Event {
    sequence: u64,
    event_ms: u64,
    observed_ms: u64,
    subject: u64,
    object: u64,
    kind: u8,
    outcome: u8,
    severity: u8,
}

impl Event {
    fn valid(&self) -> bool {
        (1..=4).contains(&self.kind) && self.outcome <= 2 && (1..=6).contains(&self.severity)
    }
}

fn put_varint(mut value: u64, bytes: &mut Vec<u8>) {
    while value >= 128 {
        bytes.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    bytes.push(value as u8);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        let end = self.offset.checked_add(N).ok_or("offset overflow")?;
        let value = self.bytes.get(self.offset..end).ok_or("truncated")?;
        self.offset = end;
        value.try_into().map_err(|_| "invalid width")
    }

    fn varint(&mut self) -> Result<u64, &'static str> {
        let mut value = 0;
        for index in 0..10 {
            let byte = self.take::<1>()?[0];
            if index == 9 && byte > 1 {
                return Err("varint overflow");
            }
            value |= u64::from(byte & 127) << (index * 7);
            if byte < 128 {
                if index > 0 && byte == 0 {
                    return Err("noncanonical varint");
                }
                return Ok(value);
            }
        }
        Err("varint too long")
    }
}

fn encode(events: &[Event]) -> Result<Vec<u8>, &'static str> {
    if events.len() > LIMIT || events.iter().any(|event| !event.valid()) {
        return Err("invalid events");
    }
    let base = events
        .iter()
        .flat_map(|event| [event.event_ms, event.observed_ms])
        .min()
        .unwrap_or(0);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AXP0");
    bytes.extend_from_slice(&(events.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&base.to_le_bytes());
    bytes.extend_from_slice(&SOURCE.to_le_bytes());
    bytes.extend_from_slice(&EPOCH.to_le_bytes());
    for event in events {
        for value in [
            event.sequence,
            event.event_ms - base,
            event.observed_ms - base,
            event.subject,
            event.object,
        ] {
            put_varint(value, &mut bytes);
        }
        bytes.extend_from_slice(&[event.kind, event.outcome, event.severity]);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Vec<Event>, &'static str> {
    if bytes.len() > HEADER + LIMIT * 53 {
        return Err("frame too large");
    }
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take::<4>()? != *b"AXP0" {
        return Err("unknown schema");
    }
    let count = u32::from_le_bytes(reader.take()?) as usize;
    if count > LIMIT {
        return Err("too many events");
    }
    let base = u64::from_le_bytes(reader.take()?);
    if u64::from_le_bytes(reader.take()?) != SOURCE || u64::from_le_bytes(reader.take()?) != EPOCH {
        return Err("unknown source or epoch");
    }
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        let event = Event {
            sequence: reader.varint()?,
            event_ms: base.checked_add(reader.varint()?).ok_or("time overflow")?,
            observed_ms: base.checked_add(reader.varint()?).ok_or("time overflow")?,
            subject: reader.varint()?,
            object: reader.varint()?,
            kind: reader.take::<1>()?[0],
            outcome: reader.take::<1>()?[0],
            severity: reader.take::<1>()?[0],
        };
        if !event.valid() {
            return Err("unknown enum");
        }
        events.push(event);
    }
    if reader.offset != bytes.len() {
        return Err("trailing bytes");
    }
    Ok(events)
}

fn json_lines(events: &[Event]) -> Vec<u8> {
    let mut text = String::new();
    for event in events {
        writeln!(text, "{{\"schema\":\"AXP0\",\"source\":{SOURCE},\"epoch\":{EPOCH},\"sequence\":{},\"event_ms\":{},\"observed_ms\":{},\"subject\":{},\"object\":{},\"kind\":{},\"outcome\":{},\"severity\":{}}}", event.sequence, event.event_ms, event.observed_ms, event.subject, event.object, event.kind, event.outcome, event.severity).unwrap();
    }
    text.into_bytes()
}

fn random(state: &mut u64) -> u64 {
    // Fixed-seed synthetic variation, never cryptography or identity generation.
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn corpus(mode: usize) -> Vec<Event> {
    let mut state = 0x6174_6865_726e_6578;
    (0..LIMIT as u64)
        .map(|sequence| {
            let first = random(&mut state);
            let second = random(&mut state);
            let event_ms = 1_800_000_000_000
                + match mode {
                    0 => sequence / 8,
                    1 => sequence * 37 + first % 1000,
                    _ => first % 86_400_000,
                };
            Event {
                sequence,
                event_ms,
                observed_ms: event_ms + if mode == 0 { 2 } else { second % 1000 },
                subject: match mode {
                    0 => sequence % 16,
                    1 => first % 256,
                    _ => first,
                },
                object: match mode {
                    0 => 7,
                    1 => second % 64,
                    _ => second,
                },
                kind: if mode == 0 { 1 } else { (first % 4 + 1) as u8 },
                outcome: if mode == 0 { 1 } else { (second % 3) as u8 },
                severity: if mode == 0 { 3 } else { (first % 6 + 1) as u8 },
            }
        })
        .collect()
}

fn zstd_size(input: &[u8]) -> io::Result<usize> {
    let mut child = Command::new("zstd")
        .args(["-q", "-3", "-T1", "--no-progress", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    // Drain stdout while feeding stdin, so a full OS pipe cannot deadlock.
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(input));
        let output = child.wait_with_output()?;
        writer
            .join()
            .map_err(|_| io::Error::other("writer panicked"))??;
        if !output.status.success() {
            return Err(io::Error::other(String::from_utf8_lossy(&output.stderr)));
        }
        Ok(output.stdout.len())
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("AXP0 research probe: 4096 events/corpus, fixed seed, 32-byte frame header included.");
    println!("Same normalized fields in JSON and binary; no raw logs, identity dictionaries, indexes, WAL, replication, encryption, or throughput measurement.");
    let zstd = match Command::new("zstd").arg("--version").output() {
        Ok(output) if output.status.success() => {
            println!("{}", String::from_utf8_lossy(&output.stdout).trim());
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("zstd unavailable: compressed comparisons are N/A.");
            false
        }
        _ => return Err("zstd version check failed".into()),
    };
    println!("corpus,events,json_bytes,binary_bytes,json_zstd3_bytes,binary_zstd3_bytes,roundtrip");
    for (mode, name) in ["repetitive", "mixed", "high-cardinality"]
        .iter()
        .enumerate()
    {
        let events = corpus(mode);
        let json = json_lines(&events);
        let binary = encode(&events)?;
        assert_eq!(decode(&binary)?, events);
        let (json_zstd, binary_zstd) = if zstd {
            (
                zstd_size(&json)?.to_string(),
                zstd_size(&binary)?.to_string(),
            )
        } else {
            ("N/A".into(), "N/A".into())
        };
        println!(
            "{name},{},{},{},{json_zstd},{binary_zstd},exact",
            events.len(),
            json.len(),
            binary.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpora_and_clock_skew_roundtrip_exactly() {
        for mode in 0..3 {
            let mut events = corpus(mode);
            events[0].observed_ms = events[0].event_ms - 100;
            assert_eq!(decode(&encode(&events).unwrap()).unwrap(), events);
        }
        assert_eq!(decode(&encode(&[]).unwrap()).unwrap(), vec![]);
    }

    #[test]
    fn rejects_truncation_unknown_schema_count_enum_and_trailing_data() {
        let frame = encode(&corpus(0)[..2]).unwrap();
        for length in 0..frame.len() {
            assert!(decode(&frame[..length]).is_err());
        }
        for offset in [0, 4, 24, frame.len() - 1] {
            let mut invalid = frame.clone();
            invalid[offset] = 255;
            assert!(decode(&invalid).is_err());
        }
        let mut trailing = frame;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        assert!(decode(&vec![0; HEADER + LIMIT * 53 + 1]).is_err());
        assert!(encode(&vec![corpus(0)[0].clone(); LIMIT + 1]).is_err());
    }

    #[test]
    fn varint_boundaries_overflow_and_noncanonical_input() {
        for value in [0, 127, 128, 16_383, 16_384, u64::MAX] {
            let mut bytes = Vec::new();
            put_varint(value, &mut bytes);
            assert_eq!(
                Reader {
                    bytes: &bytes,
                    offset: 0
                }
                .varint(),
                Ok(value)
            );
        }
        for bytes in [&[128, 0][..], &[255; 11][..], &[128][..]] {
            assert!(Reader { bytes, offset: 0 }.varint().is_err());
        }
    }

    #[test]
    fn rejects_timestamp_overflow_and_invalid_input_enum() {
        let mut events = corpus(0)[..1].to_vec();
        let mut frame = encode(&events).unwrap();
        frame[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode(&frame).is_err());
        events[0].kind = 0;
        assert!(encode(&events).is_err());
    }
}
