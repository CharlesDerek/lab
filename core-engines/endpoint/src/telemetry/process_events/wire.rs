//! Linux connector UAPI, decoded without casting unaligned network buffers.
use crate::Result;
use athernex_endpoint_protocol::process_events::{Change, ProcessEvent};
use std::collections::BTreeMap;

pub(super) struct Frame {
    pub cpu: u32,
    pub sequence: u32,
    pub ack: Option<(u32, u32)>,
    pub event: Option<ProcessEvent>,
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
pub(super) fn decode(bytes: &[u8]) -> Result<Vec<Frame>> {
    let mut offset = 0;
    let mut frames = Vec::new();
    while offset < bytes.len() {
        if frames.len() >= 64 || bytes.len() - offset < 16 {
            return Err("Truncated or excessive process connector frames".into());
        }
        let raw = &bytes[offset..];
        let len = u32_at(raw, 0) as usize;
        let kind = u16::from_ne_bytes(raw[4..6].try_into().unwrap());
        if len < 16 || len > raw.len() || u32_at(raw, 12) != 0 {
            return Err("Invalid kernel netlink envelope".into());
        }
        if kind == 2 || kind == 4 {
            return Err("Kernel reported a netlink error or overrun".into());
        }
        if kind != 3
            || len != 76
            || raw[6..8] != [0, 0]
            || u32_at(raw, 16) != 1
            || u32_at(raw, 20) != 1
            || u16::from_ne_bytes(raw[32..34].try_into().unwrap()) != 40
            || raw[34..36] != [0, 0]
        {
            return Err("Unsupported process connector message".into());
        }
        let what = u32_at(raw, 36);
        let cpu = u32_at(raw, 40);
        let sequence = u32_at(raw, 24);
        let data = &raw[52..76];
        if what == 0 {
            frames.push(Frame {
                cpu,
                sequence,
                ack: Some((u32_at(raw, 28), u32_at(data, 0))),
                event: None,
            });
        } else {
            let mut pid = u32_at(data, 4);
            let mut tid = u32_at(data, 0);
            let change =
                match what {
                    1 => {
                        pid = u32_at(data, 12);
                        tid = u32_at(data, 8);
                        Change::Fork {
                            parent_pid: u32_at(data, 4),
                            parent_tid: u32_at(data, 0),
                        }
                    }
                    2 => Change::Exec,
                    4 => Change::UserId {
                        real: u32_at(data, 8),
                        effective: u32_at(data, 12),
                    },
                    0x40 => Change::GroupId {
                        real: u32_at(data, 8),
                        effective: u32_at(data, 12),
                    },
                    0x80 => Change::Session,
                    0x100 => Change::Ptrace {
                        tracer_pid: u32_at(data, 12),
                        tracer_tid: u32_at(data, 8),
                    },
                    0x200 => Change::Name {
                        bytes_hex: data[8..24].iter().map(|b| format!("{b:02x}")).collect(),
                    },
                    0x40000000 => Change::CoreDump {
                        parent_pid: u32_at(data, 12),
                        parent_tid: u32_at(data, 8),
                    },
                    0x80000000 => Change::Exit {
                        parent_pid: u32_at(data, 20),
                        parent_tid: u32_at(data, 16),
                        code: u32_at(data, 8),
                        signal: u32_at(data, 12),
                    },
                    _ => return Err(
                        "Unknown kernel process notification; coverage requires an updated decoder"
                            .into(),
                    ),
                };
            let event = ProcessEvent {
                cpu,
                sequence,
                monotonic_ns: u64::from_ne_bytes(raw[44..52].try_into().unwrap()),
                pid,
                tid,
                change,
            };
            event.validate()?;
            frames.push(Frame {
                cpu,
                sequence,
                event: Some(event),
                ack: None,
            });
        }
        offset += (len + 3) & !3;
    }
    Ok(frames)
}

#[derive(Default)]
pub(super) struct Sequences(BTreeMap<u32, u32>);
impl Sequences {
    pub fn observe(&mut self, frame: &Frame) -> Result<bool> {
        if frame.cpu == u32::MAX && frame.ack.is_some() {
            return Ok(false);
        }
        if frame.cpu >= 8192 {
            return Err("Kernel CPU identity exceeds collector bounds".into());
        }
        Ok(self
            .0
            .insert(frame.cpu, frame.sequence)
            .is_some_and(|prior| prior.wrapping_add(1) != frame.sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(what: u32) -> Vec<u8> {
        let mut b = vec![0; 76];
        for (offset, value) in [
            (0, 76u32),
            (16, 1),
            (20, 1),
            (24, 9),
            (36, what),
            (40, 3),
            (52, 41),
            (56, 40),
            (60, 99),
            (64, 98),
        ] {
            b[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        b[4..6].copy_from_slice(&3u16.to_ne_bytes());
        b[32..34].copy_from_slice(&40u16.to_ne_bytes());
        b[44..52].copy_from_slice(&123u64.to_ne_bytes());
        b
    }
    #[test]
    fn kernel_layout_preserves_process_thread_and_credential_semantics() {
        let fork = decode(&frame(1)).unwrap().remove(0).event.unwrap();
        assert_eq!((fork.pid, fork.tid), (98, 99));
        assert_eq!(
            fork.change,
            Change::Fork {
                parent_pid: 40,
                parent_tid: 41
            }
        );
        let uid = decode(&frame(4)).unwrap().remove(0).event.unwrap();
        assert_eq!((uid.pid, uid.tid), (40, 41));
        assert_eq!(
            uid.change,
            Change::UserId {
                real: 99,
                effective: 98
            }
        );
        for what in [2, 0x40, 0x80, 0x100, 0x200, 0x40000000, 0x80000000] {
            assert!(decode(&frame(what)).unwrap()[0].event.is_some());
        }
        let both = [frame(2), frame(0x80000000)].concat();
        assert_eq!(decode(&both).unwrap().len(), 2);
    }
    #[test]
    fn malformed_truncated_forged_and_unknown_frames_are_rejected() {
        let good = frame(2);
        for length in 1..good.len() {
            assert!(decode(&good[..length]).is_err());
        }
        for (offset, value) in [
            (0, 1000u32),
            (12, 22),
            (16, 2),
            (20, 2),
            (36, 8),
            (40, 8192),
            (56, 0),
        ] {
            let mut bad = good.clone();
            bad[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            assert!(decode(&bad).is_err(), "offset {offset}");
        }
        assert!(decode(&good.repeat(65)).is_err());
    }
    #[test]
    fn per_cpu_sequences_detect_gaps_duplicates_and_wrap_without_cross_cpu_claims() {
        let mut sequences = Sequences::default();
        let mut f = decode(&frame(2)).unwrap().remove(0);
        f.sequence = u32::MAX;
        assert!(!sequences.observe(&f).unwrap());
        f.sequence = 0;
        assert!(!sequences.observe(&f).unwrap());
        f.cpu = 4;
        f.sequence = 30;
        assert!(!sequences.observe(&f).unwrap());
        f.cpu = 3;
        f.sequence = 2;
        assert!(sequences.observe(&f).unwrap());
        assert!(sequences.observe(&f).unwrap());
        f.sequence = 3;
        assert!(!sequences.observe(&f).unwrap());
    }
}
