use super::*;
use protocol::network_events::{Change, Counters, Protocol, Tuple};

pub(super) fn status() -> NetworkEventHealth {
    NetworkEventHealth {
        boot_id: "a".repeat(64),
        stream_id: "b".repeat(64),
        namespace: 42,
        families: vec![4, 6],
        state: "active".into(),
        started_ms: crate::now_ms(),
        checked_ms: crate::now_ms(),
        source_checked_ms: crate::now_ms(),
        received_events: 0,
        skipped_protocols: 0,
        dropped_events: 0,
        loss_signals: 0,
        subscriptions: 1,
        error: String::new(),
    }
}
pub(super) fn event() -> NetworkEvent {
    NetworkEvent {
        change: Change::Created,
        protocol: Protocol::Tcp,
        tracker_id: 7,
        status: 8,
        original: Tuple {
            source: "192.0.2.1:1000".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
            zone: Some(3),
        },
        reply: Tuple {
            source: "10.0.0.2:8443".parse().unwrap(),
            destination: "192.0.2.1:1000".parse().unwrap(),
            zone: None,
        },
        zone: Some(3),
        mark: Some(4),
        timeout_seconds: Some(120),
        tcp_state: Some(3),
        original_counters: Some(Counters {
            packets: 4,
            bytes: 300,
        }),
        reply_counters: None,
        started_ns: None,
        stopped_ns: None,
        origin_port: 99,
    }
}
#[test]
fn observation_identity_and_original_evidence_survive_restart_without_owner_inference() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    let e = envelope(&h, event(), 1, 100, crate::now_ms()).unwrap();
    assert!(e.telemetry.as_ref().unwrap().process().is_none());
    assert!(e.path.is_empty());
    assert_ne!(
        e.id,
        envelope(&h, event(), 2, 100, crate::now_ms()).unwrap().id
    );
    persist(&store, &mut h, std::slice::from_ref(&e)).unwrap();
    drop(store);
    let reopened = Store::open(temp.path()).unwrap();
    let raw: String = reopened
        .connection
        .query_row("SELECT payload FROM outbox WHERE id=?1", [&e.id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(raw, serde_json::to_string(&e).unwrap());
    assert!(!health(&reopened).unwrap().unwrap().healthy(crate::now_ms()));
    let mut invalid = e.clone();
    invalid.path = "/invented/owner".into();
    assert!(invalid.validate(crate::now_ms()).is_err());
    invalid = e.clone();
    invalid.telemetry = None;
    assert!(invalid.validate(crate::now_ms()).is_err());
    let mut invalid = event();
    invalid.reply.source = "[::1]:42".parse().unwrap();
    assert!(invalid.validate().is_err());
    invalid = event();
    invalid.protocol = Protocol::Udp;
    assert!(invalid.validate().is_err());
}
#[test]
fn full_queue_and_failed_transaction_preserve_evidence_and_report_loss() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut h = status();
    store.connection.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<8192) INSERT INTO telemetry_pending SELECT printf('%064x',x),'{}' FROM n; WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<3072) INSERT INTO outbox SELECT printf('%064x',x),'{}' FROM n;").unwrap();
    let e = envelope(&h, event(), 1, 100, crate::now_ms()).unwrap();
    store.connection.execute_batch("CREATE TRIGGER reject_health BEFORE INSERT ON telemetry_metadata BEGIN SELECT RAISE(ABORT,'controlled'); END;").unwrap();
    assert!(persist(&store, &mut h, std::slice::from_ref(&e)).is_err());
    assert_eq!(h.dropped_events, 0);
    store
        .connection
        .execute_batch("DROP TRIGGER reject_health;")
        .unwrap();
    persist(&store, &mut h, &[e]).unwrap();
    assert_eq!(h.dropped_events, 1);
    assert!(!h.healthy(crate::now_ms()));
    let counts: (u64, u64) = store
        .connection
        .query_row(
            "SELECT count(*),sum(payload='{}') FROM telemetry_pending",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (8192, 8192));
    persist(&store, &mut h, &[]).unwrap();
    assert_eq!(h.dropped_events, 1);
}
#[test]
fn health_requires_recent_tracking_inspection_and_an_intact_subscription() {
    let h = status();
    let now = crate::now_ms();
    assert!(h.healthy(now));
    for bad in [
        NetworkEventHealth {
            source_checked_ms: now - 15_001,
            ..h.clone()
        },
        NetworkEventHealth {
            families: vec![],
            ..h.clone()
        },
        NetworkEventHealth {
            loss_signals: 1,
            ..h.clone()
        },
        NetworkEventHealth {
            dropped_events: 1,
            ..h.clone()
        },
        NetworkEventHealth {
            state: "stopped".into(),
            ..h.clone()
        },
        NetworkEventHealth {
            checked_ms: now + 1001,
            ..h.clone()
        },
    ] {
        assert!(!bad.healthy(now));
    }
}

#[cfg(target_os = "linux")]
mod decoding {
    use super::*;
    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend(((value.len() + 4) as u16).to_ne_bytes());
        result.extend(kind.to_ne_bytes());
        result.extend(value);
        result.resize((result.len() + 3) & !3, 0);
        result
    }
    fn tuple(v6: bool, proto: u8, reverse: bool) -> Vec<u8> {
        let (a, b) = if v6 {
            (
                "2001:db8::1".parse::<std::net::IpAddr>().unwrap(),
                "2001:db8::2".parse().unwrap(),
            )
        } else {
            (
                "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
                "10.0.0.2".parse().unwrap(),
            )
        };
        let address = |a: std::net::IpAddr| match a {
            std::net::IpAddr::V4(v) => v.octets().to_vec(),
            std::net::IpAddr::V6(v) => v.octets().to_vec(),
        };
        let ips = [
            attr(
                if v6 { 3 } else { 1 },
                &address(if reverse { b } else { a }),
            ),
            attr(
                if v6 { 4 } else { 2 },
                &address(if reverse { a } else { b }),
            ),
        ]
        .concat();
        let ports = [
            attr(1, &[proto]),
            attr(2, &(if reverse { 443u16 } else { 1000 }).to_be_bytes()),
            attr(3, &(if reverse { 1000u16 } else { 443 }).to_be_bytes()),
        ]
        .concat();
        [attr(1, &ips), attr(2, &ports), attr(3, &3u16.to_be_bytes())].concat()
    }
    fn packet(v6: bool, proto: u8) -> Vec<u8> {
        let count = [attr(1, &4u64.to_be_bytes()), attr(2, &300u64.to_be_bytes())].concat();
        let attrs = [
            attr(1, &tuple(v6, proto, false)),
            attr(2, &tuple(v6, proto, true)),
            attr(3, &8u32.to_be_bytes()),
            attr(12, &7u32.to_be_bytes()),
            attr(9, &count),
            attr(18, &3u16.to_be_bytes()),
        ]
        .concat();
        let mut p = vec![0; 20];
        p[4..6].copy_from_slice(&0x100u16.to_ne_bytes());
        p[6..8].copy_from_slice(&0x600u16.to_ne_bytes());
        p[12..16].copy_from_slice(&99u32.to_ne_bytes());
        p[16] = if v6 { 10 } else { 2 };
        p.extend(attrs);
        let len = p.len() as u32;
        p[..4].copy_from_slice(&len.to_ne_bytes());
        p
    }
    #[test]
    fn ipv4_ipv6_tcp_udp_and_cumulative_counters_decode_without_pid() {
        for v6 in [false, true] {
            for proto in [6, 17] {
                let p = packet(v6, proto);
                let decoded = wire::decode(&p, 1).unwrap();
                assert_eq!(decoded.events.len(), 1);
                let event = &decoded.events[0];
                assert_eq!(
                    event.protocol,
                    if proto == 6 {
                        Protocol::Tcp
                    } else {
                        Protocol::Udp
                    }
                );
                assert_eq!(event.original.source.is_ipv6(), v6);
                assert_eq!(event.original.source.port(), 1000);
                assert_eq!(event.reply.source.port(), 443);
                assert_eq!(event.origin_port, 99);
                assert_eq!(event.zone, Some(3));
                assert_eq!(event.original_counters.as_ref().unwrap().bytes, 300);
            }
        }
        let skipped = wire::decode(&packet(false, 1), 1).unwrap();
        assert_eq!(skipped.skipped, 1);
        assert!(skipped.events.is_empty());
    }
    #[test]
    fn truncated_duplicate_and_mismatched_messages_fail_closed() {
        let p = packet(false, 6);
        for len in 1..p.len() {
            assert!(wire::decode(&p[..len], 1).is_err(), "length {len}");
        }
        assert!(wire::decode(&p, 2).is_err());
        let mut bad = p.clone();
        bad[8] = 1;
        assert!(wire::decode(&bad, 1).is_err());
        let mut bad = p.clone();
        bad.extend(attr(12, &8u32.to_be_bytes()));
        let len = bad.len() as u32;
        bad[..4].copy_from_slice(&len.to_ne_bytes());
        assert!(wire::decode(&bad, 1).is_err());
        let mut updated = p.clone();
        updated[6..8].copy_from_slice(&0u16.to_ne_bytes());
        assert_eq!(
            wire::decode(&updated, 2).unwrap().events[0].change,
            Change::Updated
        );
        updated[4..6].copy_from_slice(&0x102u16.to_ne_bytes());
        assert_eq!(
            wire::decode(&updated, 4).unwrap().events[0].change,
            Change::Removed
        );
    }
}
