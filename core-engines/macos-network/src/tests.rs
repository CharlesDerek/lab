use super::*;
use crate::{
    client::Backend,
    transport::{Control, Reply},
};
use athernex_endpoint_protocol::macos_network_events::*;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

fn config() -> Config {
    Config {
        team_id: "TESTTEAM00".into(),
        agent_identifier: "test.agent".into(),
        provider_identifier: "test.provider".into(),
        mach_service_name: "TESTTEAM00.test.group.network".into(),
        app_group: "TESTTEAM00.test.group".into(),
        provider_cdhashes: vec!["a".repeat(40)],
        source_policy_sha256: source_policy_sha256(),
    }
}
fn original(receipt: u64) -> MacosNetworkOriginal {
    MacosNetworkOriginal {
        projection_version: 1,
        stream_id: "b".repeat(64),
        receipt_sequence: receipt,
        callback: MacosNetworkCallback::NewFlow,
        receipt_time: MacosNetworkReceiptTime {
            seconds: 1,
            nanoseconds: 0,
        },
        flow_id: "00000000-0000-0000-0000-000000000001".into(),
        direction: 0,
        socket_family: 2,
        socket_type: 1,
        socket_protocol: 0,
        local: None,
        remote: Some(MacosNetworkEndpoint {
            address: "127.0.0.1".parse().unwrap(),
            port: 1,
            scope_id: None,
        }),
        source_app_audit_token_hex: None,
        source_process_audit_token_hex: Some("c".repeat(64)),
    }
}
fn status(pending: u64, acked: u64) -> Status {
    Status {
        health: MacosNetworkEventHealth {
            stream_id: "b".repeat(64),
            state: "active".into(),
            source_policy_sha256: source_policy_sha256(),
            started_ms: 1,
            checked_ms: 2,
            received_records: 10,
            pending_records: pending,
            pending_bytes: pending * 1000,
            ..Default::default()
        },
        last_acked_batch_id: acked,
    }
}
fn reply(request: u64, batch: u64, acked: u64, records: Vec<MacosNetworkOriginal>) -> Reply {
    let body = if records.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(&records).unwrap()
    };
    let c = Control {
        version: 1,
        nonce: "d".repeat(64),
        epoch: 1,
        request_id: request,
        status: status(records.len() as u64, acked),
        batch_id: batch,
        batch_sha256: if body.is_empty() {
            String::new()
        } else {
            format!("{:x}", Sha256::digest(&body))
        },
        record_count: records.len() as u32,
    };
    Reply {
        control: serde_json::to_vec(&c).unwrap(),
        batch: body,
    }
}
fn change(mut r: Reply, f: impl FnOnce(&mut Control)) -> Reply {
    let mut c: Control = serde_json::from_slice(&r.control).unwrap();
    f(&mut c);
    r.control = serde_json::to_vec(&c).unwrap();
    r
}
fn decode(r: Reply) -> Result<(u64, Delivery)> {
    transport::decode(r, &"d".repeat(64), Some(1), 1, Some(&"b".repeat(64)))
}

#[test]
fn structured_signing_configuration_refuses_injection_and_weak_pins() {
    let good = config();
    good.validate().unwrap();
    for bad in [
        "test.agent\" or true",
        "test..agent",
        "/test/agent",
        "test.agent\0",
        "test.*",
    ] {
        let mut c = good.clone();
        c.agent_identifier = bad.into();
        assert!(c.validate().is_err());
    }
    let mut c = good.clone();
    c.provider_cdhashes.push(c.provider_cdhashes[0].clone());
    assert!(c.validate().is_err());
    let mut c = good.clone();
    c.provider_cdhashes = vec!["a".repeat(64)];
    assert!(c.validate().is_err());
    let mut c = good.clone();
    c.mach_service_name = "other.group.service".into();
    assert!(c.validate().is_err());
    let mut c = good.clone();
    c.source_policy_sha256 = "e".repeat(64);
    assert!(c.validate().is_err());
    let mut v = serde_json::to_value(good).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("requirement".into(), "true".into());
    assert!(serde_json::from_value::<Config>(v).is_err());
}
#[test]
fn source_frame_preserves_reported_zero_and_missing_role_fields() {
    let (_, d) = decode(reply(1, 1, 0, vec![original(3)])).unwrap();
    assert_eq!(d.events[0].protocol, MacosNetworkProtocol::Undetermined);
    assert_eq!(d.events[0].direction, MacosNetworkDirection::Unspecified);
    assert_eq!(d.events[0].original, original(3));
    assert_eq!(d.events[0].local, None);
    assert_eq!(d.events[0].original.source_app_audit_token_hex, None);
    assert!(d.events[0]
        .original
        .source_process_audit_token_hex
        .is_some());
}
#[test]
fn framed_binding_and_coherent_receipt_limits_refuse_forgery() {
    let mutations: [fn(&mut Control); 10] = [
        |c| c.nonce = "a".repeat(64),
        |c| c.epoch = 2,
        |c| c.request_id = 2,
        |c| c.status.health.stream_id = "a".repeat(64),
        |c| c.status.health.source_policy_sha256 = "a".repeat(64),
        |c| c.record_count = 2,
        |c| c.status.health.received_records = 2,
        |c| c.status.health.pending_records = 0,
        |c| c.status.health.admitted_records = 1,
        |c| c.status.last_acked_batch_id = 2,
    ];
    for f in mutations {
        assert!(decode(change(reply(1, 1, 0, vec![original(3)]), f)).is_err());
    }
    assert!(decode(reply(1, 1, 0, vec![original(3), original(2)])).is_err());
    let mut r = reply(1, 1, 0, vec![original(3)]);
    r.batch.push(b' ');
    assert!(decode(r).is_err());
    let mut r = reply(1, 0, 0, vec![]);
    r.control.splice(1..1, b"\"version\":1,".iter().copied());
    assert!(decode(r).is_err());
    let mut r = reply(1, 0, 0, vec![]);
    r.control.resize(MAX_CONTROL_BYTES + 1, b' ');
    assert!(decode(r).is_err());
    let r = Reply {
        control: vec![],
        batch: vec![0; MAX_BATCH_BYTES + 1],
    };
    assert!(decode(r).is_err());
}
#[derive(Default)]
struct Calls {
    ops: Vec<u32>,
    invalidated: usize,
}
struct Mock {
    replies: VecDeque<Result<Reply>>,
    calls: Arc<Mutex<Calls>>,
}
impl Backend for Mock {
    fn exchange(&mut self, op: u32, _: u64, _: u64, _: u64, _: &str) -> Result<Reply> {
        self.calls.lock().unwrap().ops.push(op);
        self.replies.pop_front().unwrap()
    }
    fn invalidate(&mut self) {
        self.calls.lock().unwrap().invalidated += 1;
    }
}
fn client(replies: Vec<Result<Reply>>, hello: Reply) -> (Client, Arc<Mutex<Calls>>) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let b = Mock {
        replies: replies.into(),
        calls: calls.clone(),
    };
    (
        Client::connected(Box::new(b), "d".repeat(64), hello).unwrap(),
        calls,
    )
}
#[test]
fn exact_inflight_replay_commit_and_detach_preserve_ownership() {
    let (mut c, calls) = client(
        vec![
            Ok(reply(1, 1, 0, vec![original(2)])),
            Ok(reply(2, 1, 0, vec![original(2)])),
            Ok(reply(3, 0, 1, vec![])),
            Ok(reply(4, 0, 1, vec![])),
            Ok(reply(5, 0, 1, vec![])),
        ],
        reply(0, 0, 0, vec![]),
    );
    let d = c.poll().unwrap();
    assert_eq!(c.poll().unwrap().events, d.events);
    c.commit(d.batch_id, &d.batch_sha256).unwrap();
    c.commit(d.batch_id, &d.batch_sha256).unwrap();
    c.close().unwrap();
    assert_eq!(calls.lock().unwrap().ops, [1, 1, 2, 2, 3]);
}
#[test]
fn changed_inflight_or_frontier_terminally_refuses_further_calls() {
    for second in [reply(2, 1, 0, vec![original(4)]), reply(2, 0, 1, vec![])] {
        let (mut c, calls) = client(
            vec![Ok(reply(1, 1, 0, vec![original(3)])), Ok(second)],
            reply(0, 0, 0, vec![]),
        );
        c.poll().unwrap();
        assert!(c.poll().is_err());
        assert!(c.poll().is_err());
        assert_eq!(calls.lock().unwrap().ops.len(), 2);
        assert!(calls.lock().unwrap().invalidated > 0);
    }
}
#[test]
fn lost_ack_is_terminal_but_new_consumer_can_receive_exact_retained_batch() {
    let (mut c, _) = client(
        vec![
            Ok(reply(1, 1, 0, vec![original(2)])),
            Err("Network source exchange failed".into()),
        ],
        reply(0, 0, 0, vec![]),
    );
    let d = c.poll().unwrap();
    assert!(c.commit(d.batch_id, &d.batch_sha256).is_err());
    assert!(c.poll().is_err());
    let (mut next, _) = client(
        vec![Ok(reply(1, 1, 0, vec![original(2)]))],
        reply(0, 0, 0, vec![]),
    );
    let replay = next.poll().unwrap();
    assert_eq!(replay.batch_sha256, d.batch_sha256);
    assert_eq!(replay.events, d.events);
}
#[test]
fn new_consumer_exposes_advanced_ack_frontier_without_inventing_history() {
    let (mut c, _) = client(
        vec![Ok(reply(1, 8, 7, vec![original(9)]))],
        reply(0, 0, 7, vec![]),
    );
    assert_eq!(c.status().last_acked_batch_id, 7);
    assert_eq!(c.poll().unwrap().batch_id, 8);
    // The durable parent must reconcile this frontier, not assume past admission.
}
#[test]
fn shared_native_policy_matches_the_typed_protocol() {
    let h = include_str!("../../../infrastructure/endpoint/macos-network/Shared/NetworkIPC.h");
    assert!(h.contains(&format!(
        "#define AX_NETWORK_POLICY \"{}\"",
        source_policy_sha256()
    )));
}
