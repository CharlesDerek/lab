use super::queue::{Counters, Queue, Shared};
use super::*;
use athernex_endpoint_protocol::macos_process_events::*;
use std::{
    io::Write,
    os::unix::net::UnixStream,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(super) fn event(sequence: u64, path_size: usize) -> MacosProcessEvent {
    let mut token = [0; 8];
    token[5] = 41;
    token[7] = 2;
    MacosProcessEvent::from_original(MacosProcessOriginal {
        projection_version: 1,
        stream_id: "a".repeat(64),
        receipt_sequence: sequence,
        message_version: 5,
        event_type: 15,
        action_type: 1,
        notify_result: MacosNotifyResult::Auth { result: 0 },
        time: MacosEventTime {
            seconds: (now_ms() / 1000) as i64,
            nanoseconds: 123,
        },
        mach_time: 7,
        mach_timebase: MacosMachTimebase {
            numerator: 125,
            denominator: 3,
        },
        seq_num: sequence,
        global_seq_num: sequence,
        actor: MacosProcessProjection {
            audit_token: token,
            parent_audit_token: [0; 8],
            responsible_audit_token: token,
            ppid: 1,
            original_ppid: 1,
            group_id: 41,
            session_id: 1,
            executable: MacosExecutable {
                path_bytes_hex: "61".repeat(path_size),
                path_truncated: false,
            },
        },
        event: MacosProcessPayload::Exit {
            raw_wait_status: 7 << 8,
        },
    })
    .unwrap()
}
pub(super) fn status() -> Status {
    let time = now_ms();
    Status {
        health: MacosProcessEventHealth {
            stream_id: "a".repeat(64),
            state: "active".into(),
            source_policy_sha256: source_policy_sha256(),
            started_ms: time,
            checked_ms: time,
            scope_checked_ms: time,
            subscriptions: 3,
            received_records: 10000,
            mute_snapshot_sha256: "b".repeat(64),
            ..Default::default()
        },
        pending_records: 0,
        pending_bytes: 0,
    }
}

#[test]
fn committed_batches_replay_exactly_and_release_only_the_matching_batch() {
    let mut q = Queue::default();
    for n in 1..=70 {
        assert!(q.push(event(n, 4)).unwrap());
    }
    let first = q.delivery(status()).unwrap();
    assert_eq!(first.events.len(), 64);
    assert_eq!(first.status.pending_records, 70);
    let frozen = serde_json::to_vec(&first.events).unwrap();
    assert!(q.acknowledge(0).is_err());
    assert!(q.acknowledge(2).is_err());
    assert_eq!(
        serde_json::to_vec(&q.delivery(status()).unwrap().events).unwrap(),
        frozen
    );
    q.acknowledge(1).unwrap();
    q.acknowledge(1).unwrap();
    let second = q.delivery(status()).unwrap();
    assert_eq!(second.batch_id, 2);
    assert_eq!(second.events.len(), 6);
    assert_eq!(second.events[0].original.receipt_sequence, 65);
    assert_eq!(second.status.pending_records, 6);
    q.acknowledge(1).unwrap(); // Repeating the last ACK cannot free the next batch.
    assert_eq!(q.delivery(status()).unwrap().events.len(), 6);
    q.acknowledge(2).unwrap();
    let empty = q.delivery(status()).unwrap();
    assert_eq!(empty.batch_id, 0);
    assert!(empty.events.is_empty());
    assert_eq!(empty.status.pending_bytes, 0);
}

#[test]
fn queue_retains_inflight_capacity_and_enforces_independent_byte_and_record_limits() {
    let mut q = Queue::default();
    for n in 1..=MAX_RECORDS {
        assert!(q.push(event(n as u64, 0)).unwrap());
    }
    assert!(!q.push(event(9999, 0)).unwrap());
    let full = q.delivery(status()).unwrap();
    assert!(full.status.health.backpressured);
    assert!(!q.push(event(9999, 0)).unwrap());
    q.acknowledge(full.batch_id).unwrap();
    assert!(q.push(event(9999, 0)).unwrap());

    let mut bytes = Queue::default();
    let mut admitted = 0;
    for n in 1..=MAX_RECORDS {
        if !bytes.push(event(n as u64, MAX_PATH_BYTES)).unwrap() {
            break;
        }
        admitted += 1;
    }
    assert!(admitted > 1 && admitted < MAX_RECORDS);
    let batch = bytes.delivery(status()).unwrap();
    assert!(batch.status.pending_bytes <= MAX_QUEUE_BYTES as u64);
    assert!(batch.status.health.backpressured);
    let response = transport::Response {
        version: 1,
        nonce: "c".repeat(64),
        stream_id: "a".repeat(64),
        reply: transport::Reply::Batch { delivery: batch },
    };
    assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_FRAME_BYTES);
}

#[test]
fn first_sequences_are_baselines_and_loss_channels_do_not_double_count() {
    let c = Counters::default();
    c.sequences(0, 0, 0);
    c.sequences(1, 98, 1);
    c.sequences(0, 1, 2);
    assert_eq!(c.global_gaps.load(Ordering::SeqCst), 0);
    assert_eq!(c.type_gaps.load(Ordering::SeqCst), 0);
    c.unknown_event_sequence(3);
    c.sequences(0, 3, 6);
    assert_eq!(c.global_gaps.load(Ordering::SeqCst), 2);
    assert_eq!(c.type_gaps.load(Ordering::SeqCst), 1);
    c.sequences(0, 3, 6);
    assert_eq!(c.regressions.load(Ordering::SeqCst), 2);
    let mut s = status();
    c.apply(&mut s);
    assert_eq!(s.health.state, "degraded");
    assert!(!s.health.healthy(now_ms()));
    c.received.store(u64::MAX, Ordering::SeqCst);
    assert!(c.receive().is_none());
    assert!(c.failed.load(Ordering::SeqCst));
}

#[test]
fn callback_panic_and_late_delivery_are_fixed_failures_with_balanced_active_count() {
    let shared = Shared::default();
    shared.callback(|| panic!("synthetic callback failure"));
    assert!(shared.counters.failed.load(Ordering::SeqCst));
    assert_eq!(shared.callbacks.load(Ordering::SeqCst), 0);
    shared.closing.store(true, Ordering::SeqCst);
    shared.callback(|| panic!("late callback must not enter application code"));
    assert_eq!(shared.callbacks.load(Ordering::SeqCst), 0);
    assert_eq!(
        shared
            .queue
            .lock()
            .unwrap()
            .delivery(status())
            .unwrap()
            .status
            .pending_records,
        0
    );
}

#[test]
fn callback_contention_refuses_with_observable_drop_and_no_unbounded_wait() {
    let shared = Shared::default();
    let held = shared.queue.lock().unwrap();
    shared.enqueue(event(1, 1));
    assert_eq!(shared.counters.drops.load(Ordering::SeqCst), 1);
    drop(held);
    shared.enqueue(event(2, 1));
    let delivered = shared.queue.lock().unwrap().delivery(status()).unwrap();
    assert_eq!(delivered.events[0].original.receipt_sequence, 2);
}

#[test]
fn transport_bounds_partial_frames_and_rejects_unknown_or_trailing_data() {
    for bytes in [
        Vec::new(),
        vec![0xff; 4],
        (MAX_FRAME_BYTES as u32 + 1).to_be_bytes().to_vec(),
    ] {
        let (mut read, mut write) = UnixStream::pair().unwrap();
        write.write_all(&bytes).unwrap();
        drop(write);
        assert!(transport::read::<transport::Request>(
            &mut read,
            4096,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
    }
    for payload in [
        b"{}".as_slice(),
        br#"{"version":1,"nonce":"n","stream_id":"s","command":{"type":"poll"},"extra":0}"#,
        br#"{"version":1,"nonce":"n","stream_id":"s","command":{"type":"poll"}} {}"#,
    ] {
        let (mut read, mut write) = UnixStream::pair().unwrap();
        write
            .write_all(&(payload.len() as u32).to_be_bytes())
            .unwrap();
        write.write_all(payload).unwrap();
        drop(write);
        assert!(transport::read::<transport::Request>(
            &mut read,
            4096,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
    }
    let (mut read, _write) = UnixStream::pair().unwrap();
    let start = Instant::now();
    assert!(transport::read::<transport::Request>(
        &mut read,
        4096,
        start + Duration::from_millis(30)
    )
    .is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn transport_preserves_exact_projection_and_independent_status() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let response = transport::Response {
        version: 1,
        nonce: "c".repeat(64),
        stream_id: "a".repeat(64),
        reply: transport::Reply::Batch {
            delivery: Delivery {
                batch_id: 1,
                events: vec![event(1, 5)],
                status: status(),
            },
        },
    };
    let expected = serde_json::to_vec(&response).unwrap();
    transport::write(&mut a, &response, Instant::now() + Duration::from_secs(1)).unwrap();
    let actual: transport::Response = transport::read(
        &mut b,
        MAX_FRAME_BYTES,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(serde_json::to_vec(&actual).unwrap(), expected);
}

#[test]
fn status_and_projection_refuse_cross_stream_or_parent_owned_counters() {
    let mut s = status();
    s.validate(&"a".repeat(64)).unwrap();
    assert!(s.validate(&"b".repeat(64)).is_err());
    s.health.queue_drops = 1;
    assert!(s.validate(&"a".repeat(64)).is_err());
    s.health.queue_drops = 0;
    s.health.admitted_records = 1;
    s.health.received_records = 1;
    assert!(s.validate(&"a".repeat(64)).is_err());
    let mut delivery = Delivery {
        batch_id: 1,
        events: vec![event(2, 2), event(1, 2)],
        status: status(),
    };
    delivery.status.pending_records = 2;
    assert!(delivery.validate(&"a".repeat(64)).is_err());
    delivery.events.reverse();
    delivery.validate(&"a".repeat(64)).unwrap();
    delivery.status.health.received_records = 1;
    assert!(delivery.validate(&"a".repeat(64)).is_err());
    delivery.status.health.received_records = 10000;
    delivery.batch_id = 0;
    assert!(delivery.validate(&"a".repeat(64)).is_err());
}

#[test]
fn shared_framing_preserves_existing_process_command_wire_and_rejects_auth_policy() {
    let request = transport::Request {
        version: 1,
        nonce: "n".into(),
        stream_id: "s".into(),
        command: transport::Command::Ack { batch_id: 7 },
    };
    assert_eq!(
        serde_json::to_string(&request).unwrap(),
        r#"{"version":1,"nonce":"n","stream_id":"s","command":{"type":"ack","batch_id":7}}"#
    );
    let mut source = status();
    source.health.source_policy_sha256 =
        athernex_endpoint_protocol::macos_authentication::source_policy_sha256();
    assert!(source.validate(&"a".repeat(64)).is_err());
}

#[test]
fn parent86_process_status_delivery_policy_and_event_id_are_byte_identical() {
    // Parent9b8a718 declarations/policy were independently serialized for this
    // fixed synthetic fixture; these constants are not generated by this test.
    use sha2::{Digest, Sha256};
    let mut original = event(1, 3).original;
    original.time.seconds = 2;
    let event = MacosProcessEvent::from_original(original).unwrap();
    let mut source = status();
    source.health.started_ms = 1000;
    source.health.checked_ms = 1000;
    source.health.scope_checked_ms = 1000;
    source.pending_records = 1;
    source.pending_bytes = 777;
    assert_eq!(
        source_policy_sha256(),
        "49d32b862e130daff289ee09c6f12e9df0bddf9fe7def963bfe1debea2c5eb60"
    );
    assert_eq!(
        event.event_id(),
        "735d3e7aa5ce30f26b039200b63927a87eefb5162894dff24b2b8da7b8f40bde"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(serde_json::to_vec(&source).unwrap())),
        "0afe3a640ec199e4e2b40438dfe3feb04266d3a8c7d5590514f728ed5639fec7"
    );
    let delivery = Delivery {
        batch_id: 1,
        events: vec![event],
        status: source,
    };
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&delivery).unwrap())
        ),
        "91ab771ca30a2318ce7aa198f3fcefd4d77c22d6f7837706dc82b6159eb8d005"
    );
}
