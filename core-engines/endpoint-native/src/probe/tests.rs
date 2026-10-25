use super::*;
use crate::Verdict;
#[test]
fn denial_evidence_requires_matching_native_operation_actor_file_time_and_verdict() {
    let policy = Policy {
        roots: vec!["/watched".into()],
        socket: "/private/clamd.sock".into(),
        state: "/private/native".into(),
        scanner_uid: 1234,
        scan_timeout_ms: 1000,
    };
    let attempt = Attempt {
        schema: 1,
        nonce: "a".repeat(64),
        operation: Operation::Mmap,
        path: "/watched/probe".into(),
        identity: Identity {
            device: 1,
            inode: 2,
            size: 32,
            modified_sec: 3,
            modified_nsec: 4,
            changed_sec: 5,
            changed_nsec: 6,
        },
        actor: Actor {
            pid: 44,
            uid: 0,
            pidversion: 2,
        },
        time_ms: now_ms(),
    };
    let event = Receipt {
        schema: 1,
        id: "b".repeat(64),
        policy_sha256: receipt::policy_hash(&policy).unwrap(),
        time_ms: attempt.time_ms,
        operation: "mmap".into(),
        response_delivered: true,
        actor: attempt.actor.clone(),
        path: attempt.path.display().to_string(),
        identity: attempt.identity.clone(),
        verdict: Some(Verdict {
            sha256: "c".repeat(64),
            bytes: 32,
            detection: Some("AthernexProbe.UNOFFICIAL".into()),
        }),
        error: String::new(),
    };
    validate_denial(
        &attempt,
        &event,
        &policy,
        &"c".repeat(64),
        "AthernexProbe.UNOFFICIAL",
    )
    .unwrap();
    for field in 0..13 {
        let mut event = event.clone();
        let mut attempt = attempt.clone();
        match field {
            0 => event.actor.pid += 1,
            1 => event.actor.pidversion += 1,
            2 => event.actor.uid += 1,
            3 => event.operation = "open".into(),
            4 => event.identity.inode += 1,
            5 => event.path = "/watched/other".into(),
            6 => event.response_delivered = false,
            7 => event.verdict.as_mut().unwrap().sha256 = "d".repeat(64),
            8 => event.verdict.as_mut().unwrap().detection = Some("OtherSignature".into()),
            9 => {
                event.verdict = None;
                event.error = "Scanner unavailable".into();
            }
            10 => event.time_ms = attempt.time_ms - 1,
            11 => {
                attempt.time_ms -= 20000;
                event.time_ms = attempt.time_ms;
            }
            _ => {
                attempt.actor.uid = 1234;
                event.actor.uid = 1234;
            }
        }
        assert!(
            validate_denial(
                &attempt,
                &event,
                &policy,
                &"c".repeat(64),
                "AthernexProbe.UNOFFICIAL"
            )
            .is_err(),
            "field {field}"
        );
    }
}
