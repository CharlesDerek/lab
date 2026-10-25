use super::{engine, wire};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
fn notification() -> wire::Notification {
    let mut value: wire::Notification = unsafe { std::mem::zeroed() };
    value.version = wire::VERSION;
    value.operation = wire::SCAN;
    value.request_id = 17;
    let path: Vec<_> = "\\Device\\HarddiskVolume3\\protected\\sample"
        .encode_utf16()
        .collect();
    value.path_characters = path.len() as u32;
    value.path[..path.len()].copy_from_slice(&path);
    value
}
#[test]
fn policy_digest_binds_scope_order_deadline_and_unused_bytes() {
    let roots = vec![
        "\\Device\\HarddiskVolume3\\protected".into(),
        "\\Device\\HarddiskVolume3\\other".into(),
    ];
    let config = wire::Configuration::new(&roots, 1000).unwrap();
    config.validate().unwrap();
    assert_ne!(
        config.policy_sha256,
        wire::Configuration::new(&roots, 1001)
            .unwrap()
            .policy_sha256
    );
    let mut reversed = roots.clone();
    reversed.reverse();
    assert_ne!(
        config.policy_sha256,
        wire::Configuration::new(&reversed, 1000)
            .unwrap()
            .policy_sha256
    );
    let mut changed = config;
    changed.roots[0].path[10] = b'X' as u16;
    assert!(changed.validate().is_err());
    changed = config;
    changed.roots[15].path[1023] = 1;
    assert!(changed.validate().is_err());
    changed = config;
    changed.root_count = u32::MAX;
    assert!(changed.validate().is_err());
    for root in [
        "C:\\protected",
        "\\??\\C:\\protected",
        "\\Device\\HarddiskVolume3\\..\\protected",
        "\\Device\\HarddiskVolume3\\protected\\",
        "\\Device\\HarddiskVolume3\\protected:stream",
        "\\Device\\HarddiskVolume3\\a\0b",
    ] {
        assert!(
            wire::Configuration::new(&[root.into()], 1000).is_err(),
            "{root:?}"
        );
    }
    let emoji = format!("\\Device\\HarddiskVolume3\\{}", "🦀".repeat(500));
    assert!(wire::Configuration::new(&[emoji], 1000).is_err());
}
#[test]
fn kernel_message_bounds_identity_and_verdicts_are_checked_before_use() {
    let mut message = notification();
    assert!(message.validate().is_ok());
    for size in [0, 1024, u32::MAX] {
        message.path_characters = size;
        assert!(message.validate().is_err());
    }
    message = notification();
    message.path[1023] = 1;
    assert!(message.validate().is_err());
    message = notification();
    message.bytes = crate::MAX_FILE + 1;
    assert!(message.validate().is_err());
    message = notification();
    let mut mapping = wire::Mapping {
        version: wire::VERSION,
        request_id: 17,
        ..Default::default()
    };
    mapping.validate(&message).unwrap();
    mapping.version = 1;
    assert!(mapping.validate(&message).is_err());
    mapping.version = wire::VERSION;
    mapping.section_handle = 1234;
    assert!(mapping.validate(&message).is_err());
    mapping.section_handle = 0;
    mapping.request_id += 1;
    assert!(mapping.validate(&message).is_err());
    let verdict = crate::Verdict {
        sha256: "a".repeat(64),
        bytes: 1,
        detection: Some("Fixture.Signature".into()),
    };
    let mut reply = wire::Reply::verdict(17, &verdict).unwrap();
    assert_eq!(
        reply.detection(17).unwrap().as_deref(),
        Some("Fixture.Signature")
    );
    assert!(reply.detection(18).is_err());
    reply.detection[255] = b'X';
    assert!(reply.detection(17).is_err());
    reply = wire::Reply::verdict(17, &verdict).unwrap();
    reply.verdict = wire::CLEAN;
    assert!(reply.detection(17).is_err());
    assert!(wire::Reply::error(17).detection(17).unwrap().is_none());
}
#[test]
fn only_matching_applied_kernel_decisions_become_observations() {
    use super::evidence::Observation;
    let mut file = notification();
    file.operation = wire::APPLIED;
    file.policy_sha256 = [7; 32];
    file.file_id = [19; 16];
    let reply = wire::Reply::verdict(
        file.request_id,
        &crate::Verdict {
            sha256: "b".repeat(64),
            bytes: 0,
            detection: Some("Fixture.Signature".into()),
        },
    )
    .unwrap();
    let applied = wire::Applied {
        file,
        decision: reply,
        status: 0xc0000022u32 as i32,
        reserved: 0,
    };
    let observation = Observation::applied(applied, &[7; 32], 1000).unwrap();
    assert_eq!(observation.file_id, "13".repeat(16));
    assert_eq!(observation.outcome, "denied_malware");
    let replay: Observation =
        serde_json::from_slice(&serde_json::to_vec(&observation).unwrap()).unwrap();
    replay.validate(1000).unwrap();
    assert!(Observation::applied(applied, &[8; 32], 1000).is_err());
    let mut changed = applied;
    changed.file.operation = wire::SCAN;
    assert!(Observation::applied(changed, &[7; 32], 1000).is_err());
    changed = applied;
    changed.status = 0;
    assert!(Observation::applied(changed, &[7; 32], 1000).is_err());
    changed = applied;
    changed.reserved = 1;
    assert!(Observation::applied(changed, &[7; 32], 1000).is_err());
}
fn scan_fixture(data: &[u8], response: &[u8]) -> crate::Result<crate::Verdict> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let response = response.to_vec();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut command = [0; 10];
        stream.read_exact(&mut command).unwrap();
        assert_eq!(&command, b"zINSTREAM\0");
        let mut received = Vec::new();
        loop {
            let mut length = [0; 4];
            stream.read_exact(&mut length).unwrap();
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 {
                break;
            }
            assert!(length <= 65536 && received.len() + length < 1024 * 1024);
            let offset = received.len();
            received.resize(offset + length, 0);
            stream.read_exact(&mut received[offset..]).unwrap();
        }
        stream.write_all(&response).unwrap();
        received
    });
    let mut stream = TcpStream::connect(address).unwrap();
    let result = engine::scan(
        &mut stream,
        data.len() as u64,
        Instant::now() + Duration::from_secs(2),
        |offset, buffer| {
            buffer.copy_from_slice(&data[offset as usize..offset as usize + buffer.len()]);
            Ok(())
        },
    );
    drop(stream);
    assert_eq!(server.join().unwrap(), data);
    result
}
#[test]
fn scanner_hashes_the_entire_stream_including_empty_and_multiple_chunks() {
    for bytes in [Vec::new(), b"fixture".to_vec(), vec![37; 180_003]] {
        for response in [
            b"stream: OK\0".as_slice(),
            b"stream: AthernexFixture FOUND\0".as_slice(),
        ] {
            let result = scan_fixture(&bytes, response).unwrap();
            assert_eq!(result.sha256, format!("{:x}", Sha256::digest(&bytes)));
            assert_eq!(result.bytes, bytes.len() as u64);
            assert_eq!(result.detection.is_some(), response != b"stream: OK\0");
        }
    }
}
#[test]
fn scanner_errors_and_malformed_replies_never_become_clean() {
    for response in [
        b"stream: scan failed ERROR\0".to_vec(),
        b"OK\0".to_vec(),
        b"stream:  FOUND\0".to_vec(),
        b"stream: bad\nlabel FOUND\0".to_vec(),
        [vec![b'x'; 1025], vec![0]].concat(),
    ] {
        assert!(scan_fixture(b"approved bytes", &response).is_err());
    }
}
#[test]
fn scanner_deadline_and_file_budget_refuse_before_reading_source() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_server, _) = listener.accept().unwrap();
    for (bytes, deadline) in [
        (crate::MAX_FILE + 1, Instant::now() + Duration::from_secs(1)),
        (1, Instant::now() - Duration::from_secs(1)),
    ] {
        assert!(engine::scan(&mut stream, bytes, deadline, |_, _| panic!(
            "source must not be touched"
        ))
        .is_err());
    }
}
#[test]
#[ignore = "Requires the isolated real-ClamAV TCP fixture; no simulated verdicts"]
fn real_engine_whole_stream() {
    let address = std::env::var("ATHERNEX_NATIVE_SCANNER_ADDR")
        .expect("Set only inside the isolated scanner fixture");
    for (bytes, infected) in [
        (b"clean native Windows transport fixture".as_slice(), false),
        (
            b"Athernex native Windows stream signature fixture".as_slice(),
            true,
        ),
    ] {
        let mut stream = TcpStream::connect(&address).unwrap();
        let result = engine::scan(
            &mut stream,
            bytes.len() as u64,
            Instant::now() + Duration::from_secs(5),
            |offset, buffer| {
                buffer.copy_from_slice(&bytes[offset as usize..offset as usize + buffer.len()]);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(result.detection.is_some(), infected);
        assert_eq!(result.sha256, format!("{:x}", Sha256::digest(bytes)));
        assert_eq!(result.bytes, bytes.len() as u64);
    }
}

#[cfg(windows)]
#[test]
fn windows_client_refuses_remote_engine_before_connecting_a_driver() {
    use super::client::{self, Counters, Scanner};
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        sync::{atomic::AtomicBool, mpsc, Arc},
    };
    let config =
        wire::Configuration::new(&["\\Device\\HarddiskVolume3\\protected".into()], 1000).unwrap();
    let (events, _) = mpsc::sync_channel(1);
    let result = client::run(
        config,
        Scanner {
            address: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3310),
            pid: 1,
            created: 1,
        },
        events,
        Arc::new(AtomicBool::new(false)),
        Arc::new(Counters::default()),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("pinned local process"));
}

#[cfg(windows)]
#[test]
fn windows_scanner_connection_binds_the_actual_tcp_peer_and_creation_time() {
    use super::peer::EngineConnection;
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes},
    };
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    assert_ne!(
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        },
        0
    );
    let created = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    let pid = unsafe { GetCurrentProcessId() };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
        panic!()
    };
    assert!(EngineConnection::connect(
        address,
        pid,
        created + 1,
        Instant::now() + Duration::from_secs(1)
    )
    .is_err());
    let (stop, exit) = std::sync::mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        let (_socket, _) = listener.accept().unwrap();
        exit.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    let peer = EngineConnection::connect(
        address,
        pid,
        created,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    peer.alive().unwrap();
    drop(peer);
    stop.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn status_requires_a_current_abi_and_driver_load_identity() {
    assert_eq!(std::mem::offset_of!(wire::Status, instance), 48);
    assert_eq!(std::mem::offset_of!(wire::Status, policy_sha256), 64);
    let good = wire::Status {
        version: wire::VERSION,
        instance: [1; 16],
        armed: 1,
        connected: 1,
        policy_sha256: [2; 32],
        ..Default::default()
    };
    good.validate().unwrap();
    for invalid in [
        wire::Status { version: 1, ..good },
        wire::Status {
            instance: [0; 16],
            ..good
        },
        wire::Status {
            pending: 65,
            ..good
        },
        wire::Status { armed: 2, ..good },
        wire::Status {
            policy_sha256: [0; 32],
            ..good
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}
