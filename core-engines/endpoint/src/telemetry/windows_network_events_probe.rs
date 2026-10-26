//! Disposable source proof only. No production network collector or wire schema.
mod coexist;
mod native;
mod schema;
mod token;

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    time::{Duration, Instant},
};
use windows_sys::Win32::System::{
    Diagnostics::Etw::{TcpIpGuid, UdpIpGuid},
    Performance::QueryPerformanceCounter,
    RemoteDesktop::ProcessIdToSessionId,
};
type Result<T> = std::result::Result<T, &'static str>;

fn require(value: bool, category: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(category)
    }
}
fn api(operation: &'static str, code: u32) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    // The shared query-only token helper does not widen public diagnostics.
    if operation == "token_query" {
        return Err("token");
    }
    let category = match operation {
        "start_trace" => "session_start",
        "open_trace" => "consumer_start",
        "process_trace" | "close_trace" => "consumer_shutdown",
        "query_trace" => "session_ownership",
        "stop_trace" => "session_cleanup",
        "tdh_information" => "tdh_schema",
        "tdh_property_size" | "tdh_property" => "tdh_property",
        _ => return Err("guard"),
    };
    println!("\nATHERNEX_NETWORK_SOURCE_DIAGNOSTIC={operation}:{code}");
    Err(category)
}
fn category(error: &str) -> &'static str {
    match error {
        "guard" | "token" | "session_ownership" | "session_start" | "consumer_start"
        | "callback_bounds" | "callback_overflow" | "traffic" | "timeout" | "tdh_schema"
        | "tdh_property" | "controlled_match" | "source_loss" | "session_cleanup"
        | "consumer_shutdown" => match error {
            "guard" => "guard",
            "token" => "token",
            "session_ownership" => "session_ownership",
            "session_start" => "session_start",
            "consumer_start" => "consumer_start",
            "callback_bounds" => "callback_bounds",
            "callback_overflow" => "callback_overflow",
            "traffic" => "traffic",
            "timeout" => "timeout",
            "tdh_schema" => "tdh_schema",
            "tdh_property" => "tdh_property",
            "controlled_match" => "controlled_match",
            "source_loss" => "source_loss",
            "session_cleanup" => "session_cleanup",
            _ => "consumer_shutdown",
        },
        "Native source reports lost records" | "Native source lost records during shutdown" => {
            "source_loss"
        }
        "Native callback lost records before shutdown" => "callback_overflow",
        "Owned trace session removal was not verified" => "session_cleanup",
        "Native network consumer handle invalid"
        | "Native consumer thread could not start"
        | "Native consumer startup timeout"
        | "Native consumer exited unexpectedly" => "consumer_start",
        "Native consumer panicked" => "consumer_shutdown",
        value if value.starts_with("Session ") => "session_ownership",
        value if value.starts_with("Token ") || value.ends_with("token handle missing") => "token",
        value
            if value.starts_with("TDH scalar")
                || value.starts_with("Required network schema property")
                || value.starts_with("Network schema property")
                || value == "Invalid scalar bytes" =>
        {
            "tdh_property"
        }
        _ => "tdh_schema",
    }
}
fn failure(error: &str) {
    println!("\nATHERNEX_NETWORK_SOURCE_FAILURE={}", category(error));
}
fn qpc() -> Result<i64> {
    let mut value = 0;
    require(
        unsafe { QueryPerformanceCounter(&mut value) } != 0 && value > 0,
        "guard",
    )?;
    Ok(value)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Connect,
    Accept,
    Send,
    Receive,
    Disconnect,
}
#[derive(Clone, Copy)]
struct Kind {
    label: &'static str,
    tcp: bool,
    ipv6: bool,
    operation: Operation,
}
fn kind(original: &native::Original) -> Option<Kind> {
    let tcp = native::same_guid(original.header.ProviderId, TcpIpGuid);
    if !tcp && !native::same_guid(original.header.ProviderId, UdpIpGuid) {
        return None;
    }
    let (label, ipv6, operation) = match (tcp, original.header.EventDescriptor.Opcode) {
        (true, 10) => ("tcp4_send", false, Operation::Send),
        (true, 11) => ("tcp4_receive", false, Operation::Receive),
        (true, 12) => ("tcp4_connect", false, Operation::Connect),
        (true, 13) => ("tcp4_disconnect", false, Operation::Disconnect),
        (true, 15) => ("tcp4_accept", false, Operation::Accept),
        (true, 26) => ("tcp6_send", true, Operation::Send),
        (true, 27) => ("tcp6_receive", true, Operation::Receive),
        (true, 28) => ("tcp6_connect", true, Operation::Connect),
        (true, 29) => ("tcp6_disconnect", true, Operation::Disconnect),
        (true, 31) => ("tcp6_accept", true, Operation::Accept),
        (false, 10) => ("udp4_send", false, Operation::Send),
        (false, 11) => ("udp4_receive", false, Operation::Receive),
        (false, 26) => ("udp6_send", true, Operation::Send),
        (false, 27) => ("udp6_receive", true, Operation::Receive),
        _ => return None,
    };
    Some(Kind {
        label,
        tcp,
        ipv6,
        operation,
    })
}
struct Flow {
    tcp: bool,
    ipv6: bool,
    client: SocketAddr,
    server: SocketAddr,
    opened: i64,
    transferred: i64,
    closed: i64,
    // Keep owned listeners/datagram endpoints alive while matching records.
    _tcp_listener: Option<TcpListener>,
    _udp_sockets: Option<(UdpSocket, UdpSocket)>,
}
impl Flow {
    fn address(ipv6: bool) -> SocketAddr {
        SocketAddr::new(
            if ipv6 {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            },
            0,
        )
    }
    fn tcp(ipv6: bool) -> Result<Self> {
        let listener = TcpListener::bind(Self::address(ipv6)).map_err(|_| "traffic")?;
        listener.set_nonblocking(true).map_err(|_| "traffic")?;
        let server = listener.local_addr().map_err(|_| "traffic")?;
        let opened = qpc()?;
        let mut client =
            TcpStream::connect_timeout(&server, Duration::from_secs(5)).map_err(|_| "traffic")?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut accepted = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                _ => return Err("traffic"),
            }
        };
        for stream in [&client, &accepted] {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "traffic")?;
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "traffic")?;
            stream.set_nodelay(true).map_err(|_| "traffic")?;
        }
        let client_address = client.local_addr().map_err(|_| "traffic")?;
        require(
            accepted.peer_addr().map_err(|_| "traffic")? == client_address,
            "controlled_match",
        )?;
        let transferred = qpc()?;
        let payload = [0x35u8; 64];
        let mut received = [0u8; 64];
        client.write_all(&payload).map_err(|_| "traffic")?;
        accepted.read_exact(&mut received).map_err(|_| "traffic")?;
        require(received == payload, "traffic")?;
        accepted.write_all(&payload).map_err(|_| "traffic")?;
        client.read_exact(&mut received).map_err(|_| "traffic")?;
        require(received == payload, "traffic")?;
        let closed = qpc()?;
        client.shutdown(Shutdown::Both).map_err(|_| "traffic")?;
        accepted.shutdown(Shutdown::Both).map_err(|_| "traffic")?;
        drop(client);
        drop(accepted);
        Ok(Self {
            tcp: true,
            ipv6,
            client: client_address,
            server,
            opened,
            transferred,
            closed,
            _tcp_listener: Some(listener),
            _udp_sockets: None,
        })
    }
    fn udp(ipv6: bool) -> Result<Self> {
        let client = UdpSocket::bind(Self::address(ipv6)).map_err(|_| "traffic")?;
        let server = UdpSocket::bind(Self::address(ipv6)).map_err(|_| "traffic")?;
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "traffic")?;
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "traffic")?;
        }
        let client_address = client.local_addr().map_err(|_| "traffic")?;
        let server_address = server.local_addr().map_err(|_| "traffic")?;
        let opened = qpc()?;
        let payload = [0x71u8; 64];
        let mut received = [0u8; 65];
        require(
            client
                .send_to(&payload, server_address)
                .map_err(|_| "traffic")?
                == payload.len(),
            "traffic",
        )?;
        let (size, peer) = server.recv_from(&mut received).map_err(|_| "traffic")?;
        require(
            size == payload.len() && peer == client_address && received[..size] == payload,
            "traffic",
        )?;
        require(
            server
                .send_to(&payload, client_address)
                .map_err(|_| "traffic")?
                == payload.len(),
            "traffic",
        )?;
        let (size, peer) = client.recv_from(&mut received).map_err(|_| "traffic")?;
        require(
            size == payload.len() && peer == server_address && received[..size] == payload,
            "traffic",
        )?;
        Ok(Self {
            tcp: false,
            ipv6,
            client: client_address,
            server: server_address,
            opened,
            transferred: opened,
            closed: 0,
            _tcp_listener: None,
            _udp_sockets: Some((client, server)),
        })
    }
    fn matches(&self, kind: Kind, report: &schema::Report, timestamp: i64) -> bool {
        let bound = match kind.operation {
            Operation::Connect | Operation::Accept => self.opened,
            Operation::Disconnect => self.closed,
            _ => self.transferred,
        };
        self.tcp == kind.tcp
            && self.ipv6 == kind.ipv6
            && timestamp >= bound
            && report.pid == std::process::id()
            && ((report.source == self.client && report.destination == self.server)
                || (report.source == self.server && report.destination == self.client))
            && (!matches!(kind.operation, Operation::Send | Operation::Receive) || report.size > 0)
    }
}
fn observe(source: &native::Source, coexist: &mut coexist::Coexist<'_>) -> Result<()> {
    coexist.child()?;
    let flows = [
        Flow::tcp(false)?,
        Flow::tcp(true)?,
        Flow::udp(false)?,
        Flow::udp(true)?,
    ];
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut schemas = BTreeMap::new();
    let mut originals = Vec::new();
    let mut total = 0usize;
    while Instant::now() < deadline {
        source.check()?;
        coexist.check()?;
        for original in source.drain()? {
            require(Instant::now() < deadline, "timeout")?;
            source.check_original(&original)?;
            let Some(kind) = kind(&original) else {
                continue;
            };
            let report = schema::decode(&original, kind.ipv6)?;
            if !flows
                .iter()
                .any(|flow| flow.matches(kind, &report, original.header.TimeStamp))
            {
                continue;
            }
            let structural = (
                original.header.EventDescriptor.Version,
                report.pointer_bits,
                report.property_count,
                report.schema_hash,
            );
            if let Some(previous) = schemas.get(kind.label) {
                require(previous == &structural, "tdh_schema")?;
            } else {
                println!(
                    "\nATHERNEX_NETWORK_SOURCE_SCHEMA={}:{}:{}:{}:{}",
                    kind.label, structural.0, structural.1, structural.2, structural.3
                );
                schemas.insert(kind.label, structural);
                total = total
                    .checked_add(original.data().len())
                    .ok_or("callback_bounds")?;
                require(total <= 1024 * 1024, "callback_bounds")?;
                originals.push(original); // Private owned source bytes survive all proof checks.
            }
        }
        if schemas.len() == 14 {
            coexist.verify_child()?;
            coexist.check()?;
            source.check()?;
            println!("\nATHERNEX_NETWORK_SOURCE_STAGE=coexistence_verified");
            println!("\nATHERNEX_NETWORK_SOURCE_STAGE=tcp4_verified");
            println!("\nATHERNEX_NETWORK_SOURCE_STAGE=tcp6_verified");
            println!("\nATHERNEX_NETWORK_SOURCE_STAGE=udp4_verified");
            println!("\nATHERNEX_NETWORK_SOURCE_STAGE=udp6_verified");
            println!("\nATHERNEX_NETWORK_SOURCE_STAGE=tdh_verified");
            println!("\nATHERNEX_NETWORK_SOURCE_STAGE=source_loss_verified");
            require(originals.len() == 14, "controlled_match")?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("timeout")
}

#[test]
#[ignore = "Requires explicitly disposable LocalSystem/session-zero Windows and starts an owned network ETW source alongside the production process collector"]
fn owned_network_source_reports_controlled_tcp_udp() {
    let guard = || -> Result<()> {
        require(
            std::env::var("ATHERNEX_WINDOWS_NETWORK_EVENTS_PROBE_DISPOSABLE_HOST").as_deref()
                == Ok("1"),
            "guard",
        )?;
        require(
            athernex_endpoint_native::windows_state::require_local_system().is_ok(),
            "guard",
        )?;
        let mut session = u32::MAX;
        require(
            unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } != 0 && session == 0,
            "guard",
        )
    };
    guard().unwrap_or_else(|error| {
        failure(error);
        panic!("Network source fixture guard failed");
    });
    let before = token::snapshot().unwrap_or_else(|error| {
        failure(error);
        panic!("Token snapshot failed");
    });
    require(before.unimpersonated(), "guard").unwrap_or_else(|error| {
        failure(error);
        panic!("Network source fixture requires its original thread");
    });
    println!("\nATHERNEX_NETWORK_SOURCE_STAGE=guard_verified");
    native::callback_copies_relocatable_owned_payload_and_rejects_invalid_bounds();
    schema::property_names_and_scalar_metadata_are_bounded_and_typed();
    fixed_failure_categories_do_not_expose_values();
    let outcome = std::panic::catch_unwind(|| -> Result<()> {
        let executable = std::env::current_exe().map_err(|_| "guard")?;
        let parent = executable.parent().ok_or("guard")?;
        // The source-bound runner stages this exact executable in its protected
        // System/Admin directory. Never use the general SYSTEM temp directory.
        let private = tempfile::Builder::new()
            .prefix("network-source-")
            .tempdir_in(parent)
            .map_err(|_| "guard")?;
        let store = crate::Store::open(private.path()).map_err(|_| "session_start")?;
        let mut coexist = coexist::Coexist::start(&store)?;
        let mut source = native::Source::start()?;
        println!("\nATHERNEX_NETWORK_SOURCE_STAGE=session_ready");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observe(&source, &mut coexist)
        }));
        let network_cleanup = source.close();
        let process_cleanup = coexist.close();
        for error in [
            network_cleanup.as_ref().err(),
            process_cleanup.as_ref().err(),
        ]
        .into_iter()
        .flatten()
        {
            failure(error);
        }
        network_cleanup?;
        process_cleanup?;
        println!("\nATHERNEX_NETWORK_SOURCE_STAGE=cleanup_verified");
        result.map_err(|_| "controlled_match")?
    });
    let after = token::snapshot();
    let token_equal = after.as_ref().is_ok_and(|value| value == &before);
    if !token_equal {
        failure("token");
    }
    if let Ok(Err(error)) = &outcome {
        failure(error);
    }
    assert!(token_equal, "Network source fixture changed token state");
    println!("\nATHERNEX_NETWORK_SOURCE_STAGE=token_verified");
    assert!(
        matches!(outcome, Ok(Ok(()))),
        "Native network source proof failed"
    );
    println!("\nATHERNEX_NETWORK_SOURCE_STAGE=passed");
}
#[test]
fn fixed_failure_categories_do_not_expose_values() {
    let allowed = BTreeSet::from([
        "guard",
        "token",
        "session_ownership",
        "session_start",
        "consumer_start",
        "callback_bounds",
        "callback_overflow",
        "traffic",
        "timeout",
        "tdh_schema",
        "tdh_property",
        "controlled_match",
        "source_loss",
        "session_cleanup",
        "consumer_shutdown",
    ]);
    for text in [
        "private source values\nATHERNEX_NETWORK_SOURCE_STAGE=passed",
        "TDH scalar property size differs",
        "Session GUID ownership differs",
        "Token privilege size probe invalid",
        "Native callback lost records before shutdown",
    ] {
        assert!(allowed.contains(category(text)));
    }
}
