use super::*;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, TcpStream, UdpSocket},
};
use windows_sys::Win32::System::Diagnostics::Etw::{TcpIpGuid, UdpIpGuid, EVENT_HEADER};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Connect,
    Accept,
    Send,
    Receive,
    Disconnect,
}
#[derive(Clone, Copy)]
pub(super) struct Kind {
    pub label: &'static str,
    tcp: bool,
    pub ipv6: bool,
    operation: Operation,
}
pub(super) fn kind_header(header: &EVENT_HEADER) -> Option<Kind> {
    let tcp = native::same_guid(header.ProviderId, TcpIpGuid);
    if !tcp && !native::same_guid(header.ProviderId, UdpIpGuid) {
        return None;
    }
    let (label, ipv6, operation) = match (tcp, header.EventDescriptor.Opcode) {
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
pub(super) struct Flow {
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
    pub fn tcp(ipv6: bool) -> Result<Self> {
        let listener = TcpListener::bind(Self::address(ipv6)).map_err(|_| "controlled_traffic")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "controlled_traffic")?;
        let server = listener.local_addr().map_err(|_| "controlled_traffic")?;
        let opened = qpc()?;
        let mut client = TcpStream::connect_timeout(&server, Duration::from_secs(5))
            .map_err(|_| "controlled_traffic")?;
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
                _ => return Err("controlled_traffic"),
            }
        };
        for stream in [&client, &accepted] {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "controlled_traffic")?;
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "controlled_traffic")?;
            stream.set_nodelay(true).map_err(|_| "controlled_traffic")?;
        }
        let client_address = client.local_addr().map_err(|_| "controlled_traffic")?;
        require(
            accepted.peer_addr().map_err(|_| "controlled_traffic")? == client_address,
            "controlled_traffic",
        )?;
        let transferred = qpc()?;
        let payload = [0x35u8; 64];
        let mut received = [0u8; 64];
        client
            .write_all(&payload)
            .map_err(|_| "controlled_traffic")?;
        accepted
            .read_exact(&mut received)
            .map_err(|_| "controlled_traffic")?;
        require(received == payload, "controlled_traffic")?;
        accepted
            .write_all(&payload)
            .map_err(|_| "controlled_traffic")?;
        client
            .read_exact(&mut received)
            .map_err(|_| "controlled_traffic")?;
        require(received == payload, "controlled_traffic")?;
        let closed = qpc()?;
        client
            .shutdown(Shutdown::Both)
            .map_err(|_| "controlled_traffic")?;
        accepted
            .shutdown(Shutdown::Both)
            .map_err(|_| "controlled_traffic")?;
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
    pub fn udp(ipv6: bool) -> Result<Self> {
        let client = UdpSocket::bind(Self::address(ipv6)).map_err(|_| "controlled_traffic")?;
        let server = UdpSocket::bind(Self::address(ipv6)).map_err(|_| "controlled_traffic")?;
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "controlled_traffic")?;
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| "controlled_traffic")?;
        }
        let client_address = client.local_addr().map_err(|_| "controlled_traffic")?;
        let server_address = server.local_addr().map_err(|_| "controlled_traffic")?;
        let opened = qpc()?;
        let payload = [0x71u8; 64];
        let mut received = [0u8; 65];
        require(
            client
                .send_to(&payload, server_address)
                .map_err(|_| "controlled_traffic")?
                == payload.len(),
            "controlled_traffic",
        )?;
        let (size, peer) = server
            .recv_from(&mut received)
            .map_err(|_| "controlled_traffic")?;
        require(
            size == payload.len() && peer == client_address && received[..size] == payload,
            "controlled_traffic",
        )?;
        require(
            server
                .send_to(&payload, client_address)
                .map_err(|_| "controlled_traffic")?
                == payload.len(),
            "controlled_traffic",
        )?;
        let (size, peer) = client
            .recv_from(&mut received)
            .map_err(|_| "controlled_traffic")?;
        require(
            size == payload.len() && peer == server_address && received[..size] == payload,
            "controlled_traffic",
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
    pub fn matches(&self, kind: Kind, report: &schema::Report, timestamp: i64) -> bool {
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

pub(super) fn flows() -> Vec<Flow> {
    vec![
        safe(Flow::tcp(false), "controlled_traffic"),
        safe(Flow::tcp(true), "controlled_traffic"),
        safe(Flow::udp(false), "controlled_traffic"),
        safe(Flow::udp(true), "controlled_traffic"),
    ]
}
pub(super) fn event_kind(event: &WindowsNetworkEvent) -> Kind {
    use athernex_endpoint_protocol::windows_network_events::{
        WindowsNetworkFamily as F, WindowsNetworkOperation as O, WindowsNetworkProtocol as P,
    };
    let tcp = event.protocol == P::Tcp;
    let ipv6 = event.family == F::Ipv6;
    let (label, operation) = match (tcp, ipv6, event.operation) {
        (true, false, O::Connect) => ("tcp4_connect", Operation::Connect),
        (true, false, O::Accept) => ("tcp4_accept", Operation::Accept),
        (true, false, O::Send) => ("tcp4_send", Operation::Send),
        (true, false, O::Receive) => ("tcp4_receive", Operation::Receive),
        (true, false, O::Disconnect) => ("tcp4_disconnect", Operation::Disconnect),
        (true, true, O::Connect) => ("tcp6_connect", Operation::Connect),
        (true, true, O::Accept) => ("tcp6_accept", Operation::Accept),
        (true, true, O::Send) => ("tcp6_send", Operation::Send),
        (true, true, O::Receive) => ("tcp6_receive", Operation::Receive),
        (true, true, O::Disconnect) => ("tcp6_disconnect", Operation::Disconnect),
        (false, false, O::Send) => ("udp4_send", Operation::Send),
        (false, false, O::Receive) => ("udp4_receive", Operation::Receive),
        (false, true, O::Send) => ("udp6_send", Operation::Send),
        (false, true, O::Receive) => ("udp6_receive", Operation::Receive),
        _ => fail("controlled_traffic"),
    };
    Kind {
        label,
        tcp,
        ipv6,
        operation,
    }
}
pub(super) fn select(
    events: Vec<EndpointEvent>,
    flows: &[Flow],
    stream: &str,
) -> BTreeMap<&'static str, EndpointEvent> {
    let mut selected = BTreeMap::new();
    for envelope in events {
        let Some(Telemetry::WindowsNetworkEvent { event }) = &envelope.telemetry else {
            continue;
        };
        let kind = event_kind(event);
        let report = schema::Report {
            pid: event.reported_pid,
            source: event.source,
            destination: event.destination,
            size: event.reported_size,
            pointer_bits: event.header_pointer_bits,
            property_count: 0,
            schema_hash: String::new(),
        };
        if event.original.stream_id == stream
            && flows
                .iter()
                .any(|flow| flow.matches(kind, &report, event.original.header.timestamp_qpc))
        {
            selected.entry(kind.label).or_insert(envelope);
        }
    }
    selected
}
