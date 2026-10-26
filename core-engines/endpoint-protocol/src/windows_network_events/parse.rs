//! Exact v2/64-bit layouts passed native controlled TDH/raw differential checks
//! for fourteen TCP/UDP kinds in source commit 8ee72a16c75d5001222a65b15c9427b61a16d38e.
//! The pinned Microsoft network manifest declares a four-byte connid:
//! https://github.com/microsoft/perfview/blob/4ae8d85b25043a21e6cb65bda340a620d691ac62/src/TraceEvent/Parsers/kerneltraceeventparser.man.xml
//! This does not admit other architectures, versions, operation layouts or the
//! separate provider failure reports. No padding, pointer-width retry or guessed tail.
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() > MAX_ORIGINAL_BYTES * 2
        || !input.len().is_multiple_of(2)
        || !input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid Windows network original byte encoding".into());
    }
    let digit = |v: u8| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
    Ok(input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
        .collect())
}
fn guid(value: &str) -> bool {
    value.len() == 38
        && value.bytes().enumerate().all(|(i, b)| match i {
            0 => b == b'{',
            37 => b == b'}',
            9 | 14 | 19 | 24 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let end = self
            .offset
            .checked_add(N)
            .filter(|end| *end <= self.bytes.len())
            .ok_or("Truncated Windows network original")?;
        let bytes = self.bytes[self.offset..end]
            .try_into()
            .map_err(|_| "Invalid Windows network field width")?;
        self.offset = end;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take()?))
    }
    fn port(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take()?))
    }
    fn address(&mut self, family: WindowsNetworkFamily) -> Result<IpAddr, String> {
        Ok(match family {
            WindowsNetworkFamily::Ipv4 => Ipv4Addr::from(self.take::<4>()?).into(),
            WindowsNetworkFamily::Ipv6 => Ipv6Addr::from(self.take::<16>()?).into(),
        })
    }
}

pub(super) fn decode(original: WindowsNetworkOriginal) -> Result<WindowsNetworkEvent, String> {
    let header = &original.header;
    if !crate::hex_id(&original.stream_id)
        || original.receipt_sequence == 0
        || !guid(&header.activity_id)
        || header.flags & 0x100 == 0 // Classic header required.
        || header.flags & 0x0c != 0 // String-only/trace-message records differ.
        || header.flags & 0x60 != 0x40 // Only native-accepted header64.
        || header.descriptor.version != 2
        || original.extended_data.len() > MAX_EXTENDED_ITEMS
    {
        return Err("Unsupported Windows network provenance or layout".into());
    }
    let protocol = match header.provider_id.as_str() {
        TCP_PROVIDER => WindowsNetworkProtocol::Tcp,
        UDP_PROVIDER => WindowsNetworkProtocol::Udp,
        _ => return Err("Unsupported Windows network provider".into()),
    };
    use WindowsNetworkFamily::{Ipv4, Ipv6};
    use WindowsNetworkOperation::{Accept, Connect, Disconnect, Receive, Send};
    use WindowsNetworkProtocol::{Tcp, Udp};
    let (family, operation, expected_bytes) = match (protocol, header.descriptor.opcode) {
        (Tcp, 10) => (Ipv4, Send, 36),
        (Tcp, 11) => (Ipv4, Receive, 28),
        (Tcp, 12) => (Ipv4, Connect, 44),
        (Tcp, 13) => (Ipv4, Disconnect, 28),
        (Tcp, 15) => (Ipv4, Accept, 44),
        (Tcp, 26) => (Ipv6, Send, 60),
        (Tcp, 27) => (Ipv6, Receive, 52),
        (Tcp, 28) => (Ipv6, Connect, 68),
        (Tcp, 29) => (Ipv6, Disconnect, 52),
        (Tcp, 31) => (Ipv6, Accept, 68),
        (Udp, 10) => (Ipv4, Send, 28),
        (Udp, 11) => (Ipv4, Receive, 28),
        (Udp, 26) => (Ipv6, Send, 52),
        (Udp, 27) => (Ipv6, Receive, 52),
        _ => return Err("Unsupported Windows network operation".into()),
    };
    let bytes = hex(&original.user_data_hex)?;
    if bytes.len() != expected_bytes {
        return Err("Windows network payload does not match its exact template".into());
    }
    let mut total = bytes.len();
    for extension in &original.extended_data {
        total = total
            .checked_add(hex(&extension.data_hex)?.len())
            .filter(|total| *total <= MAX_ORIGINAL_BYTES)
            .ok_or("Windows network originals exceed their byte budget")?;
    }
    let (time_ms, time_uncertainty_ms) = original
        .clock
        .estimate(header.timestamp_qpc)
        .map_err(|_| "Invalid or distant Windows network clock sample")?;
    let mut reader = Reader {
        bytes: &bytes,
        offset: 0,
    };
    let reported_pid = reader.u32()?;
    let reported_size = reader.u32()?;
    let destination_address = reader.address(family)?;
    let source_address = reader.address(family)?;
    let destination_port = reader.port()?;
    let source_port = reader.port()?;
    if protocol == Tcp && operation == Send {
        // startime/endtime are preserved only as raw fields; do not invent a clock.
        reader.u32()?;
        reader.u32()?;
    }
    if matches!(operation, Connect | Accept) {
        for _ in 0..4 {
            reader.u16()?; // mss, sackopt, tsopt, wsopt
        }
        reader.u32()?; // rcvwin
        reader.take::<2>()?; // signed rcvwinscale, original-only
        reader.take::<2>()?; // signed sndwinscale, original-only
    }
    reader.u32()?; // seqnum is not a collector loss counter.
    reader.u32()?; // opaque connid: never infer an address or connection lifetime.
    if reader.offset != bytes.len() {
        return Err("Unrecognized trailing Windows network bytes".into());
    }
    Ok(WindowsNetworkEvent {
        original,
        operation,
        protocol,
        family,
        header_pointer_bits: 64,
        reported_pid,
        source: SocketAddr::new(source_address, source_port),
        destination: SocketAddr::new(destination_address, destination_port),
        reported_size,
        time_ms,
        time_uncertainty_ms,
        time_basis: WindowsNetworkTimeBasis::CollectorQpcEstimate,
    })
}
