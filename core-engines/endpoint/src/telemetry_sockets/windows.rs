//! Bounded snapshots from the supported Windows IP Helper owner-PID APIs.
use super::{ConnectionObservation, Socket};
use std::{
    mem::{offset_of, size_of},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{AF_INET, AF_INET6},
};

fn table(tcp: bool, family: u32) -> Option<(Vec<u64>, usize)> {
    let mut bytes = 0u32;
    for _ in 0..4 {
        if bytes > 4 * 1024 * 1024 {
            return None;
        }
        // u64 storage provides alignment for every supported table structure.
        let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
        let pointer = if buffer.is_empty() {
            std::ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        let result = unsafe {
            if tcp {
                GetExtendedTcpTable(pointer, &mut bytes, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
            } else {
                GetExtendedUdpTable(pointer, &mut bytes, 0, family, UDP_TABLE_OWNER_PID, 0)
            }
        };
        if result == ERROR_SUCCESS {
            if buffer.is_empty() || bytes as usize > buffer.len() * 8 {
                return None;
            }
            return Some((buffer, bytes as usize));
        }
        if result != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
    }
    None
}
fn decode<R: Copy>(
    buffer: &[u64],
    bytes: usize,
    offset: usize,
    limit: usize,
) -> Option<(Vec<R>, bool)> {
    if bytes < size_of::<u32>() || bytes > buffer.len() * 8 || offset < size_of::<u32>() {
        return None;
    }
    let data = buffer.as_ptr().cast::<u8>();
    let count = unsafe { data.cast::<u32>().read_unaligned() } as usize;
    let required = offset.checked_add(count.checked_mul(size_of::<R>())?)?;
    if required > bytes {
        return None;
    }
    let rows = (0..count.min(limit))
        .map(|i| unsafe {
            data.add(offset + i * size_of::<R>())
                .cast::<R>()
                .read_unaligned()
        })
        .collect();
    Some((rows, count <= limit))
}
fn state(value: u32) -> &'static str {
    [
        "UNKNOWN",
        "CLOSED",
        "LISTEN",
        "SYN_SENT",
        "SYN_RCVD",
        "ESTABLISHED",
        "FIN_WAIT_1",
        "FIN_WAIT_2",
        "CLOSE_WAIT",
        "CLOSING",
        "LAST_ACK",
        "TIME_WAIT",
        "DELETE_TCB",
    ]
    .get(value as usize)
    .copied()
    .unwrap_or("UNKNOWN")
}
fn socket(
    protocol: &str,
    local: SocketAddr,
    remote: Option<SocketAddr>,
    status: &str,
    pid: u32,
) -> Socket {
    Socket {
        connection: ConnectionObservation {
            protocol: protocol.into(),
            local,
            remote,
            state: status.into(),
            owner_pid: None,
            process: None,
        },
        owners: if pid == 0 { vec![] } else { vec![pid] },
    }
}
fn ipv4(address: u32, port: u32) -> SocketAddr {
    (
        Ipv4Addr::from(address.to_ne_bytes()),
        u16::from_be(port as u16),
    )
        .into()
}
fn ipv6(address: [u8; 16], port: u32, scope: u32) -> SocketAddr {
    SocketAddrV6::new(Ipv6Addr::from(address), u16::from_be(port as u16), 0, scope).into()
}

pub fn capture(_pids: &[u32], only_pid: Option<u32>, limit: usize) -> (Vec<Socket>, bool) {
    let mut rows = Vec::new();
    let mut complete = true;
    macro_rules! read_table {
        ($tcp:expr,$family:expr,$table:ty,$row:ty,$map:expr) => {
            match table($tcp, $family as u32)
                .and_then(|(b, bytes)| decode::<$row>(&b, bytes, offset_of!($table, table), 65536))
            {
                Some((items, all)) => {
                    complete &= all;
                    for item in items {
                        let socket: Socket = ($map)(item);
                        if only_pid.is_some_and(|p| !socket.owners.contains(&p)) {
                            continue;
                        }
                        if rows.len() == limit {
                            return (rows, false);
                        }
                        rows.push(socket);
                    }
                }
                None => complete = false,
            }
        };
    }
    read_table!(
        true,
        AF_INET,
        MIB_TCPTABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID,
        |r: MIB_TCPROW_OWNER_PID| {
            let remote = ipv4(r.dwRemoteAddr, r.dwRemotePort);
            socket(
                "tcp",
                ipv4(r.dwLocalAddr, r.dwLocalPort),
                if r.dwState == 2 || remote.port() == 0 {
                    None
                } else {
                    Some(remote)
                },
                state(r.dwState),
                r.dwOwningPid,
            )
        }
    );
    read_table!(
        true,
        AF_INET6,
        MIB_TCP6TABLE_OWNER_PID,
        MIB_TCP6ROW_OWNER_PID,
        |r: MIB_TCP6ROW_OWNER_PID| {
            let remote = ipv6(r.ucRemoteAddr, r.dwRemotePort, r.dwRemoteScopeId);
            socket(
                "tcp",
                ipv6(r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
                if r.dwState == 2 || remote.port() == 0 {
                    None
                } else {
                    Some(remote)
                },
                state(r.dwState),
                r.dwOwningPid,
            )
        }
    );
    read_table!(
        false,
        AF_INET,
        MIB_UDPTABLE_OWNER_PID,
        MIB_UDPROW_OWNER_PID,
        |r: MIB_UDPROW_OWNER_PID| socket(
            "udp",
            ipv4(r.dwLocalAddr, r.dwLocalPort),
            None,
            "bound",
            r.dwOwningPid
        )
    );
    read_table!(
        false,
        AF_INET6,
        MIB_UDP6TABLE_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID,
        |r: MIB_UDP6ROW_OWNER_PID| socket(
            "udp",
            ipv6(r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
            None,
            "bound",
            r.dwOwningPid
        )
    );
    (rows, complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn truncated_or_overflowing_native_tables_are_rejected() {
        assert!(decode::<MIB_TCPROW_OWNER_PID>(&[u64::MAX], 8, 4, 4096).is_none());
        assert!(decode::<MIB_TCPROW_OWNER_PID>(&[], 0, 4, 4096).is_none());
        assert!(decode::<MIB_TCPROW_OWNER_PID>(&[1], 8, 4, 4096).is_none());
        assert!(decode::<MIB_TCPROW_OWNER_PID>(&[0], 3, 4, 4096).is_none());
        assert!(decode::<MIB_TCPROW_OWNER_PID>(&[0], 9, 4, 4096).is_none());
        assert!(decode::<u8>(&[1], 4, 4, 4096).is_none()); // Allocation padding is not data.
        assert_eq!(
            decode::<MIB_TCPROW_OWNER_PID>(&[0], 4, 4, 4096)
                .unwrap()
                .0
                .len(),
            0
        );
    }
}
