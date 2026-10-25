//! OS socket tables. Ownership is revalidated against process snapshots by the caller.
use athernex_endpoint_protocol::telemetry::ConnectionObservation;

pub struct Socket {
    pub connection: ConnectionObservation,
    pub owners: Vec<u32>,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::capture;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::capture;

#[cfg(target_os = "macos")]
pub fn capture(pids: &[u32], only_pid: Option<u32>, limit: usize) -> (Vec<Socket>, bool) {
    use libproc::{
        file_info::{pidfdinfo, ListFDs, ProcFDType},
        net_info::SocketFDInfo,
        proc_pid::{listpidinfo, pidinfo},
        task_info::TaskAllInfo,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let mut rows = Vec::new();
    let mut complete = pids.len() <= limit;
    let mut descriptors = 0usize;
    for &pid in pids.iter().take(limit) {
        if only_pid.is_some_and(|id| id != pid) {
            continue;
        }
        let Ok(pid_i32) = i32::try_from(pid) else {
            complete = false;
            continue;
        };
        let Ok(info) = pidinfo::<TaskAllInfo>(pid_i32, 0) else {
            complete = false;
            continue;
        };
        let count = info.pbsd.pbi_nfiles as usize;
        if count > 4096 {
            complete = false;
        }
        let Ok(fds) = listpidinfo::<ListFDs>(pid_i32, count.min(4096)) else {
            complete = false;
            continue;
        };
        for fd in fds {
            descriptors += 1;
            if descriptors > 65536 || rows.len() >= limit {
                return (rows, false);
            }
            if fd.proc_fdtype != ProcFDType::Socket as u32 {
                continue;
            }
            let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid_i32, fd.proc_fd) else {
                complete = false;
                continue;
            };
            let s = socket.psi;
            if ![libc::AF_INET, libc::AF_INET6].contains(&s.soi_family) {
                continue;
            }
            // proc_info.h discriminants guard every union access below.
            let (internet, protocol, state) =
                if s.soi_protocol == libc::IPPROTO_TCP && s.soi_kind == 2 {
                    let tcp = unsafe { s.soi_proto.pri_tcp };
                    let states = [
                        "CLOSED",
                        "LISTEN",
                        "SYN_SENT",
                        "SYN_RCVD",
                        "ESTABLISHED",
                        "CLOSE_WAIT",
                        "FIN_WAIT_1",
                        "CLOSING",
                        "LAST_ACK",
                        "FIN_WAIT_2",
                        "TIME_WAIT",
                    ];
                    (
                        tcp.tcpsi_ini,
                        "tcp",
                        states
                            .get(tcp.tcpsi_state as usize)
                            .copied()
                            .unwrap_or("UNKNOWN"),
                    )
                } else if s.soi_protocol == libc::IPPROTO_UDP && s.soi_kind == 1 {
                    (unsafe { s.soi_proto.pri_in }, "udp", "bound")
                } else {
                    continue;
                };
            let (local_ip, remote_ip) = if s.soi_family == libc::AF_INET {
                unsafe {
                    (
                        IpAddr::V4(Ipv4Addr::from(
                            internet.insi_laddr.ina_46.i46a_addr4.s_addr.to_ne_bytes(),
                        )),
                        IpAddr::V4(Ipv4Addr::from(
                            internet.insi_faddr.ina_46.i46a_addr4.s_addr.to_ne_bytes(),
                        )),
                    )
                }
            } else {
                unsafe {
                    (
                        IpAddr::V6(Ipv6Addr::from(internet.insi_laddr.ina_6.s6_addr)),
                        IpAddr::V6(Ipv6Addr::from(internet.insi_faddr.ina_6.s6_addr)),
                    )
                }
            };
            let remote_port = u16::from_be(internet.insi_fport as u16);
            let connection = ConnectionObservation {
                protocol: protocol.into(),
                local: SocketAddr::new(local_ip, u16::from_be(internet.insi_lport as u16)),
                remote: if protocol == "tcp" && state != "LISTEN" && remote_port != 0 {
                    Some(SocketAddr::new(remote_ip, remote_port))
                } else {
                    None
                },
                state: state.into(),
                owner_pid: None,
                process: None,
            };
            rows.push(Socket {
                connection,
                owners: vec![pid],
            });
        }
    }
    (rows, complete)
}
