//! Read-only procfs socket snapshots. These describe the agent's network namespace.
use super::{ConnectionObservation, Socket};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

fn address(raw: &str) -> Option<SocketAddr> {
    let (ip, port) = raw.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(ip, 16).ok()?.to_ne_bytes(),
        )),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, word) in ip.as_bytes().chunks_exact(8).enumerate() {
                bytes[i * 4..i * 4 + 4].copy_from_slice(
                    &u32::from_str_radix(std::str::from_utf8(word).ok()?, 16)
                        .ok()?
                        .to_ne_bytes(),
                );
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}
fn row(line: &str, tcp: bool) -> Option<(u64, ConnectionObservation)> {
    let fields: Vec<_> = line.split_ascii_whitespace().take(16).collect();
    if fields.len() < 10 {
        return None;
    }
    let local = address(fields[1])?;
    let destination = address(fields[2])?;
    let state = u8::from_str_radix(fields[3], 16).ok()?;
    let states = [
        "UNKNOWN",
        "ESTABLISHED",
        "SYN_SENT",
        "SYN_RCVD",
        "FIN_WAIT_1",
        "FIN_WAIT_2",
        "TIME_WAIT",
        "CLOSED",
        "CLOSE_WAIT",
        "LAST_ACK",
        "LISTEN",
        "CLOSING",
        "SYN_RCVD",
    ];
    Some((
        fields[9].parse().ok()?,
        ConnectionObservation {
            protocol: if tcp { "tcp" } else { "udp" }.into(),
            local,
            remote: if tcp && state != 10 && destination.port() != 0 {
                Some(destination)
            } else {
                None
            },
            state: if tcp {
                states.get(state as usize).copied().unwrap_or("UNKNOWN")
            } else {
                "bound"
            }
            .into(),
            owner_pid: None,
            process: None,
        },
    ))
}
pub fn capture(pids: &[u32], only_pid: Option<u32>, limit: usize) -> (Vec<Socket>, bool) {
    let mut complete = pids.len() <= limit;
    let mut by_inode: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
    let mut descriptors = 0usize;
    'processes: for pid in pids.iter().take(limit) {
        if only_pid.is_some_and(|p| p != *pid) {
            continue;
        }
        let entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        for (n, entry) in entries.enumerate() {
            descriptors += 1;
            if descriptors > 65536 {
                complete = false;
                break 'processes;
            }
            if n >= 4096 {
                complete = false;
                break;
            }
            let Ok(entry) = entry else {
                complete = false;
                continue;
            };
            let link = match fs::read_link(entry.path()) {
                Ok(link) => link,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            if let Some(inode) = link
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            {
                let owners = by_inode.entry(inode).or_default();
                if !owners.contains(pid) {
                    owners.push(*pid);
                }
            }
        }
    }
    let mut rows = Vec::new();
    for (name, tcp) in [
        ("tcp", true),
        ("tcp6", true),
        ("udp", false),
        ("udp6", false),
    ] {
        let file = match fs::File::open(format!("/proc/net/{name}")) {
            Ok(file) => file,
            Err(e) if name.ends_with('6') && e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            complete = false;
            continue;
        }
        for n in 0..=65536 {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) if line.len() > 16384 || n == 65536 => {
                    complete = false;
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    complete = false;
                    break;
                }
            }
            let Some((inode, connection)) = row(&line, tcp) else {
                complete = false;
                continue;
            };
            let owners = by_inode.get(&inode).cloned().unwrap_or_default();
            if only_pid.is_some_and(|p| !owners.contains(&p)) {
                continue;
            }
            if rows.len() >= limit {
                return (rows, false);
            }
            rows.push(Socket { connection, owners });
        }
    }
    (rows, complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn procfs_byte_order_and_malformed_records() {
        assert_eq!(
            address("0100007F:01BB").unwrap().to_string(),
            "127.0.0.1:443"
        );
        assert_eq!(
            address("00000000000000000000000001000000:0050")
                .unwrap()
                .to_string(),
            "[::1]:80"
        );
        let (_, tcp) = row(
            "0: 0100007F:8000 0100007F:01BB 01 0:0 0:0 0 1000 0 42",
            true,
        )
        .unwrap();
        assert_eq!(tcp.remote.unwrap().port(), 443);
        assert!(row("incomplete", true).is_none());
        assert!(address("not-an-address:FFFF").is_none());
    }
}
