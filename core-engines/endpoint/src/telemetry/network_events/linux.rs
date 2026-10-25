use super::{hooks, wire};
use crate::Result;
use athernex_endpoint_protocol::network_events::NetworkEvent;
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

pub(super) struct Socket {
    fd: OwnedFd,
    pub port: u32,
}
impl Socket {
    pub fn new(groups: u32, capacity: i32) -> io::Result<Self> {
        let raw =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 12) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = groups;
        if unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&capacity as *const i32).cast(),
                mem::size_of_val(&capacity) as _,
            )
        } != 0
            || unsafe {
                libc::bind(
                    raw,
                    (&address as *const libc::sockaddr_nl).cast(),
                    mem::size_of_val(&address) as _,
                )
            } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut length = mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                raw,
                (&mut address as *mut libc::sockaddr_nl).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            port: address.nl_pid,
        })
    }
    pub fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        if unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
                (&kernel as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&kernel) as _,
            )
        } != bytes.len() as isize
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn receive(&self, wait_ms: i32) -> io::Result<Option<(Vec<u8>, u32)>> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, wait_ms) };
        if ready == 0 {
            return Ok(None);
        }
        if ready < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(e)
            };
        }
        let mut bytes = vec![0u8; 65536];
        let mut sender: libc::sockaddr_nl = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
        msg.msg_namelen = mem::size_of_val(&sender) as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let length = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
        if length < 0 {
            let e = io::Error::last_os_error();
            return if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(e)
            };
        }
        if length == 0
            || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || msg.msg_namelen as usize != mem::size_of_val(&sender)
            || sender.nl_family != libc::AF_NETLINK as u16
            || sender.nl_pid != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Untrusted or truncated kernel netfilter datagram",
            ));
        }
        bytes.truncate(length as usize);
        Ok(Some((bytes, sender.nl_groups)))
    }
}
pub(super) struct Reader {
    socket: Socket,
    pub families: Vec<u8>,
    pub source_checked_ms: u64,
    pub loss_signals: u64,
    pub skipped_protocols: u64,
    last_probe: Instant,
}
impl Reader {
    pub fn open() -> Result<Self> {
        Self::with_capacity(262144)
    }
    pub(super) fn with_capacity(capacity: i32) -> Result<Self> {
        // Subscribing never installs tracking rules or changes sysctls.
        let socket = Socket::new(7, capacity)?;
        let families = hooks::source()?;
        if families.is_empty() {
            return Err("No complete IPv4/IPv6 connection-tracking hooks; configure tracking policy before enabling network events".into());
        }
        Ok(Self {
            socket,
            families,
            source_checked_ms: crate::now_ms(),
            loss_signals: 0,
            skipped_protocols: 0,
            last_probe: Instant::now(),
        })
    }
    pub fn batch(&mut self) -> Result<Vec<NetworkEvent>> {
        if self.last_probe.elapsed() >= Duration::from_secs(5) {
            if hooks::source()? != self.families {
                return Err("Connection-tracking hook coverage changed during subscription".into());
            }
            self.source_checked_ms = crate::now_ms();
            self.last_probe = Instant::now();
        }
        let mut events = Vec::new();
        for index in 0..64 {
            let received = match self.socket.receive(if index == 0 { 200 } else { 0 }) {
                Ok(value) => value,
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    self.loss_signals = self.loss_signals.saturating_add(1);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let Some((bytes, group)) = received else {
                break;
            };
            let decoded = wire::decode(&bytes, group)?;
            self.skipped_protocols = self.skipped_protocols.saturating_add(decoded.skipped);
            if events.len() + decoded.events.len() > 128 {
                return Err("Network event batch exceeds admission budget".into());
            }
            events.extend(decoded.events);
            if events.len() >= 64 {
                break;
            }
        }
        Ok(events)
    }
}
pub(super) fn monotonic_ns() -> Result<u64> {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0
        || time.tv_sec < 0
        || time.tv_nsec < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok((time.tv_sec as u64).saturating_mul(1_000_000_000) + time.tv_nsec as u64)
}
