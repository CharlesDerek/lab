//! Read-only Linux CN_PROC subscription; no audit rules or tracing policy changes.
use super::wire::{self, Frame, Sequences};
use crate::Result;
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

pub(super) struct Reader {
    socket: OwnedFd,
    port: u32,
    ack: u32,
    sequences: Sequences,
    buffered: Vec<Frame>,
    listening: bool,
    pub loss_signals: u64,
}
impl Reader {
    pub fn open() -> Result<Self> {
        Self::with_capacity(262144)
    }
    fn with_capacity(capacity: libc::c_int) -> Result<Self> {
        let raw =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 11) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = 1;
        if unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&capacity as *const libc::c_int).cast(),
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
            return Err(io::Error::last_os_error().into());
        }
        let mut len = mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                raw,
                (&mut address as *mut libc::sockaddr_nl).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let mut random = [0; 4];
        getrandom::fill(&mut random)?;
        let mut reader = Self {
            socket,
            port: address.nl_pid,
            ack: u32::from_ne_bytes(random),
            sequences: Sequences::default(),
            buffered: Vec::new(),
            listening: false,
            loss_signals: 0,
        };
        reader.control(1)?;
        reader.listening = true;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let frames = reader.receive(200)?;
            let mut acknowledged = false;
            for frame in frames {
                if let Some((ack, error)) = frame.ack {
                    if ack == reader.ack.wrapping_add(1) {
                        if error != 0 {
                            return Err(io::Error::from_raw_os_error(error as i32).into());
                        }
                        acknowledged = true;
                    }
                } else {
                    if reader.buffered.len() >= 64 {
                        return Err(
                            "Process-event subscription startup exceeded buffer budget".into()
                        );
                    }
                    reader.buffered.push(frame);
                }
            }
            if acknowledged {
                return Ok(reader);
            }
        }
        Err("Process connector did not acknowledge subscription; initial PID/user/network namespaces and kernel support are required".into())
    }
    fn control(&self, operation: u32) -> Result<()> {
        let mut bytes = [0u8; 40];
        for (offset, value) in [
            (0, 40u32),
            (12, self.port),
            (16, 1),
            (20, 1),
            (28, self.ack),
            (36, operation),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        bytes[4..6].copy_from_slice(&3u16.to_ne_bytes());
        bytes[32..34].copy_from_slice(&4u16.to_ne_bytes());
        let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        if unsafe {
            libc::sendto(
                self.socket.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
                (&kernel as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&kernel) as _,
            )
        } != bytes.len() as isize
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn receive(&mut self, wait_ms: i32) -> Result<Vec<Frame>> {
        let mut poll = libc::pollfd {
            fd: self.socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, wait_ms) };
        if ready == 0 {
            return Ok(Vec::new());
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(Vec::new())
            } else {
                Err(error.into())
            };
        }
        let mut bytes = [0u8; 65536];
        let mut sender: libc::sockaddr_nl = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
        message.msg_namelen = mem::size_of_val(&sender) as _;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        let length =
            unsafe { libc::recvmsg(self.socket.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
        if length < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOBUFS) {
                self.loss_signals = self.loss_signals.saturating_add(1);
                return Ok(Vec::new());
            }
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Ok(Vec::new());
            }
            return Err(error.into());
        }
        if length == 0
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || sender.nl_family != libc::AF_NETLINK as u16
            || sender.nl_pid != 0
            || sender.nl_groups != 1
        {
            return Err("Untrusted or truncated kernel process datagram".into());
        }
        let frames = wire::decode(&bytes[..length as usize])?;
        for frame in &frames {
            if self.sequences.observe(frame)? {
                self.loss_signals = self.loss_signals.saturating_add(1);
            }
        }
        Ok(frames)
    }
    pub fn batch(
        &mut self,
    ) -> Result<Vec<athernex_endpoint_protocol::process_events::ProcessEvent>> {
        let mut frames = mem::take(&mut self.buffered);
        if frames.is_empty() {
            frames = self.receive(200)?;
        }
        while frames.len() < 64 {
            let next = self.receive(0)?;
            if next.is_empty() {
                break;
            }
            if frames.len() + next.len() > 128 {
                return Err("Process event batch exceeds bounded admission".into());
            }
            frames.extend(next);
        }
        Ok(frames.into_iter().filter_map(|f| f.event).collect())
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        if self.listening {
            let _ = self.control(2);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Requires real Linux kernel process-connector access; deliberately overflows only this socket"]
    fn kernel_socket_overflow_is_reported_without_silently_claiming_complete_capture() {
        let mut reader = Reader::with_capacity(4096).unwrap();
        for _ in 0..32 {
            assert!(std::process::Command::new("/bin/true")
                .status()
                .unwrap()
                .success());
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while reader.loss_signals == 0 && Instant::now() < deadline {
            reader.batch().unwrap();
        }
        assert!(
            reader.loss_signals > 0,
            "A deliberately overflowing socket must report a coverage gap"
        );
        println!("Verified native socket overflow is detected; no host buffer limit was changed");
    }
}
