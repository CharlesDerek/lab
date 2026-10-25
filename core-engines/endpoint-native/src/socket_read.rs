//! Deadline-bound reads also work when the peer has closed after sending data.
//! Darwin rejects setsockopt after disconnect, even with unread bytes queued.
use std::{
    io,
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Native socket deadline elapsed"))
}

pub(crate) fn read(stream: &UnixStream, bytes: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        remaining(deadline)?;
        // Per-call nonblocking I/O leaves the stream's write behavior intact.
        let count = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if count >= 0 {
            remaining(deadline)?;
            return Ok(count as usize);
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {}
            _ => return Err(error),
        }
        let timeout_ms = remaining(deadline)?
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        } else if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        // Read on readiness, hangup or error to preserve queued data and EOF.
        // Recheck the same deadline on every retry, including interruptions.
    }
}
