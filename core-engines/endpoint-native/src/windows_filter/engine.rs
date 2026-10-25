//! Exact-byte ClamAV INSTREAM transport. The Windows adapter separately verifies
//! the process identity owning both ends of its loopback scanner connection.
use crate::{Result, Verdict, MAX_FILE};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};
pub fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "Windows scan deadline elapsed".into())
}
fn write(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(bytes)?;
    Ok(())
}
pub fn scan(
    stream: &mut TcpStream,
    bytes: u64,
    deadline: Instant,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<Verdict> {
    if bytes > MAX_FILE {
        return Err("Windows scan exceeds 128 MiB".into());
    }
    write(stream, b"zINSTREAM\0", deadline)?;
    let mut offset = 0;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    while offset < bytes {
        remaining(deadline)?;
        let length = (bytes - offset).min(buffer.len() as u64) as usize;
        read(offset, &mut buffer[..length])?;
        write(stream, &(length as u32).to_be_bytes(), deadline)?;
        write(stream, &buffer[..length], deadline)?;
        digest.update(&buffer[..length]);
        offset += length as u64;
    }
    write(stream, &[0; 4], deadline)?;
    let mut response = Vec::new();
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let mut next = [0];
        stream.read_exact(&mut next)?;
        if next[0] == 0 {
            break;
        }
        if response.len() == 1024 {
            return Err("Scanner reply exceeds its byte budget".into());
        }
        response.push(next[0]);
    }
    let text = String::from_utf8(response)?;
    let detection = if text == "stream: OK" {
        None
    } else {
        let name = text
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" FOUND"))
            .filter(|s| {
                !s.is_empty() && s.len() <= 255 && s.bytes().all(|c| (0x20..=0x7e).contains(&c))
            })
            .ok_or("Scanner did not return an exact clean or malware verdict")?;
        Some(name.to_owned())
    };
    Ok(Verdict {
        sha256: format!("{:x}", digest.finalize()),
        detection,
        bytes,
    })
}
