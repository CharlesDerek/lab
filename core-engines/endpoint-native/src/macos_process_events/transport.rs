use super::{Delivery, Status, MAX_FRAME_BYTES};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::Instant,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub version: u32,
    pub nonce: String,
    pub stream_id: String,
    pub command: Command,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    Start,
    Poll,
    Ack { batch_id: u64 },
    StopSource,
    Close,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Response {
    pub version: u32,
    pub nonce: String,
    pub stream_id: String,
    pub reply: Reply,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Reply {
    Ready { status: Status },
    Batch { delivery: Delivery },
    Ack { batch_id: u64, status: Status },
    SourceStopped { status: Status },
    Closed { status: Status },
}

fn remaining(deadline: Instant) -> crate::Result<std::time::Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "Process source transport deadline exceeded".into())
}
fn read_exact(stream: &mut UnixStream, bytes: &mut [u8], deadline: Instant) -> crate::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err("Process source transport closed".into()),
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("Process source transport read failed".into()),
        }
    }
    Ok(())
}
pub(super) fn read<T: DeserializeOwned>(
    stream: &mut UnixStream,
    limit: usize,
    deadline: Instant,
) -> crate::Result<T> {
    let mut prefix = [0; 4];
    read_exact(stream, &mut prefix, deadline)?;
    let size = u32::from_be_bytes(prefix) as usize;
    if size == 0 || size > limit || size > MAX_FRAME_BYTES {
        return Err("Process source frame exceeds its bound".into());
    }
    let mut bytes = vec![0; size];
    read_exact(stream, &mut bytes, deadline)?;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid process source frame".into())
}
pub(super) fn write<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
) -> crate::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| "Process source serialization failed")?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err("Process source frame exceeds its bound".into());
    }
    for part in [&(bytes.len() as u32).to_be_bytes()[..], bytes.as_slice()] {
        let mut offset = 0;
        while offset < part.len() {
            stream.set_write_timeout(Some(remaining(deadline)?))?;
            match stream.write(&part[offset..]) {
                Ok(0) => return Err("Process source transport closed".into()),
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("Process source transport write failed".into()),
            }
        }
    }
    Ok(())
}
