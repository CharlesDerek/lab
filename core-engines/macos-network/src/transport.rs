use crate::{hex, now_ms, Delivery, Result, Status};
use athernex_endpoint_protocol::macos_network_events::{
    MacosNetworkEvent, MacosNetworkOriginal, MAX_BATCH_BYTES, MAX_BATCH_RECORDS, MAX_CONTROL_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Control {
    pub version: u32,
    pub nonce: String,
    pub epoch: u64,
    pub request_id: u64,
    pub status: Status,
    pub batch_id: u64,
    pub batch_sha256: String,
    pub record_count: u32,
}
#[derive(Default)]
pub(crate) struct Reply {
    pub control: Vec<u8>,
    pub batch: Vec<u8>,
}
pub(crate) fn decode(
    reply: Reply,
    nonce: &str,
    epoch: Option<u64>,
    request: u64,
    stream: Option<&str>,
) -> Result<(u64, Delivery)> {
    if reply.control.len() > MAX_CONTROL_BYTES
        || reply
            .control
            .len()
            .checked_add(reply.batch.len())
            .is_none_or(|n| n > MAX_BATCH_BYTES)
    {
        return Err("Network source reply exceeds budget".into());
    }
    let c: Control =
        serde_json::from_slice(&reply.control).map_err(|_| "Invalid network source reply")?;
    if c.version != 1
        || c.nonce != nonce
        || !hex(&c.nonce, 64)
        || c.epoch == 0
        || epoch.is_some_and(|e| e != c.epoch)
        || c.request_id != request
        || !hex(&c.status.health.stream_id, 64)
        || stream.is_some_and(|s| s != c.status.health.stream_id)
    {
        return Err("Invalid network source connection binding".into());
    }
    c.status.validate(&c.status.health.stream_id)?;
    let mut events = Vec::new();
    if c.batch_id == 0 {
        if !reply.batch.is_empty() || !c.batch_sha256.is_empty() || c.record_count != 0 {
            return Err("Invalid empty network source reply".into());
        }
    } else {
        if !hex(&c.batch_sha256, 64)
            || c.record_count == 0
            || c.record_count as usize > MAX_BATCH_RECORDS
            || c.record_count as u64 > c.status.health.pending_records
            || c.batch_id
                != c.status
                    .last_acked_batch_id
                    .checked_add(1)
                    .ok_or("Network source batch overflow")?
            || format!("{:x}", Sha256::digest(&reply.batch)) != c.batch_sha256
        {
            return Err("Invalid network source batch binding".into());
        }
        let originals: Vec<MacosNetworkOriginal> = serde_json::from_slice(&reply.batch)
            .map_err(|_| "Invalid network source original batch")?;
        if originals.len() != c.record_count as usize {
            return Err("Invalid network source batch count".into());
        }
        let mut previous = 0;
        for original in originals {
            if original.stream_id != c.status.health.stream_id
                || original.receipt_sequence <= previous
                || original.receipt_sequence > c.status.health.received_records
            {
                return Err("Invalid network source receipt order".into());
            }
            previous = original.receipt_sequence;
            let event = MacosNetworkEvent::from_original(original)
                .map_err(|_| "Invalid network source projection")?;
            event
                .validate(now_ms())
                .map_err(|_| "Invalid network source projected facts")?;
            events.push(event);
        }
    }
    Ok((
        c.epoch,
        Delivery {
            batch_id: c.batch_id,
            batch_sha256: c.batch_sha256,
            events,
            status: c.status,
        },
    ))
}
