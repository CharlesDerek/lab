use super::{Delivery, Status};
pub(super) use crate::macos_notify::framing::{read, write};
use serde::{Deserialize, Serialize};

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
