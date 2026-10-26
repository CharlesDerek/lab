use super::{
    transport::{self, Command, Reply, Request, Response},
    Delivery, Status, MAX_FRAME_BYTES,
};
use crate::{child, Result};
use std::{
    fs::File,
    net::Shutdown,
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(5);
use crate::macos_notify::owned::pin_helper;

/// Verify the configured installed helper without launching it or creating ES state.
pub fn verify_helper(path: &Path, expected_sha256: &str) -> Result<()> {
    pin_helper(path, expected_sha256)
        .map(|_| ())
        .map_err(|_| "Process helper identity verification failed".into())
}

/// One owned helper and one private transport. A transport failure is terminal;
/// recreating this object requires a new stream and a durable source-gap record.
pub struct Client {
    service: child::Service,
    stream: UnixStream,
    _image: File,
    nonce: String,
    stream_id: String,
    pending: Option<(u64, Vec<u8>, u64)>,
    acknowledged: u64,
    last_receipt: u64,
    last_status: Option<Status>,
    failed: bool,
    stopped: bool,
    source_stopped: bool,
}
impl Client {
    pub fn start(path: &Path, expected_sha256: &str, stream_id: &str) -> Result<Self> {
        Self::start_inner(path, expected_sha256, stream_id)
            .map_err(|_| "Process notification source startup failed".into())
    }
    fn start_inner(path: &Path, expected_sha256: &str, stream_id: &str) -> Result<Self> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (path, expected_sha256, stream_id);
            Err("Endpoint Security process collection requires macOS".into())
        }
        #[cfg(target_os = "macos")]
        {
            let (service, stream, image, nonce) = crate::macos_notify::owned::launch(
                path,
                expected_sha256,
                stream_id,
                "process-events-owned",
            )?;
            let mut client = Self {
                service,
                stream,
                _image: image,
                nonce,
                stream_id: stream_id.into(),
                pending: None,
                acknowledged: 0,
                last_receipt: 0,
                last_status: None,
                failed: false,
                stopped: false,
                source_stopped: false,
            };
            match client.exchange(Command::Start)? {
                Reply::Ready { status } => client.status(&status)?,
                _ => return Err("Invalid process helper startup response".into()),
            }
            // The protected named image must still equal the pinned release.
            verify_helper(path, expected_sha256)?;
            Ok(client)
        }
    }
    fn exchange(&mut self, command: Command) -> Result<Reply> {
        if self.failed || self.stopped {
            return Err("Process source transport is unavailable".into());
        }
        let result = (|| {
            if self.service.poll()?.is_some() {
                return Err("Process source helper exited".into());
            }
            let deadline = Instant::now() + TIMEOUT;
            transport::write(
                &mut self.stream,
                &Request {
                    version: 1,
                    nonce: self.nonce.clone(),
                    stream_id: self.stream_id.clone(),
                    command,
                },
                deadline,
            )?;
            let response: Response = transport::read(&mut self.stream, MAX_FRAME_BYTES, deadline)?;
            if response.version != 1
                || response.nonce != self.nonce
                || response.stream_id != self.stream_id
            {
                return Err("Process source response binding failed".into());
            }
            Ok(response.reply)
        })();
        if result.is_err() {
            self.failed = true;
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }
    fn status(&mut self, status: &Status) -> Result<()> {
        status.validate(&self.stream_id)?;
        if let Some(previous) = &self.last_status {
            let (a, b) = (&previous.health, &status.health);
            if a.started_ms != b.started_ms
                || b.checked_ms < a.checked_ms
                || b.scope_checked_ms < a.scope_checked_ms
                || [
                    a.received_records,
                    a.rejected_records,
                    a.callback_drops,
                    a.global_sequence_gaps,
                    a.event_sequence_gaps,
                    a.sequence_regressions,
                    a.loss_signals,
                ]
                .into_iter()
                .zip([
                    b.received_records,
                    b.rejected_records,
                    b.callback_drops,
                    b.global_sequence_gaps,
                    b.event_sequence_gaps,
                    b.sequence_regressions,
                    b.loss_signals,
                ])
                .any(|(old, new)| new < old)
            {
                self.failed = true;
                return Err("Process source counters regressed".into());
            }
        }
        self.last_status = Some(status.clone());
        Ok(())
    }
    /// Poll without releasing previously delivered originals. Empty polls carry
    /// source health; a full data frame can delay health only until the I/O bound.
    pub fn poll(&mut self) -> Result<Delivery> {
        let result = self.poll_inner();
        self.finish(result, "Process notification source poll failed")
    }
    fn poll_inner(&mut self) -> Result<Delivery> {
        let Reply::Batch { delivery } = self.exchange(Command::Poll)? else {
            self.failed = true;
            return Err("Invalid process source poll response".into());
        };
        delivery.validate(&self.stream_id)?;
        self.status(&delivery.status)?;
        let bytes = serde_json::to_vec(&delivery.events)?;
        if let Some((id, expected, _)) = &self.pending {
            if delivery.batch_id != *id || &bytes != expected {
                self.failed = true;
                return Err("Uncommitted process originals changed".into());
            }
        } else if delivery.batch_id != 0 {
            if self.acknowledged.checked_add(1) != Some(delivery.batch_id)
                || delivery.events[0].original.receipt_sequence <= self.last_receipt
            {
                self.failed = true;
                return Err("Process source receipt was reused".into());
            }
            let last = delivery
                .events
                .last()
                .ok_or("Empty process source batch")?
                .original
                .receipt_sequence;
            self.pending = Some((delivery.batch_id, bytes, last));
        }
        Ok(delivery)
    }
    /// Call only after the exact batch and its source counters are durable.
    pub fn commit(&mut self, batch_id: u64) -> Result<()> {
        let result = self.commit_inner(batch_id);
        self.finish(result, "Process notification source commit failed")
    }
    fn commit_inner(&mut self, batch_id: u64) -> Result<()> {
        if batch_id == 0 || self.pending.as_ref().is_none_or(|p| p.0 != batch_id) {
            if batch_id != 0 && batch_id == self.acknowledged {
                return Ok(());
            }
            return Err("No matching process batch is awaiting commit".into());
        }
        let Reply::Ack {
            batch_id: actual,
            status,
        } = self.exchange(Command::Ack { batch_id })?
        else {
            self.failed = true;
            return Err("Invalid process commit response".into());
        };
        if actual != batch_id {
            self.failed = true;
            return Err("Process commit binding failed".into());
        }
        self.status(&status)?;
        let (_, _, last) = self
            .pending
            .take()
            .ok_or("Process commit state disappeared")?;
        self.last_receipt = last;
        self.acknowledged = batch_id;
        Ok(())
    }
    /// Stop native delivery, retaining all queued/inflight originals for poll/commit.
    pub fn stop_source(&mut self) -> Result<Status> {
        let result = self.stop_inner();
        self.finish(result, "Process notification source stop failed")
    }
    fn stop_inner(&mut self) -> Result<Status> {
        let Reply::SourceStopped { status } = self.exchange(Command::StopSource)? else {
            self.failed = true;
            return Err("Invalid process source stop response".into());
        };
        self.status(&status)?;
        if status.health.state != "stopped" || status.health.subscriptions != 0 {
            return Err("Process source did not stop".into());
        }
        self.source_stopped = true;
        Ok(status)
    }
    /// Close only after stopping and durably draining the exact final batches.
    pub fn close(&mut self) -> Result<Status> {
        let result = self.close_inner();
        self.finish(result, "Process notification source close failed")
    }
    fn close_inner(&mut self) -> Result<Status> {
        if !self.source_stopped
            || self.pending.is_some()
            || self
                .last_status
                .as_ref()
                .is_none_or(|s| s.pending_records != 0)
        {
            return Err("Process source must be stopped and drained before close".into());
        }
        let Reply::Closed { status } = self.exchange(Command::Close)? else {
            self.failed = true;
            return Err("Invalid process source close response".into());
        };
        self.status(&status)?;
        if status.health.state != "stopped"
            || status.health.subscriptions != 0
            || status.pending_records != 0
        {
            return Err("Process source retained uncommitted records at close".into());
        }
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(code) = self.service.poll()? {
                if code != 0 {
                    return Err("Process source shutdown failed".into());
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err("Process source shutdown exceeded deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.stopped = true;
        Ok(status)
    }
    fn finish<T>(&mut self, result: Result<T>, error: &'static str) -> Result<T> {
        result.map_err(|_| {
            self.failed = true;
            let _ = self.stream.shutdown(Shutdown::Both);
            error.into()
        })
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
        // Existing Service keeps cleanup capacity held if group reap is pending.
        let _ = self.service.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_process_events::tests::{event, status};
    use std::io::Read;

    #[test]
    fn semantic_frame_refusals_close_transport_and_make_the_client_terminal() {
        for case in 0..3 {
            let (stream, mut peer) = UnixStream::pair().unwrap();
            let mut delivery = Delivery {
                batch_id: 1,
                events: vec![event(1, 1)],
                status: status(),
            };
            delivery.status.pending_records = 1;
            match case {
                0 => delivery.status.health.received_records = 0,
                1 => delivery.status.pending_records = 0,
                _ => {
                    delivery.events[0] = event(2, 1);
                    delivery.status.health.received_records = 1;
                }
            }
            let worker = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                let request: Request = transport::read(&mut peer, 4096, deadline).unwrap();
                assert!(matches!(request.command, Command::Poll));
                transport::write(
                    &mut peer,
                    &Response {
                        version: request.version,
                        nonce: request.nonce,
                        stream_id: request.stream_id,
                        reply: Reply::Batch { delivery },
                    },
                    deadline,
                )
                .unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut byte = [0];
                peer.read(&mut byte).unwrap()
            });
            let mut client = Client {
                service: child::Service::start(
                    std::process::Command::new("/bin/sleep").arg("10"),
                    4096,
                )
                .unwrap(),
                stream,
                _image: tempfile::tempfile().unwrap(),
                nonce: "c".repeat(64),
                stream_id: "a".repeat(64),
                pending: None,
                acknowledged: 0,
                last_receipt: 0,
                last_status: None,
                failed: false,
                stopped: false,
                source_stopped: false,
            };
            let refused = client.poll().unwrap_err().to_string();
            let failed = client.failed;
            let second = client.poll().unwrap_err().to_string();
            let peer_bytes = worker.join().unwrap();
            let cleanup = client.service.stop();
            assert_eq!(refused, "Process notification source poll failed");
            assert_eq!(second, refused);
            assert!(failed);
            assert_eq!(peer_bytes, 0);
            cleanup.unwrap();
        }
    }
}
