use crate::{
    transport::{decode, Reply},
    Config, Delivery, Result, Status,
};

pub(crate) trait Backend: Send {
    fn exchange(
        &mut self,
        operation: u32,
        epoch: u64,
        request: u64,
        batch: u64,
        digest: &str,
    ) -> Result<Reply>;
    fn invalidate(&mut self);
}
pub struct Client {
    backend: Box<dyn Backend>,
    nonce: String,
    epoch: u64,
    stream: String,
    request: u64,
    status: Status,
    inflight: Option<(u64, String, u64)>,
    acknowledged: Option<(u64, String)>,
    committed_receipt: u64,
    failed: bool,
}
impl Client {
    pub fn connect(config: &Config) -> Result<Self> {
        config.validate()?;
        #[cfg(target_os = "macos")]
        {
            let mut random = [0u8; 32];
            getrandom::fill(&mut random).map_err(|_| "Network connection randomness failed")?;
            let nonce = random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let (backend, reply) = crate::macos::Bridge::connect(config, &nonce)?;
            Self::connected(Box::new(backend), nonce, reply)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err("Network source requires macOS 13 or later".into())
        }
    }
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn connected(
        mut backend: Box<dyn Backend>,
        nonce: String,
        reply: Reply,
    ) -> Result<Self> {
        let decoded = decode(reply, &nonce, None, 0, None);
        let (epoch, delivery) = match decoded {
            Ok(v) => v,
            Err(e) => {
                backend.invalidate();
                return Err(e);
            }
        };
        if delivery.batch_id != 0
            || !["active", "degraded"].contains(&delivery.status.health.state.as_str())
        {
            backend.invalidate();
            return Err("Network provider is not running".into());
        }
        Ok(Self {
            backend,
            nonce,
            epoch,
            stream: delivery.status.health.stream_id.clone(),
            request: 0,
            status: delivery.status,
            inflight: None,
            acknowledged: None,
            committed_receipt: 0,
            failed: false,
        })
    }
    pub fn status(&self) -> &Status {
        &self.status
    }
    fn terminal<T>(&mut self, e: impl Into<String>) -> Result<T> {
        self.failed = true;
        self.backend.invalidate();
        Err(e.into())
    }
    fn call(&mut self, operation: u32, batch: u64, digest: &str) -> Result<Delivery> {
        if self.failed {
            return Err("Network connection is closed".into());
        }
        let Some(request) = self.request.checked_add(1) else {
            return self.terminal("Network request overflow");
        };
        self.request = request;
        let reply = match self
            .backend
            .exchange(operation, self.epoch, request, batch, digest)
        {
            Ok(v) => v,
            Err(e) => return self.terminal(e),
        };
        let (_, d) = match decode(
            reply,
            &self.nonce,
            Some(self.epoch),
            request,
            Some(&self.stream),
        ) {
            Ok(v) => v,
            Err(e) => return self.terminal(e),
        };
        let h = &d.status.health;
        let old = &self.status.health;
        let expected_ack = if operation == 2 {
            batch
        } else {
            self.status.last_acked_batch_id
        };
        if d.status.last_acked_batch_id != expected_ack
            || h.started_ms != old.started_ms
            || [
                h.received_records,
                h.excluded_records,
                h.rejected_records,
                h.callback_drops,
                h.queue_drops,
                h.transport_errors,
            ]
            .into_iter()
            .zip([
                old.received_records,
                old.excluded_records,
                old.rejected_records,
                old.callback_drops,
                old.queue_drops,
                old.transport_errors,
            ])
            .any(|(n, o)| n < o)
        {
            return self.terminal("Network source counters regressed");
        }
        self.status = d.status.clone();
        Ok(d)
    }
    pub fn poll(&mut self) -> Result<Delivery> {
        let d = self.call(1, 0, "")?;
        if d.batch_id == 0 {
            if self.inflight.is_some() {
                return self.terminal("Network inflight batch disappeared");
            }
        } else {
            let last = d
                .events
                .last()
                .ok_or("Network batch is empty")?
                .original
                .receipt_sequence;
            if let Some((id, digest, receipt)) = &self.inflight {
                if *id != d.batch_id || digest != &d.batch_sha256 || *receipt != last {
                    return self.terminal("Network inflight batch changed");
                }
            } else {
                if d.events[0].original.receipt_sequence <= self.committed_receipt {
                    return self.terminal("Network committed receipt replayed under new batch");
                }
                self.inflight = Some((d.batch_id, d.batch_sha256.clone(), last));
            }
        }
        Ok(d)
    }
    /// Call only after committing this exact batch and digest durably.
    pub fn commit(&mut self, batch_id: u64, digest: &str) -> Result<Status> {
        let repeated = self
            .acknowledged
            .as_ref()
            .is_some_and(|(i, d)| *i == batch_id && d == digest);
        if !repeated
            && !self
                .inflight
                .as_ref()
                .is_some_and(|(i, d, _)| *i == batch_id && d == digest)
        {
            return self.terminal("Network acknowledgement does not match inflight batch");
        }
        let d = self.call(2, batch_id, digest)?;
        if d.batch_id != 0 || d.status.last_acked_batch_id != batch_id {
            return self.terminal("Network acknowledgement was not applied");
        }
        if !repeated {
            self.committed_receipt = self
                .inflight
                .take()
                .ok_or("Network acknowledgement lost ownership")?
                .2;
            self.acknowledged = Some((batch_id, digest.to_string()));
        }
        Ok(d.status)
    }
    /// Detach only. Pending provider originals are retained for the next consumer.
    pub fn close(mut self) -> Result<Status> {
        let d = self.call(3, 0, "")?;
        self.failed = true;
        self.backend.invalidate();
        if d.batch_id != 0 {
            return Err("Invalid network detach reply".into());
        }
        Ok(d.status)
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.backend.invalidate();
    }
}
