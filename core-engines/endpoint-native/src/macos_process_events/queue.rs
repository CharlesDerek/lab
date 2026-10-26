use super::{Delivery, Status, MAX_BATCH_BYTES, MAX_BATCH_RECORDS, MAX_QUEUE_BYTES, MAX_RECORDS};
use athernex_endpoint_protocol::macos_process_events::MacosProcessEvent;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};

#[derive(Default)]
pub(super) struct Counters {
    pub received: AtomicU64,
    pub rejected: AtomicU64,
    pub drops: AtomicU64,
    pub global_gaps: AtomicU64,
    pub type_gaps: AtomicU64,
    pub regressions: AtomicU64,
    pub failed: AtomicBool,
    global: AtomicU64,
    global_seen: AtomicBool,
    per_type: [AtomicU64; 3],
    type_seen: [AtomicBool; 3],
}
impl Counters {
    pub fn add(&self, counter: &AtomicU64, amount: u64) {
        if counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_add(amount)
            })
            .is_err()
        {
            self.failed.store(true, Ordering::SeqCst);
        }
    }
    pub fn receive(&self) -> Option<u64> {
        match self
            .received
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
        {
            Ok(n) => Some(n + 1),
            Err(_) => {
                self.failed.store(true, Ordering::SeqCst);
                None
            }
        }
    }
    // Called only by the ES serial callback. Polling never changes sequence state.
    pub fn sequences(&self, kind: usize, seq: u64, global: u64) {
        self.sequence(&self.global, &self.global_seen, global, &self.global_gaps);
        self.sequence(
            &self.per_type[kind],
            &self.type_seen[kind],
            seq,
            &self.type_gaps,
        );
    }
    pub fn unknown_event_sequence(&self, global: u64) {
        self.sequence(&self.global, &self.global_seen, global, &self.global_gaps);
    }
    fn sequence(&self, previous: &AtomicU64, seen: &AtomicBool, value: u64, gaps: &AtomicU64) {
        let old = previous.swap(value, Ordering::SeqCst);
        if seen.swap(true, Ordering::SeqCst) {
            match old.checked_add(1) {
                Some(next) if value >= next => self.add(gaps, value - next),
                _ => self.add(&self.regressions, 1),
            }
        }
    }
    pub fn apply(&self, status: &mut Status) {
        let h = &mut status.health;
        h.rejected_records = self.rejected.load(Ordering::SeqCst);
        h.callback_drops = self.drops.load(Ordering::SeqCst);
        h.global_sequence_gaps = self.global_gaps.load(Ordering::SeqCst);
        h.event_sequence_gaps = self.type_gaps.load(Ordering::SeqCst);
        h.sequence_regressions = self.regressions.load(Ordering::SeqCst);
        h.received_records = self.received.load(Ordering::SeqCst);
        if self.failed.load(Ordering::SeqCst) {
            h.loss_signals = 1;
            h.error = "Process notification callback failed".into();
        }
        if h.rejected_records != 0
            || h.callback_drops != 0
            || h.global_sequence_gaps != 0
            || h.event_sequence_gaps != 0
            || h.sequence_regressions != 0
            || h.loss_signals != 0
        {
            if h.state != "stopped" {
                h.state = "degraded".into();
            }
            if h.error.is_empty() {
                h.error = "Process notification coverage is incomplete".into();
            }
        }
    }
}

struct Entry {
    event: MacosProcessEvent,
    size: usize,
}
#[derive(Default)]
pub(super) struct Queue {
    queued: VecDeque<Entry>,
    inflight: Vec<Entry>,
    bytes: usize,
    next_batch: u64,
    acknowledged: u64,
    refused: bool,
}
impl Queue {
    pub fn push(&mut self, event: MacosProcessEvent) -> crate::Result<bool> {
        let size = serde_json::to_vec(&event)
            .map_err(|_| "Process event serialization failed")?
            .len();
        if size > MAX_BATCH_BYTES {
            return Err("Process event exceeds batch capacity".into());
        }
        if self.queued.len() + self.inflight.len() >= MAX_RECORDS
            || self
                .bytes
                .checked_add(size)
                .is_none_or(|n| n > MAX_QUEUE_BYTES)
        {
            self.refused = true;
            return Ok(false);
        }
        self.bytes += size;
        self.queued.push_back(Entry { event, size });
        Ok(true)
    }
    pub fn delivery(&mut self, mut status: Status) -> crate::Result<Delivery> {
        if self.inflight.is_empty() && !self.queued.is_empty() {
            self.next_batch = self
                .next_batch
                .checked_add(1)
                .ok_or("Process batch counter exhausted")?;
            let mut bytes = 0;
            while self.inflight.len() < MAX_BATCH_RECORDS {
                let Some(front) = self.queued.front() else {
                    break;
                };
                if bytes + front.size > MAX_BATCH_BYTES {
                    break;
                }
                let entry = self.queued.pop_front().ok_or("Process queue changed")?;
                bytes += entry.size;
                self.inflight.push(entry);
            }
        }
        self.status(&mut status);
        Ok(Delivery {
            batch_id: if self.inflight.is_empty() {
                0
            } else {
                self.next_batch
            },
            events: self.inflight.iter().map(|e| e.event.clone()).collect(),
            status,
        })
    }
    pub fn acknowledge(&mut self, id: u64) -> crate::Result<()> {
        if id == 0 {
            return Err("Invalid process batch acknowledgement".into());
        }
        if id == self.acknowledged {
            return Ok(());
        }
        if self.inflight.is_empty() || id != self.next_batch {
            return Err("Process batch acknowledgement is not current".into());
        }
        for entry in self.inflight.drain(..) {
            self.bytes -= entry.size;
        }
        self.acknowledged = id;
        self.refused = false;
        Ok(())
    }
    pub fn status(&self, status: &mut Status) {
        status.pending_records = (self.queued.len() + self.inflight.len()) as u64;
        status.pending_bytes = self.bytes as u64;
        status.health.backpressured = self.refused
            || self.queued.len() + self.inflight.len() == MAX_RECORDS
            || self.bytes >= MAX_QUEUE_BYTES;
    }
}

#[derive(Default)]
pub(super) struct Shared {
    pub counters: Counters,
    pub queue: Mutex<Queue>,
    pub closing: AtomicBool,
    pub callbacks: AtomicU64,
}
impl Shared {
    pub fn enqueue(&self, event: MacosProcessEvent) {
        let accepted = self
            .queue
            .try_lock()
            .ok()
            .and_then(|mut q| q.push(event).ok())
            == Some(true);
        if !accepted {
            self.counters.add(&self.counters.drops, 1);
        }
    }
    pub fn callback(&self, work: impl FnOnce() + std::panic::UnwindSafe) {
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        struct Active<'a>(&'a AtomicU64);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _active = Active(&self.callbacks);
        if self.closing.load(Ordering::SeqCst) {
            self.counters.failed.store(true, Ordering::SeqCst);
            return;
        }
        if std::panic::catch_unwind(work).is_err() {
            self.counters.failed.store(true, Ordering::SeqCst);
        }
    }
}
