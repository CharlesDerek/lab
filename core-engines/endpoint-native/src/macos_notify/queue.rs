use super::{MAX_BATCH_BYTES, MAX_BATCH_RECORDS, MAX_QUEUE_BYTES, MAX_RECORDS};
use serde::Serialize;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};

pub(crate) struct Counters<const LANES: usize> {
    pub received: AtomicU64,
    pub rejected: AtomicU64,
    pub drops: AtomicU64,
    pub global_gaps: AtomicU64,
    pub type_gaps: AtomicU64,
    pub regressions: AtomicU64,
    pub failed: AtomicBool,
    global: AtomicU64,
    global_seen: AtomicBool,
    per_type: [AtomicU64; LANES],
    type_seen: [AtomicBool; LANES],
}
impl<const LANES: usize> Default for Counters<LANES> {
    fn default() -> Self {
        Self {
            received: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            global_gaps: AtomicU64::new(0),
            type_gaps: AtomicU64::new(0),
            regressions: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            global: AtomicU64::new(0),
            global_seen: AtomicBool::new(false),
            per_type: std::array::from_fn(|_| AtomicU64::new(0)),
            type_seen: std::array::from_fn(|_| AtomicBool::new(false)),
        }
    }
}
impl<const LANES: usize> Counters<LANES> {
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
}

struct Entry<E> {
    event: E,
    size: usize,
}
pub(crate) struct Queue<E> {
    queued: VecDeque<Entry<E>>,
    inflight: Vec<Entry<E>>,
    bytes: usize,
    next_batch: u64,
    acknowledged: u64,
    refused: bool,
}
impl<E> Default for Queue<E> {
    fn default() -> Self {
        Self {
            queued: VecDeque::new(),
            inflight: Vec::new(),
            bytes: 0,
            next_batch: 0,
            acknowledged: 0,
            refused: false,
        }
    }
}
pub(crate) trait QueueStatus<E> {
    type Delivery;
    fn pending(&mut self, records: u64, bytes: u64, backpressured: bool);
    fn delivery(self, id: u64, events: Vec<E>) -> Self::Delivery;
}
impl<E: Clone + Serialize> Queue<E> {
    pub fn push(&mut self, event: E) -> crate::Result<bool> {
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
    pub fn delivery<S: QueueStatus<E>>(&mut self, mut status: S) -> crate::Result<S::Delivery> {
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
        Ok(status.delivery(
            if self.inflight.is_empty() {
                0
            } else {
                self.next_batch
            },
            self.inflight.iter().map(|e| e.event.clone()).collect(),
        ))
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
    pub fn status<S: QueueStatus<E>>(&self, status: &mut S) {
        status.pending(
            (self.queued.len() + self.inflight.len()) as u64,
            self.bytes as u64,
            self.refused
                || self.queued.len() + self.inflight.len() == MAX_RECORDS
                || self.bytes >= MAX_QUEUE_BYTES,
        );
    }
}

pub(crate) struct Shared<E, const LANES: usize> {
    pub counters: Counters<LANES>,
    pub queue: Mutex<Queue<E>>,
    pub closing: AtomicBool,
    pub callbacks: AtomicU64,
}
impl<E, const LANES: usize> Default for Shared<E, LANES> {
    fn default() -> Self {
        Self {
            counters: Counters::default(),
            queue: Mutex::new(Queue::default()),
            closing: AtomicBool::new(false),
            callbacks: AtomicU64::new(0),
        }
    }
}
impl<E: Clone + Serialize, const LANES: usize> Shared<E, LANES> {
    pub fn enqueue(&self, event: E) {
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
