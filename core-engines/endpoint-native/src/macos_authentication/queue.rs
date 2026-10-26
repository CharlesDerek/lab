use super::{Delivery, Status};
use athernex_endpoint_protocol::macos_authentication::MacosAuthentication;
use std::sync::atomic::Ordering;
pub(super) type Counters = crate::macos_notify::queue::Counters<1>;
#[cfg(test)]
pub(super) type Queue = crate::macos_notify::queue::Queue<MacosAuthentication>;
pub(super) type Shared = crate::macos_notify::queue::Shared<MacosAuthentication, 1>;
impl crate::macos_notify::queue::QueueStatus<MacosAuthentication> for Status {
    type Delivery = Delivery;
    fn pending(&mut self, records: u64, bytes: u64, backpressured: bool) {
        self.pending_records = records;
        self.pending_bytes = bytes;
        self.health.backpressured = backpressured;
    }
    fn delivery(self, batch_id: u64, events: Vec<MacosAuthentication>) -> Delivery {
        Delivery {
            batch_id,
            events,
            status: self,
        }
    }
}
impl Counters {
    pub(super) fn apply(&self, status: &mut Status) {
        let h = &mut status.health;
        h.rejected_records = self.rejected.load(Ordering::SeqCst);
        h.callback_drops = self.drops.load(Ordering::SeqCst);
        h.global_sequence_gaps = self.global_gaps.load(Ordering::SeqCst);
        h.event_sequence_gaps = self.type_gaps.load(Ordering::SeqCst);
        h.sequence_regressions = self.regressions.load(Ordering::SeqCst);
        h.received_records = self.received.load(Ordering::SeqCst);
        if self.failed.load(Ordering::SeqCst) {
            h.loss_signals = 1;
            h.error = "Authentication notification callback failed".into();
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
                h.error = "Authentication notification coverage is incomplete".into();
            }
        }
    }
}
