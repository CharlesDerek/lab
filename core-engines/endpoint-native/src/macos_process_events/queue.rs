use super::{Delivery, Status};
use athernex_endpoint_protocol::macos_process_events::MacosProcessEvent;
use std::sync::atomic::Ordering;
pub(super) type Counters = crate::macos_notify::queue::Counters<3>;
#[cfg(test)]
pub(super) type Queue = crate::macos_notify::queue::Queue<MacosProcessEvent>;
pub(super) type Shared = crate::macos_notify::queue::Shared<MacosProcessEvent, 3>;
impl crate::macos_notify::queue::QueueStatus<MacosProcessEvent> for Status {
    type Delivery = Delivery;
    fn pending(&mut self, records: u64, bytes: u64, backpressured: bool) {
        self.pending_records = records;
        self.pending_bytes = bytes;
        self.health.backpressured = backpressured;
    }
    fn delivery(self, batch_id: u64, events: Vec<MacosProcessEvent>) -> Delivery {
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
