//! SCM lifecycle for the stable launcher. SERVICE_RUNNING means the owned
//! launcher started, not that prevention or endpoint health has been verified.
#[cfg(windows)]
mod host;
#[cfg(windows)]
pub use host::run;
#[cfg(windows)]
pub(crate) use host::{lease, Lease as ServiceLease};

pub const NAME: &str = "AthernexEndpoint";
#[cfg(windows)]
pub(crate) const LOCK: &str = "windows-service.lock";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Starting,
    Running,
    Stopping,
    Stopped,
}

/// Shared by the control callback and the worker under one mutex. In particular,
/// stop cannot race a delayed RUNNING report, and STOPPED is published only once.
struct Lifecycle {
    phase: Phase,
    exit_code: u32,
}
impl Lifecycle {
    fn new() -> Self {
        Self {
            phase: Phase::Starting,
            exit_code: 0,
        }
    }
    fn running(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::Starting {
            return Err("Service cannot return to running");
        }
        self.phase = Phase::Running;
        Ok(())
    }
    fn request_stop(&mut self) -> bool {
        if self.phase != Phase::Running {
            return false;
        }
        self.phase = Phase::Stopping;
        true
    }
    fn stopping(&mut self) -> Result<bool, &'static str> {
        match self.phase {
            Phase::Stopped => Err("Service has already stopped"),
            Phase::Stopping => Ok(false),
            _ => {
                self.phase = Phase::Stopping;
                Ok(true)
            }
        }
    }
    fn stopped(&mut self, cleanup_confirmed: bool, exit_code: u32) -> Result<(), &'static str> {
        if self.phase != Phase::Stopping || !cleanup_confirmed {
            return Err("Service stop requires confirmed cleanup and a pending stop");
        }
        self.phase = Phase::Stopped;
        self.exit_code = exit_code;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_cannot_be_overwritten_by_running_or_reported_twice() {
        let mut state = Lifecycle::new();
        assert!(!state.request_stop()); // Controls are not accepted during startup.
        state.running().unwrap();
        assert!(state.request_stop());
        assert!(!state.request_stop());
        assert!(state.running().is_err());
        state.stopped(true, 0).unwrap();
        assert!(state.stopped(true, 0).is_err());
        assert!(state.stopping().is_err());
        assert!(!state.request_stop());
    }

    #[test]
    fn unconfirmed_cleanup_never_becomes_stopped_and_failures_keep_their_code() {
        let mut state = Lifecycle::new();
        assert!(state.stopped(true, 0).is_err());
        assert!(state.stopping().unwrap()); // Startup failure also needs cleanup.
        assert!(!state.stopping().unwrap()); // Polling is not claimed progress.
        assert!(state.stopped(false, 0).is_err());
        assert_eq!(state.phase, Phase::Stopping);
        state.stopped(true, 17).unwrap();
        assert_eq!(state.exit_code, 17);
        assert!(state.stopped(true, 0).is_err());
        assert_eq!(state.exit_code, 17);
    }
}
