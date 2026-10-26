//! Fixed failure-only metadata; never emit source values or session identifiers.
use super::{require, Result};
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_FLAG_NETWORK_TCPIP, EVENT_TRACE_FLAG_PROCESS,
    EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN, EVENT_TRACE_REAL_TIME_MODE,
    EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN, EVENT_TRACE_SYSTEM_LOGGER_MODE,
};

const BASE_MODE: u32 = EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE;
pub(super) const NETWORK_MODE: u32 = BASE_MODE | EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN;
const PROCESS_PERSIST_MODE: u32 = BASE_MODE | EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN;

#[derive(Clone, Copy)]
pub(super) enum Ownership {
    ProcessIntent,
    ProcessIdentity,
    ProcessConfiguration,
    ProcessController,
    NetworkIdentity,
    NetworkConfiguration,
    NetworkController,
}
impl Ownership {
    fn label(self) -> &'static str {
        match self {
            Self::ProcessIntent => "process_intent",
            Self::ProcessIdentity => "process_identity",
            Self::ProcessConfiguration => "process_configuration",
            Self::ProcessController => "process_controller",
            Self::NetworkIdentity => "network_identity",
            Self::NetworkConfiguration => "network_configuration",
            Self::NetworkController => "network_controller",
        }
    }
    pub fn note(self) {
        println!("\nATHERNEX_NETWORK_SOURCE_OWNERSHIP={}", self.label());
    }
    pub fn require(self, condition: bool, error: &'static str) -> Result<()> {
        if !condition {
            self.note();
        }
        require(condition, error)
    }
    pub fn error(self, error: &'static str) -> &'static str {
        self.note();
        error
    }
}
#[derive(Clone, Copy)]
pub(super) enum Scope {
    Process,
    Network,
}
impl Scope {
    fn label(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Network => "network",
        }
    }
    fn flags(self) -> u32 {
        match self {
            Self::Process => EVENT_TRACE_FLAG_PROCESS,
            Self::Network => EVENT_TRACE_FLAG_NETWORK_TCPIP,
        }
    }
    fn branch(self) -> Ownership {
        match self {
            Self::Process => Ownership::ProcessConfiguration,
            Self::Network => Ownership::NetworkConfiguration,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Configuration {
    pub log_file_mode: u32,
    pub enable_flags: u32,
    pub client_context: u32,
    pub logfile_present: bool,
    pub logfile_offset_valid: bool,
}
impl Configuration {
    fn valid(self, scope: Scope, pinned_mode: Option<u32>) -> bool {
        // Microsoft documents an OS-selected hybrid policy if neither bit was
        // requested: https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
        // Our network source requests STOP explicitly. Query-only coexistence
        // accepts one documented process default, then pins its complete mode.
        let mode_valid = match scope {
            Scope::Network => self.log_file_mode == NETWORK_MODE,
            Scope::Process => matches!(self.log_file_mode, NETWORK_MODE | PROCESS_PERSIST_MODE),
        };
        mode_valid
            && pinned_mode.is_none_or(|expected| self.log_file_mode == expected)
            && self.enable_flags == scope.flags()
            && self.client_context == 1
            && !self.logfile_present
            && self.logfile_offset_valid
    }
    // The caller must first validate the exact private name/GUID. No offset,
    // pointer, handle, timestamp or source value is part of this projection.
    pub fn require(
        self,
        scope: Scope,
        pinned_mode: Option<u32>,
        error: &'static str,
    ) -> Result<()> {
        let valid = self.valid(scope, pinned_mode);
        if !valid {
            scope.branch().note();
            println!(
                "\nATHERNEX_NETWORK_SOURCE_CONFIGURATION={}:{}:{}:{}:{}:{}",
                scope.label(),
                self.log_file_mode,
                self.enable_flags,
                self.client_context,
                u8::from(self.logfile_present),
                u8::from(self.logfile_offset_valid)
            );
        }
        require(valid, error)
    }
}

#[test]
pub(super) fn exact_configuration_rejects_extra_modes_flags_files_and_clock_changes() {
    for (scope, mode) in [
        (Scope::Network, NETWORK_MODE),
        (Scope::Process, NETWORK_MODE),
        (Scope::Process, PROCESS_PERSIST_MODE),
    ] {
        let valid = Configuration {
            log_file_mode: mode,
            enable_flags: scope.flags(),
            client_context: 1,
            logfile_present: false,
            logfile_offset_valid: true,
        };
        assert!(valid.valid(scope, None));
        assert!(valid.valid(scope, Some(mode)));
        for bit in 0..32 {
            let mut changed = valid;
            changed.log_file_mode ^= 1 << bit;
            assert!(!changed.valid(scope, None));
            assert!(!changed.valid(scope, Some(mode)));
            let mut changed = valid;
            changed.enable_flags ^= 1 << bit;
            assert!(!changed.valid(scope, Some(mode)));
        }
        for refused in [
            0,
            BASE_MODE,
            BASE_MODE
                | EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN
                | EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN,
            u32::MAX,
        ] {
            assert!(!Configuration {
                log_file_mode: refused,
                ..valid
            }
            .valid(scope, None));
        }
        for clock in [0, 2, 3, u32::MAX] {
            assert!(!Configuration {
                client_context: clock,
                ..valid
            }
            .valid(scope, Some(mode)));
        }
        assert!(!Configuration {
            logfile_present: true,
            ..valid
        }
        .valid(scope, Some(mode)));
        assert!(!Configuration {
            logfile_offset_valid: false,
            ..valid
        }
        .valid(scope, Some(mode)));
    }
    let process = Configuration {
        log_file_mode: NETWORK_MODE,
        enable_flags: EVENT_TRACE_FLAG_PROCESS,
        client_context: 1,
        logfile_present: false,
        logfile_offset_valid: true,
    };
    let switched = Configuration {
        log_file_mode: PROCESS_PERSIST_MODE,
        ..process
    };
    assert!(switched.valid(Scope::Process, None));
    assert!(!switched.valid(Scope::Process, Some(NETWORK_MODE)));
    assert!(!process.valid(Scope::Process, Some(PROCESS_PERSIST_MODE)));
    assert!(!Configuration {
        enable_flags: EVENT_TRACE_FLAG_NETWORK_TCPIP,
        ..switched
    }
    .valid(Scope::Network, None));
}
