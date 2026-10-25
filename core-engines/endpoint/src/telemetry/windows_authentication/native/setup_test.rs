//! Disposable-fixture setup acknowledgments, before production collection starts.
//! No state, health history or production policy-marker semantics are changed.
use super::*;

fn failure(category: &str) -> Box<dyn std::error::Error + Send + Sync> {
    super::super::diagnostics::source(category);
    "Native audit setup source barrier failed".into()
}

fn changes(value: &str) -> Result<(u32, u32)> {
    // These are raw event resource tokens, never localized formatted messages.
    // Primary mapping: Azure/Azure-Sentinel, Tools/ParameterizedFunction/
    // AuditEventDataLookup_Func.ps1 (%%8448..%%8451).
    let (mut removed, mut added) = (0, 0);
    for token in value.split(',').map(|part| part.trim_matches(' ')) {
        let (target, bit) = match token {
            "%%8448" => (&mut removed, 1),
            "%%8449" => (&mut added, 1),
            "%%8450" => (&mut removed, 2),
            "%%8451" => (&mut added, 2),
            _ => return Err("Unknown native audit setup change token".into()),
        };
        if *target & bit != 0 {
            return Err("Duplicate native audit setup change token".into());
        }
        *target |= bit;
    }
    if removed & added != 0 {
        return Err("Conflicting native audit setup change tokens".into());
    }
    Ok((removed, added))
}

struct Expected {
    removed: [u32; 2],
    added: [u32; 2],
}
impl Expected {
    fn complete(&self) -> bool {
        self.removed == [0, 0] && self.added == [0, 0]
    }
    fn observe(&mut self, index: usize, removed: u32, added: u32) -> Result<()> {
        if index >= 2
            || removed | added == 0
            || removed & !self.removed[index] != 0
            || added & !self.added[index] != 0
        {
            return Err("Unexpected native audit setup delta".into());
        }
        self.removed[index] &= !removed;
        self.added[index] &= !added;
        Ok(())
    }
}

pub(in super::super) struct SourceBarrier {
    reader: Reader,
    position: Checkpoint,
}
impl SourceBarrier {
    pub fn capture() -> Result<Self> {
        let mut reader = Reader::open()?;
        // Original audit policy may be disabled. This is a private pre-mutation
        // source position, not a healthy collection claim or durable checkpoint.
        let (position, _) = reader.baseline()?;
        println!("\nATHERNEX_AUTH_STAGE=setup_position_ready");
        Ok(Self { reader, position })
    }
    pub fn observe(&mut self, removed: [u32; 2], added: [u32; 2]) -> Result<()> {
        if removed.iter().chain(&added).any(|bits| bits & !3 != 0) {
            return Err(failure("setup_barrier_delta_unexpected"));
        }
        let mut expected = Expected { removed, added };
        // Only a verified unchanged clear has no expected notification.
        if expected.complete() {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut inspected = 0;
        loop {
            let caught_up = self.batch(&mut expected, &mut inspected)?;
            if expected.complete() && caught_up {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(failure("setup_barrier_timeout"));
            }
            if caught_up {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    fn batch(&mut self, expected: &mut Expected, inspected: &mut usize) -> Result<bool> {
        let _security = privilege::SecurityPrivilege::acquire()?;
        let log = Handle::checked(
            unsafe { EvtOpenLog(0, windows_sys::core::w!("Security"), EvtOpenChannelPath) },
            "Audit setup source metadata open",
        )?;
        let created = policy::log_created(&log)?;
        let query = Reader::query(false)?;
        if created != self.position.log_created_filetime
            || !self.reader.seek_anchor(&query, &self.position)?
        {
            return Err(failure("setup_barrier_continuity"));
        }
        for _ in 0..64 {
            let Some(event) = api::next(&query)? else {
                return Ok(true);
            };
            *inspected += 1;
            if *inspected > 4096 {
                return Err(failure("setup_barrier_budget"));
            }
            let identity = Identity::read(&self.reader.context, &event)?;
            if self.position.record_id.checked_add(1) != Some(identity.record_id)
                || (identity.eventlog()
                    && [1100, 1101, 1102, 1104, 1108].contains(&identity.event_code))
                || (identity.auditing() && identity.event_code == 4912)
            {
                return Err(failure("setup_barrier_continuity"));
            }
            if identity.event_code == 4719
                && identity.provider_name == "Microsoft-Windows-Security-Auditing"
            {
                if !identity.auditing() {
                    super::super::diagnostics::source("setup_policy_provider_mismatch");
                    return Err(failure("setup_barrier_scope_invalid"));
                }
                if identity.version != Some(0) {
                    super::super::diagnostics::source(match identity.version {
                        None => "setup_policy_version_missing",
                        Some(1) => "setup_policy_version_1",
                        _ => "setup_policy_version_other",
                    });
                    return Err(failure("setup_barrier_scope_invalid"));
                }
                Self::notification(&event, expected)?;
            }
            self.position = Reader::checkpoint(&event, &identity, created, false)?;
        }
        Ok(false)
    }
    fn notification(event: &Handle, expected: &mut Expected) -> Result<()> {
        let paths = [
            api::wide("Event/EventData/Data[@Name='SubcategoryGuid']"),
            api::wide("Event/EventData/Data[@Name='AuditPolicyChanges']"),
            api::wide("Event/EventData/Data[@Name='SubjectUserSid']"),
        ];
        let pointers = paths.each_ref().map(|path| path.as_ptr());
        let context = Handle::checked(
            unsafe { EvtCreateRenderContext(3, pointers.as_ptr(), EvtRenderContextValues) },
            "Audit setup event context",
        )?;
        let values = Values::render(&context, event, 3)?;
        let scope = values.required_guid(0).map_err(|error| {
            super::super::diagnostics::source("setup_policy_guid_invalid");
            super::super::diagnostics::source(match values.diagnostic_kind(0) {
                "guid" => "setup_scope_guid",
                "string" => "setup_scope_string",
                "null" => "setup_scope_null",
                "array" => "setup_scope_array",
                _ => "setup_scope_other",
            });
            super::super::diagnostics::classify(error.as_ref());
            failure("setup_barrier_scope_invalid")
        })?;
        let index = if scope == api::guid_text(&Audit_Logon_Logon) {
            0
        } else if scope == api::guid_text(&Audit_Logon_AccountLockout) {
            1
        } else {
            return Ok(());
        };
        if !values
            .local_system_sid(2)
            .map_err(|_| failure("setup_barrier_subject_invalid"))?
        {
            return Err(failure("setup_barrier_subject_invalid"));
        }
        let value = values
            .string(1, 128)
            .map_err(|_| failure("setup_barrier_changes_invalid"))?;
        let (removed, added) =
            changes(&value).map_err(|_| failure("setup_barrier_changes_invalid"))?;
        expected
            .observe(index, removed, added)
            .map_err(|_| failure("setup_barrier_delta_unexpected"))
    }
}

pub(in super::super) fn verify_setup_delta_parser() {
    assert!(changes("%%8448, %%8450").is_ok_and(|value| value == (3, 0)));
    assert!(changes("%%8451, %%8449").is_ok_and(|value| value == (0, 3)));
    for invalid in [
        "",
        "8449",
        "Success added",
        "%%9999",
        "%%8449, %%8449",
        "%%8448, %%8449",
    ] {
        assert!(
            changes(invalid).is_err(),
            "Invalid synthetic setup delta was accepted"
        );
    }
    let mut expected = Expected {
        removed: [3, 0],
        added: [0, 2],
    };
    assert!(expected.observe(0, 1, 0).is_ok());
    assert!(!expected.complete());
    assert!(expected.observe(0, 1, 0).is_err());
    assert!(expected.observe(0, 0, 1).is_err());
    assert!(expected.observe(1, 0, 1).is_err());
    assert!(expected.observe(0, 2, 0).is_ok());
    assert!(!expected.complete());
    assert!(expected.observe(1, 0, 2).is_ok());
    assert!(expected.complete());
    assert!(expected.observe(1, 0, 2).is_err());
    assert!(expected.observe(2, 0, 1).is_err());
}

#[test]
fn setup_barrier_requires_exact_per_scope_native_change_tokens() {
    verify_setup_delta_parser();
}
