//! Enumerate every Security position, retaining only supported logon XML.
//! The bookmark anchor hashes native System identity, not the full event body.
mod api;
mod policy;
pub(super) mod privilege;
use super::{Batch, Checkpoint};
use crate::Result;
use api::{Handle, Values};
use athernex_endpoint_protocol::{
    self as protocol,
    windows_authentication::{from_xml, MAX_XML_BYTES},
};
use serde::Serialize;
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::*,
    Security::Authentication::Identity::{Audit_Logon_AccountLockout, Audit_Logon_Logon},
    System::EventLog::*,
};

const AUDITING: &str = "{54849625-5478-4994-a5ba-3e3b0328c30d}";
const EVENTLOG: &str = "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}";

#[derive(Serialize)]
struct Identity {
    record_id: u64,
    filetime: u64,
    provider_name: String,
    provider_guid: Option<String>,
    event_code: u32,
    version: Option<u8>,
    computer: String,
    channel: String,
}
impl Identity {
    fn read(context: &Handle, event: &Handle) -> Result<Self> {
        let fields = Values::render(context, event, EvtSystemPropertyIdEND as usize)?;
        let value = Self {
            record_id: fields.record_id()?,
            filetime: fields.filetime()?,
            provider_name: fields.string(EvtSystemProviderName, 256)?,
            provider_guid: fields.guid(EvtSystemProviderGuid)?,
            event_code: fields.code()?,
            version: fields.version()?,
            computer: fields.string(EvtSystemComputer, 256)?,
            channel: fields.string(EvtSystemChannel, 64)?,
        };
        if value.record_id == 0
            || value.filetime <= 116_444_736_000_000_000
            || value.channel != "Security"
            || value.computer.is_empty()
        {
            return Err("Invalid native Windows Security event identity".into());
        }
        Ok(value)
    }
    fn hash(&self) -> Result<String> {
        Ok(protocol::hash(&serde_json::to_vec(self)?))
    }
    fn time_ms(&self) -> u64 {
        (self.filetime - 116_444_736_000_000_000) / 10_000
    }
    fn auditing(&self) -> bool {
        self.provider_name == "Microsoft-Windows-Security-Auditing"
            && self.provider_guid.as_deref() == Some(AUDITING)
    }
    fn eventlog(&self) -> bool {
        self.provider_name == "Microsoft-Windows-Eventlog"
            && self.provider_guid.as_deref() == Some(EVENTLOG)
    }
}
pub(super) struct Reader {
    context: Handle,
    last_policy: Instant,
    policy_error: String,
}
impl Reader {
    #[cfg(test)]
    pub(super) fn original(record_id: u64) -> Result<String> {
        let _security = privilege::SecurityPrivilege::acquire().ok();
        let filter = api::wide(&format!("*[System[EventRecordID={record_id}]]"));
        let query = Handle::checked(
            unsafe {
                EvtQuery(
                    0,
                    windows_sys::core::w!("Security"),
                    filter.as_ptr(),
                    EvtQueryChannelPath | EvtQueryForwardDirection,
                )
            },
            "Windows Security original verification query",
        )?;
        let event = api::next(&query)?.ok_or("Windows Security original is no longer retained")?;
        api::text(&event, EvtRenderEventXml, MAX_XML_BYTES)
    }
    pub fn open() -> Result<Self> {
        Ok(Self {
            context: api::system_context()?,
            last_policy: Instant::now() - Duration::from_secs(2),
            policy_error: String::new(),
        })
    }
    fn query(reverse: bool) -> Result<Handle> {
        Handle::checked(
            unsafe {
                EvtQuery(
                    0,
                    windows_sys::core::w!("Security"),
                    windows_sys::core::w!("*"),
                    EvtQueryChannelPath
                        | if reverse {
                            EvtQueryReverseDirection
                        } else {
                            EvtQueryForwardDirection
                        },
                )
            },
            "Windows Security query",
        )
    }
    fn source(&mut self) -> Result<(u64, String)> {
        let log = Handle::checked(
            unsafe { EvtOpenLog(0, windows_sys::core::w!("Security"), EvtOpenChannelPath) },
            "Windows Security log metadata open",
        )?;
        #[cfg(test)]
        super::diagnostics::source("log_opened");
        let created = policy::log_created(&log)?;
        #[cfg(test)]
        super::diagnostics::source("log_identity_ready");
        if self.last_policy.elapsed() >= Duration::from_secs(1) {
            self.policy_error = match policy::check() {
                Ok(()) => String::new(),
                Err(error) => error.to_string().chars().take(256).collect(),
            };
            self.last_policy = Instant::now();
        }
        #[cfg(test)]
        super::diagnostics::source("audit_policy_checked");
        let error = if !policy::enabled()? {
            "Windows Security channel is disabled".into()
        } else if policy::log_full(&log)? {
            "Windows Security log is full; new events may not be recorded".into()
        } else {
            self.policy_error.clone()
        };
        #[cfg(test)]
        super::diagnostics::source("channel_health_checked");
        Ok((created, error))
    }
    fn checkpoint(
        event: &Handle,
        identity: &Identity,
        created: u64,
        policy_healthy: bool,
    ) -> Result<Checkpoint> {
        let bookmark = Handle::checked(
            unsafe { EvtCreateBookmark(std::ptr::null()) },
            "Windows Security bookmark creation",
        )?;
        if unsafe { EvtUpdateBookmark(bookmark.0, event.0) } == 0 {
            return Err(api::failure("Windows Security bookmark update"));
        }
        let result = Checkpoint {
            bookmark: api::text(&bookmark, EvtRenderBookmark, 4096)?,
            anchor_sha256: identity.hash()?,
            record_id: identity.record_id,
            log_created_filetime: created,
            policy_healthy,
            cursor_missing: false,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn baseline(&mut self) -> Result<(Checkpoint, String)> {
        // Privilege activation is confined to this read on a duplicate of the
        // effective token. ACL-authorized readers without it still get a read
        // attempt; API failures remain coverage failures.
        let _security = privilege::SecurityPrivilege::acquire().ok();
        let (created, error) = self.source()?;
        let query = Self::query(true)?;
        #[cfg(test)]
        super::diagnostics::source("baseline_query_ready");
        let event = api::next(&query)?.ok_or("Windows Security log has no baseline record")?;
        #[cfg(test)]
        super::diagnostics::source("baseline_record_ready");
        let identity = Identity::read(&self.context, &event)?;
        #[cfg(test)]
        super::diagnostics::source("baseline_identity_ready");
        let checkpoint = Self::checkpoint(&event, &identity, created, error.is_empty())?;
        #[cfg(test)]
        super::diagnostics::source("baseline_bookmark_ready");
        Ok((checkpoint, error))
    }
    fn seek_anchor(&self, query: &Handle, previous: &Checkpoint) -> Result<bool> {
        let xml = api::wide(&previous.bookmark);
        let bookmark = Handle::checked(
            unsafe { EvtCreateBookmark(xml.as_ptr()) },
            "Windows Security persisted bookmark",
        )?;
        if unsafe {
            EvtSeek(
                query.0,
                0,
                bookmark.0,
                0,
                EvtSeekRelativeToBookmark | EvtSeekStrict,
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            #[cfg(test)]
            super::diagnostics::native("source_seek", code);
            return match code {
                ERROR_NOT_FOUND
                | ERROR_EVT_QUERY_RESULT_STALE
                | ERROR_EVT_QUERY_RESULT_INVALID_POSITION => Ok(false),
                _ => Err(format!(
                    "Windows Security strict bookmark seek failed with Windows error {code}"
                )
                .into()),
            };
        }
        let Some(event) = api::next(query)? else {
            return Ok(false);
        };
        let identity = Identity::read(&self.context, &event)?;
        Ok(identity.record_id == previous.record_id && identity.hash()? == previous.anchor_sha256)
    }
    fn policy_marker(event: &Handle) -> Result<bool> {
        let path = api::wide("Event/EventData/Data[@Name='SubcategoryGuid']");
        let paths = [path.as_ptr()];
        let context = Handle::checked(
            unsafe { EvtCreateRenderContext(1, paths.as_ptr(), EvtRenderContextValues) },
            "Windows audit policy scope context",
        )?;
        let values = Values::render(&context, event, 1)?;
        let value = values.string(0, 64)?.to_ascii_lowercase();
        Ok(value == api::guid_text(&Audit_Logon_Logon)
            || value == api::guid_text(&Audit_Logon_AccountLockout))
    }
    pub fn batch(&mut self, previous: &Checkpoint) -> Result<Batch> {
        let _security = privilege::SecurityPrivilege::acquire().ok();
        previous.validate()?;
        let (created, error) = self.source()?;
        let mut result = Batch {
            checkpoint: previous.clone(),
            source_error: error,
            ..Default::default()
        };
        result.checkpoint.log_created_filetime = created;
        result.checkpoint.policy_healthy = result.source_error.is_empty();
        if previous.policy_healthy && !result.checkpoint.policy_healthy {
            result.loss_signals += 1;
        }
        let mut query = Self::query(false)?;
        let same_log = created == previous.log_created_filetime;
        let resumed = same_log && !previous.cursor_missing && self.seek_anchor(&query, previous)?;
        if !resumed {
            if !previous.cursor_missing || !same_log {
                result.loss_signals += 1;
            }
            result.checkpoint.cursor_missing = true;
            query = Self::query(false)?;
        }
        let mut last_id = resumed.then_some(previous.record_id);
        while result.received_records < 64 {
            let Some(event) = api::next(&query)? else {
                result.caught_up = true;
                break;
            };
            let identity = Identity::read(&self.context, &event)?;
            if last_id.is_some_and(|last| last.checked_add(1) != Some(identity.record_id)) {
                result.loss_signals += 1;
            }
            last_id = Some(identity.record_id);
            result.received_records += 1;
            result.last_record_ms = identity.time_ms();
            if identity.auditing() && [4624, 4625].contains(&identity.event_code) {
                let normalized = (|| -> Result<_> {
                    let xml = api::text(&event, EvtRenderEventXml, MAX_XML_BYTES)?;
                    let value = from_xml(&xml)?
                        .ok_or("Supported Windows logon record did not normalize")?;
                    if value.record_id != identity.record_id
                        || value.time_ms != identity.time_ms()
                        || value.event_code != identity.event_code
                        || Some(value.version) != identity.version
                        || value.computer != identity.computer
                    {
                        return Err(
                            "Windows logon XML differs from its native System identity".into()
                        );
                    }
                    Ok(value)
                })();
                match normalized {
                    Ok(value) => result.events.push(value),
                    Err(_) => result.rejected_records += 1,
                }
            } else if identity.provider_name == "Microsoft-Windows-Security-Auditing"
                && [4624, 4625].contains(&identity.event_code)
            {
                result.rejected_records += 1;
            } else if (identity.eventlog()
                && [1100, 1101, 1102, 1104, 1108].contains(&identity.event_code))
                || (identity.auditing() && identity.event_code == 4912)
                || (identity.auditing()
                    && identity.event_code == 4719
                    && Self::policy_marker(&event).unwrap_or(true))
            {
                // Unknown policy-change scope is uncertainty, never evidence of
                // unchanged logon coverage. No unrelated event payload is saved.
                result.loss_signals += 1;
            }
            result.checkpoint =
                Self::checkpoint(&event, &identity, created, result.source_error.is_empty())?;
        }
        Ok(result)
    }
}
