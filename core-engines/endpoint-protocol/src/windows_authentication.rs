//! Security-Auditing XML is retained verbatim. Normalized facts describe the
//! reported logon, not a verified account identity or localized message text.
use crate::authentication::AuthenticationOutcome;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[cfg(test)]
mod tests;
mod xml;

pub const MAX_XML_BYTES: usize = 65_536;
pub const SECURITY_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";
pub const SECURITY_PROVIDER_GUID: &str = "{54849625-5478-4994-a5ba-3e3b0328c30d}";
const EVENT_NAMESPACE: &str = "http://schemas.microsoft.com/win/2004/08/events/event";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsEventIdentity {
    pub record_id: u64,
    pub time_ms: u64,
    pub provider_name: String,
    /// Canonical lowercase, braced GUID, when the publisher supplies one.
    pub provider_guid: Option<String>,
    pub event_code: u32,
    pub version: u8,
    pub computer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAuthentication {
    pub xml: String,
    pub record_id: u64,
    pub time_ms: u64,
    pub event_code: u32,
    pub version: u8,
    pub computer: String,
    pub outcome: AuthenticationOutcome,
    pub target_user: Option<String>,
    pub target_domain: Option<String>,
    pub target_sid: Option<String>,
    pub logon_type: u32,
    pub target_logon_id: Option<u64>,
    pub authentication_package: String,
    pub logon_process: String,
    pub caller_pid: Option<u32>,
    pub caller_image: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub status: Option<u32>,
    pub sub_status: Option<u32>,
}

impl WindowsAuthentication {
    pub fn event_id(&self) -> String {
        crate::hash(format!("windows-security:{}", self.xml).as_bytes())
    }

    /// NewCredentials creates a local session with credentials to use later;
    /// it does not establish that those outbound credentials authenticated.
    pub fn service_outcome(&self) -> Option<AuthenticationOutcome> {
        (!(self.outcome == AuthenticationOutcome::Allowed && self.logon_type == 9))
            .then_some(self.outcome)
    }

    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.time_ms > now.saturating_add(60_000) || from_xml(&self.xml)?.as_ref() != Some(self)
        {
            return Err("Windows authentication facts do not match the original XML".into());
        }
        Ok(())
    }
}

/// Parses the bounded System identity of any Security-channel record. The
/// authentication publisher/version restrictions are applied by `from_xml`.
pub fn identity(input: &str) -> Result<WindowsEventIdentity, String> {
    system_identity(&xml::parse(input)?)
}

fn system_identity(root: &xml::Node) -> Result<WindowsEventIdentity, String> {
    root.require("Event")?;
    let system = root.one("System")?;
    system.require("System")?;
    let mut names = std::collections::BTreeSet::new();
    for child in &system.children {
        if !names.insert(&child.name) {
            return Err("Duplicate Windows System field".into());
        }
    }
    let provider = system.one("Provider")?;
    provider.require_empty("Provider")?;
    let provider_name = required_text(provider.attribute("Name")?, 256)?.to_owned();
    let provider_guid = provider
        .attributes
        .get("Guid")
        .map(|s| guid(s))
        .transpose()?;
    let event_code = decimal(system.one("EventID")?.leaf("EventID")?)?;
    let version = decimal(system.one("Version")?.leaf("Version")?)?;
    let record_id = decimal(system.one("EventRecordID")?.leaf("EventRecordID")?)?;
    if record_id == 0 || system.one("Channel")?.leaf("Channel")? != "Security" {
        return Err("Invalid Windows Security record identity".into());
    }
    let computer = required_text(system.one("Computer")?.leaf("Computer")?, 512)?.to_owned();
    let created = system.one("TimeCreated")?;
    created.require_empty("TimeCreated")?;
    let timestamp = created.attribute("SystemTime")?;
    if !timestamp.ends_with('Z') || timestamp.len() > 40 {
        return Err("Invalid Windows Security record timestamp".into());
    }
    let timestamp = OffsetDateTime::parse(timestamp, &Rfc3339)
        .map_err(|_| "Invalid Windows Security record timestamp")?;
    let time_ms = u64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| "Invalid Windows Security record timestamp")?;
    if time_ms == 0 {
        return Err("Invalid Windows Security record timestamp".into());
    }
    Ok(WindowsEventIdentity {
        record_id,
        time_ms,
        provider_name,
        provider_guid,
        event_code,
        version,
        computer,
    })
}

/// Only documented 4624 (versions 0..=2) and 4625 (version 0) records produce
/// facts. Field names and numeric codes, never rendered messages, determine
/// their meaning. Empty and hyphen placeholders remain unknown.
///
/// Schemas: <https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624>
/// and <https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625>.
pub fn from_xml(input: &str) -> Result<Option<WindowsAuthentication>, String> {
    let root = xml::parse(input)?;
    let id = system_identity(&root)?;
    if !matches!(id.event_code, 4624 | 4625) {
        return Ok(None);
    }
    if id.provider_name != SECURITY_PROVIDER
        || id.provider_guid.as_deref() != Some(SECURITY_PROVIDER_GUID)
        || !(id.event_code == 4624 && id.version <= 2 || id.event_code == 4625 && id.version == 0)
    {
        return Err("Unsupported Windows authentication provenance or version".into());
    }
    let data = root.one("EventData")?;
    data.require("EventData")?;
    let mut fields = BTreeMap::new();
    if data.children.len() > 128 {
        return Err("Too many Windows authentication fields".into());
    }
    for child in &data.children {
        let value = child.leaf("Data")?;
        let name = required_text(child.attribute("Name")?, 128)?;
        if fields.insert(name, value).is_some() {
            return Err("Duplicate Windows authentication field".into());
        }
    }
    let field = |name: &str| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| "Missing Windows authentication field".to_owned())
    };
    let optional = |name: &str, max| optional_text(field(name)?, max);
    let logon_type = decimal(field("LogonType")?)?;
    if !matches!(
        logon_type,
        0 | 2 | 3 | 4 | 5 | 7 | 8 | 9 | 10 | 11 | 12 | 13
    ) {
        return Err("Unsupported Windows logon type".into());
    }
    let target_sid = match optional("TargetUserSid", 184)? {
        Some(sid) if sid == "S-1-0-0" => None,
        Some(sid) if valid_sid(&sid) => Some(sid),
        None => None,
        _ => return Err("Invalid Windows target SID".into()),
    };
    let caller_pid = optional_hex(field("ProcessId")?)?
        .map(u32::try_from)
        .transpose()
        .map_err(|_| "Invalid Windows caller PID")?
        .filter(|pid| *pid != 0);
    let source_ip = optional("IpAddress", 64)?
        .map(|s| s.parse())
        .transpose()
        .map_err(|_| "Invalid Windows source address")?;
    let source_port = optional("IpPort", 5)?
        .map(|s| decimal::<u16>(&s))
        .transpose()?
        .filter(|port| *port != 0);
    let (outcome, target_logon_id, status, sub_status) = if id.event_code == 4624 {
        if fields.contains_key("Status") || fields.contains_key("SubStatus") {
            return Err("Unexpected Windows success status fields".into());
        }
        (
            AuthenticationOutcome::Allowed,
            optional_hex(field("TargetLogonId")?)?.filter(|value| *value != 0),
            None,
            None,
        )
    } else {
        if fields.contains_key("TargetLogonId") {
            return Err("Unexpected Windows failed-logon session identifier".into());
        }
        let status = |name| {
            optional_hex(field(name)?)?
                .map(u32::try_from)
                .transpose()
                .map_err(|_| "Invalid Windows authentication status".to_owned())
        };
        (
            AuthenticationOutcome::Denied,
            None,
            status("Status")?,
            status("SubStatus")?,
        )
    };
    Ok(Some(WindowsAuthentication {
        xml: input.to_owned(),
        record_id: id.record_id,
        time_ms: id.time_ms,
        event_code: id.event_code,
        version: id.version,
        computer: id.computer,
        outcome,
        target_user: optional("TargetUserName", 512)?,
        target_domain: optional("TargetDomainName", 512)?,
        target_sid,
        logon_type,
        target_logon_id,
        authentication_package: optional("AuthenticationPackageName", 256)?.unwrap_or_default(),
        logon_process: optional("LogonProcessName", 256)?.unwrap_or_default(),
        caller_pid,
        caller_image: optional("ProcessName", 4096)?,
        source_ip,
        source_port,
        status,
        sub_status,
    }))
}

fn required_text(value: &str, max: usize) -> Result<&str, String> {
    if crate::text(value, max) {
        Ok(value)
    } else {
        Err("Invalid Windows event text field".into())
    }
}

fn optional_text(value: &str, max: usize) -> Result<Option<String>, String> {
    if value.is_empty() || value == "-" {
        Ok(None)
    } else {
        required_text(value, max).map(|s| Some(s.to_owned()))
    }
}

fn decimal<T: std::str::FromStr>(value: &str) -> Result<T, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Invalid Windows decimal field".into());
    }
    value
        .parse()
        .map_err(|_| "Windows decimal field overflow".into())
}

fn optional_hex(value: &str) -> Result<Option<u64>, String> {
    if value.is_empty() || value == "-" {
        return Ok(None);
    }
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or("Invalid Windows hexadecimal field")?;
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid Windows hexadecimal field".into());
    }
    u64::from_str_radix(digits, 16)
        .map(Some)
        .map_err(|_| "Windows hexadecimal field overflow".into())
}

fn guid(value: &str) -> Result<String, String> {
    if value.len() != 38
        || !value.bytes().enumerate().all(|(i, b)| match i {
            0 => b == b'{',
            37 => b == b'}',
            9 | 14 | 19 | 24 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
    {
        return Err("Invalid Windows publisher GUID".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn valid_sid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("S-1-") else {
        return false;
    };
    let mut pieces = rest.split('-');
    let authority = pieces.next().and_then(|p| decimal::<u64>(p).ok());
    if authority.is_none_or(|value| value >= (1_u64 << 48)) {
        return false;
    }
    let mut count = 0;
    for piece in pieces {
        if decimal::<u32>(piece).is_err() {
            return false;
        }
        count += 1;
    }
    (1..=15).contains(&count)
}
