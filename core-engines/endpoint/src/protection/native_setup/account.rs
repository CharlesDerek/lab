//! Journal the exact Directory Service identities before creating either record.
//! Existing records require matching generated IDs; completed accounts are read-only.
use crate::{private_write, secret, update, Result};
use athernex_endpoint_native::child;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, process::Command, time::Duration};

const NAME: &str = "_athernexav";
type Record = BTreeMap<String, Vec<String>>;
trait Directory {
    fn ids(&mut self, kind: &str, key: &str) -> Result<BTreeMap<String, u32>>;
    fn record(&mut self, kind: &str) -> Result<Option<Record>>;
    fn set(&mut self, kind: &str, key: &str, value: &str) -> Result<()>;
    fn resolved(&mut self, uid: u32, gid: u32) -> Result<()>;
}
pub(super) struct MacDirectory;
fn command(args: &[&str]) -> Result<Vec<u8>> {
    let (code, output) = child::run(
        Command::new("/usr/bin/dscl").args(args),
        Duration::from_secs(15),
        1024 * 1024,
    )?;
    if code != 0 {
        return Err(
            format!("Directory Service command failed ({code}); native setup stopped").into(),
        );
    }
    Ok(output)
}
fn parse_record(bytes: &[u8]) -> Result<Record> {
    let values: BTreeMap<String, serde_json::Value> = serde_json::from_slice(bytes)?;
    let mut result = Record::new();
    for (key, value) in values {
        let Some(key) = key.strip_prefix("dsAttrTypeStandard:") else {
            continue;
        };
        // Keep only installation-relevant attributes, never credential material.
        if ![
            "GeneratedUID",
            "RecordName",
            "UniqueID",
            "PrimaryGroupID",
            "UserShell",
            "NFSHomeDirectory",
            "AuthenticationAuthority",
            "Password",
            "IsHidden",
            "GroupMembership",
            "GroupMembers",
            "NestedGroups",
        ]
        .contains(&key)
        {
            continue;
        }
        let strings = value
            .as_array()
            .ok_or("Invalid directory attribute array")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or("Invalid directory attribute value")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        result.insert(key.to_string(), strings);
    }
    Ok(result)
}
impl Directory for MacDirectory {
    fn ids(&mut self, kind: &str, key: &str) -> Result<BTreeMap<String, u32>> {
        // Search includes the configured directory search policy, not just local IDs.
        let bytes = command(&["/Search", "-list", &format!("/{kind}"), key])?;
        let text = std::str::from_utf8(&bytes)?;
        let mut values = BTreeMap::new();
        for line in text.lines().filter(|s| !s.trim().is_empty()) {
            let parts: Vec<_> = line.split_whitespace().collect();
            // A partially created record can legitimately lack this attribute.
            if parts.len() == 1 {
                continue;
            }
            // macOS may print nobody's sentinel identity as -2.
            let raw: i64 = parts.last().ok_or("Invalid directory listing")?.parse()?;
            if !(i32::MIN as i64..=u32::MAX as i64).contains(&raw) {
                return Err("Directory identity exceeds the OS numeric range".into());
            }
            let id = raw as u32;
            let name = parts[..parts.len() - 1].join(" ");
            if values.insert(name, id).is_some() {
                return Err("Duplicate directory record name".into());
            }
        }
        Ok(values)
    }
    fn record(&mut self, kind: &str) -> Result<Option<Record>> {
        let bytes = command(&[".", "-list", &format!("/{kind}")])?;
        if !std::str::from_utf8(&bytes)?
            .lines()
            .any(|line| line.trim() == NAME)
        {
            return Ok(None);
        }
        let xml = command(&["-plist", ".", "-read", &format!("/{kind}/{NAME}")])?;
        let (code, json) = child::run_with_input(
            Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-", "-"]),
            Duration::from_secs(15),
            1024 * 1024,
            &xml,
        )?;
        if code != 0 {
            return Err("Directory record could not be decoded".into());
        }
        Ok(Some(parse_record(&json)?))
    }
    fn set(&mut self, kind: &str, key: &str, value: &str) -> Result<()> {
        command(&[".", "-create", &format!("/{kind}/{NAME}"), key, value])?;
        Ok(())
    }
    fn resolved(&mut self, uid: u32, gid: u32) -> Result<()> {
        for (flag, expected) in [("-u", uid), ("-g", gid), ("-G", gid)] {
            let (code, output) = child::run(
                Command::new("/usr/bin/id").args([flag, NAME]),
                Duration::from_secs(15),
                4096,
            )?;
            if code != 0 || std::str::from_utf8(&output)?.trim() != expected.to_string() {
                return Err(
                    "Scanner identity lookup or supplementary groups do not match setup".into(),
                );
            }
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    endpoint_id: String,
    uid: u32,
    gid: u32,
    user_uuid: String,
    group_uuid: String,
    complete: bool,
}
fn uuid() -> Result<String> {
    let raw = secret()?.to_ascii_uppercase();
    Ok(format!(
        "{}-{}-4{}-A{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[13..16],
        &raw[17..20],
        &raw[20..32]
    ))
}
fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}
fn expected(j: &Journal, kind: &str) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        (
            "GeneratedUID",
            if kind == "Users" {
                j.user_uuid.clone()
            } else {
                j.group_uuid.clone()
            },
        ),
        ("RecordName", NAME.into()),
    ];
    if kind == "Users" {
        fields.extend([
            ("AuthenticationAuthority", ";DisabledUser;".into()),
            ("Password", "*".into()),
            ("UserShell", "/usr/bin/false".into()),
            ("NFSHomeDirectory", "/var/empty".into()),
            ("IsHidden", "1".into()),
            ("PrimaryGroupID", j.gid.to_string()),
            ("UniqueID", j.uid.to_string()),
        ]);
    } else {
        fields.push(("PrimaryGroupID", j.gid.to_string()));
    }
    fields
}
fn validate_record(j: &Journal, kind: &str, record: &Record, complete: bool) -> Result<()> {
    let fields = expected(j, kind);
    for (key, value) in &fields {
        if (complete || *key == "GeneratedUID") && record.get(*key) != Some(&vec![value.clone()]) {
            return Err(
                "Dedicated scanner record was replaced, shared or modified; review required".into(),
            );
        }
    }
    if kind == "Groups"
        && ["GroupMembership", "GroupMembers", "NestedGroups"]
            .iter()
            .any(|key| record.get(*key).is_some_and(|v| !v.is_empty()))
    {
        return Err(
            "Dedicated scanner group must not contain explicit members or nested groups".into(),
        );
    }
    Ok(())
}
fn unused(ids: &BTreeMap<String, u32>, id: u32) -> bool {
    ids.iter().all(|(name, value)| *value != id || name == NAME)
}
fn ensure(
    directory: &mut impl Directory,
    prior: Option<Journal>,
    endpoint: &str,
    mut save: impl FnMut(&Journal) -> Result<()>,
) -> Result<Journal> {
    let users = directory.ids("Users", "UniqueID")?;
    let groups = directory.ids("Groups", "PrimaryGroupID")?;
    let primary = directory.ids("Users", "PrimaryGroupID")?;
    let mut journal = match prior {
        Some(j) => {
            if j.schema != 1
                || j.endpoint_id != endpoint
                || !(200..500).contains(&j.uid)
                || !(200..500).contains(&j.gid)
                || !valid_uuid(&j.user_uuid)
                || !valid_uuid(&j.group_uuid)
                || j.user_uuid == j.group_uuid
            {
                return Err("Invalid scanner account setup journal".into());
            }
            j
        }
        None => {
            if users.contains_key(NAME)
                || groups.contains_key(NAME)
                || directory.record("Users")?.is_some()
                || directory.record("Groups")?.is_some()
            {
                return Err(
                    "An unowned scanner account or group already exists; review required".into(),
                );
            }
            let uid = (200..500)
                .rev()
                .find(|id| !users.values().any(|v| v == id))
                .ok_or("No unused scanner UID in the system account range")?;
            let gid = (200..500)
                .rev()
                .find(|id| !groups.values().chain(primary.values()).any(|v| v == id))
                .ok_or("No unused scanner GID in the system account range")?;
            let j = Journal {
                schema: 1,
                endpoint_id: endpoint.into(),
                uid,
                gid,
                user_uuid: uuid()?,
                group_uuid: uuid()?,
                complete: false,
            };
            save(&j)?;
            j
        }
    };
    if !unused(&users, journal.uid)
        || !unused(&groups, journal.gid)
        || !unused(&primary, journal.gid)
    {
        return Err("Dedicated scanner numeric identity is already used by another record".into());
    }
    // Validate both existing records before mutating either one.
    for kind in ["Groups", "Users"] {
        match directory.record(kind)? {
            Some(record) => validate_record(&journal, kind, &record, journal.complete)?,
            None if journal.complete => {
                return Err("Dedicated scanner record disappeared; review required".into())
            }
            None => {}
        }
    }
    if !journal.complete {
        for kind in ["Groups", "Users"] {
            for (key, value) in expected(&journal, kind) {
                directory.set(kind, key, &value)?;
            }
        }
    }
    for kind in ["Groups", "Users"] {
        validate_record(
            &journal,
            kind,
            &directory
                .record(kind)?
                .ok_or("Created scanner record is unavailable")?,
            true,
        )?;
    }
    if !unused(&directory.ids("Users", "UniqueID")?, journal.uid)
        || !unused(&directory.ids("Groups", "PrimaryGroupID")?, journal.gid)
        || !unused(&directory.ids("Users", "PrimaryGroupID")?, journal.gid)
    {
        return Err("Scanner identity changed during setup".into());
    }
    directory.resolved(journal.uid, journal.gid)?;
    if !journal.complete {
        journal.complete = true;
        save(&journal)?;
    }
    Ok(journal)
}
pub(super) fn prepare(
    directory: &mut MacDirectory,
    state: &Path,
    endpoint: &str,
) -> Result<(u32, u32)> {
    let path = state.join("protection/setup-account.json");
    let prior = if path.try_exists()? {
        update::check_destination(&path)?;
        Some(serde_json::from_slice(&update::read_bounded(&path, 8192)?)?)
    } else {
        None
    };
    let journal = ensure(directory, prior, endpoint, |j| {
        private_write(&path, &serde_json::to_vec(j)?)
    })?;
    Ok((journal.uid, journal.gid))
}

#[cfg(test)]
mod tests;
