//! Bounded Linux journal adapter. Reads the OS journal; never executes log text.
//! Journal cursors checkpoint only with the archive commit that contains their events.
use crate::{
    engine::{Engine, LabResult},
    gateway::digest,
    model::*,
    operations::Source,
};
use serde_json::Value;
use std::{
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{ChildStdout, Command},
    sync::watch,
};
const FIELDS:&str="__CURSOR,__REALTIME_TIMESTAMP,_HOSTNAME,_COMM,_EXE,_PID,_UID,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY,MESSAGE,UNIT";
fn field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
fn label(value: &str) -> String {
    let value = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_.@:/".contains(*c))
        .take(64)
        .collect::<String>();
    if value.is_empty() {
        "unknown".into()
    } else {
        value
    }
}
fn token_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    text.split_once(marker)?.1.split_whitespace().next()
}
fn bounded(value: &str, max: usize) -> String {
    let mut s = String::new();
    for c in value.chars().filter(|c| !c.is_control()) {
        if s.len() + c.len_utf8() > max {
            break;
        }
        s.push(c);
    }
    s
}
/// A generic journal line remains a system observation. Severity or a process
/// name alone is not evidence of successful execution, privilege escalation or egress.
pub fn normalize(record: &Value, source: &str, now: u64) -> LabResult<InputEvent> {
    let cursor = field(record, "__CURSOR");
    if cursor.is_empty() || cursor.len() > 512 {
        return Err("Journal record has no usable cursor".into());
    }
    let time_ms = field(record, "__REALTIME_TIMESTAMP")
        .parse::<u64>()
        .map_err(|_| "Journal timestamp is invalid")?
        / 1000;
    let message = field(record, "MESSAGE");
    let comm = field(record, "_COMM");
    let exe = field(record, "_EXE");
    let uid = field(record, "_UID").parse::<u32>().ok();
    let mut subject = uid
        .map(|u| format!("uid-{u}"))
        .unwrap_or_else(|| label(comm));
    let mut object = label(if field(record, "UNIT").is_empty() {
        field(record, "_SYSTEMD_UNIT")
    } else {
        field(record, "UNIT")
    });
    let mut kind = Kind::System;
    let mut outcome = Outcome::Observe;
    let mut severity = match field(record, "PRIORITY").parse::<u8>().unwrap_or(6) {
        0..=2 => 5,
        3 => 4,
        4 => 3,
        5..=6 => 2,
        _ => 1,
    };
    let mut summary = "Journal observation; no supported security pattern matched";
    let ssh = matches!(
        exe,
        "/usr/sbin/sshd" | "/usr/lib/openssh/sshd-session" | "/usr/libexec/openssh/sshd-session"
    );
    let pam = ssh
        || matches!(
            exe,
            "/usr/bin/sudo" | "/usr/bin/login" | "/bin/login" | "/usr/bin/su" | "/bin/su"
        );
    if ssh
        && (message.starts_with("Failed password for ")
            || message.starts_with("Failed publickey for ")
            || message.starts_with("Accepted password for ")
            || message.starts_with("Accepted publickey for "))
    {
        kind = Kind::Authentication;
        outcome = if message.starts_with("Accepted ") {
            Outcome::Allow
        } else {
            Outcome::Deny
        };
        severity = if outcome == Outcome::Allow { 1 } else { 3 };
        if let Some(user) =
            token_after(message, "for invalid user ").or_else(|| token_after(message, "for "))
        {
            subject = label(user);
        }
        object = token_after(message, " from ")
            .and_then(|v| v.parse::<std::net::IpAddr>().ok())
            .map(|ip| format!("ssh:{ip}"))
            .unwrap_or_else(|| "ssh".into());
        summary = if outcome == Outcome::Allow {
            "OpenSSH reported successful authentication"
        } else {
            "OpenSSH reported an authentication denial"
        };
    } else if pam
        && message.starts_with("pam_")
        && message.contains(":auth): authentication failure;")
    {
        kind = Kind::Authentication;
        // A sufficient/optional module may fail before another module accepts
        // the same login. Keep this evidence without asserting service denial
        // or counting it again beside the service's completed outcome.
        outcome = Outcome::Observe;
        severity = 1;
        object = label(comm);
        if let Some(user) = token_after(message, "user=") {
            subject = label(user);
        }
        summary = "PAM module reported failure; service authentication outcome is not established";
    } else if exe == "/usr/bin/sudo" {
        use athernex_endpoint_protocol::authentication::{sudo_report, SudoOutcome};
        if let Some(report) = sudo_report(message) {
            subject = label(report.claimed_user);
            object = "sudo".into();
            match report.outcome {
                SudoOutcome::PasswordDenied { .. } => {
                    kind = Kind::Authentication;
                    outcome = Outcome::Deny;
                    severity = 3;
                    summary = "sudo reported a completed password-authentication denial";
                }
                SudoOutcome::PolicyDenied => {
                    kind = Kind::Policy;
                    outcome = Outcome::Deny;
                    severity = 4;
                    summary = "sudo reported a denied policy decision";
                }
                SudoOutcome::CommandAuthorized => {
                    kind = Kind::Policy;
                    outcome = Outcome::Allow;
                    severity = 2;
                    summary = "sudo recorded an authorized command request; fresh authentication is not established";
                }
            }
        }
    } else if field(record, "_PID") == "1"
        && uid == Some(0)
        && comm == "systemd"
        && (message.contains("Failed to start ")
            || message.contains("Main process exited, code=")
            || message.contains("Failed with result "))
    {
        kind = Kind::System;
        outcome = Outcome::Deny;
        severity = 4;
        summary = "The system manager reported a service failure";
    }
    let input = InputEvent {
        time_ms,
        source: source.into(),
        subject,
        object,
        kind,
        outcome,
        severity,
        bytes: 0,
        trace: 0,
        idempotency_key: digest(cursor),
        context: Some(EventContext {
            parent_pid: None,
            process_start_ms: None,
            parent_start_ms: None,
            host: bounded(field(record, "_HOSTNAME"), 64),
            program: bounded(
                if comm.is_empty() {
                    field(record, "SYSLOG_IDENTIFIER")
                } else {
                    comm
                },
                64,
            ),
            pid: field(record, "_PID").parse().ok(),
            uid,
            summary: summary.into(),
            journal_cursor: cursor.into(),
        }),
    };
    input.validate(now)?;
    Ok(input)
}
async fn read_line(reader: &mut BufReader<ChildStdout>) -> LabResult<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            break;
        }
        let count = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |p| p + 1);
        if line.len() + count > 65536 {
            return Err("Journal record exceeded the 64 KiB input budget".into());
        }
        let done = buffer[count - 1] == b'\n';
        line.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        if done {
            break;
        }
    }
    Ok(line)
}
pub async fn read_journal(source: &Source, one_cursor: Option<&str>) -> LabResult<Vec<Value>> {
    let mut command = Command::new("/usr/bin/journalctl");
    command
        .args(["--no-pager", "--quiet", "--output=json"])
        .arg(format!("--output-fields={FIELDS}"));
    if let Some(cursor) = one_cursor {
        command
            .arg(format!("--cursor={cursor}"))
            .args(["--lines=1"]);
    } else {
        command.arg("--no-tail");
        if source.cursor.is_empty() {
            command.arg("--since=-5min");
        } else {
            command.arg(format!("--after-cursor={}", source.cursor));
        }
        if !source.selector.is_empty() {
            command.arg(format!("--unit={}", source.selector));
        }
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("Journal stdout unavailable")?);
    let read = async {
        let mut rows = Vec::new();
        let mut total = 0;
        let mut limited = false;
        loop {
            let line = read_line(&mut reader).await?;
            if line.is_empty() {
                break;
            }
            total += line.len();
            if total > 512 * 1024 {
                limited = true;
                break;
            }
            let value: Value =
                serde_json::from_slice(&line).map_err(|_| "Journal JSON was malformed")?;
            rows.push(value);
            if rows.len() >= MAX_BATCH || one_cursor.is_some() {
                limited = true;
                break;
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((rows, limited))
    };
    let result = tokio::time::timeout(Duration::from_secs(3), read).await;
    match result {
        Ok(Ok((rows, true))) => {
            let _ = child.kill().await;
            Ok(rows)
        }
        Ok(Ok((rows, false))) => {
            let status = child.wait().await?;
            if !status.success() {
                Err(
                    "journalctl failed; check journal permissions or reset an unavailable cursor"
                        .into(),
                )
            } else {
                Ok(rows)
            }
        }
        Ok(Err(error)) => {
            let _ = child.kill().await;
            Err(error)
        }
        Err(_) => {
            let _ = child.kill().await;
            Err("Journal read exceeded the 3-second budget".into())
        }
    }
}
pub async fn run(engine: Arc<Mutex<Engine>>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    loop {
        tokio::select! {_=shutdown.changed()=>{break},_=interval.tick()=>{}}
        let sources = match engine.lock() {
            Ok(e) => e.sources().unwrap_or_default(),
            Err(_) => break,
        };
        for source in sources
            .into_iter()
            .filter(|s| s.kind == "journal" && s.enabled)
        {
            if *shutdown.borrow() {
                return;
            }
            let read = read_journal(&source, None).await;
            let now = now_ms();
            let Ok(mut engine) = engine.lock() else {
                return;
            };
            // A pause or reset while journalctl was running invalidates this read.
            if !engine
                .sources()
                .unwrap_or_default()
                .iter()
                .any(|s| s.id == source.id && s.enabled && s.generation == source.generation)
            {
                continue;
            }
            match read {
                Ok(rows) => {
                    let mut inputs = Vec::new();
                    let mut skipped = 0;
                    let mut cursor = None;
                    for row in &rows {
                        let c = field(row, "__CURSOR");
                        if !c.is_empty() {
                            cursor = Some(c);
                        }
                        match normalize(row, &source.id, now) {
                            Ok(input) => inputs.push(input),
                            Err(_) => skipped += 1,
                        }
                    }
                    if let Err(error) =
                        engine.ingest_source(&source.id, None, &inputs, cursor, skipped, now)
                    {
                        let _ = engine.source_error(&source.id, &error.to_string(), 0, now);
                    }
                }
                Err(error) => {
                    let _ = engine.source_error(&source.id, &error.to_string(), 0, now);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(message: &str, exe: &str) -> Value {
        serde_json::json!({"__CURSOR":"s=fixture;i=1","__REALTIME_TIMESTAMP":"1800000000000000","MESSAGE":message,"_EXE":exe,"_COMM":"sshd","_UID":"0","_PID":"50","PRIORITY":"6","_HOSTNAME":"fixture-host","_SYSTEMD_UNIT":"ssh.service"})
    }
    #[test]
    fn trusted_ssh_denials_preserve_facts_without_storing_the_message() {
        let input = normalize(
            &record(
                "Failed password for invalid user alice from 192.0.2.10 port 1010 ssh2",
                "/usr/sbin/sshd",
            ),
            "host-journal",
            1_800_000_000_000,
        )
        .unwrap();
        assert_eq!(input.kind, Kind::Authentication);
        assert_eq!(input.outcome, Outcome::Deny);
        assert_eq!(input.subject, "alice");
        assert_eq!(input.object, "ssh:192.0.2.10");
        assert!(!serde_json::to_string(&input)
            .unwrap()
            .contains("Failed password"));
    }
    #[test]
    fn a_syslog_identifier_cannot_forge_authentication() {
        let input = normalize(
            &record(
                "Failed password for alice from 192.0.2.10 port 1010 ssh2",
                "/usr/bin/logger",
            ),
            "host-journal",
            1_800_000_000_000,
        )
        .unwrap();
        assert_eq!(input.kind, Kind::System);
        assert_eq!(input.outcome, Outcome::Observe);
    }
    #[test]
    fn pam_module_reports_do_not_double_count_denied_service_authentications() {
        let now = 1_800_000_000_000;
        let mut engine = Engine::memory().unwrap();
        for index in 0..8 {
            let mut pam = record("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.10 user=alice", "/usr/sbin/sshd");
            pam["__CURSOR"] = format!("pam-{index}").into();
            let input = normalize(&pam, "host-journal", now).unwrap();
            assert_eq!(input.outcome, Outcome::Observe);
            assert!(input.context.as_ref().unwrap().summary.contains("module"));
            engine.ingest(&[input], now).unwrap();
            let mut ssh = record(
                "Failed password for alice from 192.0.2.10 port 2222 ssh2",
                "/usr/sbin/sshd",
            );
            ssh["__CURSOR"] = format!("ssh-{index}").into();
            engine
                .ingest(&[normalize(&ssh, "host-journal", now).unwrap()], now)
                .unwrap();
            assert_eq!(
                engine
                    .findings()
                    .unwrap()
                    .iter()
                    .any(|f| f.rule == "AX-001"),
                index == 7
            );
        }
        let command = normalize(
            &record(
                "alice : TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/bin/echo authentication failure",
                "/usr/bin/sudo",
            ),
            "host-journal",
            now,
        )
        .unwrap();
        assert_eq!(command.kind, Kind::Policy);
        assert_eq!(command.outcome, Outcome::Allow);
    }

    #[test]
    fn sudo_password_denial_is_not_an_authorized_command_and_arguments_are_opaque() {
        let now = 1_800_000_000_000;
        let failure = record("alice : 2 incorrect password attempts ; TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true", "/usr/bin/sudo");
        let input = normalize(&failure, "host-journal", now).unwrap();
        assert_eq!(input.kind, Kind::Authentication);
        assert_eq!(input.outcome, Outcome::Deny);
        assert_eq!(input.subject, "alice");
        for text in [
            "NOT in sudoers",
            "not allowed to execute",
            "command not allowed",
            "1 incorrect password attempt",
        ] {
            let input = normalize(&record(&format!("alice : TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/printf {text}"), "/usr/bin/sudo"), "host-journal", now).unwrap();
            assert_eq!(input.kind, Kind::Policy);
            assert_eq!(input.outcome, Outcome::Allow);
        }
        for text in [
            "alice : custom authentication failure ; COMMAND=/usr/bin/true",
            "alice : 1 incorrect password attempt ; COMMAND=/usr/bin/true",
        ] {
            assert_eq!(
                normalize(&record(text, "/usr/bin/sudo"), "host-journal", now)
                    .unwrap()
                    .outcome,
                Outcome::Observe
            );
        }
        let mut forged = failure;
        forged["_EXE"] = "/usr/bin/logger".into();
        forged["SYSLOG_IDENTIFIER"] = "sudo".into();
        assert_eq!(
            normalize(&forged, "host-journal", now).unwrap().outcome,
            Outcome::Observe
        );
    }
    #[test]
    fn generic_error_priority_is_not_a_privilege_or_service_failure() {
        let mut row = record(
            "secret token=example should not persist",
            "/usr/bin/example",
        );
        row["PRIORITY"] = Value::String("2".into());
        let input = normalize(&row, "host-journal", 1_800_000_000_000).unwrap();
        assert_eq!(input.kind, Kind::System);
        assert_eq!(input.outcome, Outcome::Observe);
        assert_eq!(input.bytes, 0);
        assert!(!serde_json::to_string(&input)
            .unwrap()
            .contains("secret token"));
    }
}

#[cfg(test)]
mod service_detection_tests {
    use super::*;
    #[test]
    fn service_failure_requires_collector_provenance_and_separates_units() {
        let now = 1_800_000_000_000;
        let mut engine = Engine::memory().unwrap();
        for n in 1..=2 {
            let row = serde_json::json!({"__CURSOR":format!("s=fixture;i={n}"),"__REALTIME_TIMESTAMP":(now*1000).to_string(),"_COMM":"systemd","_PID":"1","_UID":"0","UNIT":format!("fixture-{n}.service"),"MESSAGE":"Failed to start fixture service."});
            let input = normalize(&row, "fixture-journal", now).unwrap();
            assert_eq!(input.outcome, Outcome::Deny);
            engine.ingest(&[input], now).unwrap();
        }
        assert_eq!(
            engine
                .findings()
                .unwrap()
                .iter()
                .filter(|f| f.rule == "AX-005")
                .count(),
            2
        );
        let mut engine = Engine::memory().unwrap();
        let token = engine
            .create_source("api", "api", "", now)
            .unwrap()
            .unwrap();
        let input = InputEvent {
            time_ms: now,
            source: "api".into(),
            subject: "uid-0".into(),
            object: "fixture.service".into(),
            kind: Kind::System,
            outcome: Outcome::Deny,
            severity: 4,
            bytes: 0,
            trace: 0,
            idempotency_key: "claimed-failure".into(),
            context: None,
        };
        engine
            .ingest_source("api", Some(&token), &[input], None, 0, now)
            .unwrap();
        assert!(engine.findings().unwrap().is_empty());
    }
}
