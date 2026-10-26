//! Bounded endpoint correlations. Snapshot facts never imply a complete trace,
//! network direction, transferred bytes or the hash of an executing image.
use crate::{
    engine::{Engine, LabResult},
    model::{Rule, MAX_FINDINGS, RULES},
};
use athernex_endpoint_protocol::{
    self as protocol,
    telemetry::{ProcessObservation, Telemetry},
    EndpointEvent,
};
use rusqlite::params;
use std::net::IpAddr;

const WINDOW: u64 = 120_000;
const FANOUT: usize = 32;

fn image(process: &ProcessObservation) -> Option<String> {
    process
        .executable
        .as_ref()
        .and_then(|p| p.rsplit(['/', '\\']).next())
        .map(str::to_ascii_lowercase)
}

fn interpreter(process: &ProcessObservation) -> bool {
    matches!(
        image(process).as_deref(),
        Some(
            "sh" | "bash"
                | "dash"
                | "zsh"
                | "fish"
                | "cmd.exe"
                | "powershell.exe"
                | "pwsh.exe"
                | "pwsh"
                | "python"
                | "python3"
                | "python.exe"
                | "python3.exe"
                | "wscript.exe"
                | "cscript.exe"
                | "mshta.exe"
        )
    )
}
fn document_application(process: &ProcessObservation) -> bool {
    matches!(
        image(process).as_deref(),
        Some(
            "winword.exe"
                | "excel.exe"
                | "powerpnt.exe"
                | "outlook.exe"
                | "acrord32.exe"
                | "acrobat.exe"
                | "soffice.bin"
                | "microsoft word"
                | "microsoft excel"
                | "microsoft powerpoint"
                | "chrome.exe"
                | "msedge.exe"
                | "firefox.exe"
                | "chrome"
                | "chromium"
                | "firefox"
                | "safari"
        )
    )
}
fn privileged(user: &str) -> bool {
    user == "0" || user.eq_ignore_ascii_case("S-1-5-18")
}
fn external(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 240
                && !(ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || {
                !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_unique_local()
                    && !ip.is_unicast_link_local()
            },
            |ip| external(IpAddr::V4(ip)),
        ),
    }
}
fn identity(endpoint: &str, boot: &str, pid: u32, started: u64) -> String {
    format!("endpoint-process:{endpoint}:{boot}:{pid}:{started}")
}
fn boot(item: &Telemetry) -> Option<&str> {
    match item {
        Telemetry::Authentication { event } => Some(&event.journal.boot_id),
        Telemetry::WindowsAuthentication { .. }
        | Telemetry::MacosProcessEvent { .. }
        | Telemetry::WindowsProcessEvent { .. }
        | Telemetry::WindowsNetworkEvent { .. } => None,
        Telemetry::Process { boot_id, .. }
        | Telemetry::Connection { boot_id, .. }
        | Telemetry::ProcessEvent { boot_id, .. }
        | Telemetry::NetworkEvent { boot_id, .. } => Some(boot_id),
    }
}

impl Engine {
    pub(crate) fn init_endpoint_detection(&self) -> LabResult<()> {
        // One claim per retained case prevents finding-window eviction from
        // reopening an analyst-resolved investigation for the same process.
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS endpoint_detection_claims(fingerprint TEXT PRIMARY KEY,case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE);")?;
        Ok(())
    }

    pub(crate) fn index_endpoint_process(
        &self,
        endpoint: &str,
        event: &EndpointEvent,
        evidence: u64,
    ) -> LabResult<()> {
        let Some(item) = &event.telemetry else {
            return Ok(());
        };
        let Some(p) = item.process().filter(|p| p.started_ms != 0) else {
            return Ok(());
        };
        let Some(boot_id) = boot(item) else {
            return Ok(());
        };
        let key = identity(endpoint, boot_id, p.pid, p.started_ms);
        self.connection.execute(
            "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
            params![key, evidence, event.time_ms],
        )?;
        if let (Some(parent), Some(started)) = (p.parent_pid, p.parent_started_ms) {
            if started != 0 && started <= p.started_ms {
                let key = format!("children:{}", identity(endpoint, boot_id, parent, started));
                self.connection.execute(
                    "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
                    params![key, evidence, event.time_ms],
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn detect_endpoint(
        &self,
        endpoint: &str,
        event: &EndpointEvent,
        evidence: u64,
        now: u64,
    ) -> LabResult<()> {
        self.detect_endpoint_item(endpoint, event, evidence, now)?;
        // A parent/process observation may be delivered after its child/socket.
        // Revisit a bounded set, retaining each observation's original time.
        if let Some(Telemetry::Process { boot_id, process }) = &event.telemetry {
            if process.started_ms != 0 {
                let key = identity(endpoint, boot_id, process.pid, process.started_ms);
                for key in [&key, &format!("children:{key}")] {
                    for id in self.graph_neighbors(
                        key,
                        evidence,
                        event.time_ms.saturating_add(WINDOW),
                        FANOUT,
                    )? {
                        let Some(other) = self.endpoint_observation(id)? else {
                            continue;
                        };
                        if other.event.time_ms >= event.time_ms {
                            self.detect_endpoint_item(endpoint, &other.event, id, now)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn detect_endpoint_item(
        &self,
        endpoint: &str,
        event: &EndpointEvent,
        evidence: u64,
        now: u64,
    ) -> LabResult<()> {
        let Some(item) = &event.telemetry else {
            return Ok(());
        };
        let Some(p) = item.process().filter(|p| p.started_ms != 0) else {
            return Ok(());
        };
        let Some(boot_id) = boot(item) else {
            return Ok(());
        };
        let key = identity(endpoint, boot_id, p.pid, p.started_ms);
        let enabled = self.enabled_rules()?;
        if interpreter(p) && enabled.iter().any(|r| r == "AX-006") {
            if let (Some(pid), Some(started)) = (p.parent_pid, p.parent_started_ms) {
                if started != 0 && started <= p.started_ms {
                    let parent_key = identity(endpoint, boot_id, pid, started);
                    for id in self.graph_neighbors(&parent_key, evidence, event.time_ms, FANOUT)? {
                        let Some(parent) = self.endpoint_observation(id)? else {
                            continue;
                        };
                        if event.time_ms.saturating_sub(parent.event.time_ms) > WINDOW {
                            continue;
                        }
                        if let Some(Telemetry::Process { process, .. }) = &parent.event.telemetry {
                            if document_application(process) {
                                self.endpoint_signal(&RULES[5], &key, endpoint, &[id, evidence], now,
                                    "A browser or document application and an interpreter share the observed parent identity. The identity includes endpoint, boot, PID and start time. This may be legitimate automation; snapshots do not establish the launch command or intent.")?;
                                break;
                            }
                        }
                    }
                }
            }
        }
        let prior = self.graph_neighbors(&key, evidence, event.time_ms, FANOUT)?;
        if let Telemetry::Connection { connection, .. } = item {
            if interpreter(p)
                && connection.protocol == "tcp"
                && connection.state.eq_ignore_ascii_case("ESTABLISHED")
                && connection.remote.is_some_and(|r| external(r.ip()))
                && enabled.iter().any(|r| r == "AX-007")
            {
                for &id in &prior {
                    let Some(process) = self.endpoint_observation(id)? else {
                        continue;
                    };
                    if event.time_ms.saturating_sub(process.event.time_ms) > WINDOW {
                        continue;
                    }
                    if let Some(Telemetry::Process { process, .. }) = &process.event.telemetry {
                        if process == p {
                            self.endpoint_signal(&RULES[6], &key, endpoint, &[id, evidence], now,
                                "An interpreter process observation matches the exact process metadata attached to an established TCP socket with a non-local peer. This may be legitimate administration. Socket snapshots do not establish connection direction, bytes transferred or malicious intent.")?;
                            break;
                        }
                    }
                }
            }
        }
        if p.user_id.as_deref().is_some_and(privileged) && enabled.iter().any(|r| r == "AX-008") {
            for id in prior {
                let Some(previous) = self.endpoint_observation(id)? else {
                    continue;
                };
                if previous.event.time_ms >= event.time_ms
                    || event.time_ms.saturating_sub(previous.event.time_ms) > WINDOW
                {
                    continue;
                }
                if let Some(Telemetry::Process { process, .. }) = &previous.event.telemetry {
                    if process.executable.is_some()
                        && process.executable == p.executable
                        && process.user_id.as_deref().is_some_and(|u| !privileged(u))
                    {
                        self.endpoint_signal(&RULES[7], &key, endpoint, &[id, evidence], now,
                            "The same observed endpoint, boot, PID, start time and executable changed from a non-system user identity to root/SYSTEM. This can be authorized privilege use. Sampling does not establish the transition mechanism or prove an exploit.")?;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn endpoint_signal(
        &self,
        rule: &Rule,
        identity: &str,
        endpoint: &str,
        ids: &[u64],
        now: u64,
        explanation: &str,
    ) -> LabResult<()> {
        let fingerprint = protocol::hash(format!("{}:{identity}", rule.id).as_bytes());
        let claimed: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM endpoint_detection_claims WHERE fingerprint=?1)",
            [&fingerprint],
            |r| r.get(0),
        )?;
        if claimed {
            return Ok(());
        }
        let evidence = ids
            .iter()
            .map(|id| self.reconstruct(*id))
            .collect::<LabResult<Vec<_>>>()?;
        if evidence.iter().any(|e| {
            e.source_label != "endpoint" || e.context.as_ref().is_none_or(|c| c.host != endpoint)
        }) {
            return Err("Endpoint detection evidence crossed a device boundary".into());
        }
        let encoded = serde_json::to_string(&evidence)?;
        let time = evidence
            .iter()
            .map(|e| e.event.time_ms)
            .max()
            .unwrap_or(now);
        self.connection.execute("INSERT INTO findings(fingerprint,rule,title,severity,subject,time_ms,explanation,evidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![fingerprint, rule.id, rule.title, rule.severity, endpoint, time, explanation, encoded])?;
        let finding = self.connection.last_insert_rowid();
        self.sync_case(finding, rule.title, rule.severity, &encoded, now)?;
        for observation in &evidence {
            self.connection.execute(
                "INSERT OR IGNORE INTO graph_links VALUES(?1,?2,?3)",
                params![
                    format!("detection:{}:{finding}", rule.id),
                    observation.event.id,
                    observation.event.time_ms
                ],
            )?;
        }
        if let Some(observation) = evidence.last() {
            self.correlate_signal(observation.event.id, Some(rule.severity), now)?;
        }
        self.connection.execute(
            "INSERT INTO endpoint_detection_claims SELECT ?1,id FROM cases WHERE finding_id=?2",
            params![fingerprint, finding],
        )?;
        self.audit(
            "detection.matched",
            &format!(
                "{} · endpoint {} · {} observations",
                rule.id,
                endpoint,
                ids.len()
            ),
            now,
        )?;
        self.connection.execute("DELETE FROM findings WHERE id NOT IN (SELECT id FROM findings ORDER BY id DESC LIMIT ?1)", [MAX_FINDINGS])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{telemetry::ConnectionObservation, Enrollment, Platform};
    const NOW: u64 = 1_800_000_000_000;

    fn enroll(engine: &Engine, name: &str) -> String {
        let id = protocol::hash(name.as_bytes());
        engine
            .enroll_endpoint(
                &Enrollment {
                    protocol: protocol::PROTOCOL,
                    enrollment_token: engine.create_enrollment(Platform::Linux, NOW).unwrap(),
                    endpoint_id: id.clone(),
                    credential: protocol::hash(format!("secret:{name}").as_bytes()),
                    hostname: name.into(),
                    platform: Platform::Linux,
                    arch: "x86_64".into(),
                    version: "fixture".into(),
                },
                NOW,
            )
            .unwrap();
        id
    }
    fn process(parent: bool) -> ProcessObservation {
        ProcessObservation {
            pid: if parent { 10 } else { 11 },
            parent_pid: if parent { None } else { Some(10) },
            started_ms: NOW - if parent { 20_000 } else { 10_000 },
            parent_started_ms: if parent { None } else { Some(NOW - 20_000) },
            name: if parent {
                "WINWORD.EXE"
            } else {
                "powershell.exe"
            }
            .into(),
            executable: Some(
                if parent {
                    r"C:\Program Files\Office\WINWORD.EXE"
                } else {
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                }
                .into(),
            ),
            user_id: Some("1000".into()),
        }
    }
    fn event(name: &str, parent: bool) -> EndpointEvent {
        let process = process(parent);
        EndpointEvent {
            id: protocol::hash(name.as_bytes()),
            time_ms: NOW,
            kind: "process".into(),
            path: process.executable.clone().unwrap(),
            sha256: String::new(),
            detection: String::new(),
            detail: String::new(),
            telemetry: Some(Telemetry::Process {
                boot_id: "a".repeat(64),
                process,
            }),
        }
    }
    fn socket(name: &str, address: &str) -> EndpointEvent {
        let mut event = event(name, false);
        event.kind = "connection".into();
        event.telemetry = Some(Telemetry::Connection {
            boot_id: "a".repeat(64),
            connection: ConnectionObservation {
                protocol: "tcp".into(),
                local: "192.168.1.1:51234".parse().unwrap(),
                remote: Some(address.parse().unwrap()),
                state: "ESTABLISHED".into(),
                owner_pid: Some(11),
                process: Some(process(false)),
            },
        });
        event
    }

    #[test]
    fn out_of_order_process_and_socket_correlate_once_and_keep_typed_evidence() {
        let mut e = Engine::memory().unwrap();
        e.configure_mode(false).unwrap();
        let endpoint = enroll(&e, "first");
        let connection = socket("socket", "8.8.8.8:443");
        e.endpoint_events(&endpoint, &[connection], NOW).unwrap();
        assert!(e.findings().unwrap().is_empty());
        e.endpoint_events(&endpoint, &[event("child", false)], NOW)
            .unwrap();
        assert_eq!(e.findings().unwrap().len(), 1);
        e.endpoint_events(&endpoint, &[event("parent", true)], NOW)
            .unwrap();
        let findings = e.findings().unwrap();
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.rule == "AX-006"));
        assert!(findings.iter().any(|f| f.rule == "AX-007"));
        for case in e.cases().unwrap() {
            assert_eq!(case.evidence.len(), 2);
            for observation in case.evidence {
                assert_eq!(observation.context.as_ref().unwrap().host, endpoint);
                assert!(e
                    .endpoint_observation(observation.event.id)
                    .unwrap()
                    .unwrap()
                    .event
                    .telemetry
                    .is_some());
            }
        }
        e.connection.execute("DELETE FROM findings", []).unwrap();
        e.endpoint_events(&endpoint, &[socket("another socket", "8.8.4.4:443")], NOW)
            .unwrap();
        assert!(
            e.findings().unwrap().is_empty(),
            "Finding eviction cannot recreate an existing case"
        );
        assert_eq!(e.cases().unwrap().len(), 2);
        assert!(
            e.fleet().unwrap().commands.is_empty(),
            "Heuristics cannot launch malware automation"
        );
    }

    #[test]
    fn lineage_requires_same_device_boot_exact_parent_and_fresh_evidence() {
        for variant in 0..5 {
            let e = Engine::memory().unwrap();
            let a = enroll(&e, "a");
            let b = enroll(&e, "b");
            let mut parent = event("parent", true);
            if variant == 4 {
                parent.time_ms -= WINDOW + 1;
            }
            e.endpoint_events(&a, &[parent], NOW).unwrap();
            let mut child = event("child", false);
            if let Some(Telemetry::Process { boot_id, process }) = &mut child.telemetry {
                match variant {
                    1 => *boot_id = "b".repeat(64),
                    2 => process.parent_started_ms = Some(NOW - 21_000),
                    3 => process.parent_started_ms = None,
                    _ => (),
                }
            }
            e.endpoint_events(if variant == 0 { &b } else { &a }, &[child], NOW)
                .unwrap();
            assert!(
                e.findings().unwrap().is_empty(),
                "Unrelated lineage variant {variant} matched"
            );
        }
    }

    #[test]
    fn network_correlation_excludes_unknown_owners_local_peers_and_metadata_changes() {
        for (index, peer) in [
            "127.0.0.1:443",
            "10.1.1.1:443",
            "[::ffff:127.0.0.1]:443",
            "[fe80::1]:443",
            "100.100.100.100:443",
            "8.8.8.8:443",
        ]
        .iter()
        .enumerate()
        {
            let e = Engine::memory().unwrap();
            let endpoint = enroll(&e, "network");
            e.endpoint_events(&endpoint, &[event("child", false)], NOW)
                .unwrap();
            let mut c = socket("connection", peer);
            if index == 5 {
                if let Some(Telemetry::Connection { connection, .. }) = &mut c.telemetry {
                    connection.process.as_mut().unwrap().started_ms += 1000;
                }
            }
            e.endpoint_events(&endpoint, &[c], NOW).unwrap();
            assert!(
                e.findings().unwrap().is_empty(),
                "Unrelated socket variant {index} matched"
            );
        }
    }

    #[test]
    fn identity_transition_is_ordered_and_rule_controls_apply() {
        let e = Engine::memory().unwrap();
        let endpoint = enroll(&e, "identity");
        let mut elevated = event("elevated", false);
        elevated.time_ms += 1000;
        if let Some(Telemetry::Process { process, .. }) = &mut elevated.telemetry {
            process.user_id = Some("0".into());
        }
        e.endpoint_events(&endpoint, &[elevated], NOW + 1000)
            .unwrap();
        e.endpoint_events(&endpoint, &[event("prior-user", false)], NOW + 1000)
            .unwrap();
        assert_eq!(e.findings().unwrap()[0].rule, "AX-008");
        let next = enroll(&e, "disabled");
        e.toggle_rule("AX-006", NOW).unwrap();
        e.endpoint_events(&next, &[event("parent", true), event("child", false)], NOW)
            .unwrap();
        assert_eq!(e.findings().unwrap().len(), 1);
    }

    #[test]
    fn failure_rolls_back_evidence_and_detection_then_restart_preserves_claims() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("server.sqlite3");
        let e = Engine::open(&db).unwrap();
        let endpoint = enroll(&e, "recovery");
        e.connection.execute_batch("CREATE TRIGGER reject_claim BEFORE INSERT ON endpoint_detection_claims BEGIN SELECT RAISE(ABORT,'fixture disk failure'); END;").unwrap();
        let batch = [event("parent", true), event("child", false)];
        assert!(e.endpoint_events(&endpoint, &batch, NOW).is_err());
        assert!(e
            .endpoint_observations(&endpoint, u64::MAX, 64)
            .unwrap()
            .is_empty());
        assert!(e.findings().unwrap().is_empty());
        assert!(e.cases().unwrap().is_empty());
        e.connection
            .execute_batch("DROP TRIGGER reject_claim;")
            .unwrap();
        e.endpoint_events(&endpoint, &batch, NOW).unwrap();
        drop(e);
        let e = Engine::open(&db).unwrap();
        assert_eq!(e.endpoint_events(&endpoint, &batch, NOW).unwrap(), 0);
        e.endpoint_events(&endpoint, &[event("child-again", false)], NOW)
            .unwrap();
        assert_eq!(e.cases().unwrap().len(), 1);
    }
}
