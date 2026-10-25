use athernex_endpoint_protocol::{self as p, EndpointEvent, Enrollment, Platform};
use athernex_siem::{
    engine::Engine,
    model::{Kind, Outcome},
};

const NOW: u64 = 1_800_000_000_000;

fn enroll(engine: &Engine, id: char) -> Enrollment {
    let endpoint = Enrollment {
        protocol: 1,
        enrollment_token: engine.create_enrollment(Platform::Windows, NOW).unwrap(),
        endpoint_id: id.to_string().repeat(64),
        credential: "d".repeat(64),
        hostname: "fixture-host".into(),
        platform: Platform::Windows,
        arch: "x86_64".into(),
        version: "fixture".into(),
    };
    engine.enroll_endpoint(&endpoint, NOW).unwrap();
    endpoint
}

fn report(record_id: u64, domain: &str, allowed: bool) -> EndpointEvent {
    let code = if allowed { 4624 } else { 4625 };
    let keywords = if allowed {
        "0x8020000000000000"
    } else {
        "0x8010000000000000"
    };
    let target_sid = if allowed {
        "S-1-5-21-100-200-300-1001"
    } else {
        "S-1-0-0"
    };
    let outcome_fields = if allowed {
        "<Data Name='TargetLogonId'>0x1234</Data>".to_owned()
    } else {
        "<Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>0xc000006a</Data>".to_owned()
    };
    let xml = format!(
        r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/><EventID>{code}</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords><TimeCreated SystemTime='2027-01-15T07:59:59.0000000Z'/><EventRecordID>{record_id}</EventRecordID><Execution ProcessID='500' ThreadID='7'/><Channel>Security</Channel><Computer>fixture.invalid</Computer><Security/></System><EventData><Data Name='TargetUserSid'>{target_sid}</Data><Data Name='TargetUserName'>fixture</Data><Data Name='TargetDomainName'>{domain}</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>Advapi</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='ProcessId'>0x2a</Data><Data Name='ProcessName'>C:\Windows\System32\fixture.exe</Data><Data Name='IpAddress'>192.0.2.7</Data><Data Name='IpPort'>41822</Data>{outcome_fields}</EventData></Event>"#
    );
    let authentication = p::windows_authentication::from_xml(&xml).unwrap().unwrap();
    EndpointEvent {
        id: authentication.event_id(),
        time_ms: authentication.time_ms,
        kind: "authentication".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: String::new(),
        telemetry: Some(p::telemetry::Telemetry::WindowsAuthentication {
            event: authentication,
        }),
    }
}

#[test]
fn windows_accounts_preserve_domain_device_and_original_evidence_across_replay() {
    let temporary = tempfile::tempdir().unwrap();
    let database = temporary.path().join("events.db");
    let mut engine = Engine::open(&database).unwrap();
    engine.configure_mode(false).unwrap();
    let first = enroll(&engine, 'a');
    let second = enroll(&engine, 'b');
    let reports = (1..=8)
        .map(|id| report(id, "DOMAIN-A", false))
        .collect::<Vec<_>>();
    engine
        .endpoint_events(&first.endpoint_id, &reports[..7], NOW)
        .unwrap();
    engine
        .endpoint_events(&second.endpoint_id, &reports[7..], NOW)
        .unwrap();
    let other_domain = report(9, "DOMAIN-B", false);
    engine
        .endpoint_events(&first.endpoint_id, &[other_domain], NOW)
        .unwrap();
    assert!(!engine
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .any(|f| f.rule == "AX-001"));
    engine
        .endpoint_events(&first.endpoint_id, &reports[7..], NOW)
        .unwrap();
    let snapshot = engine.snapshot().unwrap();
    let burst = snapshot
        .findings
        .iter()
        .find(|f| f.rule == "AX-001")
        .unwrap();
    assert_eq!(burst.evidence.len(), 8);
    for evidence in &burst.evidence {
        let context = evidence.context.as_ref().unwrap();
        assert_eq!(context.host, first.endpoint_id);
        assert_eq!(context.pid, Some(42));
        assert_eq!(context.uid, None);
        assert_eq!(context.process_start_ms, None);
        assert!(context.journal_cursor.is_empty());
        assert_eq!(evidence.event.kind, Kind::Authentication);
        assert_eq!(evidence.event.outcome, Outcome::Deny);
    }
    let saved = engine
        .endpoint_observations(&first.endpoint_id, u64::MAX, 32)
        .unwrap();
    for original in &reports {
        assert!(saved
            .iter()
            .any(|row| serde_json::to_value(&row.event).unwrap()
                == serde_json::to_value(original).unwrap()));
    }
    let success = report(10, "DOMAIN-A", true);
    engine
        .endpoint_events(&first.endpoint_id, std::slice::from_ref(&success), NOW)
        .unwrap();
    let row = engine
        .endpoint_observations(&first.endpoint_id, u64::MAX, 32)
        .unwrap()
        .into_iter()
        .find(|row| row.event.id == success.id)
        .unwrap();
    assert_eq!(
        engine.reconstruct(row.evidence_id).unwrap().event.outcome,
        Outcome::Allow
    );
    let count = engine.snapshot().unwrap().findings.len();
    drop(engine);
    let engine = Engine::open(&database).unwrap();
    assert_eq!(
        engine
            .endpoint_events(&first.endpoint_id, &reports, NOW)
            .unwrap(),
        0
    );
    assert_eq!(engine.snapshot().unwrap().findings.len(), count);
    let mut altered = reports[0].clone();
    if let Some(p::telemetry::Telemetry::WindowsAuthentication { event }) = &mut altered.telemetry {
        event.target_domain = Some("different".into());
    }
    assert!(engine
        .endpoint_events(&first.endpoint_id, &[altered], NOW)
        .is_err());
}

#[tokio::test]
async fn windows_coverage_and_original_xml_are_visible_without_inventing_outbound_authentication() {
    use athernex_siem::web::{router, App};
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(false).unwrap();
    let endpoint = enroll(&engine, 'a');
    let mut observation = report(50, "DOMAIN-A", true);
    if let Some(p::telemetry::Telemetry::WindowsAuthentication { event }) =
        &mut observation.telemetry
    {
        let xml = event.xml.replace(
            "<Data Name='LogonType'>3</Data>",
            "<Data Name='LogonType'>9</Data>",
        );
        *event = p::windows_authentication::from_xml(&xml).unwrap().unwrap();
        observation.id = event.event_id();
    }
    engine
        .endpoint_events(&endpoint.endpoint_id, &[observation], NOW)
        .unwrap();
    let record = engine
        .endpoint_observations(&endpoint.endpoint_id, u64::MAX, 1)
        .unwrap()
        .remove(0);
    assert_eq!(
        engine
            .reconstruct(record.evidence_id)
            .unwrap()
            .event
            .outcome,
        Outcome::Observe
    );
    engine
        .endpoint_heartbeat(
            &endpoint.endpoint_id,
            &p::Heartbeat {
                version: "fixture".into(),
                capabilities: vec![],
                scanner: String::new(),
                realtime: false,
                signature_version: String::new(),
                spool_events: 0,
                error: String::new(),
                protection: None,
                updates: None,
                controller_updates: None,
                collector: Some(p::telemetry::CollectorHealth {
                    mode: "snapshot".into(),
                    incomplete: true,
                    windows_authentication: Some(p::authentication::AuthenticationHealth {
                        state: "degraded".into(),
                        started_ms: NOW,
                        checked_ms: NOW,
                        error: "Logon policy <unavailable>".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            },
            NOW,
        )
        .unwrap();
    let token = "w".repeat(32);
    let app = router(App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(athernex_siem::auth::OperatorAuth::new(&token).unwrap()),
    });
    for (path, required) in [
        (
            "/endpoints".to_owned(),
            "Windows Security logons: coverage incomplete / catching up",
        ),
        (
            format!("/endpoints/{}", endpoint.endpoint_id),
            "NewCredentials session; outbound authentication not established",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&path)
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains(required));
        if path == "/endpoints" {
            assert!(html.contains("Logon policy &lt;unavailable&gt;"));
        } else {
            assert!(html.contains("Original XML"));
            assert!(html.contains("&lt;Event xmlns="));
            assert!(!html.contains("<Event xmlns="));
        }
    }
}
