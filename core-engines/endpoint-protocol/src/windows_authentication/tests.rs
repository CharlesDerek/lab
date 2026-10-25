use super::*;
use crate::{telemetry::Telemetry, EndpointEvent};

fn fixture(code: u32, version: u8) -> String {
    let result = if code == 4624 {
        "<Data Name=\"TargetLogonId\">0x1234</Data>"
    } else {
        "<Data Name=\"Status\">0xc000006d</Data><Data Name=\"SubStatus\">0x0</Data><Data Name=\"FailureReason\">%%2313</Data>"
    };
    format!(
        r#"<Event xmlns="{EVENT_NAMESPACE}">
  <System><Provider Name="{SECURITY_PROVIDER}" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>
    <EventID>{code}</EventID><Version>{version}</Version><Level>0</Level>
    <TimeCreated SystemTime="2026-01-02T03:04:05.123456700Z"/>
    <EventRecordID>42</EventRecordID><Channel>Security</Channel><Computer>host.example.invalid</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">reporter</Data><Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="TargetUserSid">S-1-5-21-1-2-3-1001</Data>
    <Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">EXAMPLE</Data>
    <Data Name="LogonType">3</Data><Data Name="LogonProcessName">NtLmSsp </Data>
    <Data Name="AuthenticationPackageName">NTLM</Data><Data Name="ProcessId">0x2a</Data>
    <Data Name="ProcessName">C:\Windows\System32\example.exe</Data>
    <Data Name="IpAddress">2001:db8::1</Data><Data Name="IpPort">50123</Data>{result}
  </EventData>
</Event>"#
    )
}

fn parsed(code: u32, version: u8) -> WindowsAuthentication {
    from_xml(&fixture(code, version)).unwrap().unwrap()
}

fn envelope(event: WindowsAuthentication) -> EndpointEvent {
    EndpointEvent {
        id: event.event_id(),
        time_ms: event.time_ms,
        kind: "authentication".into(),
        path: String::new(),
        sha256: String::new(),
        detection: String::new(),
        detail: String::new(),
        telemetry: Some(Telemetry::WindowsAuthentication { event }),
    }
}

#[test]
fn documented_versions_preserve_original_and_typed_identity() {
    for (code, version) in [(4624, 0), (4624, 1), (4624, 2), (4625, 0)] {
        let event = parsed(code, version);
        assert_eq!(event.xml, fixture(code, version));
        assert_eq!(event.record_id, 42);
        assert_eq!(event.time_ms, 1_767_323_045_123);
        assert_eq!(event.caller_pid, Some(42));
        assert_eq!(event.target_user.as_deref(), Some("alice"));
        assert_eq!(event.target_sid.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(event.source_ip, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(event.source_port, Some(50123));
        assert_eq!(event.logon_process, "NtLmSsp ");
        assert!(event.validate(event.time_ms).is_ok());
        let wire = serde_json::to_string(&event).unwrap();
        assert_eq!(
            serde_json::from_str::<WindowsAuthentication>(&wire).unwrap(),
            event
        );
        assert_eq!(
            event.event_id(),
            crate::hash(format!("windows-security:{}", event.xml).as_bytes())
        );
        if code == 4625 {
            assert_eq!(event.outcome, AuthenticationOutcome::Denied);
            assert_eq!(event.target_logon_id, None);
            assert_eq!(event.status, Some(0xc000006d));
            assert_eq!(event.sub_status, Some(0));
        } else {
            assert_eq!(event.outcome, AuthenticationOutcome::Allowed);
            assert_eq!(event.target_logon_id, Some(0x1234));
            assert_eq!(event.status, None);
        }
    }
}

#[test]
fn all_normalized_fields_are_bound_to_the_original() {
    for code in [4624, 4625] {
        let original = parsed(code, 0);
        let wire = serde_json::to_value(&original).unwrap();
        for (key, value) in wire.as_object().unwrap() {
            if key == "xml" {
                continue;
            }
            let replacement = match value {
                serde_json::Value::String(_) if key == "outcome" => {
                    serde_json::json!(if code == 4624 { "denied" } else { "allowed" })
                }
                serde_json::Value::String(_) if key == "source_ip" => {
                    serde_json::json!("192.0.2.1")
                }
                serde_json::Value::String(s) => serde_json::json!(format!("{s}altered")),
                serde_json::Value::Number(n) => serde_json::json!(n.as_u64().unwrap() + 1),
                serde_json::Value::Null => serde_json::json!(1),
                _ => panic!("unexpected normalized type"),
            };
            let mut changed = wire.clone();
            changed[key] = replacement;
            let changed: WindowsAuthentication = serde_json::from_value(changed).unwrap();
            assert!(changed.validate(original.time_ms).is_err(), "field {key}");
        }
    }
}

#[test]
fn provenance_versions_and_namespaces_are_required() {
    let xml = fixture(4624, 2);
    for bad in [
        xml.replace(SECURITY_PROVIDER, "Untrusted-Publisher"),
        xml.replace("54849625-5478-4994", "54849625-5478-4995"),
        xml.replace(
            "<Channel>Security</Channel>",
            "<Channel>Application</Channel>",
        ),
        xml.replace("<Version>2</Version>", "<Version>3</Version>"),
        xml.replace(EVENT_NAMESPACE, "urn:untrusted"),
        xml.replace("<System>", "<System xmlns=\"urn:untrusted\">"),
        xml.replace("<EventData>", "<EventData xmlns=\"urn:untrusted\">"),
        xml.replace(
            "<Data Name=\"LogonType\">",
            "<Data xmlns=\"urn:untrusted\" Name=\"LogonType\">",
        ),
        fixture(4625, 1),
    ] {
        assert!(from_xml(&bad).is_err());
    }
    let unrelated = xml
        .replace("4624", "9999")
        .replace(SECURITY_PROVIDER, "Other-Publisher");
    assert!(from_xml(&unrelated).unwrap().is_none());
    assert_eq!(identity(&unrelated).unwrap().event_code, 9999);
    let no_guid = unrelated.replace(" Guid=\"{54849625-5478-4994-A5BA-3E3B0328C30D}\"", "");
    assert_eq!(identity(&no_guid).unwrap().provider_guid, None);
}

#[test]
fn duplicates_nested_fields_and_entities_cannot_change_meaning() {
    let xml = fixture(4624, 0);
    for bad in [
        xml.replace("</System>", "<EventID>4625</EventID></System>"),
        xml.replace(
            "</EventData>",
            "<Data Name=\"TargetUserName\">mallory</Data></EventData>",
        ),
        xml.replace(
            "</EventData>",
            "<Data Name=\"Status\">0x0</Data></EventData>",
        ),
        xml.replace(
            "Name=\"TargetUserName\"",
            "Name=\"TargetUserName\" Name=\"SubjectUserName\"",
        ),
        xml.replace("alice", "<Data>alice</Data>"),
        xml.replace("alice", "&custom;"),
        format!("<!DOCTYPE Event [<!ENTITY custom 'alice'>]>{xml}"),
        format!("{xml}{xml}"),
        xml.replace("</Event>", ""),
        xml.replace("alice", "&#x0;"),
        xml.replace("alice", "\u{0001}"),
        xml.replace("<EventID>4624</EventID>", "<EventID>4624</Version>"),
    ] {
        assert!(from_xml(&bad).is_err());
    }
    let escaped = xml.replace("alice", "élise&amp;co&#x20;&lt;name&gt;");
    let event = from_xml(&escaped).unwrap().unwrap();
    assert_eq!(event.target_user.as_deref(), Some("élise&co <name>"));
    assert_eq!(event.xml, escaped);
}

#[test]
fn placeholders_remain_unknown_and_localized_messages_do_not_set_outcome() {
    let xml = fixture(4625, 0)
        .replace("S-1-5-21-1-2-3-1001", "S-1-0-0")
        .replace(">alice<", ">-<")
        .replace(">EXAMPLE<", "><")
        .replace(">0x2a<", ">0x0<")
        .replace("C:\\Windows\\System32\\example.exe", "-")
        .replace("2001:db8::1", "-")
        .replace("50123", "0")
        .replace("%%2313", "Authentification acceptée");
    let event = from_xml(&xml).unwrap().unwrap();
    assert_eq!(event.outcome, AuthenticationOutcome::Denied);
    assert_eq!(event.target_user, None);
    assert_eq!(event.target_domain, None);
    assert_eq!(event.target_sid, None);
    assert_eq!(event.caller_pid, None);
    assert_eq!(event.caller_image, None);
    assert_eq!(event.source_ip, None);
    assert_eq!(event.source_port, None);
    assert_eq!(event.sub_status, Some(0));
    let new_credentials = from_xml(&fixture(4624, 2).replace(">3</Data>", ">9</Data>"))
        .unwrap()
        .unwrap();
    assert_eq!(new_credentials.outcome, AuthenticationOutcome::Allowed);
    assert_eq!(new_credentials.service_outcome(), None);
    assert_eq!(event.service_outcome(), Some(AuthenticationOutcome::Denied));
}

#[test]
fn unknown_logon_types_cannot_establish_authentication_outcomes() {
    for code in [4624, 4625] {
        let xml = fixture(code, 0);
        for kind in [0_u32, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13] {
            let xml = xml.replace(">3</Data>", &format!(">{kind}</Data>"));
            let event = from_xml(&xml).unwrap().unwrap();
            assert_eq!(event.logon_type, kind);
        }
        for kind in [1_u32, 6, 14, u32::MAX] {
            let xml = xml.replace(">3</Data>", &format!(">{kind}</Data>"));
            assert!(from_xml(&xml).is_err());
        }
    }
}

#[test]
fn malformed_numeric_and_account_fields_are_rejected() {
    let xml = fixture(4624, 0);
    for (before, after) in [
        ("0x2a", "0x100000000"),
        ("0x2a", "42"),
        ("0x1234", "0x10000000000000000"),
        ("50123", "65536"),
        ("2001:db8::1", "source.example.invalid"),
        ("S-1-5-21-1-2-3-1001", "resolved-account"),
        ("S-1-5-21-1-2-3-1001", "S-1-5-4294967296"),
        (">3</Data>", ">-1</Data>"),
        (">42</EventRecordID>", ">0</EventRecordID>"),
        ("2026-01-02T03:04:05.123456700Z", "invalid-time"),
    ] {
        assert!(
            from_xml(&xml.replace(before, after)).is_err(),
            "field {before}"
        );
    }
    assert!(from_xml(&fixture(4625, 0).replace("0xc000006d", "0x100000000")).is_err());
}

#[test]
fn envelope_id_and_time_are_checked_and_replay_is_stable() {
    let event = parsed(4624, 0);
    let mut wire = envelope(event.clone());
    assert!(wire.validate(event.time_ms).is_ok());
    wire.id = "a".repeat(64);
    assert!(wire.validate(event.time_ms).is_err());
    wire.id = event.event_id();
    wire.time_ms += 1;
    assert!(wire.validate(event.time_ms).is_err());
    assert!(event.validate(event.time_ms - 60_001).is_err());
    let again = from_xml(&event.xml).unwrap().unwrap();
    assert_eq!(again.event_id(), event.event_id());
    let formatted = from_xml(&format!("\n{}\n", event.xml)).unwrap().unwrap();
    assert_ne!(formatted.event_id(), event.event_id());
    assert_eq!(formatted.target_user, event.target_user);
}

#[test]
fn bounded_xml_and_encoded_event_fit_transport_budget() {
    let xml = fixture(4624, 0);
    assert!(from_xml(&" ".repeat(MAX_XML_BYTES + 1)).is_err());
    assert!(from_xml(&xml.replace("alice", &"a".repeat(513))).is_err());
    assert!(from_xml(&xml.replace("alice", &"a".repeat(4097))).is_err());
    let nested = format!("{}alice{}", "<Nested>".repeat(17), "</Nested>".repeat(17));
    assert!(from_xml(&xml.replace("alice", &nested)).is_err());
    let fields = (0..129)
        .map(|i| format!("<Data Name=\"Extra{i}\"/>"))
        .collect::<String>();
    assert!(from_xml(&xml.replace("</EventData>", &format!("{fields}</EventData>"))).is_err());
    // An otherwise irrelevant bounded comment maximizes JSON escape growth
    // without altering facts. Raw XML permits tab/CR/LF, but no other C0 chars.
    let budget = MAX_XML_BYTES - xml.len() - "<!---->".len();
    let padded = xml.replace(
        "</Event>",
        &format!("<!--{}--></Event>", "\t".repeat(budget)),
    );
    assert_eq!(padded.len(), MAX_XML_BYTES);
    let event = from_xml(&padded).unwrap().unwrap();
    assert_eq!(event.xml, padded);
    assert!(serde_json::to_vec(&envelope(event)).unwrap().len() < 192 * 1024);
}

#[test]
fn windows_health_is_optional_and_validated_independently() {
    let mut health = crate::telemetry::CollectorHealth::default();
    let old_wire = serde_json::to_value(&health).unwrap();
    assert!(old_wire.get("windows_authentication").is_none());
    health.windows_authentication = Some(crate::authentication::AuthenticationHealth::default());
    assert!(health.validate().is_err());
    let auth = health.windows_authentication.as_mut().unwrap();
    auth.state = "starting".into();
    auth.started_ms = 1;
    // CollectorHealth's independently required mode is still validated.
    health.mode = "snapshot".into();
    assert!(health.validate().is_ok());
}
