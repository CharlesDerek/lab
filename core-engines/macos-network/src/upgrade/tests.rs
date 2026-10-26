use super::*;
fn plan() -> UpgradePlan {
    let identity = BundleIdentity {
        team_id: "TESTTEAM00".into(),
        agent_identifier: "com.example.agent".into(),
        container_identifier: "com.example.container".into(),
        provider_identifier: "com.example.provider".into(),
        app_group: "TESTTEAM00.com.example.network".into(),
        mach_service_name: "TESTTEAM00.com.example.network.ipc".into(),
    };
    let pin = |v: &str, h: &str| UpgradeCodePin {
        executable_sha256: h.repeat(64),
        cdhashes: vec![h.repeat(40)],
        info_plist_sha256: h.repeat(64),
        bundle_version: v.into(),
        short_version: "0.1".into(),
    };
    UpgradePlan {
        mode: UpgradeMode::Submit,
        transaction_id: "a".repeat(64),
        generation: 1,
        identity,
        source_policy_sha256:
            athernex_endpoint_protocol::macos_network_events::source_policy_sha256(),
        old: pin("1", "a"),
        new: pin("2.0.0", "b"),
        container_cdhashes: vec!["c".repeat(40)],
    }
}
#[test]
fn legacy_predecessor_and_inactive_filter_preserve_exact_semantics() {
    let p = plan();
    p.validate().unwrap();
    assert_eq!(version("1").unwrap(), version("1.0.0").unwrap());
    let property = ExtensionProperty {
        url: "/Library/SystemExtensions/fixed/com.example.provider.systemextension".into(),
        bundle_identifier: p.identity.provider_identifier.clone(),
        bundle_version: p.old.bundle_version.clone(),
        bundle_short_version: p.old.short_version.clone(),
        is_enabled: false,
        is_awaiting_user_approval: false,
        is_uninstalling: false,
    };
    let permit = UpgradePermit {
        plan: p,
        old_property: property,
        attempt_id: "d".repeat(64),
        attempt_nonce: "e".repeat(64),
        permit_ms: 5000,
    };
    permit.validate().unwrap();
    let mut invalid = permit.clone();
    invalid.plan.mode = UpgradeMode::Reconcile;
    assert!(invalid.validate().is_err());
    for field in [0, 1] {
        let mut invalid = permit.clone();
        if field == 0 {
            invalid.old_property.is_uninstalling = true;
        } else {
            invalid.old_property.is_awaiting_user_approval = true;
        }
        assert!(invalid.validate().is_err());
    }
    assert_eq!(
        serde_json::to_string(&FilterState::Owned { enabled: false }).unwrap(),
        r#"{"type":"owned","enabled":false}"#
    );
}
#[test]
fn exact_build_and_forward_version_binding_cannot_be_replaced_by_names() {
    let p = plan();
    for v in ["1", "1.0.0", "0.9.9", "02.0.0", "2..0", "2.0b1"] {
        let mut q = p.clone();
        q.new.bundle_version = v.into();
        assert!(q.validate().is_err());
    }
    let mut q = p.clone();
    q.new.cdhashes = q.old.cdhashes.clone();
    assert!(q.validate().is_err());
    let mut q = p.clone();
    q.container_cdhashes.push(q.container_cdhashes[0].clone());
    assert!(q.validate().is_err());
    let mut q = p;
    q.source_policy_sha256 = "0".repeat(64);
    assert!(q.validate().is_err());
}
#[test]
fn request_json_is_closed_and_duplicate_fields_do_not_disappear() {
    for body in [
        r#"{"type":"claim","plan_sha256":"a","command":"activate"}"#,
        r#"{"type":"plan","type":"plan"}"#,
        r#"{"type":"inspect","properties":[],"filter":{"type":"owned","enabled":0}}"#,
    ] {
        assert!(serde_json::from_str::<UpgradeRequest>(body).is_err());
    }
    let body = serde_json::to_vec(&UpgradeReply::Plan {
        plan: plan(),
        plan_sha256: "f".repeat(64),
    })
    .unwrap();
    let reply: UpgradeReply = serde_json::from_slice(&body).unwrap();
    reply.validate().unwrap();
    assert!(body.len() < MAX_MESSAGE_BYTES);
    let request = UpgradeRequest::Report {
        attempt_id: "d".repeat(64),
        attempt_nonce: "e".repeat(64),
        sequence: 1,
        outcome: UpgradeOutcome::UnexpectedCompleted,
    };
    request.validate().unwrap();
    let request = UpgradeRequest::Claim {
        plan_sha256: "not-an-authenticated-digest".into(),
    };
    assert!(request.validate().is_err());
}
