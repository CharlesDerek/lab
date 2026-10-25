use athernex_siem::{
    engine::Engine,
    signals::{KubernetesBatch, Signal, SignalKind as K, SignalPolicy},
};
const NOW: u64 = 1_800_000_000_000;
fn signal(id: &str, kind: K, time: u64) -> Signal {
    Signal {
        id: id.into(),
        time_ms: time,
        principal: "alice@example.test".into(),
        kind,
        namespace: "workloads".into(),
        object: "fixture".into(),
        object_uid: Some("uid-1".into()),
        source_ip: Some("192.0.2.4".parse().unwrap()),
        user_agent: Some("public-client-metadata".repeat(50)),
    }
}
fn setup() -> (Engine, String) {
    let e = Engine::memory().unwrap();
    let token = e.create_source("cluster", "api", "", NOW).unwrap().unwrap();
    (e, token)
}
fn rules(e: &Engine) -> Vec<String> {
    let mut result: Vec<_> = e
        .findings()
        .unwrap()
        .into_iter()
        .filter(|f| f.rule.starts_with("EK-"))
        .map(|f| f.rule)
        .collect();
    result.sort();
    result
}
#[test]
fn kubernetes_metadata_preserves_identity_and_distinguishes_authentication_from_authorization() {
    let raw = serde_json::json!({"apiVersion":"audit.k8s.io/v1","kind":"EventList","items":[{
        "auditID":"audit-1","stage":"ResponseComplete","verb":"create","user":{"username":"system:serviceaccount:team:runner"},
        "objectRef":{"resource":"pods","namespace":"team","name":"worker","uid":"pod-uid","subresource":"exec"},
        "responseStatus":{"code":201},"requestReceivedTimestamp":"2027-01-15T08:00:00.123456Z","sourceIPs":["192.0.2.3"],
        "requestObject":{"secret":"must-never-be-stored"},"responseObject":{"secret":"also-private"}
    }]});
    let normalized = serde_json::from_value::<KubernetesBatch>(raw.clone())
        .unwrap()
        .normalize()
        .unwrap();
    assert_eq!(normalized[0].kind, K::WorkloadExec);
    assert_eq!(normalized[0].principal, "system:serviceaccount:team:runner");
    assert_eq!(normalized[0].source_ip.unwrap().to_string(), "192.0.2.3");
    assert!(!serde_json::to_string(&normalized)
        .unwrap()
        .contains("must-never"));
    for (code, kind) in [(401, K::AuthenticationDenied), (403, K::AccessDenied)] {
        let mut denied = raw.clone();
        denied["items"][0]["responseStatus"]["code"] = code.into();
        assert_eq!(
            serde_json::from_value::<KubernetesBatch>(denied)
                .unwrap()
                .normalize()
                .unwrap()[0]
                .kind,
            kind
        );
    }
    let mut invalid = raw;
    invalid["items"][0]["stage"] = "RequestReceived".into();
    assert!(serde_json::from_value::<KubernetesBatch>(invalid)
        .unwrap()
        .normalize()
        .is_err());
}
#[test]
fn out_of_order_replay_and_changed_duplicate_preserve_exact_evidence() {
    let (mut e, token) = setup();
    let exec = signal("exec", K::WorkloadExec, NOW - 1000);
    let secret = signal("secret", K::SecretRead, NOW - 2000);
    e.ingest_signals("cluster", &token, std::slice::from_ref(&exec), NOW)
        .unwrap();
    assert!(rules(&e).is_empty());
    e.ingest_signals("cluster", &token, std::slice::from_ref(&secret), NOW)
        .unwrap();
    assert_eq!(rules(&e), vec!["EK-002"]);
    let evidence = e
        .findings()
        .unwrap()
        .into_iter()
        .find(|f| f.rule == "EK-002")
        .unwrap()
        .evidence;
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        e.signal_fact(evidence[0].event.id).unwrap().signal.id,
        "secret"
    );
    assert_eq!(
        e.ingest_signals("cluster", &token, &[exec.clone(), secret], NOW)
            .unwrap(),
        0
    );
    e.replay_signals(NOW).unwrap();
    assert_eq!(rules(&e), vec!["EK-002"]);
    let mut changed = exec;
    changed.principal = "someone-else".into();
    assert!(e
        .ingest_signals(
            "cluster",
            &token,
            &[signal("new", K::Observation, NOW), changed],
            NOW
        )
        .is_err());
    assert_eq!(
        e.signal_coverage().unwrap().records,
        2,
        "failed batch is atomic"
    );
}
#[test]
fn sources_are_separate_until_explicitly_mapped_and_spray_counts_distinct_principals() {
    let (mut e, token) = setup();
    let identity_token = e
        .create_source("identity", "api", "", NOW)
        .unwrap()
        .unwrap();
    for source in ["identity", "cluster"] {
        e.map_signal_identity(source, "alice@example.test", "alice", None, NOW)
            .unwrap();
    }
    let denied: Vec<_> = (0..5)
        .map(|i| {
            signal(
                &format!("deny-{i}"),
                K::AuthenticationDenied,
                NOW - 10000 + i,
            )
        })
        .collect();
    e.ingest_signals("identity", &identity_token, &denied, NOW)
        .unwrap();
    e.ingest_signals(
        "cluster",
        &token,
        &[signal("exec", K::WorkloadExec, NOW)],
        NOW,
    )
    .unwrap();
    assert_eq!(rules(&e), vec!["EK-001"]);
    let spray: Vec<_> = (0..5)
        .map(|i| {
            let mut s = signal(&format!("spray-{i}"), K::AuthenticationDenied, NOW + i);
            s.principal = format!("principal-{i}");
            s
        })
        .collect();
    e.ingest_signals("cluster", &token, &spray, NOW + 5)
        .unwrap();
    assert!(rules(&e).contains(&"EK-003".into()));
    let other = e.create_source("other", "api", "", NOW).unwrap().unwrap();
    e.ingest_signals(
        "other",
        &other,
        &[signal("separate-exec", K::WorkloadExec, NOW)],
        NOW,
    )
    .unwrap();
    assert_eq!(rules(&e).iter().filter(|id| *id == "EK-001").count(), 1);
    assert!(e
        .ingest_signals(
            "cluster",
            &identity_token,
            &[signal("wrong-token", K::Observation, NOW)],
            NOW
        )
        .is_err());
}
#[test]
fn detection_aware_compaction_saves_payload_and_preserves_findings_and_replay() {
    let (mut full, token) = setup();
    let inputs = [
        signal("secret", K::SecretRead, NOW - 1000),
        signal("exec", K::WorkloadExec, NOW),
    ];
    full.ingest_signals("cluster", &token, &inputs, NOW)
        .unwrap();
    let expected = serde_json::to_value(full.cases().unwrap()).unwrap();
    let mut policy = SignalPolicy {
        keep_source_ip: false,
        ..Default::default()
    };
    assert!(full.configure_signal_policy(&policy, NOW).is_err());
    policy.keep_source_ip = true;
    policy.keep_user_agent = false;
    full.configure_signal_policy(&policy, NOW).unwrap();
    let (before, after) = full.compact_signals(NOW).unwrap();
    assert!(after < before / 2);
    full.replay_signals(NOW).unwrap();
    assert_eq!(
        serde_json::to_value(full.cases().unwrap()).unwrap(),
        expected
    );
    assert_eq!(
        full.ingest_signals("cluster", &token, &inputs, NOW)
            .unwrap(),
        0,
        "compaction preserves original replay hashes"
    );
    let (mut projected, token) = setup();
    projected.configure_signal_policy(&policy, NOW).unwrap();
    projected
        .ingest_signals("cluster", &token, &inputs, NOW)
        .unwrap();
    assert_eq!(rules(&projected), rules(&full));
    assert_eq!(projected.signal_coverage().unwrap().payload_bytes, after);
}

#[test]
fn paged_replay_and_old_exact_delivery_remain_idempotent() {
    let (mut e, token) = setup();
    let first = signal("old", K::SecretRead, NOW - 100);
    let second = signal("exec", K::WorkloadExec, NOW);
    e.ingest_signals("cluster", &token, &[first.clone(), second], NOW)
        .unwrap();
    let count = e.findings().unwrap().len();
    let (n, next) = e.replay_signal_page(0, 1, NOW + 1).unwrap();
    assert_eq!(n, 1);
    assert!(next.is_some());
    assert_eq!(
        e.replay_signal_page(next.unwrap(), 1, NOW + 2).unwrap(),
        (1, None)
    );
    e.replay_signal_page(0, 1, NOW + 3).unwrap();
    assert_eq!(e.findings().unwrap().len(), count);
    let mut policy = e.signal_policy().unwrap();
    policy.accepted_lateness_ms = 0;
    e.configure_signal_policy(&policy, NOW + 4).unwrap();
    assert_eq!(
        e.ingest_signals("cluster", &token, std::slice::from_ref(&first), NOW + 4)
            .unwrap(),
        0
    );
    let mut changed = first;
    changed.id = "new-late".into();
    assert!(e
        .ingest_signals("cluster", &token, &[changed], NOW + 4)
        .is_err());
}
