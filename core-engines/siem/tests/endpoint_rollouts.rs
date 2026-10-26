use athernex_endpoint_protocol::{
    self as p,
    protection::ProtectionHealth,
    telemetry::CollectorHealth,
    update::{self as wire, DeploymentReceipt, InstallationReceipt, SignedRelease},
    Enrollment, Heartbeat, Platform,
};
use athernex_siem::{engine::Engine, fleet_rollout::RolloutRequest, model::now_ms};

struct Fixture {
    dir: tempfile::TempDir,
    engine: Engine,
    public: String,
    release: SignedRelease,
    ids: Vec<String>,
    health: Heartbeat,
    now: u64,
    component: wire::Component,
}
impl Fixture {
    fn new(count: usize) -> Self {
        Self::new_component(count, wire::Component::Agent)
    }
    fn new_component(count: usize, component: wire::Component) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&dir.path().join("ledger.db")).unwrap();
        let now = now_ms();
        let (private, public) = wire::generate_key().unwrap();
        let release = SignedRelease::sign(
            wire::Release {
                schema: 1,
                target: wire::target(),
                version: "next".into(),
                channel: "stable".into(),
                sequence: 1,
                issued_ms: now,
                expires_ms: now + 86_400_000,
                sha256: p::hash(&[13; 256]),
                bytes: 256,
                protocol: p::PROTOCOL,
            },
            &private,
        )
        .unwrap();
        let mut health = Heartbeat {
            controller_updates: None,
            version: "prior".into(),
            capabilities: vec!["inventory".into()],
            scanner: "Fixture scanner".into(),
            realtime: true,
            signature_version: "Fixture signatures".into(),
            spool_events: 0,
            error: String::new(),
            updates: Some(wire::UpdateHealth {
                automatic: true,
                supervised: true,
                managed: true,
                key_fingerprint: wire::fingerprint(&public).unwrap(),
                channel: "stable".into(),
                highwater: 0,
                staged_release: None,
                installed_release: None,
                state: "ready".into(),
                error: String::new(),
            }),
            protection: Some(ProtectionHealth {
                state: "active".into(),
                backend: "fixture".into(),
                checked_ms: now,
                roots: vec!["/fixture".into()],
                excluded_uid: Some(1000),
                pending_events: 0,
                dropped_events: 0,
                error: String::new(),
            }),
            collector: Some(CollectorHealth {
                network_events: None,
                process_events: None,
                windows_process_events: None,
                windows_network_events: None,
                authentication: None,
                windows_authentication: None,
                mode: "snapshot".into(),
                last_attempt_ms: now,
                last_success_ms: now,
                process_count: 1,
                connection_count: 0,
                pending_changes: 0,
                incomplete: false,
                error: String::new(),
            }),
        };
        if component == wire::Component::Controller {
            health.controller_updates = health.updates.clone();
            // Controller policy and rollback floor are independent of agent updates.
            let agent = health.updates.as_mut().unwrap();
            agent.managed = false;
            agent.automatic = false;
            agent.highwater = 100;
            agent.installed_release = Some("b".repeat(64));
        }
        let ids = (1..=count).map(|i| format!("{i:064x}")).collect::<Vec<_>>();
        for id in &ids {
            let token = engine.create_enrollment(Platform::current(), now).unwrap();
            engine
                .enroll_endpoint(
                    &Enrollment {
                        protocol: p::PROTOCOL,
                        enrollment_token: token,
                        endpoint_id: id.clone(),
                        credential: "a".repeat(64),
                        hostname: format!("Fixture {} <device>", &id[60..]),
                        platform: Platform::current(),
                        arch: std::env::consts::ARCH.into(),
                        version: "prior".into(),
                    },
                    now,
                )
                .unwrap();
            engine.endpoint_heartbeat(id, &health, now).unwrap();
        }
        Self {
            dir,
            engine,
            public,
            release,
            ids,
            health,
            now,
            component,
        }
    }
    fn request(&self) -> RolloutRequest {
        RolloutRequest {
            name: "Controlled rollout <review>".into(),
            endpoint_ids: self.ids.clone(),
            canary_count: 1,
            batch_size: 2,
            observe_secs: 60,
            not_before_ms: self.now + 1000,
            deadline_ms: self.now + 3_600_000,
        }
    }
    fn propose(&self) -> String {
        self.engine
            .propose_component_rollout(
                self.request(),
                &self.release,
                &self.public,
                self.component,
                self.now,
            )
            .unwrap()
    }
    fn review(&self, id: &str, action: &str, now: u64) {
        let hash = self.engine.endpoint_rollout(id).unwrap().plan_hash;
        self.engine
            .review_endpoint_rollout(id, &hash, action, now)
            .unwrap();
    }
    fn health_at(&self, state: &str, now: u64) -> Heartbeat {
        let mut health = self.health.clone();
        health.protection.as_mut().unwrap().checked_ms = now;
        health.collector.as_mut().unwrap().last_success_ms = now;
        health.collector.as_mut().unwrap().last_attempt_ms = now;
        let updates = match self.component {
            wire::Component::Agent => health.updates.as_mut().unwrap(),
            wire::Component::Controller => health.controller_updates.as_mut().unwrap(),
        };
        updates.state = state.into();
        if state == "staged" {
            updates.highwater = 1;
            updates.staged_release = Some(self.release.id().unwrap());
        }
        if state == "installed" {
            updates.highwater = 1;
            updates.installed_release = Some(self.release.id().unwrap());
            if self.component == wire::Component::Agent {
                health.version = "next".into();
            }
        }
        health
    }
    fn beat(&self, index: usize, state: &str, now: u64) {
        self.engine
            .endpoint_heartbeat(&self.ids[index], &self.health_at(state, now), now)
            .unwrap();
    }
    fn start(&self, index: usize, now: u64) -> String {
        let endpoint = &self.ids[index];
        let deployment = self
            .engine
            .poll_endpoint_update(endpoint, now)
            .unwrap()
            .unwrap();
        assert_eq!(deployment.component, self.component);
        self.engine
            .endpoint_update_receipt(
                endpoint,
                &DeploymentReceipt {
                    deployment_id: deployment.id.clone(),
                    release_id: self.release.id().unwrap(),
                    outcome: "staged".into(),
                    detail: "Fixture staged".into(),
                    finished_ms: now,
                },
                now,
            )
            .unwrap();
        self.beat(index, "staged", now);
        self.engine
            .start_endpoint_installation(endpoint, &deployment.id, now)
            .unwrap();
        deployment.id
    }
    fn receipt(&self, index: usize, deployment: &str, outcome: &str, now: u64) {
        self.engine
            .endpoint_installation_receipt(
                &self.ids[index],
                &InstallationReceipt {
                    deployment_id: deployment.into(),
                    release_id: self.release.id().unwrap(),
                    outcome: outcome.into(),
                    detail: "Controlled runtime result".into(),
                    finished_ms: now,
                },
                now,
            )
            .unwrap();
    }
    fn complete(&self, index: usize, now: u64) {
        let deployment = self.start(index, now);
        self.receipt(index, &deployment, "installed", now);
    }
    fn reopen(self) -> Self {
        let Self {
            dir,
            engine,
            public,
            release,
            ids,
            health,
            now,
            component,
        } = self;
        drop(engine);
        let engine = Engine::open(&dir.path().join("ledger.db")).unwrap();
        Self {
            dir,
            engine,
            public,
            release,
            ids,
            health,
            now,
            component,
        }
    }
}

#[test]
fn rollout_requires_exact_approval_and_real_health_observations_across_restart() {
    observed_rollout(wire::Component::Agent);
}

#[test]
fn controller_rollout_uses_independent_policy_and_health_across_restart() {
    observed_rollout(wire::Component::Controller);
}

fn observed_rollout(component: wire::Component) {
    let mut f = Fixture::new_component(3, component);
    let id = f.propose();
    let t = f.now;
    f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
    assert!(f
        .engine
        .endpoint_deployments(u64::MAX, t + 1000)
        .unwrap()
        .is_empty());
    assert!(f
        .engine
        .review_endpoint_rollout(&id, &"0".repeat(64), "approve", t)
        .is_err());
    assert!(f
        .engine
        .propose_endpoint_update(&f.ids[0], &f.release, &f.public, t)
        .is_err());
    f.review(&id, "approve", t);
    f.engine.tick_endpoint_rollouts(t + 999).unwrap();
    assert!(f
        .engine
        .endpoint_deployments(u64::MAX, t)
        .unwrap()
        .is_empty());
    f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
    assert_eq!(
        f.engine
            .endpoint_deployments(u64::MAX, t + 1000)
            .unwrap()
            .len(),
        1
    );
    f.complete(0, t + 2000);
    f.engine.tick_endpoint_rollouts(t + 2001).unwrap();
    assert_eq!(f.engine.endpoint_rollout(&id).unwrap().state, "running");
    f.beat(0, "installed", t + 3000);
    f = f.reopen();
    f.engine.tick_endpoint_rollouts(t + 63000).unwrap();
    assert_eq!(
        f.engine
            .endpoint_deployments(u64::MAX, t + 63000)
            .unwrap()
            .len(),
        1,
        "Elapsed time alone is not a healthy observation"
    );
    f.beat(0, "installed", t + 63000);
    f.beat(1, "ready", t + 63000);
    f.beat(2, "ready", t + 63000);
    f.engine.tick_endpoint_rollouts(t + 63000).unwrap();
    f = f.reopen();
    f.engine.tick_endpoint_rollouts(t + 63000).unwrap();
    assert_eq!(
        f.engine
            .endpoint_deployments(u64::MAX, t + 63000)
            .unwrap()
            .len(),
        3,
        "Restart must not issue duplicate deployments"
    );
    f.complete(1, t + 64000);
    f.complete(2, t + 64000);
    for index in 0..3 {
        f.beat(index, "installed", t + 65000);
        f.beat(index, "installed", t + 125000);
    }
    f.engine.tick_endpoint_rollouts(t + 125000).unwrap();
    assert_eq!(f.engine.endpoint_rollout(&id).unwrap().state, "completed");
}

#[test]
fn legacy_agent_plan_keeps_its_hash_and_controller_component_binds_approval() {
    for component in [wire::Component::Agent, wire::Component::Controller] {
        let f = Fixture::new_component(2, component);
        let id = f.propose();
        let record = f.engine.endpoint_rollout(&id).unwrap();
        let raw = serde_json::to_vec(&record.plan).unwrap();
        assert_eq!(record.plan_hash, p::hash(&raw));
        let mut value = serde_json::to_value(&record.plan).unwrap();
        if component == wire::Component::Agent {
            assert!(value.get("component").is_none());
            assert!(value.get("agent_identities").is_none());
            let restored: athernex_siem::fleet_rollout::RolloutPlan =
                serde_json::from_slice(&raw).unwrap();
            assert_eq!(restored.component, wire::Component::Agent);
            assert_eq!(serde_json::to_vec(&restored).unwrap(), raw);
        } else {
            assert_eq!(value["component"], "controller");
            assert_eq!(value["agent_identities"].as_array().unwrap().len(), 2);
        }
        value["component"] = serde_json::json!(if component == wire::Component::Agent {
            "controller"
        } else {
            "agent"
        });
        let altered: athernex_siem::fleet_rollout::RolloutPlan =
            serde_json::from_value(value).unwrap();
        let altered_hash = p::hash(&serde_json::to_vec(&altered).unwrap());
        assert!(f
            .engine
            .review_endpoint_rollout(&id, &altered_hash, "approve", f.now)
            .is_err());
        f.review(&id, "approve", f.now);
    }
}

#[test]
fn controller_promotion_rejects_agent_changes_wrong_component_and_lost_launcher() {
    for failure in 0..6 {
        let f = Fixture::new_component(2, wire::Component::Controller);
        let id = f.propose();
        let t = f.now;
        f.review(&id, "approve", t);
        f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
        f.complete(0, t + 2000);
        f.beat(0, "installed", t + 3000);
        let mut bad = f.health_at("installed", t + 4000);
        match failure {
            0 => bad.version = "unexpected-agent".into(),
            1 => bad.updates.as_mut().unwrap().installed_release = Some("c".repeat(64)),
            2 => {
                bad.updates = bad.controller_updates.take();
            }
            3 => bad.controller_updates.as_mut().unwrap().supervised = false,
            4 => bad.controller_updates.as_mut().unwrap().automatic = false,
            _ => bad.controller_updates.as_mut().unwrap().installed_release = Some("d".repeat(64)),
        }
        f.engine
            .endpoint_heartbeat(&f.ids[0], &bad, t + 4000)
            .unwrap();
        f.beat(0, "installed", t + 5000);
        f.engine.tick_endpoint_rollouts(t + 65000).unwrap();
        let record = f.engine.endpoint_rollout(&id).unwrap();
        assert_eq!(record.state, "failed", "failure {failure}");
        assert!(record.members[1].deployment_id.is_none());
    }
}

#[test]
fn controller_rollout_rechecks_agent_identity_before_approval_and_later_dispatch() {
    for before_approval in [true, false] {
        let f = Fixture::new_component(2, wire::Component::Controller);
        let id = f.propose();
        let t = f.now;
        if !before_approval {
            f.review(&id, "approve", t);
            f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
            f.complete(0, t + 2000);
            f.beat(0, "installed", t + 3000);
            f.beat(0, "installed", t + 63000);
        }
        let mut changed = f.health_at("ready", t + 63000);
        changed.version = "changed-after-proposal".into();
        f.engine
            .endpoint_heartbeat(&f.ids[1], &changed, t + 63000)
            .unwrap();
        if before_approval {
            let hash = f.engine.endpoint_rollout(&id).unwrap().plan_hash;
            assert!(f
                .engine
                .review_endpoint_rollout(&id, &hash, "approve", t + 63000)
                .is_err());
        } else {
            f.engine.tick_endpoint_rollouts(t + 63000).unwrap();
            assert_eq!(f.engine.endpoint_rollout(&id).unwrap().state, "failed");
        }
        assert!(f.engine.endpoint_rollout(&id).unwrap().members[1]
            .deployment_id
            .is_none());
    }
}

#[test]
fn failed_canary_stops_undispatched_devices_and_retains_its_receipt() {
    let f = Fixture::new(3);
    let id = f.propose();
    let t = f.now;
    f.review(&id, "approve", t);
    f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
    let deployment = f.start(0, t + 2000);
    f.receipt(0, &deployment, "rolled_back", t + 3000);
    f.engine.tick_endpoint_rollouts(t + 3000).unwrap();
    let record = f.engine.endpoint_rollout(&id).unwrap();
    assert_eq!(record.state, "failed");
    assert!(record.members[1..]
        .iter()
        .all(|m| m.deployment_id.is_none()));
    assert_eq!(
        record.members[0].deployment_state.as_deref(),
        Some("rolled_back")
    );
    assert!(f
        .engine
        .review_endpoint_rollout(&id, &record.plan_hash, "resume", t + 4000)
        .is_err());
    assert!(f
        .engine
        .propose_endpoint_update(&f.ids[1], &f.release, &f.public, t + 4000)
        .is_ok());
}

#[test]
fn pause_holds_dispatch_but_started_installation_can_finish_after_cancellation() {
    let f = Fixture::new(2);
    let id = f.propose();
    let t = f.now;
    f.review(&id, "approve", t);
    f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
    let deployment = f.engine.endpoint_rollout(&id).unwrap().members[0]
        .deployment_id
        .clone()
        .unwrap();
    f.review(&id, "pause", t + 1100);
    assert!(f
        .engine
        .authorized_endpoint_update(&f.ids[0], &deployment, t + 1200)
        .is_err());
    f.review(&id, "resume", t + 1300);
    let started = f.start(0, t + 1400);
    assert_eq!(deployment, started);
    f.review(&id, "pause", t + 1500);
    assert!(f
        .engine
        .start_endpoint_installation(&f.ids[0], &deployment, t + 1600)
        .is_ok());
    f.review(&id, "cancel", t + 1700);
    f.receipt(0, &deployment, "installed", t + 1800);
    f.beat(0, "installed", t + 1900);
    f.engine.tick_endpoint_rollouts(t + 80000).unwrap();
    let record = f.engine.endpoint_rollout(&id).unwrap();
    assert_eq!(record.state, "cancelled");
    assert_eq!(
        record.members[0].deployment_state.as_deref(),
        Some("installed")
    );
    assert!(record.members[1].deployment_id.is_none());
}

#[test]
fn protection_scope_collection_signatures_and_update_health_cannot_silently_degrade() {
    for failure in 0..5 {
        let f = Fixture::new(2);
        let id = f.propose();
        let t = f.now;
        f.review(&id, "approve", t);
        f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
        f.complete(0, t + 2000);
        f.beat(0, "installed", t + 3000);
        let mut bad = f.health_at("installed", t + 4000);
        match failure {
            0 => bad.protection.as_mut().unwrap().roots = vec!["/different".into()],
            1 => bad.collector.as_mut().unwrap().incomplete = true,
            2 => bad.signature_version.clear(),
            3 => bad.updates.as_mut().unwrap().supervised = false,
            _ => bad.protection.as_mut().unwrap().dropped_events = 1,
        }
        f.engine
            .endpoint_heartbeat(&f.ids[0], &bad, t + 4000)
            .unwrap();
        f.beat(0, "installed", t + 5000); // A later good report must not erase the failure.
        f.engine.tick_endpoint_rollouts(t + 65000).unwrap();
        let record = f.engine.endpoint_rollout(&id).unwrap();
        assert_eq!(record.state, "failed");
        assert!(record.members[1].deployment_id.is_none());
    }
}

#[test]
fn agent_and_controller_rollouts_keep_the_reviewed_authentication_requirement() {
    for component in [wire::Component::Agent, wire::Component::Controller] {
        for windows in [false, true] {
            for missing in [true, false] {
                let mut f = Fixture::new_component(2, component);
                let t = f.now;
                let healthy = p::authentication::AuthenticationHealth {
                    state: "active".into(),
                    started_ms: t,
                    checked_ms: t,
                    caught_up: true,
                    ..Default::default()
                };
                let collector = f.health.collector.as_mut().unwrap();
                if windows {
                    collector.windows_authentication = Some(healthy.clone());
                } else {
                    collector.authentication = Some(healthy.clone());
                }
                for index in 0..2 {
                    f.beat(index, "ready", t);
                }
                let id = f.propose();
                let gates = f.engine.endpoint_rollout(&id).unwrap().plan.gates;
                assert_eq!(gates.len(), f.ids.len());
                assert!(gates
                    .iter()
                    .all(|gate| gate.authentication != windows
                        && gate.windows_authentication == windows));
                f.review(&id, "approve", t);
                f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
                f.complete(0, t + 2000);
                f.beat(0, "installed", t + 3000);
                let mut bad = f.health_at("installed", t + 4000);
                let collector = bad.collector.as_mut().unwrap();
                let (auth, other) = if windows {
                    (
                        &mut collector.windows_authentication,
                        &mut collector.authentication,
                    )
                } else {
                    (
                        &mut collector.authentication,
                        &mut collector.windows_authentication,
                    )
                };
                // A healthy different source cannot replace the one reviewed.
                *other = Some(healthy);
                if missing {
                    *auth = None;
                } else {
                    auth.as_mut().unwrap().loss_signals = 1;
                }
                f.engine
                    .endpoint_heartbeat(&f.ids[0], &bad, t + 4000)
                    .unwrap();
                let record = f.engine.endpoint_rollout(&id).unwrap();
                assert_eq!(record.state, "failed");
                assert!(record.members[1].deployment_id.is_none());
                let collector = f.health.collector.as_mut().unwrap();
                let auth = if windows {
                    &mut collector.windows_authentication
                } else {
                    &mut collector.authentication
                };
                auth.as_mut().unwrap().checked_ms = t + 65_000;
                f.beat(0, "installed", t + 65_000);
                f.beat(1, "ready", t + 65_000);
                f.engine.tick_endpoint_rollouts(t + 65_000).unwrap();
                let record = f.engine.endpoint_rollout(&id).unwrap();
                assert_eq!(record.state, "failed");
                assert!(record.members[1].deployment_id.is_none());
            }
        }
    }
}

#[test]
fn agent_and_controller_rollouts_pin_windows_process_coverage_and_stop_after_a_gap() {
    for component in [wire::Component::Agent, wire::Component::Controller] {
        for failure in 0..4 {
            let mut f = Fixture::new_component(2, component);
            let t = f.now;
            let windows = p::windows_process_events::WindowsProcessEventHealth {
                stream_id: "c".repeat(64),
                state: "active".into(),
                started_ms: t - 60_000,
                checked_ms: t,
                subscriptions: 1,
                ..Default::default()
            };
            f.health.collector.as_mut().unwrap().windows_process_events = Some(windows);
            for index in 0..2 {
                f.beat(index, "ready", t);
            }
            let id = f.propose();
            assert!(f
                .engine
                .endpoint_rollout(&id)
                .unwrap()
                .plan
                .gates
                .iter()
                .all(|gate| gate.windows_process_events && !gate.process_events));
            f.review(&id, "approve", t);
            f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
            f.complete(0, t + 2000);
            f.beat(0, "installed", t + 3000);
            let mut bad = f.health_at("installed", t + 4000);
            let collector = bad.collector.as_mut().unwrap();
            collector.process_events = Some(p::process_events::ProcessEventHealth {
                boot_id: "a".repeat(64),
                stream_id: "b".repeat(64),
                state: "active".into(),
                started_ms: t,
                checked_ms: t + 4000,
                subscriptions: 1,
                received_events: 0,
                dropped_events: 0,
                loss_signals: 0,
                error: String::new(),
            });
            if failure == 0 {
                collector.windows_process_events = None;
            } else {
                let source = collector.windows_process_events.as_mut().unwrap();
                match failure {
                    1 => source.events_lost = 1,
                    2 => source.checked_ms = t - 30_001,
                    _ => {
                        source.subscriptions = 2;
                        source.loss_signals = 1;
                        source.state = "active".into();
                        source.error.clear();
                    }
                }
            }
            f.engine
                .endpoint_heartbeat(&f.ids[0], &bad, t + 4000)
                .unwrap();
            let record = f.engine.endpoint_rollout(&id).unwrap();
            assert_eq!(record.state, "failed");
            assert!(record.members[1].deployment_id.is_none());
            f.health
                .collector
                .as_mut()
                .unwrap()
                .windows_process_events
                .as_mut()
                .unwrap()
                .checked_ms = t + 65_000;
            for index in 0..2 {
                f.beat(
                    index,
                    if index == 0 { "installed" } else { "ready" },
                    t + 65_000,
                );
            }
            f.engine.tick_endpoint_rollouts(t + 65_000).unwrap();
            let record = f.engine.endpoint_rollout(&id).unwrap();
            assert_eq!(record.state, "failed");
            assert!(record.members[1].deployment_id.is_none());
        }
    }
}

#[test]
fn agent_and_controller_rollouts_pin_windows_network_coverage_and_stop_after_a_gap() {
    for component in [wire::Component::Agent, wire::Component::Controller] {
        for failure in 0..8 {
            let mut f = Fixture::new_component(2, component);
            let t = f.now;
            let windows = p::windows_network_events::WindowsNetworkEventHealth {
                stream_id: "c".repeat(64),
                state: "active".into(),
                started_ms: t - 60_000,
                checked_ms: t,
                subscriptions: 1,
                ..Default::default()
            };
            f.health.collector.as_mut().unwrap().windows_network_events = Some(windows);
            for index in 0..2 {
                f.beat(index, "ready", t);
            }
            let id = f.propose();
            let original_plan_hash = f.engine.endpoint_rollout(&id).unwrap().plan_hash;
            assert!(f
                .engine
                .endpoint_rollout(&id)
                .unwrap()
                .plan
                .gates
                .iter()
                .all(|gate| gate.windows_network_events && !gate.process_events));
            f.review(&id, "approve", t);
            f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
            f.complete(0, t + 2000);
            f.beat(0, "installed", t + 3000);
            let mut bad = f.health_at("installed", t + 4000);
            let collector = bad.collector.as_mut().unwrap();
            collector.process_events = Some(p::process_events::ProcessEventHealth {
                boot_id: "a".repeat(64),
                stream_id: "b".repeat(64),
                state: "active".into(),
                started_ms: t,
                checked_ms: t + 4000,
                subscriptions: 1,
                received_events: 0,
                dropped_events: 0,
                loss_signals: 0,
                error: String::new(),
            });
            collector.windows_process_events =
                Some(p::windows_process_events::WindowsProcessEventHealth {
                    stream_id: "e".repeat(64),
                    state: "active".into(),
                    started_ms: t,
                    checked_ms: t + 4000,
                    subscriptions: 1,
                    ..Default::default()
                });
            if failure == 0 {
                collector.windows_network_events = None;
            } else {
                let source = collector.windows_network_events.as_mut().unwrap();
                match failure {
                    1 => source.events_lost = 1,
                    2 => source.checked_ms = t - 30_001,
                    4 => source.state = "stopped".into(),
                    5 => source.state = "degraded".into(),
                    6 => source.backpressured = true,
                    7 => source.queue_drops = 1,
                    _ => {
                        source.subscriptions = 2;
                        source.loss_signals = 1;
                        source.state = "active".into();
                        source.error.clear();
                    }
                }
            }
            f.engine
                .endpoint_heartbeat(&f.ids[0], &bad, t + 4000)
                .unwrap();
            let record = f.engine.endpoint_rollout(&id).unwrap();
            assert_eq!(record.state, "failed");
            assert_eq!(record.plan_hash, original_plan_hash);
            assert!(record.members[1].deployment_id.is_none());
            f.health
                .collector
                .as_mut()
                .unwrap()
                .windows_network_events
                .as_mut()
                .unwrap()
                .checked_ms = t + 65_000;
            for index in 0..2 {
                f.beat(
                    index,
                    if index == 0 { "installed" } else { "ready" },
                    t + 65_000,
                );
            }
            f.engine.tick_endpoint_rollouts(t + 65_000).unwrap();
            let record = f.engine.endpoint_rollout(&id).unwrap();
            assert_eq!(record.state, "failed");
            assert_eq!(record.plan_hash, original_plan_hash);
            assert!(record.members[1].deployment_id.is_none());
        }
    }
}

#[test]
fn missing_heartbeats_reset_observation_and_missing_post_install_health_fails() {
    let f = Fixture::new(2);
    let id = f.propose();
    let t = f.now;
    f.review(&id, "approve", t);
    f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
    f.complete(0, t + 2000);
    f.beat(0, "installed", t + 3000);
    f.beat(0, "installed", t + 124000);
    let member = &f.engine.endpoint_rollout(&id).unwrap().members[0];
    assert_eq!(member.healthy_since_ms, Some(t + 124000));
    f.engine.tick_endpoint_rollouts(t + 124000).unwrap();
    assert!(f.engine.endpoint_rollout(&id).unwrap().members[1]
        .deployment_id
        .is_none());
    f.engine.tick_endpoint_rollouts(t + 245000).unwrap();
    assert_eq!(f.engine.endpoint_rollout(&id).unwrap().state, "failed");
    let f = Fixture::new(2);
    let id = f.propose();
    let t = f.now;
    f.review(&id, "approve", t);
    f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
    f.complete(0, t + 2000);
    f.engine.tick_endpoint_rollouts(t + 122001).unwrap();
    assert_eq!(f.engine.endpoint_rollout(&id).unwrap().state, "failed");
}

#[test]
fn rollout_membership_limits_reservations_window_and_live_policy_are_enforced() {
    let f = Fixture::new(2);
    let t = f.now;
    let mut request = f.request();
    request.endpoint_ids.push(f.ids[0].clone());
    assert!(f
        .engine
        .propose_endpoint_rollout(request, &f.release, &f.public, t)
        .is_err());
    let mut request = f.request();
    request.observe_secs = 0;
    assert!(f
        .engine
        .propose_endpoint_rollout(request, &f.release, &f.public, t)
        .is_err());
    let mut request = f.request();
    request.batch_size = 17;
    assert!(f
        .engine
        .propose_endpoint_rollout(request, &f.release, &f.public, t)
        .is_err());
    let mut request = f.request();
    request.deadline_ms = t + 180000;
    let id = f
        .engine
        .propose_endpoint_rollout(request, &f.release, &f.public, t)
        .unwrap();
    assert!(f
        .engine
        .propose_endpoint_rollout(f.request(), &f.release, &f.public, t)
        .is_err());
    f.review(&id, "approve", t);
    f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
    let deployment = f
        .engine
        .poll_endpoint_update(&f.ids[0], t + 1000)
        .unwrap()
        .unwrap();
    assert_eq!(deployment.expires_ms, t + 180000);
    f.engine.tick_endpoint_rollouts(t + 180000).unwrap();
    assert_eq!(f.engine.endpoint_rollout(&id).unwrap().state, "expired");
    let f = Fixture::new(2);
    let id = f.propose();
    let t = f.now;
    f.review(&id, "approve", t);
    let mut health = f.health_at("ready", t + 500);
    health.updates.as_mut().unwrap().automatic = false;
    f.engine
        .endpoint_heartbeat(&f.ids[0], &health, t + 500)
        .unwrap();
    f.engine.tick_endpoint_rollouts(t + 1000).unwrap();
    assert_eq!(f.engine.endpoint_rollout(&id).unwrap().state, "failed");
    assert!(f
        .engine
        .endpoint_deployments(u64::MAX, t + 1000)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn rollout_routes_require_operator_authorization_and_csrf() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    let f = Fixture::new(2);
    let id = f.propose();
    let hash = f.engine.endpoint_rollout(&id).unwrap().plan_hash;
    let app = athernex_siem::web::App {
        engine: Arc::new(Mutex::new(f.engine)),
        csrf: "rollout-csrf".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("rollout-operator-key-long-enough").unwrap(),
        ),
    };
    let router =
        athernex_siem::web::router_with_release_catalog(app.clone(), f.dir.path().join("catalog"));
    for uri in [
        "/api/endpoint-rollouts".to_string(),
        format!("/api/endpoint-rollouts/{id}"),
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for (csrf, expected) in [
        ("wrong", StatusCode::BAD_REQUEST),
        ("rollout-csrf", StatusCode::SEE_OTHER),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/endpoints/rollouts/action")
                    .header("authorization", "Bearer rollout-operator-key-long-enough")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "csrf={csrf}&op=approve&id={id}&plan_hash={hash}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let response = router
        .oneshot(
            Request::builder()
                .uri("/endpoint-rollouts")
                .header("authorization", "Bearer rollout-operator-key-long-enough")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        app.engine
            .lock()
            .unwrap()
            .endpoint_rollout(&id)
            .unwrap()
            .state,
        "scheduled"
    );
}
