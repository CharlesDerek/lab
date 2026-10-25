use athernex_endpoint_protocol::{
    self as p,
    engine::{File, Release, Roles, SignedRelease},
    engine_fleet::{Health, Receipt},
    Enrollment, Heartbeat, Platform,
};
use athernex_siem::{engine::Engine, fleet_rollout::RolloutRequest};
const NOW: u64 = 1_800_000_000_000;
struct Fixture {
    dir: tempfile::TempDir,
    engine: Engine,
    key: String,
    release: SignedRelease,
    ids: Vec<String>,
    health: Heartbeat,
    engine_health: Health,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&dir.path().join("db")).unwrap();
        let (private, key) = p::update::generate_key().unwrap();
        let paths = [
            "bin/clamscan",
            "bin/freshclam",
            "sbin/clamd",
            "sbin/clamonacc",
            "lib/libfixture.so",
            "etc/certs/fixture.crt",
        ];
        let release = SignedRelease::sign(
            Release {
                schema: 1,
                protocol: p::PROTOCOL,
                engine: "clamav".into(),
                target: p::update::target(),
                version: "next".into(),
                channel: "stable".into(),
                sequence: 1,
                issued_ms: NOW,
                expires_ms: NOW + 86_400_000,
                roles: Roles {
                    scanner: paths[0].into(),
                    updater: paths[1].into(),
                    daemon: paths[2].into(),
                    monitor: Some(paths[3].into()),
                    library_dirs: vec!["lib".into()],
                    certificates: "etc/certs".into(),
                },
                files: paths
                    .iter()
                    .map(|path| File {
                        path: (*path).into(),
                        sha256: p::hash(path.as_bytes()),
                        bytes: path.len() as u64,
                        executable: path.starts_with("bin/") || path.starts_with("sbin/"),
                    })
                    .collect(),
            },
            &private,
        )
        .unwrap();
        let health = Heartbeat {
            controller_updates: None,
            updates: None,
            protection: None,
            collector: None,
            version: "prior".into(),
            capabilities: vec!["inventory".into()],
            scanner: "fixture".into(),
            realtime: false,
            signature_version: "fixture".into(),
            spool_events: 0,
            error: String::new(),
        };
        let engine_health = Health {
            managed: true,
            automatic: true,
            supervised: true,
            target: p::update::target(),
            key_fingerprint: p::update::fingerprint(&key).unwrap(),
            channel: "stable".into(),
            highwater: 0,
            staged_release: None,
            installed_release: None,
            phase: "ready".into(),
            error: String::new(),
        };
        let ids = (1..=3).map(|i| format!("{i:064x}")).collect::<Vec<_>>();
        for id in &ids {
            let token = engine.create_enrollment(Platform::current(), NOW).unwrap();
            engine
                .enroll_endpoint(
                    &Enrollment {
                        protocol: p::PROTOCOL,
                        enrollment_token: token,
                        endpoint_id: id.clone(),
                        credential: "a".repeat(64),
                        hostname: "fixture".into(),
                        platform: Platform::current(),
                        arch: std::env::consts::ARCH.into(),
                        version: "prior".into(),
                    },
                    NOW,
                )
                .unwrap();
            engine.endpoint_heartbeat(id, &health, NOW).unwrap();
            engine
                .endpoint_engine_health(id, &engine_health, NOW)
                .unwrap();
        }
        Self {
            dir,
            engine,
            key,
            release,
            ids,
            health,
            engine_health,
        }
    }
    fn propose(&self) -> String {
        self.engine
            .propose_engine_rollout(
                RolloutRequest {
                    name: "engine canaries".into(),
                    endpoint_ids: self.ids.clone(),
                    canary_count: 1,
                    batch_size: 2,
                    observe_secs: 60,
                    not_before_ms: NOW,
                    deadline_ms: NOW + 3_600_000,
                },
                &self.release,
                &self.key,
                NOW,
            )
            .unwrap()
    }
    fn review(&self, id: &str, action: &str, now: u64) {
        let hash = self.engine.engine_rollout(id).unwrap().plan_hash;
        self.engine
            .review_engine_rollout(id, &hash, action, now)
            .unwrap();
    }
    fn beat(&self, index: usize, installed: bool, now: u64) {
        let mut h = self.engine_health.clone();
        if installed {
            h.highwater = 1;
            h.installed_release = Some(self.release.id().unwrap());
            h.phase = "installed".into();
        }
        self.engine
            .endpoint_heartbeat(&self.ids[index], &self.health, now)
            .unwrap();
        self.engine
            .endpoint_engine_health(&self.ids[index], &h, now)
            .unwrap();
    }
    fn install(&self, index: usize, outcome: &str, now: u64) -> String {
        let ep = &self.ids[index];
        let plan = self
            .engine
            .poll_engine_update(ep, &self.key, now)
            .unwrap()
            .unwrap();
        self.engine
            .finish_engine_delivery(
                ep,
                &Receipt {
                    deployment_id: plan.id.clone(),
                    release_id: self.release.id().unwrap(),
                    outcome: "staged".into(),
                    detail: String::new(),
                    finished_ms: now,
                },
                now,
            )
            .unwrap();
        let mut h = self.engine_health.clone();
        h.highwater = 1;
        h.staged_release = Some(self.release.id().unwrap());
        h.phase = "staged".into();
        self.engine.endpoint_engine_health(ep, &h, now).unwrap();
        self.engine
            .authorize_engine_install(ep, &plan.id, &self.key, now)
            .unwrap();
        self.engine
            .finish_engine_delivery(
                ep,
                &Receipt {
                    deployment_id: plan.id.clone(),
                    release_id: self.release.id().unwrap(),
                    outcome: outcome.into(),
                    detail: String::new(),
                    finished_ms: now,
                },
                now,
            )
            .unwrap();
        plan.id
    }
}
#[test]
fn engine_canary_requires_receipt_and_two_fresh_health_streams_across_restart() {
    let mut f = Fixture::new();
    let id = f.propose();
    f.review(&id, "approve", NOW);
    f.engine.tick_engine_rollouts(NOW).unwrap();
    assert!(f
        .engine
        .poll_engine_update(&f.ids[1], &f.key, NOW)
        .unwrap()
        .is_none());
    f.install(0, "installed", NOW + 1);
    f.engine.tick_engine_rollouts(NOW + 2).unwrap();
    assert!(f.engine.engine_rollout(&id).unwrap().members[1]
        .deployment_id
        .is_none());
    f.beat(0, true, NOW + 10);
    f.engine.tick_engine_rollouts(NOW + 60_010).unwrap();
    assert!(
        f.engine.engine_rollout(&id).unwrap().members[1]
            .deployment_id
            .is_none(),
        "clock passage without two fresh streams cannot promote"
    );
    drop(f.engine);
    f.engine = Engine::open(&f.dir.path().join("db")).unwrap();
    f.beat(0, true, NOW + 60_011);
    f.beat(1, false, NOW + 60_011);
    f.beat(2, false, NOW + 60_011);
    f.engine.tick_engine_rollouts(NOW + 60_011).unwrap();
    assert!(f.engine.engine_rollout(&id).unwrap().members[1]
        .deployment_id
        .is_some());
    f.install(1, "installed", NOW + 60_012);
    f.install(2, "installed", NOW + 60_012);
    f.beat(1, true, NOW + 60_013);
    f.beat(2, true, NOW + 60_013);
    for i in 0..3 {
        f.beat(i, true, NOW + 120_014);
    }
    f.engine.tick_engine_rollouts(NOW + 120_014).unwrap();
    assert_eq!(f.engine.engine_rollout(&id).unwrap().state, "completed");
}

#[test]
fn engine_rollouts_keep_the_reviewed_authentication_requirement() {
    for windows in [false, true] {
        for missing in [true, false] {
            let mut f = Fixture::new();
            let healthy = p::authentication::AuthenticationHealth {
                state: "active".into(),
                started_ms: NOW,
                checked_ms: NOW,
                caught_up: true,
                ..Default::default()
            };
            f.health.collector = Some(p::telemetry::CollectorHealth {
                authentication: (!windows).then_some(healthy.clone()),
                network_events: None,
                process_events: None,
                windows_authentication: windows.then_some(healthy.clone()),
                mode: "snapshot".into(),
                last_attempt_ms: NOW,
                last_success_ms: NOW,
                process_count: 1,
                connection_count: 0,
                pending_changes: 0,
                incomplete: false,
                error: String::new(),
            });
            for index in 0..3 {
                f.beat(index, false, NOW);
            }
            let id = f.propose();
            let gates = f.engine.engine_rollout(&id).unwrap().plan.gates;
            assert_eq!(gates.len(), f.ids.len());
            assert!(gates.iter().all(
                |gate| gate.authentication != windows && gate.windows_authentication == windows
            ));
            f.review(&id, "approve", NOW);
            f.engine.tick_engine_rollouts(NOW).unwrap();
            f.install(0, "installed", NOW + 1);
            f.beat(0, true, NOW + 2);
            let mut bad = f.health.clone();
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
                .endpoint_heartbeat(&f.ids[0], &bad, NOW + 3)
                .unwrap();
            let record = f.engine.engine_rollout(&id).unwrap();
            assert_eq!(record.state, "failed");
            assert!(record.members[1..]
                .iter()
                .all(|member| member.deployment_id.is_none()));
            let collector = f.health.collector.as_mut().unwrap();
            collector.last_attempt_ms = NOW + 60_010;
            collector.last_success_ms = NOW + 60_010;
            let auth = if windows {
                &mut collector.windows_authentication
            } else {
                &mut collector.authentication
            };
            auth.as_mut().unwrap().checked_ms = NOW + 60_010;
            for index in 0..3 {
                f.beat(index, index == 0, NOW + 60_010);
            }
            f.engine.tick_engine_rollouts(NOW + 60_010).unwrap();
            let record = f.engine.engine_rollout(&id).unwrap();
            assert_eq!(record.state, "failed");
            assert!(record.members[1..]
                .iter()
                .all(|member| member.deployment_id.is_none()));
        }
    }
}
#[test]
fn pause_cancellation_and_failed_receipt_stop_future_install_authority() {
    let f = Fixture::new();
    let id = f.propose();
    let hash = f.engine.engine_rollout(&id).unwrap().plan_hash;
    assert!(f
        .engine
        .review_engine_rollout(&id, "changed", "approve", NOW)
        .is_err());
    f.review(&id, "approve", NOW);
    f.engine.tick_engine_rollouts(NOW).unwrap();
    let deployment = f
        .engine
        .poll_engine_update(&f.ids[0], &f.key, NOW)
        .unwrap()
        .unwrap();
    assert!(f
        .engine
        .review_engine_update(&deployment.id, &p::hash(b"anything"), &f.key, true, NOW)
        .is_err());
    f.review(&id, "pause", NOW + 1);
    assert!(f
        .engine
        .authorize_engine_download(&f.ids[0], &deployment.id, &f.key, NOW + 2)
        .is_err());
    f.review(&id, "resume", NOW + 3);
    f.install(0, "rolled_back", NOW + 4);
    f.engine.tick_engine_rollouts(NOW + 5).unwrap();
    assert_eq!(f.engine.engine_rollout(&id).unwrap().state, "failed");
    assert!(f.engine.engine_rollout(&id).unwrap().members[1]
        .deployment_id
        .is_none());
    assert!(f
        .engine
        .review_engine_rollout(&id, &hash, "resume", NOW + 6)
        .is_err());
}
#[test]
fn group_reservation_excludes_individual_and_cross_component_maintenance() {
    let f = Fixture::new();
    let id = f.propose();
    assert!(f
        .engine
        .propose_engine_update(&f.ids[2], &f.release, &f.key, true, NOW)
        .is_err());
    let (private, key) = p::update::generate_key().unwrap();
    let agent = p::update::SignedRelease::sign(
        p::update::Release {
            schema: 1,
            protocol: p::PROTOCOL,
            target: p::update::target(),
            version: "next".into(),
            channel: "stable".into(),
            sequence: 1,
            issued_ms: NOW,
            expires_ms: NOW + 3_600_000,
            sha256: p::hash(&[1; 256]),
            bytes: 256,
        },
        &private,
    )
    .unwrap();
    assert!(f
        .engine
        .propose_endpoint_release(&f.ids[2], &agent, &key, false, NOW)
        .unwrap_err()
        .to_string()
        .contains("active rollout"));
    f.review(&id, "cancel", NOW + 1);
    f.engine
        .propose_engine_update(&f.ids[2], &f.release, &f.key, true, NOW + 2)
        .unwrap();
    assert!(f
        .engine
        .propose_endpoint_release(&f.ids[2], &agent, &key, false, NOW + 3)
        .unwrap_err()
        .to_string()
        .contains("Engine maintenance"));
}

#[test]
fn recovered_rollback_can_stage_newer_release_but_current_degradation_still_blocks() {
    let f = Fixture::new();
    let mut health = f.engine_health.clone();
    health.phase = "rolled_back".into();
    health.error = "Historical candidate failure; prior engine restored".into();
    f.engine
        .endpoint_engine_health(&f.ids[0], &health, NOW + 1)
        .unwrap();
    f.engine
        .propose_engine_update(&f.ids[0], &f.release, &f.key, false, NOW + 1)
        .unwrap();
    let mut degraded = f.health.clone();
    degraded.error = "Live scanner unavailable".into();
    f.engine
        .endpoint_heartbeat(&f.ids[1], &degraded, NOW + 1)
        .unwrap();
    f.engine
        .endpoint_engine_health(&f.ids[1], &health, NOW + 1)
        .unwrap();
    assert!(f
        .engine
        .propose_engine_update(&f.ids[1], &f.release, &f.key, false, NOW + 1)
        .is_err());
}
