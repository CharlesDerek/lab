//! Component preflight using unchanged, natively captured network subhealth.
//! All enrollment, update policy and signing context here is synthetic. Times
//! evaluate each captured sample as of its own check; this performs no deployment.
use athernex_endpoint_protocol::{
    self as protocol,
    telemetry::CollectorHealth,
    update::{self as wire, Component, SignedRelease, UpdateHealth},
    windows_network_events::WindowsNetworkEventHealth,
    windows_process_events::WindowsProcessEventHealth,
    Enrollment, Heartbeat, Platform,
};
use athernex_siem::{engine::Engine, fleet_rollout::RolloutRequest};
use std::path::Path;

type Result<T> = std::result::Result<T, &'static str>;
fn safe<T, E>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|_| "rollout")
}
fn ensure(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err("rollout")
    }
}

pub(super) fn verify(
    private: &Path,
    healthy: &WindowsNetworkEventHealth,
    degraded: &WindowsNetworkEventHealth,
) -> Result<()> {
    safe(healthy.validate())?;
    safe(degraded.validate())?;
    let before = healthy.checked_ms;
    let after = degraded.checked_ms;
    ensure(healthy.healthy(before))?;
    ensure(after >= before && after - before < 3_600_000)?;
    ensure(degraded.checked_ms >= degraded.started_ms)?;
    ensure(degraded.loss_signals > healthy.loss_signals)?;
    ensure(degraded.subscriptions > healthy.subscriptions && !degraded.healthy(after))?;

    for component in [Component::Agent, Component::Controller] {
        let label = if component == Component::Agent {
            "agent"
        } else {
            "controller"
        };
        let database = private.join(format!("network-{label}-preflight.db"));
        ensure(!database.exists())?;
        let mut engine = safe(Engine::open(&database))?;
        safe(engine.configure_mode(false))?;
        // This key never leaves memory. The signed bytes are a fixture value,
        // not an executable, and no installation or dispatch API is invoked.
        let (key, public) = safe(wire::generate_key())?;
        let release = safe(SignedRelease::sign(
            wire::Release {
                schema: 1,
                target: wire::target(),
                version: "network-preflight-next".into(),
                channel: "stable".into(),
                sequence: 1,
                issued_ms: before,
                expires_ms: before + 86_400_000,
                sha256: protocol::hash(&[0xd5; 256]),
                bytes: 256,
                protocol: protocol::PROTOCOL,
            },
            &key,
        ))?;
        let id = protocol::hash(format!("synthetic-network-preflight-{label}").as_bytes());
        let enrollment = Enrollment {
            protocol: protocol::PROTOCOL,
            enrollment_token: safe(engine.create_enrollment(Platform::current(), before))?,
            endpoint_id: id.clone(),
            credential: protocol::hash(b"synthetic-preflight-credential"),
            hostname: "Synthetic network preflight".into(),
            platform: Platform::current(),
            arch: std::env::consts::ARCH.into(),
            version: "network-preflight-prior".into(),
        };
        safe(engine.enroll_endpoint(&enrollment, before))?;
        let updates = UpdateHealth {
            automatic: true,
            supervised: true,
            managed: true,
            key_fingerprint: safe(wire::fingerprint(&public))?,
            channel: "stable".into(),
            highwater: 0,
            staged_release: None,
            installed_release: None,
            state: "ready".into(),
            error: String::new(),
        };
        let mut heartbeat = Heartbeat {
            version: "network-preflight-prior".into(),
            capabilities: vec!["inventory".into()],
            scanner: String::new(),
            realtime: false,
            signature_version: String::new(),
            spool_events: 0,
            error: String::new(),
            protection: None,
            updates: Some(updates.clone()),
            controller_updates: (component == Component::Controller).then_some(updates),
            collector: Some(CollectorHealth {
                mode: "snapshot".into(),
                last_attempt_ms: before,
                last_success_ms: before,
                windows_network_events: Some(healthy.clone()),
                ..Default::default()
            }),
        };
        safe(engine.endpoint_heartbeat(&id, &heartbeat, before))?;
        let request = RolloutRequest {
            name: "Synthetic network preflight".into(),
            endpoint_ids: vec![id.clone()],
            canary_count: 1,
            batch_size: 1,
            observe_secs: 60,
            not_before_ms: before,
            deadline_ms: before + 3_600_000,
        };
        let positive = safe(engine.propose_component_rollout(
            request.clone(),
            &release,
            &public,
            component,
            before,
        ))?;
        let plan = safe(engine.endpoint_rollout(&positive))?;
        ensure(plan.plan.gates.len() == 1 && plan.plan.gates[0].windows_network_events)?;
        safe(engine.review_endpoint_rollout(&positive, &plan.plan_hash, "approve", before))?;
        let approved = safe(engine.endpoint_rollout(&positive))?;
        ensure(approved.state == "scheduled" && approved.members[0].deployment_id.is_none())?;
        safe(engine.review_endpoint_rollout(&positive, &plan.plan_hash, "cancel", before))?;

        // Both negative cases exercise this same immutable, initially valid plan.
        let negative =
            safe(engine.propose_component_rollout(request, &release, &public, component, before))?;
        let plan = safe(engine.endpoint_rollout(&negative))?;
        ensure(plan.plan.gates[0].windows_network_events)?;
        let collector = heartbeat.collector.as_mut().ok_or("rollout")?;
        collector.last_attempt_ms = after;
        collector.last_success_ms = after;
        let other = WindowsProcessEventHealth {
            stream_id: protocol::hash(b"synthetic-unrelated-process-source"),
            state: "active".into(),
            started_ms: after,
            checked_ms: after,
            subscriptions: 1,
            ..Default::default()
        };
        ensure(other.healthy(after))?;
        collector.windows_process_events = Some(other);
        for network in [Some(degraded.clone()), None] {
            heartbeat
                .collector
                .as_mut()
                .ok_or("rollout")?
                .windows_network_events = network;
            safe(engine.endpoint_heartbeat(&id, &heartbeat, after))?;
            let refused =
                engine.review_endpoint_rollout(&negative, &plan.plan_hash, "approve", after);
            ensure(refused.is_err_and(|error| {
                error.to_string()
                    == "Rollout target has stale or degraded protection/collection health"
            }))?;
            let unchanged = safe(engine.endpoint_rollout(&negative))?;
            ensure(
                unchanged.state == "pending"
                    && unchanged.plan_hash == plan.plan_hash
                    && unchanged.plan.gates[0].windows_network_events
                    && unchanged.members[0].deployment_id.is_none(),
            )?;
        }
        safe(engine.review_endpoint_rollout(&negative, &plan.plan_hash, "cancel", after))?;
    }
    Ok(())
}
