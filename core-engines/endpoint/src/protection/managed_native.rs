//! Endpoint/controller integration for the separately signed macOS adapter.
//! Linux exposes this only through an explicit lifecycle fixture command.
use super::{ProtectionConfig, ProtectionHealth};
use crate::{private_write, update, Config, Result};
use athernex_endpoint_native::{child, service, Policy};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

pub fn plan(policy: &ProtectionConfig, state: &Path) -> Result<service::Plan> {
    policy.validate_platform("macos")?;
    if !policy.enabled {
        return Err("Native protection is disabled".into());
    }
    let monitor = policy
        .monitor
        .as_ref()
        .ok_or("Missing authorization adapter")?;
    for root in &policy.roots {
        for excluded in [state, monitor.as_path()] {
            if root.starts_with(excluded) || excluded.starts_with(root) {
                return Err("Native protection scope overlaps endpoint runtime".into());
            }
        }
    }
    let plan = service::Plan {
        schema: 1,
        policy: Policy {
            roots: policy.roots.clone(),
            socket: policy
                .runtime
                .as_ref()
                .ok_or("Missing scanner runtime")?
                .join("clamd.sock"),
            state: state.join("protection/native"),
            scanner_uid: policy.engine_uid.ok_or("Missing scanner UID")?,
            scan_timeout_ms: 1000,
        },
        daemon: policy.daemon.clone().ok_or("Missing scanner daemon")?,
        engine_libraries: Vec::new(),
        engine_certificates: None,
        database: policy
            .database
            .clone()
            .ok_or("Missing signature database")?,
        scanner_gid: policy.engine_gid.ok_or("Missing scanner GID")?,
        startup_secs: 120,
    };
    plan.validate()?;
    Ok(plan)
}
pub fn configured_plan(policy: &ProtectionConfig, state: &Path) -> Result<service::Plan> {
    let config: Config =
        serde_json::from_slice(&update::read_bounded(&state.join("config.json"), 65536)?)?;
    config.engine_updates.validate()?;
    let mut plan = plan(policy, state)?;
    plan.engine_libraries = config.engine_updates.active_libraries;
    plan.engine_certificates = config.engine_updates.active_certificates;
    plan.validate()?;
    Ok(plan)
}

fn private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o077 != 0 || path.canonicalize()? != path {
        return Err(
            "Native endpoint state must be a canonical private root-owned directory".into(),
        );
    }
    Ok(())
}

pub fn supervise(state: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Native protection requires root".into());
    }
    update::check_destination(&state.join("config.json"))?;
    let state = state.canonicalize()?;
    private_directory(&state)?;
    let config: Config =
        serde_json::from_slice(&update::read_bounded(&state.join("config.json"), 65536)?)?;
    config.validate()?;
    let plan = configured_plan(&config.protection, &state)?;
    let monitor = config
        .protection
        .monitor
        .as_ref()
        .ok_or("Missing authorization adapter")?;
    update::check_destination(monitor)?;
    if monitor.canonicalize()? != *monitor {
        return Err("Authorization adapter path must be canonical".into());
    }
    let directory = state.join("protection");
    private_directory(&directory)?;
    private_directory(&plan.policy.state)?;
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join("supervisor.lock"))?;
    let m = lease.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.nlink() != 1 || m.len() != 0 {
        return Err("Invalid endpoint protection lock".into());
    }
    lease
        .try_lock()
        .map_err(|_| "Endpoint protection is already supervised")?;
    update::require_recovered(&state)?;
    let path = plan.policy.state.join("service-plan.json");
    private_write(&path, &serde_json::to_vec(&plan)?)?;
    service::read_plan(&path)?;
    #[cfg(target_os = "macos")]
    let mode = "supervise-owned";
    #[cfg(target_os = "linux")]
    let mode = "supervise-owned-fixture";
    let mut service = child::Service::start(
        Command::new(monitor)
            .arg(mode)
            .arg(std::process::id().to_string())
            .arg(path),
        8192,
    )?;
    loop {
        if let Some(code) = service.poll()? {
            return Err(format!(
                "Native supervisor exited ({code}): {}",
                String::from_utf8_lossy(service.output())
                    .chars()
                    .take(2048)
                    .collect::<String>()
            )
            .into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn has_plan(state: &Path) -> Result<bool> {
    match fs::symlink_metadata(state.join("protection/native/service-plan.json")) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
pub fn quiescent(policy: &ProtectionConfig, state: &Path) -> Result<service::Quiescent> {
    // A local policy edit does not establish that the previous service stopped.
    // Use the last prepared plan to retain its state and engine ownership locks.
    let plan = if has_plan(state)? {
        service::read_plan(&state.join("protection/native/service-plan.json"))?
    } else {
        configured_plan(policy, state)?
    };
    if plan.policy.state != state.join("protection/native") {
        return Err("Native service plan belongs to another endpoint".into());
    }
    service::quiescent(&plan)
}

pub fn health(policy: &ProtectionConfig, state: &Path) -> ProtectionHealth {
    let mut health = ProtectionHealth {
        state: "degraded".into(),
        backend: "macos-endpoint-security".into(),
        roots: policy
            .roots
            .iter()
            .map(|p| p.to_string_lossy().into())
            .collect(),
        excluded_uid: policy.engine_uid,
        ..Default::default()
    };
    let observed = (|| -> Result<service::Observation> {
        service::observe(&configured_plan(policy, &state.canonicalize()?)?)
    })();
    match observed {
        Ok(status) => {
            health.checked_ms = status.checked_ms;
            if status.phase == "starting" {
                health.state = "starting".into();
            }
            if status.runtime_protection_verified {
                health.state = "active".into();
                health.checked_ms = status.verification.as_ref().map_or(0, |v| v.checked_ms);
            }
            health.error = status.error.chars().take(120).collect();
        }
        Err(e) => {
            health.error = e.to_string().chars().take(120).collect();
        }
    }
    coverage_health(&mut health, policy, state);
    health
}

fn coverage_health(health: &mut ProtectionHealth, policy: &ProtectionConfig, state: &Path) {
    let coverage = (|| -> Result<_> {
        let plan = plan(policy, &state.canonicalize()?)?;
        let coverage = athernex_endpoint_native::coverage::load(&plan.policy.state)?;
        // Preserve durable loss totals even during startup or stale-heartbeat
        // failure. They describe history, not current process liveness.
        health.dropped_events = coverage.evidence.totals.evidence_dropped;
        coverage.check_live(&plan.policy, coverage.evidence.pid, crate::now_ms())?;
        Ok(coverage)
    })();
    let error = match coverage {
        Ok(coverage) => {
            let e = &coverage.evidence;
            health.dropped_events = e.totals.evidence_dropped;
            if !e.incomplete() {
                return;
            }
            format!("Native evidence coverage incomplete: {} restart intervals, {} event gaps, {} dropped receipts, {} response errors, {} scope losses{}",
                e.unobserved_intervals, e.totals.event_gaps, e.totals.evidence_dropped, e.totals.response_errors,
                e.scope_losses,
                if e.legacy_history_unknown { "; legacy history unknown" } else { "" })
        }
        Err(error) => format!("Native evidence coverage unavailable: {error}"),
    };
    if health.state == "active" {
        health.state = "degraded".into();
    }
    let mut error = if health.error.is_empty() {
        error
    } else {
        format!("{}; {error}", health.error)
    };
    let mut limit = error.len().min(512);
    while !error.is_char_boundary(limit) {
        limit -= 1;
    }
    error.truncate(limit);
    health.error = error;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> ProtectionConfig {
        ProtectionConfig {
            enabled: true,
            roots: vec!["/watched".into()],
            daemon: Some("/engine/bin/clamd".into()),
            monitor: Some("/installed/adapter".into()),
            database: Some("/engine/db".into()),
            runtime: Some("/engine/runtime".into()),
            engine_uid: Some(1234),
            engine_gid: Some(1234),
        }
    }
    #[test]
    fn policy_selects_supported_platforms_and_excludes_management_files() {
        let p = policy();
        p.validate_platform("macos").unwrap();
        p.validate_platform("linux").unwrap();
        assert!(p.validate_platform("windows").is_err());
        let state = Path::new("/endpoint");
        assert_eq!(
            plan(&p, state).unwrap().policy.state,
            Path::new("/endpoint/protection/native")
        );
        for root in ["/endpoint", "/endpoint/quarantine", "/installed", "/engine"] {
            let mut p = p.clone();
            p.roots = vec![root.into()];
            assert!(plan(&p, state).is_err(), "{root}");
        }
    }
    #[test]
    fn absent_native_status_cannot_report_active_protection() {
        let temp = tempfile::tempdir().unwrap();
        let h = health(&policy(), temp.path());
        assert_eq!(h.state, "degraded");
        assert_eq!(h.backend, "macos-endpoint-security");
        assert!(!h.error.is_empty());
        h.validate().unwrap();
    }

    #[test]
    fn historical_loss_stays_visible_during_restart_and_stale_heartbeat() {
        use athernex_endpoint_native::coverage::{Loss, Snapshot, FILE};
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().canonicalize().unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let policy = policy();
        let plan = plan(&policy, &state).unwrap();
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&plan.policy.state)
            .unwrap();
        let now = crate::now_ms();
        let initial = Snapshot::begin(None, &plan.policy, 42, 7, false, now - 10_000).unwrap();
        let lost = initial
            .observe(
                Loss {
                    evidence_dropped: 4,
                    event_gaps: 3,
                    response_errors: 2,
                },
                true,
                true,
                now - 9_000,
            )
            .unwrap();
        for snapshot in [
            lost.clone(),
            Snapshot::begin(Some(&lost), &plan.policy, 43, 8, false, now).unwrap(),
        ] {
            private_write(
                &plan.policy.state.join(FILE),
                &serde_json::to_vec(&snapshot).unwrap(),
            )
            .unwrap();
            let mut h = ProtectionHealth {
                state: "active".into(),
                backend: "macos-endpoint-security".into(),
                ..Default::default()
            };
            coverage_health(&mut h, &policy, &state);
            assert_eq!(h.state, "degraded");
            assert_eq!(h.dropped_events, 4, "{}", h.error);
            assert!(h.error.contains("coverage unavailable"));
            h.validate().unwrap();
        }
        let restarted = Snapshot::begin(Some(&lost), &plan.policy, 43, 8, false, now)
            .unwrap()
            .observe(Loss::default(), true, true, now)
            .unwrap();
        private_write(
            &plan.policy.state.join(FILE),
            &serde_json::to_vec(&restarted).unwrap(),
        )
        .unwrap();
        let mut h = ProtectionHealth {
            state: "active".into(),
            backend: "macos-endpoint-security".into(),
            ..Default::default()
        };
        coverage_health(&mut h, &policy, &state);
        assert_eq!(h.state, "degraded");
        assert_eq!(h.dropped_events, 4);
        assert!(h.error.contains("1 restart intervals"));
        assert!(h.error.contains("3 event gaps"));
        h.validate().unwrap();
    }
}
