//! Code, OS registration and live status are independent proofs. This module
//! never enables a filter, requests a replacement, or pulls/acknowledges data.
#[cfg(target_os = "macos")]
use super::journal::{Inspection, Record};
#[cfg(target_os = "macos")]
use crate::macos_network_bundle::{self as bundle, Deployment};
use crate::Result;
#[cfg(target_os = "macos")]
use athernex_macos_network::upgrade::FilterState;
use athernex_macos_network::upgrade::{ExtensionProperty, UpgradeCodePin};
#[cfg(target_os = "macos")]
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Original,
    Candidate,
}

fn select_registered(
    properties: &[ExtensionProperty],
    identifier: &str,
    pin: &UpgradeCodePin,
    target: Target,
) -> Result<ExtensionProperty> {
    // Apple may expose a retiring predecessor alongside a candidate. No public
    // ordering guarantee permits treating that ambiguity as completed cleanup.
    let [property] = properties else {
        return Err("Network extension registration is absent or ambiguous".into());
    };
    property.validate()?;
    pin.validate()?;
    if property.bundle_identifier != identifier
        || property.bundle_version != pin.bundle_version
        || property.bundle_short_version != pin.short_version
        || property.is_awaiting_user_approval
        || property.is_uninstalling
        || (target == Target::Candidate && !property.is_enabled)
    {
        return Err("Network extension registration differs from the approved transition".into());
    }
    Ok(property.clone())
}

#[cfg(target_os = "macos")]
pub fn verify_app(path: &Path, deployment: &Deployment) -> Result<()> {
    deployment.validate()?;
    if deployment.target != athernex_endpoint_protocol::update::target() {
        return Err("Network upgrade platform differs".into());
    }
    let tree = bundle::read_tree(path, &deployment.artifact, true)?;
    bundle::verify_tree(&tree, &deployment.artifact, &deployment.target)?;
    bundle::verify_native(path, &deployment.artifact)
}

#[cfg(target_os = "macos")]
pub fn verify_property(
    record: &Record,
    target: Target,
    properties: &[ExtensionProperty],
    filter: &FilterState,
) -> Result<Inspection> {
    record.validate()?;
    if *filter == FilterState::Foreign {
        return Err("A foreign network filter configuration is present".into());
    }
    if let Some(attempt) = &record.attempt {
        if &attempt.inspection.filter != filter {
            return Err("Network filter state changed during the upgrade".into());
        }
    } else if target == Target::Candidate {
        return Err("Candidate inspection has no durable upgrade attempt".into());
    }
    let pin = match target {
        Target::Original => &record.plan.old,
        Target::Candidate => &record.plan.new,
    };
    let property = select_registered(
        properties,
        &record.plan.identity.provider_identifier,
        pin,
        target,
    )?;
    athernex_macos_network::upgrade::inspect_upgrade_property(
        &property,
        &record.plan.identity,
        pin,
    )?;
    Ok(Inspection {
        property,
        filter: filter.clone(),
    })
}

/// The facade calls this for an enabled filter when finalizing a candidate or
/// proving an original after a failed request. Retain the full returned health:
/// fresh authenticated activity is not zero-loss/readiness. Historical losses
/// during the offline interval must not prevent draining or be reset to finish.
#[cfg(target_os = "macos")]
pub fn verify_running_source(deployment: &Deployment) -> Result<athernex_macos_network::Status> {
    deployment.validate()?;
    let client = athernex_macos_network::Client::connect(&deployment.client_config())?;
    let initial = client.status().clone();
    // Always detach, including degraded samples. No pull or ACK is performed.
    let final_status = client.close()?;
    for status in [&initial, &final_status] {
        validate_activity(
            status,
            &deployment.artifact.source_policy_sha256,
            crate::now_ms(),
        )?;
    }
    Ok(final_status)
}

fn validate_activity(
    status: &athernex_macos_network::Status,
    policy: &str,
    now: u64,
) -> Result<()> {
    let h = &status.health;
    h.validate()?;
    if h.source_policy_sha256 != policy
        || !matches!(h.state.as_str(), "active" | "degraded")
        || h.error == "Network source configuration failed"
        || h.checked_ms < h.started_ms
        || h.checked_ms > now.saturating_add(1000)
        || now.saturating_sub(h.checked_ms) > 30_000
    {
        return Err("Network source did not prove fresh authenticated activity".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn current_boot() -> Result<String> {
    athernex_endpoint_native::service::boot_identity()
}

#[cfg(target_os = "macos")]
pub fn require_applications_parent() -> Result<()> {
    use std::{
        fs::OpenOptions,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
    };
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let m = root.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7022 != 0 {
        return Err("Applications ancestry is not protected".into());
    }
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c"Applications".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("Applications directory is unavailable".into());
    }
    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    let m = directory.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7002 != 0 {
        return Err("Applications directory is not protected".into());
    }
    if m.mode() & 0o020 != 0 {
        // Exactly the existing administrator group, not any writable group.
        // A missing/over-bound directory-service result refuses this exception.
        let mut buffer = [0u8; 16384];
        let mut group = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut found = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                c"admin".as_ptr(),
                group.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if rc != 0 || found.is_null() {
            return Err("Applications administrator group could not be verified".into());
        }
        if m.gid() != unsafe { (*found).gr_gid } {
            return Err("Applications writable group is not the administrator group".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (ExtensionProperty, UpgradeCodePin) {
        (
            ExtensionProperty {
                url: "/Library/SystemExtensions/fixed/com.example.provider.systemextension".into(),
                bundle_identifier: "com.example.provider".into(),
                bundle_version: "2.0.0".into(),
                bundle_short_version: "0.1.0".into(),
                is_enabled: true,
                is_awaiting_user_approval: false,
                is_uninstalling: false,
            },
            UpgradeCodePin {
                executable_sha256: "a".repeat(64),
                cdhashes: vec!["b".repeat(40)],
                info_plist_sha256: "c".repeat(64),
                bundle_version: "2.0.0".into(),
                short_version: "0.1.0".into(),
            },
        )
    }
    #[test]
    fn registration_selection_refuses_ambiguity_pending_and_wrong_build() {
        let (p, pin) = fixture();
        let id = &p.bundle_identifier;
        assert_eq!(
            select_registered(std::slice::from_ref(&p), id, &pin, Target::Candidate).unwrap(),
            p
        );
        assert!(select_registered(&[], id, &pin, Target::Candidate).is_err());
        assert!(select_registered(&[p.clone(), p.clone()], id, &pin, Target::Candidate).is_err());
        for case in 0..4 {
            let mut q = p.clone();
            match case {
                0 => q.is_awaiting_user_approval = true,
                1 => q.is_uninstalling = true,
                2 => q.bundle_version = "3.0.0".into(),
                _ => q.bundle_identifier = "com.example.other".into(),
            };
            assert!(select_registered(&[q], id, &pin, Target::Candidate).is_err());
        }
        let mut inactive = p.clone();
        inactive.is_enabled = false;
        assert!(
            select_registered(std::slice::from_ref(&inactive), id, &pin, Target::Candidate)
                .is_err()
        );
        assert!(select_registered(&[inactive], id, &pin, Target::Original).is_ok());
    }
    #[test]
    fn fresh_authenticated_activity_preserves_loss_without_promoting_readiness() {
        let policy = athernex_endpoint_protocol::macos_network_events::source_policy_sha256();
        let health = athernex_endpoint_protocol::macos_network_events::MacosNetworkEventHealth {
            stream_id: "a".repeat(64),
            state: "degraded".into(),
            source_policy_sha256: policy.clone(),
            started_ms: 1,
            checked_ms: 1000,
            received_records: 10,
            queue_drops: 2,
            transport_errors: 1,
            pending_records: 3,
            pending_bytes: 300,
            error: "Network source queue lost records".into(),
            ..Default::default()
        };
        let status = athernex_macos_network::Status {
            health,
            last_acked_batch_id: 7,
        };
        let original = status.clone();
        validate_activity(&status, &policy, 1000).unwrap();
        assert_eq!(status, original);
        assert!(!status.health.healthy(1000));
        for state in ["starting", "stopped"] {
            let mut bad = status.clone();
            bad.health.state = state.into();
            assert!(validate_activity(&bad, &policy, 1000).is_err());
        }
        let mut bad = status.clone();
        bad.health.error = "Network source configuration failed".into();
        assert!(validate_activity(&bad, &policy, 1000).is_err());
        assert!(validate_activity(&status, &policy, 31_001).is_err());
        assert!(validate_activity(&status, &"b".repeat(64), 1000).is_err());
    }
}
