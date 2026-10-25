//! One locally authorized engine request. The controller owns activation,
//! cleanup and recovery; staging alone never authorizes a service interruption.
use super::*;
use protocol::engine_fleet::{Deployment, Receipt};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Queued,
    Applying,
    Installed,
    RolledBack,
    Refused,
    Cancelled,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub release_id: String,
    pub deadline_ms: u64,
    pub phase: Phase,
    pub detail: String,
    pub updated_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<Deployment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,
    #[serde(default)]
    pub acknowledged: bool,
}
impl Request {
    pub(super) fn validate(&self) -> Result<()> {
        if !protocol::hex_id(&self.release_id)
            || self.deadline_ms == 0
            || self.deadline_ms > i64::MAX as u64
            || self.detail.len() > 2048
        {
            return Err("Invalid automatic engine request".into());
        }
        if let Some(deployment) = &self.deployment {
            deployment.validate(&deployment.endpoint_id, deployment.created_ms)?;
            if !deployment.install
                || deployment.release.id()? != self.release_id
                || deployment.expires_ms != self.deadline_ms
                || (!self.pending() && self.receipt.is_none())
            {
                return Err("Engine request differs from its reviewed deployment".into());
            }
        }
        if let Some(receipt) = &self.receipt {
            receipt.validate()?;
            if self
                .deployment
                .as_ref()
                .is_none_or(|d| d.id != receipt.deployment_id)
                || receipt.release_id != self.release_id
                || Some(receipt.outcome.as_str()) != self.phase.outcome()
                || receipt.finished_ms != self.updated_ms
            {
                return Err("Engine receipt differs from its terminal deployment".into());
            }
        } else if self.acknowledged {
            return Err("Engine receipt acknowledgement has no receipt".into());
        }
        Ok(())
    }
    fn pending(&self) -> bool {
        matches!(self.phase, Phase::Queued | Phase::Applying)
    }
    fn retained(&self) -> bool {
        self.pending() || (self.receipt.is_some() && !self.acknowledged)
    }
    fn finish(&mut self, phase: Phase, detail: &str) -> Result<()> {
        let outcome = phase.outcome().ok_or("Engine result must be terminal")?;
        if self.receipt.is_some() {
            return Err("Engine installation receipts are immutable".into());
        }
        self.phase = phase;
        self.detail = detail.chars().take(512).collect();
        self.updated_ms = now_ms();
        if let Some(deployment) = &self.deployment {
            self.receipt = Some(Receipt {
                deployment_id: deployment.id.clone(),
                release_id: self.release_id.clone(),
                outcome: outcome.into(),
                detail: detail.chars().take(120).collect(),
                finished_ms: self.updated_ms,
            });
        }
        self.validate()
    }
}
impl Phase {
    fn outcome(self) -> Option<&'static str> {
        match self {
            Self::Installed => Some("installed"),
            Self::RolledBack => Some("rolled_back"),
            Self::Refused | Self::Cancelled => Some("refused"),
            _ => None,
        }
    }
}
pub(super) fn require_idle(record: &Status) -> Result<()> {
    if record.maintenance.as_ref().is_some_and(Request::retained) {
        return Err("Cancel or recover pending engine maintenance and deliver its receipt before other engine maintenance".into());
    }
    Ok(())
}
/// The exact staged release and a bounded deadline are local installation
/// authorization. Identical retries do not renew or broaden that authorization.
pub fn request(state: &Path, release_id: &str, deadline_ms: u64) -> Result<()> {
    request_inner(state, release_id, deadline_ms, None)
}
pub(crate) fn request_fleet(state: &Path, deployment: &Deployment) -> Result<()> {
    request_inner(
        state,
        &deployment.release.id()?,
        deployment.expires_ms,
        Some(deployment),
    )
}
fn request_inner(
    state: &Path,
    release_id: &str,
    deadline_ms: u64,
    deployment: Option<&Deployment>,
) -> Result<()> {
    let state = state.canonicalize()?;
    let (config, _) = configuration(&state)?;
    let _lock = update::maintenance_lock(&state)?;
    update::require_component_transactions_settled(&state)?;
    let mut record = status(&state)?;
    if let Some(existing) = &record.maintenance {
        if deployment.is_some() && existing.deployment.as_ref() == deployment {
            return Ok(());
        }
        if existing.retained() {
            if existing.phase == Phase::Queued
                && existing.release_id == release_id
                && existing.deadline_ms == deadline_ms
                && existing.deployment.as_ref() == deployment
            {
                return Ok(());
            }
            return Err("An engine request is already pending".into());
        }
    }
    if record.transaction.is_some() || record.phase != "staged" {
        return Err(
            "Automatic engine maintenance requires completed staging and no pending activation"
                .into(),
        );
    }
    let release = record.staged.as_ref().ok_or("No staged engine release")?;
    let now = now_ms();
    if let Some(deployment) = deployment {
        deployment.validate(&config.endpoint_id, now)?;
        if !config.engine_updates.managed || !deployment.install || &deployment.release != release {
            return Err("Fleet engine request requires its exact staged release and local managed permission".into());
        }
    }
    if !config.engine_updates.automatic
        || release.id()? != release_id
        || deadline_ms <= now
        || deadline_ms > now.saturating_add(900_000)
        || deadline_ms > release.release.expires_ms
    {
        return Err("Engine request requires local automatic policy, the exact staged release and a deadline within 15 minutes and release validity".into());
    }
    release.admit(
        &config.engine_updates.public_key,
        &protocol::update::target(),
        &config.engine_updates.channel,
        config.engine_updates.minimum_sequence,
        now,
    )?;
    record.maintenance = Some(Request {
        release_id: release_id.into(),
        deadline_ms,
        phase: Phase::Queued,
        detail: String::new(),
        updated_ms: now,
        deployment: deployment.cloned(),
        receipt: None,
        acknowledged: false,
    });
    save(&state, &mut record)
}
pub fn cancel(state: &Path, release_id: &str) -> Result<()> {
    let state = state.canonicalize()?;
    configuration(&state)?;
    let _lock = update::maintenance_lock(&state)?;
    let mut record = status(&state)?;
    let request = record.maintenance.as_mut().ok_or("No engine request")?;
    if request.release_id != release_id {
        return Err("Engine cancellation must identify the exact requested release".into());
    }
    if request.phase == Phase::Cancelled {
        return Ok(());
    }
    if request.phase != Phase::Queued || record.transaction.is_some() {
        return Err("Engine activation already began or ended; cancellation cannot undo it".into());
    }
    request.finish(
        Phase::Cancelled,
        "Local engine request cancelled before activation",
    )?;
    save(&state, &mut record)
}
pub fn queued(state: &Path) -> Result<bool> {
    Ok(status(state)?
        .maintenance
        .is_some_and(|r| r.phase == Phase::Queued))
}
/// Refuse revoked/expired requests before interrupting running protection. The
/// same admission is repeated under the activation lock after children stop.
pub(crate) fn eligible(state: &Path) -> Result<bool> {
    let Some(_lock) = update::try_maintenance_lock(state)? else {
        return Ok(false);
    };
    let mut record = status(state)?;
    if !record
        .maintenance
        .as_ref()
        .is_some_and(|r| r.phase == Phase::Queued)
    {
        return Ok(false);
    }
    let allowed = (|| -> Result<()> {
        let (config, _) = configuration(state)?;
        let release = record
            .staged
            .as_ref()
            .ok_or("Queued engine release is missing")?;
        admit(&config, &record, release)?;
        authorize(&config, record.maintenance.as_ref().unwrap())
    })();
    if let Err(error) = allowed {
        let request = record.maintenance.as_mut().unwrap();
        request.finish(Phase::Refused, &error.to_string())?;
        save(state, &mut record)?;
        return Ok(false);
    }
    Ok(true)
}
pub(super) fn admit(config: &Config, record: &Status, release: &SignedRelease) -> Result<()> {
    let request = record
        .maintenance
        .as_ref()
        .ok_or("No automatic engine request")?;
    request.validate()?;
    if let Some(deployment) = &request.deployment {
        deployment.validate(&config.endpoint_id, now_ms())?;
        if !config.engine_updates.managed || &deployment.release != release {
            return Err("Fleet engine policy or reviewed deployment changed".into());
        }
    }
    if !config.engine_updates.automatic
        || request.phase != Phase::Queued
        || now_ms() >= request.deadline_ms
        || request.release_id != release.id()?
        || record.phase != "staged"
        || record.transaction.is_some()
        || record.highwater != release.release.sequence
    {
        return Err("Automatic engine policy or request authorization changed or expired".into());
    }
    release.admit(
        &config.engine_updates.public_key,
        &protocol::update::target(),
        &config.engine_updates.channel,
        config
            .engine_updates
            .minimum_sequence
            .max(record.installed.as_ref().map_or(0, |r| r.release.sequence)),
        now_ms(),
    )?;
    Ok(())
}
pub(super) fn authorize(config: &Config, request: &Request) -> Result<()> {
    if let Some(deployment) = &request.deployment {
        crate::Client::new(config.clone())?.authorize_engine_installation(deployment)?;
    }
    Ok(())
}
pub(super) fn finished(record: &mut Status, phase: Phase, detail: &str) -> Result<()> {
    if let Some(request) = &mut record.maintenance {
        if request.phase == Phase::Applying {
            request.finish(phase, detail)?;
        }
    }
    Ok(())
}
/// Called only after the owning controller stopped all managed children. Errors
/// with an unfinished transaction stop the controller; they never start children
/// against an uncertain configuration.
pub(crate) fn maintain(state: &Path, token: &str) -> Result<()> {
    if !crate::supervisor::controller_owned(state, token) {
        return Err("Automatic engine request has no owning controller".into());
    }
    let Some(request) = status(state)?.maintenance else {
        return Ok(());
    };
    if request.phase != Phase::Queued {
        return Ok(());
    }
    if let Err(error) = apply_inner(state, Some(token)) {
        let _lock = update::maintenance_lock(state)?;
        let mut record = status(state)?;
        if record.transaction.is_some() {
            return Err(error);
        }
        if let Some(current) = &mut record.maintenance {
            if current.phase == Phase::Queued && current.release_id == request.release_id {
                current.finish(Phase::Refused, &error.to_string())?;
                save(state, &mut record)?;
            }
        }
        eprintln!("Automatic engine activation did not install: {error}");
    }
    require_start_allowed(state)
}

impl crate::Client {
    /// A terminal result survives server loss and local policy revocation.
    /// Commit the remote receipt and delivery journal before releasing its owner.
    pub(crate) fn engine_installation_receipts(&self, state: &Path) -> Result<()> {
        let Some(request) = status(state)?.maintenance else {
            return Ok(());
        };
        let Some(receipt) = &request.receipt else {
            return Ok(());
        };
        if request.acknowledged {
            return Ok(());
        }
        if self.post("engines/receipt", receipt)?["committed"] != true {
            return Err("Server did not commit the engine installation receipt".into());
        }
        let _lock = update::maintenance_lock(state)?;
        let mut record = status(state)?;
        let current = record
            .maintenance
            .as_mut()
            .ok_or("Engine request disappeared")?;
        if current.receipt.as_ref() != Some(receipt) || current.deployment != request.deployment {
            return Err("Engine receipt changed while being acknowledged".into());
        }
        crate::managed_engine::finish_delivery(
            state,
            current.deployment.as_ref().unwrap(),
            receipt,
        )?;
        current.acknowledged = true;
        save(state, &mut record)
    }
}
/// Recovery remains authorized after request expiry: it restores the previously
/// confirmed configuration and never retries installation. Concurrent policy
/// edits and manual interrupted transactions still require operator review.
pub(crate) fn reconcile(state: &Path, token: &str) -> Result<()> {
    if !crate::supervisor::controller_owned(state, token) {
        return Err("Automatic engine recovery has no owning controller".into());
    }
    let record = status(state)?;
    if let Some(transaction) = &record.transaction {
        if !record.maintenance.as_ref().is_some_and(|r| {
            r.phase == Phase::Applying
                && transaction.release.id().ok().as_deref() == Some(&r.release_id)
        }) {
            return Err(
                "Recover the manually interrupted engine activation before starting the controller"
                    .into(),
            );
        }
        recover_inner(state, Some(token))?;
    } else if record
        .maintenance
        .as_ref()
        .is_some_and(|r| r.phase == Phase::Applying)
    {
        return Err(
            "Automatic engine journal has no matching activation; retained for review".into(),
        );
    }
    require_start_allowed(state)
}
