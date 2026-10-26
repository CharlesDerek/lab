//! Pure durable state for one approved replacement. These transitions do not
//! inspect native code, authenticate a peer, prove retirement, or write files.
//! The caller verifies those facts and durably saves the returned record before
//! sending a permit/acknowledgement or proceeding to the next filesystem phase.
use crate::{macos_network_bundle::Deployment, Result};
use athernex_endpoint_protocol as protocol;
use athernex_macos_network::{
    upgrade::{ExtensionProperty, FilterState, UpgradeMode, UpgradeOutcome, UpgradePlan},
    BundleIdentity,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(test)]
mod tests;

pub const MAX_RECORD_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    CandidatePlaced,
    MayBePending,
    OsCompleted,
    RebootRequired,
    OsFailed,
    Unexpected,
    Uncertain,
    ConfigCommitted,
    Complete,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerBinding {
    pub instance_nonce: String,
    pub connection_generation: u64,
    pub operator_uid: u32,
}
impl OwnerBinding {
    pub fn validate(&self) -> Result<()> {
        if !protocol::hex_id(&self.instance_nonce) || self.connection_generation == 0 {
            return Err("Invalid upgrade owner binding".into());
        }
        Ok(())
    }
}

/// The native inspector must authenticate this property and its code pin before
/// it is supplied here. Matching metadata alone is not a static-code proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub property: ExtensionProperty,
    pub filter: FilterState,
}
impl Inspection {
    fn validate(&self) -> Result<()> {
        self.property.validate()?;
        if !canonical_path(&self.property.url)
            || self.property.is_awaiting_user_approval
            || self.property.is_uninstalling
            || self.filter == FilterState::Foreign
        {
            return Err("Invalid upgrade inspection".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub sequence: u64,
    pub outcome: UpgradeOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementDecision {
    pub sequence: u64,
    pub allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub owner: OwnerBinding,
    pub id: String,
    pub nonce: String,
    pub plan_sha256: String,
    pub inspection: Inspection,
    pub last_report: Option<Report>,
    pub replacement: Option<ReplacementDecision>,
    /// Set only when an unresolved owner's connection or lifetime is lost.
    pub owner_lost: bool,
}

/// Retained caller-verified reconciliation, not a fabricated SDK callback.
/// For an enabled filter the caller additionally proves the candidate live
/// channel. Inactive/absent filters remain inactive and claim no live source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    pub boot: String,
    pub candidate: Inspection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: u32,
    pub id: String,
    /// Lexically canonical Mac path; root protection/canonical filesystem
    /// identity and the global transaction lease are verified by the caller.
    pub state_path: PathBuf,
    pub original_boot: String,
    pub operator_uid: u32,
    pub old: Deployment,
    pub candidate: Deployment,
    pub original_config_sha256: String,
    pub candidate_config_sha256: String,
    pub management_sha256: String,
    pub old_container_cdhashes: Vec<String>,
    pub plan: UpgradePlan,
    pub phase: Phase,
    pub attempt: Option<Attempt>,
    pub reconciliation: Option<Reconciliation>,
    /// Only a failed SDK request can be rolled back after a claim, and only
    /// after an independent native inspection proves the original deployment.
    pub rollback: Option<Inspection>,
}

impl Record {
    pub fn validate(&self) -> Result<()> {
        self.old.validate()?;
        self.candidate.validate()?;
        self.plan.validate()?;
        if self.schema != 1
            || !protocol::hex_id(&self.id)
            || !self.state_path.to_str().is_some_and(canonical_path)
            || !boot_id(&self.original_boot)
            || [
                &self.original_config_sha256,
                &self.candidate_config_sha256,
                &self.management_sha256,
            ]
            .iter()
            .any(|value| !protocol::hex_id(value))
            || !cdhashes(&self.old_container_cdhashes)
            || self.plan.mode != UpgradeMode::Submit
            || self.plan.transaction_id != self.id
            || self.plan.identity != identity(&self.old)
            || self.plan.identity != identity(&self.candidate)
            || self.old.target != self.candidate.target
            || self.plan.old.executable_sha256 != self.old.artifact.provider_sha256
            || self.plan.new.executable_sha256 != self.candidate.artifact.provider_sha256
            || self.plan.old.cdhashes != self.old.artifact.provider_cdhashes
            || self.plan.new.cdhashes != self.candidate.artifact.provider_cdhashes
            || self.plan.source_policy_sha256 != self.old.artifact.source_policy_sha256
            || self.plan.source_policy_sha256 != self.candidate.artifact.source_policy_sha256
            || serde_json::to_vec(self)?.len() > MAX_RECORD_BYTES
        {
            return Err("Invalid upgrade journal binding".into());
        }
        let Some(attempt) = &self.attempt else {
            if !matches!(
                self.phase,
                Phase::Prepared | Phase::CandidatePlaced | Phase::Aborted
            ) || self.reconciliation.is_some()
                || self.rollback.is_some()
            {
                return Err("Invalid unclaimed upgrade phase".into());
            }
            return Ok(());
        };
        attempt.owner.validate()?;
        self.old_inspection(&attempt.inspection)?;
        if attempt.owner.operator_uid != self.operator_uid
            || !protocol::hex_id(&attempt.id)
            || !protocol::hex_id(&attempt.nonce)
            || attempt.plan_sha256 != self.plan_sha256()?
        {
            return Err("Invalid upgrade attempt binding".into());
        }
        let observed = observed_phase(attempt)?;
        if let Some(proof) = &self.reconciliation {
            self.check_reconciliation(observed, proof)?;
        }
        match self.phase {
            Phase::ConfigCommitted | Phase::Complete => {
                if self.reconciliation.is_none() || self.rollback.is_some() {
                    return Err("Upgrade commit lacks reconciliation".into());
                }
            }
            Phase::Aborted => {
                let proof = self
                    .rollback
                    .as_ref()
                    .ok_or("Upgrade rollback lacks inspection")?;
                if observed != Phase::OsFailed || self.reconciliation.is_some() {
                    return Err("Uncertain upgrade cannot roll back".into());
                }
                self.check_rollback(attempt, proof)?;
            }
            phase => {
                if phase != observed || self.rollback.is_some() {
                    return Err("Upgrade phase differs from durable report".into());
                }
            }
        }
        Ok(())
    }

    pub fn plan_sha256(&self) -> Result<String> {
        Ok(protocol::hash(&serde_json::to_vec(&self.plan)?))
    }

    /// Call after the candidate exchange is complete and its filesystem state
    /// has been independently checked. This method does not exchange files.
    pub fn candidate_placed(&self) -> Result<Self> {
        self.validate()?;
        if self.phase != Phase::Prepared {
            return Err("Upgrade candidate cannot be placed in this phase".into());
        }
        self.with_phase(Phase::CandidatePlaced)
    }

    /// The returned claim MUST be durably saved before constructing/sending a
    /// permit. A lost permit is not grounds to authorize a second attempt.
    pub fn claim(
        &self,
        current_boot: &str,
        owner: OwnerBinding,
        attempt_id: String,
        attempt_nonce: String,
        plan_sha256: &str,
        inspection: Inspection,
    ) -> Result<Self> {
        self.validate()?;
        owner.validate()?;
        self.old_inspection(&inspection)?;
        if self.phase != Phase::CandidatePlaced
            || self.attempt.is_some()
            || current_boot != self.original_boot
            || owner.operator_uid != self.operator_uid
            || !protocol::hex_id(&attempt_id)
            || !protocol::hex_id(&attempt_nonce)
            || plan_sha256 != self.plan_sha256()?
        {
            return Err("Upgrade claim refused".into());
        }
        let mut next = self.clone();
        next.attempt = Some(Attempt {
            owner,
            id: attempt_id,
            nonce: attempt_nonce,
            plan_sha256: plan_sha256.into(),
            inspection,
            last_report: None,
            replacement: None,
            owner_lost: false,
        });
        next.phase = Phase::MayBePending;
        next.validate()?;
        Ok(next)
    }

    /// Authenticate and durably save before replying Recorded. Only an exact
    /// replay of the last report is idempotent, including after a terminal ACK
    /// was lost. Terminal reports without a replacement callback are retained
    /// as Unexpected, which is not same-boot authorization to commit.
    pub fn report(
        &self,
        owner: &OwnerBinding,
        attempt_id: &str,
        attempt_nonce: &str,
        report: Report,
    ) -> Result<Self> {
        self.validate()?;
        let attempt = self.bound_attempt(owner)?;
        if attempt.id != attempt_id || attempt.nonce != attempt_nonce || report.sequence == 0 {
            return Err("Upgrade report binding differs".into());
        }
        if attempt.last_report.as_ref() == Some(&report) {
            return Ok(self.clone());
        }
        let expected = attempt
            .last_report
            .as_ref()
            .map_or(Some(1), |last| last.sequence.checked_add(1));
        if self.phase != Phase::MayBePending || expected != Some(report.sequence) {
            return Err("Upgrade report sequence or phase differs".into());
        }
        let mut next = self.clone();
        let attempt = next.attempt.as_mut().ok_or("Upgrade attempt absent")?;
        if matches!(
            report.outcome,
            UpgradeOutcome::ReplacementAllowed | UpgradeOutcome::ReplacementRefused
        ) {
            if attempt.replacement.is_some() {
                return Err("Upgrade replacement decision already recorded".into());
            }
            attempt.replacement = Some(ReplacementDecision {
                sequence: report.sequence,
                allowed: report.outcome == UpgradeOutcome::ReplacementAllowed,
            });
        }
        attempt.last_report = Some(report);
        next.phase = observed_phase(attempt)?;
        next.validate()?;
        Ok(next)
    }

    /// Disconnect, owner exit, or timeout cannot turn an unresolved attempt
    /// back into a fresh claim. A durable terminal result survives owner loss.
    pub fn owner_lost(&self, owner: &OwnerBinding) -> Result<Self> {
        self.validate()?;
        self.bound_attempt(owner)?;
        if self.phase != Phase::MayBePending {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.attempt
            .as_mut()
            .ok_or("Upgrade attempt absent")?
            .owner_lost = true;
        next.phase = Phase::Uncertain;
        next.validate()?;
        Ok(next)
    }

    /// Preclaim rollback still requires the caller's verified filesystem
    /// restoration. There is no analogous generic postclaim rollback method.
    pub fn abort_before_claim(&self) -> Result<Self> {
        self.validate()?;
        if self.attempt.is_some() || !matches!(self.phase, Phase::Prepared | Phase::CandidatePlaced)
        {
            return Err("Claimed upgrade cannot use preclaim rollback".into());
        }
        self.with_phase(Phase::Aborted)
    }

    /// Only call after proving that the SDK-terminal failure left the exact
    /// original code/filter registration and safely restoring the old files.
    pub fn abort_failed(&self, inspection: Inspection) -> Result<Self> {
        self.validate()?;
        if self.phase != Phase::OsFailed {
            return Err("Upgrade rollback requires terminal failure".into());
        }
        self.check_rollback(
            self.attempt.as_ref().ok_or("Upgrade attempt absent")?,
            &inspection,
        )?;
        let mut next = self.clone();
        next.rollback = Some(inspection);
        next.phase = Phase::Aborted;
        next.validate()?;
        Ok(next)
    }

    /// Eligibility only: no peer presence or matching path establishes old
    /// provider retirement. The caller supplies independent native proof.
    pub fn can_reconcile(&self, current_boot: &str) -> Result<()> {
        self.validate()?;
        if !matches!(
            self.phase,
            Phase::OsCompleted
                | Phase::RebootRequired
                | Phase::Unexpected
                | Phase::Uncertain
                | Phase::ConfigCommitted
        ) {
            return Err("Upgrade phase cannot reconcile".into());
        }
        let observed = observed_phase(self.attempt.as_ref().ok_or("Upgrade attempt absent")?)?;
        reconciliation_boot(observed, &self.original_boot, current_boot)
    }

    /// Durably retain this proof before config commit. Reconciliation does not
    /// alter the recorded callback or erase the history of an uncertain attempt.
    pub fn reconcile_candidate(&self, current_boot: &str, candidate: Inspection) -> Result<Self> {
        self.can_reconcile(current_boot)?;
        let mut next = self.clone();
        next.reconciliation = Some(Reconciliation {
            boot: current_boot.into(),
            candidate,
        });
        next.validate()?;
        Ok(next)
    }

    /// Call after committing the exact candidate config under the filesystem
    /// lease. A proof from an earlier boot cannot authorize this transition.
    pub fn config_committed(&self, current_boot: &str) -> Result<Self> {
        self.can_reconcile(current_boot)?;
        self.current_proof(current_boot)?;
        self.with_phase(Phase::ConfigCommitted)
    }

    /// The caller has checked its final durable config/files and retained the
    /// original evidence/history. This model never claims live collection.
    pub fn complete(&self, current_boot: &str) -> Result<Self> {
        self.validate()?;
        if !matches!(self.phase, Phase::ConfigCommitted | Phase::Complete) {
            return Err("Upgrade config not committed".into());
        }
        self.current_proof(current_boot)?;
        self.with_phase(Phase::Complete)
    }

    fn bound_attempt(&self, owner: &OwnerBinding) -> Result<&Attempt> {
        owner.validate()?;
        let attempt = self.attempt.as_ref().ok_or("Upgrade attempt absent")?;
        if &attempt.owner != owner {
            return Err("Upgrade owner differs".into());
        }
        Ok(attempt)
    }
    fn old_inspection(&self, inspection: &Inspection) -> Result<()> {
        inspection.validate()?;
        if !inspection
            .property
            .matches(&self.plan.identity, &self.plan.old)
        {
            return Err("Upgrade original property differs".into());
        }
        Ok(())
    }
    fn check_rollback(&self, attempt: &Attempt, inspection: &Inspection) -> Result<()> {
        self.old_inspection(inspection)?;
        if inspection != &attempt.inspection {
            return Err("Upgrade original inspection differs".into());
        }
        Ok(())
    }
    fn check_reconciliation(&self, observed: Phase, proof: &Reconciliation) -> Result<()> {
        reconciliation_boot(observed, &self.original_boot, &proof.boot)?;
        proof.candidate.validate()?;
        let attempt = self.attempt.as_ref().ok_or("Upgrade attempt absent")?;
        if !proof
            .candidate
            .property
            .matches(&self.plan.identity, &self.plan.new)
            || !proof.candidate.property.is_enabled
            || proof.candidate.filter != attempt.inspection.filter
        {
            return Err("Upgrade candidate reconciliation differs".into());
        }
        Ok(())
    }
    fn current_proof(&self, current_boot: &str) -> Result<()> {
        if self
            .reconciliation
            .as_ref()
            .is_none_or(|proof| proof.boot != current_boot)
        {
            return Err("Upgrade lacks current boot reconciliation".into());
        }
        Ok(())
    }
    fn with_phase(&self, phase: Phase) -> Result<Self> {
        let mut next = self.clone();
        next.phase = phase;
        next.validate()?;
        Ok(next)
    }
}

fn observed_phase(attempt: &Attempt) -> Result<Phase> {
    let Some(report) = &attempt.last_report else {
        if attempt.replacement.is_some() {
            return Err("Upgrade decision lacks a report".into());
        }
        return Ok(if attempt.owner_lost {
            Phase::Uncertain
        } else {
            Phase::MayBePending
        });
    };
    if report.sequence == 0 {
        return Err("Invalid upgrade report sequence".into());
    }
    if let Some(decision) = &attempt.replacement {
        let decision_report = if decision.allowed {
            UpgradeOutcome::ReplacementAllowed
        } else {
            UpgradeOutcome::ReplacementRefused
        };
        if decision.sequence == 0
            || decision.sequence > report.sequence
            || (decision.sequence == report.sequence && report.outcome != decision_report)
            || (matches!(
                report.outcome,
                UpgradeOutcome::ReplacementAllowed | UpgradeOutcome::ReplacementRefused
            ) && decision.sequence != report.sequence)
        {
            return Err("Invalid upgrade replacement decision".into());
        }
    } else if matches!(
        report.outcome,
        UpgradeOutcome::ReplacementAllowed | UpgradeOutcome::ReplacementRefused
    ) {
        return Err("Upgrade report lacks replacement decision".into());
    }
    let allowed = attempt
        .replacement
        .as_ref()
        .is_some_and(|decision| decision.allowed);
    let phase = match report.outcome {
        UpgradeOutcome::AwaitingApproval
        | UpgradeOutcome::ReplacementAllowed
        | UpgradeOutcome::ReplacementRefused => Phase::MayBePending,
        UpgradeOutcome::Completed if allowed => Phase::OsCompleted,
        UpgradeOutcome::RebootRequired if allowed => Phase::RebootRequired,
        UpgradeOutcome::Completed
        | UpgradeOutcome::RebootRequired
        | UpgradeOutcome::UnexpectedCompleted => Phase::Unexpected,
        UpgradeOutcome::Failed => Phase::OsFailed,
        UpgradeOutcome::Abandoned => Phase::Uncertain,
    };
    if attempt.owner_lost && phase != Phase::MayBePending {
        return Err("Upgrade owner loss conflicts with terminal report".into());
    }
    Ok(if attempt.owner_lost {
        Phase::Uncertain
    } else {
        phase
    })
}

fn reconciliation_boot(phase: Phase, original_boot: &str, current_boot: &str) -> Result<()> {
    if !boot_id(current_boot)
        || !matches!(
            phase,
            Phase::OsCompleted | Phase::RebootRequired | Phase::Unexpected | Phase::Uncertain
        )
        || (phase != Phase::OsCompleted && original_boot == current_boot)
    {
        return Err("Upgrade reconciliation requires a verified boot boundary".into());
    }
    Ok(())
}
fn identity(deployment: &Deployment) -> BundleIdentity {
    let a = &deployment.artifact;
    BundleIdentity {
        team_id: a.team_id.clone(),
        agent_identifier: a.agent_identifier.clone(),
        container_identifier: a.container_identifier.clone(),
        provider_identifier: a.provider_identifier.clone(),
        app_group: a.app_group.clone(),
        mach_service_name: a.mach_service_name.clone(),
    }
}
fn canonical_path(value: &str) -> bool {
    value.len() <= 4096
        && value.starts_with('/')
        && value.len() > 1
        && !value.chars().any(|ch| ch.is_control() || ch == '\\')
        && value[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn cdhashes(values: &[String]) -> bool {
    (1..=4).contains(&values.len())
        && values.iter().all(|value| {
            value.len() == 40
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        && values.windows(2).all(|pair| pair[0] < pair[1])
}
