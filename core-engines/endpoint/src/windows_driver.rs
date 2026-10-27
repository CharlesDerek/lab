//! Machine-global driver deployment ownership. A durable native intent is
//! at-most-once: absence of a completion receipt never permits API replay.
use crate::Result;
use athernex_endpoint_native::windows_driver_lifecycle::{
    LoadObserved, NativeEffect, ObjectIdentity, Registration,
};
use athernex_endpoint_protocol::{
    self as protocol,
    windows_filter_package::{Deployment, Descriptor, Member},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Admission;
#[cfg(windows)]
pub use windows::{
    coordinate, install, recover, require_live, require_owned, require_settled, retire, status,
};
#[cfg(windows)]
pub(crate) use windows::{Capability, Exclusive};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Snapshot,
    Ready,
    CreateIntent,
    HelperCreated,
    StartIntent,
    StartRequested,
    Claimed,
    Endpoint,
    InstallIntent,
    Installed,
    LoadIntent,
    Loaded,
    Complete,
    RefreshIntent,
    RetireRequested,
    UnloadIntent,
    Unloaded,
    UninstallIntent,
    Retired,
    DeleteIntent,
    HelperDeleted,
    Released,
    RebootPending,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Install,
    Reload,
    Retire,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub approved: Member,
    pub identity: Option<ObjectIdentity>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Completed,
    Retired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub kind: ReceiptKind,
    pub temporary: String,
    pub receipt: Input,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedLoad {
    pub epoch: String,
    pub load: LoadObserved,
    /// Immutable prior Complete record, including its own historical link.
    pub receipt: Input,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: u32,
    pub transaction: String,
    pub nonce: String,
    pub source_sha256: String,
    pub state: PathBuf,
    pub state_identity: ObjectIdentity,
    pub agent: PathBuf,
    pub descriptor: Descriptor,
    pub epoch: String,
    pub epoch_confirmed: bool,
    pub refresh_epoch: Option<String>,
    pub previous_load: Option<CompletedLoad>,
    pub snapshot: Option<ObjectIdentity>,
    pub inputs: BTreeMap<String, Input>,
    pub phase: Phase,
    pub operation: Operation,
    pub helper_created: bool,
    pub helper_owner_system: bool,
    pub resume_phase: Option<Phase>,
    pub archive: Option<ObjectIdentity>,
    pub publication: Option<Publication>,
    pub worker: Option<(u32, u64)>,
    pub registration: Option<Registration>,
    pub load: Option<LoadObserved>,
    pub effect: Option<NativeEffect>,
}
const INPUTS: [&str; 6] = [
    "athernex-endpoint.exe",
    "management.exe",
    "bootstrap.json",
    "release.json",
    "windows-filter.axpkg",
    "windows-filter.required",
];
impl Record {
    pub fn validate(&self) -> Result<()> {
        self.descriptor.validate()?;
        if self.schema != 1
            || [
                &self.transaction,
                &self.nonce,
                &self.source_sha256,
                &self.epoch,
            ]
            .iter()
            .any(|s| !protocol::hex_id(s))
            || self.descriptor.deployment != Some(Deployment::InstallAndObserveDisarmedV1)
            || self.inputs.len() != INPUTS.len()
            || INPUTS.iter().any(|n| !self.inputs.contains_key(*n))
            || !self.state.is_absolute()
            || !self.agent.is_absolute()
            || self.state_identity.file_id == [0; 16]
            || self.inputs.values().any(|v| {
                v.approved.bytes == 0
                    || v.approved.bytes > 64 * 1024 * 1024
                    || !protocol::hex_id(&v.approved.sha256)
            })
            || self.inputs["athernex-endpoint.exe"].approved.sha256 != self.source_sha256
            || self.inputs["management.exe"].approved
                != self.inputs["athernex-endpoint.exe"].approved
            || self.inputs["windows-filter.axpkg"].approved.sha256 != self.descriptor.sha256
            || self.inputs["windows-filter.axpkg"].approved.bytes != self.descriptor.bytes
            || self.inputs["windows-filter.required"].approved
                != (Member {
                    bytes: 2,
                    sha256: protocol::hash(b"1\n"),
                })
            || self.resume_phase.is_some_and(|p| {
                !matches!(
                    p,
                    Phase::Claimed
                        | Phase::Endpoint
                        | Phase::Installed
                        | Phase::Loaded
                        | Phase::Unloaded
                )
            })
            || self.resume_phase.is_some()
                && !matches!(self.phase, Phase::StartIntent | Phase::StartRequested)
            || self.phase == Phase::Released && self.archive.is_none()
            || self.archive.is_some()
                && !matches!(self.phase, Phase::HelperDeleted | Phase::Released)
            || self
                .worker
                .is_some_and(|(pid, created)| pid <= 4 || created == 0)
        {
            return Err("Invalid driver deployment ownership record".into());
        }
        if let Some(publication) = &self.publication {
            if !protocol::hex_id(&publication.temporary)
                || publication.receipt.identity.is_none()
                || publication.receipt.approved.bytes == 0
                || publication.receipt.approved.bytes > 65536
                || !protocol::hex_id(&publication.receipt.approved.sha256)
                || !matches!(
                    (publication.kind, self.phase),
                    (ReceiptKind::Completed, Phase::Complete)
                        | (ReceiptKind::Retired, Phase::HelperDeleted)
                )
                || self.archive.is_some()
            {
                return Err("Invalid local receipt publication intent".into());
            }
        }
        if self.refresh_epoch.is_some() != (self.phase == Phase::RefreshIntent)
            || self
                .refresh_epoch
                .as_ref()
                .is_some_and(|v| !protocol::hex_id(v))
            || self.phase == Phase::RefreshIntent && self.operation != Operation::Reload
            || self.operation == Operation::Reload && self.previous_load.is_none()
        {
            return Err("Invalid completed-registration refresh ownership".into());
        }
        if let Some(previous) = &self.previous_load {
            previous.load.validate()?;
            if !protocol::hex_id(&previous.epoch)
                || previous.receipt.identity.is_none()
                || !protocol::hex_id(&previous.receipt.approved.sha256)
                || previous.receipt.approved.bytes == 0
                || previous.receipt.approved.bytes > 65536
            {
                return Err("Invalid previous completed-load receipt".into());
            }
        }
        if self.phase != Phase::Snapshot
            && (self.snapshot.is_none()
                || !self.epoch_confirmed
                || self.inputs.values().any(|v| v.identity.is_none()))
        {
            return Err(
                "Driver transaction advanced without its immutable snapshot and epoch receipts"
                    .into(),
            );
        }
        if matches!(
            self.phase,
            Phase::HelperCreated
                | Phase::StartIntent
                | Phase::StartRequested
                | Phase::Claimed
                | Phase::Endpoint
                | Phase::InstallIntent
                | Phase::Installed
                | Phase::LoadIntent
                | Phase::Loaded
                | Phase::Complete
                | Phase::RefreshIntent
                | Phase::RetireRequested
                | Phase::UnloadIntent
                | Phase::Unloaded
                | Phase::UninstallIntent
                | Phase::Retired
                | Phase::DeleteIntent
                | Phase::HelperDeleted
                | Phase::Released
                | Phase::RebootPending
        ) && !self.helper_created
        {
            return Err("Driver transaction lacks a successful helper creation receipt".into());
        }
        if matches!(
            self.phase,
            Phase::Installed
                | Phase::LoadIntent
                | Phase::Loaded
                | Phase::Complete
                | Phase::RefreshIntent
                | Phase::RetireRequested
                | Phase::UnloadIntent
                | Phase::Unloaded
                | Phase::UninstallIntent
                | Phase::Retired
                | Phase::DeleteIntent
                | Phase::HelperDeleted
                | Phase::Released
        ) && self.registration.is_none()
        {
            return Err("Driver transaction lacks its owned registration".into());
        }
        if matches!(
            self.phase,
            Phase::Loaded | Phase::Complete | Phase::RetireRequested | Phase::UnloadIntent
        ) && self.load.is_none()
        {
            return Err("Driver transaction lacks its owned load observation".into());
        }
        if let Some(load) = &self.load {
            load.validate()?;
        }
        Ok(())
    }
    fn advance(&mut self, from: Phase, to: Phase) -> Result<()> {
        self.validate()?;
        if self.phase != from {
            return Err("Driver lifecycle transition cannot be replayed or skipped".into());
        }
        self.phase = to;
        Ok(())
    }
    pub fn ready(&mut self) -> Result<()> {
        self.advance(Phase::Snapshot, Phase::Ready)?;
        self.validate()
    }
    pub fn create_intent(&mut self) -> Result<()> {
        self.advance(Phase::Ready, Phase::CreateIntent)
    }
    pub fn created(&mut self) -> Result<()> {
        self.advance(Phase::CreateIntent, Phase::HelperCreated)?;
        self.helper_created = true;
        self.validate()
    }
    pub fn start_intent(&mut self) -> Result<()> {
        self.validate()?;
        if matches!(
            self.phase,
            Phase::Claimed | Phase::Endpoint | Phase::Installed | Phase::Loaded | Phase::Unloaded
        ) {
            self.resume_phase = Some(self.phase);
        } else if !matches!(self.phase, Phase::HelperCreated | Phase::RetireRequested) {
            return Err("Coordinator start is not authorized".into());
        }
        self.phase = Phase::StartIntent;
        self.worker = None;
        Ok(())
    }
    pub fn started(&mut self) -> Result<()> {
        self.advance(Phase::StartIntent, Phase::StartRequested)
    }
    pub fn claim(&mut self, pid: u32, created: u64) -> Result<()> {
        self.advance(Phase::StartRequested, Phase::Claimed)?;
        self.worker = Some((pid, created));
        if let Some(phase) = self.resume_phase.take() {
            self.phase = phase;
        }
        self.validate()
    }
    pub fn endpoint(&mut self) -> Result<()> {
        self.advance(Phase::Claimed, Phase::Endpoint)
    }
    pub fn intent(&mut self) -> Result<()> {
        self.validate()?;
        self.phase = match (self.operation, self.phase) {
            (Operation::Install, Phase::Endpoint) => Phase::InstallIntent,
            (Operation::Install | Operation::Reload, Phase::Installed) => Phase::LoadIntent,
            (Operation::Retire, Phase::Claimed) => Phase::UnloadIntent,
            (Operation::Retire, Phase::Unloaded) => Phase::UninstallIntent,
            _ => return Err("Native effect is not authorized or was already claimed".into()),
        };
        self.effect = None;
        Ok(())
    }
    pub fn result(
        &mut self,
        effect: NativeEffect,
        registration: Option<Registration>,
        load: Option<LoadObserved>,
    ) -> Result<()> {
        self.validate()?;
        if !matches!(
            self.phase,
            Phase::InstallIntent | Phase::LoadIntent | Phase::UnloadIntent | Phase::UninstallIntent
        ) {
            return Err("Native result has no matching effect intent".into());
        }
        self.effect = Some(effect);
        if !effect.succeeded {
            self.phase = Phase::Uncertain;
            return Ok(());
        }
        if effect.need_reboot {
            self.phase = Phase::RebootPending;
            return Ok(());
        }
        self.phase = match self.phase {
            Phase::InstallIntent => {
                self.registration =
                    Some(registration.ok_or("Install result lacks exact registration")?);
                Phase::Installed
            }
            Phase::LoadIntent => {
                let load = load.ok_or("Load result lacks disarmed ABI observation")?;
                if self.operation == Operation::Reload
                    && self
                        .previous_load
                        .as_ref()
                        .is_some_and(|p| p.load.instance == load.instance)
                {
                    return Err("Fresh load reused the previous observed instance".into());
                }
                self.load = Some(load);
                Phase::Loaded
            }
            Phase::UnloadIntent => Phase::Unloaded,
            Phase::UninstallIntent => Phase::Retired,
            _ => unreachable!(),
        };
        self.validate()
    }
    pub fn complete(&mut self) -> Result<()> {
        self.advance(Phase::Loaded, Phase::Complete)
    }
    /// Called only after exact registration, absence, stopped/ended helper and
    /// immutable historical receipt checks. An epoch is not reboot evidence.
    pub fn publish_intent(&mut self, publication: Publication) -> Result<()> {
        self.validate()?;
        if self.publication.is_some() {
            return Err("Receipt publication is already claimed".into());
        }
        self.publication = Some(publication);
        self.validate()
    }
    pub fn refresh_intent(&mut self, epoch: String, previous: CompletedLoad) -> Result<()> {
        self.validate()?;
        if self.phase != Phase::Complete
            || previous.epoch != self.epoch
            || Some(&previous.load) != self.load.as_ref()
            || !protocol::hex_id(&epoch)
        {
            return Err("Only a known completed load may refresh its registration".into());
        }
        if self
            .publication
            .as_ref()
            .is_none_or(|p| p.kind != ReceiptKind::Completed || p.receipt != previous.receipt)
        {
            return Err("Completed-load receipt lacks its durable publication claim".into());
        }
        self.publication = None;
        self.operation = Operation::Reload;
        self.phase = Phase::RefreshIntent;
        self.refresh_epoch = Some(epoch);
        self.previous_load = Some(previous);
        self.validate()
    }
    pub fn refreshed(&mut self, confirmed_epoch: &str) -> Result<()> {
        self.validate()?;
        if self.phase != Phase::RefreshIntent
            || self.refresh_epoch.as_deref() != Some(confirmed_epoch)
        {
            return Err("Refreshed epoch has no exact durable claim".into());
        }
        self.epoch = confirmed_epoch.into();
        self.refresh_epoch = None;
        self.load = None;
        self.effect = None;
        self.phase = Phase::Installed;
        self.validate()
    }
    pub fn request_retirement(&mut self) -> Result<()> {
        self.advance(Phase::Complete, Phase::RetireRequested)?;
        self.operation = Operation::Retire;
        Ok(())
    }
    pub fn delete_intent(&mut self) -> Result<()> {
        self.advance(Phase::Retired, Phase::DeleteIntent)
    }
    pub fn helper_deleted(&mut self) -> Result<()> {
        self.advance(Phase::DeleteIntent, Phase::HelperDeleted)
    }
    pub fn archived(&mut self) -> Result<()> {
        self.validate()?;
        let publication = self
            .publication
            .as_ref()
            .filter(|p| p.kind == ReceiptKind::Retired)
            .ok_or("Terminal receipt publication missing")?;
        self.archive = publication.receipt.identity.clone();
        self.publication = None;
        self.validate()
    }
    pub fn release(&mut self) -> Result<()> {
        if self.archive.is_none() {
            return Err("Terminal driver receipt is not archived".into());
        }
        self.advance(Phase::HelperDeleted, Phase::Released)
    }
    pub fn failed_load_retirement(&mut self, filter_absent: bool) -> Result<()> {
        self.validate()?;
        if self.phase != Phase::Uncertain
            || self.registration.is_none()
            || self.load.is_some()
            || !filter_absent
            || self.effect.is_none_or(|e| e.succeeded || e.need_reboot)
        {
            return Err("Failed load has no owned, confirmed-absent retirement authority".into());
        }
        self.operation = Operation::Retire;
        self.phase = Phase::Unloaded;
        Ok(())
    }
    pub fn authorize_complete(&self, epoch_matches: bool, instance: [u8; 16]) -> Result<()> {
        self.validate()?;
        if !matches!(self.phase, Phase::Loaded | Phase::Complete)
            || !epoch_matches
            || self.load.as_ref().is_none_or(|l| l.instance != instance)
        {
            return Err("Driver deployment is not durably observed in this kernel lifetime".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
