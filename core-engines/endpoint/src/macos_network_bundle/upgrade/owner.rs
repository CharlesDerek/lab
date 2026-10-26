//! Ordered journal effects for the authenticated lifecycle listener.
//! Native inspection and protected filesystem effects are supplied by the
//! platform backend. Replies follow durable effects, never precede them.
use super::journal::{Inspection, OwnerBinding, Phase, Record, Report};
use crate::Result;
use athernex_macos_network::upgrade::{
    ExtensionProperty, FilterState, UpgradeEvent, UpgradeIncoming, UpgradeMode, UpgradePermit,
    UpgradeReply, UpgradeRequest, MAX_PERMIT_MS,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InspectTarget {
    Original,
    Candidate,
}

pub(super) trait Backend {
    /// Compare the previous durable record before atomically persisting next.
    /// An error can mean the write reached disk; callers must stop issuing
    /// replies and reopen/reconcile the durable record rather than retrying it.
    fn persist(&mut self, previous: &Record, next: &Record) -> Result<()>;
    /// Validate exact static OS code, app/config/snapshot ownership and filter
    /// state. Candidate/rollback verification includes an exact pinned live
    /// channel when the preserved filter is enabled, without pulling batches.
    fn inspect(
        &mut self,
        record: &Record,
        target: InspectTarget,
        properties: &[ExtensionProperty],
        filter: &FilterState,
    ) -> Result<Inspection>;
    /// Recheck the original property and immutable candidate immediately
    /// before reserving the only request. Metadata alone is not authorization.
    fn before_permit(&mut self, record: &Record, inspection: &Inspection) -> Result<()>;
    /// The reconciliation record has already been persisted. Commit only the
    /// exact approved candidate config, accepting an already-completed write.
    fn commit_config(&mut self, record: &Record) -> Result<()>;
    /// Persist a bound rollback intent before restoring exact original files.
    /// This does not submit any activation/deactivation or infer OS rollback.
    fn restore_original(&mut self, record: &Record, inspection: &Inspection) -> Result<()>;
}

pub(super) struct Owner<B> {
    pub record: Record,
    backend: B,
    boot: String,
    instance_nonce: String,
    connection: Option<u64>,
    inspection: Option<Inspection>,
    poisoned: bool,
}

impl<B: Backend> Owner<B> {
    pub fn new(record: Record, backend: B, boot: String, instance_nonce: String) -> Result<Self> {
        record.validate()?;
        if !athernex_endpoint_protocol::hex_id(&instance_nonce) {
            return Err("Invalid network upgrade owner identity".into());
        }
        let mut owner = Self {
            record,
            backend,
            boot,
            instance_nonce,
            connection: None,
            inspection: None,
            poisoned: false,
        };
        // A new root process cannot reattach the previous connection's terminal
        // authority, including a permit reply that may have been lost.
        if owner.record.phase == Phase::MayBePending {
            let prior = owner
                .record
                .attempt
                .as_ref()
                .ok_or("Upgrade attempt is missing")?
                .owner
                .clone();
            let next = owner.record.owner_lost(&prior)?;
            owner.persist(next)?;
        }
        owner.mode()?;
        Ok(owner)
    }

    fn mode(&self) -> Result<UpgradeMode> {
        if self.record.phase == Phase::CandidatePlaced
            && self.record.original_boot == self.boot
            && self.record.attempt.is_none()
        {
            return Ok(UpgradeMode::Submit);
        }
        if self.record.phase == Phase::OsFailed {
            return Ok(UpgradeMode::Reconcile);
        }
        self.record.can_reconcile(&self.boot)?;
        Ok(UpgradeMode::Reconcile)
    }

    fn binding(&self, generation: u64) -> OwnerBinding {
        OwnerBinding {
            instance_nonce: self.instance_nonce.clone(),
            connection_generation: generation,
            operator_uid: self.record.operator_uid,
        }
    }

    fn persist(&mut self, next: Record) -> Result<()> {
        next.validate()?;
        // A failed fsync/rename must not leave an old in-memory unclaimed
        // record available to another request on this listener.
        self.poisoned = true;
        self.backend.persist(&self.record, &next)?;
        self.record = next;
        self.poisoned = false;
        Ok(())
    }

    pub fn handle(&mut self, incoming: &UpgradeIncoming) -> Result<Option<UpgradeReply>> {
        if self.poisoned
            || incoming.connection_generation == 0
            || incoming.peer_euid != self.record.operator_uid
        {
            return Err("Network upgrade connection is not authorized".into());
        }
        if let Some(generation) = self.connection {
            if generation != incoming.connection_generation {
                return Err("Network upgrade connection ownership changed".into());
            }
        } else {
            if !matches!(
                &incoming.event,
                UpgradeEvent::Request {
                    request: UpgradeRequest::Plan
                }
            ) {
                return Err("Network upgrade connection has no plan".into());
            }
            self.connection = Some(incoming.connection_generation);
        }
        let binding = self.binding(incoming.connection_generation);
        let UpgradeEvent::Request { request } = &incoming.event else {
            self.disconnected(&binding)?;
            return Ok(None);
        };
        if incoming.request_token == 0 {
            return Err("Network upgrade request token is missing".into());
        }
        request.validate()?;
        let reply = match request {
            UpgradeRequest::Plan => {
                let mut plan = self.record.plan.clone();
                plan.mode = self.mode()?;
                let plan_sha256 = athernex_endpoint_protocol::hash(&serde_json::to_vec(&plan)?);
                UpgradeReply::Plan { plan, plan_sha256 }
            }
            UpgradeRequest::Inspect { properties, filter } => {
                match self.mode()? {
                    UpgradeMode::Submit => {
                        let inspected = self.backend.inspect(
                            &self.record,
                            InspectTarget::Original,
                            properties,
                            filter,
                        )?;
                        self.inspection = Some(inspected);
                    }
                    UpgradeMode::Reconcile if self.record.phase == Phase::OsFailed => {
                        let inspected = self.backend.inspect(
                            &self.record,
                            InspectTarget::Original,
                            properties,
                            filter,
                        )?;
                        // Refuse a changed original before any restoration.
                        self.record.abort_failed(inspected.clone())?;
                        self.poisoned = true;
                        self.backend.restore_original(&self.record, &inspected)?;
                        self.poisoned = false;
                        let next = self.record.abort_failed(inspected)?;
                        self.persist(next)?;
                    }
                    UpgradeMode::Reconcile => {
                        let inspected = self.backend.inspect(
                            &self.record,
                            InspectTarget::Candidate,
                            properties,
                            filter,
                        )?;
                        let next = self.record.reconcile_candidate(&self.boot, inspected)?;
                        self.persist(next)?;
                        self.poisoned = true;
                        self.backend.commit_config(&self.record)?;
                        self.poisoned = false;
                        let next = self.record.config_committed(&self.boot)?;
                        self.persist(next)?;
                    }
                }
                UpgradeReply::Inspected
            }
            UpgradeRequest::Claim { plan_sha256 } => {
                if self.mode()? != UpgradeMode::Submit {
                    return Err("Reconciliation cannot authorize another request".into());
                }
                let inspection = self.inspection.take().ok_or("Upgrade was not inspected")?;
                self.backend.before_permit(&self.record, &inspection)?;
                let attempt_id = nonce()?;
                let attempt_nonce = nonce()?;
                let next = self.record.claim(
                    &self.boot,
                    binding,
                    attempt_id.clone(),
                    attempt_nonce.clone(),
                    plan_sha256,
                    inspection.clone(),
                )?;
                self.persist(next)?;
                UpgradeReply::Permit {
                    permit: UpgradePermit {
                        plan: self.record.plan.clone(),
                        old_property: inspection.property,
                        attempt_id,
                        attempt_nonce,
                        permit_ms: MAX_PERMIT_MS,
                    },
                }
            }
            UpgradeRequest::Report {
                attempt_id,
                attempt_nonce,
                sequence,
                outcome,
            } => {
                let next = self.record.report(
                    &binding,
                    attempt_id,
                    attempt_nonce,
                    Report {
                        sequence: *sequence,
                        outcome: *outcome,
                    },
                )?;
                // Includes exact terminal replay; never ACK a merely transient
                // in-memory terminal callback.
                self.persist(next)?;
                UpgradeReply::Recorded
            }
        };
        reply.validate()?;
        Ok(Some(reply))
    }

    fn disconnected(&mut self, binding: &OwnerBinding) -> Result<()> {
        self.inspection = None;
        if self
            .record
            .attempt
            .as_ref()
            .is_some_and(|a| &a.owner == binding)
        {
            let next = self.record.owner_lost(binding)?;
            self.persist(next)?;
        }
        self.poisoned = true;
        Ok(())
    }

    /// Call on reply failure, timeout, or listener shutdown. If persistence was
    /// already uncertain, do not overwrite a possibly newer on-disk record.
    pub fn lost(&mut self) -> Result<()> {
        if self.poisoned {
            return Ok(());
        }
        if let Some(generation) = self.connection {
            let binding = self.binding(generation);
            self.disconnected(&binding)?;
        }
        self.poisoned = true;
        Ok(())
    }
}

pub(super) fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "Network upgrade nonce unavailable")?;
    Ok(athernex_endpoint_protocol::hash(&bytes))
}
