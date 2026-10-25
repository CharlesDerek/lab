//! Correlate one disposable mutation worker's denied open. Neither the worker
//! nor the scanner receives an exemption from the minifilter.
use super::*;
use athernex_endpoint_native::{
    mutation::{self, Identity, Verifier},
    windows_filter::evidence::hex,
};
use evidence::responses::Probe;
use std::sync::atomic::AtomicBool;

// PID+creation time is an unambiguous actor only because this process attempts
// exactly one source verification. Recovery does not invoke this callback.
static ATTEMPTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn verifier(state: &Path) -> Result<Verifier> {
    let path = state.join("protection/windows");
    if !path.try_exists()? {
        return Ok(Verifier::Local);
    }
    let live = status(&path)?;
    Ok(Verifier::WindowsProtected {
        session: live.session,
        policy: live.policy_sha256,
    })
}
pub(crate) fn verify(
    state: &Path,
    session: &str,
    policy: &str,
    path: &Path,
    identity: &Identity,
    timeout: Duration,
) -> Result<athernex_endpoint_native::Verdict> {
    if ATTEMPTED.swap(true, Ordering::AcqRel) {
        return Err(
            "Windows response requires a new disposable worker for each source read".into(),
        );
    }
    let timeout = timeout.min(Duration::from_secs(10));
    if timeout.is_zero() {
        return Err("Windows response deadline elapsed".into());
    }
    let deadline = Instant::now() + timeout;
    let state_path = state.join("protection/windows");
    let directory = Directory::open(&state_path)?;
    let queue = Queue::open(&directory.database_path("evidence.sqlite3")?)?;
    let live = status(&state_path)?;
    if live.session != session || live.policy_sha256 != policy {
        return Err("Windows response protection binding changed since admission".into());
    }
    let parent = PinnedDirectory::open(path.parent().ok_or("Source has no parent")?)?;
    let dos = format!("{}\\{}", parent.dos()?, leaf(path)?);
    let actor_pid = std::process::id();
    let started_ms = now_ms();
    let probe = Probe {
        id: secret()?,
        session: session.into(),
        policy: policy.into(),
        actor_pid,
        actor_created: peer::identify(actor_pid)?,
        path: dos,
        volume: identity.device,
        file_id: hex(&identity.file_id),
        bytes: identity.size,
        started_ms,
        expires_ms: started_ms.saturating_add(engine::remaining(deadline)?.as_millis() as u64),
    };
    queue.begin_response(&probe)?;
    let result = (|| -> Result<_> {
        match mutation::windows_source_verdict(path, identity, engine::remaining(deadline)?) {
            Ok(verdict) => Ok(verdict),
            Err(error) => {
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_none_or(|e| e.raw_os_error() != Some(5))
                {
                    return Err(error);
                }
                loop {
                    engine::remaining(deadline)?;
                    if let Some(verdict) = queue.take_response(&probe)? {
                        return Ok(verdict);
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    })();
    // Successful evidence consumption and a clean ordinary read both retire the
    // probe. A killed worker leaves only a bounded, expiring correlation row.
    queue.cancel_response(&probe)?;
    let verdict = result?;
    let live = status(&state_path)?;
    if live.session != session || live.policy_sha256 != policy {
        return Err("Windows response protection changed during verification".into());
    }
    engine::remaining(deadline)?;
    Ok(verdict)
}
