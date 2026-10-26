//! Fixed transaction service registration. The facade owns protected files,
//! their inode identities, the global lease, and durable operation intent.
//! Matching plist bytes alone never establish ownership of a loaded job.
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "macos", test))]
use std::time::Duration;
use std::{ffi::OsStr, path::Path, process::Command};

#[cfg(test)]
mod tests;

pub const LABEL: &str = "com.athernex.endpoint.network-upgrade";
pub const PLIST: &str = "/Library/LaunchDaemons/com.athernex.endpoint.network-upgrade.plist";
pub const PRIVATE_PLIST: &str =
    "/Library/AthernexEndpoint/network-upgrade/pending/upgrade-service.plist";
pub const PROGRAM: &str = "/Library/AthernexEndpoint/network-upgrade/pending/management";
pub const STATE: &str = "/Library/AthernexEndpoint/state";
pub const MANAGEMENT_PLIST: &str = "/Library/LaunchDaemons/com.athernex.endpoint.plist";
const LAUNCHCTL: &str = "/bin/launchctl";
#[cfg(any(target_os = "macos", test))]
const TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(target_os = "macos", test))]
const OUTPUT_LIMIT: usize = 4096;
const INVALID: &str = "Network upgrade service identity differs";
#[cfg(any(target_os = "macos", test))]
const FAILED: &str = "Network upgrade service operation failed; retain transaction";

/// Apple documents a null SMJobCopyDictionary result as no matching job. Use
/// that fixed-label public API, never launchctl text or an arbitrary nonzero
/// command status. Presence refuses; this function never unloads/adopts a job.
/// The API is deprecated but remains the documented query for legacy jobs.
/// Its OS call has no application-enforced wall-clock bound.
#[cfg(target_os = "macos")]
pub fn require_management_unloaded() -> Result<()> {
    require_unloaded(FixedService::Management)
}

/// Absence alone does not reconcile an attempted bootstrap or bootout. The
/// facade also requires its prior-boot parking barrier, confirmed operation,
/// or never-submitted cancellation proof, according to the recorded phase.
#[cfg(target_os = "macos")]
pub fn require_helper_unloaded() -> Result<()> {
    require_unloaded(FixedService::UpgradeHelper)
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy)]
enum FixedService {
    Management,
    UpgradeHelper,
}

#[cfg(any(target_os = "macos", test))]
impl FixedService {
    fn label(self) -> &'static std::ffi::CStr {
        match self {
            Self::Management => c"com.athernex.endpoint",
            Self::UpgradeHelper => c"com.athernex.endpoint.network-upgrade",
        }
    }
}

#[cfg(target_os = "macos")]
fn require_unloaded(service: FixedService) -> Result<()> {
    unloaded(unsafe { libc::geteuid() }, || service_present(service))
}

#[cfg(any(target_os = "macos", test))]
fn unloaded(uid: u32, query: impl FnOnce() -> Result<bool>) -> Result<()> {
    if uid != 0 {
        return Err("Network upgrade management query requires root".into());
    }
    match query() {
        Ok(false) => Ok(()),
        _ => Err("Network upgrade requires the selected job to be unloaded".into()),
    }
}

#[cfg(target_os = "macos")]
fn service_present(service: FixedService) -> Result<bool> {
    use std::ffi::{c_char, c_void};
    #[link(name = "ServiceManagement", kind = "framework")]
    unsafe extern "C" {
        static kSMDomainSystemLaunchd: *const c_void;
        fn SMJobCopyDictionary(domain: *const c_void, label: *const c_void) -> *const c_void;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            allocator: *const c_void,
            value: *const c_char,
            encoding: u32,
        ) -> *const c_void;
        fn CFRelease(value: *const c_void);
    }
    // Never pass a null domain/label: neither is evidence that the fixed system
    // job is absent. CFString and a returned copied dictionary are both owned.
    unsafe {
        let domain = kSMDomainSystemLaunchd;
        if domain.is_null() {
            return Err("Network upgrade management query is unavailable".into());
        }
        let label = CFStringCreateWithCString(
            std::ptr::null(),
            service.label().as_ptr(),
            0x0800_0100, // kCFStringEncodingUTF8
        );
        if label.is_null() {
            return Err("Network upgrade management query is unavailable".into());
        }
        let job = SMJobCopyDictionary(domain, label);
        CFRelease(label);
        if job.is_null() {
            Ok(false)
        } else {
            CFRelease(job);
            Ok(true)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Prepared,
    BootstrapConfirmed,
    Uncertain,
    BootoutConfirmed,
    /// Cancellation before any bootstrap submission, with actual fixed-label
    /// absence checked by the facade. No bootout was performed or inferred.
    NotRegistered,
    /// A durable private-plist parking receipt predates the current boot and
    /// the facade has checked actual helper absence. No bootout is inferred.
    RetiredAfterBoot,
}

/// Durable facade-owned evidence, never reconstructed from `launchctl print`
/// or an existing matching file. An interrupted Prepared operation is uncertain;
/// it must not be retried as a fresh registration after reopening the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedJobRecord {
    pub schema: u32,
    pub label: String,
    pub mach_service: String,
    pub transaction_id: String,
    pub management_sha256: String,
    pub plist_sha256: String,
    pub state: JobState,
}

#[derive(Debug, Clone)]
pub struct Job {
    mach_service: String,
    transaction_id: String,
    management_sha256: String,
}

impl Job {
    /// `app_group` must already be approved by the signed deployment identity.
    /// The facade verifies the immutable candidate program against this hash.
    pub fn new(
        app_group: &str,
        state: &Path,
        transaction_id: &str,
        management_sha256: &str,
    ) -> Result<Self> {
        let mach_service = format!("{app_group}.network-upgrade");
        if state.as_os_str() != OsStr::new(STATE)
            || !identifier(app_group)
            || mach_service.len() >= 128
            || !hex64(transaction_id)
            || !hex64(management_sha256)
        {
            return Err(INVALID.into());
        }
        Ok(Self {
            mach_service,
            transaction_id: transaction_id.into(),
            management_sha256: management_sha256.into(),
        })
    }

    pub fn plist_bytes(&self) -> Vec<u8> {
        // No stdout/stderr file paths: raw service diagnostics are not exported.
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
             <key>Label</key><string>{LABEL}</string>\n\
             <key>ProgramArguments</key><array><string>{PROGRAM}</string><string>serve-macos-network-upgrade</string><string>{STATE}</string><string>{}</string></array>\n\
             <key>MachServices</key><dict><key>{}</key><true/></dict>\n\
             <key>UserName</key><string>root</string>\n\
             <key>RunAtLoad</key><false/><key>KeepAlive</key><false/>\n\
             <key>WorkingDirectory</key><string>/</string>\n\
             <key>Umask</key><integer>63</integer>\n\
             </dict></plist>\n",
            escape(&self.transaction_id),
            escape(&self.mach_service),
        )
        .into_bytes()
    }

    pub fn plist_sha256(&self) -> String {
        sha256(&self.plist_bytes())
    }

    /// Save this record and the exclusive-create intent before bootstrap.
    /// The caller must refuse any preexisting unknown file or loaded job.
    pub fn prepared_record(&self) -> OwnedJobRecord {
        OwnedJobRecord {
            schema: 1,
            label: LABEL.into(),
            mach_service: self.mach_service.clone(),
            transaction_id: self.transaction_id.clone(),
            management_sha256: self.management_sha256.clone(),
            plist_sha256: self.plist_sha256(),
            state: JobState::Prepared,
        }
    }

    fn verify(
        &self,
        record: &OwnedJobRecord,
        observed_path: &Path,
        observed_bytes: &[u8],
        state: JobState,
        expected_path: &str,
    ) -> Result<()> {
        let mut expected = self.prepared_record();
        expected.state = state;
        if record != &expected
            || observed_path.as_os_str() != OsStr::new(expected_path)
            || observed_bytes != self.plist_bytes()
            || sha256(observed_bytes) != record.plist_sha256
        {
            return Err(INVALID.into());
        }
        Ok(())
    }

    /// Pure builder. The facade must retain its lease and verify protected
    /// ancestry/inode, exact bytes, and the candidate program immediately before
    /// execution. Bootstrap never replaces or adopts an existing loaded job.
    pub fn bootstrap_command(
        &self,
        record: &OwnedJobRecord,
        observed_path: &Path,
        observed_bytes: &[u8],
    ) -> Result<Command> {
        self.verify(
            record,
            observed_path,
            observed_bytes,
            JobState::Prepared,
            PLIST,
        )?;
        Ok(command(false))
    }

    /// Only a durably confirmed bootstrap permits bootout. The facade must
    /// first durably park the exact owned plist at PRIVATE_PLIST, preventing
    /// automatic reload at the next boot. Uncertain recovery cannot infer
    /// absence from launchctl output or merely matching private bytes.
    pub fn bootout_command(
        &self,
        record: &OwnedJobRecord,
        observed_path: &Path,
        observed_bytes: &[u8],
    ) -> Result<Command> {
        self.verify(
            record,
            observed_path,
            observed_bytes,
            JobState::BootstrapConfirmed,
            PRIVATE_PLIST,
        )?;
        Ok(command(true))
    }

    #[cfg(target_os = "macos")]
    pub fn bootstrap(
        &self,
        record: &OwnedJobRecord,
        observed_path: &Path,
        observed_bytes: &[u8],
    ) -> Result<OwnedJobRecord> {
        self.perform(record, observed_path, observed_bytes, false, &mut Native)
    }

    #[cfg(target_os = "macos")]
    pub fn bootout(
        &self,
        record: &OwnedJobRecord,
        observed_path: &Path,
        observed_bytes: &[u8],
    ) -> Result<OwnedJobRecord> {
        self.perform(record, observed_path, observed_bytes, true, &mut Native)
    }

    #[cfg(any(target_os = "macos", test))]
    fn perform(
        &self,
        record: &OwnedJobRecord,
        observed_path: &Path,
        observed_bytes: &[u8],
        stopping: bool,
        backend: &mut impl Backend,
    ) -> Result<OwnedJobRecord> {
        let mut command = if stopping {
            self.bootout_command(record, observed_path, observed_bytes)?
        } else {
            self.bootstrap_command(record, observed_path, observed_bytes)?
        };
        match backend.run(&mut command, TIMEOUT, OUTPUT_LIMIT) {
            Ok((0, _)) => {
                let mut confirmed = record.clone();
                confirmed.state = if stopping {
                    JobState::BootoutConfirmed
                } else {
                    JobState::BootstrapConfirmed
                };
                Ok(confirmed)
            }
            // A nonzero result, timeout, cleanup uncertainty or lost reply is
            // not proof of absence. Do not unlink/restore/retry here.
            _ => Err(FAILED.into()),
        }
    }
}

fn command(stopping: bool) -> Command {
    let mut command = Command::new(LAUNCHCTL);
    if stopping {
        command.args(["bootout", &format!("system/{LABEL}")]);
    } else {
        command.args(["bootstrap", "system", PLIST]);
    }
    command.env_clear().current_dir("/");
    command
}

#[cfg(any(target_os = "macos", test))]
trait Backend {
    fn run(
        &mut self,
        command: &mut Command,
        timeout: Duration,
        limit: usize,
    ) -> Result<(i32, Vec<u8>)>;
}
#[cfg(target_os = "macos")]
struct Native;
#[cfg(target_os = "macos")]
impl Backend for Native {
    fn run(
        &mut self,
        command: &mut Command,
        timeout: Duration,
        limit: usize,
    ) -> Result<(i32, Vec<u8>)> {
        athernex_endpoint_native::child::run(command, timeout, limit)
    }
}

fn identifier(value: &str) -> bool {
    value.len() <= 255
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Exact standard management registration produced by install-macos.sh. The
/// facade snapshots/moves this only while its services are already quiescent;
/// restoration also requires its recorded inode/bytes/hash and an absent target.
pub fn management_plist_bytes() -> &'static [u8] {
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\"><dict>\n\
<key>Label</key><string>com.athernex.endpoint</string>\n\
<key>ProgramArguments</key><array><string>/Library/AthernexEndpoint/athernex-controller</string><string>supervise</string><string>/Library/AthernexEndpoint/state</string><string>/Library/AthernexEndpoint/athernex-endpoint</string></array>\n\
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n\
<key>ThrottleInterval</key><integer>15</integer><key>Umask</key><integer>63</integer>\n\
</dict></plist>\n"
}

pub fn verify_management_snapshot(bytes: &[u8], recorded_sha256: &str) -> Result<()> {
    if bytes != management_plist_bytes()
        || !hex64(recorded_sha256)
        || sha256(bytes) != recorded_sha256
    {
        return Err("Network upgrade management registration differs".into());
    }
    Ok(())
}
