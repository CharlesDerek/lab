//! Execute on a native Windows filesystem. Linking this suite does not validate
//! NT file-operation, ACL, sharing, or flush behavior.
use super::*;
use std::{fs as stdfs, io::Write};
const CONTENTS: &[u8] = b"approved Windows response fixture";

#[test]
fn windows_source_capture_needs_metadata_and_delete_access_without_content_access() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_WRITE,
    };
    let f = Fixture::new();
    // This handle permits rename but deliberately refuses shared content reads.
    // The former DELETE|GENERIC_READ capture open would fail with error 32.
    let held = stdfs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_DELETE | FILE_SHARE_WRITE)
        .open(&f.intent.path)
        .unwrap();
    assert_eq!(
        stdfs::File::open(&f.intent.path)
            .unwrap_err()
            .raw_os_error(),
        Some(32)
    );
    let parent = fs::Dir::open(f.intent.path.parent().unwrap()).unwrap();
    let state = fs::Dir::open(&f.intent.state).unwrap();
    let quarantine = state.directory("quarantine").unwrap();
    fs::capture(
        &parent,
        "sample.txt",
        &quarantine,
        "captured",
        &fs::identity(&held).unwrap(),
    )
    .unwrap();
    drop(held);
    assert!(!f.intent.path.exists());
    assert_eq!(
        stdfs::read(quarantine.path.join("captured")).unwrap(),
        CONTENTS
    );
}

#[test]
fn windows_protected_verification_requires_a_reader_and_recovery_never_repeats_it() {
    let mut f = Fixture::new();
    f.intent.verifier = Some(Verifier::WindowsProtected {
        session: "a".repeat(64),
        policy: "b".repeat(64),
    });
    assert!(apply(&f.intent, false, Duration::from_secs(10))
        .unwrap_err()
        .to_string()
        .contains("Protected reader implementation"));
    assert_eq!(stdfs::read(&f.intent.path).unwrap(), CONTENTS);
    let mut calls = 0;
    let report = apply_with_verifier(
        &f.intent,
        false,
        Duration::from_secs(10),
        |path, expected, timeout, _| {
            calls += 1;
            let mut wrong = expected.clone();
            wrong.file_id[0] ^= 1;
            assert!(windows_source_verdict(path, &wrong, timeout).is_err());
            windows_source_verdict(path, expected, timeout)
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(report.outcome, Outcome::Completed);
    assert_eq!(stdfs::read(f.retained()).unwrap(), CONTENTS);
    let recovered = apply_with_verifier(&f.intent, true, Duration::from_secs(10), |_, _, _, _| {
        panic!("Committed recovery must not repeat source verification")
    })
    .unwrap();
    assert_eq!(recovered.outcome, Outcome::Completed);
    let mut restore = f.restore();
    restore.verifier = f.intent.verifier.clone();
    assert!(restore.validate().is_err());
}

// Deliberately loosen only a disposable fixture's ACL to exercise refusal at
// both the state and persisted-journal boundaries. Never modify a host policy.
fn grant_everyone(path: &Path) {
    use std::{
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        ptr::null_mut,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        },
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC,
        },
    };
    let file = stdfs::OpenOptions::new()
        .access_mode(WRITE_DAC | READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap();
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;WD)".encode_utf16().chain([0]).collect();
    let mut descriptor = null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        },
        0
    );
    let mut dacl = null_mut();
    let (mut present, mut defaulted) = (0, 0);
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    assert!(!dacl.is_null());
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    assert_eq!(result, 0);
}
struct Fixture {
    _temp: tempfile::TempDir,
    intent: Intent,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let root_dir = fs::Dir::open(&root).unwrap();
        let state = root_dir.directory("state").unwrap();
        let watched = root.join("watched");
        stdfs::create_dir(&watched).unwrap();
        let path = watched.join("sample.txt");
        stdfs::write(&path, CONTENTS).unwrap();
        let intent = Intent {
            verifier: Some(Verifier::Local),
            schema: 1,
            command_id: "1".repeat(64),
            quarantine_id: "1".repeat(64),
            operation: Operation::Quarantine,
            state: state.path.clone(),
            path,
            roots: vec![watched],
            sha256: format!("{:x}", Sha256::digest(CONTENTS)),
        };
        drop(state);
        drop(root_dir);
        Self {
            _temp: temp,
            intent,
        }
    }
    fn retained(&self) -> PathBuf {
        self.intent
            .state
            .join("quarantine")
            .join(&self.intent.quarantine_id)
    }
    fn restore(&self) -> Intent {
        let mut intent = self.intent.clone();
        intent.operation = Operation::Restore;
        intent.verifier = Some(Verifier::Retained);
        intent.command_id = "2".repeat(64);
        intent
    }
    fn cut(&self, intent: &Intent, phase: &str) {
        let mut observed = false;
        assert!(
            apply_inner(intent, false, Duration::from_secs(10), &mut |here| {
                if here == phase {
                    observed = true;
                    return Err("simulated worker interruption".into());
                }
                Ok(())
            })
            .is_err()
        );
        assert!(observed, "checkpoint {phase} was not reached");
    }
}
#[test]
fn windows_quarantine_recovers_every_checkpoint_without_replaying_source_capture() {
    for phase in ["prepared", "captured", "ready", "retained", "complete"] {
        let f = Fixture::new();
        f.cut(&f.intent, phase);
        let report = apply(&f.intent, true, Duration::from_secs(10)).unwrap();
        if phase == "prepared" {
            assert_eq!(report.outcome, Outcome::Unconfirmed);
            assert_eq!(stdfs::read(&f.intent.path).unwrap(), CONTENTS);
            assert!(!f.retained().exists());
        } else {
            assert_eq!(report.outcome, Outcome::Completed);
            assert!(!report.cleanup_pending);
            assert!(!f.intent.path.exists());
            assert_eq!(stdfs::read(f.retained()).unwrap(), CONTENTS);
            let repeated = apply(&f.intent, true, Duration::from_secs(10)).unwrap();
            assert_eq!(repeated.finished_ms, report.finished_ms);
        }
    }
}
#[test]
fn windows_restore_recovers_only_already_published_bytes() {
    for phase in ["prepared", "ready", "published", "complete"] {
        let f = Fixture::new();
        apply(&f.intent, false, Duration::from_secs(10)).unwrap();
        let restore = f.restore();
        f.cut(&restore, phase);
        let report = apply(&restore, true, Duration::from_secs(10)).unwrap();
        if ["prepared", "ready"].contains(&phase) {
            assert_eq!(report.outcome, Outcome::Unconfirmed);
            assert!(!f.intent.path.exists());
            assert_eq!(stdfs::read(f.retained()).unwrap(), CONTENTS);
        } else {
            assert_eq!(report.outcome, Outcome::Completed);
            assert!(!report.cleanup_pending);
            assert_eq!(stdfs::read(&f.intent.path).unwrap(), CONTENTS);
            assert!(!f.retained().exists());
        }
    }
}
#[test]
fn windows_capture_binds_the_original_file_and_retains_independent_bytes() {
    let f = Fixture::new();
    let mut writer = stdfs::OpenOptions::new()
        .write(true)
        .open(&f.intent.path)
        .unwrap();
    let original = fs::identity(&writer).unwrap();
    let alias = f.intent.roots[0].join("old-alias");
    stdfs::hard_link(&f.intent.path, &alias).unwrap();
    let report = apply(&f.intent, false, Duration::from_secs(10)).unwrap();
    assert_eq!(report.outcome, Outcome::Completed);
    assert!(!report.cleanup_pending);
    let retained = stdfs::File::open(f.retained()).unwrap();
    assert!(!fs::same_node(&original, &fs::identity(&retained).unwrap()));
    writer
        .write_all(b"changed through the original handle")
        .unwrap();
    writer.sync_all().unwrap();
    assert_eq!(stdfs::read(f.retained()).unwrap(), CONTENTS);
    drop(retained);
    drop(writer);
    let restore = f.restore();
    stdfs::write(&f.intent.path, b"unrelated replacement").unwrap();
    assert!(apply(&restore, false, Duration::from_secs(10)).is_err());
    assert_eq!(
        stdfs::read(&f.intent.path).unwrap(),
        b"unrelated replacement"
    );
    assert_eq!(stdfs::read(f.retained()).unwrap(), CONTENTS);
}
#[test]
fn windows_changed_source_and_parent_cannot_authorize_a_different_mutation() {
    let f = Fixture::new();
    let old = f.intent.path.with_extension("old");
    assert!(
        apply_inner(&f.intent, false, Duration::from_secs(10), &mut |phase| {
            if phase == "prepared" {
                stdfs::rename(&f.intent.path, &old)?;
                stdfs::write(&f.intent.path, b"unapproved replacement")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(
        stdfs::read(&f.intent.path).unwrap(),
        b"unapproved replacement"
    );
    assert_eq!(stdfs::read(&old).unwrap(), CONTENTS);
    assert_eq!(
        apply(&f.intent, true, Duration::from_secs(10))
            .unwrap()
            .outcome,
        Outcome::Unconfirmed
    );
    let old_parent = f.intent.roots[0].with_extension("old");
    stdfs::rename(&f.intent.roots[0], old_parent).unwrap();
    stdfs::create_dir(&f.intent.roots[0]).unwrap();
    assert!(apply(&f.intent, true, Duration::from_secs(10)).is_err());
}
#[test]
fn windows_streams_reparse_points_and_aliases_cannot_bypass_scope_or_retention() {
    let f = Fixture::new();
    let stream = format!("{}:alternate", f.intent.path.display());
    stdfs::write(&stream, b"must not be discarded").unwrap();
    assert!(apply(&f.intent, false, Duration::from_secs(10))
        .unwrap_err()
        .to_string()
        .contains("alternate data streams"));
    assert_eq!(stdfs::read(&stream).unwrap(), b"must not be discarded");
    let outside = f._temp.path().join("outside.txt");
    stdfs::write(&outside, CONTENTS).unwrap();
    let link = f.intent.roots[0].join("link.txt");
    std::os::windows::fs::symlink_file(&outside, &link)
        .expect("native fixture needs Windows symlink privilege or Developer Mode");
    let mut intent = f.intent.clone();
    intent.path = link;
    assert!(apply(&intent, false, Duration::from_secs(10)).is_err());
    intent.path = outside.clone();
    assert!(apply(&intent, false, Duration::from_secs(10)).is_err());
    assert_eq!(stdfs::read(outside).unwrap(), CONTENTS);
    // Physical directory identity, not case-sensitive string-prefix checks,
    // excludes state even when the configured root uses another spelling.
    intent = f.intent.clone();
    intent.roots = vec![PathBuf::from(
        f._temp
            .path()
            .canonicalize()
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase(),
    )];
    assert!(apply(&intent, false, Duration::from_secs(10)).is_err());
}
#[test]
fn windows_untrusted_state_and_journal_acls_refuse_without_replaying_mutations() {
    let f = Fixture::new();
    grant_everyone(&f.intent.state);
    assert!(apply(&f.intent, false, Duration::from_secs(10))
        .unwrap_err()
        .to_string()
        .contains("grants access outside"));
    assert_eq!(stdfs::read(&f.intent.path).unwrap(), CONTENTS);
    assert!(!f.retained().exists());

    let f = Fixture::new();
    f.cut(&f.intent, "captured");
    let record = f
        .intent
        .state
        .join("quarantine/operations")
        .join(format!("{}.json", f.intent.command_id));
    grant_everyone(&record);
    assert!(apply(&f.intent, true, Duration::from_secs(10))
        .unwrap_err()
        .to_string()
        .contains("grants access outside"));
    let capture = f
        .intent
        .state
        .join("quarantine")
        .join(format!(".capture-{}", f.intent.quarantine_id));
    assert_eq!(stdfs::read(capture).unwrap(), CONTENTS);
    assert!(!f.retained().exists());
    assert!(!f.intent.path.exists());
}
#[test]
fn windows_private_journal_and_worker_lock_preserve_unresolved_work() {
    let f = Fixture::new();
    f.cut(&f.intent, "captured");
    let journal = f.intent.state.join("quarantine/operations");
    let lock = stdfs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(journal.join("worker.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    assert!(apply(&f.intent, true, Duration::from_secs(10))
        .unwrap_err()
        .to_string()
        .contains("still owns"));
    lock.unlock().unwrap();
    drop(lock);
    let record = journal.join(format!("{}.json", f.intent.command_id));
    let mut value: serde_json::Value =
        serde_json::from_slice(&stdfs::read(&record).unwrap()).unwrap();
    value["record"]["phase"] = "complete".into();
    stdfs::write(record, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(apply(&f.intent, true, Duration::from_secs(10)).is_err());
    assert!(!f.retained().exists());
    assert_eq!(
        stdfs::read(
            f.intent
                .state
                .join("quarantine")
                .join(format!(".capture-{}", f.intent.quarantine_id))
        )
        .unwrap(),
        CONTENTS
    );
}
