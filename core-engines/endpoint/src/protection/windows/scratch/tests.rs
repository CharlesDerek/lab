//! These opt-in tests need LocalSystem/session zero and create only a private
//! 256 MiB disk. The real formatter/worker runs inside the production owned job.
use super::*;
use std::{fs::File, io::Write};

fn fixture_invocation(name: &str, temporary: &Path) -> crate::Process {
    let mut command = command(&std::env::current_exe().unwrap(), temporary).unwrap();
    command.args([
        "--exact",
        name,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    command
}

#[test]
#[ignore = "internal owned scratch worker fixture"]
fn owned_worker_fixture() {
    let Ok(parent) = std::env::var("ATHERNEX_SCRATCH_TEST_PARENT") else {
        return;
    };
    worker_main(parent.parse().unwrap()).unwrap();
}

// On failure, distinguish a volume/device denial from scratch ACL/inheritance.
// Probe only this fixture's checked path; report masks/error codes, never names.
fn scratch_access_probe(path: &Path) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::*;
    for access in [
        READ_CONTROL,
        FILE_READ_ATTRIBUTES,
        FILE_LIST_DIRECTORY,
        FILE_TRAVERSE,
    ] {
        for overlapped in [0, FILE_FLAG_OVERLAPPED] {
            let result = std::fs::OpenOptions::new()
                .access_mode(access)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | overlapped,
                )
                .open(path);
            eprintln!(
                "scratch directory access mask={access:#x}, overlapped={}, error={:?}",
                overlapped != 0,
                result.err().and_then(|e| e.raw_os_error())
            );
        }
    }
    eprintln!(
        "scratch metadata error={:?}",
        std::fs::metadata(path).err().and_then(|e| e.raw_os_error())
    );
    eprintln!(
        "existing scratch file read error={:?}",
        std::fs::read(path.join("existing-proof"))
            .err()
            .and_then(|e| e.raw_os_error())
    );
    eprintln!(
        "existing scratch file write error={:?}",
        std::fs::write(path.join("existing-proof"), b"scanner fixture bytes")
            .err()
            .and_then(|e| e.raw_os_error())
    );
    let alternative = PathBuf::from(std::env::var_os("ATHERNEX_SCRATCH_TEST_NT_PATH").unwrap());
    eprintln!(
        "checked NT scratch metadata error={:?}",
        std::fs::metadata(&alternative)
            .err()
            .and_then(|e| e.raw_os_error())
    );
    let created = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(alternative.join("alternative-proof"));
    match created {
        Ok(mut file) => {
            file.write_all(b"fixture").unwrap();
            drop(file);
            std::fs::remove_file(alternative.join("alternative-proof")).unwrap();
            eprintln!("checked NT scratch create/write/remove passed");
        }
        Err(error) => eprintln!("checked NT scratch create error={:?}", error.raw_os_error()),
    }
}

fn checked_nt_path(ready: &Health, token: &Token) -> PathBuf {
    use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::{
        Security::{ImpersonateLoggedOnUser, RevertToSelf},
        Storage::FileSystem::*,
    };
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&ready.path)
        .unwrap();
    let mut name = [0u16; 4096];
    let n = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            name.as_mut_ptr(),
            name.len() as u32,
            VOLUME_NAME_NT,
        )
    } as usize;
    assert!(n > 0 && n < name.len());
    let name = std::ffi::OsString::from_wide(&name[..n]);
    let name = name.to_str().unwrap();
    let number = name
        .strip_prefix(r"\Device\HarddiskVolume")
        .unwrap()
        .strip_suffix(r"\scratch")
        .unwrap();
    assert!(!number.is_empty() && number.len() <= 10 && number.bytes().all(|v| v.is_ascii_digit()));
    let path = PathBuf::from(format!(r"\\?\GLOBALROOT{name}"));
    let alternative = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
        .unwrap();
    let mut identity = FILE_ID_INFO::default();
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                alternative.as_raw_handle(),
                FileIdInfo,
                (&mut identity as *mut FILE_ID_INFO).cast(),
                std::mem::size_of_val(&identity) as u32,
            )
        },
        0
    );
    assert_eq!(identity.VolumeSerialNumber, ready.directory.volume);
    assert_eq!(identity.FileId.Identifier, ready.directory.file_id);
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    assert_ne!(
        unsafe { ImpersonateLoggedOnUser(token.handle().as_raw_handle()) },
        0
    );
    let _restore = Restore;
    for (kind, candidate) in [("guid", &ready.path), ("nt", &path)] {
        let result = std::fs::metadata(candidate);
        eprintln!(
            "impersonated scratch metadata kind={kind}, error={:?}",
            result.err().and_then(|e| e.raw_os_error())
        );
    }
    // Keep no inherited handles: the child receives only this identity-checked
    // string, and its normal restricted token still authorizes every operation.
    path
}

fn scratch_acl_probe(ready: &Health, token: &Token) {
    use std::{
        mem::size_of_val,
        os::windows::{
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        ptr::null_mut,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
    };
    let mut raw_token = null_mut();
    assert_ne!(
        unsafe {
            DuplicateToken(
                token.handle().as_raw_handle(),
                SecurityImpersonation,
                &mut raw_token,
            )
        },
        0
    );
    let impersonation = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut privilege = TOKEN_PRIVILEGES::default();
    let mut returned = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                impersonation.as_raw_handle(),
                TokenPrivileges,
                (&mut privilege as *mut TOKEN_PRIVILEGES).cast(),
                size_of_val(&privilege) as u32,
                &mut returned,
            )
        },
        0
    );
    assert_eq!(privilege.PrivilegeCount, 1);
    eprintln!(
        "scanner retained privilege enabled={}",
        privilege.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED != 0
    );
    let objects = [
        ("root", ready.target.volume.clone()),
        ("scratch", ready.path.to_str().unwrap().to_owned()),
        (
            "volume-device",
            ready.target.volume.trim_end_matches('\\').to_owned(),
        ),
        (
            "physical-device",
            format!(r"\\.\PhysicalDrive{}", ready.target.disk_number),
        ),
    ];
    struct Descriptor(*mut std::ffi::c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    for (kind, path) in objects {
        let opened = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path);
        let file = match opened {
            Ok(file) => file,
            Err(error) => {
                eprintln!(
                    "scratch ACL object={kind}, open error={:?}",
                    error.raw_os_error()
                );
                continue;
            }
        };
        let mut raw = null_mut();
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut raw,
            )
        };
        let descriptor = Descriptor(raw);
        if error != 0 {
            eprintln!("scratch ACL object={kind}, query error={error}");
            continue;
        }
        for access in [FILE_TRAVERSE, FILE_READ_ATTRIBUTES, FILE_ADD_FILE] {
            let mapping = GENERIC_MAPPING {
                GenericRead: FILE_GENERIC_READ,
                GenericWrite: FILE_GENERIC_WRITE,
                GenericExecute: FILE_GENERIC_EXECUTE,
                GenericAll: FILE_ALL_ACCESS,
            };
            let mut privileges = [0u64; 128];
            let mut length = size_of_val(&privileges) as u32;
            let (mut granted, mut allowed) = (0, 0);
            assert_ne!(
                unsafe {
                    AccessCheck(
                        descriptor.0,
                        impersonation.as_raw_handle(),
                        access,
                        &mapping,
                        privileges.as_mut_ptr().cast(),
                        &mut length,
                        &mut granted,
                        &mut allowed,
                    )
                },
                0
            );
            eprintln!("scratch ACL object={kind}, access={access:#x}, allowed={allowed}, granted={granted:#x}");
        }
    }
}

fn raw_device_access_is_denied() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::*,
    };
    let devices: [String; 2] =
        serde_json::from_str(&std::env::var("ATHERNEX_SCRATCH_TEST_DEVICES").unwrap()).unwrap();
    for device in devices {
        for access in [
            GENERIC_READ,
            GENERIC_WRITE,
            FILE_READ_DATA,
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_ATTRIBUTES,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            let result = std::fs::OpenOptions::new()
                .access_mode(access)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&device);
            assert_eq!(
                result.err().and_then(|error| error.raw_os_error()),
                Some(5),
                "raw scratch device access must be denied for mask {access:#x}"
            );
        }
    }
}

#[test]
#[ignore = "internal restricted scratch filesystem fixture"]
fn restricted_io_fixture() {
    let Some(path) = std::env::var_os("ATHERNEX_SCRATCH_TEST_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    raw_device_access_is_denied();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join("capacity-proof"));
    if std::env::var_os("ATHERNEX_SCRATCH_TEST_DENIED").is_some() {
        assert!(
            file.is_err(),
            "another logon could write to the scratch disk"
        );
        println!("other-logon-denied");
        return;
    }
    if file.is_err() {
        scratch_access_probe(&path);
    }
    let mut file = file.unwrap();
    let block = vec![0x4a; 4 * 1024 * 1024];
    let mut written = 0;
    let error = loop {
        match file.write_all(&block) {
            Ok(()) => {
                written += block.len();
                assert!(
                    written <= 256 * 1024 * 1024,
                    "scratch disk escaped its virtual capacity"
                );
            }
            Err(error) => break error,
        }
    };
    assert!(written >= 64 * 1024 * 1024);
    assert_eq!(
        error.raw_os_error(),
        Some(112),
        "failure must be native disk full, not an unrelated write error"
    );
    drop(file);
    assert!(std::fs::rename(&path, path.with_file_name("changed")).is_err());
    assert!(std::fs::read_dir(path.parent().unwrap()).is_err());
    // Opening the root itself for FILE_WRITE_DATA must fail: otherwise a
    // compromised scanner could submit FSCTL_SET_REPARSE_POINT on that handle.
    {
        use std::{
            os::windows::ffi::OsStrExt,
            ptr::{null, null_mut},
        };
        use windows_sys::Win32::{
            Foundation::{GetLastError, INVALID_HANDLE_VALUE},
            Storage::FileSystem::*,
        };
        let wide: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_WRITE_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        assert_eq!(raw, INVALID_HANDLE_VALUE);
        assert!([5, 32].contains(&unsafe { GetLastError() }));
    }
    std::fs::remove_file(path.join("capacity-proof")).unwrap();
    println!("native-scratch-disk-full-and-root-protection-proven");
}

fn run_scanner(state: &Directory, token: &Token, ready: &Health, denied: bool) {
    let path = &ready.path;
    let nt_path = checked_nt_path(ready, token);
    let devices = [
        ready.target.volume.trim_end_matches('\\').to_owned(),
        format!(r"\\.\PhysicalDrive{}", ready.target.disk_number),
    ];
    // Positive controls use only the worker's identity-checked volume/disk.
    // Failure under the scanner must be access denied, never a missing device.
    for device in &devices {
        File::open(device).unwrap();
    }
    let staging = state
        .scanner_workspace(&format!("scanner-{}", secret().unwrap()), token)
        .unwrap();
    let mut source = File::open(std::env::current_exe().unwrap()).unwrap();
    staging
        .copy("fixture.exe", &mut source, &mut (192 * 1024 * 1024))
        .unwrap();
    let mut command = command(&staging.path().join("fixture.exe"), path).unwrap();
    command
        .args([
            "--exact",
            "protection::windows::scratch::tests::restricted_io_fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ATHERNEX_SCRATCH_TEST_PATH", path)
        .env("ATHERNEX_SCRATCH_TEST_NT_PATH", nt_path)
        .env(
            "ATHERNEX_SCRATCH_TEST_DEVICES",
            serde_json::to_string(&devices).unwrap(),
        );
    if denied {
        command.env("ATHERNEX_SCRATCH_TEST_DENIED", "yes");
    }
    let mut scanner = Service::start_scanner(&command, token, 8192, |_, _| Ok(())).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(code) = scanner.poll().unwrap() {
            assert_eq!(code, 0, "{}", String::from_utf8_lossy(scanner.output()));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "restricted scratch fixture timed out"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let output = String::from_utf8_lossy(scanner.output());
    assert!(
        output.contains(if denied {
            "other-logon-denied"
        } else {
            "native-scratch-disk-full-and-root-protection-proven"
        }),
        "{output}"
    );
    let identity = staging.identity().unwrap();
    let leaf = staging
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    drop(scanner);
    drop(staging);
    state
        .remove_scanner_workspace(&leaf, Some(&identity))
        .unwrap();
}

#[test]
#[ignore = "requires native Windows LocalSystem/session zero; formats and fills one new private 256 MiB scratch disk"]
fn owned_worker_formats_bounds_scanner_writes_and_recovers_only_after_exit() {
    let _serial = windows_job::TEST_SERIAL.lock().unwrap();
    let token = Token::new().unwrap();
    let retained = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
    eprintln!(
        "native scratch fixture retained on failure: {}",
        retained.display()
    );
    let state = Directory::create_under(&retained, "private").unwrap();
    let _lease = state.lock("supervisor.lock").unwrap();
    let id = secret().unwrap();
    let spec = Spec {
        schema: 1,
        id: id.clone(),
        bytes: 256 * 1024 * 1024,
    };
    let runtime = state.directory("scratch-runtime").unwrap();
    let container = Directory::create_under(runtime.path(), &format!("scanner-{id}")).unwrap();
    let record = Record {
        schema: 1,
        spec: spec.clone(),
        directory: container.identity().unwrap(),
        logon: token.logon_sid().into(),
        owner: None,
        image_ready: false,
    };
    record
        .save(&state.directory("scratch-journal").unwrap())
        .unwrap();
    drop(container);
    let temporary = state.directory("worker-temporary").unwrap();
    let mut invocation = fixture_invocation(
        "protection::windows::scratch::tests::owned_worker_fixture",
        temporary.path(),
    );
    invocation.env(
        "ATHERNEX_SCRATCH_TEST_PARENT",
        std::process::id().to_string(),
    );
    let request = Request {
        schema: 1,
        state: state.path().into(),
        id: id.clone(),
    };
    let mut worker = Service::start(
        &invocation,
        Some(&serde_json::to_vec(&request).unwrap()),
        8192,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    let ready = loop {
        check_running(&mut worker, "scratch fixture worker").unwrap();
        if let Ok(ready) = health(&state, &id, token.logon_sid()) {
            break ready;
        }
        assert!(
            Instant::now() < deadline,
            "scratch worker failed to publish readiness: {}",
            String::from_utf8_lossy(worker.output())
        );
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(ready.worker_pid, worker.id());
    assert_eq!(ready.worker_created, worker.creation_time().unwrap());
    let mut stale = ready.clone();
    stale.checked_ms = now_ms().saturating_sub(6000);
    assert!(validate_observation(&state, &stale, token.logon_sid()).is_err());
    let mut changed = ready.clone();
    changed.directory.file_id[0] ^= 0xff;
    assert!(validate_observation(&state, &changed, token.logon_sid()).is_err());
    assert!(recovery::clean(&state).is_err());
    scratch_acl_probe(&ready, &token);
    run_scanner(&state, &Token::new().unwrap(), &ready, true);
    // Inherited access on an existing SYSTEM-created child is an independent
    // diagnostic of the scanner's create-file permissions on the directory.
    std::fs::write(ready.path.join("existing-proof"), b"system fixture bytes").unwrap();
    run_scanner(&state, &token, &ready, false);
    health(&state, &id, token.logon_sid()).unwrap();
    let network = state.directory("network").unwrap();
    network
        .write_json("retained.json", &serde_json::json!({"unreconciled":true}))
        .unwrap();
    worker.stop().unwrap();
    assert!(recovery::clean(&state).is_err());
    assert!(runtime
        .path()
        .join(format!("scanner-{id}"))
        .join(native::IMAGE)
        .exists());
    network.remove("retained.json").unwrap();
    assert_eq!(recovery::clean(&state).unwrap(), 1);
    assert_eq!(recovery::clean(&state).unwrap(), 0);
    assert!(names(&runtime).unwrap().is_empty());
    assert!(names(&state.directory("scratch-journal").unwrap())
        .unwrap()
        .is_empty());
    assert!(names(&state.directory("scratch-health").unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn scratch_journal_rejects_impossible_ownership_and_changed_identity() {
    let spec = Spec {
        schema: 1,
        id: "a".repeat(64),
        bytes: 256 * 1024 * 1024,
    };
    let mut record = Record {
        schema: 1,
        spec,
        directory: WorkspaceIdentity {
            volume: 1,
            file_id: [1; 16],
        },
        logon: "S-1-5-5-0-123".into(),
        owner: None,
        image_ready: false,
    };
    record.validate(&record.spec.id).unwrap();
    record.image_ready = true;
    assert!(record.validate(&record.spec.id).is_err());
    record.owner = Some(Owner { pid: 4, created: 1 });
    assert!(record.validate(&record.spec.id).is_err());
    record.owner = Some(Owner {
        pid: 100,
        created: 1,
    });
    record.validate(&record.spec.id).unwrap();
    assert!(record.validate(&"b".repeat(64)).is_err());
    let mut value = serde_json::to_value(record).unwrap();
    value["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Record>(value).is_err());
}

#[test]
#[ignore = "requires native Windows LocalSystem; checks partial-image recovery without attaching or formatting a disk"]
fn recovery_preserves_live_corrupt_changed_and_pinned_images_and_replays_deletion() {
    let _serial = windows_job::TEST_SERIAL.lock().unwrap();
    athernex_endpoint_native::windows_state::require_local_system().unwrap();
    let retained = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
    let state = Directory::create_under(&retained, "private").unwrap();
    let runtime = state.directory("scratch-runtime").unwrap();
    let journal = state.directory("scratch-journal").unwrap();
    let id = secret().unwrap();
    let leaf = format!("scanner-{id}");
    let directory = Directory::create_under(runtime.path(), &leaf).unwrap();
    let root_id = directory.identity().unwrap();
    let mut partial = directory.create(native::IMAGE).unwrap();
    partial
        .write_all(b"interrupted private image creation")
        .unwrap();
    partial.sync_all().unwrap();
    drop(partial);
    drop(directory);
    let created = peer::identify(std::process::id()).unwrap();
    let mut record = Record {
        schema: 1,
        spec: Spec {
            schema: 1,
            id: id.clone(),
            bytes: 256 * 1024 * 1024,
        },
        directory: root_id.clone(),
        logon: "S-1-5-5-0-123".into(),
        owner: Some(Owner {
            pid: std::process::id(),
            created,
        }),
        image_ready: false,
    };
    record.save(&journal).unwrap();
    assert!(
        recovery::clean(&state).is_err(),
        "live original owner must prevent cleanup"
    );
    // Model a reused PID: the original creation time no longer names this
    // process. Recovery must not kill or otherwise alter the current process.
    record.owner.as_mut().unwrap().created -= 1;
    record.image_ready = true;
    record.save(&journal).unwrap();
    assert!(
        recovery::clean(&state).is_err(),
        "an image-ready record must not adopt a corrupt image"
    );
    assert_eq!(
        std::fs::read(runtime.path().join(&leaf).join(native::IMAGE)).unwrap(),
        b"interrupted private image creation"
    );
    record.image_ready = false;
    record.directory.file_id[0] ^= 0xff;
    record.save(&journal).unwrap();
    assert!(recovery::clean(&state).is_err());
    record.directory = root_id;
    record.save(&journal).unwrap();
    let directory = Directory::open(&runtime.path().join(&leaf)).unwrap();
    let pin = directory.read(native::IMAGE).unwrap();
    drop(directory);
    assert!(
        recovery::clean(&state).is_err(),
        "an existing image handle must block exclusive deletion"
    );
    assert!(journal.path().join(format!("{id}.json")).exists());
    drop(pin);
    assert_eq!(recovery::clean(&state).unwrap(), 1);
    assert!(!runtime.path().join(&leaf).exists());
    record.image_ready = true;
    record.save(&journal).unwrap();
    assert_eq!(
        recovery::clean(&state).unwrap(),
        1,
        "root-deleted/journal-retained interruption must replay"
    );
    assert_eq!(recovery::clean(&state).unwrap(), 0);

    let orphan = Directory::create_under(runtime.path(), &leaf).unwrap();
    drop(orphan.create(native::IMAGE).unwrap());
    drop(orphan);
    assert!(
        recovery::clean(&state).is_err(),
        "unrecorded nonempty containers must be retained"
    );
    let orphan = Directory::open(&runtime.path().join(&leaf)).unwrap();
    orphan.remove(native::IMAGE).unwrap();
    drop(orphan);
    assert_eq!(recovery::clean(&state).unwrap(), 1);
}
