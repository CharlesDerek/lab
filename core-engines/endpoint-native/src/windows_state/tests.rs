//! Native Windows sharing and filesystem behavior; cross-linking is not execution.
use super::*;
use serde_json::json;
use std::{sync::Arc, thread};

#[test]
fn private_snapshots_allow_atomic_replacement_and_locks_exclude_other_owners() {
    let temp = tempfile::tempdir().unwrap();
    let parent = Dir::open(&temp.path().canonicalize().unwrap()).unwrap();
    let private = parent.directory("private").unwrap();
    let path = private.path.clone();
    drop(private);
    let state = Arc::new(Directory::open(&path).unwrap());
    let lease = state.lock("service.lock").unwrap();
    assert!(state.lock("service.lock").is_err());
    drop(lease);
    drop(state.lock("service.lock").unwrap());
    state
        .write_json("status.json", &json!({"generation":0}))
        .unwrap();
    let reader_state = state.clone();
    let reader = thread::spawn(move || {
        for _ in 0..100 {
            let value: serde_json::Value = reader_state.read_json("status.json").unwrap();
            assert!(value["generation"].as_u64().unwrap() <= 100);
        }
    });
    for generation in 1..=100 {
        state
            .write_json("status.json", &json!({"generation":generation}))
            .unwrap();
    }
    reader.join().unwrap();
    let pinned = PinnedDirectory::open(&path).unwrap();
    assert!(pinned.nt().unwrap().starts_with("\\Device\\"));
    assert!(pinned.dos().unwrap().as_bytes().get(1) == Some(&b':'));
    assert!(std::fs::rename(&path, temp.path().join("moved")).is_err());
}

fn pin_snapshot_destination(path: &std::path::Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path)
        .unwrap()
}

#[test]
fn private_snapshot_replacement_waits_for_a_temporary_destination_reader() {
    use std::{sync::mpsc, time::Duration};
    let temp = tempfile::tempdir().unwrap();
    let state =
        Arc::new(Directory::create_under(&temp.path().canonicalize().unwrap(), "private").unwrap());
    state
        .write_json("status.json", &json!({"generation": 0}))
        .unwrap();
    let reader = pin_snapshot_destination(&state.path().join("status.json"));
    let writer_state = state.clone();
    let (sender, receiver) = mpsc::channel();
    let writer = thread::spawn(move || {
        sender
            .send(writer_state.write_json("status.json", &json!({"generation": 1})))
            .unwrap();
    });
    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(150)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(
        state.read_json::<serde_json::Value>("status.json").unwrap(),
        json!({"generation": 0})
    );
    drop(reader);
    receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap();
    writer.join().unwrap();
    assert_eq!(
        state.read_json::<serde_json::Value>("status.json").unwrap(),
        json!({"generation": 1})
    );
    assert!(!state.path().join(".status.json.new").exists());
}

#[test]
fn private_snapshot_replacement_refuses_a_persistent_reader_without_losing_state() {
    use std::time::{Duration, Instant};
    let temp = tempfile::tempdir().unwrap();
    let state = Directory::create_under(&temp.path().canonicalize().unwrap(), "private").unwrap();
    state
        .write_json("status.json", &json!({"generation": 0}))
        .unwrap();
    let reader = pin_snapshot_destination(&state.path().join("status.json"));
    let started = Instant::now();
    assert!(state
        .write_json("status.json", &json!({"generation": 1}))
        .is_err());
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(
        state.read_json::<serde_json::Value>("status.json").unwrap(),
        json!({"generation": 0})
    );
    // Preserve the existing journal recovery contract: failure leaves the
    // complete private candidate while the old published destination survives.
    assert_eq!(
        state
            .read_json::<serde_json::Value>(".status.json.new")
            .unwrap(),
        json!({"generation": 1})
    );
    drop(reader);
    state
        .write_json("status.json", &json!({"generation": 2}))
        .unwrap();
    assert_eq!(
        state.read_json::<serde_json::Value>("status.json").unwrap(),
        json!({"generation": 2})
    );
    assert!(!state.path().join(".status.json.new").exists());
}

#[test]
fn maintenance_objects_keep_service_compatible_permissions_for_elevated_creators() {
    use crate::windows_scanner;
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        CheckTokenMembership, GetAce, GetSecurityDescriptorOwner, IsWellKnownSid,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    };
    let admins = windows_scanner::descriptor("O:BA").unwrap();
    let (mut admin_sid, mut defaulted) = (null_mut(), 0);
    assert_ne!(
        unsafe { GetSecurityDescriptorOwner(admins.0, &mut admin_sid, &mut defaulted) },
        0
    );
    let mut administrator = 0;
    assert_ne!(
        unsafe { CheckTokenMembership(null_mut(), admin_sid, &mut administrator) },
        0
    );
    let owner = if require_local_system().is_ok() {
        Some(WinLocalSystemSid)
    } else if administrator != 0 {
        Some(WinBuiltinAdministratorsSid)
    } else {
        None
    };
    let temp = tempfile::tempdir().unwrap();
    let endpoint =
        Directory::create_under(&temp.path().canonicalize().unwrap(), "private").unwrap();
    let directory = endpoint.maintenance_directory("protection").unwrap();
    let lease = directory.maintenance_lock("supervisor.lock").unwrap();
    directory
        .write_maintenance_json("installer.json", &json!({"phase":"preparing"}))
        .unwrap();
    directory
        .write_maintenance("agent.exe", b"first snapshot")
        .unwrap();
    directory
        .write_maintenance("agent.exe", b"replacement snapshot")
        .unwrap();
    let journal = directory.read("installer.json").unwrap();
    let binary = directory.read("agent.exe").unwrap();
    let package = directory.create_maintenance("package.msi").unwrap();
    assert_eq!(
        std::fs::read(directory.path().join("agent.exe")).unwrap(),
        b"replacement snapshot"
    );
    assert!(directory.lock("supervisor.lock").is_err());
    if let Some(expected_owner) = owner {
        directory.require_service_access().unwrap();
        for file in [&directory.0.file, &lease, &journal, &binary, &package] {
            let (mut owner, mut dacl, mut raw) = (null_mut(), null_mut(), null_mut());
            assert_eq!(
                unsafe {
                    GetSecurityInfo(
                        file.as_raw_handle(),
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &mut owner,
                        null_mut(),
                        &mut dacl,
                        null_mut(),
                        &mut raw,
                    )
                },
                0
            );
            let _descriptor = windows_scanner::Allocation(raw);
            assert_ne!(unsafe { IsWellKnownSid(owner, expected_owner) }, 0);
            assert!(!dacl.is_null());
            assert_eq!(unsafe { (*dacl).AceCount }, 2);
            let mut principals = Vec::new();
            for index in 0..2 {
                let mut ace = null_mut();
                assert_ne!(unsafe { GetAce(dacl, index, &mut ace) }, 0);
                let header = unsafe { &*ace.cast::<ACE_HEADER>() };
                assert_eq!(header.AceType, 0); // ACCESS_ALLOWED_ACE_TYPE
                assert!(header.AceSize as usize >= size_of::<ACCESS_ALLOWED_ACE>());
                let sid = unsafe {
                    std::ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast()
                };
                principals.push(if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0 {
                    "system"
                } else if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0 {
                    "administrators"
                } else {
                    panic!("maintenance object grants access to an individual/unexpected account");
                });
            }
            principals.sort();
            assert_eq!(principals, ["administrators", "system"]);
        }
    }
    drop(lease);
    // Ordinary service-side opens recognize the exact same lease object.
    let service = directory.lock("supervisor.lock").unwrap();
    assert!(directory.maintenance_lock("supervisor.lock").is_err());
    drop(service);
}

#[test]
fn machine_installation_requires_effective_full_access_for_system_and_administrators() {
    use crate::windows_scanner;
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::{
        Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    if require_administrator().is_err() {
        return; // This fixture edits ownership only on a newly created test directory.
    }
    let temp = tempfile::tempdir().unwrap();
    let directory =
        Directory::create_under(&std::path::absolute(temp.path()).unwrap(), "private").unwrap();
    let owner = if require_local_system().is_ok() {
        "SY"
    } else {
        "BA"
    };
    for (grants, accepted) in [
        ("(A;;FR;;;SY)(A;;FA;;;BA)", false),
        ("(A;;FA;;;SY)(A;;FR;;;BA)", false),
        ("(A;;FA;;;SY)(A;OICIIO;FA;;;BA)", false),
        ("(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", false),
        ("(A;;FA;;;SY)(A;;FA;;;BA)", true),
    ] {
        let descriptor = windows_scanner::descriptor(&format!("O:{owner}D:P{grants}")).unwrap();
        let (mut owner, mut dacl, mut present, mut defaulted) = (null_mut(), null_mut(), 0, 0);
        assert_ne!(
            unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) },
            0
        );
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
            },
            0
        );
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    directory.0.file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    owner,
                    null_mut(),
                    dacl,
                    null_mut(),
                )
            },
            0
        );
        assert_eq!(
            directory.require_service_access().is_ok(),
            accepted,
            "{grants}"
        );
    }
}

#[test]
fn ordinary_shared_admission_excludes_deployment_until_every_holder_releases() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        Directory::maintenance_under(&temp.path().canonicalize().unwrap(), "admission").unwrap();
    let second = Directory::open(root.path()).unwrap();
    let first = root.maintenance_shared_lock("global.lock").unwrap();
    let other = second.maintenance_shared_lock("global.lock").unwrap();
    assert!(root.maintenance_lock("global.lock").is_err());
    first.unlock().unwrap();
    drop(first);
    assert!(root.maintenance_lock("global.lock").is_err());
    other.unlock().unwrap();
    drop(other);
    let deployment = root.maintenance_lock("global.lock").unwrap();
    assert!(second.maintenance_shared_lock("global.lock").is_err());
    assert!(second.maintenance_lock("global.lock").is_err());
    deployment.unlock().unwrap();
    drop(deployment);
    let ordinary = second.maintenance_shared_lock("global.lock").unwrap();
    ordinary.unlock().unwrap();
}

#[test]
fn recorded_receipt_move_recovers_only_the_owned_inode_and_preserves_foreign_names() {
    use athernex_endpoint_protocol::{hash, windows_filter_package::Member};
    use std::io::Read;
    let temp = tempfile::tempdir().unwrap();
    let root =
        Directory::maintenance_under(&temp.path().canonicalize().unwrap(), "receipts").unwrap();
    let expected = Member {
        bytes: 4,
        sha256: hash(b"safe"),
    };
    root.publish_maintenance("staged", b"safe").unwrap();
    let f = root.read("staged").unwrap();
    let (volume, id) = crate::windows_filter_package::identity(&f).unwrap();
    drop(f);
    assert!(root
        .publish_recorded_receipt("staged", "final", volume, [0; 16], &expected)
        .is_err());
    root.publish_recorded_receipt("staged", "final", volume, id, &expected)
        .unwrap();
    assert!(!root.path().join("staged").exists());
    // Lost final journal transition: confirm the exact final inode and sync again.
    root.publish_recorded_receipt("staged", "final", volume, id, &expected)
        .unwrap();
    root.publish_maintenance("foreign", b"safe").unwrap();
    assert!(root
        .publish_recorded_receipt("missing", "foreign", volume, id, &expected)
        .is_err());
    root.publish_maintenance("another-staged", b"safe").unwrap();
    let f = root.read("another-staged").unwrap();
    let (v, other) = crate::windows_filter_package::identity(&f).unwrap();
    drop(f);
    assert!(root
        .publish_recorded_receipt("another-staged", "foreign", v, other, &expected)
        .is_err());
    assert!(root.path().join("another-staged").exists());
    let mut bytes = String::new();
    root.read("foreign")
        .unwrap()
        .read_to_string(&mut bytes)
        .unwrap();
    assert_eq!(bytes, "safe");
    assert!(root
        .publish_recorded_receipt(
            "another-staged",
            "next",
            v,
            other,
            &Member {
                bytes: 4,
                sha256: hash(b"evil")
            }
        )
        .is_err());
}
