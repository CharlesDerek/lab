//! Real Windows filesystem tests; cross-linking is not native execution.
use super::*;
use crate::windows_scanner::Token;
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::windows::{
        ffi::OsStringExt,
        fs::{symlink_dir, symlink_file, OpenOptionsExt},
    },
};

#[test]
#[ignore = "requires native Windows LocalSystem session zero and symbolic-link privilege"]
fn cleanup_preserves_external_links_streams_attributes_and_retries_pinned_entries() {
    let token = Token::new().unwrap();
    let retained = tempfile::tempdir().unwrap().keep();
    let state = Directory::create_under(&retained.canonicalize().unwrap(), "private").unwrap();
    let runtime = state.directory("runtime").unwrap();
    let outside = state.directory("outside").unwrap();
    let outside_file = outside.path().join("retained.txt");
    fs::write(&outside_file, b"outside bytes").unwrap();
    let stream = outside.path().join("retained.txt:retained");
    fs::write(&stream, b"outside stream").unwrap();
    let mut permissions = fs::metadata(&outside_file).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&outside_file, permissions).unwrap();
    let name = format!("scanner-{}", "a".repeat(64));
    let workspace = runtime.scanner_workspace(&name, &token).unwrap();
    let expected = workspace.identity().unwrap();
    let workspace_path = workspace.path().to_owned();
    let scratch = workspace.directory("temporary", true).unwrap();
    fs::create_dir(scratch.path().join("nested")).unwrap();
    fs::write(scratch.path().join("nested/data"), b"scratch").unwrap();
    fs::hard_link(&outside_file, scratch.path().join("hard-link")).unwrap();
    symlink_file(&outside_file, scratch.path().join("file-link")).unwrap();
    symlink_dir(outside.path(), scratch.path().join("directory-link")).unwrap();
    fs::write(
        scratch.path().join(OsString::from_wide(&[0xd800, 65])),
        b"raw name",
    )
    .unwrap();
    let pinned_path = scratch.path().join("pinned");
    fs::write(&pinned_path, b"pinned").unwrap();
    drop(scratch);
    drop(workspace);

    let mut wrong = expected.clone();
    wrong.file_id[0] ^= 1;
    assert!(runtime
        .remove_scanner_workspace(&name, Some(&wrong))
        .is_err());
    assert!(runtime.remove_scanner_workspace(&name, None).is_err());
    assert!(pinned_path.exists());

    let pinned = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&pinned_path)
        .unwrap();
    assert!(runtime
        .remove_scanner_workspace(&name, Some(&expected))
        .is_err());
    assert!(workspace_path.exists());
    assert_eq!(fs::read(&outside_file).unwrap(), b"outside bytes");
    drop(pinned);
    runtime
        .remove_scanner_workspace(&name, Some(&expected))
        .unwrap();
    runtime
        .remove_scanner_workspace(&name, Some(&expected))
        .unwrap();
    assert!(!workspace_path.exists());
    assert_eq!(fs::read(&outside_file).unwrap(), b"outside bytes");
    assert_eq!(fs::read(&stream).unwrap(), b"outside stream");
    assert!(fs::metadata(&outside_file)
        .unwrap()
        .permissions()
        .readonly());
    assert!(outside.path().exists());
}

#[test]
#[ignore = "requires native Windows LocalSystem session zero and symbolic-link privilege"]
fn cleanup_refuses_root_redirection_and_reclaims_only_empty_unrecorded_orphans() {
    let token = Token::new().unwrap();
    let retained = tempfile::tempdir().unwrap().keep();
    let state = Directory::create_under(&retained.canonicalize().unwrap(), "private").unwrap();
    let runtime = state.directory("runtime").unwrap();
    let name = format!("scanner-{}", "b".repeat(64));
    let workspace = runtime.scanner_workspace(&name, &token).unwrap();
    drop(workspace);
    runtime.remove_scanner_workspace(&name, None).unwrap();
    let workspace = runtime.scanner_workspace(&name, &token).unwrap();
    workspace
        .write("retained", b"unrecorded nonempty tree")
        .unwrap();
    drop(workspace);
    assert!(runtime.remove_scanner_workspace(&name, None).is_err());
    assert!(runtime.path().join(&name).join("retained").exists());
    let link_name = format!("scanner-{}", "c".repeat(64));
    symlink_dir(runtime.path().join(&name), runtime.path().join(&link_name)).unwrap();
    assert!(runtime.remove_scanner_workspace(&link_name, None).is_err());
    assert!(runtime.path().join(&name).join("retained").exists());
    assert!(runtime
        .remove_scanner_workspace("scanner-../outside", None)
        .is_err());

    // Real handle enumeration with an exhausted budget must retain the tree.
    let leaf: Vec<_> = name.encode_utf16().collect();
    let directory = open(&runtime.0.file, &leaf, true).unwrap();
    let volume = identity(&directory).unwrap().volume;
    assert!(clear(
        &directory,
        volume,
        0,
        &mut Budget {
            operations: 16384,
            deadline: Instant::now() + Duration::from_secs(1)
        }
    )
    .is_err());
    assert!(runtime.path().join(&name).join("retained").exists());
    // The opened directory pins its name while its children are enumerated.
    assert!(fs::rename(runtime.path().join(&name), runtime.path().join("moved")).is_err());
    drop(directory);
    let mut artifact = state.create("fixture-note.txt").unwrap();
    artifact
        .write_all(b"Retained root-redirection fixture for native inspection")
        .unwrap();
}
