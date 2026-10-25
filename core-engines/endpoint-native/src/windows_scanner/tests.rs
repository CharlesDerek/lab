//! Explicit native gates. Run only as LocalSystem in service session zero;
//! ordinary CI users must not report these checks as successful.
use super::*;
use crate::{mutation::fs::Dir, windows_state::Directory};
use std::{fs, io::Write};
use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};

fn impersonate<T>(token: &Token, work: impl FnOnce() -> T) -> T {
    impersonate_handle(token.handle(), work)
}
fn impersonate_handle<T>(token: BorrowedHandle<'_>, work: impl FnOnce() -> T) -> T {
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // Continuing in the wrong security context is never a safe test
            // failure. This guard also runs if an assertion panics.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
    let _revert = Revert;
    work()
}

#[test]
#[ignore = "requires native Windows LocalSystem session zero; creates temporary scanner workspace"]
fn scanner_reads_copies_writes_scratch_and_cannot_read_private_state_or_change_engine() {
    let token = Token::new().unwrap();
    let other = Token::new().unwrap();
    let (other_unrestricted, _) = logon().unwrap();
    assert_ne!(
        token.logon_sid(),
        other.logon_sid(),
        "Separate logons must not share workspace access"
    );
    assert!(verify(token.handle(), other.logon_sid()).is_err());
    let temporary = tempfile::tempdir().unwrap();
    let parent = Dir::open(&temporary.path().canonicalize().unwrap()).unwrap();
    let private = parent.directory("private").unwrap();
    let state = Directory::open(&private.path).unwrap();
    let mut credentials = state.create("credentials.json").unwrap();
    credentials
        .write_all(b"private endpoint credentials")
        .unwrap();
    credentials.sync_all().unwrap();
    drop(credentials);
    let workspace = state.scanner_workspace("scanner", &token).unwrap();
    assert!(
        state.scanner_workspace("scanner", &token).is_err(),
        "Never adopt an existing shared workspace"
    );
    assert!(
        Directory::open(workspace.path()).is_err(),
        "Shared scanner ACLs must not satisfy private state checks"
    );
    let engine = workspace.directory("engine", false).unwrap();
    let scratch = workspace.directory("scratch", true).unwrap();
    engine.write("engine.dll", b"fixture-engine").unwrap();
    let source = state.create("source").unwrap();
    drop(source);
    let mut source = state.read("source").unwrap();
    engine.copy("empty", &mut source, &mut 0).unwrap();
    let private_path = state.path().join("credentials.json");
    let image = engine.path().join("engine.dll");
    let output = scratch.path().join("scan.tmp");
    let shared_path = state.path().join("public-medium");
    let mut shared = private.create_for_scanner("public-medium").unwrap();
    shared.write_all(b"public fixture bytes").unwrap();
    public_fixture(&shared, "(A;;FA;;;BU)");
    drop(shared);
    let authenticated_path = state.path().join("authenticated-only");
    let authenticated = private.create_for_scanner("authenticated-only").unwrap();
    public_fixture(&authenticated, "(A;;FRFX;;;AU)");
    drop(authenticated);
    impersonate(&token, || {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
        assert_eq!(fs::read(&image).unwrap(), b"fixture-engine");
        assert_eq!(fs::read(&shared_path).unwrap(), b"public fixture bytes");
        assert_eq!(
            fs::write(&shared_path, b"changed").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(fs::OpenOptions::new()
            .access_mode(WRITE_DAC)
            .open(&shared_path)
            .is_err());
        assert!(fs::remove_file(&shared_path).is_err());
        assert_eq!(
            fs::read(&authenticated_path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            fs::read(&private_path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            fs::write(&image, b"changed").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(fs::remove_file(&image).is_err());
        assert!(fs::write(engine.path().join("injected.dll"), b"bad").is_err());
        fs::write(&output, b"scratch").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"scratch");
    });
    impersonate(&other, || {
        assert!(fs::read(&image).is_err());
        assert!(fs::write(&output, b"other logon").is_err());
    });
    // Check the actual file owner as well as access from a regular LocalService
    // token. A second restricted token alone could mask an owner-rights defect.
    {
        use windows_sys::Win32::Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            OWNER_SECURITY_INFORMATION,
        };
        let file = fs::File::open(&output).unwrap();
        let (mut owner, mut descriptor) = (null_mut(), null_mut());
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        let _descriptor = Allocation(descriptor);
        assert_eq!(sid_text(owner).unwrap(), token.logon_sid());
    }
    impersonate_handle(other_unrestricted.as_handle(), || {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
        assert!(fs::read(&output).is_err());
        assert!(
            fs::OpenOptions::new()
                .read(true)
                .access_mode(READ_CONTROL | WRITE_DAC)
                .open(&output)
                .is_err(),
            "Another LocalService process acquired owner ACL rights"
        );
    });
    impersonate(&token, || fs::remove_file(&output).unwrap());
    assert_eq!(fs::read(&image).unwrap(), b"fixture-engine");
    assert_eq!(fs::read(&shared_path).unwrap(), b"public fixture bytes");
    verify_runtime_reads(&token);
}

// System runtime DLLs must be readable under the actual production token.
// Resolve already loaded modules while still SYSTEM; never change their ACLs.
fn verify_runtime_reads(token: &Token) {
    use std::{
        ffi::OsString,
        os::windows::{ffi::OsStringExt, fs::OpenOptionsExt},
        path::PathBuf,
    };
    use windows_sys::Win32::{
        Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ},
        System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW},
    };
    let mut modules = Vec::new();
    for name in [
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "ucrtbase.dll",
        "vcruntime140.dll",
    ] {
        let wide: Vec<_> = name.encode_utf16().chain([0]).collect();
        let module = unsafe { GetModuleHandleW(wide.as_ptr()) };
        if module.is_null() {
            // GNU and MSVC executables do not use identical CRT dependencies.
            assert!(name == "ucrtbase.dll" || name == "vcruntime140.dll");
            continue;
        }
        let mut path = [0u16; 2048];
        let length =
            unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
        assert!(length > 0 && length < path.len());
        modules.push((name, PathBuf::from(OsString::from_wide(&path[..length]))));
    }
    impersonate(token, || {
        for (name, path) in modules {
            fs::OpenOptions::new()
                .access_mode(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
                .open(path)
                .unwrap_or_else(|error| panic!("Scanner cannot read/execute {name}: {error}"));
        }
    });
}

// Only fresh synthetic fixture files are assigned public ACLs. A low-integrity
// token must still refuse medium-integrity writes even when their DACL allows it.
fn public_fixture(file: &fs::File, grants: &str) {
    use windows_sys::Win32::Security::{
        Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
        GetSecurityDescriptorSacl, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let security = descriptor(&format!("D:P(A;;FA;;;SY){grants}S:(ML;;NW;;;ME)")).unwrap();
    let (mut present, mut defaulted, mut sacl) = (0, 0, null_mut());
    assert_ne!(
        unsafe { GetSecurityDescriptorSacl(security.0, &mut present, &mut sacl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    assert!(!sacl.is_null());
    assert_eq!(
        unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl(&security).unwrap(),
                sacl,
            )
        },
        0
    );
}
