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
    impersonate(&token, || {
        assert_eq!(fs::read(&image).unwrap(), b"fixture-engine");
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
    if let Err(error) = log_runtime_read_candidate(&token, &private_path) {
        eprintln!("Scanner runtime read diagnostic failed: {error}");
    }
}

// Test-only investigation of the native STATUS_DLL_NOT_FOUND failure. This
// candidate token is never launched or returned to production code. Compare
// read/execute opens only; do not modify any system ACL or scanner policy.
fn log_runtime_read_candidate(current: &Token, private: &std::path::Path) -> Result<()> {
    use std::{
        ffi::OsString,
        os::windows::{ffi::OsStringExt, fs::OpenOptionsExt},
        path::PathBuf,
    };
    use windows_sys::Win32::{
        Security::WinBuiltinUsersSid,
        Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ},
        System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW},
    };
    let (original, logon) = logon()?;
    let user = query(original.as_raw_handle(), TokenUser)?;
    if unsafe { IsWellKnownSid(value::<TOKEN_USER>(&user)?.User.Sid, WinLocalServiceSid) } == 0 {
        return Err("Runtime probe did not receive a LocalService token".into());
    }
    let data = query(original.as_raw_handle(), TokenGroups)?;
    let entries = groups(&data)?;
    let users_enabled = entries.iter().any(|g| {
        (unsafe { IsWellKnownSid(g.Sid, WinBuiltinUsersSid) != 0 })
            && g.Attributes & SE_GROUP_ENABLED as u32 != 0
    });
    eprintln!("Scanner runtime probe: original BuiltinUsers enabled={users_enabled}");
    if !users_enabled {
        return Err("Runtime probe requires an existing enabled BuiltinUsers group".into());
    }
    let disabled: Vec<_> = entries
        .iter()
        .filter(|g| !retained(g) && unsafe { IsWellKnownSid(g.Sid, WinBuiltinUsersSid) == 0 })
        .copied()
        .collect();
    let world = sid("S-1-1-0")?;
    let users = sid("S-1-5-32-545")?;
    let logon_sid = sid(&logon)?;
    let restricted = [world.0, users.0, logon_sid.0].map(|sid| SID_AND_ATTRIBUTES {
        Sid: sid,
        Attributes: 0,
    });
    let mut raw = null_mut();
    if unsafe {
        CreateRestrictedToken(
            original.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            disabled.len() as u32,
            disabled.as_ptr(),
            0,
            null(),
            restricted.len() as u32,
            restricted.as_ptr(),
            &mut raw,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let candidate = unsafe { OwnedHandle::from_raw_handle(raw) };
    drop(original);
    let low = sid("S-1-16-4096")?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low.0,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    if unsafe {
        SetTokenInformation(
            candidate.as_raw_handle(),
            TokenIntegrityLevel,
            (&label as *const TOKEN_MANDATORY_LABEL).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low.0),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
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
            eprintln!("Scanner runtime probe {name}: not loaded in parent");
            continue;
        }
        let mut path = [0u16; 2048];
        let length =
            unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
        if length == 0 || length >= path.len() {
            return Err("Runtime probe could not resolve an existing module".into());
        }
        modules.push((name, PathBuf::from(OsString::from_wide(&path[..length]))));
    }
    for (label, token) in [
        ("current", current.handle()),
        ("BuiltinUsers candidate", candidate.as_handle()),
    ] {
        impersonate_handle(token, || {
            for (name, path) in &modules {
                let result = fs::OpenOptions::new()
                    .access_mode(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
                    .open(path)
                    .map(|_| ())
                    .map_err(|e| e.raw_os_error());
                eprintln!("Scanner runtime probe {label} {name}: {result:?}");
            }
            let private = fs::File::open(private)
                .map(|_| ())
                .map_err(|e| e.raw_os_error());
            eprintln!("Scanner runtime probe {label} private-state read: {private:?}");
        });
    }
    Ok(())
}
