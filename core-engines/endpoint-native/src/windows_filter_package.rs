//! Offline WHQL catalog-policy and exact-member verification. Call only inside
//! the management executable's bounded owned verification worker. This is not
//! Windows Code Integrity/load eligibility, Driver Store staging, or live ABI proof.
use crate::{windows_state::PinnedDirectory, Result};
use athernex_endpoint_protocol::windows_filter_package::{Descriptor, NAMES};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek},
    mem::size_of,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::{
    core::{BOOL, GUID, PCWSTR},
    Win32::{
        Foundation::{FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE},
        Security::{Cryptography::CERT_STRONG_SIGN_PARA, WinTrust::*},
        Storage::FileSystem::*,
        System::LibraryLoader::*,
    },
};

type Acquire = unsafe extern "system" fn(
    *mut isize,
    *const GUID,
    PCWSTR,
    *const CERT_STRONG_SIGN_PARA,
    u32,
) -> BOOL;
type Hash = unsafe extern "system" fn(isize, HANDLE, *mut u32, *mut u8, u32) -> BOOL;
type Verify = unsafe extern "system" fn(HANDLE, *mut GUID, *mut core::ffi::c_void) -> i32;
type Release = unsafe extern "system" fn(isize, u32) -> BOOL;
struct Api {
    module: HMODULE,
    acquire: Acquire,
    hash: Hash,
    release: Release,
    verify: Verify,
}
impl Api {
    fn load() -> Result<Self> {
        let module = unsafe {
            LoadLibraryExW(
                windows_sys::core::w!("wintrust.dll"),
                null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err("Driver trust provider unavailable".into());
        }
        // Public APIs documented as dynamically linked. No layout casts or
        // current-directory DLL search. Every exact signature is SDK-bound.
        let addresses = unsafe {
            [
                GetProcAddress(module, c"CryptCATAdminAcquireContext2".as_ptr().cast()),
                GetProcAddress(
                    module,
                    c"CryptCATAdminCalcHashFromFileHandle2".as_ptr().cast(),
                ),
                GetProcAddress(module, c"CryptCATAdminReleaseContext".as_ptr().cast()),
                GetProcAddress(module, c"WinVerifyTrust".as_ptr().cast()),
            ]
        };
        let [Some(a), Some(h), Some(r), Some(v)] = addresses else {
            unsafe { FreeLibrary(module) };
            return Err("Driver trust API unavailable".into());
        };
        Ok(Self {
            module,
            acquire: unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Acquire>(a)
            },
            hash: unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, Hash>(h) },
            release: unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Release>(r)
            },
            verify: unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Verify>(v)
            },
        })
    }
}
impl Drop for Api {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}
struct Context<'a> {
    api: &'a Api,
    handle: isize,
}
impl Drop for Context<'_> {
    fn drop(&mut self) {
        unsafe { (self.api.release)(self.handle, 0) };
    }
}
fn wide(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut s: Vec<_> = path.as_os_str().encode_wide().collect();
    if !path.is_absolute() || s.contains(&0) || s.len() > 32760 {
        return Err("Invalid driver verification path".into());
    }
    s.push(0);
    Ok(s)
}
/// Pins the path against write/delete replacement and rejects aliases/reparse leaves.
/// The caller retains the parent directory pin separately.
pub fn pin(
    path: &Path,
    expected: &athernex_endpoint_protocol::windows_filter_package::Member,
) -> Result<File> {
    let mut f = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| "Cannot pin driver package member")?;
    let m = f
        .metadata()
        .map_err(|_| "Cannot inspect driver package member")?;
    let mut info = FILE_STANDARD_INFO::default();
    if !m.is_file()
        || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || m.len() != expected.bytes
        || m.len() > 64 * 1024 * 1024
        || unsafe {
            GetFileInformationByHandleEx(
                f.as_raw_handle(),
                FileStandardInfo,
                (&mut info as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        } == 0
        || info.NumberOfLinks != 1
    {
        return Err("Driver package member is not an immutable regular file".into());
    }
    crate::mutation::fs::unnamed_stream_only(&f)?;
    let mut bytes = Vec::new();
    (&mut f)
        .take(expected.bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read driver package member")?;
    if bytes.len() as u64 != expected.bytes
        || athernex_endpoint_protocol::hash(&bytes) != expected.sha256
    {
        return Err("Driver package member differs from approval".into());
    }
    f.rewind()
        .map_err(|_| "Cannot rewind driver package member")?;
    Ok(f)
}
pub fn identity(file: &File) -> Result<(u64, [u8; 16])> {
    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err("Driver package identity unavailable".into());
    }
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}
fn member(ctx: &Context<'_>, catalog: &Path, path: &Path, file: &File) -> Result<()> {
    let mut hash = [0u8; 32];
    let mut count = 32;
    if unsafe {
        (ctx.api.hash)(
            ctx.handle,
            file.as_raw_handle(),
            &mut count,
            hash.as_mut_ptr(),
            0,
        )
    } == 0
        || count != 32
    {
        return Err("Driver catalog member hash failed".into());
    }
    let tag = hash.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let tag: Vec<u16> = tag.encode_utf16().chain([0]).collect();
    let cat = wide(catalog)?;
    let name = wide(path)?;
    let mut info = WINTRUST_CATALOG_INFO {
        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
        pcwszCatalogFilePath: cat.as_ptr(),
        pcwszMemberTag: tag.as_ptr(),
        pcwszMemberFilePath: name.as_ptr(),
        hMemberFile: file.as_raw_handle(),
        pbCalculatedFileHash: hash.as_mut_ptr(),
        cbCalculatedFileHash: 32,
        hCatAdmin: ctx.handle,
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &mut info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_CHAIN
            | WTD_USE_DEFAULT_OSVER_CHECK
            | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    };
    let mut action = DRIVER_ACTION_VERIFY;
    let status = unsafe {
        (ctx.api.verify)(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    // CLOSE is required for every VERIFY, even failed/unknown policy outcomes.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let closed = unsafe {
        (ctx.api.verify)(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    if status != 0 || closed != 0 {
        return Err("Offline WHQL driver catalog policy or membership refused".into());
    }
    Ok(())
}
/// Management executable Authenticode is separate from driver catalog policy.
/// The operational caller runs both inside its owned bounded worker.
pub fn verify_executable(
    path: &Path,
    expected: &athernex_endpoint_protocol::windows_filter_package::Member,
) -> Result<()> {
    let file = pin(path, expected)?;
    let name = wide(path)?;
    let api = Api::load()?;
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: name.as_ptr(),
        hFile: file.as_raw_handle(),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_CHAIN
            | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        (api.verify)(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let closed = unsafe {
        (api.verify)(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    if status != 0 || closed != 0 {
        return Err("Offline management Authenticode policy refused".into());
    }
    Ok(())
}
pub fn verify(directory: &Path, descriptor: &Descriptor) -> Result<()> {
    descriptor.validate()?;
    let _parent = PinnedDirectory::open(directory)?;
    let files = descriptor
        .members()
        .iter()
        .zip(NAMES)
        .map(|(m, n)| pin(&directory.join(n), m))
        .collect::<Result<Vec<_>>>()?;
    let api = Api::load()?;
    let mut handle = 0;
    if unsafe {
        (api.acquire)(
            &mut handle,
            &DRIVER_ACTION_VERIFY,
            windows_sys::core::w!("SHA256"),
            null(),
            0,
        )
    } == 0
        || handle == 0
    {
        return Err("SHA256 driver catalog context unavailable".into());
    }
    let ctx = Context { api: &api, handle };
    member(
        &ctx,
        &directory.join(NAMES[2]),
        &directory.join(NAMES[0]),
        &files[0],
    )?;
    member(
        &ctx,
        &directory.join(NAMES[2]),
        &directory.join(NAMES[1]),
        &files[1],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use athernex_endpoint_protocol::windows_filter_package::{Member, PROFILE, TRUST};
    #[test]
    fn create_only_preparation_primitives_never_adopt_or_replace_existing_objects() {
        use crate::windows_state::Directory;
        let temp = tempfile::tempdir().unwrap();
        let parent =
            Directory::maintenance_under(&std::path::absolute(temp.path()).unwrap(), "state")
                .unwrap();
        let child = parent.fresh_maintenance_directory("package").unwrap();
        let before = child.identity().unwrap();
        assert!(parent.fresh_maintenance_directory("package").is_err());
        assert_eq!(child.identity().unwrap(), before);
        child
            .publish_maintenance("member", b"first owned bytes")
            .unwrap();
        let mut original = child.read("member").unwrap();
        let id = identity(&original).unwrap();
        let mut before = Vec::new();
        original.read_to_end(&mut before).unwrap();
        drop(original); // Refusal must come from no-replace, not a held delete-denying handle.
        assert!(child
            .publish_maintenance("member", b"unapproved replacement")
            .is_err());
        let mut original = child.read("member").unwrap();
        let mut bytes = Vec::new();
        original.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, before);
        assert_eq!(bytes, b"first owned bytes");
        assert_eq!(identity(&original).unwrap(), id);
    }
    fn broad_dacl(path: &Path) {
        use windows_sys::Win32::Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    windows_sys::core::w!("D:P(A;;FA;;;WD)"),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let path = wide(path).unwrap();
        let result = unsafe {
            SetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
        assert_ne!(result, 0);
    }
    #[test]
    fn private_catalog_refuses_broad_destination_without_changing_its_acl_or_bytes() {
        use crate::windows_state::Directory;
        let temp = tempfile::tempdir().unwrap();
        let catalog =
            Directory::create_under(&std::path::absolute(temp.path()).unwrap(), "catalog").unwrap();
        catalog.write_private_bytes("release", b"old").unwrap();
        broad_dacl(&catalog.path().join("release"));
        assert!(catalog.write_private_bytes("release", b"new").is_err());
        assert_eq!(
            std::fs::read(catalog.path().join("release")).unwrap(),
            b"old"
        );
        broad_dacl(catalog.path());
        assert!(Directory::open(catalog.path()).is_err());
        assert!(catalog.write_private_bytes("another", b"refused").is_err());
        assert!(!catalog.path().join("another").exists());
    }
    #[test]
    fn private_catalog_updates_preserve_unrelated_entries_and_refuse_linked_targets() {
        use crate::windows_state::Directory;
        let temp = tempfile::tempdir().unwrap();
        let catalog =
            Directory::create_under(&std::path::absolute(temp.path()).unwrap(), "catalog").unwrap();
        catalog
            .write_private_bytes("other-target", b"retained")
            .unwrap();
        catalog.write_private_bytes("release", b"old").unwrap();
        catalog.write_private_bytes("release", b"new").unwrap();
        let mut bytes = Vec::new();
        catalog
            .read("release")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"new");
        bytes.clear();
        catalog
            .read("other-target")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"retained");
        std::fs::hard_link(catalog.path().join("release"), catalog.path().join("alias")).unwrap();
        assert!(catalog
            .write_private_bytes("release", b"must not replace")
            .is_err());
        bytes.clear();
        catalog
            .read("release")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"new");
    }
    #[test]
    fn unsigned_catalog_never_passes_native_driver_policy_and_pins_block_writers() {
        let temp = tempfile::tempdir().unwrap();
        let mut members = Vec::new();
        for (name, bytes) in NAMES.into_iter().zip([
            std::fs::read(std::env::current_exe().unwrap()).unwrap(),
            b"synthetic INF".to_vec(),
            b"unsigned CAT".to_vec(),
        ]) {
            std::fs::write(temp.path().join(name), &bytes).unwrap();
            members.push(Member {
                bytes: bytes.len() as u64,
                sha256: athernex_endpoint_protocol::hash(&bytes),
            });
        }
        let descriptor = Descriptor {
            schema: 1,
            sha256: "a".repeat(64),
            bytes: 32 + members.iter().map(|m| m.bytes).sum::<u64>(),
            profile: PROFILE.into(),
            trust_policy: TRUST.into(),
            source_revision: "b".repeat(40),
            expected_abi: 2,
            deployment: None,
            driver_version: "1.2.3.4".into(),
            driver_date: "01/01/2025".into(),
            altitude: "325000.01".into(),
            sys: members[0].clone(),
            inf: members[1].clone(),
            cat: members[2].clone(),
        };
        let path = temp.path().join(NAMES[0]);
        let held = pin(&path, &descriptor.sys).unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, temp.path().join("moved.sys")).is_err());
        assert_eq!(
            verify(temp.path(), &descriptor).unwrap_err().to_string(),
            "Offline WHQL driver catalog policy or membership refused"
        );
        drop(held);
        let mut stream = path.as_os_str().to_os_string();
        stream.push(":synthetic");
        std::fs::write(&stream, b"alternate stream").unwrap();
        assert!(pin(&path, &descriptor.sys).is_err());
        std::fs::remove_file(&stream).unwrap();
        let mut changed = descriptor.sys.clone();
        changed.sha256 = "c".repeat(64);
        assert!(pin(&path, &changed).is_err());
        std::fs::hard_link(&path, temp.path().join("alias.sys")).unwrap();
        assert!(pin(&path, &descriptor.sys).is_err());
    }
}
