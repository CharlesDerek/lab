//! Opt-in native tests create only new private VHDX files. They never accept a
//! host disk number, attach an existing image, format a volume, or change policy.
//! The keep-on-failure fixture leaves its private evidence available for review.
use super::*;
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_NO_TOKEN},
    Security::TOKEN_QUERY,
    System::Threading::{GetCurrentThread, OpenThreadToken},
};

struct Fixture {
    path: PathBuf,
    spec: Spec,
}
impl Fixture {
    fn new() -> Self {
        crate::windows_state::require_local_system().unwrap();
        let path = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
        let directory = Directory::create_under(&path, "private").unwrap();
        let mut random = [0; 32];
        getrandom::fill(&mut random).unwrap();
        let spec = Spec {
            schema: 1,
            id: random.iter().map(|b| format!("{b:02x}")).collect(),
            bytes: 256 * MIB,
        };
        drop(directory);
        eprintln!("scratch fixture (retained on failure): {}", path.display());
        Self { path, spec }
    }
    fn directory(&self) -> Directory {
        Directory::open(&self.path.join("private")).unwrap()
    }
    fn create(&self) -> FreshDisk {
        FreshDisk::create(self.directory(), self.spec.clone()).unwrap()
    }
    fn remove(self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match require_detached(self.directory(), self.spec.clone()) {
                Ok(()) => break,
                Err(error) if Instant::now() >= deadline => panic!("{error}"),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        let directory = self.directory();
        directory.remove(IMAGE).unwrap();
        // Only a known helper proof can remain; never recursively traverse an
        // unexpected tree while cleaning a privileged native-test fixture.
        if directory.path().join("attached.json").exists() {
            directory.remove("attached.json").unwrap();
        }
        drop(directory);
        std::fs::remove_dir(self.path.join("private")).unwrap();
        std::fs::remove_dir(self.path).unwrap();
    }
}
fn no_thread_impersonation() {
    let mut raw = null_mut();
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    if result != 0 {
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
    }
    assert_eq!(result, 0, "scratch operation left a thread token installed");
    assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);
}

#[test]
#[ignore = "requires native Windows LocalSystem; reserves a private 256 MiB VHDX"]
fn fixed_image_capacity_identity_and_detached_recovery_are_verified() {
    let f = Fixture::new();
    no_thread_impersonation();
    {
        use std::io::Write;
        let directory = f.directory();
        let mut partial = directory.create(IMAGE).unwrap();
        partial.write_all(b"incomplete creation fixture").unwrap();
        partial.sync_all().unwrap();
        drop(partial);
        assert!(FreshDisk::create(f.directory(), f.spec.clone()).is_err());
        assert!(require_detached(f.directory(), f.spec.clone()).is_err());
        assert_eq!(
            std::fs::read(directory.path().join(IMAGE)).unwrap(),
            b"incomplete creation fixture"
        );
        directory.remove(IMAGE).unwrap();
    }
    let fresh = f.create();
    fresh.0.verify().unwrap();
    let original_size = std::fs::metadata(f.directory().path().join(IMAGE))
        .unwrap()
        .len();
    assert!((f.spec.bytes..=f.spec.bytes + MAX_OVERHEAD).contains(&original_size));
    assert!(FreshDisk::create(f.directory(), f.spec.clone()).is_err());
    assert_eq!(
        std::fs::metadata(f.directory().path().join(IMAGE))
            .unwrap()
            .len(),
        original_size
    );
    let attached = fresh.attach().unwrap();
    no_thread_impersonation();
    attached.verify().unwrap();
    assert!(require_detached(f.directory(), f.spec.clone()).is_err());
    assert!(std::fs::rename(
        f.directory().path().join(IMAGE),
        f.directory().path().join("changed.vhdx")
    )
    .is_err());
    attached.detach().unwrap();
    no_thread_impersonation();
    require_detached(f.directory(), f.spec.clone()).unwrap();
    let mut changed = f.spec.clone();
    changed.id = if changed.id == "a".repeat(64) {
        "b".repeat(64)
    } else {
        "a".repeat(64)
    };
    assert!(require_detached(f.directory(), changed).is_err());
    let mut changed = f.spec.clone();
    changed.bytes += MIB;
    assert!(require_detached(f.directory(), changed).is_err());
    f.remove();
}

#[test]
#[ignore = "requires native Windows LocalSystem; initializes only a new private scratch disk"]
fn fresh_disk_gpt_and_discovered_volume_remain_bound_to_the_created_image() {
    // Refuse nonempty primary/backup regions even if the provider reports no
    // partitions. These writes target only this test's newly created VHDX.
    use std::os::windows::fs::FileExt;
    for backup in [false, true] {
        let f = Fixture::new();
        let disk = f.create().attach().unwrap();
        let offset = if backup { f.spec.bytes - 512 } else { 512 };
        let mut marker = [0u8; 512];
        marker[0] = 0x5a;
        assert_eq!(
            disk.physical.seek_write(&marker, offset).unwrap(),
            marker.len()
        );
        disk.physical.sync_all().unwrap();
        let error = disk
            .initialize()
            .err()
            .expect("Nonempty headers were overwritten");
        assert_eq!(error.to_string(), "Scratch partition headers are not empty");
        f.remove();
    }
    let f = Fixture::new();
    let disk = f.create().attach().unwrap().initialize().unwrap();
    no_thread_impersonation();
    disk.verify().unwrap();
    let volume = disk.discover().unwrap();
    volume.verify().unwrap();
    crate::windows_scratch_spec::volume_name(&volume.target().volume).unwrap();
    assert!(volume.target().bytes < f.spec.bytes);
    assert_eq!(volume.target().offset, 17 * MIB);
    assert!(require_detached(f.directory(), f.spec.clone()).is_err());
    volume.detach().unwrap();
    no_thread_impersonation();
    f.remove();
}

#[test]
#[ignore = "internal native scratch attachment owner-exit helper"]
fn attachment_owner_exit_fixture() {
    let Some(path) = std::env::var_os("ATHERNEX_SCRATCH_FIXTURE_PATH") else {
        return;
    };
    let spec: Spec =
        serde_json::from_str(&std::env::var("ATHERNEX_SCRATCH_FIXTURE_SPEC").unwrap()).unwrap();
    let directory = Directory::open(Path::new(&path)).unwrap();
    let disk = FreshDisk::create(directory, spec)
        .unwrap()
        .attach()
        .unwrap();
    disk.verify().unwrap();
    disk.container()
        .write_json("attached.json", disk.spec())
        .unwrap();
    // Deliberately bypass every Rust destructor. The OS must release the
    // non-permanent VHDX attachment when the original handle owner exits.
    std::process::exit(0);
}

#[test]
#[ignore = "requires native Windows LocalSystem; verifies attachment owner process exit"]
fn owner_process_exit_releases_the_nonpermanent_scratch_attachment() {
    let f = Fixture::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "windows_scratch::tests::attachment_owner_exit_fixture",
            "--ignored",
            "--test-threads=1",
        ])
        .env("ATHERNEX_SCRATCH_FIXTURE_PATH", f.directory().path())
        .env(
            "ATHERNEX_SCRATCH_FIXTURE_SPEC",
            serde_json::to_string(&f.spec).unwrap(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("native scratch owner fixture exceeded its deadline; private evidence retained");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let proof: Spec = f.directory().read_json("attached.json").unwrap();
    assert_eq!(proof.id, f.spec.id);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match require_detached(f.directory(), f.spec.clone()) {
            Ok(()) => break,
            Err(error) if Instant::now() >= deadline => {
                panic!("owner exit did not release scratch attachment: {error}")
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    f.remove();
}
