//! Explicit native gate. This starts real preview confinement and uses a loaded
//! driver; the ordinary Windows mutation tests never do so. All evidence and
//! fixture files are retained, including on timeout or failed cleanup.
use super::*;
use athernex_endpoint::protection::{
    windows,
    windows_evidence::{self, Root, Scope},
};
use athernex_endpoint_native::{
    windows_filter::{peer, port::Port},
    windows_state::{Directory, PinnedDirectory},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, Seek, SeekFrom},
    mem::size_of,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    panic::{catch_unwind, AssertUnwindSafe},
    process::{Child, Stdio},
    ptr::null,
    time::Instant,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    },
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{
            CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ,
            MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READONLY,
        },
        RemoteDesktop::ProcessIdToSessionId,
        Threading::GetCurrentProcess,
    },
};

const MARKER: &str = "ATHERNEX_NATIVE_EXECUTION_PROBE_OK";
const REQUIRED_CHECKS: &[&str] = &[
    "clean_and_synthetic_controls_before_activation",
    "clean_read_execution_existing_handle_and_mappings_after_activation",
    "new_read_denied_with_kernel_receipt",
    "execution_denied_with_kernel_receipt",
    "existing_handle_read_denied_with_kernel_receipt",
    "existing_handle_mapping_denied_with_kernel_receipt",
    "existing_view_read_denied_with_kernel_receipt",
    "changed_after_clean_open_denied_with_kernel_receipt",
    "quarantine_with_armed_filter",
    "committed_recovery_keeps_receipt_and_replacement",
    "restore_stays_blocked_with_kernel_receipt",
    "restore_committed_while_filter_remains_armed",
    "filter_session_remained_active",
];

#[derive(Serialize, Deserialize)]
struct Spec {
    schema: u32,
    nonce: String,
    parent: u32,
    parent_created: u64,
    agent: PathBuf,
    state: PathBuf,
    config: Config,
    plan: windows::Plan,
    instance: [u8; 16],
}
#[derive(Serialize, Default)]
struct Report {
    schema: u32,
    nonce: String,
    checked_ms: u64,
    agent_sha256: String,
    test_sha256: String,
    driver_instance: String,
    policy: String,
    session: String,
    checks: BTreeMap<String, serde_json::Value>,
    failure: Option<String>,
    cleanup: Option<String>,
    supervisor_diagnostics: String,
    all_checks_passed: bool,
    production_protection_enabled: bool,
}

fn local(path: &Path) -> PathBuf {
    let text = path.to_str().unwrap();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(text))
}
fn require_host() {
    assert_eq!(
        std::env::var("ATHERNEX_NATIVE_WINDOWS_FIXTURE").as_deref(),
        Ok("1"),
        "Set ATHERNEX_NATIVE_WINDOWS_FIXTURE=1 only on a disposable native host"
    );
    athernex_endpoint_native::windows_state::require_local_system().unwrap();
    let mut session = u32::MAX;
    assert_ne!(
        unsafe { ProcessIdToSessionId(std::process::id(), &mut session) },
        0
    );
    assert_eq!(
        session, 0,
        "Native scanner fixture requires LocalSystem session zero"
    );
}

#[test]
#[ignore = "Requires a disposable native Windows host, LocalSystem session zero, private ClamAV and an already loaded ABI2 driver"]
fn native_windows_protection_and_response() {
    require_host();
    let port = Port::connect().expect("Load the development driver separately before this fixture");
    let initial = port.status().unwrap();
    assert_eq!(
        initial.armed, 0,
        "Never replace an existing protection policy"
    );
    assert_eq!(initial.pending, 0);
    drop(port);
    let mut f = Fixture::new();
    let root = f._temp.as_ref().unwrap().path().canonicalize().unwrap();
    Directory::open(&root).expect("Native fixture root must be private");
    f._temp.as_mut().unwrap().disable_cleanup(true);
    let state = Directory::open(&f.state).unwrap();
    let bin = state.directory("agent").unwrap();
    f.agent = bin.path().join("athernex-endpoint.exe");
    let source_agent = std::env::var_os("ATHERNEX_NATIVE_AGENT")
        .map(PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_athernex-endpoint").into());
    fs::copy(&source_agent, &f.agent).unwrap();
    assert_eq!(
        hash(&fs::read(source_agent).unwrap()),
        hash(&fs::read(&f.agent).unwrap())
    );
    let database = state.directory("fixture-signatures").unwrap();
    let daemon = local(
        &PathBuf::from(
            std::env::var_os("ATHERNEX_WINDOWS_CLAMD")
                .expect("Set ATHERNEX_WINDOWS_CLAMD to a private ClamAV installation"),
        )
        .canonicalize()
        .unwrap(),
    );
    let port_number = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let spec = Spec {
        schema: 1,
        nonce: secret().unwrap(),
        parent: std::process::id(),
        parent_created: peer::identify(std::process::id()).unwrap(),
        agent: f.agent.clone(),
        state: f.state.clone(),
        config: f.config.clone(),
        instance: initial.instance,
        plan: windows::Plan {
            schema: 1,
            roots: f.config.scan_roots.iter().map(|p| local(p)).collect(),
            state: local(&f.state),
            daemon_sha256: hash(&fs::read(&daemon).unwrap()),
            daemon,
            database: local(database.path()),
            port: port_number,
            timeout_ms: 5000,
            startup_secs: 120,
            scanner_isolation: "restricted-local-service".into(),
            scratch_mib: 256,
        },
    };
    state.write_json("native-fixture.json", &spec).unwrap();
    println!("Retained native fixture: {}", root.display());
    let result = run_bounded(
        Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native::native_validation_child",
                "--ignored",
                "--nocapture",
            ])
            .env(
                "ATHERNEX_NATIVE_FIXTURE_SPEC",
                state.path().join("native-fixture.json"),
            ),
        600,
    );
    let (code, output) = result.unwrap_or_else(|error| {
        panic!("Native worker failed: {error}; retained {}", root.display())
    });
    println!("{output}");
    let report: serde_json::Value =
        state
            .read_json("native-validation.json")
            .unwrap_or_else(|error| {
                panic!(
                    "Native worker produced no final report: {error}; retained {}; code {code}",
                    root.display()
                )
            });
    assert_eq!(report["nonce"], spec.nonce);
    assert_eq!(code, 0, "Native report: {report}");
    assert_eq!(report["all_checks_passed"], true, "Native report: {report}");
}

#[test]
#[ignore = "Benign executable fixture child; invoked only by the native validation worker"]
fn executable_probe_child() {
    assert_eq!(
        std::env::var("ATHERNEX_NATIVE_EXECUTION_PROBE").as_deref(),
        Ok("1")
    );
    println!("{MARKER}");
}

struct Live {
    process: Option<Child>,
    agent: PathBuf,
    state: PathBuf,
    instance: [u8; 16],
    policy: [u8; 32],
    diagnostics: Arc<Mutex<Vec<u8>>>,
}
impl Live {
    fn finish(&mut self) -> athernex_endpoint::Result<()> {
        if let Some(process) = self.process.as_mut() {
            if process.try_wait()?.is_none() {
                process.kill()?;
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while process.try_wait()?.is_none() {
                if Instant::now() >= deadline {
                    return Err("Owned preview did not exit".into());
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        let port = loop {
            match Port::connect() {
                Ok(port) => break port,
                Err(error) if Instant::now() >= deadline => return Err(error),
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        };
        let status = port.status()?;
        if status.instance != self.instance
            || (status.armed == 1
                && (self.process.is_none() || status.policy_sha256 != self.policy))
        {
            return Err("Driver or policy changed; refusing to disarm unrelated protection".into());
        }
        if status.armed == 1 {
            port.disarm()?;
        }
        if port.status()?.armed != 0 {
            return Err("Fixture policy did not disarm".into());
        }
        drop(port);
        let (code, output) = run_bounded(
            Process::new(&self.agent)
                .arg("windows-protection-recover")
                .arg(&self.state),
            60,
        )?;
        if code != 0 {
            return Err(format!("Native recovery failed ({code}): {output}").into());
        }
        Ok(())
    }
}
impl Drop for Live {
    fn drop(&mut self) {
        // Do not disarm or delete anything from a destructor. On panic, stop
        // only our own process; the explicit recovery report retains uncertainty.
        if let Some(process) = self.process.as_mut() {
            let _ = process.kill();
        }
    }
}

#[derive(Clone)]
struct Target {
    path: PathBuf,
    sha256: String,
    bytes: Vec<u8>,
    volume: u64,
    file_id: String,
    detection: String,
}
impl Target {
    fn capture(path: PathBuf, detection: &str) -> Self {
        let file = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .open(&path)
            .unwrap();
        let mut id = FILE_ID_INFO::default();
        assert_ne!(
            unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    FileIdInfo,
                    (&mut id as *mut FILE_ID_INFO).cast(),
                    size_of::<FILE_ID_INFO>() as u32,
                )
            },
            0
        );
        let bytes = fs::read(&path).unwrap();
        Self {
            detection: detection.into(),
            sha256: hash(&bytes),
            path,
            bytes,
            volume: id.VolumeSerialNumber,
            file_id: athernex_endpoint_native::windows_filter::evidence::hex(&id.FileId.Identifier),
        }
    }
}
struct View {
    _mapping: OwnedHandle,
    address: MEMORY_MAPPED_VIEW_ADDRESS,
    bytes: usize,
}
impl Drop for View {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.address);
        }
    }
}
impl View {
    fn new(file: &fs::File, bytes: usize) -> io::Result<Self> {
        let mapping = unsafe {
            CreateFileMappingW(file.as_raw_handle(), null(), PAGE_READONLY, 0, 0, null())
        };
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mapping = unsafe { OwnedHandle::from_raw_handle(mapping) };
        let view = unsafe { MapViewOfFile(mapping.as_raw_handle(), FILE_MAP_READ, 0, 0, bytes) };
        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _mapping: mapping,
            address: view,
            bytes,
        })
    }
    fn read(&self) -> io::Result<Vec<u8>> {
        let mut copied = 0;
        let mut output = vec![0; self.bytes];
        let success = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                self.address.Value,
                output.as_mut_ptr().cast(),
                self.bytes,
                &mut copied,
            )
        };
        let error = io::Error::last_os_error();
        if success == 0 {
            return Err(error);
        }
        if copied != self.bytes {
            return Err(io::Error::other("Partial mapped probe read"));
        }
        Ok(output)
    }
}
fn mapped(file: &fs::File, bytes: usize) -> io::Result<Vec<u8>> {
    View::new(file, bytes)?.read()
}
fn execute(path: &Path) -> athernex_endpoint::Result<()> {
    let (code, output) = run_bounded(
        Process::new(path)
            .args([
                "--exact",
                "native::executable_probe_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ATHERNEX_NATIVE_EXECUTION_PROBE", "1"),
        10,
    )?;
    if code != 0 || !output.contains(MARKER) {
        return Err("Executable probe did not complete its benign child".into());
    }
    Ok(())
}

fn read_denial(
    f: &Fixture,
    live: &windows::Status,
    scope: &Scope,
    target: &Target,
    start: u64,
    actor: u32,
    created: u64,
) -> Option<serde_json::Value> {
    let state = Directory::open(&f.state.join("protection/windows")).unwrap();
    let connection = Connection::open(state.database_path("evidence.sqlite3").unwrap()).unwrap();
    connection.busy_timeout(Duration::from_secs(2)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let rows = connection
            .prepare("SELECT payload FROM decisions ORDER BY rowid DESC LIMIT 2048")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        for raw in rows {
            let receipt: windows_evidence::Receipt = serde_json::from_str(&raw).unwrap();
            let e = &receipt.observation;
            if receipt.session == live.session
                && e.policy_sha256 == live.policy_sha256
                && e.checked_ms >= start
                && e.checked_ms <= now_ms()
                && e.actor_pid == u64::from(actor)
                && e.actor_created == created
                && e.volume == target.volume
                && e.file_id == target.file_id
                && e.bytes == target.bytes.len() as u64
                && e.sha256 == target.sha256
                && e.outcome == "denied_malware"
                && e.detection.as_deref() == Some(&target.detection)
                && windows_evidence::prefix_equal(
                    &scope.path(&e.path).unwrap(),
                    local(&target.path).to_str().unwrap(),
                )
                && receipt.event(scope).is_ok()
            {
                return Some(serde_json::to_value(receipt).unwrap());
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn probe(
    report: &mut Report,
    f: &Fixture,
    live: &windows::Status,
    scope: &Scope,
    label: &str,
    target: &Target,
    operation: impl FnOnce() -> athernex_endpoint::Result<()>,
) {
    let started = now_ms();
    let actor = std::process::id();
    let created = peer::identify(actor).unwrap();
    let result = operation();
    let error = result.as_ref().err();
    let code = error
        .and_then(|e| e.downcast_ref::<io::Error>())
        .and_then(|e| e.raw_os_error());
    let receipt = if code == Some(5) {
        read_denial(f, live, scope, target, started, actor, created)
    } else {
        None
    };
    report.checks.insert(label.into(), serde_json::json!({"passed":code==Some(5)&&receipt.is_some(),
        "operation_allowed":result.is_ok(),"win32_error":code,"error":error.map(|e|e.to_string()),"receipt":receipt,
        "path":target.path,"sha256":target.sha256,"actor_pid":actor,"actor_created":created}));
}

#[test]
#[ignore = "Owned native fixture child; invoked only by native_windows_protection_and_response"]
fn native_validation_child() {
    require_host();
    let spec_path = PathBuf::from(
        std::env::var_os("ATHERNEX_NATIVE_FIXTURE_SPEC").expect("Missing private fixture spec"),
    );
    let directory = Directory::open(spec_path.parent().unwrap()).unwrap();
    let spec: Spec = directory.read_json("native-fixture.json").unwrap();
    assert_eq!(spec.schema, 1);
    assert_eq!(peer::identify(spec.parent).unwrap(), spec.parent_created);
    let pin = PinnedDirectory::open(&spec.plan.roots[0]).unwrap();
    let scope = Scope {
        roots: vec![Root {
            nt: pin.nt().unwrap(),
            dos: pin.dos().unwrap(),
        }],
        timeout_ms: spec.plan.timeout_ms,
    };
    let mut live = Live {
        process: None,
        agent: spec.agent.clone(),
        state: spec.state.clone(),
        instance: spec.instance,
        policy: scope.config().unwrap().policy_sha256,
        diagnostics: Arc::new(Mutex::new(Vec::new())),
    };
    let mut report = Report {
        schema: 1,
        nonce: spec.nonce.clone(),
        agent_sha256: hash(&fs::read(&spec.agent).unwrap()),
        test_sha256: hash(&fs::read(std::env::current_exe().unwrap()).unwrap()),
        driver_instance: athernex_endpoint_native::windows_filter::evidence::hex(&spec.instance),
        policy: scope.digest().unwrap(),
        ..Report::default()
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        exercise(&spec, &scope, &mut live, &mut report)
    }));
    if let Err(error) = result {
        report.failure = Some(
            error
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "Native fixture panicked".into()),
        );
    }
    report.cleanup = live.finish().err().map(|e| e.to_string());
    report.supervisor_diagnostics =
        String::from_utf8_lossy(&live.diagnostics.lock().unwrap()).into();
    report.checked_ms = now_ms();
    report.all_checks_passed = report.failure.is_none()
        && report.cleanup.is_none()
        && REQUIRED_CHECKS
            .iter()
            .all(|key| report.checks.contains_key(*key))
        && report.checks.values().all(|v| v["passed"] == true);
    directory
        .write_json("native-validation.json", &report)
        .unwrap();
    assert!(
        report.all_checks_passed,
        "Native gate failed; see {}",
        directory.path().join("native-validation.json").display()
    );
}

fn exercise(spec: &Spec, scope: &Scope, owned: &mut Live, report: &mut Report) {
    let f = Fixture {
        _temp: None,
        agent: spec.agent.clone(),
        state: spec.state.clone(),
        config: spec.config.clone(),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let watched = &spec.plan.roots[0];
    let clean = watched.join("clean.bin");
    fs::write(&clean, b"ordinary native validation content").unwrap();
    // Binary prefix avoids text normalization before whole-file hash matching.
    let mut sample = vec![0, 255, 127, 0];
    sample.extend_from_slice(
        format!(
            "Athernex harmless synthetic Windows signature {}",
            spec.nonce
        )
        .as_bytes(),
    );
    let mut targets = Vec::new();
    for name in [
        "read.bin",
        "existing-read.bin",
        "existing-map.bin",
        "existing-view.bin",
        "quarantine.bin",
    ] {
        let path = watched.join(name);
        fs::write(&path, &sample).unwrap();
        targets.push(Target::capture(path, "AthernexNativeText.UNOFFICIAL"));
    }
    let clean_exec = watched.join("clean.exe");
    let bad_exec = watched.join("signature.exe");
    fs::copy(std::env::current_exe().unwrap(), &clean_exec).unwrap();
    fs::copy(&clean_exec, &bad_exec).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&bad_exec)
        .unwrap()
        .write_all(spec.nonce.as_bytes())
        .unwrap();
    let executable = Target::capture(bad_exec, "AthernexNativeExec.UNOFFICIAL");
    assert_ne!(executable.sha256, hash(&fs::read(&clean_exec).unwrap()));
    execute(&clean_exec).unwrap();
    execute(&executable.path).unwrap();
    let mut existing = fs::File::open(&targets[1].path).unwrap();
    let mapping = fs::File::open(&targets[2].path).unwrap();
    let retained_view =
        View::new(&fs::File::open(&targets[3].path).unwrap(), sample.len()).unwrap();
    assert_eq!(retained_view.read().unwrap(), sample);
    let mut clean_existing = fs::File::open(&clean).unwrap();
    let clean_mapping = fs::File::open(&clean).unwrap();
    let clean_view =
        View::new(&clean_mapping, b"ordinary native validation content".len()).unwrap();
    let changed_path = watched.join("changed-after-clean.bin");
    fs::write(&changed_path, vec![b'x'; sample.len()]).unwrap();
    let mut changed = Target::capture(changed_path, "AthernexNativeText.UNOFFICIAL");
    changed.sha256 = hash(&sample);
    changed.bytes = sample.clone();
    assert_eq!(mapped(&mapping, sample.len()).unwrap(), sample);
    let mut baseline = Vec::new();
    existing.read_to_end(&mut baseline).unwrap();
    assert_eq!(baseline, sample);
    existing.seek(SeekFrom::Start(0)).unwrap();
    let signatures = format!(
        "{}:{}:AthernexNativeText\n{}:{}:AthernexNativeExec\n",
        hash(&sample),
        sample.len(),
        executable.sha256,
        executable.bytes.len()
    );
    Directory::open(&spec.plan.database)
        .unwrap()
        .write_maintenance("fixture.hsb", signatures.as_bytes())
        .unwrap();
    private_write(
        &f.state.join("config.json"),
        &serde_json::to_vec(&f.config).unwrap(),
    )
    .unwrap();
    let directory = Directory::open(&f.state).unwrap();
    directory
        .write_json("preview-plan.json", &spec.plan)
        .unwrap();
    let port = Port::connect().unwrap();
    let initial = port.status().unwrap();
    assert_eq!(initial.instance, spec.instance);
    assert_eq!(initial.armed, 0);
    assert_eq!(initial.pending, 0);
    drop(port);
    report.checks.insert(
        "clean_and_synthetic_controls_before_activation".into(),
        serde_json::json!({"passed":true}),
    );
    owned.process = Some(
        std::process::Command::new(&f.agent)
            .arg("protect-windows-preview")
            .arg(f.state.join("preview-plan.json"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let child = owned.process.as_mut().unwrap();
    for mut input in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let diagnostics = owned.diagnostics.clone();
        thread::spawn(move || {
            let mut buffer = [0; 1024];
            while let Ok(n) = input.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let mut output = diagnostics.lock().unwrap();
                let keep = n.min(16_384usize.saturating_sub(output.len()));
                output.extend_from_slice(&buffer[..keep]);
            }
        });
    }
    let deadline = Instant::now() + Duration::from_secs(135);
    let live = loop {
        assert!(
            owned
                .process
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none(),
            "Preview exited during startup"
        );
        if let Ok(status) = windows::status(&f.state.join("protection/windows")) {
            if status.coverage.state == "active" {
                break status;
            }
        }
        assert!(Instant::now() < deadline, "Preview startup timed out");
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(live.policy_sha256, scope.digest().unwrap());
    assert_eq!(live.kernel.as_ref().unwrap().status.instance, spec.instance);
    report.session = live.session.clone();
    assert_eq!(
        fs::read(&clean).unwrap(),
        b"ordinary native validation content"
    );
    execute(&clean_exec).unwrap();
    let mut clean_read = Vec::new();
    clean_existing.read_to_end(&mut clean_read).unwrap();
    assert_eq!(clean_read, b"ordinary native validation content");
    assert_eq!(
        mapped(&clean_mapping, clean_read.len()).unwrap(),
        clean_read
    );
    assert_eq!(clean_view.read().unwrap(), clean_read);
    report.checks.insert(
        "clean_read_execution_existing_handle_and_mappings_after_activation".into(),
        serde_json::json!({"passed":true}),
    );
    probe(
        report,
        &f,
        &live,
        scope,
        "new_read_denied_with_kernel_receipt",
        &targets[0],
        || {
            fs::read(&targets[0].path)?;
            Ok(())
        },
    );
    probe(
        report,
        &f,
        &live,
        scope,
        "execution_denied_with_kernel_receipt",
        &executable,
        || execute(&executable.path),
    );
    probe(
        report,
        &f,
        &live,
        scope,
        "existing_handle_read_denied_with_kernel_receipt",
        &targets[1],
        || {
            let mut bytes = Vec::new();
            existing.read_to_end(&mut bytes)?;
            assert_eq!(bytes, sample);
            Ok(())
        },
    );
    probe(
        report,
        &f,
        &live,
        scope,
        "existing_handle_mapping_denied_with_kernel_receipt",
        &targets[2],
        || {
            assert_eq!(mapped(&mapping, sample.len())?, sample);
            Ok(())
        },
    );
    drop(existing);
    drop(mapping);
    probe(
        report,
        &f,
        &live,
        scope,
        "existing_view_read_denied_with_kernel_receipt",
        &targets[3],
        || {
            assert_eq!(retained_view.read()?, sample);
            Ok(())
        },
    );
    drop(retained_view);
    // A clean open must not authorize malicious bytes written through that
    // same handle later. Both prevention at write and at read need a receipt.
    let mut writer = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&changed.path)
        .unwrap();
    probe(
        report,
        &f,
        &live,
        scope,
        "changed_after_clean_open_denied_with_kernel_receipt",
        &changed,
        || {
            writer.write_all(&sample)?;
            writer.sync_all()?;
            writer.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            writer.read_to_end(&mut bytes)?;
            assert_eq!(bytes, sample);
            Ok(())
        },
    );
    drop(writer);
    let original = &targets[4];
    let mut quarantine = f.command(Action::Quarantine {
        path: original.path.to_str().unwrap().into(),
        sha256: original.sha256.clone(),
    });
    quarantine.timeout_secs = 30;
    let receipt = f.execute(&quarantine);
    assert_eq!(receipt.outcome, "succeeded", "{}", receipt.output);
    assert!(!original.path.exists());
    assert_eq!(fs::read(f.retained(&quarantine.id)).unwrap(), sample);
    let intent: String = f
        .connection()
        .query_row(
            "SELECT intent FROM native_mutations WHERE command_id=?1",
            [&quarantine.id],
            |r| r.get(0),
        )
        .unwrap();
    let intent: Intent = serde_json::from_str(&intent).unwrap();
    assert!(
        matches!(&intent.verifier,Some(Verifier::WindowsProtected {session,policy}) if session==&live.session&&policy==&live.policy_sha256)
    );
    report.checks.insert(
        "quarantine_with_armed_filter".into(),
        serde_json::json!({"passed":true,"receipt":receipt,"intent":intent}),
    );
    // Repeat management recovery after a committed operation whose receipt was
    // already issued. It must retain that receipt and not capture a replacement.
    fs::write(&original.path, b"replacement must remain untouched").unwrap();
    f.connection()
        .execute(
            "UPDATE native_mutations SET state='pending',report=NULL WHERE command_id=?1",
            [&quarantine.id],
        )
        .unwrap();
    let recovered = f.execute(&quarantine);
    assert_eq!(
        serde_json::to_value(&recovered).unwrap(),
        serde_json::to_value(&receipt).unwrap()
    );
    assert_eq!(
        fs::read(&original.path).unwrap(),
        b"replacement must remain untouched"
    );
    report.checks.insert(
        "committed_recovery_keeps_receipt_and_replacement".into(),
        serde_json::json!({"passed":true}),
    );
    fs::remove_file(&original.path).unwrap();
    let mut restore = f.command(Action::Restore {
        quarantine_id: quarantine.id.clone(),
    });
    restore.timeout_secs = 30;
    let restored = f.execute(&restore);
    assert_eq!(restored.outcome, "succeeded", "{}", restored.output);
    // Restore publishes a new file identity, so read metadata without consuming
    // its protected contents and bind the fresh denial to that new identity.
    let file = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .open(&original.path)
        .unwrap();
    let mut id = FILE_ID_INFO::default();
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut id as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        },
        0
    );
    let restored_target = Target {
        volume: id.VolumeSerialNumber,
        file_id: athernex_endpoint_native::windows_filter::evidence::hex(&id.FileId.Identifier),
        ..original.clone()
    };
    probe(
        report,
        &f,
        &live,
        scope,
        "restore_stays_blocked_with_kernel_receipt",
        &restored_target,
        || {
            fs::read(&original.path)?;
            Ok(())
        },
    );
    assert!(!f.retained(&quarantine.id).exists());
    report.checks.insert(
        "restore_committed_while_filter_remains_armed".into(),
        serde_json::json!({"passed":true,"receipt":restored}),
    );
    let current = windows::status(&f.state.join("protection/windows")).unwrap();
    assert_eq!(current.session, live.session);
    assert_eq!(current.policy_sha256, live.policy_sha256);
    assert_eq!(
        current.kernel.as_ref().unwrap().status.instance,
        spec.instance
    );
    assert_eq!(current.coverage.state, "active");
    report.checks.insert(
        "filter_session_remained_active".into(),
        serde_json::json!({"passed":true,"kernel":current.kernel}),
    );
}
