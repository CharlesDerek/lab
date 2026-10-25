//! Native gates: linking these tests does not establish crash recovery on Windows.
use super::*;
use crate::windows_job::{self, Command, Service};
use std::{
    fs::File,
    io::Write,
    path::Path,
    process::{Command as StdCommand, Stdio},
    thread,
    time::{Duration, Instant},
};

const HELPER: &str = "protection::windows::recovery::tests::crash_helper";
const JOURNAL: &str = "ATHERNEX_WINDOWS_RECOVERY_JOURNAL";
const ID: &str = "ATHERNEX_WINDOWS_RECOVERY_ID";
const PHASE: &str = "ATHERNEX_WINDOWS_RECOVERY_PHASE";

fn fixture() -> (Directory, File, NetworkPolicy) {
    let retained = tempfile::tempdir().unwrap().keep();
    let directory = Directory::create_under(&retained.canonicalize().unwrap(), "private").unwrap();
    let mut image = directory.create("scanner.exe").unwrap();
    image
        .write_all(b"non-executable recovery policy fixture")
        .unwrap();
    image.sync_all().unwrap();
    drop(image);
    let image = directory.read("scanner.exe").unwrap();
    let policy = NetworkPolicy::new(&image, 3310).unwrap();
    println!(
        "Retained recovery fixture: {}; policy {}",
        directory.path().display(),
        policy.id
    );
    (directory, image, policy)
}

#[test]
#[ignore = "helper launched only by native Windows recovery test"]
fn crash_helper() {
    let Ok(path) = std::env::var(JOURNAL) else {
        return;
    };
    let journal = Directory::open(Path::new(&path)).unwrap();
    let id = std::env::var(ID).unwrap();
    let phase = std::env::var(PHASE).unwrap();
    let mut record = read(&journal, &id).unwrap();
    let token = athernex_endpoint_native::windows_scanner::Token::new().unwrap();
    let root = std::env::var_os("SystemRoot").unwrap();
    let mut command = Command::new(Path::new(&root).join("System32/cmd.exe"));
    command.env_clear().env("SystemRoot", root).args([
        "/d",
        "/q",
        "/s",
        "/c",
        "echo SCANNER_READY&for /l %i in (1,1,2147483647) do @rem keepalive",
    ]);
    let mut scanner = Service::start_scanner(&command, &token, 4096, |pid, created| {
        if phase == "prepared" {
            // The process exists but remains suspended, with no PID on disk.
            std::process::exit(0);
        }
        record
            .own(&journal, pid, created, token.logon_sid())
            .unwrap();
        if phase == "owned" {
            std::process::exit(0);
        }
        assert_eq!(phase, "running");
        Ok(())
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !scanner
        .output()
        .windows(b"SCANNER_READY".len())
        .any(|s| s == b"SCANNER_READY")
    {
        assert!(scanner.poll().unwrap().is_none());
        assert!(Instant::now() < deadline, "scanner never executed");
        thread::sleep(Duration::from_millis(10));
    }
    // No Rust destructors: only actual job-handle closure owns cleanup.
    std::process::exit(0);
}

#[test]
#[ignore = "requires native Windows LocalSystem session zero; scoped persistent WFP rules retained on failure"]
fn recovery_reconciles_aborted_installs_owner_crashes_and_committed_deletions() {
    let _serial = windows_job::TEST_SERIAL.lock().unwrap();
    let (state, _image, policy) = fixture();
    let _lease = state.lock("supervisor.lock").unwrap();
    let journal = state.directory("network").unwrap();
    let engine = NetworkEngine::open().unwrap();
    let record = Record::prepared(policy.clone()).unwrap();

    // Crash before install: no WFP objects, and a partial next atomic write.
    record.save(&journal).unwrap();
    let temporary = format!(".{}.json.new", policy.id);
    let mut file = journal.create(&temporary).unwrap();
    file.write_all(b"{partial").unwrap();
    file.sync_all().unwrap();
    drop(file);
    recover(&journal).unwrap();
    assert!(!journal.path().join(&temporary).exists());
    assert!(read(&journal, &policy.id).is_err());

    // All three crash boundaries execute in a separate owner process. Its
    // scanner is assigned to a job at creation, without an enclosing test job.
    for phase in ["prepared", "owned", "running"] {
        record.save(&journal).unwrap();
        engine.install(&policy).unwrap();
        let mut owner = StdCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                HELPER,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(JOURNAL, journal.path())
            .env(ID, &policy.id)
            .env(PHASE, phase)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = owner.try_wait().unwrap() {
                assert!(status.success(), "recovery owner failed at {phase}");
                break;
            }
            if Instant::now() >= deadline {
                owner.kill().unwrap();
                owner.wait().unwrap();
                panic!("recovery owner exceeded deadline at {phase}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        engine.verify(&policy).unwrap();
        let saved = read(&journal, &policy.id).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while saved.ensure_stopped().is_err() {
            engine.verify(&policy).unwrap();
            assert!(Instant::now() < deadline, "owned scanner did not terminate");
            thread::sleep(Duration::from_millis(10));
        }
        recover(&journal).unwrap();
        assert!(read(&journal, &policy.id).is_err());
        assert!(engine.verify(&policy).is_err());
        recover(&journal).unwrap();
    }

    // A live original process always prevents automatic rule removal.
    let pid = std::process::id();
    let created = peer::identify(pid).unwrap();
    let mut live = record.clone();
    live.own(&journal, pid, created, "S-1-5-5-1-2").unwrap();
    engine.install(&policy).unwrap();
    assert!(recover(&journal).is_err());
    engine.verify(&policy).unwrap();
    assert!(read(&journal, &policy.id)
        .unwrap()
        .matches_scanner(pid, created, "S-1-5-5-1-2"));
    assert!(!peer::original_process_ended(pid, created).unwrap());
    assert!(peer::original_process_ended(pid, created + 1).unwrap());
    assert!(peer::original_process_ended(0, created).is_err());

    // This fixture never ran a scanner at the policy image. Simulate the
    // deletion-committed/journal-unlink-not-yet-committed crash boundary.
    record.save(&journal).unwrap();
    engine.remove_after_job_exit(&policy).unwrap();
    recover(&journal).unwrap();
    recover(&journal).unwrap();

    // Legacy policy-only records must not gain the new launch guarantee.
    journal
        .write_json(&format!("{}.json", policy.id), &policy)
        .unwrap();
    assert!(recover(&journal).is_err());
    assert!(journal.path().join(format!("{}.json", policy.id)).exists());
    journal.remove(&format!("{}.json", policy.id)).unwrap();
}

#[test]
fn recovery_schema_rejects_ambiguous_owners_and_unknown_states() {
    let app = "\\device\\harddiskvolume3\\scanner.exe";
    let policy = NetworkPolicy {
        schema: 1,
        id: "a".repeat(64),
        application: "C:\\scanner.exe".into(),
        app_id: app
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect(),
        port: 3310,
    };
    let mut record = Record::prepared(policy).unwrap();
    assert!(record.validate(&"b".repeat(64)).is_err());
    for (pid, created, logon) in [
        (0, 1, "S-1-5-5-1-2"),
        (4, 1, "S-1-5-5-1-2"),
        (42, 0, "S-1-5-5-1-2"),
        (42, 1, "S-1-5-19"),
        (42, 1, "S-1-5-5-4294967296-1"),
        (42, 1, "S-1-5-5-1-2-3"),
    ] {
        record.launch = Launch::Owned {
            pid,
            created,
            logon: logon.into(),
        };
        assert!(record.validate(&record.network.id).is_err());
    }
    record.launch = Launch::Prepared {};
    let mut value = serde_json::to_value(&record).unwrap();
    value["launch"]["state"] = "unknown".into();
    assert!(serde_json::from_value::<Record>(value).is_err());
    let mut value = serde_json::to_value(&record).unwrap();
    value["launch"]["pid"] = 42.into();
    assert!(serde_json::from_value::<Record>(value).is_err());
}
