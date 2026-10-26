use super::*;
use std::ffi::OsStr;

fn job() -> Job {
    Job::new(
        "group.example.endpoint",
        Path::new(STATE),
        &"a".repeat(64),
        &"b".repeat(64),
    )
    .unwrap()
}

struct Mock {
    result: Option<Result<(i32, Vec<u8>)>>,
    calls: Vec<Vec<String>>,
}
impl Mock {
    fn reply(result: Result<(i32, Vec<u8>)>) -> Self {
        Self {
            result: Some(result),
            calls: Vec::new(),
        }
    }
}
impl Backend for Mock {
    fn run(
        &mut self,
        command: &mut Command,
        timeout: Duration,
        limit: usize,
    ) -> Result<(i32, Vec<u8>)> {
        assert_eq!(command.get_program(), OsStr::new("/bin/launchctl"));
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
        assert_eq!(timeout, Duration::from_secs(30));
        assert_eq!(limit, 4096);
        assert_eq!(command.get_envs().count(), 0);
        self.calls.push(
            command
                .get_args()
                .map(|arg| arg.to_str().unwrap().into())
                .collect(),
        );
        self.result.take().expect("No implicit launchctl retry")
    }
}

#[test]
fn exact_job_is_deterministic_and_has_only_the_candidate_service_arguments() {
    let job = job();
    let record = job.prepared_record();
    let bytes = job.plist_bytes();
    assert_eq!(bytes, job.plist_bytes());
    assert_eq!(record.plist_sha256, sha256(&bytes));
    let plist = std::str::from_utf8(&bytes).unwrap();
    assert!(plist.contains(&format!("<key>Label</key><string>{LABEL}</string>")));
    assert!(plist.contains(&format!(
        "<key>ProgramArguments</key><array><string>{PROGRAM}</string><string>serve-macos-network-upgrade</string><string>{STATE}</string><string>{}</string></array>",
        "a".repeat(64)
    )));
    assert!(plist.contains("<key>MachServices</key><dict><key>group.example.endpoint.network-upgrade</key><true/></dict>"));
    assert!(plist.contains("<key>UserName</key><string>root</string>"));
    assert!(plist.contains("<key>RunAtLoad</key><false/>"));
    assert!(plist.contains("<key>KeepAlive</key><false/>"));
    for forbidden in [
        "StandardOutPath",
        "StandardErrorPath",
        "EnvironmentVariables",
        "sh</string>",
    ] {
        assert!(!plist.contains(forbidden));
    }
}

#[test]
fn unapproved_paths_and_injected_or_noncanonical_identifiers_refuse() {
    for state in [
        "state",
        "/tmp/state",
        "/Library/AthernexEndpoint/./state",
        "/Library/AthernexEndpoint/state/",
    ] {
        let result = Job::new(
            "group.example",
            Path::new(state),
            &"a".repeat(64),
            &"b".repeat(64),
        );
        assert!(result.is_err());
    }
    for group in [
        "",
        "single",
        "group..example",
        ".group",
        "group.",
        "group/example",
        "group.$(id)",
        "group.é",
        "group.\nvalue",
        "group.<key>",
        "group._value",
    ] {
        assert!(Job::new(group, Path::new(STATE), &"a".repeat(64), &"b".repeat(64)).is_err());
    }
    assert!(Job::new(
        &format!("group.{}", "x".repeat(220)),
        Path::new(STATE),
        &"a".repeat(64),
        &"b".repeat(64)
    )
    .is_err());
    for value in [
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        format!("{}\n", "a".repeat(64)),
    ] {
        assert!(Job::new("group.example", Path::new(STATE), &value, &"b".repeat(64)).is_err());
        assert!(Job::new("group.example", Path::new(STATE), &"a".repeat(64), &value).is_err());
    }
    assert_eq!(escape("<&>\"'"), "&lt;&amp;&gt;&quot;&apos;");
}

#[test]
fn successful_bootstrap_and_bootout_return_distinct_owned_receipts() {
    let job = job();
    let prepared = job.prepared_record();
    let bytes = job.plist_bytes();
    let mut start = Mock::reply(Ok((0, b"private output is discarded".to_vec())));
    let confirmed = job
        .perform(&prepared, Path::new(PLIST), &bytes, false, &mut start)
        .unwrap();
    assert_eq!(
        start.calls,
        vec![vec!["bootstrap".to_string(), "system".into(), PLIST.into()]]
    );
    assert_eq!(prepared.state, JobState::Prepared);
    assert_eq!(confirmed.state, JobState::BootstrapConfirmed);
    let mut stop = Mock::reply(Ok((0, Vec::new())));
    let stopped = job
        .perform(
            &confirmed,
            Path::new(PRIVATE_PLIST),
            &bytes,
            true,
            &mut stop,
        )
        .unwrap();
    assert_eq!(
        stop.calls,
        vec![vec!["bootout".to_string(), format!("system/{LABEL}")]]
    );
    assert_eq!(stopped.state, JobState::BootoutConfirmed);
    assert_eq!(confirmed.state, JobState::BootstrapConfirmed);
}

#[test]
fn every_record_identity_field_is_required_before_any_command() {
    let job = job();
    let original = job.prepared_record();
    let mut variants = Vec::new();
    let mut r = original.clone();
    r.schema = 2;
    variants.push(r);
    let mut r = original.clone();
    r.label = "com.athernex.endpoint".into();
    variants.push(r);
    let mut r = original.clone();
    r.mach_service.push_str(".other");
    variants.push(r);
    let mut r = original.clone();
    r.transaction_id = "c".repeat(64);
    variants.push(r);
    let mut r = original.clone();
    r.management_sha256 = "d".repeat(64);
    variants.push(r);
    let mut r = original.clone();
    r.plist_sha256 = "e".repeat(64);
    variants.push(r);
    for record in variants {
        let mut backend = Mock::reply(Ok((0, Vec::new())));
        assert!(job
            .perform(
                &record,
                Path::new(PLIST),
                &job.plist_bytes(),
                false,
                &mut backend
            )
            .is_err());
        assert!(backend.calls.is_empty());
    }
}

#[test]
fn matching_file_never_authorizes_uncertain_or_unrecorded_recovery() {
    let job = job();
    for state in [
        JobState::Prepared,
        JobState::Uncertain,
        JobState::BootoutConfirmed,
        JobState::NotRegistered,
        JobState::RetiredAfterBoot,
    ] {
        let mut record = job.prepared_record();
        record.state = state;
        let mut backend = Mock::reply(Ok((0, Vec::new())));
        assert!(job
            .perform(
                &record,
                Path::new(PRIVATE_PLIST),
                &job.plist_bytes(),
                true,
                &mut backend
            )
            .is_err());
        assert!(backend.calls.is_empty());
    }
    for state in [
        JobState::BootstrapConfirmed,
        JobState::Uncertain,
        JobState::BootoutConfirmed,
        JobState::NotRegistered,
        JobState::RetiredAfterBoot,
    ] {
        let mut record = job.prepared_record();
        record.state = state;
        let mut backend = Mock::reply(Ok((0, Vec::new())));
        assert!(job
            .perform(
                &record,
                Path::new(PLIST),
                &job.plist_bytes(),
                false,
                &mut backend
            )
            .is_err());
        assert!(backend.calls.is_empty());
    }
}

#[test]
fn confirmed_job_cannot_bootout_until_its_exact_plist_is_parked() {
    let job = job();
    let mut record = job.prepared_record();
    record.state = JobState::BootstrapConfirmed;
    let bytes = job.plist_bytes();
    for (path, content) in [
        (Path::new(PLIST), bytes.clone()),
        (Path::new(MANAGEMENT_PLIST), bytes.clone()),
        (Path::new(PRIVATE_PLIST), [bytes.as_slice(), b"\n"].concat()),
    ] {
        let mut backend = Mock::reply(Ok((0, Vec::new())));
        assert!(job
            .perform(&record, path, &content, true, &mut backend)
            .is_err());
        assert!(backend.calls.is_empty());
    }
}

#[test]
fn changed_plist_or_other_path_refuses_without_side_effect() {
    let job = job();
    let record = job.prepared_record();
    let mut changed = job.plist_bytes();
    changed.push(b'\n');
    for (path, bytes) in [
        (Path::new(PLIST), changed.as_slice()),
        (Path::new(MANAGEMENT_PLIST), job.plist_bytes().as_slice()),
    ] {
        let mut backend = Mock::reply(Ok((0, Vec::new())));
        assert!(job
            .perform(&record, path, bytes, false, &mut backend)
            .is_err());
        assert!(backend.calls.is_empty());
    }
}

#[test]
fn command_failures_never_retry_confirm_or_export_private_diagnostics() {
    let job = job();
    for stopping in [false, true] {
        let mut record = job.prepared_record();
        if stopping {
            record.state = JobState::BootstrapConfirmed;
        }
        for result in [
            Ok((7, b"private stderr and path".to_vec())),
            Err("private timeout detail".into()),
            Err("private cleanup uncertainty".into()),
        ] {
            let before = record.clone();
            let mut backend = Mock::reply(result);
            let error = job
                .perform(
                    &record,
                    Path::new(if stopping { PRIVATE_PLIST } else { PLIST }),
                    &job.plist_bytes(),
                    stopping,
                    &mut backend,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), FAILED);
            assert_eq!(backend.calls.len(), 1);
            assert_eq!(record, before);
        }
    }
}

#[test]
fn durable_record_refuses_unknown_duplicate_and_wrongly_typed_fields() {
    let text = serde_json::to_string(&job().prepared_record()).unwrap();
    assert!(
        serde_json::from_str::<OwnedJobRecord>(&text.replacen('{', "{\"unknown\":true,", 1))
            .is_err()
    );
    assert!(
        serde_json::from_str::<OwnedJobRecord>(&text.replacen('{', "{\"schema\":1,", 1)).is_err()
    );
    assert!(
        serde_json::from_str::<OwnedJobRecord>(&text.replace("\"prepared\"", "\"unknown\""))
            .is_err()
    );
    assert!(serde_json::from_str::<OwnedJobRecord>(
        &text.replace("\"schema\":1", "\"schema\":\"1\"")
    )
    .is_err());
}

#[test]
fn management_snapshot_is_exact_standard_installer_output_and_pinned() {
    let installer = include_str!("../../../../../../infrastructure/endpoint/install-macos.sh");
    let emitted = installer
        .split("<<'PLIST'\n")
        .nth(1)
        .unwrap()
        .split("\nPLIST\n")
        .next()
        .unwrap();
    assert_eq!(management_plist_bytes(), format!("{emitted}\n").as_bytes());
    let bytes = management_plist_bytes();
    verify_management_snapshot(bytes, &sha256(bytes)).unwrap();
    assert!(verify_management_snapshot(bytes, &"0".repeat(64)).is_err());
    let changed = String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace("athernex-controller", "other-controller");
    assert!(verify_management_snapshot(changed.as_bytes(), &sha256(changed.as_bytes())).is_err());
}

#[test]
fn management_absence_query_requires_root_and_never_accepts_failure_or_presence() {
    assert_eq!(
        FixedService::Management.label().to_bytes(),
        b"com.athernex.endpoint"
    );
    assert_eq!(
        FixedService::UpgradeHelper.label().to_bytes(),
        LABEL.as_bytes()
    );
    unloaded(0, || Ok(false)).unwrap();
    assert!(unloaded(501, || panic!("Non-root must not query the system domain")).is_err());
    assert!(unloaded(0, || Ok(true)).is_err());
    let error = unloaded(0, || Err("private OS error".into())).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Network upgrade requires the selected job to be unloaded"
    );
}
