//! Actual installed-command worker protocol, parent binding and job ownership.
//! Cross-building this fixture does not execute it on Windows.
#![cfg(windows)]
use athernex_endpoint::{run_bounded, secret, Process};
use athernex_endpoint_native::{windows_scanner::Token, windows_state::Directory};
use serde_json::{json, Value};
use std::{
    fs,
    os::windows::io::{FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr::null_mut,
};

struct Fixture {
    agent: PathBuf,
    private: tempfile::TempDir,
}

enum Operation {
    ScratchCleanup,
    PreviewRecovery,
    WorkspaceCleanup,
}

fn unexpected_exit(operation: Operation, code: i32, output: &str) {
    if code == 0 {
        return;
    }
    let operation = match operation {
        Operation::ScratchCleanup => "scratch_cleanup",
        Operation::PreviewRecovery => "preview_recovery",
        Operation::WorkspaceCleanup => "workspace_cleanup",
    };
    // These are command exit statuses, not inferred Win32 API errors. Match
    // complete static error lines only; all other worker output stays private.
    let category = output
        .lines()
        .find_map(|line| match line {
            "Error: \"Invalid scratch recovery request\"" => Some("invalid_scratch_request"),
            "Error: \"Invalid Windows workspace cleanup request\"" => {
                Some("invalid_workspace_request")
            }
            "Error: \"Scratch helper is still alive; retain its image and journal\"" => {
                Some("scratch_live_owner")
            }
            "Error: \"Scanner launch/network recovery must finish before scratch reclamation\"" => {
                Some("scratch_network_pending")
            }
            "Error: \"Scanner launch/network recovery must finish before workspace cleanup\"" => {
                Some("workspace_network_pending")
            }
            _ => None,
        })
        .unwrap_or("other_private");
    println!("\nATHERNEX_WORKSPACE_EXIT={operation}:{code}");
    println!("\nATHERNEX_WORKSPACE_FAILURE={category}");
}

impl Fixture {
    fn new() -> Self {
        use windows_sys::Win32::{
            Foundation::{GetLastError, ERROR_NO_TOKEN},
            Security::TOKEN_QUERY,
            System::{
                RemoteDesktop::ProcessIdToSessionId,
                Threading::{GetCurrentThread, OpenThreadToken},
            },
        };
        println!("\nATHERNEX_WORKSPACE_STAGE=guard_started");
        assert!(
            std::env::var("ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST").as_deref() == Ok("1"),
            "Disposable workspace fixture opt-in required"
        );
        assert!(
            athernex_endpoint_native::windows_state::require_local_system().is_ok(),
            "Native LocalSystem identity required"
        );
        let mut session = u32::MAX;
        assert!(
            unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } != 0 && session == 0,
            "Native session zero required"
        );
        let mut handle = null_mut();
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut handle) };
        let error = unsafe { GetLastError() };
        if opened != 0 {
            assert!(!handle.is_null(), "Thread token handle missing");
            let _token = unsafe { OwnedHandle::from_raw_handle(handle) };
            panic!("Workspace fixture refuses impersonation");
        }
        assert!(
            error == ERROR_NO_TOKEN,
            "Thread identity could not be verified"
        );
        println!("\nATHERNEX_WORKSPACE_STAGE=guard_verified");
        let agent = PathBuf::from(
            std::env::var_os("ATHERNEX_NATIVE_WORKSPACE_AGENT")
                .expect("Exact staged release agent required"),
        );
        assert!(
            agent.is_absolute()
                && agent.is_file()
                && agent.file_name().is_some_and(|v| v == "agent.exe"),
            "Staged agent path invalid"
        );
        let agent = agent
            .canonicalize()
            .expect("Staged agent resolution failed");
        let executable = std::env::current_exe()
            .and_then(|value| value.canonicalize())
            .expect("Fixture executable resolution failed");
        let parent = agent.parent().expect("Staged agent parent missing");
        assert!(
            executable.parent() == Some(parent),
            "Agent and fixture must share the protected staging directory"
        );
        println!("\nATHERNEX_WORKSPACE_STAGE=agent_verified");
        // The source-bound runner stages both binaries under a System/Admin-only
        // ACL. Keep all nonce-bearing journals and worker output in that tree.
        let private = tempfile::Builder::new()
            .prefix("workspace-private-")
            .tempdir_in(parent)
            .expect("Private fixture directory creation failed");
        println!("\nATHERNEX_WORKSPACE_STAGE=private_ready");
        Self { agent, private }
    }
}

fn run(agent: &Path, state: &Path, nonce: &str, spoof_parent: bool) -> (i32, String) {
    run_cleanup(
        agent,
        "windows-workspace-cleanup",
        state,
        nonce,
        spoof_parent,
    )
}

fn run_cleanup(
    agent: &Path,
    command: &str,
    state: &Path,
    nonce: &str,
    spoof_parent: bool,
) -> (i32, String) {
    assert!(["windows-workspace-cleanup", "windows-scratch-cleanup"].contains(&command));
    let root = std::env::var_os("SystemRoot").unwrap();
    let powershell = Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    // The production process runner owns PowerShell and the worker as a job.
    // .NET supplies stdin to the real agent executable without a shell command
    // string containing the executable path, JSON, or user-controlled arguments.
    let script = r#"$ErrorActionPreference='Stop'; $p=[System.Diagnostics.Process]::new(); $p.StartInfo.FileName=$env:ATHERNEX_WORKSPACE_BINARY; $p.StartInfo.Arguments=$env:ATHERNEX_WORKSPACE_COMMAND+' '+$(if($env:ATHERNEX_WORKSPACE_SPOOF -eq 'yes'){'0'}else{$PID}); $p.StartInfo.UseShellExecute=$false; $p.StartInfo.RedirectStandardInput=$true; $p.StartInfo.RedirectStandardOutput=$true; $null=$p.Start(); $p.StandardInput.WriteLine($env:ATHERNEX_WORKSPACE_REQUEST); $p.StandardInput.Close(); $reply=$p.StandardOutput.ReadToEnd(); $p.WaitForExit(); [Console]::Write($reply); exit $p.ExitCode"#;
    run_bounded(
        Process::new(powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .env("ATHERNEX_WORKSPACE_BINARY", agent)
            .env("ATHERNEX_WORKSPACE_COMMAND", command)
            .env(
                "ATHERNEX_WORKSPACE_SPOOF",
                if spoof_parent { "yes" } else { "no" },
            )
            .env(
                "ATHERNEX_WORKSPACE_REQUEST",
                json!({"schema":1,"state":state,"nonce":nonce}).to_string(),
            ),
        40,
    )
    .unwrap_or_else(|_| {
        println!("\nATHERNEX_WORKSPACE_FAILURE=bounded_cleanup_failed");
        panic!("Bounded cleanup worker failed")
    })
}

#[test]
#[ignore = "requires native Windows LocalSystem; runs actual agent scratch cleanup without attaching or formatting a disk"]
fn actual_scratch_cleanup_excludes_live_workers_and_replays_partial_image_retirement() {
    use athernex_endpoint_native::{windows_filter::peer, windows_scratch};
    use std::io::Write;

    let fixture = Fixture::new();
    let token = Token::new().unwrap();
    let retained = fixture.private.path();
    let state = Directory::create_under(&retained.canonicalize().unwrap(), "private").unwrap();
    let _lease = state.lock("supervisor.lock").unwrap();
    let runtime = state.directory("scratch-runtime").unwrap();
    let journal = state.directory("scratch-journal").unwrap();
    let id = secret().unwrap();
    let leaf = format!("scanner-{id}");
    let container = Directory::create_under(runtime.path(), &leaf).unwrap();
    let identity = container.identity().unwrap();
    let mut partial = container.create(windows_scratch::IMAGE).unwrap();
    partial.write_all(b"interrupted image creation").unwrap();
    partial.sync_all().unwrap();
    drop(partial);
    drop(container);
    let mut record = json!({
        "schema":1,
        "spec":{"schema":1,"id":id,"bytes":256 * 1024 * 1024},
        "directory":identity,
        "logon":token.logon_sid(),
        "owner":{"pid":std::process::id(),"created":peer::identify(std::process::id()).unwrap()},
        "image_ready":false
    });
    let name = format!("{id}.json");
    journal.write_json(&name, &record).unwrap();
    let nonce = secret().unwrap();
    let run = |spoof| {
        run_cleanup(
            &fixture.agent,
            "windows-scratch-cleanup",
            state.path(),
            &nonce,
            spoof,
        )
    };
    println!("\nATHERNEX_WORKSPACE_STAGE=scratch_prepared");
    assert_ne!(run(true).0, 0, "spoofed parent must be refused");
    println!("\nATHERNEX_WORKSPACE_STAGE=scratch_spoof_refused");
    assert_ne!(run(false).0, 0, "live recorded owner must be retained");
    assert!(runtime
        .path()
        .join(&leaf)
        .join(windows_scratch::IMAGE)
        .exists());
    assert!(journal.path().join(&name).exists());
    println!("\nATHERNEX_WORKSPACE_STAGE=scratch_live_owner_retained");

    // A different creation time proves this PID no longer names the original
    // owner. The cleanup command must never terminate the current process.
    record["owner"]["created"] = json!(record["owner"]["created"].as_u64().unwrap() - 1);
    journal.write_json(&name, &record).unwrap();
    let worker_lease = state.lock("scratch-worker.lock").unwrap();
    assert_ne!(run(false).0, 0, "worker lease must exclude cleanup");
    drop(worker_lease);
    println!("\nATHERNEX_WORKSPACE_STAGE=scratch_worker_lease_refused");
    let network = state.directory("network").unwrap();
    network
        .write_json("retained.json", &json!({"unreconciled":true}))
        .unwrap();
    assert_ne!(
        run(false).0,
        0,
        "scanner recovery must precede scratch cleanup"
    );
    println!("\nATHERNEX_WORKSPACE_STAGE=scratch_network_retained");
    network.remove("retained.json").unwrap();
    let (code, output) = run(false);
    unexpected_exit(Operation::ScratchCleanup, code, &output);
    assert!(code == 0, "Cleanup command failed");
    assert!(
        serde_json::from_str::<Value>(&output).unwrap()
            == json!({"schema":1,"nonce":nonce,"removed":1}),
        "Cleanup response differs"
    );
    assert!(!runtime.path().join(&leaf).exists());
    assert!(!journal.path().join(&name).exists());
    println!("\nATHERNEX_WORKSPACE_STAGE=scratch_cleanup_verified");

    journal.write_json(&name, &record).unwrap();
    let (code, output) = run(false);
    unexpected_exit(Operation::ScratchCleanup, code, &output);
    assert!(code == 0, "Cleanup command failed");
    assert!(
        serde_json::from_str::<Value>(&output).unwrap()
            == json!({"schema":1,"nonce":nonce,"removed":1}),
        "Cleanup response differs"
    );
    println!("\nATHERNEX_WORKSPACE_STAGE=scratch_retirement_replayed");
    let (code, output) = run(false);
    unexpected_exit(Operation::ScratchCleanup, code, &output);
    assert!(code == 0, "Cleanup command failed");
    assert!(
        serde_json::from_str::<Value>(&output).unwrap()
            == json!({"schema":1,"nonce":nonce,"removed":0}),
        "Cleanup replay response differs"
    );
    println!("\nATHERNEX_WORKSPACE_STAGE=scratch_empty_replayed");
}

#[test]
#[ignore = "requires native Windows LocalSystem/session zero; runs actual preview recovery without a driver or attached disk"]
fn actual_preview_recovery_waits_for_workers_and_retires_scratch_before_staged_files() {
    use athernex_endpoint_native::{windows_filter::peer, windows_scratch};
    use std::io::Write;
    let fixture = Fixture::new();
    let token = Token::new().unwrap();
    let retained = fixture.private.path();
    let endpoint = Directory::create_under(&retained.canonicalize().unwrap(), "private").unwrap();
    let protection = endpoint.directory("protection").unwrap();
    let state = protection.directory("windows").unwrap();
    let id = secret().unwrap();
    let leaf = format!("scanner-{id}");
    let scratch = state.directory("scratch-runtime").unwrap();
    let container = Directory::create_under(scratch.path(), &leaf).unwrap();
    let identity = container.identity().unwrap();
    let mut file = container.create(windows_scratch::IMAGE).unwrap();
    file.write_all(b"interrupted image creation").unwrap();
    file.sync_all().unwrap();
    drop(file);
    drop(container);
    state.directory("scratch-journal").unwrap().write_json(&format!("{id}.json"), &json!({
        "schema":1,"spec":{"schema":1,"id":id,"bytes":256 * 1024 * 1024},
        "directory":identity,"logon":token.logon_sid(),"image_ready":false,
        "owner":{"pid":std::process::id(),"created":peer::identify(std::process::id()).unwrap()-1}
    })).unwrap();
    let runtime = state.directory("runtime").unwrap();
    let workspace = runtime.scanner_workspace(&leaf, &token).unwrap();
    workspace
        .write("retired-engine", b"staged scanner bytes")
        .unwrap();
    state
        .directory("workspaces")
        .unwrap()
        .write_json(
            &format!("{id}.json"),
            &json!({
                "schema":1,"id":id,"identity":workspace.identity().unwrap()
            }),
        )
        .unwrap();
    drop(workspace);
    let network = state.directory("network").unwrap();
    network
        .write_json("retained.json", &json!({"unreconciled":true}))
        .unwrap();
    let run = || {
        run_bounded(
            Process::new(&fixture.agent)
                .arg("windows-protection-recover")
                .arg(endpoint.path()),
            75,
        )
        .unwrap_or_else(|_| {
            println!("\nATHERNEX_WORKSPACE_FAILURE=bounded_recovery_failed");
            panic!("Bounded recovery command failed")
        })
    };
    println!("\nATHERNEX_WORKSPACE_STAGE=preview_prepared");
    let common = protection.lock("supervisor.lock").unwrap();
    assert_ne!(run().0, 0);
    drop(common);
    println!("\nATHERNEX_WORKSPACE_STAGE=preview_supervisor_refused");
    for name in ["supervisor.lock", "client.lock", "scratch-worker.lock"] {
        let worker = state.lock(name).unwrap();
        assert_ne!(run().0, 0, "live {name} must prevent recovery");
        drop(worker);
    }
    println!("\nATHERNEX_WORKSPACE_STAGE=preview_workers_refused");
    assert_ne!(
        run().0,
        0,
        "unresolved network ownership must retain all storage"
    );
    assert!(scratch
        .path()
        .join(&leaf)
        .join(windows_scratch::IMAGE)
        .exists());
    assert!(runtime.path().join(&leaf).join("retired-engine").exists());
    println!("\nATHERNEX_WORKSPACE_STAGE=preview_network_retained");
    network.remove("retained.json").unwrap();
    for attempt in 0..2 {
        let (code, output) = run();
        unexpected_exit(Operation::PreviewRecovery, code, &output);
        assert!(code == 0, "Cleanup command failed");
        assert!(
            serde_json::from_str::<Value>(&output).unwrap() == json!({"schema":1,"recovered":true}),
            "Recovery response differs"
        );
        if attempt == 0 {
            println!("\nATHERNEX_WORKSPACE_STAGE=preview_cleanup_verified");
        } else {
            println!("\nATHERNEX_WORKSPACE_STAGE=preview_empty_replayed");
        }
    }
    for name in [
        "network",
        "scratch-journal",
        "scratch-runtime",
        "scratch-health",
        "workspaces",
        "runtime",
    ] {
        assert_eq!(
            fs::read_dir(state.path().join(name)).unwrap().count(),
            0,
            "{name}"
        );
    }
    println!("\nATHERNEX_WORKSPACE_STAGE=preview_storage_empty");
}

#[test]
#[ignore = "requires native Windows LocalSystem session zero; runs actual agent cleanup worker"]
fn actual_cleanup_worker_preserves_live_journals_and_replays_committed_workspace_deletion() {
    let fixture = Fixture::new();
    let token = Token::new().unwrap();
    let retained = fixture.private.path();
    let state = Directory::create_under(&retained.canonicalize().unwrap(), "private").unwrap();
    let _lease = state.lock("supervisor.lock").unwrap();
    let network = state.directory("network").unwrap();
    let runtime = state.directory("runtime").unwrap();
    let journal = state.directory("workspaces").unwrap();
    let id = secret().unwrap();
    let name = format!("scanner-{id}");
    let workspace = runtime.scanner_workspace(&name, &token).unwrap();
    let identity = workspace.identity().unwrap();
    let record_name = format!("{id}.json");
    journal
        .write_json(
            &record_name,
            &json!({"schema":1,"id":id,"identity":identity}),
        )
        .unwrap();
    workspace
        .write("staged-file", b"retired scanner data")
        .unwrap();
    drop(workspace);
    let nonce = secret().unwrap();
    println!("\nATHERNEX_WORKSPACE_STAGE=workspace_prepared");
    assert_ne!(run(&fixture.agent, state.path(), &nonce, true).0, 0);
    assert!(runtime.path().join(&name).exists());
    println!("\nATHERNEX_WORKSPACE_STAGE=workspace_spoof_refused");
    network
        .write_json("retained.json", &json!({"unreconciled":true}))
        .unwrap();
    assert_ne!(run(&fixture.agent, state.path(), &nonce, false).0, 0);
    assert!(runtime.path().join(&name).join("staged-file").exists());
    assert!(journal.path().join(&record_name).exists());
    println!("\nATHERNEX_WORKSPACE_STAGE=workspace_network_retained");
    network.remove("retained.json").unwrap();
    let (code, output) = run(&fixture.agent, state.path(), &nonce, false);
    unexpected_exit(Operation::WorkspaceCleanup, code, &output);
    assert!(code == 0, "Cleanup command failed");
    let response: Value = serde_json::from_str(&output).unwrap();
    assert!(
        response == json!({"schema":1,"nonce":nonce,"removed":1}),
        "Cleanup response differs"
    );
    assert!(!runtime.path().join(&name).exists());
    assert!(!journal.path().join(&record_name).exists());
    println!("\nATHERNEX_WORKSPACE_STAGE=workspace_cleanup_verified");

    // Crash after root deletion but before journal unlink: replay is harmless.
    journal
        .write_json(
            &record_name,
            &json!({"schema":1,"id":id,"identity":identity}),
        )
        .unwrap();
    let (code, output) = run(&fixture.agent, state.path(), &nonce, false);
    unexpected_exit(Operation::WorkspaceCleanup, code, &output);
    assert!(code == 0, "Cleanup command failed");
    assert!(!journal.path().join(&record_name).exists());
    assert_eq!(fs::read_dir(runtime.path()).unwrap().count(), 0);
    println!("\nATHERNEX_WORKSPACE_STAGE=workspace_deletion_replayed");
}
