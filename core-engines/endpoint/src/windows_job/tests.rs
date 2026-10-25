//! These tests must execute on Windows. Cross-compilation only checks their types.
use super::*;
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    fs,
    io::Write,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::Path,
    process::{Command as StdCommand, Stdio},
};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::SECURITY_ATTRIBUTES,
    System::{
        JobObjects::IsProcessInJob,
        Threading::{
            CreateEventW, OpenProcess, SetEvent, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE,
        },
    },
};
const HELPER: &str = "windows_job::tests::helper";
const MODE: &str = "ATHERNEX_WINDOWS_FIXTURE_MODE";
const FILE: &str = "ATHERNEX_WINDOWS_FIXTURE_FILE";
const RELEASE: &str = "ATHERNEX_WINDOWS_FIXTURE_RELEASE";

fn args() -> [&'static str; 5] {
    [
        "--exact",
        HELPER,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
}
fn command(mode: &str, file: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(args()).env(MODE, mode).env(FILE, file);
    command
}
fn wait_file(path: &Path) -> Value {
    let start = Instant::now();
    loop {
        if let Ok(bytes) = fs::read(path) {
            if let Ok(value) = serde_json::from_slice(&bytes) {
                return value;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "fixture did not become ready: {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn process(pid: u32) -> OwnedHandle {
    handles::owned(unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    })
    .unwrap()
}
fn finished(handle: &OwnedHandle, millis: u32) -> bool {
    unsafe { WaitForSingleObject(handle.as_raw_handle(), millis) == WAIT_OBJECT_0 }
}
fn wait_release(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "fixture release deadline exceeded"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
#[ignore = "helper process launched by Windows lifecycle tests"]
fn helper() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let file = std::env::var_os(FILE).unwrap();
    match mode.as_str() {
        "echo" => {
            if let Ok(raw) = std::env::var("ATHERNEX_WINDOWS_FIXTURE_HANDLE") {
                unsafe {
                    SetEvent(raw.parse::<usize>().unwrap() as HANDLE);
                }
            }
            let value = json!({
                "argv": std::env::args_os().map(|a| a.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                "path": std::env::var_os("PATH").map(|v| v.encode_wide().collect::<Vec<_>>()),
                "case": std::env::var("ATHERNEX_CASE").ok(),
                "removed": std::env::var("ATHERNEX_REMOVED").ok(),
                "cleared": std::env::var("ATHERNEX_BEFORE_CLEAR").ok(),
                "directory": std::env::current_dir().unwrap(),
            });
            fs::write(file, serde_json::to_vec(&value).unwrap()).unwrap();
            print!("stdout-fixture");
            std::io::stdout().flush().unwrap();
            eprint!("stderr-fixture");
            std::io::stderr().flush().unwrap();
        }
        "sleep" => {
            thread::sleep(Duration::from_secs(30));
        }
        "scanner-ready" => {
            println!("SCANNER_READY");
            std::io::stdout().flush().unwrap();
            thread::sleep(Duration::from_secs(30));
        }
        "input" => {
            use std::io::Read;
            super::guard_parent(
                std::env::var("ATHERNEX_WINDOWS_FIXTURE_PARENT")
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
            .unwrap();
            let mut input = Vec::new();
            std::io::stdin()
                .take(65537)
                .read_to_end(&mut input)
                .unwrap();
            assert!(input.len() <= 65536);
            fs::write(file, input).unwrap();
        }
        "tree" => {
            // Intentional orphan fixture: the enclosing job, not this helper,
            // must terminate the descendant after the root exits.
            #[allow(clippy::zombie_processes)]
            let leaf = StdCommand::new(std::env::current_exe().unwrap())
                .args(args())
                .env(MODE, "sleep")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            fs::write(
                file,
                serde_json::to_vec(&json!({"pid": std::process::id(), "leaf": leaf.id()})).unwrap(),
            )
            .unwrap();
            wait_release(Path::new(&std::env::var_os(RELEASE).unwrap()));
            // Deliberately leave the leaf running. The enclosing job must stop it.
        }
        "owner" => {
            let mut child = command("tree", Path::new(&file));
            child.env(RELEASE, std::env::var_os(RELEASE).unwrap());
            let _child = child.spawn().unwrap();
            thread::sleep(Duration::from_secs(30));
        }
        "flood" => {
            let mut stdout = std::io::stdout().lock();
            loop {
                stdout.write_all(&[b'x'; 4096]).unwrap();
            }
        }
        "exit259" => std::process::exit(259),
        "network-install" => {
            use athernex_endpoint_native::windows_network::{Engine, Policy};
            use std::io::Read;
            let policy: Policy = serde_json::from_reader(std::io::stdin().take(65537)).unwrap();
            let engine = Engine::open().unwrap();
            engine.install(&policy).unwrap();
            // Skip destructors: the rules must survive process/RPC-session death.
            std::process::exit(0);
        }
        "network-probe" => network_probe(Path::new(&file), false),
        "network-control" => network_probe(Path::new(&file), true),
        _ => panic!("unknown fixture mode"),
    }
}

fn network_probe(result: &Path, control: bool) {
    use std::{
        io::Read,
        net::{TcpListener, TcpStream, UdpSocket},
    };
    let allowed: u16 = std::env::var("ATHERNEX_WINDOWS_NETWORK_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let denied: u16 = std::env::var("ATHERNEX_WINDOWS_NETWORK_DENIED_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let ipv6 = std::env::var("ATHERNEX_WINDOWS_NETWORK_IPV6").unwrap();
    let denied_listen: u16 = std::env::var("ATHERNEX_WINDOWS_NETWORK_DENIED_LISTEN")
        .unwrap()
        .parse()
        .unwrap();
    let udp = std::env::var("ATHERNEX_WINDOWS_NETWORK_UDP").unwrap();
    let forbidden = |error: io::Error| {
        // A timeout/refused connection cannot stand in for a policy denial.
        assert_eq!(
            error.raw_os_error(),
            Some(10013),
            "Expected WSAEACCES: {error}"
        );
    };
    for address in [format!("127.0.0.1:{denied}"), ipv6] {
        let attempt = TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_secs(1));
        if control {
            drop(attempt.unwrap());
        } else {
            forbidden(attempt.unwrap_err());
        }
    }
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let attempt = socket.send_to(b"denied", udp);
    if control {
        assert_eq!(attempt.unwrap(), 6);
    } else {
        forbidden(attempt.unwrap_err());
    }
    for address in [
        format!("127.0.0.2:{allowed}"),
        format!("0.0.0.0:{allowed}"),
        format!("[::1]:{allowed}"),
        format!("127.0.0.1:{denied_listen}"),
    ] {
        let attempt = TcpListener::bind(address);
        if control {
            drop(attempt.unwrap());
        } else {
            forbidden(attempt.unwrap_err());
        }
    }
    let listener = TcpListener::bind(("127.0.0.1", allowed)).unwrap();
    if control {
        fs::write(result, b"{\"control\":true}").unwrap();
        return;
    }
    listener.set_nonblocking(true).unwrap();
    fs::write(result, b"{\"ready\":true}").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((mut stream, address)) => {
                assert!(address.ip().is_loopback());
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut bytes = [0u8; 8];
                stream.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"SCANTEST");
                stream.write_all(&bytes).unwrap();
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("scanner accept failed: {error}"),
        }
    }
}

#[test]
#[ignore = "requires native Windows LocalSystem session zero; installs scoped persistent WFP rules and retains fixture/journal for recovery"]
fn scanner_network_rules_survive_owner_exit_and_allow_only_configured_loopback_service() {
    use athernex_endpoint_native::{
        windows_network::{Engine, Policy},
        windows_scanner::Token,
        windows_state::Directory,
    };
    use std::{
        io::Read,
        net::{TcpListener, TcpStream, UdpSocket},
    };
    let _serial = TEST_SERIAL.lock().unwrap();
    let token = Token::new().unwrap();
    let retained = tempfile::tempdir().unwrap().keep();
    let state = Directory::create_under(&retained.canonicalize().unwrap(), "private").unwrap();
    let workspace = state.scanner_workspace("scanner", &token).unwrap();
    let images = workspace.directory("engine", false).unwrap();
    let scratch = workspace.directory("temporary", true).unwrap();
    let mut source = fs::File::open(std::env::current_exe().unwrap()).unwrap();
    images
        .copy("scanner.exe", &mut source, &mut (512 * 1024 * 1024))
        .unwrap();
    let image = images.pin("scanner.exe").unwrap();
    let chosen = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = chosen.local_addr().unwrap().port();
    let denied = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied_listen = TcpListener::bind("127.0.0.1:0").unwrap();
    let ipv6 = TcpListener::bind("[::1]:0").unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let policy = Policy::new(&image, port).unwrap();
    state.write_json("network.json", &policy).unwrap();
    println!(
        "Retained native network fixture: {}; policy: {}",
        state.path().display(),
        policy.id
    );
    let result = scratch.path().join("result.json");
    let mut invocation = Command::new(&policy.application);
    invocation
        .args(args())
        .env_clear()
        .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
        .env("TEMP", scratch.path())
        .env("TMP", scratch.path())
        .env(MODE, "network-probe")
        .env(FILE, &result)
        .env("ATHERNEX_WINDOWS_NETWORK_PORT", port.to_string())
        .env(
            "ATHERNEX_WINDOWS_NETWORK_DENIED_LISTEN",
            denied_listen.local_addr().unwrap().port().to_string(),
        )
        .env(
            "ATHERNEX_WINDOWS_NETWORK_DENIED_PORT",
            denied.local_addr().unwrap().port().to_string(),
        )
        .env(
            "ATHERNEX_WINDOWS_NETWORK_IPV6",
            ipv6.local_addr().unwrap().to_string(),
        )
        .env(
            "ATHERNEX_WINDOWS_NETWORK_UDP",
            udp.local_addr().unwrap().to_string(),
        )
        .current_dir(images.path());
    drop(chosen);
    drop(denied_listen);
    // A failed durable ownership callback must never execute scanner code.
    // Keep the original process handle to observe actual termination, not a PID.
    invocation.env(MODE, "echo");
    let mut refused_process = None;
    assert!(
        Service::start_scanner(&invocation, &token, 16384, |pid, birth| {
            assert!(!result.exists());
            assert!(
                !athernex_endpoint_native::windows_filter::peer::original_process_ended(pid, birth)
                    .unwrap()
            );
            refused_process = Some(process(pid));
            Err(io::Error::other("injected ownership journal failure"))
        })
        .is_err()
    );
    assert!(finished(&refused_process.unwrap(), 5000));
    assert!(!result.exists(), "Uncommitted scanner executed its helper");
    let deadline = Instant::now() + Duration::from_secs(5);
    while cleanup_ready().is_err() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    // A control run under the same token/image proves the host and token can
    // perform these operations before our rules are installed.
    invocation.env(MODE, "network-control");
    let mut control = Service::start_scanner(&invocation, &token, 16384, |pid, birth| {
        assert!(!result.exists(), "Scanner ran before ownership callback");
        assert!(
            !athernex_endpoint_native::windows_filter::peer::original_process_ended(pid, birth)
                .unwrap()
        );
        Ok(())
    })
    .unwrap();
    control.verify_scanner(token.logon_sid()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(code) = control.poll().unwrap() {
            assert_eq!(
                code,
                0,
                "network control failed: {}",
                String::from_utf8_lossy(control.output())
            );
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    control.stop().unwrap();
    assert_eq!(wait_file(&result)["control"], true);
    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut datagram = [0u8; 16];
    let (size, _) = udp.recv_from(&mut datagram).unwrap();
    assert_eq!(&datagram[..size], b"denied");
    fs::remove_file(&result).unwrap();
    let installer = command("network-install", &state.path().join("unused"));
    assert_eq!(
        run_with_input(
            &installer,
            Duration::from_secs(20),
            8192,
            &serde_json::to_vec(&policy).unwrap()
        )
        .unwrap()
        .0,
        0
    );
    let engine = Engine::open().unwrap();
    engine.verify(&policy).unwrap();
    let mut changed = policy.clone();
    changed.port = if port == u16::MAX { port - 1 } else { port + 1 };
    assert!(engine.verify(&changed).is_err());
    assert!(
        engine.remove_after_job_exit(&changed).is_err(),
        "A changed journal must never remove the original rules"
    );
    engine.verify(&policy).unwrap();
    invocation.env(MODE, "network-probe");
    let mut service = Service::start_scanner(&invocation, &token, 16384, |_, _| Ok(())).unwrap();
    service.verify_scanner(token.logon_sid()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !result.exists() {
        assert!(
            service.poll().unwrap().is_none(),
            "probe exited: {}",
            String::from_utf8_lossy(service.output())
        );
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let mut client = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(1),
    )
    .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(b"SCANTEST").unwrap();
    let mut reply = [0u8; 8];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"SCANTEST");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(code) = service.poll().unwrap() {
            assert_eq!(code, 0, "{}", String::from_utf8_lossy(service.output()));
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    service.stop().unwrap();
    engine.remove_after_job_exit(&policy).unwrap();
    engine.remove_after_job_exit(&policy).unwrap();
    assert!(engine.verify(&policy).is_err());
    state.remove("network.json").unwrap();
    state.sync().unwrap();
}

#[test]
fn exact_arguments_environment_working_directory_and_handle_allowlist() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = dir.path().join("echo.json");
    let mut attributes: SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };
    attributes.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
    attributes.bInheritHandle = 1;
    let event = handles::owned(unsafe { CreateEventW(&attributes, 1, 0, null()) }).unwrap();
    let arguments: Vec<OsString> = [
        "",
        "a b\tc",
        "a\"b",
        "end\\",
        "&|<>^%!$()",
        "雪",
        "--fake-option",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let expected: Vec<Vec<u16>> = arguments
        .iter()
        .map(|a| a.encode_wide().collect())
        .collect();
    let mut child = command("echo", &result);
    child
        .env("ATHERNEX_BEFORE_CLEAR", "discard")
        .env_clear()
        .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
        .env(MODE, "echo")
        .env(FILE, &result)
        .env("athernex_case", "old")
        .env("ATHERNEX_CASE", "new")
        .env("ATHERNEX_REMOVED", "discard")
        .env_remove("athernex_removed")
        .env(
            "ATHERNEX_WINDOWS_FIXTURE_HANDLE",
            (event.as_raw_handle() as usize).to_string(),
        )
        .current_dir(dir.path())
        .arg("--")
        .args(&arguments);
    let (code, output) = run(&child, Duration::from_secs(10), 16384).unwrap();
    assert_eq!(code, 0);
    assert!(output.windows(14).any(|s| s == b"stdout-fixture"));
    assert!(output.windows(14).any(|s| s == b"stderr-fixture"));
    let value = wait_file(&result);
    let actual: Vec<Vec<u16>> = serde_json::from_value(value["argv"].clone()).unwrap();
    assert!(
        actual.ends_with(&expected),
        "UTF-16 argv changed in the child"
    );
    assert_eq!(value["path"], Value::Null);
    assert_eq!(value["cleared"], Value::Null);
    assert_eq!(value["removed"], Value::Null);
    assert_eq!(value["case"], "new");
    let directory = Path::new(value["directory"].as_str().unwrap())
        .canonicalize()
        .unwrap();
    assert_eq!(directory, dir.path().canonicalize().unwrap());
    assert_eq!(
        unsafe { WaitForSingleObject(event.as_raw_handle(), 0) },
        WAIT_TIMEOUT,
        "an unrelated inheritable event leaked to the child"
    );
}

#[test]
fn root_exit_and_explicit_stop_confirm_the_entire_job_is_empty() {
    let _serial = TEST_SERIAL.lock().unwrap();
    for natural in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let result = dir.path().join("tree.json");
        let release = dir.path().join("release");
        let mut command = command("tree", &result);
        command.env(RELEASE, &release);
        let mut child = command.spawn().unwrap();
        let value = wait_file(&result);
        let leaf = process(value["leaf"].as_u64().unwrap() as u32);
        let tree = child.tree.as_ref().unwrap();
        let mut member = 0;
        assert_ne!(
            unsafe {
                IsProcessInJob(
                    tree.process.as_raw_handle(),
                    tree.job.as_raw_handle(),
                    &mut member,
                )
            },
            0
        );
        assert_eq!(member, 1);
        assert!(!finished(&leaf, 0));
        if natural {
            fs::write(&release, b"go").unwrap();
            let start = Instant::now();
            loop {
                if let Some(code) = child.poll().unwrap() {
                    assert_eq!(code, 0);
                    break;
                }
                assert!(start.elapsed() < Duration::from_secs(5));
                thread::sleep(Duration::from_millis(5));
            }
        } else {
            let start = Instant::now();
            while child.stop().is_err() {
                assert!(start.elapsed() < Duration::from_secs(5));
            }
        }
        assert!(
            finished(&leaf, 0),
            "completion was reported while a descendant remained alive"
        );
    }
}

#[test]
fn owner_death_closes_the_noninherited_job_and_stops_descendants() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = dir.path().join("tree.json");
    struct Owner(std::process::Child);
    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut owner = Owner(
        StdCommand::new(std::env::current_exe().unwrap())
            .args(args())
            .env(MODE, "owner")
            .env(FILE, &result)
            .env(RELEASE, dir.path().join("release"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let value = wait_file(&result);
    let root = process(value["pid"].as_u64().unwrap() as u32);
    let leaf = process(value["leaf"].as_u64().unwrap() as u32);
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    assert!(finished(&root, 5000), "owned root survived owner death");
    assert!(
        finished(&leaf, 5000),
        "owned descendant survived owner death"
    );
}

#[test]
fn bounded_pipe_and_deadline_stop_work_and_259_is_a_real_exit_code() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = dir.path().join("unused");
    let start = Instant::now();
    assert!(
        run(&command("flood", &result), Duration::from_secs(10), 1024)
            .unwrap_err()
            .to_string()
            .contains("output budget")
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(
        run(&command("sleep", &result), Duration::from_millis(200), 1024)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    // Let any legitimately delayed kernel cleanup finish before another launch.
    let start = Instant::now();
    while cleanup_ready().is_err() {
        assert!(start.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        run(&command("exit259", &result), Duration::from_secs(10), 4096)
            .unwrap()
            .0,
        259
    );
}

#[test]
fn timeout_stops_a_running_descendant_and_inheritance_preserves_parent_environment() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = dir.path().join("tree.json");
    let mut tree = command("tree", &result);
    tree.env(RELEASE, dir.path().join("never-released"));
    let run = thread::spawn(move || super::run(&tree, Duration::from_secs(5), 4096));
    let value = wait_file(&result);
    let root = process(value["pid"].as_u64().unwrap() as u32);
    let leaf = process(value["leaf"].as_u64().unwrap() as u32);
    assert_eq!(
        run.join().unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(finished(&root, 5000));
    assert!(finished(&leaf, 5000));
    let start = Instant::now();
    while cleanup_ready().is_err() {
        assert!(start.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    }
    let echo = dir.path().join("echo.json");
    super::run(&command("echo", &echo), Duration::from_secs(10), 16384).unwrap();
    let expected = std::env::var_os("PATH").map(|v| v.encode_wide().collect::<Vec<_>>());
    assert_eq!(
        wait_file(&echo)["path"],
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn creation_failure_and_invalid_input_do_not_leave_owned_work() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    for _ in 0..MAX_TREES + 2 {
        assert!(command("echo", &dir.path().join("none"))
            .arg(OsString::from_wide(&[0]))
            .spawn()
            .is_err());
        assert!(Command::new(dir.path().join("missing.exe"))
            .spawn()
            .is_err());
    }
    assert!(Command::new("powershell.exe").spawn().is_err());
    assert!(Command::new(dir.path().join("script.cmd")).spawn().is_err());
    assert_eq!(
        run(
            &command("exit259", &dir.path().join("unused")),
            Duration::from_secs(10),
            4096
        )
        .unwrap()
        .0,
        259
    );
}

#[test]
fn worker_input_is_bounded_and_checks_the_actual_creating_parent() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = dir.path().join("request.bin");
    let bytes: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
    let mut worker = command("input", &result);
    worker.env(
        "ATHERNEX_WINDOWS_FIXTURE_PARENT",
        std::process::id().to_string(),
    );
    assert_eq!(
        run_with_input(&worker, Duration::from_secs(10), 4096, &bytes)
            .unwrap()
            .0,
        0
    );
    assert_eq!(fs::read(&result).unwrap(), bytes);
    fs::remove_file(&result).unwrap();
    assert!(run_with_input(&worker, Duration::from_secs(10), 4096, &vec![0; 65537]).is_err());
    assert!(!result.exists());
    worker.env("ATHERNEX_WINDOWS_FIXTURE_PARENT", "0");
    assert_ne!(
        run_with_input(&worker, Duration::from_secs(10), 4096, b"invalid parent")
            .unwrap()
            .0,
        0
    );
    assert!(!result.exists());
    let start = Instant::now();
    assert_eq!(
        run_with_input(
            &command("sleep", &result),
            Duration::from_millis(200),
            4096,
            &bytes
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "unread worker input blocked the parent"
    );
}

#[test]
fn service_keeps_process_identity_and_drains_bounded_output_until_drop() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut service = Service::start(
        &command("flood", &directory.path().join("unused")),
        None,
        1024,
    )
    .unwrap();
    let process = process(service.id());
    let birth = service.creation_time().unwrap();
    assert_ne!(birth, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while service.output().len() < 1024 {
        assert!(service.poll().unwrap().is_none());
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(service.creation_time().unwrap(), birth);
    assert_eq!(service.output().len(), 1024);
    drop(service);
    assert!(finished(&process, 5000));
    let deadline = Instant::now() + Duration::from_secs(5);
    while cleanup_ready().is_err() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires native Windows LocalSystem service session zero"]
fn scanner_launch_has_checked_identity_job_limits_and_owned_cleanup() {
    use athernex_endpoint_native::{
        windows_scanner::{self, Token},
        windows_state::Directory,
    };
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    let _serial = TEST_SERIAL.lock().unwrap();
    let token = Token::new().unwrap();
    let other = Token::new().unwrap();
    // Execute our own bounded helper from the same private scanner workspace
    // used by production. A command shell has unrelated startup requirements.
    let retained = tempfile::tempdir().unwrap().keep();
    let state = Directory::create_under(&retained.canonicalize().unwrap(), "private").unwrap();
    let workspace = state.scanner_workspace("scanner", &token).unwrap();
    let images = workspace.directory("engine", false).unwrap();
    let scratch = workspace.directory("temporary", true).unwrap();
    let mut source = fs::File::open(std::env::current_exe().unwrap()).unwrap();
    images
        .copy("scanner.exe", &mut source, &mut (512 * 1024 * 1024))
        .unwrap();
    let _image = images.pin("scanner.exe").unwrap();
    let mut invocation = Command::new(images.path().join("scanner.exe"));
    invocation
        .env_clear()
        .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
        .env("TEMP", scratch.path())
        .env("TMP", scratch.path())
        .env(MODE, "scanner-ready")
        .env(FILE, scratch.path().join("unused"))
        .current_dir(images.path())
        .args(args());
    let mut service = Service::start_scanner(&invocation, &token, 4096, |_, _| Ok(())).unwrap();
    let original = process(service.id());
    service.verify_scanner(token.logon_sid()).unwrap();
    assert!(service.verify_scanner(other.logon_sid()).is_err());
    let birth = service.creation_time().unwrap();
    windows_scanner::verify_process(service.id(), birth, token.logon_sid()).unwrap();
    assert!(windows_scanner::verify_process(service.id(), birth + 1, token.logon_sid()).is_err());
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let job = &service.child.tree.as_ref().unwrap().job;
    assert_ne!(
        unsafe {
            QueryInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                null_mut(),
            )
        },
        0
    );
    assert_eq!(limits.BasicLimitInformation.ActiveProcessLimit, 1);
    assert_eq!(limits.ProcessMemoryLimit, 2 * 1024 * 1024 * 1024);
    let required = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    assert_eq!(limits.BasicLimitInformation.LimitFlags & required, required);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !service
        .output()
        .windows(b"SCANNER_READY".len())
        .any(|v| v == b"SCANNER_READY")
    {
        if let Some(code) = service.poll().unwrap() {
            panic!(
                "scanner fixture exited with {code} (0x{:08x}): {}",
                code as u32,
                String::from_utf8_lossy(service.output())
            );
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    drop(service);
    assert!(finished(&original, 5000));
}
