use super::TEST_SERIAL as SERIAL;
use super::*;

#[test]
fn request_pipe_is_bounded_and_deadline_applies_when_child_does_not_read() {
    let _serial = SERIAL.lock().unwrap();
    let bytes = vec![b'x'; 65536];
    let (code, echoed) = run_with_input(
        &mut Command::new("/bin/cat"),
        Duration::from_secs(2),
        65536,
        &bytes,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(echoed, bytes);
    let start = Instant::now();
    let error = run_with_input(
        Command::new("/bin/sleep").arg("30"),
        Duration::from_millis(100),
        1024,
        &bytes,
    )
    .unwrap_err();
    assert!(error.to_string().contains("time budget"));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(run_with_input(
        &mut Command::new("/usr/bin/true"),
        Duration::from_secs(1),
        1024,
        &vec![0; 65537]
    )
    .unwrap_err()
    .to_string()
    .contains("input budget"));
}

#[test]
fn bounded_child_captures_both_streams_and_exit_status() {
    let _serial = SERIAL.lock().unwrap();
    let (code, bytes) = run(
        Command::new("/bin/sh").args(["-c", "printf output; printf diagnostic >&2; exit 7"]),
        Duration::from_secs(2),
        1024,
    )
    .unwrap();
    assert_eq!(code, 7);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("output"));
    assert!(text.contains("diagnostic"));
}

#[test]
fn oversized_output_and_ignored_soft_signals_do_not_block_the_caller() {
    let _serial = SERIAL.lock().unwrap();
    let start = Instant::now();
    let error = run(
        Command::new("/bin/sh").args(["-c", "while :; do printf 01234567890123456789; done"]),
        Duration::from_secs(2),
        100,
    )
    .unwrap_err();
    assert!(error.to_string().contains("output budget"));
    assert!(start.elapsed() < Duration::from_secs(2));
    let start = Instant::now();
    let error = run(
        Command::new("/bin/sh").args(["-c", "trap '' TERM; sleep 30 & wait"]),
        Duration::from_millis(100),
        1024,
    )
    .unwrap_err();
    assert!(error.to_string().contains("time budget"));
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn leader_exit_does_not_wait_for_inherited_output_pipes() {
    let _serial = SERIAL.lock().unwrap();
    let start = Instant::now();
    let (code, bytes) = run(
        Command::new("/bin/sh").args(["-c", "sleep 30 & printf done"]),
        Duration::from_secs(2),
        1024,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(bytes, b"done");
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn unreaped_children_hold_capacity_until_the_cleanup_worker_confirms_exit() {
    let _serial = SERIAL.lock().unwrap();
    let r = reaper().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while ACTIVE.load(Ordering::SeqCst) != 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    // These live, short-lived processes exercise delayed cleanup bookkeeping;
    // this does not simulate a kernel-uninterruptible filesystem operation.
    let mut entries = Vec::new();
    for _ in 0..LIMIT {
        let slot = Slot::acquire().unwrap();
        let child = Command::new("/bin/sleep").arg("0.3").spawn().unwrap();
        entries.push(Pending {
            child,
            group: None,
            _slot: slot,
        });
    }
    r.pending.lock().unwrap().extend(entries);
    assert!(run(
        &mut Command::new("/usr/bin/true"),
        Duration::from_secs(1),
        1024
    )
    .unwrap_err()
    .to_string()
    .contains("budget exhausted"));
    let deadline = Instant::now() + Duration::from_secs(3);
    while ACTIVE.load(Ordering::SeqCst) != 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        run(
            &mut Command::new("/usr/bin/true"),
            Duration::from_secs(1),
            1024
        )
        .unwrap()
        .0,
        0
    );
}

#[test]
fn worker_parent_guard_rejects_an_unowned_process_group() {
    assert!(guard_parent(0).is_err());
    assert!(guard_parent(std::process::id()).is_err());
}

#[test]
fn explicit_lease_survives_parent_descriptors_but_does_not_leak_to_unrelated_exec() {
    let _serial = SERIAL.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("lease");
    let lease = File::create(&path).unwrap();
    lease.try_lock().unwrap();
    let mut command = Command::new("/bin/sleep");
    command.arg("30");
    let fd = inherit_lease(&mut command, &lease).unwrap();
    assert!(fd >= 3);
    let mut holder = command.spawn().unwrap();
    let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    drop(command);
    drop(lease);
    let contender = File::open(&path).unwrap();
    assert!(contender.try_lock().is_err());
    holder.kill().unwrap();
    holder.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while contender.try_lock().is_err() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(unrelated.try_wait().unwrap().is_none());
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}

#[test]
fn service_output_stays_bounded_and_stop_reaps_the_owned_leader() {
    let _serial = SERIAL.lock().unwrap();
    let mut service = Service::start(
        Command::new("/bin/sh").args(["-c", "while :; do printf 'bounded fixture output\n'; done"]),
        512,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while service.dropped_output() == 0 && Instant::now() < deadline {
        assert_eq!(service.poll().unwrap(), None);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(service.dropped_output() > 0);
    assert!(service.output().len() <= 512);
    let start = Instant::now();
    service.stop().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(service.pid().is_none());
    assert!(service.poll().unwrap().is_some());
}

#[test]
fn service_poll_does_not_wait_for_descendants_holding_output_pipes() {
    let _serial = SERIAL.lock().unwrap();
    let mut service = Service::start(
        Command::new("/bin/sh").args(["-c", "sleep 30 & exit 7"]),
        512,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(code) = service.poll().unwrap() {
            assert_eq!(code, 7);
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(service.pid().is_none());
}

#[test]
fn watcher_does_not_retain_inherited_file_locks() {
    let _serial = SERIAL.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("lease");
    let marker = temp.path().join("started");
    let lease = File::create(&path).unwrap();
    lease.try_lock().unwrap();
    let child_marker = marker.clone();
    let worker = thread::spawn(move || {
        run(
            Command::new("/bin/sh")
                .env("ATHERNEX_FIXTURE_MARKER", child_marker)
                .args([
                    "-c",
                    "printf started > \"$ATHERNEX_FIXTURE_MARKER\"; sleep 0.5",
                ]),
            Duration::from_secs(3),
            1024,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !marker.exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    drop(lease);
    let contender = File::open(path).unwrap();
    assert!(
        contender.try_lock().is_ok(),
        "Watcher retained an unrelated inherited lock"
    );
    assert_eq!(worker.join().unwrap().unwrap().0, 0);
}

#[test]
fn reaped_leader_keeps_capacity_while_its_group_still_exists() {
    let _serial = SERIAL.lock().unwrap();
    let reaper = reaper().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while ACTIVE.load(Ordering::SeqCst) != 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let slot = Slot::acquire().unwrap();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 0.5 & exit 0"])
        .process_group(0)
        .spawn()
        .unwrap();
    let group = child.id();
    child.wait().unwrap();
    assert!(group_exists(group).unwrap());
    reaper.pending.lock().unwrap().push(Pending {
        child,
        group: Some(group),
        _slot: slot,
    });
    thread::sleep(Duration::from_millis(50));
    assert_eq!(ACTIVE.load(Ordering::SeqCst), 1);
    let deadline = Instant::now() + Duration::from_secs(3);
    while ACTIVE.load(Ordering::SeqCst) != 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn reusing_a_command_installs_only_one_watcher_per_spawn() {
    let _serial = SERIAL.lock().unwrap();
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "read children < /proc/$$/task/$$/children; set -- $children; printf '%s' \"$#\"",
    ]);
    for _ in 0..5 {
        let (code, output) = run(&mut command, Duration::from_secs(2), 1024).unwrap();
        assert_eq!(code, 0);
        assert_eq!(output, b"1");
    }
}
