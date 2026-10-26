#![cfg(target_os = "linux")]

//! Each case changes subreaper behavior only in a fresh, bounded subprocess.
//! The controller waits only for the exact watcher reported by its own shell;
//! the production reaper remains the sole owner of the command leader.
use athernex_endpoint_native::child;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Check<T> = Result<T, &'static str>;
const HELPER: &str = "isolated_child_cleanup_worker";
const SCRIPT: &str = "read children < /proc/$$/task/$$/children; set -- $children; test \"$#\" -eq 1 || exit 91; printf '%s %s\\n' \"$$\" \"$1\" > \"$ATHERNEX_CHILD_MARKER\"; printf controlled-output; printf controlled-error >&2; exit 7";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Case {
    Normal,
    Deadline,
    Independent,
    Output,
}
impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Deadline => "deadline",
            Self::Independent => "independent",
            Self::Output => "output",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    elapsed_ms: u64,
    code: Option<i32>,
    output_matches: bool,
    time_budget: bool,
    output_budget: bool,
    cleanup_pending: bool,
    pending_at_return: usize,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metrics {
    case: Case,
    observations: Vec<Observation>,
    watcher_hold_ms: Vec<u64>,
    cleanup_finished: bool,
}

fn supervise(case: Case) {
    let private = tempfile::tempdir().expect("Private cleanup fixture directory failed");
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700))
        .expect("Private cleanup fixture permissions failed");
    let log = File::create(private.path().join("helper.log"))
        .expect("Private helper log creation failed");
    log.set_permissions(fs::Permissions::from_mode(0o600))
        .expect("Private helper log permissions failed");
    let mut command =
        Command::new(std::env::current_exe().expect("Fixture executable unavailable"));
    command
        .args(["--ignored", "--exact", HELPER, "--nocapture"])
        .env("ATHERNEX_CHILD_CLEANUP_CASE", case.name())
        .env("ATHERNEX_CHILD_CLEANUP_PRIVATE", private.path())
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("Private helper log clone failed"))
        .stderr(log);
    // Supervision owns this direct child handle, never a guessed PID/group.
    unsafe {
        let parent = std::process::id() as i32;
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
            {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let mut worker = command
        .spawn()
        .expect("Isolated cleanup helper failed to start");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match worker.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = worker.kill();
                let cleanup_deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match worker.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) if Instant::now() < cleanup_deadline => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        _ => std::process::abort(),
                    }
                }
                break None;
            }
        }
    };
    // Only the typed numeric/fixed report may enter libtest output. Raw child
    // diagnostics and the PID marker remain in the private temporary directory.
    let mut bytes = Vec::new();
    File::open(private.path().join("metrics.json"))
        .unwrap_or_else(|_| panic!("Required cleanup metrics missing"))
        .take(4097)
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("Private cleanup metric read failed"));
    assert!(bytes.len() <= 4096, "Cleanup metric budget exceeded");
    let metrics: Metrics =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("Invalid cleanup metrics"));
    let expected = if case == Case::Independent { 2 } else { 1 };
    assert!(
        metrics.case == case
            && metrics.cleanup_finished
            && metrics.observations.len() == expected
            && metrics.watcher_hold_ms.len() == expected
            && metrics
                .observations
                .iter()
                .all(|o| o.elapsed_ms < 15_000 && o.pending_at_return <= 16)
            && metrics.watcher_hold_ms.iter().all(|ms| *ms < 15_000),
        "Cleanup metric identity or bounds changed"
    );
    println!(
        "controlled_cleanup_metrics={}",
        serde_json::to_string(&metrics).unwrap()
    );
    let mut log = Vec::new();
    File::open(private.path().join("helper.log"))
        .unwrap_or_else(|_| panic!("Required helper log missing"))
        .take(65_537)
        .read_to_end(&mut log)
        .unwrap_or_else(|_| panic!("Private helper log read failed"));
    assert!(log.len() <= 65_536, "Private helper log budget exceeded");
    let log =
        String::from_utf8(log).unwrap_or_else(|_| panic!("Private helper log encoding changed"));
    let summaries = log
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect::<Vec<_>>();
    let exact_result = summaries.len() == 1
        && summaries[0]
            .split_once("; finished in ")
            .is_some_and(|(summary, elapsed)| {
                summary
                    == "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out"
                    && elapsed
                        .strip_suffix('s')
                        .and_then(|value| value.parse::<f64>().ok())
                        .is_some_and(|value| value.is_finite() && (0.0..15.0).contains(&value))
            });
    assert!(
        log.lines().filter(|line| *line == "running 1 test").count() == 1
            && log
                .lines()
                .filter(|line| *line == "test isolated_child_cleanup_worker ... ok")
                .count()
                == 1
            && exact_result,
        "Exact isolated helper execution was not verified"
    );
    assert!(
        status.is_some_and(|s| s.success()),
        "Controlled child cleanup case failed"
    );
}

#[test]
fn normal_exit_waits_for_its_known_watcher_within_the_command_deadline() {
    supervise(Case::Normal);
}
#[test]
fn original_deadline_refuses_pending_cleanup_and_retains_capacity() {
    supervise(Case::Deadline);
}
#[test]
fn completion_is_per_group_and_does_not_wait_for_an_unrelated_cleanup() {
    supervise(Case::Independent);
}
#[test]
fn output_failure_keeps_fast_cleanup_and_retains_its_slot() {
    supervise(Case::Output);
}

struct Group {
    marker: PathBuf,
    worker: Option<JoinHandle<()>>,
    result: Receiver<Observation>,
    observed: Option<Observation>,
    ids: Option<(i32, i32)>,
    zombie_since: Option<Instant>,
    reaped: bool,
}
impl Group {
    fn start(private: &Path, name: &str, timeout: Duration, limit: usize) -> Self {
        let marker = private.join(name);
        let child_marker = marker.clone();
        let (sender, result) = mpsc::channel();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            let result = child::run(
                Command::new("/bin/sh")
                    .args(["-c", SCRIPT])
                    .env("ATHERNEX_CHILD_MARKER", child_marker),
                timeout,
                limit,
            );
            let elapsed_ms = started.elapsed().as_millis() as u64;
            let (code, output_matches, time_budget, output_budget, cleanup_pending) = match result {
                Ok((code, output)) => (
                    Some(code),
                    output == b"controlled-outputcontrolled-error"
                        || output == b"controlled-errorcontrolled-output",
                    false,
                    false,
                    false,
                ),
                Err(error) => {
                    let text = error.to_string();
                    (
                        None,
                        false,
                        text.contains("time budget"),
                        text.contains("output budget"),
                        text.contains("cleanup pending"),
                    )
                }
            };
            let _ = sender.send(Observation {
                elapsed_ms,
                code,
                output_matches,
                time_budget,
                output_budget,
                cleanup_pending,
                pending_at_return: child::pending_cleanup(),
            });
        });
        Self {
            marker,
            worker: Some(worker),
            result,
            observed: None,
            ids: None,
            zombie_since: None,
            reaped: false,
        }
    }

    fn await_watcher(&mut self) -> Check<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if self.ids.is_none() {
                if let Ok(text) = fs::read_to_string(&self.marker) {
                    if text.len() > 64 {
                        return Err("Watcher marker exceeded its bound");
                    }
                    let ids = text
                        .split_whitespace()
                        .map(str::parse::<i32>)
                        .collect::<Result<Vec<_>, _>>();
                    if let Ok(ids) = ids {
                        if ids.len() == 2 && ids[0] > 1 && ids[1] > 1 && ids[0] != ids[1] {
                            self.ids = Some((ids[0], ids[1]));
                        }
                    }
                }
            }
            if let Some((leader, watcher)) = self.ids {
                let comm = fs::read_to_string(format!("/proc/{watcher}/comm"))
                    .map_err(|_| "Known watcher identity unavailable")?;
                if comm.trim_end() != "athernex-watch"
                    || unsafe { libc::getpgid(watcher) } != leader
                {
                    return Err("Known watcher identity changed");
                }
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        watcher as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result == 0 && unsafe { info.si_pid() } == watcher {
                    self.zombie_since = Some(Instant::now());
                    return Ok(());
                }
                if result != 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
                {
                    return Err("Known watcher observation failed");
                }
            }
            if Instant::now() >= deadline {
                return Err("Known watcher observation timed out");
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn hold(&mut self, duration: Duration) -> Check<bool> {
        let deadline = self.zombie_since.ok_or("Watcher was not observed")? + duration;
        let mut quiet = self.observed.is_none();
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if self.observed.is_some() {
                thread::sleep(remaining);
            } else {
                match self.result.recv_timeout(remaining) {
                    Ok(value) => {
                        self.observed = Some(value);
                        quiet = false;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(_) => return Err("Command result channel closed"),
                }
            }
        }
        Ok(quiet)
    }

    fn release(&mut self) -> Check<u64> {
        let watcher = self.ids.ok_or("Watcher marker missing")?.1;
        let held = self
            .zombie_since
            .ok_or("Watcher was not observed")?
            .elapsed()
            .as_millis() as u64;
        let mut status = 0;
        if unsafe { libc::waitpid(watcher, &mut status, libc::WNOHANG) } != watcher {
            return Err("Exact watcher reaping failed");
        }
        self.reaped = true;
        Ok(held)
    }

    fn finish(&mut self) -> Check<Observation> {
        let value = match self.observed.take() {
            Some(value) => value,
            None => self
                .result
                .recv_timeout(Duration::from_secs(3))
                .map_err(|_| "Command completion timed out")?,
        };
        self.join()?;
        Ok(value)
    }
    fn group_gone(&self) -> bool {
        let Some((leader, _)) = self.ids else {
            return false;
        };
        // Signal zero only observes the previously owned group; it does not
        // deliver a signal to a possibly recycled process or process group.
        (unsafe { libc::kill(-leader, 0) }) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
    fn join(&mut self) -> Check<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        if let Some(worker) = &self.worker {
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            if !worker.is_finished() {
                return Err("Command worker did not stop");
            }
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| "Command worker panicked")?;
        }
        Ok(())
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        if !self.reaped && self.await_watcher().and_then(|_| self.release()).is_err() {
            // Do not return from an isolated helper while known children or a
            // worker thread might outlive its ownership checks.
            std::process::abort();
        }
        if self.join().is_err() {
            std::process::abort();
        }
    }
}

fn pending(expected: usize) -> Check<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while child::pending_cleanup() != expected {
        if Instant::now() >= deadline {
            return Err("Pending cleanup count did not converge");
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}
fn record(private: &Path, case: Case, observations: Vec<Observation>, held: Vec<u64>) -> Check<()> {
    let metrics = Metrics {
        case,
        observations,
        watcher_hold_ms: held,
        cleanup_finished: child::pending_cleanup() == 0,
    };
    let path = private.join("metrics.json");
    fs::write(
        &path,
        serde_json::to_vec(&metrics).map_err(|_| "Metric serialization failed")?,
    )
    .map_err(|_| "Private metric write failed")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "Private metric permissions failed")
}
fn normal(private: &Path) -> Check<()> {
    let mut group = Group::start(private, "normal", Duration::from_secs(2), 1024);
    group.await_watcher()?;
    let quiet = group.hold(Duration::from_millis(300))?;
    let held = group.release()?;
    let result = group.finish()?;
    pending(0)?;
    let valid = quiet
        && group.group_gone()
        && result.code == Some(7)
        && result.output_matches
        && result.elapsed_ms >= 300
        && result.elapsed_ms < 2000
        && result.pending_at_return == 0;
    record(private, Case::Normal, vec![result], vec![held])?;
    if valid {
        Ok(())
    } else {
        Err("Normal exit completed before exact group cleanup or lost its result")
    }
}
fn failure(private: &Path, output: bool) -> Check<()> {
    let mut group = Group::start(
        private,
        "failure",
        if output {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(150)
        },
        if output { 8 } else { 1024 },
    );
    group.await_watcher()?;
    let quiet = group.hold(Duration::from_millis(700))?;
    // The watcher is still a waitable child here, so pending capacity cannot
    // legitimately be released. Fill the remaining fifteen slots with owned
    // service handles, then demand exact budget refusal for the sixteenth.
    let pending_before = child::pending_cleanup();
    let mut holders = Vec::new();
    for _ in 0..15 {
        holders.push(
            child::Service::start(Command::new("/bin/sleep").arg("10"), 256)
                .map_err(|_| "Remaining capacity could not be occupied")?,
        );
    }
    let full = child::Service::start(Command::new("/bin/sleep").arg("10"), 256)
        .err()
        .is_some_and(|error| error.to_string().contains("budget exhausted"));
    let held = group.release()?;
    let result = group.finish()?;
    pending(0)?;
    let mut reused = child::Service::start(Command::new("/bin/sleep").arg("10"), 256)
        .map_err(|_| "Completed cleanup did not release capacity")?;
    reused
        .stop()
        .map_err(|_| "Capacity control cleanup failed")?;
    for holder in &mut holders {
        holder
            .stop()
            .map_err(|_| "Owned capacity holder cleanup failed")?;
    }
    pending(0)?;
    let valid = !quiet
        && group.group_gone()
        && pending_before == 1
        && full
        && result.code.is_none()
        && result.cleanup_pending
        && result.pending_at_return == 1
        && result.elapsed_ms < 500
        && if output {
            result.output_budget
        } else {
            result.time_budget && result.elapsed_ms >= 150
        };
    record(
        private,
        if output { Case::Output } else { Case::Deadline },
        vec![result],
        vec![held],
    )?;
    if valid {
        Ok(())
    } else {
        Err("Failure cleanup changed its deadline or released pending capacity")
    }
}
fn independent(private: &Path) -> Check<()> {
    let mut long = Group::start(private, "long", Duration::from_secs(2), 1024);
    let mut short = Group::start(private, "short", Duration::from_secs(2), 1024);
    long.await_watcher()?;
    short.await_watcher()?;
    let quiet_short = short.hold(Duration::from_millis(300))?;
    let short_held = short.release()?;
    let short_result = short.finish()?;
    let pending_long = child::pending_cleanup() == 1;
    let long_still_held = !long.reaped;
    let quiet_long = long.hold(Duration::from_millis(700))?;
    let long_held = long.release()?;
    let long_result = long.finish()?;
    pending(0)?;
    let valid = quiet_short
        && quiet_long
        && pending_long
        && long_still_held
        && short_result.code == Some(7)
        && short_result.output_matches
        && short.group_gone()
        && long.group_gone()
        && short_result.elapsed_ms < 2000
        && long_result.code == Some(7)
        && long_result.output_matches
        && long_result.elapsed_ms >= 700
        && long_result.elapsed_ms < 2000;
    record(
        private,
        Case::Independent,
        vec![short_result, long_result],
        vec![short_held, long_held],
    )?;
    if valid {
        Ok(())
    } else {
        Err("Cleanup completion was not independent for each owned group")
    }
}

#[test]
#[ignore = "Isolated subprocess helper; invoked only by its bounded supervisor"]
fn isolated_child_cleanup_worker() {
    let case = std::env::var("ATHERNEX_CHILD_CLEANUP_CASE").expect("Isolated case missing");
    let private = PathBuf::from(
        std::env::var_os("ATHERNEX_CHILD_CLEANUP_PRIVATE").expect("Private fixture root missing"),
    );
    assert!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } == 0,
        "Isolated subreaper setup failed"
    );
    let result = match case.as_str() {
        "normal" => normal(&private),
        "deadline" => failure(&private, false),
        "independent" => independent(&private),
        "output" => failure(&private, true),
        _ => Err("Unknown isolated cleanup case"),
    };
    if let Err(error) = result {
        panic!("{error}");
    }
}
