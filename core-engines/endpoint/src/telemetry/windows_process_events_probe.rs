//! Disposable native source proof only; this is not a production collector.
mod native;
mod schema;
mod token;

use std::{
    collections::{BTreeMap, BTreeSet},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

type Result<T> = std::result::Result<T, &'static str>;
const CHILD_TEST: &str = "telemetry::windows_process_events_probe::controlled_child";
const CHILDREN: usize = 8;
const EXIT_CODE: i32 = 23;

fn require(value: bool, message: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(message)
    }
}
fn api(operation: &'static str, code: u32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        println!("\nATHERNEX_PROCESS_PROBE_DIAGNOSTIC={operation}:{code}");
        Err("Native process source API failed")
    }
}
fn failure_category(error: &str) -> &'static str {
    match error {
        "TDH schema provenance differs" => "schema_provenance",
        "TDH schema event identity differs" => "schema_identity",
        "TDH metadata size probe invalid"
        | "TDH metadata exceeds bounds"
        | "TDH metadata result invalid"
        | "TDH property array exceeds buffer"
        | "Invalid schema property name offset"
        | "Schema property name empty"
        | "Schema property name encoding invalid"
        | "Schema property name invalid"
        | "Schema property name unterminated"
        | "Schema property name overlaps metadata array" => "schema_bounds",
        "TDH property count exceeds flat schema budget"
        | "Unsupported structured process schema"
        | "Duplicate process property"
        | "Schema fingerprint failed" => "schema_shape",
        "Required process schema property missing" => "property_missing",
        "Process schema property type differs" => "property_type",
        "Process schema property is not scalar" => "property_scalar",
        "TDH scalar property size differs"
        | "Invalid scalar bytes"
        | "Invalid pointer scalar bytes" => "property_size",
        "Invalid native process provenance" | "Native process pointer width is ambiguous" => {
            "record_provenance"
        }
        "Invalid process payload"
        | "Invalid process extended data"
        | "Process record size overflow"
        | "Process record exceeds copy budget" => "record_bounds",
        "Session GUID ownership differs"
        | "Session name is unterminated"
        | "Session name ownership differs" => "session_ownership",
        "Session source configuration differs" => "session_configuration",
        "Owned trace session removal was not verified" => "session_cleanup",
        "Native source reports lost records" | "Native source lost records during shutdown" => {
            "native_loss"
        }
        "Native callback lost or rejected records"
        | "Native callback lost records before shutdown" => "callback_loss",
        "Native process consumer handle invalid"
        | "Native consumer thread could not start"
        | "Native consumer startup timeout"
        | "Native consumer exited unexpectedly"
        | "Native consumer panicked" => "consumer_lifecycle",
        "Probe executable unavailable"
        | "Controlled child could not start"
        | "Controlled child identifiers collided"
        | "Child status unavailable"
        | "Child exit was not verified"
        | "Reported child parent differs"
        | "Reported child session differs"
        | "Duplicate controlled Start"
        | "Reported child exit differs"
        | "Duplicate controlled End"
        | "Controlled Start missing"
        | "Controlled End missing"
        | "Controlled lifecycle identity differs"
        | "Start and End schemas were not observed" => "controlled_lifecycle",
        "Controlled child timeout" | "Controlled native lifecycle timeout" => "controlled_timeout",
        "Token statistics size differs"
        | "Token privilege size probe invalid"
        | "Token privilege result invalid"
        | "Token privileges exceed buffer"
        | "Process token handle missing"
        | "Thread token handle missing"
        | "Source fixture token state changed"
        | "Source fixture requires its original LocalSystem thread" => "token_state",
        "Native process source API failed" => "api_failure",
        _ => "other",
    }
}
fn failure(error: &str) {
    println!(
        "\nATHERNEX_PROCESS_PROBE_FAILURE={}",
        failure_category(error)
    );
}

struct Children(Vec<Child>);
impl Children {
    fn start() -> Result<Self> {
        let executable = std::env::current_exe().map_err(|_| "Probe executable unavailable")?;
        let mut children = Self(Vec::new());
        for _ in 0..CHILDREN {
            let child = Command::new(&executable)
                .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
                .env("ATHERNEX_PROCESS_SOURCE_CHILD", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| "Controlled child could not start")?;
            children.0.push(child);
        }
        Ok(children)
    }
    fn wait(&mut self) -> Result<BTreeSet<u32>> {
        let ids: BTreeSet<_> = self.0.iter().map(Child::id).collect();
        require(
            ids.len() == CHILDREN,
            "Controlled child identifiers collided",
        )?;
        let deadline = Instant::now() + Duration::from_secs(20);
        for child in &mut self.0 {
            loop {
                match child.try_wait().map_err(|_| "Child status unavailable")? {
                    Some(status) => {
                        require(
                            status.code() == Some(EXIT_CODE),
                            "Child exit was not verified",
                        )?;
                        break;
                    }
                    None if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    None => return Err("Controlled child timeout"),
                }
            }
        }
        Ok(ids)
    }
}
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        eprintln!("Controlled child cleanup exceeded its bounded interval");
                        std::process::abort();
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
}

fn observe(source: &native::Source) -> Result<()> {
    let mut children = Children::start()?;
    let ids = children.wait()?;
    println!("\nATHERNEX_PROCESS_PROBE_STAGE=children_exited");
    let mut starts = BTreeMap::new();
    let mut ends = BTreeMap::new();
    let mut schemas = BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        source.check()?;
        for original in source.drain()? {
            // Rundown and defunct records cannot satisfy lifecycle proof.
            if !matches!(original.header.EventDescriptor.Opcode, 1 | 2) {
                continue;
            }
            let report = schema::decode(&original)?;
            if !ids.contains(&report.pid) {
                continue;
            }
            require(
                report.parent == std::process::id(),
                "Reported child parent differs",
            )?;
            require(report.session == 0, "Reported child session differs")?;
            let identity = (report.key, original.header.TimeStamp);
            if original.header.EventDescriptor.Opcode == 1 {
                require(
                    starts.insert(report.pid, identity).is_none(),
                    "Duplicate controlled Start",
                )?;
            } else {
                require(report.exit == EXIT_CODE, "Reported child exit differs")?;
                require(
                    ends.insert(report.pid, identity).is_none(),
                    "Duplicate controlled End",
                )?;
            }
            let label = if original.header.EventDescriptor.Opcode == 1 {
                "start"
            } else {
                "end"
            };
            let metadata = (
                label,
                original.header.EventDescriptor.Version,
                report.pointer_bits,
                report.property_count,
                report.schema_hash,
            );
            if schemas.insert(metadata.clone()) {
                println!(
                    "\nATHERNEX_PROCESS_PROBE_SCHEMA={}:{}:{}:{}:{}",
                    metadata.0, metadata.1, metadata.2, metadata.3, metadata.4
                );
            }
        }
        if starts.len() == CHILDREN && ends.len() == CHILDREN {
            for pid in &ids {
                let start = starts.get(pid).ok_or("Controlled Start missing")?;
                let end = ends.get(pid).ok_or("Controlled End missing")?;
                require(
                    start.0 != 0 && start.0 == end.0 && start.1 <= end.1,
                    "Controlled lifecycle identity differs",
                )?;
            }
            println!("\nATHERNEX_PROCESS_PROBE_STAGE=lifecycle_verified");
            require(
                schemas.len() >= 2,
                "Start and End schemas were not observed",
            )?;
            println!("\nATHERNEX_PROCESS_PROBE_STAGE=schema_verified");
            return source.check();
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("Controlled native lifecycle timeout")
}

#[test]
#[ignore = "Requires an explicitly disposable native Windows LocalSystem/session-zero host; starts one owned system ETW session"]
fn owned_system_logger_reports_controlled_process_lifecycles() {
    assert!(
        std::env::var("ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST").as_deref()
            == Ok("1"),
        "Disposable process source fixture was not enabled"
    );
    assert!(
        athernex_endpoint_native::windows_state::require_local_system().is_ok(),
        "Process source fixture requires LocalSystem"
    );
    let mut session = u32::MAX;
    assert!(
        unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } != 0 && session == 0,
        "Process source fixture requires session zero"
    );
    println!("\nATHERNEX_PROCESS_PROBE_STAGE=guard_verified");
    native::callback_copies_relocatable_owned_payload_and_rejects_invalid_bounds();
    schema::property_names_and_scalar_metadata_are_bounded_and_typed();
    failure_categories_never_return_arbitrary_error_text();
    let before = token::snapshot().unwrap_or_else(|error| {
        failure(error);
        panic!("Cannot capture source fixture token state");
    });
    require(
        before.unimpersonated(),
        "Source fixture requires its original LocalSystem thread",
    )
    .unwrap_or_else(|error| {
        failure(error);
        panic!("Unexpected fixture impersonation");
    });
    println!("\nATHERNEX_PROCESS_PROBE_STAGE=token_verified");
    let mut source = native::Source::start().unwrap_or_else(|error| {
        failure(error);
        panic!("Owned native process source did not start");
    });
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| observe(&source)));
    let cleanup = source.close();
    let after = token::snapshot();
    if let Err(error) = cleanup {
        failure(error);
    }
    if !after.as_ref().is_ok_and(|value| value == &before) {
        failure("Source fixture token state changed");
    }
    match &outcome {
        Ok(Err(error)) => failure(error),
        Err(_) => failure("Fixture panic"),
        Ok(Ok(())) => (),
    }
    assert!(
        cleanup.is_ok(),
        "Owned native process source cleanup was not verified"
    );
    assert!(
        after.as_ref().is_ok_and(|value| value == &before),
        "Source fixture token state changed"
    );
    println!("\nATHERNEX_PROCESS_PROBE_STAGE=cleanup_verified");
    assert!(
        matches!(outcome, Ok(Ok(()))),
        "Native process lifecycle/schema proof failed"
    );
    println!("\nATHERNEX_PROCESS_PROBE_STAGE=passed");
}

#[test]
#[ignore = "Internal owned helper for the explicitly guarded process source fixture"]
fn controlled_child() {
    assert!(
        std::env::var("ATHERNEX_PROCESS_SOURCE_CHILD").as_deref() == Ok("1"),
        "Controlled child was not enabled"
    );
    std::process::exit(EXIT_CODE);
}

#[test]
fn failure_categories_never_return_arbitrary_error_text() {
    assert!(failure_category("TDH schema provenance differs") == "schema_provenance");
    assert!(failure_category("Process schema property type differs") == "property_type");
    assert!(failure_category("Session GUID ownership differs") == "session_ownership");
    assert!(
        failure_category("private host payload\nATHERNEX_PROCESS_PROBE_STAGE=passed") == "other"
    );
}
