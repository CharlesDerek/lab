#![cfg(any(target_os = "linux", target_os = "macos"))]
use athernex_endpoint_native::{child, probe::Attempt};
use std::{fs, os::unix::fs::PermissionsExt, process::Command, time::Duration};
fn run(
    operation: &str,
    path: &std::path::Path,
    fd: Option<&fs::File>,
) -> (i32, Vec<serde_json::Value>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_athernex-endpoint-native"));
    let descriptor = fd
        .map(|f| child::inherit_lease(&mut cmd, f).unwrap().to_string())
        .unwrap_or_else(|| "-".into());
    cmd.args([
        "probe-owned",
        &std::process::id().to_string(),
        operation,
        path.to_str().unwrap(),
        &descriptor,
        &"a".repeat(64),
    ]);
    let (code, output) = child::run(&mut cmd, Duration::from_secs(5), 8192).unwrap();
    let values = String::from_utf8(output)
        .unwrap()
        .lines()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect();
    (code, values)
}
#[test]
fn actual_probes_distinguish_open_mapping_and_exec_outcomes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = root.join("sample");
    fs::write(&file, b"Public mapping fixture").unwrap();
    let descriptor = fs::File::open(&file).unwrap();
    for (op, fd) in [("open", None), ("mmap", Some(&descriptor))] {
        let (code, values) = run(op, &file, fd);
        assert_eq!(code, 0);
        assert_eq!(values.len(), 2);
        let attempt: Attempt = serde_json::from_value(values[0].clone()).unwrap();
        assert_eq!(attempt.path, file);
        assert_eq!(attempt.identity.size, 22);
        assert_eq!(values[1]["outcome"], "allowed");
    }
    let executable = root.join("true");
    // A full debug management image can exceed the production probe's 16 MiB
    // bound. Compile a dedicated benign native image without changing that cap
    // or modifying a production executable. rustc/linker run in the same bounded
    // owned process group as other fixture commands; this is not a shell script.
    let source = root.join("probe_fixture.rs");
    fs::write(&source, b"fn main() {}\n").unwrap();
    let (compiled, _) = child::run(
        Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&executable),
        Duration::from_secs(30),
        65536,
    )
    .expect("Native probe fixture compiler failed within owned execution limits");
    assert_eq!(compiled, 0, "Native probe fixture compilation failed");
    assert!((1..=16 * 1024 * 1024).contains(&fs::metadata(&executable).unwrap().len()));
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let (code, values) = run("exec", &executable, None);
    assert_eq!(code, 0);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["operation"], "exec");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
    let (code, values) = run("exec", &file, None);
    assert_eq!(code, 1);
    assert_eq!(values[1]["outcome"], "error");
}
#[test]
fn mapping_probe_refuses_descriptor_for_another_file() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let a = root.join("a");
    let b = root.join("b");
    fs::write(&a, b"one").unwrap();
    fs::write(&b, b"two").unwrap();
    let (code, values) = run("mmap", &a, Some(&fs::File::open(b).unwrap()));
    assert_ne!(code, 0);
    assert!(values.is_empty());
}
