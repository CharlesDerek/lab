//! Actual installer metadata command; OS signature validation is a separate gate.
use athernex_endpoint_protocol::{
    hash,
    installer::{Artifact, NativeArtifact},
    update::target,
};
use std::{fs, process::Command};

#[test]
fn installer_metadata_command_is_platform_and_binary_bound() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("release.json");
    let binary = env!("CARGO_BIN_EXE_athernex-endpoint");
    let native = cfg!(target_os = "macos").then(|| NativeArtifact {
        backend: "macos-endpoint-security".into(),
        sha256: "b".repeat(64),
        signing: "native-signature-verified".into(),
    });
    let mut artifact = Artifact {
        target: target(),
        version: "fixture".into(),
        sha256: hash(&fs::read(binary).unwrap()),
        signing: "native-signature-verified".into(),
        native_adapter: native,
    };
    let run = || {
        Command::new(binary)
            .arg("installer-native-hash")
            .arg(&manifest)
            .output()
            .unwrap()
    };
    fs::write(&manifest, serde_json::to_vec(&artifact).unwrap()).unwrap();
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        if cfg!(target_os = "macos") {
            "b".repeat(64)
        } else {
            String::new()
        }
    );
    if cfg!(target_os = "macos") {
        artifact.sha256 = "0".repeat(64);
        fs::write(&manifest, serde_json::to_vec(&artifact).unwrap()).unwrap();
        assert!(!run().status.success());
    }
    artifact.target = "unsupported-target".into();
    fs::write(&manifest, serde_json::to_vec(&artifact).unwrap()).unwrap();
    assert!(!run().status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn installer_refuses_unavailable_command_lifetime_monitoring_before_state_changes() {
    use std::os::unix::process::CommandExt;
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("untouched-state");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_athernex-endpoint"));
    command
        .arg("installer-check")
        .arg(&state)
        .arg(env!("CARGO_BIN_EXE_athernex-endpoint"));
    unsafe {
        command.pre_exec(|| {
            // Deny only close_range in this disposable child, representing a
            // kernel/container policy that cannot support the lifetime guard.
            let filter = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_close_range as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut _,
            };
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let result = command.output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("close_range"));
    assert!(!state.exists());
}
