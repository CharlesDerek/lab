fn main() {
    println!("cargo:rerun-if-changed=src/macos/client.m");
    println!("cargo:rerun-if-changed=src/macos/inspection.m");
    println!("cargo:rerun-if-changed=src/macos/upgrade_listener.m");
    println!("cargo:rerun-if-changed=src/macos/upgrade_inspection.m");
    println!("cargo:rerun-if-changed=src/macos/upgrade.h");
    println!(
        "cargo:rerun-if-changed=../../infrastructure/endpoint/macos-network/Shared/UpgradeIPC.h"
    );
    println!("cargo:rerun-if-changed=src/macos/bridge.h");
    println!(
        "cargo:rerun-if-changed=../../infrastructure/endpoint/macos-network/Shared/NetworkIPC.h"
    );
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let sdk = std::process::Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .expect("The network bridge requires a real Apple SDK");
    assert!(
        sdk.status.success(),
        "The network bridge requires a real Apple SDK"
    );
    let sdk = std::str::from_utf8(&sdk.stdout)
        .expect("Invalid Apple SDK path")
        .trim();
    cc::Build::new()
        .files([
            "src/macos/client.m",
            "src/macos/inspection.m",
            "src/macos/upgrade_listener.m",
            "src/macos/upgrade_inspection.m",
        ])
        .include("../../infrastructure/endpoint/macos-network/Shared")
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .flag("-mmacosx-version-min=12.0")
        .flag("-isysroot")
        .flag(sdk)
        .warnings_into_errors(true)
        .compile("athernex_network_bridge");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
}
