use athernex_endpoint::{Client, Config, Result, Store};
use athernex_endpoint_protocol::PROTOCOL;
use std::{fs, path::PathBuf, time::Duration};

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let args = if args.first().is_some_and(|s| s == "launcher-owned") {
        if args.len() != 5 || args[2] != "supervise" {
            return Err("Invalid owned launcher command".into());
        }
        athernex_endpoint::guardian::guard_parent(args[1].parse()?)?;
        args[2..].to_vec()
    } else {
        args
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let args = if args.first().is_some_and(|s| s == "controller-owned") {
        if args.len() != 4 || !["run", "protect"].contains(&args[2].as_str()) {
            return Err("Invalid owned controller command".into());
        }
        athernex_endpoint_native::child::guard_parent(args[1].parse()?)?;
        args[2..].to_vec()
    } else {
        args
    };
    #[cfg(target_os = "linux")]
    let args = if args.first().is_some_and(|s| s == "native-fixture-owned") {
        if args.len() != 3 {
            return Err("Invalid owned native fixture command".into());
        }
        athernex_endpoint_native::child::guard_parent(args[1].parse()?)?;
        vec!["protect-native-fixture".into(), args[2].clone()]
    } else {
        args
    };
    if args.is_empty() || args[0] == "--help" {
        println!("athernex-endpoint enroll BOOTSTRAP_JSON STATE_DIR\nathernex-endpoint provision-antivirus BOOTSTRAP_JSON STATE_DIR\nathernex-endpoint run STATE_DIR [--once]\nState is private and durable. Endpoint policy is STATE_DIR/config.json. HTTPS required outside literal loopback. Existing antivirus is preserved.");
        println!("athernex-endpoint protection-status STATE_DIR [--require-active]\nathernex-endpoint release-keygen NEW_PRIVATE_DIRECTORY\nathernex-endpoint release-sign KEY_PK8 BINARY VERSION CHANNEL SEQUENCE EXPIRES_MS OUTPUT_JSON\nathernex-endpoint update-stage STATE_DIR SIGNED_RELEASE_JSON BINARY\nathernex-endpoint update-apply STATE_DIR\nathernex-endpoint update-recover STATE_DIR\nathernex-endpoint update-status STATE_DIR\nUse controller-update-stage/apply/recover/status for the separately configured controller_path.\nUpdates require a locally trusted release key. Apply/recover require stopped services and a separate trusted updater executable.");
        println!("athernex-endpoint supervise STATE_DIR INSTALLED_BINARY\nathernex-endpoint launch STATE_DIR CONTROLLER_BINARY AGENT_BINARY\nathernex-endpoint controller-update-request STATE_DIR RELEASE_ID DEADLINE_MS\nathernex-endpoint controller-update-cancel STATE_DIR RELEASE_ID\nathernex-endpoint controller-maintenance-status STATE_DIR\nLauncher, controller and agent must be separate trusted executable copies. Automatic controller replacement requires explicit local policy and an exact signed request.");
        println!("athernex-endpoint release-publish SIGNED_MANIFEST BINARY PUBLIC_KEY CATALOG_DIR");
        #[cfg(windows)]
        println!("athernex-endpoint windows-service STATE_DIR CONTROLLER_BINARY AGENT_BINARY\nSCM-only LocalSystem host for the stable launcher. Service running state does not establish prevention readiness.");
        println!("athernex-endpoint engine-sign KEY_PK8 CONTENT_DIRECTORY ROLES_JSON TARGET VERSION CHANNEL SEQUENCE EXPIRES_MS OUTPUT_JSON\nathernex-endpoint engine-publish SIGNED_MANIFEST CONTENT_DIRECTORY PUBLIC_KEY_FILE CATALOG_DIR\nathernex-endpoint engine-stage STATE_DIR SIGNED_MANIFEST CONTENT_DIRECTORY\nathernex-endpoint engine-apply|engine-recover|engine-discard|engine-prune|engine-status STATE_DIR\nathernex-endpoint engine-request STATE_DIR RELEASE_ID DEADLINE_MS\nathernex-endpoint engine-cancel STATE_DIR RELEASE_ID\nManual engine activation requires stopped services and a locally pinned engine key/root. Queued activation requires local engine automatic policy and a live controller.");
        #[cfg(target_os = "linux")]
        println!("athernex-endpoint configure-protection STATE_DIR\nathernex-endpoint protect STATE_DIR\nLinux native prevention requires root, clamd/clamonacc, signatures and configured scan roots. The installer creates its separate protection service.");
        #[cfg(target_os = "macos")]
        println!("athernex-endpoint configure-native-protection STATE_DIR SIGNED_ADAPTER\nathernex-endpoint protect STATE_DIR\nmacOS setup requires a signed Endpoint Security adapter and provisioned ClamAV signatures. It prepares a dedicated scanner account and runtime. The controller starts enabled protection separately; native authorization and live blocking remain unverified.");
        #[cfg(target_os = "macos")]
        println!("athernex-endpoint configure-macos-process-adapter STATE_DIR APPROVED_SIGNED_ADAPTER SHA256\nRecords the approved process helper pin with services stopped. This does not enable telemetry or protection and does not require ClamAV. Enable macos_process_events separately in local telemetry policy.");
        #[cfg(target_os = "macos")]
        println!("athernex-endpoint configure-macos-authentication-adapter STATE_DIR APPROVED_SIGNED_ADAPTER SHA256\nRecords the approved authentication helper pin with services stopped. Collection remains disabled. Enable macos_authentication separately on macOS13 or newer; no ClamAV setup is required.");
        #[cfg(target_os = "macos")]
        println!("athernex-endpoint install-macos-network-bundle STATE_DIR APPROVED_ARCHIVE RELEASE_JSON\nInstalls the approved network app and records its private pin with services stopped. Existing enablement is preserved; this does not activate the OS extension. Activate the container and enable macos_network_events separately on macOS13 or newer. Stopping the consumer does not stop the provider.");
        #[cfg(target_os = "macos")]
        println!("athernex-endpoint prepare-macos-network-upgrade STATE_DIR APPROVED_ARCHIVE RELEASE_JSON OPERATOR_UID\nathernex-endpoint recover-macos-network-upgrade STATE_DIR\nathernex-endpoint abort-macos-network-upgrade STATE_DIR\nathernex-endpoint finish-macos-network-upgrade STATE_DIR\nathernex-endpoint macos-network-upgrade-status STATE_DIR\nRoot-controlled network replacement requires the standard management job unloaded first and an approved non-root operator for the container. Abort is available only before an issued request; uncertain outcomes require reconciliation and may require reboot. Finish restores registration but does not bootstrap normal management. Existing filter policy and event history are preserved. Signed-host upgrade acceptance remains unverified.");
        return Ok(());
    }
    match args[0].as_str() {
        #[cfg(windows)]
        "windows-service" if args.len() == 4 => {
            athernex_endpoint::windows_service::run(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
            )?;
        }
        #[cfg(windows)]
        "windows-install" if args.len() == 4 => {
            athernex_endpoint::installer::install(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
            )?;
        }
        #[cfg(windows)]
        "protect-windows-preview" if args.len() == 2 => {
            athernex_endpoint::protection::windows::supervise_preview(std::path::Path::new(
                &args[1],
            ))?;
        }
        #[cfg(windows)]
        "windows-filter-worker" if args.len() == 2 => {
            athernex_endpoint::protection::windows::worker_main(args[1].parse()?)?;
        }
        #[cfg(windows)]
        "windows-desktop-worker" if args.len() == 2 => {
            athernex_endpoint::windows_desktop_worker(args[1].parse()?)?;
        }
        #[cfg(windows)]
        "windows-scratch-worker" if args.len() == 2 => {
            athernex_endpoint::protection::windows::scratch_worker(args[1].parse()?)?;
        }
        #[cfg(windows)]
        "windows-scratch-cleanup" if args.len() == 2 => {
            println!(
                "{}",
                serde_json::to_string(
                    &athernex_endpoint::protection::windows::scratch_cleanup_worker(
                        args[1].parse()?
                    )?
                )?
            );
        }
        #[cfg(windows)]
        "windows-workspace-cleanup" if args.len() == 2 => {
            println!(
                "{}",
                serde_json::to_string(
                    &athernex_endpoint::protection::windows::workspace_cleanup_worker(
                        args[1].parse()?
                    )?
                )?
            );
        }
        #[cfg(windows)]
        "windows-protection-recover" if args.len() == 2 => {
            athernex_endpoint::protection::windows::recover(std::path::Path::new(&args[1]))?;
            println!("{{\"schema\":1,\"recovered\":true}}");
        }
        #[cfg(windows)]
        "windows-protection-status" if args.len() == 2 => {
            println!(
                "{}",
                serde_json::to_string(&athernex_endpoint::protection::windows::status(
                    std::path::Path::new(&args[1])
                )?)?
            );
        }
        "installer-network-hash" if args.len() == 2 => {
            if let Some(hash) = athernex_endpoint::macos_network_bundle::installer_hash(
                std::path::Path::new(&args[1]),
            )? {
                println!("{hash}");
            }
        }
        #[cfg(target_os = "macos")]
        "inspect-macos-network-bundle" if args.len() == 3 => {
            let result = athernex_endpoint::macos_network_bundle::inspect(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
            )?;
            println!("{}", serde_json::to_string(&result)?);
        }
        #[cfg(target_os = "macos")]
        "installer-network-check" if args.len() == 3 => {
            athernex_endpoint::macos_network_bundle::preflight(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
            )?;
        }
        #[cfg(target_os = "macos")]
        "install-macos-network-bundle" if args.len() == 4 => {
            athernex_endpoint::macos_network_bundle::install(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
            )?;
        }
        #[cfg(target_os = "macos")]
        "prepare-macos-network-upgrade" if args.len() == 5 => {
            athernex_endpoint::macos_network_bundle::upgrade::prepare(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
                args[4].parse()?,
            )?;
        }
        #[cfg(target_os = "macos")]
        "recover-macos-network-upgrade" if args.len() == 2 => {
            athernex_endpoint::macos_network_bundle::upgrade::recover(std::path::Path::new(
                &args[1],
            ))?;
        }
        #[cfg(target_os = "macos")]
        "abort-macos-network-upgrade" if args.len() == 2 => {
            athernex_endpoint::macos_network_bundle::upgrade::abort(std::path::Path::new(
                &args[1],
            ))?;
        }
        #[cfg(target_os = "macos")]
        "finish-macos-network-upgrade" if args.len() == 2 => {
            athernex_endpoint::macos_network_bundle::upgrade::finish(std::path::Path::new(
                &args[1],
            ))?;
        }
        #[cfg(target_os = "macos")]
        "macos-network-upgrade-status" if args.len() == 2 => {
            println!(
                "{}",
                serde_json::to_string(&athernex_endpoint::macos_network_bundle::upgrade::status(
                    std::path::Path::new(&args[1])
                )?)?
            );
        }
        // Private launchd entry point; never a general operator workflow.
        #[cfg(target_os = "macos")]
        "serve-macos-network-upgrade" if args.len() == 3 => {
            athernex_endpoint::macos_network_bundle::upgrade::serve(
                std::path::Path::new(&args[1]),
                &args[2],
            )?;
        }
        "installer-native-hash" if args.len() == 2 => {
            if let Some(hash) =
                athernex_endpoint::update::installer_native_hash(std::path::Path::new(&args[1]))?
            {
                println!("{hash}");
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        "native-mutation-worker" if args.len() == 2 => {
            athernex_endpoint::native_mutation::worker_main(args[1].parse()?)?;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "native-response-worker" if args.len() == 2 => {
            athernex_endpoint::protection::native_response::worker_main(args[1].parse()?)?;
        }
        "installer-check" if args.len() == 3 || (args.len() == 4 && args[3] == "--stopped") => {
            athernex_endpoint::update::installer_check(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                args.len() == 4,
            )?;
        }
        "launch" if args.len() == 4 => {
            athernex_endpoint::guardian::launch(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
            )?;
        }
        "controller-update-request" if args.len() == 4 => {
            athernex_endpoint::guardian::request(
                std::path::Path::new(&args[1]),
                &args[2],
                args[3].parse()?,
            )?;
        }
        "controller-update-cancel" if args.len() == 3 => {
            athernex_endpoint::guardian::cancel(std::path::Path::new(&args[1]), &args[2])?;
        }
        "controller-maintenance-status" if args.len() == 2 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&athernex_endpoint::guardian::status(
                    std::path::Path::new(&args[1])
                )?)?
            );
        }
        "supervise" if args.len() == 3 => {
            athernex_endpoint::supervisor::supervise(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
            )?;
        }
        "release-publish" if args.len() == 5 => {
            println!(
                "{}",
                athernex_endpoint::update::publish(
                    std::path::Path::new(&args[1]),
                    std::path::Path::new(&args[2]),
                    &args[3],
                    std::path::Path::new(&args[4])
                )?
            );
        }
        "engine-publish" if args.len() == 5 => {
            let public = fs::read_to_string(&args[3])?;
            println!(
                "{}",
                athernex_endpoint::managed_engine::publish(
                    std::path::Path::new(&args[1]),
                    std::path::Path::new(&args[2]),
                    &public,
                    std::path::Path::new(&args[4])
                )?
            );
        }
        "release-check" if args.len() == 2 => {
            if !athernex_endpoint_protocol::hex_id(&args[1]) {
                return Err("Invalid release challenge".into());
            }
            println!(
                "{}",
                serde_json::json!({"challenge":args[1],"protocol":PROTOCOL,"target":athernex_endpoint_protocol::update::target(),"version":env!("CARGO_PKG_VERSION"),"controller_protocol":1})
            );
        }
        "release-keygen" if args.len() == 2 => {
            println!(
                "{}",
                athernex_endpoint::update::keygen(std::path::Path::new(&args[1]))?
            );
        }
        "release-sign" if args.len() == 8 => {
            athernex_endpoint::update::sign(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                &args[3],
                &args[4],
                args[5].parse()?,
                args[6].parse()?,
                std::path::Path::new(&args[7]),
            )?;
        }
        "update-stage" | "controller-update-stage" if args.len() == 4 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&athernex_endpoint::update::stage_component(
                    std::path::Path::new(&args[1]),
                    if args[0].starts_with("controller-") {
                        athernex_endpoint::update::Component::Controller
                    } else {
                        athernex_endpoint::update::Component::Agent
                    },
                    std::path::Path::new(&args[2]),
                    std::path::Path::new(&args[3])
                )?)?
            );
        }
        "engine-sign" if args.len() == 10 => {
            athernex_endpoint::engine_update::sign(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
                athernex_endpoint::engine_update::Signing {
                    target: &args[4],
                    version: &args[5],
                    channel: &args[6],
                    sequence: args[7].parse()?,
                    expires: args[8].parse()?,
                },
                std::path::Path::new(&args[9]),
            )?;
        }
        "engine-request" if args.len() == 4 => {
            let state = std::path::Path::new(&args[1]);
            athernex_endpoint::engine_update::automatic::request(
                state,
                &args[2],
                args[3].parse()?,
            )?;
            println!("{}", athernex_endpoint::engine_update::summary(state)?);
        }
        "engine-cancel" if args.len() == 3 => {
            let state = std::path::Path::new(&args[1]);
            athernex_endpoint::engine_update::automatic::cancel(state, &args[2])?;
            println!("{}", athernex_endpoint::engine_update::summary(state)?);
        }
        "engine-stage" if args.len() == 4 => {
            let state = std::path::Path::new(&args[1]);
            athernex_endpoint::engine_update::stage(
                state,
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
            )?;
            println!("{}", athernex_endpoint::engine_update::summary(state)?);
        }
        "engine-apply" | "engine-recover" | "engine-discard" | "engine-prune" | "engine-status"
            if args.len() == 2 =>
        {
            let state = std::path::Path::new(&args[1]);
            match args[0].as_str() {
                "engine-apply" => athernex_endpoint::engine_update::apply(state)?,
                "engine-recover" => athernex_endpoint::engine_update::recover(state)?,
                "engine-discard" => athernex_endpoint::engine_update::discard(state)?,
                "engine-prune" => athernex_endpoint::engine_update::prune(state)?,
                _ => (),
            }
            println!("{}", athernex_endpoint::engine_update::summary(state)?);
        }
        "update-apply" | "controller-update-apply" if args.len() == 2 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&athernex_endpoint::update::apply_component(
                    std::path::Path::new(&args[1]),
                    if args[0].starts_with("controller-") {
                        athernex_endpoint::update::Component::Controller
                    } else {
                        athernex_endpoint::update::Component::Agent
                    }
                )?)?
            );
        }
        "update-recover" | "controller-update-recover" if args.len() == 2 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&athernex_endpoint::update::recover_component(
                    std::path::Path::new(&args[1]),
                    if args[0].starts_with("controller-") {
                        athernex_endpoint::update::Component::Controller
                    } else {
                        athernex_endpoint::update::Component::Agent
                    }
                )?)?
            );
        }
        "update-status" | "controller-update-status" if args.len() == 2 => {
            let record = athernex_endpoint::update::status_component(
                std::path::Path::new(&args[1]),
                if args[0].starts_with("controller-") {
                    athernex_endpoint::update::Component::Controller
                } else {
                    athernex_endpoint::update::Component::Agent
                },
            )?;
            let mut output = serde_json::to_value(&record)?;
            if args[0].starts_with("controller-") {
                output["staged_release_id"] =
                    serde_json::json!(record.staged.as_ref().map(|r| r.id()).transpose()?);
                output["installed_release_id"] =
                    serde_json::json!(record.installed.as_ref().map(|r| r.id()).transpose()?);
            }
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        #[cfg(target_os = "linux")]
        "configure-protection" if args.len() == 2 => {
            athernex_endpoint::protection::configure(std::path::Path::new(&args[1]))?;
        }
        #[cfg(target_os = "macos")]
        "configure-native-protection" if args.len() == 3 => {
            athernex_endpoint::protection::native_setup::configure(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
            )?;
        }
        #[cfg(target_os = "macos")]
        "configure-macos-process-adapter" if args.len() == 4 => {
            athernex_endpoint::telemetry::configure_macos_process_adapter(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                &args[3],
            )?;
        }
        #[cfg(target_os = "macos")]
        "configure-macos-authentication-adapter" if args.len() == 4 => {
            athernex_endpoint::telemetry::configure_macos_authentication_adapter(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                &args[3],
            )?;
        }
        #[cfg(target_os = "linux")]
        "configure-native-fixture" if args.len() == 6 => {
            athernex_endpoint::protection::native_setup::configure_fixture(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
                args[4].parse()?,
                args[5].parse()?,
            )?;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "protect" if args.len() == 2 => {
            athernex_endpoint::protection::supervise(std::path::Path::new(&args[1]))?;
        }
        #[cfg(target_os = "linux")]
        "protect-native-fixture" if args.len() == 2 => {
            athernex_endpoint::protection::managed_native::supervise(std::path::Path::new(
                &args[1],
            ))?;
        }
        #[cfg(target_os = "linux")]
        "native-fixture-status" | "native-fixture-quiescent" if args.len() == 2 => {
            let state = PathBuf::from(&args[1]).canonicalize()?;
            let config: Config = serde_json::from_slice(&fs::read(state.join("config.json"))?)?;
            config.validate()?;
            if args[0] == "native-fixture-quiescent" {
                let _lease = athernex_endpoint::protection::managed_native::quiescent(
                    &config.protection,
                    &state,
                )?;
            } else {
                println!(
                    "{}",
                    serde_json::to_string(&athernex_endpoint::protection::managed_native::health(
                        &config.protection,
                        &state
                    ))?
                );
            }
        }
        #[cfg(target_os = "linux")]
        "protection-probe-read" if args.len() == 2 => {
            std::process::exit(athernex_endpoint::protection::probe_read(
                std::path::Path::new(&args[1]),
            ));
        }
        #[cfg(target_os = "linux")]
        "protection-mutation-hash" if args.len() == 3 => {
            println!(
                "{}",
                serde_json::to_string(&athernex_endpoint::protection::mutation_hash_worker(
                    args[1].parse()?,
                    args[2].parse()?
                )?)?
            );
        }
        #[cfg(target_os = "linux")]
        "protection-scan" if args.len() == 3 => {
            println!(
                "{}",
                athernex_endpoint::protection::scan_worker(
                    std::path::Path::new(&args[1]),
                    std::path::Path::new(&args[2])
                )?
            );
        }
        "protection-status"
            if args.len() == 2 || (args.len() == 3 && args[2] == "--require-active") =>
        {
            let state = PathBuf::from(&args[1]);
            let config: Config = serde_json::from_slice(&fs::read(state.join("config.json"))?)?;
            config.validate()?;
            let health = athernex_endpoint::protection::health(&config, &state);
            println!("{}", serde_json::to_string_pretty(&health)?);
            if args.len() == 3 && health.state != "active" {
                std::process::exit(3);
            }
        }
        "protection-enabled" if args.len() == 2 => {
            let config: Config =
                serde_json::from_slice(&fs::read(PathBuf::from(&args[1]).join("config.json"))?)?;
            config.validate()?;
            std::process::exit(if config.protection.enabled { 0 } else { 3 });
        }
        "capture-telemetry" if args.len() == 1 || (args.len() == 3 && args[1] == "--pid") => {
            let pid = args.get(2).map(|v| v.parse()).transpose()?;
            let snapshot = athernex_endpoint::telemetry::capture_native(pid)?;
            println!("{}", serde_json::to_string(&snapshot)?);
        }
        "provision-antivirus" if args.len() == 3 => {
            let bootstrap =
                athernex_endpoint::setup::read_bootstrap(std::path::Path::new(&args[1]))?;
            #[cfg(windows)]
            let _store = athernex_endpoint::setup::open_store(std::path::Path::new(&args[2]))?;
            athernex_endpoint::setup::provision(&bootstrap, std::path::Path::new(&args[2]))?;
        }
        "enroll" if args.len() == 3 => {
            let bootstrap =
                athernex_endpoint::setup::read_bootstrap(std::path::Path::new(&args[1]))?;
            let directory = PathBuf::from(&args[2]);
            let store = athernex_endpoint::setup::open_store(&directory)?;
            let config = athernex_endpoint::setup::enroll(&bootstrap, &store)?;
            Client::new(config)?.cycle(&store)?;
            println!("Endpoint enrolled. Configure local action roots and scanner paths before enabling protection.");
        }
        "run" if args.len() == 2 || (args.len() == 3 && args[2] == "--once") => {
            let directory = PathBuf::from(&args[1]);
            let config: Config = serde_json::from_slice(&fs::read(directory.join("config.json"))?)?;
            let poll_secs = if config.telemetry.enabled {
                config.telemetry.interval_secs.min(
                    if config.telemetry.linux_process_events
                        || config.telemetry.linux_authentication
                        || config.telemetry.windows_authentication
                        || config.telemetry.windows_process_events
                        || config.telemetry.macos_process_events
                        || config.telemetry.macos_authentication
                        || config.telemetry.macos_network_events
                        || config.telemetry.windows_network_events
                        || config.telemetry.linux_network_events
                    {
                        5
                    } else {
                        30
                    },
                )
            } else {
                30
            };
            let telemetry_policy = config.telemetry.clone();
            let client = Client::new(config)?;
            let store = Store::open(&directory)?;
            athernex_endpoint::update::require_recovered(&directory)?;
            let supervised = athernex_endpoint::supervisor::enter(&directory)?;
            store.recover()?;
            let once = args.get(2).is_some_and(|a| a == "--once");
            if once
                && (telemetry_policy.linux_process_events
                    || telemetry_policy.linux_authentication
                    || telemetry_policy.windows_authentication
                    || telemetry_policy.windows_process_events
                    || telemetry_policy.macos_process_events
                    || telemetry_policy.macos_authentication
                    || telemetry_policy.macos_network_events
                    || telemetry_policy.windows_network_events
                    || telemetry_policy.linux_network_events)
            {
                return Err("Native event collection requires continuous run mode".into());
            }
            let collector = if once {
                None
            } else {
                Some(athernex_endpoint::telemetry::ContinuousCollector::start(
                    &store,
                    &telemetry_policy,
                )?)
            };
            loop {
                let telemetry = match &collector {
                    Some(worker) => worker.check(),
                    None => client.collect_telemetry(&store),
                };
                let cycle = client.cycle(&store);
                if cycle.is_ok() && telemetry.is_ok() {
                    if let Some(token) = &supervised {
                        athernex_endpoint::supervisor::notify_ready(&directory, token)?;
                    }
                }
                if supervised.is_some()
                    && !athernex_endpoint::supervisor::in_trial(&directory)?
                    && athernex_endpoint::supervisor::requested(&directory)?
                {
                    drop(collector);
                    drop(store);
                    std::process::exit(athernex_endpoint::supervisor::update_exit_code());
                }
                let maintenance = if athernex_endpoint::supervisor::in_trial(&directory)? {
                    Ok(())
                } else {
                    client.maintain(&store)
                };
                if once {
                    cycle?;
                    maintenance?;
                    telemetry?;
                    break;
                }
                if let Err(error) = cycle {
                    eprintln!("{error}");
                }
                if let Err(error) = telemetry {
                    eprintln!("Endpoint telemetry: {error}");
                }
                if let Err(error) = maintenance {
                    eprintln!("Local protection maintenance: {error}");
                }
                std::thread::sleep(Duration::from_secs(poll_secs));
            }
        }
        _ => return Err("Invalid command; use --help".into()),
    }
    Ok(())
}
