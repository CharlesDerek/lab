use athernex_endpoint_native::Result;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        // Copied and re-signed health images exercise real native exec without
        // opening service state, starting a scanner, or acquiring entitlements.
        Some("--athernex-health-image") if args.len() == 1 => Ok(()),
        #[cfg(target_os = "macos")]
        Some("process-events-owned") if args.len() == 3 => {
            athernex_endpoint_native::macos_process_events::run_owned(
                args[1].parse()?,
                args[2].parse()?,
            )
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some("health-status") if args.len() == 2 => {
            let plan=athernex_endpoint_native::service::read_plan(std::path::Path::new(&args[1]))?;
            println!("{}",serde_json::to_string(&athernex_endpoint_native::service::observe(&plan)?)?);Ok(())
        }
        #[cfg(target_os = "linux")]
        Some("prepare-health-fixture") if args.len() == 2 => {
            let plan=athernex_endpoint_native::service::read_plan(std::path::Path::new(&args[1]))?;
            let _quiet=athernex_endpoint_native::service::quiescent(&plan)?;
            let prepared=athernex_endpoint_native::health::prepare(&plan,&std::env::current_exe()?)?;
            athernex_endpoint_native::health::baseline(&prepared,&plan.policy,&std::env::current_exe()?)?;
            println!("{}",serde_json::to_string(&prepared.manifest)?);Ok(())
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some("probe-evidence") if args.len() == 6 => athernex_endpoint_native::probe::validate_saved(std::path::Path::new(&args[1]),std::path::Path::new(&args[2]),std::path::Path::new(&args[3]),&args[4],&args[5]),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some("probe-owned") if args.len() == 6 => {
            let fd=if args[4]=="-" {None} else {Some(args[4].parse()?)};
            let code=athernex_endpoint_native::probe::run(args[1].parse()?,athernex_endpoint_native::probe::Operation::parse(&args[2])?,std::path::Path::new(&args[3]),fd,&args[5])?;
            std::process::exit(code);
        }
        #[cfg(target_os = "macos")]
        Some("supervise") if args.len() == 2 => athernex_endpoint_native::service::supervise(std::path::Path::new(&args[1]), None),
        #[cfg(target_os = "macos")]
        Some("supervise-owned") if args.len() == 3 => athernex_endpoint_native::service::supervise(std::path::Path::new(&args[2]), Some(args[1].parse()?)),
        #[cfg(target_os = "linux")]
        Some("supervise-fixture") if args.len() == 2 => athernex_endpoint_native::service::supervise(std::path::Path::new(&args[1]), None),
        #[cfg(target_os = "linux")]
        Some("supervise-owned-fixture") if args.len() == 3 => athernex_endpoint_native::service::supervise(std::path::Path::new(&args[2]), Some(args[1].parse()?)),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some("scanner-owned") if args.len() == 4 => athernex_endpoint_native::service::scanner_worker(args[1].parse()?, &args[2], std::path::Path::new(&args[3])),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some("adapter-owned") if args.len() == 4 => athernex_endpoint_native::service::adapter_worker(args[1].parse()?, &args[2], std::path::Path::new(&args[3])),
        Some("run") if args.len() == 2 => run_native(&args[1]),
        Some("scan") if args.len() == 3 => scan_file(&args[1], &args[2]),
        #[cfg(unix)]
        Some("query") if args.len() == 3 => {
            let verdict=athernex_endpoint_native::broker::query(std::path::Path::new(&args[1]),std::path::Path::new(&args[2]),std::time::Duration::from_secs(5))?;
            println!("{}",serde_json::to_string(&verdict)?);Ok(())
        }
        #[cfg(target_os = "linux")]
        Some("serve-scanner") if args.len() == 2 => athernex_endpoint_native::broker::serve_fixture(std::path::Path::new(&args[1])),
        _ => Err("Usage: athernex-endpoint-native run PRIVATE_POLICY.json | scan CLAMD_SOCKET ABSOLUTE_FILE | query PRIVATE_STATE ABSOLUTE_FILE. On macOS: supervise PRIVATE_SERVICE_PLAN.json. On Linux: supervise-fixture PRIVATE_SERVICE_PLAN.json (transport/lifecycle tests only). The macOS authorization adapter requires signed packaging and native runtime validation before deployment.".into()),
    }
}

#[cfg(target_os = "macos")]
fn run_native(path: &str) -> Result<()> {
    let policy = athernex_endpoint_native::macos::read_policy_file(std::path::Path::new(path))?;
    athernex_endpoint_native::macos::run(policy)
}

#[cfg(not(target_os = "macos"))]
fn run_native(_path: &str) -> Result<()> {
    Err("Endpoint Security authorization requires macOS 12 or later".into())
}

#[cfg(unix)]
fn scan_file(socket: &str, path: &str) -> Result<()> {
    use athernex_endpoint_native::{scanner, Scan};
    use std::{
        path::Path,
        time::{Duration, Instant},
    };

    let path = Path::new(path);
    let file = scanner::open_file(path)?;
    let request = Scan {
        path: path.into(),
        identity: scanner::identity(&file.metadata()?),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    println!(
        "{}",
        serde_json::to_string(&scanner::scan(&request, Path::new(socket))?)?
    );
    Ok(())
}

#[cfg(not(unix))]
fn scan_file(_socket: &str, _path: &str) -> Result<()> {
    Err("This scanner transport requires Unix sockets".into())
}
