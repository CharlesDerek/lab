use athernex_siem::{
    engine::Engine,
    model::now_ms,
    web::{self, App},
};
use std::{
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

fn initialize_key(path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    writeln!(file, "{}", athernex_siem::gateway::secret()?)?;
    file.sync_all()?;
    println!("Created private operator key file. Existing files are never overwritten.");
    Ok(())
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port = 8787u16;
    let mut database = None;
    let mut demo = false;
    let mut journal = true;
    let mut memory = false;
    let mut key_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => port = args.next().ok_or("--port needs a value")?.parse()?,
            "--db" => database = Some(args.next().ok_or("--db needs a path")?),
            "--demo" => demo = true,
            "--no-seed" => demo = false,
            "--no-journal" => journal = false,
            "--memory" => memory = true,
            "--operator-key-file" => {
                key_file = Some(args.next().ok_or("--operator-key-file needs a path")?)
            }
            "--init-operator-key" => {
                return initialize_key(&args.next().ok_or("--init-operator-key needs a path")?)
            }
            "--help" | "-h" => {
                println!("athernex-siem [--port 8787] [--db PATH] [--operator-key-file PATH] [--no-journal] [--demo] [--memory]\nOperational by default: local journald collector, no sample events. Loopback only.\nDefault database: .athernex/live.sqlite3 (demo: .athernex/demo.sqlite3). Never mix modes.\n--no-journal disables the collector process; sources remain visible.\n--init-operator-key PATH creates a private key file and exits.\nOtherwise use ATHERNEX_OPERATOR_KEY or the random key printed in an interactive terminal.\nService deployments require a key file or environment credential. --no-seed is a compatibility alias for operational mode.");
                return Ok(());
            }
            _ => return Err(format!("Unknown argument: {arg}").into()),
        }
    }
    let generated = key_file.is_none() && std::env::var("ATHERNEX_OPERATOR_KEY").is_err();
    if generated {
        use std::io::IsTerminal;
        if !std::io::stdout().is_terminal() {
            return Err(
                "Non-interactive deployment requires --operator-key-file or ATHERNEX_OPERATOR_KEY"
                    .into(),
            );
        }
    }
    let operator_key = if let Some(path) = key_file {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
                return Err(
                    "Operator key file must not be accessible to group or others (chmod 600)"
                        .into(),
                );
            }
        }
        std::fs::read_to_string(path)?.trim().to_string()
    } else {
        std::env::var("ATHERNEX_OPERATOR_KEY").unwrap_or(athernex_siem::gateway::secret()?)
    };
    let operator = Arc::new(athernex_siem::auth::OperatorAuth::new(&operator_key)?);
    // Refuse an occupied port before opening or migrating any ledger.
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let database = database.unwrap_or_else(|| {
        if demo {
            ".athernex/demo.sqlite3"
        } else {
            ".athernex/live.sqlite3"
        }
        .into()
    });
    let mut engine = if memory {
        Engine::memory()?
    } else {
        Engine::open(Path::new(&database))?
    };
    engine.configure_mode(demo)?;
    if demo {
        engine.seed(now_ms())?;
        engine.seed_hive(now_ms())?;
        engine.flush(now_ms())?;
    } else if journal && !engine.sources()?.iter().any(|s| s.id == "host-journal") {
        engine.create_source("host-journal", "journal", "", now_ms())?;
    }
    let ingest_token = if demo {
        std::env::var("ATHERNEX_INGEST_TOKEN").ok()
    } else {
        None
    };
    if ingest_token.as_ref().is_some_and(|token| token.len() < 24) {
        return Err("ATHERNEX_INGEST_TOKEN must contain at least 24 characters".into());
    }
    if generated {
        println!("Operator key (local console only): {operator_key}");
    }
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: athernex_siem::gateway::secret()?,
        ingest_token,
        operator,
    };
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let collector = if journal && !demo {
        Some(tokio::spawn(athernex_siem::collector::run(
            Arc::clone(&app.engine),
            stopped.clone(),
        )))
    } else {
        None
    };
    let ticker = Arc::clone(&app.engine);
    let mut ticker_stop = stopped;
    let tick = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {_=ticker_stop.changed()=>break, _=interval.tick()=>{}}
            if let Ok(mut engine) = ticker.lock() {
                match engine.tick(now_ms()) {
                    Ok(()) => engine.storage_error.clear(),
                    Err(error) => {
                        engine.live = false;
                        engine.storage_error = error.to_string();
                    }
                }
            }
        }
    });
    println!("Athernex SIEM · http://127.0.0.1:{port} · {}\nAEF1 facts / AXR2 archive · SIGTERM flushes pending telemetry",if demo {"synthetic demo"} else {"operational"});
    let shutdown_engine = Arc::clone(&app.engine);
    let result = axum::serve(listener, web::router(app))
        .with_graceful_shutdown(shutdown_signal())
        .await;
    let _ = stop.send(true);
    if let Some(collector) = collector {
        collector.await?;
    }
    tick.await?;
    shutdown_engine
        .lock()
        .map_err(|_| "Engine unavailable at shutdown")?
        .flush(now_ms())?;
    result?;
    Ok(())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=terminate.recv()=>{} }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
