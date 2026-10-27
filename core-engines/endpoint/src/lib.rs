//! Portable endpoint runtime. All work is explicit, bounded and journaled before execution.
pub mod antivirus;
pub mod engine_update;
pub mod guardian;
#[cfg(any(windows, test))]
pub mod installer;
pub mod macos_network_bundle;
pub mod managed_engine;
pub mod managed_update;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod native_mutation;
pub mod protection;
mod scan;
pub mod setup;
pub mod supervisor;
pub mod telemetry;
mod telemetry_sockets;
pub mod update;
pub mod windows_driver;
pub mod windows_filter_package;
#[cfg(windows)]
mod windows_job;
#[cfg(windows)]
mod windows_private_write;
#[cfg(any(windows, test))]
pub mod windows_service;
#[cfg(any(windows, test))]
mod windows_wire;
use athernex_endpoint_protocol as protocol;
use protocol::{Action, Command, EndpointEvent, Heartbeat, Platform, Receipt};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
#[cfg(not(windows))]
pub use std::process::Command as Process;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(windows)]
#[doc(hidden)]
pub use windows_job::desktop_worker as windows_desktop_worker;
#[cfg(windows)]
pub use windows_job::Command as Process;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn secret() -> Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| e.to_string())?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub engine_updates: engine_update::Policy,
    #[serde(default)]
    pub updates: update::UpdatePolicy,
    #[serde(default)]
    pub protection: protection::ProtectionConfig,
    #[serde(default)]
    pub telemetry: telemetry::TelemetryConfig,
    pub server: String,
    pub endpoint_id: String,
    pub credential: String,
    pub enrollment_token: Option<String>,
    pub scanner: PathBuf,
    pub updater: PathBuf,
    pub scan_roots: Vec<PathBuf>,
    pub allow_scripts: bool,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub signature_database: Option<PathBuf>,
    #[serde(default)]
    pub signature_config: Option<PathBuf>,
    #[serde(default)]
    pub maintenance: Maintenance,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Maintenance {
    pub scan_interval_secs: u64,
    pub signature_interval_secs: u64,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        self.engine_updates.validate()?;
        self.updates.validate()?;
        self.protection.validate()?;
        protocol::server_url(&self.server)?;
        self.telemetry.validate()?;
        for interval in [
            self.maintenance.scan_interval_secs,
            self.maintenance.signature_interval_secs,
        ] {
            if interval != 0 && !(3600..=30 * 86400).contains(&interval) {
                return Err(
                    "Maintenance intervals must be disabled or between one hour and 30 days".into(),
                );
            }
        }
        if !protocol::hex_id(&self.endpoint_id)
            || !protocol::hex_id(&self.credential)
            || !self.scanner.is_absolute()
            || !self.updater.is_absolute()
            || self.scan_roots.is_empty()
            || self.scan_roots.len() > 16
            || self.scan_roots.iter().any(|p| !p.is_absolute())
        {
            return Err("Invalid endpoint configuration".into());
        }
        Ok(())
    }
}

pub fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("No parent directory")?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    #[cfg(windows)]
    windows_private_write::persist(temp, path)?;
    #[cfg(not(windows))]
    temp.persist(path)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

struct StateLock(fs::File);
impl Drop for StateLock {
    fn drop(&mut self) {
        // A forked child can briefly inherit the open file description before exec.
        // Explicit unlock releases ownership even while that duplicate still exists.
        let _ = self.0.unlock();
    }
}
pub struct Store {
    pub connection: Connection,
    pub directory: PathBuf,
    // Only this process's live collector can keep a durable in-flight capture
    // healthy. Reopening the state never adopts an interrupted worker.
    pub(crate) telemetry_capture: std::sync::Arc<std::sync::Mutex<u64>>,
    pub(crate) network_events_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) process_events_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) authentication_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) windows_authentication_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) windows_process_events_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) macos_process_events_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) macos_authentication_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) macos_network_events_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) windows_network_events_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _lock: Option<StateLock>,
}
impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        fs::create_dir_all(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("agent.lock"))?;
        lock.try_lock()
            .map_err(|_| "Endpoint state is already owned by another process")?;
        let lock = StateLock(lock);
        let connection = Connection::open(directory.join("endpoint.sqlite3"))?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA max_page_count=16384;PRAGMA wal_autocheckpoint=128;
            CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS work(id TEXT PRIMARY KEY,payload TEXT NOT NULL,receipt TEXT,acknowledged INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS quarantine(id TEXT PRIMARY KEY,path TEXT NOT NULL,sha256 TEXT NOT NULL,state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS maintenance(name TEXT PRIMARY KEY,last_ms INTEGER NOT NULL);")?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS telemetry_seen(key TEXT PRIMARY KEY,domain TEXT NOT NULL,hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS telemetry_pending(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS telemetry_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);")?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS native_mutations(command_id TEXT PRIMARY KEY,quarantine_id TEXT NOT NULL,intent TEXT NOT NULL,state TEXT NOT NULL,report TEXT);")?;
        Ok(Self {
            connection,
            directory: directory.into(),
            telemetry_capture: Default::default(),
            network_events_live: Default::default(),
            process_events_live: Default::default(),
            authentication_live: Default::default(),
            windows_authentication_live: Default::default(),
            windows_process_events_live: Default::default(),
            macos_process_events_live: Default::default(),
            macos_authentication_live: Default::default(),
            macos_network_events_live: Default::default(),
            windows_network_events_live: Default::default(),
            _lock: Some(lock),
        })
    }
    // Only the in-process collector may borrow the owner's database. Its guard
    // joins the worker before the Store (and exclusive process lock) can drop.
    pub(crate) fn collector_connection(&self) -> Result<Self> {
        let connection = Connection::open_with_flags(
            self.directory.join("endpoint.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=128;")?;
        Ok(Self {
            connection,
            directory: self.directory.clone(),
            telemetry_capture: self.telemetry_capture.clone(),
            network_events_live: self.network_events_live.clone(),
            process_events_live: self.process_events_live.clone(),
            authentication_live: self.authentication_live.clone(),
            windows_authentication_live: self.windows_authentication_live.clone(),
            windows_process_events_live: self.windows_process_events_live.clone(),
            macos_process_events_live: self.macos_process_events_live.clone(),
            macos_authentication_live: self.macos_authentication_live.clone(),
            macos_network_events_live: self.macos_network_events_live.clone(),
            windows_network_events_live: self.windows_network_events_live.clone(),
            _lock: None,
        })
    }
    pub fn enqueue(&self, event: &EndpointEvent) -> Result<()> {
        event.validate(now_ms())?;
        // Admission and insertion share one SQLite statement; the collector and
        // action thread cannot both consume the last available slot.
        let inserted = self.connection.execute(
            "INSERT INTO outbox SELECT ?1,?2 WHERE (SELECT count(*) FROM outbox)<4096",
            params![event.id, serde_json::to_string(event)?],
        )?;
        if inserted == 0 {
            return Err("Local event spool is full; operator attention required".into());
        }
        Ok(())
    }
    pub fn recover(&self) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        let _ = native_mutation::recover(self);
        let rows = self
            .connection
            .prepare("SELECT payload FROM work WHERE receipt IS NULL")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for raw in rows {
            let command: Command = serde_json::from_str(&raw)?;
            self.save_receipt(&Receipt{command_id:command.id,action_hash:command.action_hash,outcome:"interrupted".into(),output:"Agent restarted after durable command claim. Execution may have partially completed; automatic re-execution refused.".into(),finished_ms:now_ms()})?;
        }
        Ok(())
    }
    pub fn save_receipt(&self, receipt: &Receipt) -> Result<()> {
        receipt.validate()?;
        self.connection.execute(
            "UPDATE work SET receipt=?1 WHERE id=?2",
            params![serde_json::to_string(receipt)?, receipt.command_id],
        )?;
        Ok(())
    }
    pub fn claim(&self, command: &Command) -> Result<bool> {
        let previous: Option<String> = self
            .connection
            .query_row("SELECT payload FROM work WHERE id=?1", [&command.id], |r| {
                r.get(0)
            })
            .optional()?;
        let raw = serde_json::to_string(command)?;
        if let Some(previous) = previous {
            if previous != raw {
                return Err("Command identifier reused with different contents".into());
            }
            return Ok(false);
        }
        self.connection.execute(
            "INSERT INTO work(id,payload) VALUES(?1,?2)",
            params![command.id, raw],
        )?;
        Ok(true)
    }
}

pub struct Client {
    http: reqwest::blocking::Client,
    config: Config,
}
impl Client {
    pub fn maintain(&self, store: &Store) -> Result<()> {
        for (name, interval) in [
            (
                "signatures",
                self.config.maintenance.signature_interval_secs,
            ),
            ("scan", self.config.maintenance.scan_interval_secs),
        ] {
            if interval == 0 {
                continue;
            }
            let last: u64 = store
                .connection
                .query_row(
                    "SELECT last_ms FROM maintenance WHERE name=?1",
                    [name],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
            if now_ms().saturating_sub(last) < interval * 1000 {
                continue;
            }
            // Persist the attempt before work so restarts cannot cause an uncontrolled scan loop.
            store.connection.execute("INSERT INTO maintenance VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET last_ms=excluded.last_ms",params![name,now_ms()])?;
            let actions = if name == "signatures" {
                vec![Action::UpdateSignatures]
            } else {
                self.config
                    .scan_roots
                    .iter()
                    .map(|p| Action::Scan {
                        path: p.to_string_lossy().into(),
                    })
                    .collect()
            };
            for action in actions {
                let command = Command {
                    id: secret()?,
                    endpoint_id: self.config.endpoint_id.clone(),
                    action_hash: protocol::hash(&serde_json::to_vec(&action)?),
                    action,
                    created_ms: now_ms(),
                    expires_ms: now_ms() + 300_000,
                    timeout_secs: 300,
                    case_id: 0,
                };
                if let Err(error) = execute(&self.config, store, &command) {
                    store.enqueue(&EndpointEvent {
                        telemetry: None,
                        id: secret()?,
                        time_ms: now_ms(),
                        kind: "agent_error".into(),
                        path: String::new(),
                        sha256: String::new(),
                        detection: String::new(),
                        detail: format!("Scheduled {name}: {error}")
                            .chars()
                            .take(4000)
                            .collect(),
                    })?;
                }
            }
        }
        Ok(())
    }
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(ca) = &config.ca_file {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&fs::read(ca)?)?);
        }
        Ok(Self {
            http: builder.build()?,
            config,
        })
    }
    fn url(&self, suffix: &str) -> String {
        format!(
            "{}/api/endpoint/{}/{}",
            self.config.server.trim_end_matches('/'),
            self.config.endpoint_id,
            suffix
        )
    }
    fn post<T: Serialize>(&self, suffix: &str, body: &T) -> Result<serde_json::Value> {
        let response = self
            .http
            .post(self.url(suffix))
            .bearer_auth(&self.config.credential)
            .json(body)
            .send()?;
        let status = response.status();
        let mut body = String::new();
        response.take(256 * 1024 + 1).read_to_string(&mut body)?;
        if body.len() > 256 * 1024 {
            return Err("Server response exceeds budget".into());
        }
        if !status.is_success() {
            return Err(format!(
                "Endpoint request rejected ({status}); durable local work retained"
            )
            .into());
        }
        Ok(serde_json::from_str(&body)?)
    }
    pub fn enroll(&self) -> Result<()> {
        if let Some(token) = &self.config.enrollment_token {
            let request = protocol::Enrollment {
                protocol: protocol::PROTOCOL,
                enrollment_token: token.clone(),
                endpoint_id: self.config.endpoint_id.clone(),
                credential: self.config.credential.clone(),
                hostname: std::env::var("COMPUTERNAME")
                    .or_else(|_| std::env::var("HOSTNAME"))
                    .unwrap_or_else(|_| "managed-endpoint".into())
                    .chars()
                    .take(128)
                    .collect(),
                platform: Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: env!("CARGO_PKG_VERSION").into(),
            };
            self.http
                .post(format!(
                    "{}/api/endpoint/enroll",
                    self.config.server.trim_end_matches('/')
                ))
                .json(&request)
                .send()?
                .error_for_status()?;
        }
        Ok(())
    }
    pub fn cycle(&self, store: &Store) -> Result<()> {
        let protection_collection = protection::collect(store);
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        let protection_collection =
            protection_collection.and_then(|()| native_mutation::recover(store));
        let count = store
            .connection
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))?;
        let mut status = health(&self.config, count);
        let mut protection = protection::health(&self.config, &store.directory);
        if let Err(e) = &protection_collection {
            protection.state = "degraded".into();
            protection.error = e.to_string().chars().take(120).collect();
        }
        status.realtime = protection.state == "active";
        status.protection = Some(protection);
        status.collector = Some(telemetry::health(store, &self.config.telemetry)?);
        status.updates = managed_update::health(&self.config, &store.directory);
        status.controller_updates = managed_update::component_health(
            &self.config,
            &store.directory,
            athernex_endpoint_protocol::update::Component::Controller,
        );
        self.post("heartbeat", &status)?;
        let rows=store.connection.prepare("SELECT receipt FROM work WHERE acknowledged=0 AND receipt IS NOT NULL ORDER BY rowid LIMIT 16")?.query_map([],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
        for raw in rows {
            let receipt: Receipt = serde_json::from_str(&raw)?;
            let committed = self.post("receipt", &receipt)?;
            if committed["committed"] != true {
                return Err("Server did not commit the execution receipt".into());
            }
            store.connection.execute(
                "UPDATE work SET acknowledged=1 WHERE id=?1",
                [receipt.command_id],
            )?;
        }
        for _ in 0..4 {
            let rows = store
                .connection
                .prepare("SELECT payload FROM outbox ORDER BY rowid LIMIT 64")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            // Bound the encoded body as well as the record count. Escaped paths,
            // scan output and typed observations can otherwise exceed HTTP limits.
            let mut events = Vec::new();
            let mut bytes = 2usize;
            for raw in rows {
                let event: EndpointEvent = serde_json::from_str(&raw)?;
                let encoded = serde_json::to_vec(&event)?.len() + 1;
                if encoded + 2 > 192 * 1024 {
                    return Err("Individual endpoint event exceeds transport budget".into());
                }
                if bytes + encoded > 192 * 1024 {
                    break;
                }
                bytes += encoded;
                events.push(event);
            }
            if events.is_empty() {
                break;
            }
            {
                let receipt = self.post("events", &events)?;
                if receipt["durability"] != "committed"
                    || receipt["acknowledged"].as_u64() != Some(events.len() as u64)
                {
                    return Err("Server did not acknowledge complete durable batch".into());
                }
                let tx = rusqlite::Transaction::new_unchecked(
                    &store.connection,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                for event in events {
                    tx.execute("DELETE FROM outbox WHERE id=?1", [event.id])?;
                }
                tx.commit()?;
            }
        }
        if supervisor::in_trial(&store.directory)? {
            return protection_collection;
        }
        let commands: Vec<Command> =
            serde_json::from_value(self.post("poll", &serde_json::json!({}))?)?;
        if commands.len() > 4 {
            return Err("Command batch exceeds budget".into());
        }
        for command in commands {
            command.validate(&self.config.endpoint_id, now_ms())?;
            if !store.claim(&command)? {
                continue;
            }
            let mut authorized_for_execution = false;
            let result = (|| -> Result<String> {
                let authorized: Command = serde_json::from_value(self.post(
                    &format!("command/{}/start", command.id),
                    &serde_json::json!({}),
                )?)?;
                if serde_json::to_vec(&authorized)? != serde_json::to_vec(&command)? {
                    return Err("Dispatch changed after local claim".into());
                }
                authorized_for_execution = true;
                execute(&self.config, store, &command)
            })();
            let (outcome, output) = match result {
                Ok(s) => ("succeeded", s),
                Err(e) => (
                    if authorized_for_execution {
                        "failed"
                    } else {
                        "refused"
                    },
                    e.to_string(),
                ),
            };
            let receipt = Receipt {
                command_id: command.id,
                action_hash: command.action_hash,
                outcome: outcome.into(),
                output: bounded(&output),
                finished_ms: now_ms(),
            };
            store.save_receipt(&receipt)?;
        }
        let updates = self.managed_updates(store);
        let engines = self.managed_engines(store);
        protection_collection?;
        updates?;
        engines
    }
}

pub fn bounded(s: &str) -> String {
    let mut end = s.len().min(protocol::MAX_OUTPUT);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}
pub fn health(config: &Config, spool_events: u64) -> Heartbeat {
    let mut capabilities = vec!["inventory".into(), "quarantine".into(), "restore".into()];
    if config.scanner.is_file() {
        capabilities.push("scan".into());
    }
    if config.updater.is_file() {
        capabilities.push("update_signatures".into());
    }
    if config.allow_scripts {
        capabilities.push("script".into());
    }
    let mut version = Process::new(&config.scanner);
    let environment = engine_update::environment(&mut version, config);
    if let Some(database) = &config.signature_database {
        version.arg(format!("--database={}", database.display()));
    }
    version.arg("--version");
    let signature_version = if config.scanner.is_file() {
        environment
            .and_then(|()| run_bounded(&mut version, 3))
            .ok()
            .filter(|(code, _)| *code == 0)
            .map(|(_, v)| v.trim().chars().take(256).collect())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Heartbeat {
        controller_updates: None,
        updates: None,
        protection: None,
        collector: None,
        version: env!("CARGO_PKG_VERSION").into(),
        capabilities,
        scanner: if config.scanner.is_file() {
            "clamav"
        } else {
            "unavailable"
        }
        .into(),
        realtime: false,
        signature_version,
        spool_events,
        error: if config.scanner.is_file() {
            String::new()
        } else {
            "ClamAV is not installed at the configured path".into()
        },
    }
}

fn allowed_path(config: &Config, path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if !path.is_absolute() || fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err("An absolute, non-symlink path is required".into());
    }
    let canonical = path.canonicalize()?;
    if !config
        .scan_roots
        .iter()
        .filter_map(|p| p.canonicalize().ok())
        .any(|root| canonical.starts_with(root))
    {
        return Err("Path is outside the locally configured action roots".into());
    }
    Ok(canonical)
}
pub fn file_hash(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 512 * 1024 * 1024 {
        return Err("File must be regular and at most 512 MiB".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > 512 * 1024 * 1024 {
            return Err("File grew beyond hash budget".into());
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn action_hash(config: &Config, store: &Store, path: &Path, timeout: u64) -> Result<String> {
    #[cfg(target_os = "linux")]
    if config.protection.enabled {
        return protection::hash_file(config, path, timeout);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if protection::native_response::configured(store)? {
        return protection::native_response::hash_file(config, store, path, timeout);
    }
    let _ = (config, store, timeout);
    file_hash(path)
}

pub fn execute(config: &Config, store: &Store, command: &Command) -> Result<String> {
    command.validate(&config.endpoint_id, now_ms())?;
    let remaining = command.expires_ms.saturating_sub(now_ms()) / 1000;
    if remaining == 0 {
        return Err("Command expired before execution".into());
    }
    let timeout = command.timeout_secs.min(remaining);
    match &command.action {
        Action::Inventory => {
            let mut status = health(
                config,
                store
                    .connection
                    .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))?,
            );
            let protection = protection::health(config, &store.directory);
            status.realtime = protection.state == "active";
            status.protection = Some(protection);
            status.collector = Some(telemetry::health(store, &config.telemetry)?);
            let output = serde_json::to_string(
                &serde_json::json!({"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"version":env!("CARGO_PKG_VERSION"),"health":status}),
            )?;
            if output.len() > protocol::MAX_OUTPUT {
                return Err("Inventory exceeds output budget".into());
            }
            Ok(output)
        }
        Action::UpdateSignatures => {
            let mut process = antivirus::command(config, &config.updater)?;
            if let Some(path) = &config.signature_config {
                process.arg(format!("--config-file={}", path.display()));
            }
            let (code, output) = run_bounded(&mut process, timeout)?;
            if code != 0 {
                return Err(format!("Signature update failed ({code}): {output}").into());
            }
            Ok(output)
        }
        Action::Scan { path } => {
            let started = Instant::now();
            #[cfg(target_os = "linux")]
            if config.protection.enabled {
                let path = allowed_path(config, path)?;
                return protection::execute_scan(config, store, &path, timeout);
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if (cfg!(target_os = "macos") && config.protection.enabled)
                || protection::native_response::configured(store)?
            {
                return protection::native_response::execute_scan(
                    config,
                    store,
                    Path::new(path),
                    timeout,
                );
            }
            let path = allowed_path(config, path)?;
            let mut process = antivirus::command(config, &config.scanner)?;
            if let Some(database) = &config.signature_database {
                process.arg(format!("--database={}", database.display()));
            }
            let (code, output) = run_bounded(
                process
                    .arg("--recursive=yes")
                    .arg("--infected")
                    .arg("--max-filesize=100M")
                    .arg("--max-scansize=200M")
                    .arg("--")
                    .arg(&path),
                timeout,
            )?;
            if ![0, 1].contains(&code) {
                return Err(format!("Scan failed ({code}): {output}").into());
            }
            let mut events = Vec::new();
            for line in output.lines().filter(|s| s.ends_with(" FOUND")) {
                if let Some((path, _)) = line.trim_end_matches(" FOUND").rsplit_once(": ") {
                    let path = allowed_path(config, path)?;
                    let remaining = timeout.saturating_sub(started.elapsed().as_secs());
                    let (sha, verified_detection) =
                        scan::verify_snapshot(config, store, &path, remaining)?;
                    let path = path.to_string_lossy();
                    events.push(EndpointEvent{telemetry: None,id:secret()?,time_ms:now_ms(),kind:"malware".into(),path:path.into(),sha256:sha,detection:verified_detection,detail:"ClamAV matched a private snapshot identified by this SHA-256. Quarantine verifies the current file against that hash.".into()});
                }
            }
            if code == 1 && events.is_empty() {
                return Err("Scanner report contained no verifiable file detection".into());
            }
            events.push(EndpointEvent {
                telemetry: None,
                id: secret()?,
                time_ms: now_ms(),
                kind: "scan".into(),
                path: path.to_string_lossy().into(),
                sha256: String::new(),
                detection: String::new(),
                detail: output.chars().take(4000).collect(),
            });
            let tx = store.connection.unchecked_transaction()?;
            for event in &events {
                store.enqueue(event)?;
            }
            tx.commit()?;
            Ok(output)
        }
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Action::Quarantine { .. } | Action::Restore { .. } => {
            native_mutation::require_resolved(store)?;
            native_mutation::execute(config, store, command, timeout)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        Action::Quarantine { path, sha256 } => {
            let path = allowed_path(config, path)?;
            if action_hash(config, store, &path, timeout.min(30))? != *sha256 {
                return Err("File changed since approval".into());
            }
            let id = command.id.clone();
            let directory = store.directory.join("quarantine");
            fs::create_dir_all(&directory)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            }
            let target = directory.join(&id);
            if target.exists() {
                return Err("Quarantine destination already exists".into());
            }
            store.connection.execute(
                "INSERT INTO quarantine VALUES(?1,?2,?3,'preparing')",
                params![id, path.to_string_lossy(), sha256],
            )?;
            // Atomic rename deliberately refuses cross-filesystem moves rather than risking a partial delete.
            fs::rename(&path, &target)?;
            if file_hash(&target)? != *sha256 {
                return Err("Quarantine integrity mismatch; retained for manual review".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
            }
            store.connection.execute(
                "UPDATE quarantine SET state='quarantined' WHERE id=?1",
                [&id],
            )?;
            Ok(format!("Quarantined {sha256}; restore reference {id}"))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        Action::Restore { quarantine_id } => {
            let (path, sha): (String, String) = store.connection.query_row(
                "SELECT path,sha256 FROM quarantine WHERE id=?1 AND state='quarantined'",
                [quarantine_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let target = PathBuf::from(&path);
            let parent = target.parent().ok_or("Missing parent")?;
            allowed_path(config, &parent.to_string_lossy())?;
            let source = store.directory.join("quarantine").join(quarantine_id);
            if file_hash(&source)? != sha {
                return Err("Quarantine integrity check failed".into());
            }
            // create_new prevents overwriting an unrelated file that has appeared at the original path.
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            std::io::copy(&mut fs::File::open(&source)?, &mut output)?;
            output.sync_all()?;
            store.connection.execute(
                "UPDATE quarantine SET state='restored' WHERE id=?1",
                [quarantine_id],
            )?;
            fs::remove_file(source)?;
            Ok(format!("Restored {path}"))
        }
        Action::Script {
            interpreter,
            script,
            ..
        } => {
            if !config.allow_scripts {
                return Err("Scripts are disabled by local endpoint policy".into());
            }
            let suffix = if interpreter == "powershell" {
                ".ps1"
            } else {
                ".sh"
            };
            let mut file = tempfile::Builder::new()
                .suffix(suffix)
                .tempfile_in(&store.directory)?;
            file.write_all(script.as_bytes())?;
            file.as_file().sync_all()?;
            let mut process = if interpreter == "powershell" && cfg!(windows) {
                let mut p =
                    Process::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
                p.args(["-NoProfile", "-NonInteractive", "-File"]);
                p
            } else if interpreter == "sh" && !cfg!(windows) {
                let mut p = Process::new("/bin/sh");
                p.arg("--");
                p
            } else {
                return Err("Interpreter unavailable on this platform".into());
            };
            let (code, output) = run_bounded(process.arg(file.path()), timeout)?;
            if code != 0 {
                return Err(format!("Automation failed ({code}): {output}").into());
            }
            Ok(output)
        }
    }
}

pub fn run_bounded(process: &mut Process, seconds: u64) -> Result<(i32, String)> {
    run_bounded_with_limit(process, seconds, protocol::MAX_OUTPUT)
}
pub(crate) fn run_bounded_with_limit(
    process: &mut Process,
    seconds: u64,
    output_limit: usize,
) -> Result<(i32, String)> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let (code, bytes) = athernex_endpoint_native::child::run(
            process,
            Duration::from_secs(seconds),
            output_limit,
        )?;
        Ok((code, String::from_utf8_lossy(&bytes).into_owned()))
    }
    #[cfg(windows)]
    {
        let (code, bytes) = windows_job::run(process, Duration::from_secs(seconds), output_limit)?;
        Ok((code, String::from_utf8_lossy(&bytes).into_owned()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        run_bounded_fallback(process, seconds, output_limit)
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn run_bounded_fallback(
    process: &mut Process,
    seconds: u64,
    output_limit: usize,
) -> Result<(i32, String)> {
    let output = tempfile::tempfile()?;
    process
        .stdin(std::process::Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output.try_clone()?);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        process.process_group(0);
        #[cfg(target_os = "linux")]
        unsafe {
            let parent = std::process::id();
            process.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent as i32 {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                Ok(())
            });
        }
    }
    let mut child = process.spawn()?;
    let terminate = |child: &mut std::process::Child| {
        kill_tree(child);
    };
    let start = Instant::now();
    let result: Result<i32> = loop {
        if start.elapsed() > Duration::from_secs(seconds)
            || output.metadata()?.len() > output_limit as u64
        {
            terminate(&mut child);
            break Err("Action exceeded its time/output budget; process tree terminated".into());
        }
        if let Some(status) = child.try_wait()? {
            terminate(&mut child);
            break Ok(status.code().unwrap_or(-1));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    use std::io::{Seek, SeekFrom};
    let mut output = output;
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    output.take(output_limit as u64).read_to_end(&mut bytes)?;
    Ok((result?, String::from_utf8_lossy(&bytes).into_owned()))
}
#[cfg(not(any(target_os = "macos", windows)))]
fn kill_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // The child has its own process group; never target the agent's group.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(root: &Path) -> Config {
        Config {
            engine_updates: Default::default(),
            updates: Default::default(),
            protection: Default::default(),
            telemetry: Default::default(),
            server: "http://127.0.0.1:8787/".into(),
            endpoint_id: "a".repeat(64),
            credential: "b".repeat(64),
            enrollment_token: None,
            scanner: root.join("missing"),
            updater: root.join("missing"),
            scan_roots: vec![root.into()],
            allow_scripts: false,
            ca_file: None,
            signature_database: None,
            signature_config: None,
            maintenance: Default::default(),
        }
    }
    fn command(action: Action) -> Command {
        Command {
            id: "c".repeat(64),
            endpoint_id: "a".repeat(64),
            action_hash: protocol::hash(&serde_json::to_vec(&action).unwrap()),
            action,
            created_ms: now_ms(),
            expires_ms: now_ms() + 60_000,
            timeout_secs: 2,
            case_id: 1,
        }
    }
    #[test]
    fn durable_claim_never_reexecutes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = command(Action::Inventory);
        let inherited_lock;
        {
            let store = Store::open(dir.path()).unwrap();
            assert!(store.claim(&cmd).unwrap());
            assert!(Store::open(dir.path()).is_err());
            inherited_lock = store._lock.as_ref().unwrap().0.try_clone().unwrap();
        }
        let store = Store::open(dir.path()).unwrap();
        drop(inherited_lock);
        store.recover().unwrap();
        assert!(!store.claim(&cmd).unwrap());
        let receipt: String = store
            .connection
            .query_row("SELECT receipt FROM work", [], |r| r.get(0))
            .unwrap();
        assert!(receipt.contains("interrupted"));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    #[test]
    fn quarantine_requires_exact_hash_and_restores_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state")).unwrap();
        let cfg = config(dir.path());
        let file = dir.path().join("sample.txt");
        fs::write(&file, b"test fixture").unwrap();
        let sha = file_hash(&file).unwrap();
        assert!(execute(
            &cfg,
            &store,
            &command(Action::Quarantine {
                path: file.to_string_lossy().into(),
                sha256: "0".repeat(64)
            })
        )
        .is_err());
        let cmd = command(Action::Quarantine {
            path: file.to_string_lossy().into(),
            sha256: sha,
        });
        execute(&cfg, &store, &cmd).unwrap();
        assert!(!file.exists());
        execute(
            &cfg,
            &store,
            &command(Action::Restore {
                quarantine_id: cmd.id,
            }),
        )
        .unwrap();
        assert_eq!(fs::read(file).unwrap(), b"test fixture");
    }
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn pending_native_work_blocks_mutations_after_a_backend_change() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state")).unwrap();
        let cfg = config(dir.path());
        let file = dir.path().join("sample");
        fs::write(&file, b"fixture").unwrap();
        store.connection.execute("INSERT INTO native_mutations(command_id,quarantine_id,intent,state) VALUES(?1,?1,'{}','pending')",["d".repeat(64)]).unwrap();
        for action in [
            Action::Quarantine {
                path: file.to_string_lossy().into(),
                sha256: file_hash(&file).unwrap(),
            },
            Action::Restore {
                quarantine_id: "d".repeat(64),
            },
        ] {
            assert!(execute(&cfg, &store, &command(action))
                .unwrap_err()
                .to_string()
                .contains("still requires recovery"));
        }
        assert_eq!(fs::read(file).unwrap(), b"fixture");
        assert!(!store.directory.join("quarantine").exists());
    }
    #[test]
    fn scripts_require_local_policy_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let cfg = config(dir.path());
        assert!(execute(
            &cfg,
            &store,
            &command(Action::Script {
                interpreter: "sh".into(),
                script: "echo test".into(),
                sha256: protocol::hash(b"echo test")
            })
        )
        .is_err());
    }
    #[cfg(unix)]
    #[test]
    fn subprocess_timeout_and_output_budget() {
        assert!(run_bounded(Process::new("/bin/sh").args(["-c", "sleep 5"]), 1).is_err());
        assert!(run_bounded(Process::new("/bin/sh").args(["-c", "yes fixture"]), 2).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn windows_subprocess_timeout_and_output_budget() {
        let _serial = crate::windows_job::TEST_SERIAL.lock().unwrap();
        let shell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        assert!(run_bounded(
            Process::new(shell).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 5"
            ]),
            1
        )
        .is_err());
        assert!(run_bounded(
            Process::new(shell).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "while ($true) { Write-Output ('fixture' * 1000) }"
            ]),
            3
        )
        .is_err());
    }
}
