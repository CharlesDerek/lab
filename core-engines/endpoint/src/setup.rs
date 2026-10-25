//! Shared setup operations. The caller owns endpoint state for the entire
//! operation; an installer can enroll without transferring its maintenance lease.
use crate::{secret, update, Client, Config, Result, Store};
use athernex_endpoint_protocol::{self as protocol, Bootstrap, Platform, PROTOCOL};
use std::path::Path;
#[cfg(test)]
mod tests;

pub fn read_bootstrap(path: &Path) -> Result<Bootstrap> {
    let bootstrap: Bootstrap = serde_json::from_slice(&update::read_bounded(path, 65536)?)?;
    validate(&bootstrap)?;
    Ok(bootstrap)
}
/// Standalone setup owns the endpoint before writing configuration. Windows
/// creates new state with the same service-compatible ACL as the installer.
pub struct SetupStore {
    store: Store,
    #[cfg(windows)]
    _lease: std::fs::File,
    #[cfg(windows)]
    _directory: athernex_endpoint_native::windows_state::Directory,
}
impl std::ops::Deref for SetupStore {
    type Target = Store;
    fn deref(&self) -> &Store {
        &self.store
    }
}
pub fn open_store(state: &Path) -> Result<SetupStore> {
    #[cfg(windows)]
    {
        let state = std::path::absolute(state)?;
        let directory = athernex_endpoint_native::windows_state::Directory::maintenance_under(
            state.parent().ok_or("Endpoint state has no parent")?,
            state
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or("Invalid endpoint state directory")?,
        )?;
        // Serialize standalone enrollment with an installer's very first
        // preparing record, before either operation creates an identity.
        let lease = directory.maintenance_lock(crate::installer::LOCK)?;
        crate::installer::require_complete(&state)?;
        let store = Store::open(&state)?;
        Ok(SetupStore {
            store,
            _lease: lease,
            _directory: directory,
        })
    }
    #[cfg(not(windows))]
    Ok(SetupStore {
        store: Store::open(state)?,
    })
}
pub fn validate(bootstrap: &Bootstrap) -> Result<()> {
    if bootstrap.protocol != PROTOCOL || bootstrap.platform != Platform::current() {
        return Err("Installer platform/protocol mismatch".into());
    }
    protocol::server_url(&bootstrap.server)?;
    if !protocol::hex_id(&bootstrap.enrollment_token) || bootstrap.antivirus.len() > 8 {
        return Err("Invalid endpoint bootstrap".into());
    }
    for package in &bootstrap.antivirus {
        package.validate()?;
    }
    Ok(())
}
pub fn configuration(bootstrap: &Bootstrap, state: &Path) -> Result<Config> {
    validate(bootstrap)?;
    match update::read_bounded(&state.join("config.json"), 65536) {
        Ok(bytes) => {
            let existing: Config = serde_json::from_slice(&bytes)?;
            existing.validate()?;
            if protocol::server_url(&existing.server)? != protocol::server_url(&bootstrap.server)? {
                return Err(
                    "Endpoint state belongs to a different server; choose a new state directory"
                        .into(),
                );
            }
            return Ok(existing);
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    let (scanner, updater, root) = if cfg!(windows) {
        (
            r"C:\Program Files\ClamAV\clamscan.exe",
            r"C:\Program Files\ClamAV\freshclam.exe",
            r"C:\Users",
        )
    } else if cfg!(target_os = "macos") {
        (
            "/opt/homebrew/bin/clamscan",
            "/opt/homebrew/bin/freshclam",
            "/Users",
        )
    } else {
        ("/usr/bin/clamscan", "/usr/bin/freshclam", "/home")
    };
    let config = Config {
        engine_updates: Default::default(),
        updates: Default::default(),
        protection: Default::default(),
        telemetry: crate::telemetry::TelemetryConfig {
            enabled: true,
            interval_secs: 30,
            ..Default::default()
        },
        server: bootstrap.server.clone(),
        endpoint_id: secret()?,
        credential: secret()?,
        enrollment_token: Some(bootstrap.enrollment_token.clone()),
        scanner: scanner.into(),
        updater: updater.into(),
        scan_roots: vec![root.into()],
        allow_scripts: false,
        ca_file: None,
        signature_database: None,
        signature_config: None,
        maintenance: Default::default(),
    };
    config.validate()?;
    Ok(config)
}
pub fn enroll(bootstrap: &Bootstrap, store: &Store) -> Result<Config> {
    let mut config = configuration(bootstrap, &store.directory)?;
    save(&store.directory, &config)?;
    Client::new(config.clone())?.enroll()?;
    config.enrollment_token = None;
    save(&store.directory, &config)?;
    Ok(config)
}
pub fn provision(bootstrap: &Bootstrap, state: &Path) -> Result<()> {
    validate(bootstrap)?;
    let path = state.join("config.json");
    let mut config: Config = serde_json::from_slice(&update::read_bounded(&path, 65536)?)?;
    config.validate()?;
    if protocol::server_url(&config.server)? != protocol::server_url(&bootstrap.server)? {
        return Err("Antivirus bootstrap belongs to a different server".into());
    }
    crate::antivirus::provision(bootstrap, state)?;
    if !bootstrap.antivirus.is_empty() {
        (config.scanner, config.updater) = crate::antivirus::paths();
        if !cfg!(target_os = "macos") || config.protection.roots.is_empty() {
            config.signature_database = Some(state.join("av/db"));
            config.signature_config = Some(state.join("av/freshclam.conf"));
        }
        config.maintenance = crate::Maintenance {
            scan_interval_secs: 86400,
            signature_interval_secs: 3600,
        };
        save(state, &config)?;
        #[cfg(target_os = "linux")]
        crate::protection::configure(state)?;
    }
    Ok(())
}
pub fn save(state: &Path, config: &Config) -> Result<()> {
    config.validate()?;
    #[cfg(windows)]
    {
        athernex_endpoint_native::windows_state::Directory::open(&std::path::absolute(state)?)?
            .write_maintenance_json("config.json", config)
    }
    #[cfg(not(windows))]
    crate::private_write(
        &state.join("config.json"),
        &serde_json::to_vec_pretty(config)?,
    )
}
