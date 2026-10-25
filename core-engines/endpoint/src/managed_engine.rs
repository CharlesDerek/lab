//! Fleet transport reuses local signed-tree admission and controller recovery.
use crate::{engine_update, now_ms, private_write, update, Client, Result, Store};
use athernex_endpoint_protocol::{
    self as protocol,
    engine_fleet::{Deployment, Health, Receipt},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
#[derive(Serialize, Deserialize)]
struct Delivery {
    deployment: Deployment,
    attempts: u8,
    staging: Option<Receipt>,
    installation: Option<Receipt>,
    terminal: bool,
}
fn load(state: &Path) -> Result<Option<Delivery>> {
    match update::read_bounded(&state.join("engine-updates/delivery.json"), 131072) {
        Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
fn save(state: &Path, record: &Delivery) -> Result<()> {
    private_write(
        &state.join("engine-updates/delivery.json"),
        &serde_json::to_vec(record)?,
    )
}
/// Called under the engine maintenance lock after the server committed the
/// immutable controller result. A crash before owner acknowledgement is replayable.
pub(crate) fn finish_delivery(
    state: &Path,
    deployment: &Deployment,
    receipt: &Receipt,
) -> Result<()> {
    let mut record = load(state)?.ok_or("Engine installation has no delivery journal")?;
    if &record.deployment != deployment
        || record
            .staging
            .as_ref()
            .is_none_or(|r| r.outcome != "staged")
        || record.installation.as_ref().is_some_and(|r| r != receipt)
        || receipt.deployment_id != deployment.id
        || receipt.release_id != deployment.release.id()?
    {
        return Err("Engine result differs from its delivery journal".into());
    }
    record.installation = Some(receipt.clone());
    record.terminal = true;
    save(state, &record)
}
fn receipt(
    deployment: &Deployment,
    outcome: &str,
    detail: &str,
    finished_ms: u64,
) -> Result<Receipt> {
    Ok(Receipt {
        deployment_id: deployment.id.clone(),
        release_id: deployment.release.id()?,
        outcome: outcome.into(),
        detail: detail.chars().take(120).collect(),
        finished_ms,
    })
}
pub fn health(config: &crate::Config, state: &Path) -> Result<Health> {
    let status = engine_update::status(state)?;
    Ok(Health {
        managed: config.engine_updates.managed,
        automatic: config.engine_updates.automatic,
        supervised: crate::supervisor::child_context(state).is_some(),
        target: protocol::update::target(),
        key_fingerprint: protocol::update::fingerprint(&config.engine_updates.public_key)?,
        channel: config.engine_updates.channel.clone(),
        highwater: status.highwater.max(config.engine_updates.minimum_sequence),
        staged_release: status.staged.as_ref().map(|r| r.id()).transpose()?,
        installed_release: status.installed.as_ref().map(|r| r.id()).transpose()?,
        phase: status.phase,
        error: status.error.chars().take(120).collect(),
    })
}
impl Client {
    pub(crate) fn authorize_engine_installation(&self, expected: &Deployment) -> Result<()> {
        let authorized = self.post(
            &format!("engines/{}/install", expected.id),
            &serde_json::json!({}),
        )?;
        let deployment: Deployment = serde_json::from_value(authorized["deployment"].clone())?;
        if &deployment != expected {
            return Err("Installation authorization changed the reviewed engine deployment".into());
        }
        deployment.validate(&self.config.endpoint_id, now_ms())?;
        Ok(())
    }
    pub fn managed_engines(&self, store: &Store) -> Result<()> {
        let state = &store.directory;
        self.engine_installation_receipts(state)?;
        let managed = self.config.engine_updates.managed;
        if managed {
            self.post("engines/health", &health(&self.config, state)?)?;
        }
        let mut prior = load(state)?;
        if let Some(record) = &mut prior {
            let status = engine_update::status(state)?;
            if record.staging.is_none()
                && status.staged.as_ref() == Some(&record.deployment.release)
                && status.phase == "staged"
            {
                record.staging = Some(receipt(
                    &record.deployment,
                    "staged",
                    "Recovered durable local staging",
                    status.updated_ms,
                )?);
                save(state, record)?;
            }
            if let Some(staged) = &record.staging {
                let response = self.post("engines/receipt", staged)?;
                if response["committed"] != true {
                    return Err("Engine staging receipt not committed".into());
                }
                if staged.outcome != "staged"
                    || !record.deployment.install
                    || matches!(response["state"].as_str(), Some("cancelled" | "expired"))
                {
                    record.terminal = true;
                    save(state, record)?;
                }
            }
            if managed && !record.terminal && record.staging.is_some() && record.deployment.install
            {
                // A local request for the same release is not authority or
                // evidence for this deployment. Only its exact bound owner can
                // supply an installation result; otherwise request new authority.
                let owned = status
                    .maintenance
                    .as_ref()
                    .is_some_and(|r| r.deployment.as_ref() == Some(&record.deployment));
                if !owned && record.installation.is_none() {
                    let deployment = &record.deployment;
                    self.authorize_engine_installation(deployment)?;
                    if let Err(error) = engine_update::automatic::request_fleet(state, deployment) {
                        // A failed durable write can be ambiguous. Re-read before
                        // reporting refusal; an already queued controller must finish.
                        let latest = engine_update::status(state)?;
                        if latest
                            .maintenance
                            .as_ref()
                            .is_some_and(|r| r.deployment.as_ref() == Some(deployment))
                            || latest.transaction.is_some()
                        {
                            return Err(error);
                        }
                        record.installation = Some(receipt(
                            deployment,
                            "refused",
                            &error.to_string(),
                            now_ms(),
                        )?);
                        save(state, record)?;
                    }
                }
            }
            if let Some(installed) = &record.installation {
                if self.post("engines/receipt", installed)?["committed"] != true {
                    return Err("Engine installation receipt not committed".into());
                }
                record.terminal = true;
                save(state, record)?;
            }
            if !record.terminal && record.staging.is_some() {
                return Ok(());
            }
        }
        if !managed {
            return Ok(());
        }
        if prior.as_ref().is_none_or(|r| r.terminal) {
            let response = self.post("engines/poll", &serde_json::json!({}))?;
            if response["deployment"].is_null() {
                return Ok(());
            }
            let deployment: Deployment = serde_json::from_value(response["deployment"].clone())?;
            if prior
                .as_ref()
                .is_some_and(|r| r.terminal && r.deployment.id == deployment.id)
            {
                return Err("Server replayed terminal engine work".into());
            }
            prior = Some(Delivery {
                deployment,
                attempts: 0,
                staging: None,
                installation: None,
                terminal: false,
            });
            save(state, prior.as_ref().unwrap())?;
        }
        let record = prior.as_mut().ok_or("Missing engine delivery")?;
        if record.attempts >= 3 {
            return Err("Engine transfer retry budget exhausted".into());
        }
        record.attempts += 1;
        save(state, record)?;
        match self.download_engine(store, &record.deployment) {
            Ok(()) => {
                record.staging = Some(receipt(
                    &record.deployment,
                    "staged",
                    "Signed engine tree staged; no installation implied",
                    now_ms(),
                )?)
            }
            Err(error) => {
                if record.attempts < 3 && now_ms() < record.deployment.expires_ms {
                    return Err(error);
                }
                record.staging = Some(receipt(
                    &record.deployment,
                    "refused",
                    &error.to_string(),
                    now_ms(),
                )?);
            }
        }
        save(state, record)?;
        if self.post("engines/receipt", record.staging.as_ref().unwrap())?["committed"] != true {
            return Err("Engine staging receipt not committed".into());
        }
        Ok(())
    }
    fn download_engine(&self, store: &Store, deployment: &Deployment) -> Result<()> {
        deployment.validate(&self.config.endpoint_id, now_ms())?;
        let status = engine_update::status(&store.directory)?;
        let floor = if status.staged.as_ref() == Some(&deployment.release) {
            self.config.engine_updates.minimum_sequence
        } else {
            status
                .highwater
                .max(self.config.engine_updates.minimum_sequence)
        };
        deployment.release.admit(
            &self.config.engine_updates.public_key,
            &protocol::update::target(),
            &self.config.engine_updates.channel,
            floor,
            now_ms(),
        )?;
        let download = tempfile::Builder::new()
            .prefix("engine-download-")
            .tempdir_in(&store.directory)?;
        let content = download.path().join("content");
        fs::create_dir(&content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&content, fs::Permissions::from_mode(0o700))?;
        }
        for (index, member) in deployment.release.release.files.iter().enumerate() {
            deployment.validate(&self.config.endpoint_id, now_ms())?;
            self.post("engines/health", &health(&self.config, &store.directory)?)?;
            let response = self
                .http
                .get(self.url(&format!("engines/{}/file/{index}", deployment.id)))
                .bearer_auth(&self.config.credential)
                .timeout(std::time::Duration::from_millis(
                    deployment
                        .expires_ms
                        .saturating_sub(now_ms())
                        .clamp(1, 20000),
                ))
                .send()?
                .error_for_status()?;
            if response.content_length().is_some_and(|n| n != member.bytes) {
                return Err("Engine transfer length mismatch".into());
            }
            let path = content.join(&member.path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    for directory in parent.ancestors().take_while(|p| p.starts_with(&content)) {
                        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
                    }
                }
            }
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path)?;
            let mut stream = response.take(member.bytes + 1);
            let mut buffer = [0u8; 65536];
            let mut count = 0u64;
            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            loop {
                let n = stream.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                count += n as u64;
                if count > member.bytes {
                    return Err("Engine transfer exceeds its signed byte limit".into());
                }
                hash.update(&buffer[..n]);
                file.write_all(&buffer[..n])?;
            }
            if count != member.bytes || format!("{:x}", hash.finalize()) != member.sha256 {
                return Err("Engine transfer checksum mismatch".into());
            }
            file.sync_all()?;
        }
        deployment.validate(&self.config.endpoint_id, now_ms())?;
        let manifest = download.path().join("manifest.json");
        private_write(&manifest, &serde_json::to_vec(&deployment.release)?)?;
        engine_update::stage(&store.directory, &manifest, &content)
    }
}

/// Publish a signed engine bundle to the server catalog without installing it.
/// Copy only manifest-bound files and atomically expose a fully verified tree.
pub fn publish(
    manifest: &Path,
    content: &Path,
    public_key: &str,
    catalog: &Path,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let release: protocol::engine::SignedRelease = serde_json::from_slice(&update::read_bounded(
        manifest,
        protocol::engine::MAX_MANIFEST,
    )?)?;
    let public_key = public_key.trim();
    release.authenticate(public_key)?;
    let id = release.id()?;
    fs::create_dir_all(catalog)?;
    let key_path = catalog.join("public-key.txt");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&key_path)
    {
        Ok(mut file) => {
            file.write_all(public_key.as_bytes())?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(&key_path)?.file_type().is_symlink()
                || String::from_utf8(update::read_bounded(&key_path, 128)?)?.trim() != public_key
            {
                return Err("Engine catalog is bound to a different release key".into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let count = fs::read_dir(catalog)?.take(65).count();
    if count > 64 {
        return Err("Engine catalog capacity reached".into());
    }
    let destination = catalog.join(&id);
    if destination.exists() {
        return Err(
            "Engine release is already published; existing catalog entries are never replaced"
                .into(),
        );
    }
    let source = content.canonicalize()?;
    let staged = tempfile::Builder::new()
        .prefix(".engine-publish-")
        .tempdir_in(catalog)?;
    let target = staged.path().join("content");
    fs::create_dir(&target)?;
    let mut directories = std::collections::BTreeSet::new();
    directories.insert(target.clone());
    for member in &release.release.files {
        let path = source.join(&member.path);
        if !fs::symlink_metadata(&path)?.is_file() || !path.canonicalize()?.starts_with(&source) {
            return Err("Engine bundle source leaves its content tree".into());
        }
        let mut input = fs::File::open(path)?.take(member.bytes + 1);
        let output = target.join(&member.path);
        fs::create_dir_all(output.parent().ok_or("Missing engine parent")?)?;
        let mut parent = output.parent();
        while let Some(directory) = parent.filter(|p| p.starts_with(&target)) {
            directories.insert(directory.to_owned());
            parent = directory.parent();
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        let mut hash = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > member.bytes {
                return Err("Engine bundle exceeds its signed size".into());
            }
            hash.update(&buffer[..n]);
            file.write_all(&buffer[..n])?;
        }
        if total != member.bytes || format!("{:x}", hash.finalize()) != member.sha256 {
            return Err("Engine bundle checksum mismatch".into());
        }
        file.sync_all()?;
    }
    private_write(
        &staged.path().join("manifest.json"),
        &serde_json::to_vec(&release)?,
    )?;
    #[cfg(unix)]
    {
        for directory in directories.iter().rev() {
            fs::File::open(directory)?.sync_all()?;
        }
        fs::File::open(staged.path())?.sync_all()?;
    }
    fs::rename(staged.path(), &destination)?;
    #[cfg(unix)]
    fs::File::open(catalog)?.sync_all()?;
    Ok(id)
}
