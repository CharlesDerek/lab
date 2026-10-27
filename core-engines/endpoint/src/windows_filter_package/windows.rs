use super::*;
use athernex_endpoint_native::{
    windows_filter_package as trust,
    windows_state::{Directory, PinnedDirectory},
};
use protocol::windows_filter_package::{Member, NAMES};
use std::{fs::File, io::Read, time::Duration};
fn record_name(hash: &str) -> Result<String> {
    if !protocol::hex_id(hash) {
        return Err("Invalid driver package receipt name".into());
    }
    Ok(format!("windows-filter-{hash}.json"))
}
fn missing(e: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
fn read_record(state: &Directory, hash: &str) -> Result<Option<Preparation>> {
    let name = record_name(hash)?;
    let r: Preparation = match state.read_json(&name) {
        Ok(r) => r,
        Err(e) if missing(e.as_ref()) => return Ok(None),
        Err(e) => return Err(e),
    };
    r.validate()?;
    let id = state.identity()?;
    if (r.state_volume, r.state_file_id) != (id.volume, id.file_id) {
        return Err("Driver preparation receipt belongs to another state directory".into());
    }
    Ok(Some(r))
}
fn directory(state: &Directory, r: &Preparation) -> Result<Directory> {
    let directory = Directory::open(
        &state
            .path()
            .join(format!("filter-package-{}", r.transaction)),
    )?;
    let id = directory.identity()?;
    if r.directory != Some((id.volume, id.file_id)) {
        return Err("Driver preparation directory identity changed".into());
    }
    for entry in std::fs::read_dir(directory.path())? {
        let n = entry?.file_name();
        if !NAMES
            .iter()
            .chain([&"descriptor.json"])
            .any(|s| n == std::ffi::OsStr::new(s))
        {
            return Err("Unexpected entry in private driver preparation".into());
        }
    }
    Ok(directory)
}
fn pins(directory: &Directory, r: &Preparation) -> Result<Vec<File>> {
    let mut files = Vec::new();
    for (name, member) in NAMES.iter().zip(r.descriptor.members()) {
        files.push(trust::pin(&directory.path().join(name), member)?);
    }
    let descriptor = serde_json::to_vec(&r.descriptor)?;
    files.push(trust::pin(
        &directory.path().join("descriptor.json"),
        &Member {
            bytes: descriptor.len() as u64,
            sha256: protocol::hash(&descriptor),
        },
    )?);
    for (file, expected) in files.iter().zip(r.members) {
        if Some(trust::identity(file)?) != expected {
            return Err("Driver preparation member identity changed".into());
        }
    }
    Ok(files)
}
pub(crate) fn require_prepared(state: &Path, expected: &str) -> Result<()> {
    let state = Directory::open(state)?;
    let r = read_record(&state, expected)?.ok_or("Missing driver preparation receipt")?;
    if !r.prepared || r.descriptor.sha256 != expected {
        return Err("Required driver package is not prepared".into());
    }
    let directory = directory(&state, &r)?;
    let _pins = pins(&directory, &r)?;
    Ok(())
}
/// Retain the exact prepared directory while the native deployment API uses its paths.
pub(crate) fn prepared_directory(state: &Path, hash: &str) -> Result<Directory> {
    let state = Directory::open(state)?;
    let record = read_record(&state, hash)?.ok_or("Missing prepared driver receipt")?;
    if !record.prepared {
        return Err("Driver package is not prepared".into());
    }
    let result = directory(&state, &record)?;
    let _pins = pins(&result, &record)?;
    Ok(result)
}
/// Parent holds the installer/service/protection leases and original bundle pin.
/// A failed or unknown trust result leaves an incomplete durable transaction.
pub(crate) fn prepare(
    state: &Directory,
    bundle: &Path,
    source: &str,
    descriptor: &Descriptor,
) -> Result<()> {
    let _bundle = PinnedDirectory::open(bundle)?;
    let archive = trust::pin(
        &bundle.join("windows-filter.axpkg"),
        &Member {
            bytes: descriptor.bytes,
            sha256: descriptor.sha256.clone(),
        },
    )?;
    let mut bytes = Vec::new();
    (&archive)
        .take(descriptor.bytes + 1)
        .read_to_end(&mut bytes)?;
    let parts = descriptor.unpack(&bytes)?;
    let id = state.identity()?;
    let name_for_receipt = record_name(&descriptor.sha256)?;
    let mut r = if let Some(r) = read_record(state, &descriptor.sha256)? {
        r.matches(source, descriptor)?;
        r
    } else {
        let r = Preparation {
            schema: 1,
            transaction: crate::secret()?,
            source_sha256: source.into(),
            descriptor: descriptor.clone(),
            state_volume: id.volume,
            state_file_id: id.file_id,
            directory: None,
            prepared: false,
            members: [None; 4],
        };
        state.publish_maintenance(&name_for_receipt, &serde_json::to_vec(&r)?)?;
        r
    };
    if r.directory.is_none() {
        let leaf = format!("filter-package-{}", r.transaction);
        // Never adopt a directory created before an interrupted identity receipt.
        // That narrow uncertainty remains refused for operator-owned recovery.
        if state.path().join(&leaf).try_exists()? {
            return Err("Unconfirmed driver preparation directory requires recovery".into());
        }
        let dir = state.fresh_maintenance_directory(&leaf)?;
        let id = dir.identity()?;
        r.directory = Some((id.volume, id.file_id));
        state.write_maintenance_json(&name_for_receipt, &r)?;
    }
    let directory = directory(state, &r)?;
    let encoded = serde_json::to_vec(descriptor)?;
    for (i, (name, part)) in NAMES
        .iter()
        .copied()
        .zip(parts)
        .chain([("descriptor.json", encoded.as_slice())])
        .enumerate()
    {
        let member = Member {
            bytes: part.len() as u64,
            sha256: protocol::hash(part),
        };
        match directory.read(name) {
            Ok(existing) => {
                r.member_action(i, Some(trust::identity(&existing)?))?;
                let _pin = trust::pin(&directory.path().join(name), &member)?;
            }
            Err(e) if missing(e.as_ref()) => {
                r.member_action(i, None)?;
                directory.publish_maintenance(name, part)?;
                let file = trust::pin(&directory.path().join(name), &member)?;
                r.members[i] = Some(trust::identity(&file)?);
                state.write_maintenance_json(&name_for_receipt, &r)?;
            }
            Err(e) => return Err(e),
        }
    }
    let _pins = pins(&directory, &r)?;
    verify_bounded(directory.path(), descriptor, source)?;
    directory.sync()?;
    r.prepared = true;
    state.write_maintenance_json(&name_for_receipt, &r)?;
    Ok(())
}
/// Fixed private child entry point. Reconstructing the exact container also
/// validates finite INF and image grammar before any native trust call.
pub(crate) fn worker(path: &Path) -> Result<String> {
    let _parent = PinnedDirectory::open(path)?;
    let d: Descriptor =
        serde_json::from_slice(&update::read_bounded(&path.join("descriptor.json"), 16384)?)?;
    d.validate()?;
    let mut bytes = protocol::windows_filter_package::MAGIC.to_vec();
    for m in d.members() {
        bytes.extend(m.bytes.to_le_bytes());
    }
    let mut pins = Vec::new();
    for (n, m) in NAMES.iter().zip(d.members()) {
        let f = trust::pin(&path.join(n), m)?;
        (&f).take(m.bytes + 1).read_to_end(&mut bytes)?;
        pins.push(f);
    }
    d.unpack(&bytes)?;
    let exe = std::env::current_exe()?;
    trust::verify_executable(
        &exe,
        &Member {
            bytes: std::fs::metadata(&exe)?.len(),
            sha256: crate::file_hash(&exe)?,
        },
    )?;
    trust::verify(path, &d)?;
    Ok(d.sha256)
}

/// All operational trust calls use this owned, finite worker. OS teardown can
/// still fail; a timeout or unconfirmed cleanup never yields a trust receipt.
pub(crate) fn verify_bounded(
    directory: &Path,
    descriptor: &Descriptor,
    source: &str,
) -> Result<()> {
    let _directory = PinnedDirectory::open(directory)?;
    let raw = update::read_bounded(&directory.join("descriptor.json"), 16384)?;
    let actual: Descriptor = serde_json::from_slice(&raw)?;
    if actual != *descriptor {
        return Err("Driver trust worker descriptor differs from approval".into());
    }
    let _descriptor = trust::pin(
        &directory.join("descriptor.json"),
        &Member {
            bytes: raw.len() as u64,
            sha256: protocol::hash(&raw),
        },
    )?;
    let _members = NAMES
        .iter()
        .zip(descriptor.members())
        .map(|(name, member)| trust::pin(&directory.join(name), member))
        .collect::<Result<Vec<_>>>()?;
    let exe = std::env::current_exe()?;
    let _exe = trust::pin(
        &exe,
        &Member {
            bytes: std::fs::metadata(&exe)?.len(),
            sha256: source.into(),
        },
    )?;
    let root = crate::protection::windows::system_root()?;
    let mut command = crate::Process::new(&exe);
    command
        .env_clear()
        .env("SystemRoot", &root)
        .current_dir(directory)
        .arg("windows-filter-verify")
        .arg(directory);
    let (code, output) = crate::windows_job::run(&command, Duration::from_secs(30), 128)
        .map_err(|_| "Driver trust worker did not complete within owned execution limits")?;
    if code != 0 || output != format!("{}\n", descriptor.sha256).as_bytes() {
        return Err("Driver trust worker refused the approved package".into());
    }
    crate::windows_job::cleanup_ready()?;
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogRelease {
    target: String,
    version: String,
    sha256: String,
    signing: String,
    windows_filter: Descriptor,
}
/// Exact named Windows outputs only. The private DACL, namespace handles and
/// catalog lease remain held through all writes; metadata is published last.
pub(crate) fn publish_catalog(snapshot: &Path, output: &Path) -> Result<String> {
    let snapshot = std::path::absolute(snapshot)?;
    let output = std::path::absolute(output)?;
    let _source = PinnedDirectory::open(&snapshot)?;
    let release = update::read_bounded(&snapshot.join("filter-release.json"), 16384)?;
    let artifact: CatalogRelease = serde_json::from_slice(&release)?;
    if artifact.target != "windows-x86_64"
        || artifact.version != env!("CARGO_PKG_VERSION")
        || artifact.signing != "native-signature-verified"
        || !protocol::hex_id(&artifact.sha256)
    {
        return Err("Invalid private Windows catalog release".into());
    }
    let descriptor = &artifact.windows_filter;
    descriptor.validate()?;
    let _release = trust::pin(
        &snapshot.join("filter-release.json"),
        &Member {
            bytes: release.len() as u64,
            sha256: protocol::hash(&release),
        },
    )?;
    let source = snapshot.join("endpoint.exe");
    let length = std::fs::metadata(&source)?.len();
    if length
        .checked_add(descriptor.bytes)
        .is_none_or(|n| n > 64 * 1024 * 1024)
    {
        return Err("Private Windows catalog exceeds combined budget".into());
    }
    let binary = trust::pin(
        &source,
        &Member {
            bytes: length,
            sha256: artifact.sha256.clone(),
        },
    )?;
    let exe = std::env::current_exe()?;
    let _exe = trust::pin(
        &exe,
        &Member {
            bytes: std::fs::metadata(&exe)?.len(),
            sha256: artifact.sha256.clone(),
        },
    )?;
    let mut data = Vec::new();
    (&binary).take(length + 1).read_to_end(&mut data)?;
    if update::binary_target(&data)? != artifact.target {
        return Err("Private Windows catalog architecture differs".into());
    }
    let archive = trust::pin(
        &snapshot.join("windows-filter.axpkg"),
        &Member {
            bytes: descriptor.bytes,
            sha256: descriptor.sha256.clone(),
        },
    )?;
    let mut bytes = Vec::new();
    (&archive)
        .take(descriptor.bytes + 1)
        .read_to_end(&mut bytes)?;
    descriptor.unpack(&bytes)?;
    verify_bounded(
        &snapshot.join("windows-filter"),
        descriptor,
        &artifact.sha256,
    )?;
    let catalog = match Directory::open(&output) {
        Ok(d) => d,
        Err(e) if missing(e.as_ref()) => Directory::create_under(
            output.parent().ok_or("Catalog parent missing")?,
            output
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("Invalid catalog leaf")?,
        )?,
        Err(e) => return Err(e),
    };
    let a = _source.nt()?;
    let b = catalog.nt()?;
    if crate::protection::windows_evidence::suffix(&a, &b).is_some()
        || crate::protection::windows_evidence::suffix(&b, &a).is_some()
    {
        return Err("Catalog and source snapshot must be disjoint".into());
    }
    let _lease = catalog.lock("windows-filter-catalog.lock")?;
    catalog.write_private_bytes("athernex-endpoint-windows-x86_64.exe", &data)?;
    catalog.write_private_bytes("athernex-windows-filter-windows-x86_64.axpkg", &bytes)?;
    catalog.write_private_bytes("windows-x86_64.json", &release)?;
    Ok(descriptor.sha256.clone())
}
