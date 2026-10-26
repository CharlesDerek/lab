//! Private signed deployment artifacts. These operations never activate a filter.
use crate::{update, Result};
use athernex_endpoint_protocol::{
    self as protocol,
    installer::{Artifact, MacosNetworkArtifact},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", test))]
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};
#[cfg(any(target_os = "macos", test))]
const LIMIT: usize = 64 * 1024 * 1024;
#[cfg(any(target_os = "macos", test))]
const APP: &str = "AthernexNetwork.app";
pub const INSTALL_PATH: &str = "/Applications/AthernexNetwork.app";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub path: PathBuf,
    pub target: String,
    pub artifact: MacosNetworkArtifact,
}
impl Deployment {
    pub fn validate(&self) -> Result<()> {
        self.artifact.validate()?;
        if self.path != Path::new(INSTALL_PATH)
            || !["macos-x86_64", "macos-aarch64"].contains(&self.target.as_str())
        {
            return Err("Invalid approved Mac network deployment".into());
        }
        self.client_config().validate()?;
        Ok(())
    }
    pub fn client_config(&self) -> athernex_macos_network::Config {
        let a = &self.artifact;
        athernex_macos_network::Config {
            team_id: a.team_id.clone(),
            agent_identifier: a.agent_identifier.clone(),
            provider_identifier: a.provider_identifier.clone(),
            mach_service_name: a.mach_service_name.clone(),
            app_group: a.app_group.clone(),
            provider_cdhashes: a.provider_cdhashes.clone(),
            source_policy_sha256: a.source_policy_sha256.clone(),
        }
    }
    #[cfg(target_os = "macos")]
    pub fn verify_installed(&self) -> Result<()> {
        self.validate()?;
        if self.target != protocol::update::target() {
            return Err("Network deployment platform differs".into());
        }
        let tree = read_tree(&self.path, &self.artifact, true)?;
        verify_tree(&tree, &self.artifact, &self.target)?;
        verify_native(&self.path, &self.artifact)
    }
}
#[cfg(target_os = "macos")]
fn identity(a: &MacosNetworkArtifact) -> athernex_macos_network::BundleIdentity {
    athernex_macos_network::BundleIdentity {
        team_id: a.team_id.clone(),
        agent_identifier: a.agent_identifier.clone(),
        container_identifier: a.container_identifier.clone(),
        provider_identifier: a.provider_identifier.clone(),
        app_group: a.app_group.clone(),
        mach_service_name: a.mach_service_name.clone(),
    }
}
#[cfg(any(target_os = "macos", test))]
fn provider_prefix(a: &MacosNetworkArtifact) -> String {
    format!(
        "{APP}/Contents/Library/SystemExtensions/{}.systemextension",
        a.provider_identifier
    )
}
#[cfg(any(target_os = "macos", test))]
fn allowed(path: &str, a: &MacosNetworkArtifact) -> bool {
    let provider = provider_prefix(a);
    [APP, provider.as_str()].into_iter().any(|base| {
        [
            "Contents/Info.plist",
            "Contents/PkgInfo",
            "Contents/_CodeSignature/CodeResources",
            "Contents/embedded.provisionprofile",
        ]
        .iter()
        .any(|suffix| path == format!("{base}/{suffix}"))
    }) || path == format!("{APP}/Contents/MacOS/AthernexNetwork")
        || path == format!("{provider}/Contents/MacOS/AthernexNetworkProvider")
}
#[cfg(any(target_os = "macos", test))]
type Tree = BTreeMap<String, (u32, Vec<u8>)>;
/// The hash is SHA256 of sorted UTF8 path\0mode(4 octal)\0decimal size\0file SHA256\n.
#[cfg(any(target_os = "macos", test))]
fn tree_digest(tree: &Tree) -> String {
    let mut manifest = Vec::new();
    for (path, (mode, bytes)) in tree {
        manifest.extend_from_slice(
            format!(
                "{path}\0{mode:04o}\0{}\0{}\n",
                bytes.len(),
                protocol::hash(bytes)
            )
            .as_bytes(),
        );
    }
    protocol::hash(&manifest)
}
#[cfg(any(target_os = "macos", test))]
fn verify_tree(tree: &Tree, a: &MacosNetworkArtifact, target: &str) -> Result<()> {
    a.validate()?;
    if tree.is_empty()
        || tree.len() > 512
        || tree.values().map(|(_, b)| b.len()).sum::<usize>() > LIMIT
        || tree.keys().any(|p| !allowed(p, a))
        || tree_digest(tree) != a.tree_sha256
    {
        return Err("Network bundle tree integrity differs".into());
    }
    for (path, digest) in [
        (
            format!("{APP}/Contents/MacOS/AthernexNetwork"),
            &a.container_sha256,
        ),
        (
            format!(
                "{}/Contents/MacOS/AthernexNetworkProvider",
                provider_prefix(a)
            ),
            &a.provider_sha256,
        ),
    ] {
        let (mode, bytes) = tree.get(&path).ok_or("Network bundle executable missing")?;
        let machine: u32 = match target {
            "macos-x86_64" => 0x1000007,
            "macos-aarch64" => 0x100000c,
            _ => return Err("Network bundle platform differs".into()),
        };
        if *mode != 0o755
            || bytes.len() < 64
            || bytes[..4] != [0xcf, 0xfa, 0xed, 0xfe]
            || bytes[4..8] != machine.to_le_bytes()
            || protocol::hash(bytes) != *digest
        {
            return Err("Network bundle executable integrity or architecture differs".into());
        }
    }
    for prefix in [APP.to_string(), provider_prefix(a)] {
        if !tree.contains_key(&format!("{prefix}/Contents/Info.plist")) {
            return Err("Network bundle metadata missing".into());
        }
    }
    Ok(())
}
#[cfg(any(target_os = "macos", test))]
fn unpack(bytes: &[u8], a: &MacosNetworkArtifact, target: &str) -> Result<Tree> {
    a.validate()?;
    if bytes.len() > LIMIT || bytes.len() as u64 != a.bytes || protocol::hash(bytes) != a.sha256 {
        return Err("Network archive integrity differs".into());
    }
    // The private producer needs neither ZIP64 nor comments. Bound the directory
    // count before the ZIP library allocates its per-entry metadata.
    let footer = bytes
        .get(
            bytes
                .len()
                .checked_sub(22)
                .ok_or("Network archive footer missing")?..,
        )
        .ok_or("Network archive footer missing")?;
    let u16_at = |n| u16::from_le_bytes([footer[n], footer[n + 1]]);
    let u32_at = |n| u32::from_le_bytes([footer[n], footer[n + 1], footer[n + 2], footer[n + 3]]);
    if footer[..4] != [0x50, 0x4b, 0x05, 0x06]
        || u16_at(4) != 0
        || u16_at(6) != 0
        || u16_at(8) != u16_at(10)
        || !(1..=512).contains(&u16_at(10))
        || u16_at(20) != 0
        || (u32_at(12) as u64).checked_add(u32_at(16) as u64) != Some((bytes.len() - 22) as u64)
    {
        return Err("Network archive directory exceeds its finite format".into());
    }
    // ZIP libraries may search an earlier footer after a malformed final one.
    // Bind our finite directory explicitly, then decode local files sequentially;
    // never invoke the archive-wide metadata scanner on deployment input.
    let directory_start = u32_at(16) as usize;
    let directory_end = bytes.len() - 22;
    let mut directory_cursor = directory_start;
    let mut local_cursor = Cursor::new(bytes);
    let mut tree = Tree::new();
    let mut total = 0usize;
    let mut aliases = std::collections::BTreeSet::new();
    for _ in 0..u16_at(10) {
        let h = bytes
            .get(
                directory_cursor
                    ..directory_cursor
                        .checked_add(46)
                        .ok_or("Network ZIP offset overflow")?,
            )
            .filter(|_| directory_cursor + 46 <= directory_end)
            .ok_or("Network central record missing")?;
        let u16h = |n| u16::from_le_bytes([h[n], h[n + 1]]);
        let u32h = |n| u32::from_le_bytes([h[n], h[n + 1], h[n + 2], h[n + 3]]);
        let name_len = usize::from(u16h(28));
        let size = u32h(24) as usize;
        let mode = u32h(38) >> 16;
        if h[..4] != [0x50, 0x4b, 0x01, 0x02]
            || h[5] != 3
            || u16h(6) > 20
            || ![0, 0x800].contains(&u16h(8))
            || u16h(10) != 0
            || u32h(20) != u32h(24)
            || size > LIMIT
            || total.checked_add(size).is_none_or(|n| n > LIMIT)
            || !(1..=512).contains(&name_len)
            || u16h(30) != 0
            || u16h(32) != 0
            || u16h(34) != 0
            || mode & !0o777 != 0o100000
            || ![0o644, 0o755].contains(&(mode & 0o777))
            || u64::from(u32h(42)) != local_cursor.position()
        {
            return Err("Network archive central entry exceeds its finite format".into());
        }
        let name_end = directory_cursor + 46 + name_len;
        if name_end > directory_end {
            return Err("Network archive central name exceeds budget".into());
        }
        let name = &bytes[directory_cursor + 46..name_end];
        let path =
            std::str::from_utf8(name).map_err(|_| "Network archive path encoding differs")?;
        if !allowed(path, a) || !aliases.insert(path.to_ascii_lowercase()) {
            return Err("Network archive contains an unapproved path".into());
        }
        let local_start = local_cursor.position() as usize;
        let local = bytes
            .get(
                local_start
                    ..local_start
                        .checked_add(30)
                        .ok_or("Network ZIP offset overflow")?,
            )
            .filter(|_| local_start + 30 <= directory_start)
            .ok_or("Network local record missing")?;
        let local_end = local_start
            .checked_add(30 + name_len)
            .and_then(|n| n.checked_add(size))
            .ok_or("Network ZIP offset overflow")?;
        if local[..4] != [0x50, 0x4b, 0x03, 0x04]
            || local[4..26] != h[6..28]
            || u16::from_le_bytes([local[26], local[27]]) as usize != name_len
            || local[28..30] != [0, 0]
            || local_end > directory_start
            || bytes.get(local_start + 30..local_start + 30 + name_len) != Some(name)
        {
            return Err("Network archive local and central records differ".into());
        }
        let mut file = zip::read::read_zipfile_from_stream(&mut local_cursor)?
            .ok_or("Network archive file missing")?;
        if file.name_raw() != name
            || file.size() != size as u64
            || file.compression() != zip::CompressionMethod::Stored
        {
            return Err("Network streamed archive binding differs".into());
        }
        let mut data = Vec::new();
        file.by_ref().take(size as u64 + 1).read_to_end(&mut data)?;
        if data.len() != size {
            return Err("Network streamed archive size differs".into());
        }
        drop(file);
        if local_cursor.position() != local_end as u64 {
            return Err("Network archive file boundary differs".into());
        }
        total += size;
        tree.insert(path.to_owned(), (mode & 0o777, data));
        directory_cursor = name_end;
    }
    if directory_cursor != directory_end || local_cursor.position() != directory_start as u64 {
        return Err("Network archive has unapproved trailing or intervening records".into());
    }
    verify_tree(&tree, a, target)?;
    Ok(tree)
}
fn check_declared_components(artifact: &Artifact, directory: &Path) -> Result<()> {
    let marker = directory.join("macos-network.required");
    let archive = directory.join("macos-network.zip");
    let declared = artifact.network()?;
    let exists = |path: &Path| -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    };
    let marked = exists(&marker)?;
    let bundled = exists(&archive)?;
    if declared.is_some() != marked || marked != bundled {
        return Err("Required Mac network component declarations and files differ".into());
    }
    if declared.is_some() {
        for path in [&marker, &archive] {
            let m = std::fs::symlink_metadata(path)?;
            if !m.is_file() || m.file_type().is_symlink() {
                return Err("Network installer component must be a regular file".into());
            }
        }
        if update::read_bounded(&marker, 16)? != b"1\n" {
            return Err("Network installer marker version differs".into());
        }
        // Bytes are verified from the installer's private immutable snapshot.
        // Do not reread the mutable input archive after that snapshot was checked.
    }
    Ok(())
}
/// Used by the existing pre-service installer command, including when an attacker
/// or incomplete extraction removed both required-component files.
pub fn installer_components(binary: &Path) -> Result<()> {
    let directory = binary
        .parent()
        .ok_or("Installer binary directory missing")?;
    let release = directory.join("release.json");
    if !release.try_exists()? {
        return Ok(());
    }
    let artifact: Artifact = serde_json::from_slice(&update::read_bounded(&release, 16384)?)?;
    check_declared_components(&artifact, directory)?;
    if artifact.macos_network.is_some() {
        release_component(&artifact)?;
    }
    Ok(())
}
/// Required-component readiness binds the running management binary to release.
pub fn installer_hash(manifest: &Path) -> Result<Option<String>> {
    let a: Artifact = serde_json::from_slice(&update::read_bounded(manifest, 16384)?)?;
    Ok(release_component(&a)?.map(|n| n.sha256.clone()))
}
fn release_component(a: &Artifact) -> Result<Option<&MacosNetworkArtifact>> {
    if a.target != protocol::update::target() {
        return Err("Installer build does not match this platform".into());
    }
    if let Some(n) = a.network()? {
        if crate::file_hash(&std::env::current_exe()?)? != a.sha256 {
            return Err("Installer management binary checksum mismatch".into());
        }
        return Ok(Some(n));
    }
    Ok(None)
}
/// Packaging-only inspection of an immutable private snapshot, with bounded output.
pub fn inspect(path: &Path, expected: &Path) -> Result<athernex_macos_network::BundleInspection> {
    let id: athernex_macos_network::BundleIdentity =
        serde_json::from_slice(&update::read_bounded(expected, 4096)?)?;
    Ok(athernex_macos_network::inspect_bundle(path, &id)?)
}
#[cfg(target_os = "macos")]
fn verify_native(path: &Path, a: &MacosNetworkArtifact) -> Result<()> {
    let mut result = athernex_macos_network::inspect_bundle(path, &identity(a))?;
    result.provider_cdhashes.sort();
    if result.identity != identity(a) || result.provider_cdhashes != a.provider_cdhashes {
        return Err("Signed network deployment pin differs".into());
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn read_tree(app: &Path, a: &MacosNetworkArtifact, root_owned: bool) -> Result<Tree> {
    use std::{fs, os::unix::fs::MetadataExt};
    fn walk(
        base: &Path,
        path: &Path,
        a: &MacosNetworkArtifact,
        root_owned: bool,
        tree: &mut Tree,
        total: &mut usize,
    ) -> Result<()> {
        let m = fs::symlink_metadata(path)?;
        if m.mode() & 0o7000 != 0
            || m.file_type().is_symlink()
            || (root_owned && (m.uid() != 0 || m.mode() & 0o022 != 0))
        {
            return Err("Network bundle ownership or link differs".into());
        }
        if m.is_dir() {
            let relative = path
                .strip_prefix(base)?
                .to_str()
                .ok_or("Network directory encoding differs")?;
            let provider = provider_prefix(a);
            let directories = [
                APP.to_string(),
                format!("{APP}/Contents"),
                format!("{APP}/Contents/MacOS"),
                format!("{APP}/Contents/_CodeSignature"),
                format!("{APP}/Contents/Library"),
                format!("{APP}/Contents/Library/SystemExtensions"),
                provider.clone(),
                format!("{provider}/Contents"),
                format!("{provider}/Contents/MacOS"),
                format!("{provider}/Contents/_CodeSignature"),
            ];
            if !directories.iter().any(|d| d == relative) {
                return Err("Network bundle directory is unapproved".into());
            }
            for (index, entry) in fs::read_dir(path)?.enumerate() {
                if index >= 512 {
                    return Err("Network directory entry budget exceeded".into());
                }
                walk(base, &entry?.path(), a, root_owned, tree, total)?;
            }
        } else {
            let relative = path
                .strip_prefix(base)?
                .to_str()
                .ok_or("Network bundle path encoding differs")?
                .to_owned();
            if !m.is_file()
                || m.nlink() != 1
                || !allowed(&relative, a)
                || ![0o644, 0o755].contains(&(m.mode() & 0o777))
                || m.len() > LIMIT as u64
            {
                return Err("Network bundle contains an unapproved file".into());
            }
            let data = update::read_bounded(path, LIMIT as u64)?;
            *total += data.len();
            if *total > LIMIT || tree.len() >= 512 {
                return Err("Network bundle size budget exceeded".into());
            }
            tree.insert(relative, (m.mode() & 0o777, data));
        }
        Ok(())
    }
    let mut tree = Tree::new();
    let mut total = 0;
    walk(
        app.parent().ok_or("Network bundle parent missing")?,
        app,
        a,
        root_owned,
        &mut tree,
        &mut total,
    )?;
    Ok(tree)
}
#[cfg(target_os = "macos")]
fn protected_staging_root() -> Result<PathBuf> {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, MetadataExt},
    };
    let parent = Path::new("/Library");
    for ancestor in parent.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("Network staging ancestor is not root-protected".into());
        }
    }
    let root = parent.join("AthernexEndpoint");
    match fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(&root)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o7777 != 0o700 {
        return Err("Network staging requires a private root-owned directory".into());
    }
    Ok(root)
}
#[cfg(target_os = "macos")]
fn stage(archive: &Path, manifest: &Path) -> Result<(tempfile::TempDir, Deployment)> {
    use std::{fs, os::unix::fs::PermissionsExt};
    if unsafe { libc::geteuid() } != 0 {
        return Err("Network installation requires root".into());
    }
    let artifact: Artifact = serde_json::from_slice(&update::read_bounded(manifest, 16384)?)?;
    let component = release_component(&artifact)?
        .ok_or("Required network release is missing")?
        .clone();
    let tree = unpack(
        &update::read_bounded(archive, LIMIT as u64)?,
        &component,
        &artifact.target,
    )?;
    let parent = protected_staging_root()?;
    let temp = tempfile::Builder::new()
        .prefix(".network-")
        .tempdir_in(parent)?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    for (path, (mode, data)) in &tree {
        let destination = temp.path().join(path);
        fs::create_dir_all(destination.parent().ok_or("Network entry parent missing")?)?;
        for parent in destination
            .parent()
            .ok_or("Network entry parent missing")?
            .ancestors()
        {
            if parent == temp.path() {
                break;
            }
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
        }
        fs::write(&destination, data)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(*mode))?;
    }
    verify_native(&temp.path().join(APP), &component)?;
    let deployment = Deployment {
        path: INSTALL_PATH.into(),
        target: artifact.target,
        artifact: component,
    };
    deployment.validate()?;
    Ok((temp, deployment))
}
/// Preflight before the shell installer stops services or copies binaries.
#[cfg(target_os = "macos")]
pub fn preflight(archive: &Path, manifest: &Path) -> Result<()> {
    use std::{fs, os::unix::fs::MetadataExt};
    let parent = fs::symlink_metadata("/Applications")?;
    if !parent.is_dir()
        || parent.file_type().is_symlink()
        || parent.uid() != 0
        || parent.mode() & 0o002 != 0
    {
        return Err("Applications directory must be root-owned and not world-writable".into());
    }
    let (_snapshot, deployment) = stage(archive, manifest)?;
    if deployment.path.try_exists()? {
        deployment.verify_installed()?;
    }
    Ok(())
}
/// Records a verified, privately pinned installation; preserves enablement.
/// A differing existing bundle refuses: retire/upgrade its OS-managed extension
/// through an explicitly controlled lifecycle before replacing its app.
#[cfg(target_os = "macos")]
pub fn install(state: &Path, archive: &Path, manifest: &Path) -> Result<()> {
    use std::{fs, os::unix::fs::MetadataExt};
    preflight(archive, manifest)?;
    if !state.is_absolute() || state.canonicalize()? != state {
        return Err("Network state must be absolute and canonical".into());
    }
    for (index, path) in state.ancestors().enumerate() {
        let m = fs::symlink_metadata(path)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != 0
            || m.mode() & 0o022 != 0
            || (index == 0 && m.mode() & 0o777 != 0o700)
        {
            return Err("Network state requires private root-owned storage".into());
        }
    }
    let config_path = state.join("config.json");
    update::check_destination(&config_path)?;
    let m = fs::symlink_metadata(&config_path)?;
    if m.nlink() != 1 || m.mode() & 0o077 != 0 {
        return Err("Network configuration must be private and singly linked".into());
    }
    let bytes = update::read_bounded(&config_path, 65536)?;
    let mut config: crate::Config = serde_json::from_slice(&bytes)?;
    config.validate()?;
    let _maintenance = update::offline_maintenance(state, &config)?;
    if update::read_bounded(&config_path, 65536)? != bytes {
        return Err("Network policy changed during setup".into());
    }
    let (snapshot, deployment) = stage(archive, manifest)?;
    if deployment.path.try_exists()? {
        deployment.verify_installed()?;
    } else {
        // rename with exclusive destination prevents replacement after preflight.
        let from =
            std::ffi::CString::new(snapshot.path().join(APP).as_os_str().as_encoded_bytes())?;
        let to = std::ffi::CString::new(deployment.path.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } != 0 {
            return Err("Network bundle installation refused".into());
        }
    }
    deployment.verify_installed()?;
    config.telemetry.macos_network_deployment = Some(deployment);
    config.validate()?;
    crate::private_write(&config_path, &serde_json::to_vec_pretty(&config)?)
}
#[cfg(test)]
mod tests;
