//! Installs a pinned upstream engine after SHA-256 verification; preserves existing protection.
use crate::{private_write, run_bounded, Process as Command, Result};
use athernex_endpoint_protocol::{AntivirusPackage, Bootstrap, Platform};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub fn provision(bootstrap: &Bootstrap, state: &Path) -> Result<()> {
    if bootstrap.antivirus.is_empty() {
        return Ok(());
    }
    let current: crate::Config = serde_json::from_slice(&crate::update::read_bounded(
        &state.join("config.json"),
        65536,
    )?)?;
    let engine = crate::engine_update::status(state)?;
    if current.engine_updates.enabled()
        || engine.installed.is_some()
        || engine.staged.is_some()
        || engine.transaction.is_some()
    {
        return Err(
            "Use signed engine maintenance; package provisioning cannot bypass the engine ledger"
                .into(),
        );
    }
    if bootstrap.platform != Platform::current() {
        return Err("Antivirus platform mismatch".into());
    }
    let package = bootstrap
        .antivirus
        .iter()
        .find(|p| {
            p.platform == Platform::current()
                && (p.arch == std::env::consts::ARCH || p.arch == "universal")
                && match p.format.as_str() {
                    "deb" => Path::new("/usr/bin/dpkg").is_file(),
                    "rpm" => Path::new("/usr/bin/rpm").is_file(),
                    "pkg" => cfg!(target_os = "macos"),
                    "msi" => cfg!(windows),
                    _ => false,
                }
        })
        .ok_or("No antivirus package supports this platform/package manager")?;
    package.validate()?;
    #[cfg(windows)]
    let package_directory = private_package_directory(state)?;
    #[cfg(windows)]
    let mut file = WindowsPackage::create(&package_directory)?;
    #[cfg(not(windows))]
    let mut file = tempfile::Builder::new()
        .suffix(&format!(".{}", package.format))
        .tempfile()?;
    download(package, file.as_file_mut())?;
    let package_path = file.into_temp_path();
    let mut installer = match package.format.as_str() {
        "deb" => {
            let mut c = Command::new("/usr/bin/dpkg");
            c.arg("--install");
            c
        }
        "rpm" => {
            let mut c = Command::new("/usr/bin/rpm");
            c.arg("--upgrade");
            c
        }
        "pkg" => {
            let mut c = Command::new("/usr/sbin/installer");
            c.arg("-pkg");
            c
        }
        "msi" => {
            let mut c = Command::new(r"C:\Windows\System32\msiexec.exe");
            c.arg("/i");
            c
        }
        _ => return Err("Unsupported antivirus installer".into()),
    };
    installer.arg(&package_path);
    if package.format == "pkg" {
        installer.args(["-target", "/"]);
    } else if package.format == "msi" {
        installer.args(["/qn", "/norestart"]);
    }
    let (code, output) = run_bounded(&mut installer, 900)?;
    if code != 0 && !(package.format == "msi" && code == 3010) {
        return Err(format!("Antivirus installation failed ({code}): {output}").into());
    }
    let av = state.join("av");
    let database = av.join("db");
    fs::create_dir_all(&database)?;
    let database = database.canonicalize()?;
    let config = av.join("freshclam.conf");
    let owner = if cfg!(unix) {
        "DatabaseOwner root\n"
    } else {
        ""
    };
    private_write(&config,format!("DatabaseDirectory \"{}\"\nDatabaseMirror database.clamav.net\n{owner}ConnectTimeout 15\nReceiveTimeout 120\n",database.display()).as_bytes())?;
    let (_, updater) = paths();
    let (code, output) = run_bounded(
        Command::new(updater)
            .arg("--quiet")
            .arg(format!("--config-file={}", config.display())),
        900,
    )?;
    if code != 0 {
        return Err(format!("Engine installed, but signature bootstrap failed ({code}): {output}. Retry before enabling scans.").into());
    }
    Ok(())
}
#[cfg(windows)]
struct WindowsPackage {
    // Close the write handle before TempPath cleanup on download failure.
    file: fs::File,
    path: tempfile::TempPath,
}
#[cfg(windows)]
impl WindowsPackage {
    fn create(directory: &athernex_endpoint_native::windows_state::Directory) -> Result<Self> {
        let file = directory.create_maintenance("package.msi")?;
        let path = tempfile::TempPath::try_from_path(directory.path().join("package.msi"))?;
        Ok(Self { file, path })
    }
    fn as_file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }
    fn into_temp_path(self) -> tempfile::TempPath {
        drop(self.file);
        self.path
    }
}
#[cfg(windows)]
fn private_package_directory(
    state: &Path,
) -> Result<athernex_endpoint_native::windows_state::Directory> {
    use athernex_endpoint_native::windows_state::Directory;
    let state = Directory::open(&std::path::absolute(state)?)?;
    state.require_service_access()?;
    let directory = state.maintenance_directory("installer-packages")?;
    directory.require_service_access()?;
    // A crashed or delegated MSI may still reference a staged package. Do not
    // delete it or accumulate another download without explicit reconciliation.
    if fs::read_dir(directory.path())?
        .next()
        .transpose()?
        .is_some()
    {
        return Err("Retained antivirus package staging requires recovery: finish or repair Windows Installer work, then remove only retired files from installer-packages before retrying".into());
    }
    Ok(directory)
}
#[cfg(all(windows, test))]
mod windows_installer_tests {
    use super::*;
    #[test]
    fn package_staging_is_private_pinned_and_refuses_unreconciled_files() {
        use athernex_endpoint_native::windows_state::{require_administrator, Directory};
        if require_administrator().is_err() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let state =
            Directory::maintenance_under(&std::path::absolute(temp.path()).unwrap(), "state")
                .unwrap();
        let directory = private_package_directory(state.path()).unwrap();
        directory.require_service_access().unwrap();
        let package = WindowsPackage::create(&directory).unwrap();
        assert!(private_package_directory(state.path()).is_err());
        drop(package);
        assert!(!directory.path().join("package.msi").exists());
        let package = WindowsPackage::create(&directory).unwrap().into_temp_path();
        assert!(package.is_file());
        drop(package);
        private_package_directory(state.path()).unwrap();
        assert!(fs::rename(directory.path(), state.path().join("moved")).is_err());
        directory
            .write_maintenance("retained.msi", b"partial or delegated package")
            .unwrap();
        assert!(private_package_directory(state.path()).is_err());
        assert_eq!(
            fs::read(directory.path().join("retained.msi")).unwrap(),
            b"partial or delegated package"
        );
    }
}
pub(crate) fn command(config: &crate::Config, binary: &Path) -> Result<Command> {
    let mut command = Command::new(binary);
    crate::engine_update::environment(&mut command, config)?;
    if binary == config.scanner
        || binary == config.updater
        || config.protection.daemon.as_deref() == Some(binary)
    {
        if let Some(path) = &config.engine_updates.active_certificates {
            command.arg("--cvdcertsdir").arg(path);
        }
    }
    Ok(command)
}
pub fn paths() -> (PathBuf, PathBuf) {
    if cfg!(windows) {
        return (
            r"C:\Program Files\ClamAV\clamscan.exe".into(),
            r"C:\Program Files\ClamAV\freshclam.exe".into(),
        );
    }
    let candidates = if cfg!(target_os = "macos") {
        vec![
            "/usr/local/clamav/bin",
            "/opt/homebrew/bin",
            "/usr/local/bin",
        ]
    } else {
        vec!["/usr/local/bin", "/usr/bin"]
    };
    for directory in &candidates {
        let scanner = Path::new(directory).join("clamscan");
        if scanner.is_file() {
            return (scanner, Path::new(directory).join("freshclam"));
        }
    }
    (
        Path::new(candidates[0]).join("clamscan"),
        Path::new(candidates[0]).join("freshclam"),
    )
}
fn download(package: &AntivirusPackage, output: &mut fs::File) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let mut response = client.get(&package.url).send()?.error_for_status()?;
    let mut bytes = [0u8; 65536];
    let mut count = 0u64;
    let mut hash = Sha256::new();
    loop {
        let n = response.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > package.bytes {
            return Err("Antivirus download exceeds pinned size".into());
        }
        hash.update(&bytes[..n]);
        output.write_all(&bytes[..n])?;
    }
    if count != package.bytes || format!("{:x}", hash.finalize()) != package.sha256 {
        return Err("Antivirus package checksum mismatch; installation refused".into());
    }
    output.sync_all()?;
    Ok(())
}
