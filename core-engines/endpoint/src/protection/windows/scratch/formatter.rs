use super::*;
use athernex_endpoint_native::windows_scratch::{ReadyVolume, UnformattedVolume};

const SCRIPT: &str = include_str!("format.ps1");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Formatted {
    schema: u32,
    nonce: String,
    volume: String,
}

pub(super) fn run(volume: UnformattedVolume, logon: &str, temporary: &Path) -> Result<ReadyVolume> {
    volume.verify()?;
    let root = super::super::system_root()?;
    let powershell = PathBuf::from(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let _system_directory =
        PinnedDirectory::open(powershell.parent().ok_or("PowerShell has no parent")?)?;
    let nonce = secret()?;
    let input = serde_json::to_vec(
        &serde_json::json!({"schema":1,"nonce":nonce,"target":volume.target()}),
    )?;
    if input.len() > 16384 {
        return Err("Scratch formatter input exceeds its budget".into());
    }
    let mut invocation = command(&powershell, temporary)?;
    invocation
        // Storage's manifest resolves its native assembly through windir.
        // Supply the API-derived directory after command clears inheritance.
        .env("windir", root)
        .env("PSModulePath", powershell.parent().unwrap().join("Modules"))
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ]);
    let (code, output) =
        windows_job::run_with_input(&invocation, Duration::from_secs(60), 8192, &input)?;
    windows_job::cleanup_ready()?;
    if code != 0 {
        return Err(format!(
            "Owned scratch formatter failed ({code}): {}",
            String::from_utf8_lossy(&output)
        )
        .into());
    }
    let reply: Formatted = serde_json::from_slice(&output)?;
    if reply.schema != 1 || reply.nonce != nonce || reply.volume != volume.target().volume {
        return Err("Scratch formatter acknowledgement does not match its request".into());
    }
    volume.prepare(logon)
}
