//! System policy assessment after native signature and identity inspection.
//! No shell, policy changes, inherited environment, or raw diagnostic output.
use crate::Result;
use std::{path::Path, process::Command, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_LIMIT: usize = 4096;
const REFUSAL: &str = "Network bundle system policy assessment failed";

fn command(path: &Path) -> Result<Command> {
    let value = path
        .to_str()
        .filter(|p| p.starts_with('/') && !p.contains('\0') && p.len() <= 4096)
        .ok_or(REFUSAL)?;
    let mut command = Command::new("/usr/sbin/spctl");
    command
        .args(["--assess", "--type", "execute", value])
        .env_clear()
        .current_dir("/");
    Ok(command)
}

fn accepted(result: athernex_endpoint_native::Result<(i32, Vec<u8>)>) -> Result<()> {
    match result {
        Ok((0, _)) => Ok(()),
        // The owned runner has bounded both streams and cleanup ownership.
        // Neither retained command output nor underlying errors leave this gate.
        _ => Err(REFUSAL.into()),
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn verify(path: &Path) -> Result<()> {
    accepted(athernex_endpoint_native::child::run(
        &mut command(path)?,
        TIMEOUT,
        OUTPUT_LIMIT,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn assessment_command_is_fixed_and_keeps_the_path_one_argument() {
        let path = Path::new("/private/approved name/AthernexNetwork.app");
        let cmd = command(path).unwrap();
        assert_eq!(cmd.get_program(), OsStr::new("/usr/sbin/spctl"));
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            ["--assess", "--type", "execute", path.to_str().unwrap()].map(OsStr::new)
        );
        assert_eq!(cmd.get_current_dir(), Some(Path::new("/")));
        assert_eq!(TIMEOUT, Duration::from_secs(30));
        assert_eq!(OUTPUT_LIMIT, 4096);
        for invalid in ["relative.app", "/private/invalid\0/AthernexNetwork.app"] {
            assert!(command(Path::new(invalid)).is_err());
        }
    }

    // Only tests choose another executable or execution budget. Production has
    // one private call site using the fixed command and budgets above.
    fn controlled(
        script: &str,
        timeout: Duration,
    ) -> athernex_endpoint_native::Result<(i32, Vec<u8>)> {
        athernex_endpoint_native::child::run(
            Command::new("/bin/sh")
                .args(["-c", script])
                .env_clear()
                .current_dir("/"),
            timeout,
            OUTPUT_LIMIT,
        )
    }

    #[test]
    fn assessment_requires_zero_and_discards_both_private_output_streams() {
        accepted(controlled(
            "printf private_stdout; printf private_stderr >&2; exit 0",
            TIMEOUT,
        ))
        .unwrap();
        let refused = controlled(
            "printf private_stdout; printf private_stderr >&2; exit 7",
            TIMEOUT,
        )
        .expect("Controlled assessment did not finish");
        assert_eq!(refused.0, 7);
        let error = accepted(Ok(refused)).unwrap_err();
        assert_eq!(error.to_string(), REFUSAL);
    }

    #[test]
    fn assessment_owned_child_output_and_deadline_failures_stay_closed() {
        let output = controlled("while :; do printf 0123456789abcdef; done", TIMEOUT).unwrap_err();
        assert!(
            output
                .to_string()
                .starts_with("Action exceeded its output budget"),
            "Controlled output refusal changed"
        );
        assert_eq!(accepted(Err(output)).unwrap_err(), REFUSAL);
        let timeout =
            controlled("while :; do sleep 1; done", Duration::from_millis(100)).unwrap_err();
        assert!(
            timeout
                .to_string()
                .starts_with("Action exceeded its time budget"),
            "Controlled deadline refusal changed"
        );
        assert_eq!(accepted(Err(timeout)).unwrap_err(), REFUSAL);
    }
}
