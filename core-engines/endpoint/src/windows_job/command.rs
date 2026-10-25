use super::{handles, Child};
use std::{
    ffi::{OsStr, OsString},
    io,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
};

/// An explicit Windows executable command. Jobs are assigned during creation,
/// before any user code runs. Requires Windows 10 / Windows Server 2016 or newer.
/// Only .exe applications are accepted; callers select a shell explicitly.
#[derive(Debug)]
pub struct Command {
    program: OsString,
    args: Vec<OsString>,
    pub(super) clear_env: bool,
    pub(super) environment: Vec<(OsString, Option<OsString>)>,
    directory: Option<PathBuf>,
}
impl Command {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().into(),
            args: Vec::new(),
            clear_env: false,
            environment: Vec::new(),
            directory: None,
        }
    }
    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.args.push(arg.as_ref().into());
        self
    }
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }
    pub fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.environment
            .push((key.as_ref().into(), Some(value.as_ref().into())));
        self
    }
    pub fn env_remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        self.environment.push((key.as_ref().into(), None));
        self
    }
    pub fn env_clear(&mut self) -> &mut Self {
        self.clear_env = true;
        self.environment.clear();
        self
    }
    pub fn current_dir(&mut self, directory: impl AsRef<std::path::Path>) -> &mut Self {
        self.directory = Some(directory.as_ref().into());
        self
    }
    pub(crate) fn spawn(&self) -> io::Result<Child> {
        let stdio = handles::Stdio::inherit()?;
        self.spawn_with(&stdio)
    }
    pub(super) fn spawn_with(&self, stdio: &handles::Stdio) -> io::Result<Child> {
        self.spawn_with_token(stdio, None)
    }
    pub(super) fn spawn_with_token(
        &self,
        stdio: &handles::Stdio,
        token: Option<&athernex_endpoint_native::windows_scanner::Token>,
    ) -> io::Result<Child> {
        let program_path = std::path::Path::new(&self.program);
        if !program_path.is_absolute()
            || !program_path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "An absolute Windows .exe path is required",
            ));
        }
        if self.args.len() > 4096 || self.environment.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows command exceeds entry budget",
            ));
        }
        let program: Vec<u16> = self.program.encode_wide().collect();
        let args: Vec<Vec<u16>> = self
            .args
            .iter()
            .map(|a| a.encode_wide().collect())
            .collect();
        let mut line = crate::windows_wire::command_line(&program, &args)?;
        let application = terminated(&self.program)?;
        let directory = self
            .directory
            .as_ref()
            .map(|d| {
                if !d.is_absolute() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Working directory must be absolute",
                    ));
                }
                terminated(d.as_os_str())
            })
            .transpose()?;
        let environment = super::environment::block(self)?;
        super::spawn(
            &application,
            &mut line,
            directory.as_deref(),
            &environment,
            stdio,
            token,
        )
    }
}
fn terminated(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut result: Vec<u16> = value.encode_wide().collect();
    if result.contains(&0) || result.len() >= 32767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid Windows path",
        ));
    }
    result.push(0);
    Ok(result)
}
