//! Sharing is limited to fresh scanner workspace objects, never existing agent
//! state. The private Directory contract and mutation ACL checks stay strict.
use super::*;
use crate::windows_scanner::{self, Token};
use std::io::{Read, Write};
use windows_sys::Win32::Security::{
    Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
    GetSecurityDescriptorSacl, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION,
};

pub struct ScannerDirectory {
    pub(super) directory: Dir,
    logon: String,
}
fn grant(file: &File, logon: &str, scratch: bool) -> Result<()> {
    let (access, label) = if scratch {
        ("0x1301bf", "LW")
    } else {
        ("FRFX", "ME")
    };
    let descriptor = windows_scanner::descriptor(&format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;{access};;;{logon})S:(ML;OICI;NW;;;{label})"
    ))?;
    let dacl = windows_scanner::dacl(&descriptor)?;
    let (mut present, mut defaulted, mut sacl) = (0, 0, std::ptr::null_mut());
    if unsafe { GetSecurityDescriptorSacl(descriptor.0, &mut present, &mut sacl, &mut defaulted) }
        == 0
        || present == 0
        || sacl.is_null()
    {
        return Err("Scanner workspace is missing its integrity label".into());
    }
    let error = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            sacl,
        )
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32).into());
    }
    Ok(())
}
impl Directory {
    pub fn scanner_workspace(&self, leaf: &str, token: &Token) -> Result<ScannerDirectory> {
        token.verify()?;
        let directory = self.0.fresh_directory(leaf)?;
        grant(&directory.file, token.logon_sid(), false)?;
        directory.sync()?;
        Ok(ScannerDirectory {
            directory,
            logon: token.logon_sid().into(),
        })
    }
}
impl ScannerDirectory {
    pub fn path(&self) -> &Path {
        &self.directory.path
    }
    pub fn directory(&self, leaf: &str, scratch: bool) -> Result<Self> {
        let directory = self.directory.fresh_directory(leaf)?;
        grant(&directory.file, &self.logon, scratch)?;
        directory.sync()?;
        Ok(Self {
            directory,
            logon: self.logon.clone(),
        })
    }
    /// Source handles come from a private Directory. A finite copy budget also
    /// bounds a source that changes while it is being copied.
    pub fn copy(&self, leaf: &str, source: &mut File, budget: &mut u64) -> Result<()> {
        let size = source.metadata()?.len();
        if size > *budget {
            return Err("Scanner staging byte budget exceeded".into());
        }
        let mut file = self.directory.create_for_scanner(leaf)?;
        let copied = std::io::copy(&mut source.take((*budget).saturating_add(1)), &mut file)?;
        if copied > *budget || copied != size {
            return Err("Scanner staging source changed or exceeded its byte budget".into());
        }
        *budget -= copied;
        file.sync_all()?;
        grant(&file, &self.logon, false)?;
        file.sync_all()?;
        drop(file);
        self.directory.sync()
    }
    pub fn write(&self, leaf: &str, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 65536 {
            return Err("Scanner configuration exceeds its budget".into());
        }
        let mut file = self.directory.create_for_scanner(leaf)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        grant(&file, &self.logon, false)?;
        file.sync_all()?;
        drop(file);
        self.directory.sync()
    }
    pub fn pin(&self, leaf: &str) -> Result<File> {
        self.directory.read(leaf)
    }
}
