//! Audit policy is observed, never configured by the production collector.
use super::api::{failure, Handle};
use crate::Result;
use std::{mem::size_of, ptr::null_mut};
use windows_sys::Win32::{
    Security::{Authentication::Identity::*, GetLengthSid, IsValidSid, SECURITY_MAX_SID_SIZE},
    System::EventLog::*,
};

struct Allocation(*mut std::ffi::c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            AuditFree(self.0);
        }
    }
}

fn system() -> Result<()> {
    let wanted = [Audit_Logon_Logon, Audit_Logon_AccountLockout];
    let mut raw = null_mut();
    let ok = unsafe { AuditQuerySystemPolicy(wanted.as_ptr(), wanted.len() as u32, &mut raw) };
    let _allocation = Allocation(raw.cast());
    if !ok {
        return Err(failure("Windows logon audit policy query"));
    }
    if raw.is_null() {
        return Err("Windows logon audit policy is missing".into());
    }
    for (index, guid) in wanted.iter().enumerate() {
        let value = unsafe { *raw.add(index) };
        if super::api::guid_text(&value.AuditSubCategoryGuid) != super::api::guid_text(guid) {
            return Err("Windows logon audit policy response changed scope".into());
        }
        let required = if index == 0 { 3 } else { 2 };
        if value.AuditingInformation & required != required || value.AuditingInformation & !3 != 0 {
            return Err(
                "Windows Security logon success/failure or lockout failure auditing is disabled"
                    .into(),
            );
        }
    }
    Ok(())
}
fn per_user() -> Result<()> {
    let mut raw = null_mut();
    let ok = unsafe { AuditEnumeratePerUserPolicy(&mut raw) };
    let _allocation = Allocation(raw.cast());
    if !ok {
        return Err(failure("Windows per-user audit policy enumeration"));
    }
    if raw.is_null() {
        return Err("Windows per-user audit policy enumeration is missing".into());
    }
    let count = unsafe { (*raw).UsersCount } as usize;
    let users = unsafe { (*raw).UserSidArray };
    if count > 1024 || (count != 0 && users.is_null()) {
        return Err("Windows per-user audit policy exceeds its inspection budget".into());
    }
    let wanted = [Audit_Logon_Logon, Audit_Logon_AccountLockout];
    for index in 0..count {
        let sid = unsafe { *users.add(index) };
        if sid.is_null()
            || unsafe { IsValidSid(sid) } == 0
            || unsafe { GetLengthSid(sid) } > SECURITY_MAX_SID_SIZE
        {
            return Err("Windows per-user audit policy has an invalid principal".into());
        }
        let mut raw_policy = null_mut();
        let ok = unsafe {
            AuditQueryPerUserPolicy(sid, wanted.as_ptr(), wanted.len() as u32, &mut raw_policy)
        };
        let _policy = Allocation(raw_policy.cast());
        if !ok {
            return Err(failure("Windows per-user audit policy query"));
        }
        if raw_policy.is_null() {
            return Err("Windows per-user audit policy is missing".into());
        }
        for (offset, guid) in wanted.iter().enumerate() {
            let value = unsafe { *raw_policy.add(offset) };
            if super::api::guid_text(&value.AuditSubCategoryGuid) != super::api::guid_text(guid)
                || value.AuditingInformation
                    & !(PER_USER_AUDIT_SUCCESS_INCLUDE | PER_USER_AUDIT_FAILURE_INCLUDE)
                    != 0
            {
                return Err("Windows Security per-user audit exclusions or unknown policy prevent complete source coverage".into());
            }
        }
    }
    Ok(())
}
pub(super) fn check() -> Result<()> {
    system()?;
    per_user()
}

pub(super) fn log_created(log: &Handle) -> Result<u64> {
    let value = log_property(log, EvtLogCreationTime, EvtVarTypeFileTime)?;
    let time = unsafe { value.Anonymous.FileTimeVal };
    if time == 0 {
        return Err("Windows Security log creation identity is unavailable".into());
    }
    Ok(time)
}
pub(super) fn log_full(log: &Handle) -> Result<bool> {
    let value = log_property(log, EvtLogFull, EvtVarTypeBoolean)?;
    Ok(unsafe { value.Anonymous.BooleanVal } != 0)
}
fn log_property(log: &Handle, property: i32, kind: i32) -> Result<EVT_VARIANT> {
    let mut value = EVT_VARIANT::default();
    let mut bytes = 0;
    if unsafe {
        EvtGetLogInfo(
            log.0,
            property,
            size_of::<EVT_VARIANT>() as u32,
            &mut value,
            &mut bytes,
        )
    } == 0
    {
        return Err(failure("Windows Security log metadata query"));
    }
    if bytes as usize != size_of::<EVT_VARIANT>() || value.Type != kind as u32 {
        return Err("Windows Security log metadata has an unexpected type".into());
    }
    Ok(value)
}
pub(super) fn enabled() -> Result<bool> {
    let config = Handle::checked(
        unsafe { EvtOpenChannelConfig(0, windows_sys::core::w!("Security"), 0) },
        "Windows Security channel configuration",
    )?;
    let mut value = EVT_VARIANT::default();
    let mut bytes = 0;
    if unsafe {
        EvtGetChannelConfigProperty(
            config.0,
            EvtChannelConfigEnabled,
            0,
            size_of::<EVT_VARIANT>() as u32,
            &mut value,
            &mut bytes,
        )
    } == 0
    {
        return Err(failure("Windows Security channel enabled query"));
    }
    if bytes as usize != size_of::<EVT_VARIANT>() || value.Type != EvtVarTypeBoolean as u32 {
        return Err("Windows Security channel configuration has an unexpected type".into());
    }
    Ok(unsafe { value.Anonymous.BooleanVal } != 0)
}
