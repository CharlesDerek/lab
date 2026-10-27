use super::*;
use crate::{
    windows_filter::port::Port, windows_filter_package as trust, windows_state::PinnedDirectory,
    Result,
};
use athernex_endpoint_protocol::windows_filter_package::{Descriptor, NAMES};
use std::{
    ffi::c_void,
    fs::File,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Devices::DeviceAndDriverInstallation::*,
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_SERVICE_DOES_NOT_EXIST},
    Storage::InstallableFileSystems::*,
    System::{Services::*, SystemInformation::GetWindowsDirectoryW},
};

mod registry;
mod service;
pub use registry::{create_epoch, epoch, global_path};
pub use service::{helper_absent, serve, Helper, HelperSpec, HelperStatus};

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Result<Vec<u16>> {
    let value: Vec<u16> = value.as_ref().encode_wide().collect();
    if value.is_empty() || value.len() > 1023 || value.contains(&0) {
        return Err("Native lifecycle name exceeds its profile".into());
    }
    Ok(value.into_iter().chain([0]).collect())
}
fn terminated(value: &[u16]) -> Result<String> {
    let length = value
        .iter()
        .position(|v| *v == 0)
        .ok_or("Unterminated native name")?;
    let text = String::from_utf16(&value[..length])?;
    if text.chars().any(char::is_control) {
        return Err("Native lifecycle name contains control characters".into());
    }
    Ok(text)
}
fn bool_result(value: i32) -> Result<()> {
    if value == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}
fn identity(file: &File) -> Result<ObjectIdentity> {
    let (volume, file_id) = trust::identity(file)?;
    Ok(ObjectIdentity { volume, file_id })
}
fn windows_root() -> Result<PathBuf> {
    let mut value = [0u16; 1024];
    let len = unsafe { GetWindowsDirectoryW(value.as_mut_ptr(), value.len() as u32) };
    if len == 0 || len as usize >= value.len() {
        return Err("Windows directory unavailable".into());
    }
    Ok(String::from_utf16(&value[..len as usize])?.into())
}

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn scm(access: u32) -> Result<ServiceHandle> {
    let handle = unsafe { OpenSCManagerW(null(), null(), access) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(ServiceHandle(handle))
}
fn open_service(manager: &ServiceHandle, name: &str, access: u32) -> Result<Option<ServiceHandle>> {
    let name = wide(name)?;
    let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
            Ok(None)
        } else {
            Err(error.into())
        };
    }
    Ok(Some(ServiceHandle(handle)))
}

/// QueryServiceConfig pointers must remain inside the returned allocation.
fn buffer_string(pointer: *const u16, bytes: &[usize], used: usize) -> Result<String> {
    if pointer.is_null() {
        return Ok(String::new());
    }
    let start = bytes.as_ptr() as usize;
    let at = pointer as usize;
    let end = start.checked_add(used).ok_or("Native buffer overflow")?;
    if at < start || at >= end || !at.is_multiple_of(2) {
        return Err("Native string escapes its buffer".into());
    }
    terminated(unsafe { std::slice::from_raw_parts(pointer, (end - at) / 2) })
}
fn configuration(handle: &ServiceHandle) -> Result<ServiceConfiguration> {
    let mut needed = 0;
    let result = unsafe { QueryServiceConfigW(handle.0, null_mut(), 0, &mut needed) };
    if result != 0
        || std::io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || needed < size_of::<QUERY_SERVICE_CONFIGW>() as u32
        || needed > 8192
    {
        return Err("Service configuration size refused".into());
    }
    let mut bytes = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let allocated = needed;
    bool_result(unsafe {
        QueryServiceConfigW(handle.0, bytes.as_mut_ptr().cast(), allocated, &mut needed)
    })?;
    if needed > allocated {
        return Err("Service configuration changed size".into());
    }
    let value = unsafe { &*bytes.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    let mut dependencies = Vec::new();
    let mut pointer = value.lpDependencies;
    if !pointer.is_null() {
        loop {
            let item = buffer_string(pointer, &bytes, allocated as usize)?;
            if item.is_empty() {
                break;
            }
            if dependencies.len() == 16 {
                return Err("Service dependencies exceed profile".into());
            }
            pointer = unsafe { pointer.add(item.encode_utf16().count() + 1) };
            dependencies.push(item);
        }
    }
    Ok(ServiceConfiguration {
        service_type: value.dwServiceType,
        start_type: value.dwStartType,
        error_control: value.dwErrorControl,
        binary_path: buffer_string(value.lpBinaryPathName, &bytes, allocated as usize)?,
        load_order_group: buffer_string(value.lpLoadOrderGroup, &bytes, allocated as usize)?,
        account: buffer_string(value.lpServiceStartName, &bytes, allocated as usize)?,
        dependencies,
    })
}
fn service_observation(handle: &ServiceHandle) -> Result<ServiceObservation> {
    let configuration = configuration(handle)?;
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut returned = 0;
    bool_result(unsafe {
        QueryServiceStatusEx(
            handle.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut returned,
        )
    })?;
    // pcbBytesNeeded is documented only for ERROR_INSUFFICIENT_BUFFER;
    // success does not promise to write it. The successful ABI output is the
    // fixed SERVICE_STATUS_PROCESS allocation supplied above.
    Ok(ServiceObservation {
        configuration,
        state: status.dwCurrentState,
        process_id: status.dwProcessId,
        win32_exit_code: status.dwWin32ExitCode,
        service_exit_code: status.dwServiceSpecificExitCode,
    })
}

fn original_names(path: &Path) -> Result<(String, String)> {
    let path = wide(path)?;
    let mut needed = 0;
    bool_result(unsafe {
        SetupGetInfInformationW(
            path.as_ptr().cast(),
            INFINFO_INF_NAME_IS_ABSOLUTE,
            null_mut(),
            0,
            &mut needed,
        )
    })?;
    if needed < size_of::<SP_INF_INFORMATION>() as u32 || needed > 65536 {
        return Err("Native INF information exceeds budget".into());
    }
    let mut bytes = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let allocated = needed;
    bool_result(unsafe {
        SetupGetInfInformationW(
            path.as_ptr().cast(),
            INFINFO_INF_NAME_IS_ABSOLUTE,
            bytes.as_mut_ptr().cast(),
            allocated,
            &mut needed,
        )
    })?;
    if needed > allocated {
        return Err("Native INF information changed size".into());
    }
    let info = unsafe { &*bytes.as_ptr().cast::<SP_INF_INFORMATION>() };
    if info.InfCount != 1 {
        return Err("Compound native INF information refused".into());
    }
    let mut original = SP_ORIGINAL_FILE_INFO_W {
        cbSize: size_of::<SP_ORIGINAL_FILE_INFO_W>() as u32,
        ..Default::default()
    };
    bool_result(unsafe { SetupQueryInfOriginalFileInformationW(info, 0, null(), &mut original) })?;
    Ok((
        terminated(&original.OriginalInfName)?,
        terminated(&original.OriginalCatalogName)?,
    ))
}

fn package_candidates() -> Result<Vec<PathBuf>> {
    let mut needed = 0;
    bool_result(unsafe {
        SetupGetInfFileListW(null(), INF_STYLE_WIN4, null_mut(), 0, &mut needed)
    })?;
    if needed < 2 || needed as usize > MAX_INVENTORY_CHARS {
        return Err("INF inventory exceeds budget".into());
    }
    let mut names = vec![0u16; needed as usize];
    let allocated = needed;
    bool_result(unsafe {
        SetupGetInfFileListW(
            null(),
            INF_STYLE_WIN4,
            names.as_mut_ptr(),
            allocated,
            &mut needed,
        )
    })?;
    if needed > allocated {
        return Err("INF inventory changed size".into());
    }
    let root = windows_root()?.join("INF");
    let mut candidates = Vec::new();
    let mut count = 0;
    let mut at = 0;
    loop {
        let name = terminated(names.get(at..).ok_or("Invalid INF inventory")?)?;
        if name.is_empty() {
            break;
        }
        count += 1;
        if count > MAX_INVENTORY_FILES || name.contains(['\\', '/', ':']) {
            return Err("INF inventory name refused".into());
        }
        at += name.encode_utf16().count() + 1;
        // Only OEM packages can be ours. Inbox inventory is not a package adoption path.
        if !name.to_ascii_lowercase().starts_with("oem") {
            continue;
        }
        let path = root.join(&name);
        let (inf, cat) = original_names(&path)?;
        if inf.eq_ignore_ascii_case(NAMES[1]) || cat.eq_ignore_ascii_case(NAMES[2]) {
            candidates.push(path);
            if candidates.len() > 16 {
                return Err("Ambiguous driver package inventory".into());
            }
        }
    }
    Ok(candidates)
}

pub fn filter_present() -> Result<bool> {
    struct Find(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Find {
        fn drop(&mut self) {
            unsafe {
                FilterFindClose(self.0);
            }
        }
    }
    let mut bytes = vec![0usize; 65536 / size_of::<usize>()];
    let mut returned = 0;
    let mut raw = null_mut();
    let mut status = unsafe {
        FilterFindFirst(
            FilterFullInformation,
            bytes.as_mut_ptr().cast(),
            65536,
            &mut returned,
            &mut raw,
        )
    };
    let no_more = (0x80070000u32 | ERROR_NO_MORE_ITEMS) as i32;
    if status == no_more {
        return Ok(false);
    }
    if status < 0 {
        return Err("Filter inventory unavailable".into());
    }
    if raw.is_null() || raw as isize == -1 {
        return Err("Invalid filter inventory handle".into());
    }
    let find = Find(raw);
    let mut count = 0;
    loop {
        if status < 0
            || returned as usize > 65536
            || (returned as usize) < size_of::<FILTER_FULL_INFORMATION>()
        {
            return Err("Filter inventory record refused".into());
        }
        let info = unsafe { &*bytes.as_ptr().cast::<FILTER_FULL_INFORMATION>() };
        let offset = std::mem::offset_of!(FILTER_FULL_INFORMATION, FilterNameBuffer);
        let length = info.FilterNameLength as usize;
        if !length.is_multiple_of(2)
            || offset
                .checked_add(length)
                .is_none_or(|n| n > returned as usize)
        {
            return Err("Filter inventory name bounds refused".into());
        }
        let name = String::from_utf16(unsafe {
            std::slice::from_raw_parts(
                bytes.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
                length / 2,
            )
        })?;
        if name.eq_ignore_ascii_case(DRIVER) {
            return Ok(true);
        }
        count += 1;
        if count > 4096 {
            return Err("Filter inventory exceeds budget".into());
        }
        status = unsafe {
            FilterFindNext(
                find.0,
                FilterFullInformation,
                bytes.as_mut_ptr().cast(),
                65536,
                &mut returned,
            )
        };
        if status == no_more {
            return Ok(false);
        }
    }
}

pub fn inspect() -> Result<Inventory> {
    let manager = scm(SC_MANAGER_CONNECT)?;
    let service = open_service(
        &manager,
        DRIVER,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
    )?
    .as_ref()
    .map(service_observation)
    .transpose()?;
    Ok(Inventory {
        candidate_infs: package_candidates()?,
        service,
        filter_present: filter_present()?,
    })
}

fn store_location(published: &Path) -> Result<PathBuf> {
    let published = wide(published)?;
    let mut path = [0u16; 260];
    let mut needed = 0;
    bool_result(unsafe {
        SetupGetInfDriverStoreLocationW(
            published.as_ptr(),
            null(),
            null(),
            path.as_mut_ptr(),
            path.len() as u32,
            &mut needed,
        )
    })?;
    if needed == 0 || needed as usize > path.len() {
        return Err("Driver Store location exceeds profile".into());
    }
    Ok(terminated(&path)?.into())
}

pub fn observe_registration(expected: &Descriptor) -> Result<Registration> {
    let current = inspect()?;
    if current.candidate_infs.len() != 1 {
        return Err("Driver package registration is absent or ambiguous".into());
    }
    let published_inf = current.candidate_infs[0].clone();
    let store_inf = store_location(&published_inf)?;
    let root = store_inf
        .parent()
        .ok_or("Driver Store path has no parent")?;
    let mut reverse = [0u16; 260];
    let mut needed = 0;
    bool_result(unsafe {
        SetupGetInfPublishedNameW(
            wide(&store_inf)?.as_ptr(),
            reverse.as_mut_ptr(),
            reverse.len() as u32,
            &mut needed,
        )
    })?;
    if needed == 0
        || needed as usize > reverse.len()
        || !terminated(&reverse)?
            .eq_ignore_ascii_case(published_inf.to_str().ok_or("Non-Unicode published INF")?)
    {
        return Err("Driver Store reverse mapping differs".into());
    }
    let _published_parent = PinnedDirectory::open(
        published_inf
            .parent()
            .ok_or("Published INF parent missing")?,
    )?;
    let _store_parent = PinnedDirectory::open(root)?;
    let published = trust::pin(&published_inf, &expected.inf)?;
    let mut ids = Vec::new();
    let mut pins = Vec::new();
    for (name, member) in NAMES.iter().zip(expected.members()) {
        let pin = trust::pin(&root.join(name), member)?;
        ids.push(identity(&pin)?);
        pins.push(pin);
    }
    let configuration = current
        .service
        .ok_or("Driver service is missing")?
        .configuration;
    if configuration.service_type != SERVICE_FILE_SYSTEM_DRIVER
        || configuration.start_type != SERVICE_DEMAND_START
        || configuration.error_control != SERVICE_ERROR_NORMAL
        || configuration.load_order_group != "FSFilter Anti-Virus"
        || configuration.dependencies != ["FltMgr"]
    {
        return Err("Driver service configuration differs from approval".into());
    }
    let image = registry::image_path(&configuration.binary_path)?;
    let _image_parent =
        PinnedDirectory::open(image.parent().ok_or("Driver image parent missing")?)?;
    let image = trust::pin(&image, &expected.sys)?;
    if identity(&image)? != ids[0] {
        return Err("Driver service image is not the approved store object".into());
    }
    let (instance, altitude, instance_flags) = registry::instance(expected)?;
    Ok(Registration {
        published_inf,
        store_inf,
        published_identity: identity(&published)?,
        member_identities: ids
            .try_into()
            .map_err(|_| "Invalid member identity count")?,
        configuration,
        instance,
        altitude,
        instance_flags,
    })
}

fn require_registration(expected: &Descriptor, owned: &Registration) -> Result<()> {
    if observe_registration(expected)? != *owned {
        return Err("Owned driver registration changed".into());
    }
    Ok(())
}

struct RegistrationPins {
    _directory: PinnedDirectory,
    _files: Vec<File>,
}
fn registration_pins(expected: &Descriptor, owned: &Registration) -> Result<RegistrationPins> {
    let root = owned
        .store_inf
        .parent()
        .ok_or("Driver Store path has no parent")?;
    let directory = PinnedDirectory::open(root)?;
    let mut files = Vec::new();
    for ((name, member), id) in NAMES
        .iter()
        .zip(expected.members())
        .zip(&owned.member_identities)
    {
        let file = trust::pin(&root.join(name), member)?;
        if identity(&file)? != *id {
            return Err("Driver Store object changed before effect".into());
        }
        files.push(file);
    }
    Ok(RegistrationPins {
        _directory: directory,
        _files: files,
    })
}

/// Caller must durably claim this non-idempotent effect before invocation.
/// Failure may leave OS effects; it is never permission for an automatic retry.
pub fn install(source: &Path, expected: &Descriptor) -> Result<NativeEffect> {
    crate::windows_state::require_local_system()?;
    registry::require_profile(expected)?;
    let before = inspect()?;
    if before.service.is_some() || before.filter_present || !before.candidate_infs.is_empty() {
        return Err("Existing driver state is not a fresh installation".into());
    }
    let _source_parent = PinnedDirectory::open(source)?;
    trust::verify(source, expected)?;
    let pins = NAMES
        .iter()
        .zip(expected.members())
        .map(|(n, m)| trust::pin(&source.join(n), m))
        .collect::<Result<Vec<_>>>()?;
    use std::io::Read;
    let mut inf_bytes = Vec::new();
    (&pins[1]).take(16385).read_to_end(&mut inf_bytes)?;
    if inf_bytes != expected.inf_bytes() {
        return Err("Native installation requires the exact finite INF".into());
    }
    let inf = wide(source.join(NAMES[1]))?;
    let prior = unsafe { SetupSetNonInteractiveMode(1) };
    let mut need_reboot = 0;
    let succeeded = unsafe { DiInstallDriverW(null_mut(), inf.as_ptr(), 0, &mut need_reboot) } != 0;
    let code = if succeeded {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(1) as u32
    };
    unsafe {
        SetupSetNonInteractiveMode(prior);
    }
    drop(pins);
    Ok(NativeEffect {
        succeeded,
        need_reboot: need_reboot != 0,
        code,
    })
}

pub fn load(expected: &Descriptor, owned: &Registration) -> Result<NativeEffect> {
    crate::windows_state::require_local_system()?;
    registry::require_profile(expected)?;
    let _pins = registration_pins(expected, owned)?;
    require_registration(expected, owned)?;
    if filter_present()? {
        return Err("A driver is already loaded; refusing ownership adoption".into());
    }
    let _privilege = registry::load_privilege()?;
    let code = unsafe { FilterLoad(wide(DRIVER)?.as_ptr()) };
    Ok(NativeEffect {
        succeeded: code == 0,
        need_reboot: false,
        code: code as u32,
    })
}

pub fn observe_load() -> Result<LoadObserved> {
    crate::windows_state::require_local_system()?;
    if !filter_present()? {
        return Err("Driver is not currently registered with Filter Manager".into());
    }
    let port = Port::connect()?;
    let status = port.status()?;
    let result = LoadObserved {
        version: status.version,
        instance: status.instance,
        armed: status.armed,
        connected: status.connected,
        pending: status.pending,
        policy_sha256: status.policy_sha256,
    };
    result.validate()?;
    Ok(result)
}

pub fn unload(
    expected: &Descriptor,
    owned: &Registration,
    load: &LoadObserved,
) -> Result<NativeEffect> {
    crate::windows_state::require_local_system()?;
    let _pins = registration_pins(expected, owned)?;
    require_registration(expected, owned)?;
    if observe_load()?.instance != load.instance {
        return Err("Driver load instance differs from ownership receipt".into());
    }
    let _privilege = registry::load_privilege()?;
    // Normal FilterUnload invokes the actual callback. No inference that zero
    // pending means teardown is possible, and no force/SCM-stop fallback.
    let code = unsafe { FilterUnload(wide(DRIVER)?.as_ptr()) };
    Ok(NativeEffect {
        succeeded: code == 0,
        need_reboot: false,
        code: code as u32,
    })
}

pub fn uninstall(expected: &Descriptor, owned: &Registration) -> Result<NativeEffect> {
    crate::windows_state::require_local_system()?;
    require_registration(expected, owned)?;
    if filter_present()? {
        return Err("Loaded driver cannot be uninstalled by this transaction".into());
    }
    // Inspection pins have closed: native uninstallation is the explicitly
    // authorized deletion boundary, not raw filesystem removal by our code.
    let inf = wide(&owned.published_inf)?;
    let prior = unsafe { SetupSetNonInteractiveMode(1) };
    let mut need_reboot = 0;
    let succeeded =
        unsafe { DiUninstallDriverW(null_mut(), inf.as_ptr(), 0, &mut need_reboot) } != 0;
    let code = if succeeded {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(1) as u32
    };
    unsafe {
        SetupSetNonInteractiveMode(prior);
    }
    Ok(NativeEffect {
        succeeded,
        need_reboot: need_reboot != 0,
        code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn system_service_status_is_read_without_a_success_bytes_needed_assumption() {
        // Read-only OS API control. No driver, service or registry mutation.
        let manager = scm(SC_MANAGER_CONNECT).expect("SCM read-only access");
        let service = open_service(
            &manager,
            "EventLog",
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
        .expect("System event-log service query")
        .expect("System event-log service exists");
        let observation =
            service_observation(&service).expect("Fixed native service status output");
        assert!(matches!(
            observation.state,
            SERVICE_STOPPED
                | SERVICE_START_PENDING
                | SERVICE_STOP_PENDING
                | SERVICE_RUNNING
                | SERVICE_CONTINUE_PENDING
                | SERVICE_PAUSE_PENDING
                | SERVICE_PAUSED
        ));
        assert_ne!(observation.configuration.service_type, 0);
    }
}
