use endpoint_sec::sys;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, ffi::CString};

const MAX_ENTRIES: usize = 1024;
const MAX_EVENTS: usize = 512;
const MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
enum Tuple {
    Path { ty: u32, path: Vec<u8>, event: u32 },
    Process { token: [u32; 8], event: u32 },
}
impl Tuple {
    fn event(&self) -> u32 {
        match self {
            Self::Path { event, .. } | Self::Process { event, .. } => *event,
        }
    }
}
fn targeted(event: u32) -> bool {
    [9, 11, 15].contains(&event)
}

pub(super) struct Inventory {
    tuples: BTreeSet<Tuple>,
    pub paths: u64,
    pub processes: u64,
}
impl Inventory {
    pub fn digest(&self) -> crate::Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&self.tuples)?)
        ))
    }
    pub fn intersections(&self) -> u64 {
        self.tuples.iter().filter(|t| targeted(t.event())).count() as u64
    }
    fn other(&self) -> BTreeSet<Tuple> {
        self.tuples
            .iter()
            .filter(|t| !targeted(t.event()))
            .cloned()
            .collect()
    }
}
struct Paths(*mut sys::es_muted_paths_t);
impl Drop for Paths {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::es_release_muted_paths(self.0) };
        }
    }
}
struct Processes(*mut sys::es_muted_processes_t);
impl Drop for Processes {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::es_release_muted_processes(self.0) };
        }
    }
}

pub(super) fn inspect(client: *mut sys::es_client_t) -> crate::Result<Inventory> {
    let mut result = Inventory {
        tuples: BTreeSet::new(),
        paths: 0,
        processes: 0,
    };
    let mut bytes = 0_usize;
    let mut paths = Paths(std::ptr::null_mut());
    let code = unsafe { sys::es_muted_paths_events(client, &mut paths.0) };
    if code != sys::es_return_t::ES_RETURN_SUCCESS {
        return Err("Process source path inventory failed".into());
    }
    if !paths.0.is_null() {
        // The API owns initialized pointer/count pairs; application copies are
        // bounded before allocation. Native API allocation is outside our queue.
        let paths_ref = unsafe { &*paths.0 };
        if paths_ref.count > MAX_ENTRIES || (paths_ref.count != 0 && paths_ref.paths.is_null()) {
            return Err("Process source path inventory exceeds bounds".into());
        }
        result.paths = paths_ref.count as u64;
        for path in unsafe { paths_ref.paths() } {
            if path.type_.0 > 3
                || path.path.length > 16 * 1024
                || path.event_count > MAX_EVENTS
                || (path.path.length != 0 && path.path.data.is_null())
                || (path.event_count != 0 && path.events.is_null())
            {
                return Err("Invalid process source mute path".into());
            }
            bytes = bytes
                .checked_add(path.path.length.saturating_mul(path.event_count))
                .and_then(|n| n.checked_add(path.event_count * 8))
                .ok_or("Mute inventory size overflow")?;
            if bytes > MAX_BYTES {
                return Err("Process source mute inventory exceeds bounds".into());
            }
            let raw = if path.path.length == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(path.path.data.cast::<u8>(), path.path.length) }
            };
            if raw.contains(&0) {
                return Err("Process source mute path contains NUL".into());
            }
            for event in unsafe { path.events() } {
                result.tuples.insert(Tuple::Path {
                    ty: path.type_.0,
                    path: raw.to_vec(),
                    event: event.0,
                });
            }
        }
    }
    let mut processes = Processes(std::ptr::null_mut());
    let code = unsafe { sys::es_muted_processes_events(client, &mut processes.0) };
    if code != sys::es_return_t::ES_RETURN_SUCCESS {
        return Err("Process source token inventory failed".into());
    }
    if !processes.0.is_null() {
        // Pinned bindings expose this SDK-owned slice without allocating.
        let items = unsafe { (&*processes.0).processes() };
        if items.len() > MAX_ENTRIES {
            return Err("Process source token inventory exceeds bounds".into());
        }
        result.processes = items.len() as u64;
        for process in items {
            if process.event_count > MAX_EVENTS
                || (process.event_count != 0 && process.events.is_null())
            {
                return Err("Invalid process source mute token".into());
            }
            bytes = bytes
                .checked_add(process.event_count * 36)
                .ok_or("Mute inventory size overflow")?;
            if bytes > MAX_BYTES {
                return Err("Process source mute inventory exceeds bounds".into());
            }
            for event in unsafe { process.events() } {
                result.tuples.insert(Tuple::Process {
                    token: process.audit_token.val,
                    event: event.0,
                });
            }
        }
    }
    Ok(result)
}

pub(super) fn prepare(client: *mut sys::es_client_t) -> crate::Result<Inventory> {
    let before = inspect(client)?;
    for tuple in &before.tuples {
        if !targeted(tuple.event()) {
            continue;
        }
        let event = sys::es_event_type_t(tuple.event());
        let code = match tuple {
            Tuple::Path { ty, path, .. } => {
                let path = CString::new(path.as_slice()).map_err(|_| "Invalid mute path")?;
                unsafe {
                    sys::es_unmute_path_events(
                        client,
                        path.as_ptr(),
                        sys::es_mute_path_type_t(*ty),
                        &event,
                        1,
                    )
                }
            }
            Tuple::Process { token, .. } => {
                let token = sys::audit_token_t { val: *token };
                unsafe { sys::es_unmute_process_events(client, &token, &event, 1) }
            }
        };
        if code != sys::es_return_t::ES_RETURN_SUCCESS {
            return Err("Scoped process event unmute failed".into());
        }
    }
    let after = inspect(client)?;
    if after.intersections() != 0 || after.other() != before.other() {
        return Err("Process source mute scope did not match its profile".into());
    }
    Ok(after)
}
