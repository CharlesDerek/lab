use super::*;
use std::{ffi::c_void, ptr::NonNull};

#[repr(C)]
#[derive(Default)]
struct Incoming {
    data: *mut u8,
    length: usize,
    generation: u64,
    token: u64,
    uid: u32,
    kind: u32,
}
#[repr(C)]
#[derive(Default)]
struct Buffer {
    data: *mut u8,
    length: usize,
    batch: *mut u8,
    batch_length: usize,
}
unsafe extern "C" {
    fn ax_upgrade_start(data: *const u8, len: usize) -> *mut c_void;
    fn ax_upgrade_poll(owner: *mut c_void, wait_ms: u32, out: *mut Incoming) -> i32;
    fn ax_upgrade_reply(owner: *mut c_void, token: u64, data: *const u8, len: usize) -> i32;
    fn ax_upgrade_incoming_free(out: *mut Incoming);
    fn ax_upgrade_close(owner: *mut c_void);
    fn ax_upgrade_inspect(data: *const u8, len: usize, out: *mut Buffer) -> i32;
    fn ax_upgrade_inspect_property(data: *const u8, len: usize) -> i32;
    fn ax_network_reply_free(out: *mut Buffer);
}
impl Drop for Incoming {
    fn drop(&mut self) {
        unsafe { ax_upgrade_incoming_free(self) }
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe { ax_network_reply_free(self) }
    }
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let data = serde_json::to_vec(value).map_err(|_| "Network upgrade serialization failed")?;
    if data.is_empty() || data.len() > MAX_MESSAGE_BYTES {
        return Err("Network upgrade message exceeds its bound".into());
    }
    Ok(data)
}
pub(super) struct Server {
    handle: Option<NonNull<c_void>>,
    uid: u32,
    last_token: u64,
    pending: Option<u64>,
}
// Calls are serial. Native reply closures own only native objects, no Rust context.
unsafe impl Send for Server {}
impl Server {
    pub(super) fn start(config: &UpgradeServerConfig) -> Result<Self> {
        let data = encode(config)?;
        let handle = NonNull::new(unsafe { ax_upgrade_start(data.as_ptr(), data.len()) })
            .ok_or("Network upgrade listener refused startup")?;
        Ok(Self {
            handle: Some(handle),
            uid: config.operator_uid,
            last_token: 0,
            pending: None,
        })
    }
    fn handle(&self) -> Result<*mut c_void> {
        self.handle
            .map(NonNull::as_ptr)
            .ok_or_else(|| "Network upgrade listener is closed".into())
    }
    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            unsafe { ax_upgrade_close(handle.as_ptr()) }
        }
        self.pending = None;
    }
    pub(super) fn poll(&mut self, timeout: Duration) -> Result<Option<UpgradeIncoming>> {
        let result = self.poll_inner(timeout);
        if result.is_err() {
            self.stop();
        }
        result
    }
    fn poll_inner(&mut self, timeout: Duration) -> Result<Option<UpgradeIncoming>> {
        if timeout > Duration::from_secs(5) {
            return Err("Network upgrade poll exceeds its bound".into());
        }
        let mut input = Incoming::default();
        if unsafe { ax_upgrade_poll(self.handle()?, timeout.as_millis() as u32, &mut input) } != 0 {
            return Err("Network upgrade listener failed".into());
        }
        if input.kind == 0 {
            return Ok(None);
        }
        if input.generation != 1 || input.uid != self.uid || input.length > MAX_MESSAGE_BYTES {
            return Err("Network upgrade peer binding changed".into());
        }
        let event = match input.kind {
            1 => {
                if self.pending.is_some()
                    || input.token <= self.last_token
                    || input.data.is_null()
                    || input.length == 0
                {
                    return Err("Network upgrade request ownership changed".into());
                }
                // Parse original NSData directly; native JSON must not erase duplicates.
                let data = unsafe { std::slice::from_raw_parts(input.data, input.length) };
                let request: UpgradeRequest =
                    serde_json::from_slice(data).map_err(|_| "Invalid network upgrade request")?;
                request.validate()?;
                self.last_token = input.token;
                self.pending = Some(input.token);
                UpgradeEvent::Request { request }
            }
            2 if input.token == 0 && input.length == 0 => {
                self.pending = None;
                UpgradeEvent::Disconnected
            }
            _ => return Err("Invalid network upgrade listener event".into()),
        };
        Ok(Some(UpgradeIncoming {
            connection_generation: input.generation,
            request_token: input.token,
            peer_euid: input.uid,
            event,
        }))
    }
    pub(super) fn reply(&mut self, token: u64, reply: &UpgradeReply) -> Result<()> {
        let data = encode(reply)?;
        if self.pending != Some(token) {
            self.stop();
            return Err("Network upgrade reply ownership changed".into());
        }
        self.pending = None;
        if unsafe { ax_upgrade_reply(self.handle()?, token, data.as_ptr(), data.len()) } != 0 {
            self.stop();
            return Err("Network upgrade reply was not delivered".into());
        }
        Ok(())
    }
    pub(super) fn close(mut self) -> Result<()> {
        self.stop();
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}
pub(super) fn inspect_bundle(
    path: &Path,
    identity: &BundleIdentity,
) -> Result<UpgradeBundleInspection> {
    let path = path.to_str().ok_or("Invalid network upgrade bundle path")?;
    bounded_path(path)?;
    let data = encode(&serde_json::json!({"path":path,"identity":identity}))?;
    let mut out = Buffer::default();
    if unsafe { ax_upgrade_inspect(data.as_ptr(), data.len(), &mut out) } != 0
        || out.length == 0
        || out.length > MAX_MESSAGE_BYTES
        || out.data.is_null()
        || out.batch_length != 0
    {
        return Err("Network upgrade bundle inspection failed".into());
    }
    let inspection: UpgradeBundleInspection =
        serde_json::from_slice(unsafe { std::slice::from_raw_parts(out.data, out.length) })
            .map_err(|_| "Invalid network upgrade bundle inspection")?;
    inspection.validate()?;
    crate::assessment::verify(Path::new(path))?;
    Ok(inspection)
}
pub(super) fn inspect_property(
    property: &ExtensionProperty,
    identity: &BundleIdentity,
    pin: &UpgradeCodePin,
) -> Result<()> {
    let data = encode(&serde_json::json!({"property":property,"identity":identity,"pin":pin}))?;
    if unsafe { ax_upgrade_inspect_property(data.as_ptr(), data.len()) } != 0 {
        return Err("Installed network extension differs from approved code".into());
    }
    Ok(())
}
