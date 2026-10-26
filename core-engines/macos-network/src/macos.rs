use crate::{client::Backend, transport::Reply, BundleIdentity, BundleInspection, Config, Result};
use std::{ffi::c_void, path::Path, ptr::NonNull};

#[repr(C)]
#[derive(Default)]
struct NativeReply {
    control: *mut u8,
    control_len: usize,
    batch: *mut u8,
    batch_len: usize,
}
unsafe extern "C" {
    fn ax_network_connect(data: *const u8, len: usize, out: *mut NativeReply) -> *mut c_void;
    fn ax_network_exchange(
        handle: *mut c_void,
        op: u32,
        epoch: u64,
        request: u64,
        batch: u64,
        digest: *const u8,
        digest_len: usize,
        out: *mut NativeReply,
    ) -> i32;
    fn ax_network_invalidate(handle: *mut c_void);
    fn ax_network_release(handle: *mut c_void);
    fn ax_network_reply_free(out: *mut NativeReply);
    fn ax_network_inspect(data: *const u8, len: usize, out: *mut NativeReply) -> i32;
}
impl NativeReply {
    fn copy(&self) -> Result<Reply> {
        use athernex_endpoint_protocol::macos_network_events::{
            MAX_BATCH_BYTES, MAX_CONTROL_BYTES,
        };
        if self.control_len > MAX_CONTROL_BYTES
            || self
                .control_len
                .checked_add(self.batch_len)
                .is_none_or(|n| n > MAX_BATCH_BYTES)
            || (self.control_len != 0 && self.control.is_null())
            || (self.batch_len != 0 && self.batch.is_null())
        {
            return Err("Invalid network bridge buffer".into());
        }
        // Native buffers are separately allocated, bounded, and retained by this
        // result until Drop. Empty buffers need not have a dereferenceable pointer.
        let control = if self.control_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(self.control, self.control_len) }.to_vec()
        };
        let batch = if self.batch_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(self.batch, self.batch_len) }.to_vec()
        };
        Ok(Reply { control, batch })
    }
}
impl Drop for NativeReply {
    fn drop(&mut self) {
        unsafe { ax_network_reply_free(self) }
    }
}
pub(crate) struct Bridge {
    handle: NonNull<c_void>,
}
// NSXPCConnection is operated serially through &mut Backend. Native completion
// handlers own Objective-C attempt state and never borrow a Rust stack or object.
unsafe impl Send for Bridge {}
impl Bridge {
    pub(crate) fn connect(config: &Config, nonce: &str) -> Result<(Self, Reply)> {
        let bytes = serde_json::to_vec(&serde_json::json!({"config":config,"nonce":nonce}))
            .map_err(|_| "Network connection serialization failed")?;
        let mut reply = NativeReply::default();
        let handle =
            NonNull::new(unsafe { ax_network_connect(bytes.as_ptr(), bytes.len(), &mut reply) })
                .ok_or("Network source connection failed")?;
        let bridge = Self { handle };
        let bytes = reply.copy()?;
        Ok((bridge, bytes))
    }
}
impl Backend for Bridge {
    fn exchange(
        &mut self,
        operation: u32,
        epoch: u64,
        request: u64,
        batch: u64,
        digest: &str,
    ) -> Result<Reply> {
        let mut reply = NativeReply::default();
        let rc = unsafe {
            ax_network_exchange(
                self.handle.as_ptr(),
                operation,
                epoch,
                request,
                batch,
                digest.as_ptr(),
                digest.len(),
                &mut reply,
            )
        };
        if rc != 0 {
            return Err("Network source exchange failed".into());
        }
        reply.copy()
    }
    fn invalidate(&mut self) {
        unsafe { ax_network_invalidate(self.handle.as_ptr()) }
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        unsafe { ax_network_release(self.handle.as_ptr()) }
    }
}
pub(crate) fn inspect_bundle(path: &Path, expected: &BundleIdentity) -> Result<BundleInspection> {
    let path = path
        .to_str()
        .filter(|p| p.starts_with('/') && !p.contains('\0') && p.len() <= 4096)
        .ok_or("Invalid network bundle path")?;
    let data = serde_json::to_vec(&serde_json::json!({"path":path,"identity":expected}))
        .map_err(|_| "Network inspection serialization failed")?;
    let mut reply = NativeReply::default();
    if unsafe { ax_network_inspect(data.as_ptr(), data.len(), &mut reply) } != 0 {
        return Err("Network bundle signature or identity verification failed".into());
    }
    let reply = reply.copy()?;
    let inspected: BundleInspection =
        serde_json::from_slice(&reply.control).map_err(|_| "Invalid network bundle inspection")?;
    if !reply.batch.is_empty() || &inspected.identity != expected {
        return Err("Network bundle inspection identity changed".into());
    }
    let c = Config {
        team_id: expected.team_id.clone(),
        agent_identifier: expected.agent_identifier.clone(),
        provider_identifier: expected.provider_identifier.clone(),
        mach_service_name: expected.mach_service_name.clone(),
        app_group: expected.app_group.clone(),
        provider_cdhashes: inspected.provider_cdhashes.clone(),
        source_policy_sha256:
            athernex_endpoint_protocol::macos_network_events::source_policy_sha256(),
    };
    c.validate()?;
    Ok(inspected)
}
