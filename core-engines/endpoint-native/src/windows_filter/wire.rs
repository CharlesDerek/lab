//! Fixed-width Windows minifilter ABI; see windows-filter/wire.h. Every byte in
//! these repr(C) layouts is an initialized integer field (no implicit padding).
use crate::{Result, MAX_FILE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const VERSION: u32 = 2;
pub const ROOTS: usize = 16;
pub const PATH_CHARS: usize = 1024;
pub const SCAN: u32 = 1;
pub const APPLIED: u32 = 2;
pub const CLEAN: u32 = 1;
pub const MALWARE: u32 = 2;
pub const ERROR: u32 = 3;
pub const CONFIGURE: u32 = 1;
pub const MAP_SCAN: u32 = 2;
pub const GET_STATUS: u32 = 3;
pub const DISARM: u32 = 4;
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Header {
    pub version: u32,
    pub operation: u32,
    pub bytes: u32,
    pub reserved: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Root {
    pub characters: u32,
    pub path: [u16; PATH_CHARS],
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Configuration {
    pub header: Header,
    pub root_count: u32,
    pub timeout_ms: u32,
    pub policy_sha256: [u8; 32],
    pub roots: [Root; ROOTS],
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Notification {
    pub version: u32,
    pub operation: u32,
    pub request_id: u64,
    pub bytes: u64,
    pub volume: u64,
    pub actor_pid: u64,
    pub actor_created: u64,
    pub policy_sha256: [u8; 32],
    pub file_id: [u8; 16],
    pub path_characters: u32,
    pub reserved: u32,
    pub path: [u16; PATH_CHARS],
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Reply {
    pub version: u32,
    pub verdict: u32,
    pub request_id: u64,
    pub sha256: [u8; 32],
    pub detection: [u8; 256],
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct MapRequest {
    pub header: Header,
    pub request_id: u64,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Mapping {
    pub version: u32,
    pub reserved: u32,
    pub request_id: u64,
    pub section_handle: u64,
    pub bytes: u64,
}
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[repr(C)]
pub struct Status {
    pub version: u32,
    pub armed: u32,
    pub connected: u32,
    pub pending: u32,
    pub allowed: u64,
    pub malware: u64,
    pub errors: u64,
    pub evidence_dropped: u64,
    pub instance: [u8; 16],
    pub policy_sha256: [u8; 32],
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Applied {
    pub file: Notification,
    pub decision: Reply,
    pub status: i32,
    pub reserved: u32,
}
const _: () = {
    assert!(std::mem::size_of::<Header>() == 16);
    assert!(std::mem::size_of::<Root>() == 2052);
    assert!(std::mem::size_of::<Configuration>() == 32888);
    assert!(std::mem::size_of::<Notification>() == 2152);
    assert!(std::mem::size_of::<Reply>() == 304);
    assert!(std::mem::size_of::<MapRequest>() == 24);
    assert!(std::mem::size_of::<Mapping>() == 32);
    assert!(std::mem::size_of::<Status>() == 96);
    assert!(std::mem::size_of::<Applied>() == 2464);
};
impl Header {
    pub fn new<T>(operation: u32) -> Self {
        Self {
            version: VERSION,
            operation,
            bytes: std::mem::size_of::<T>() as u32,
            reserved: 0,
        }
    }
}
impl Configuration {
    /// Build an immutable kernel policy from normalized NT directory names.
    /// The caller must resolve DOS paths using handles before this boundary.
    pub fn new(roots: &[String], timeout_ms: u32) -> Result<Self> {
        if !(1..=ROOTS).contains(&roots.len()) || !(100..=5000).contains(&timeout_ms) {
            return Err("Windows filter requires 1–16 roots and a 100–5000 ms deadline".into());
        }
        let mut config = Self {
            header: Header::new::<Self>(CONFIGURE),
            root_count: roots.len() as u32,
            timeout_ms,
            policy_sha256: [0; 32],
            roots: [Root {
                characters: 0,
                path: [0; PATH_CHARS],
            }; ROOTS],
        };
        for (slot, root) in config.roots.iter_mut().zip(roots) {
            let wide: Vec<_> = root.encode_utf16().collect();
            if wide.len() >= PATH_CHARS {
                return Err("Windows filter root exceeds its path budget".into());
            }
            slot.characters = wide.len() as u32;
            slot.path[..wide.len()].copy_from_slice(&wide);
            slot.validate()?;
        }
        config.policy_sha256 = config.digest();
        config.validate()?;
        Ok(config)
    }
    fn digest(&self) -> [u8; 32] {
        // Explicit integer encoding avoids host layout/endianness in the policy
        // identity. Include ordering and lengths, not ambiguous joined strings.
        let mut hash = Sha256::new();
        hash.update(b"athernex-windows-filter-policy-v1\0");
        hash.update(self.timeout_ms.to_le_bytes());
        hash.update(self.root_count.to_le_bytes());
        for root in &self.roots {
            hash.update(root.characters.to_le_bytes());
            let mut encoded = [0u8; PATH_CHARS * 2];
            for (output, character) in encoded.chunks_exact_mut(2).zip(root.path) {
                output.copy_from_slice(&character.to_le_bytes());
            }
            hash.update(encoded);
        }
        hash.finalize().into()
    }
    pub fn validate(&self) -> Result<()> {
        if self.header.version != VERSION
            || self.header.operation != CONFIGURE
            || self.header.bytes as usize != std::mem::size_of::<Self>()
            || self.header.reserved != 0
            || !(1..=ROOTS as u32).contains(&self.root_count)
            || !(100..=5000).contains(&self.timeout_ms)
        {
            return Err("Invalid Windows filter configuration".into());
        }
        for root in &self.roots[..self.root_count as usize] {
            root.validate()?;
        }
        if self.roots[self.root_count as usize..]
            .iter()
            .any(|root| root.characters != 0 || root.path.iter().any(|c| *c != 0))
            || self.policy_sha256 != self.digest()
        {
            return Err("Windows filter policy does not match its content digest".into());
        }
        Ok(())
    }
}
impl Root {
    fn validate(&self) -> Result<()> {
        let length = self.characters as usize;
        if length == 0 || length >= PATH_CHARS || self.path[length..].iter().any(|c| *c != 0) {
            return Err("Invalid Windows filter root length".into());
        }
        let root = String::from_utf16(&self.path[..length])?;
        let parts: Vec<_> = root.split('\\').collect();
        if parts.len() < 3
            || !parts[0].is_empty()
            || !parts[1].eq_ignore_ascii_case("Device")
            || parts[2..]
                .iter()
                .any(|part| part.is_empty() || [".", ".."].contains(part))
            || parts.len() > 130
            || root
                .chars()
                .any(|c| c.is_control() || "/:*?\"<>|".contains(c))
        {
            return Err("Windows filter roots require normalized NT directory names".into());
        }
        Ok(())
    }
}
impl Notification {
    pub fn validate(&self) -> Result<String> {
        let length = self.path_characters as usize;
        if self.version != VERSION
            || ![SCAN, APPLIED].contains(&self.operation)
            || self.request_id == 0
            || self.reserved != 0
            || self.bytes > MAX_FILE
            || length == 0
            || length >= PATH_CHARS
            || self.path[0] != b'\\' as u16
            || self.path[length..].iter().any(|c| *c != 0)
        {
            return Err("Invalid Windows filter notification".into());
        }
        let path = String::from_utf16(&self.path[..length])?;
        if path.chars().any(char::is_control) {
            return Err("Invalid Windows filter path".into());
        }
        Ok(path)
    }
}
impl Reply {
    pub fn error(id: u64) -> Self {
        Self {
            version: VERSION,
            verdict: ERROR,
            request_id: id,
            sha256: [0; 32],
            detection: [0; 256],
        }
    }
    pub fn verdict(id: u64, verdict: &crate::Verdict) -> Result<Self> {
        let mut reply = Self::error(id);
        if verdict.sha256.len() != 64
            || !verdict
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("Invalid scanner content digest".into());
        }
        for (slot, pair) in reply
            .sha256
            .iter_mut()
            .zip(verdict.sha256.as_bytes().chunks_exact(2))
        {
            *slot = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        }
        reply.verdict = CLEAN;
        if let Some(detection) = &verdict.detection {
            if detection.is_empty()
                || detection.len() > 255
                || !detection.bytes().all(|c| (0x20..=0x7e).contains(&c))
            {
                return Err("Invalid scanner detection label".into());
            }
            reply.verdict = MALWARE;
            reply.detection[..detection.len()].copy_from_slice(detection.as_bytes());
        }
        Ok(reply)
    }
    pub fn detection(&self, id: u64) -> Result<Option<String>> {
        if self.version != VERSION
            || self.request_id != id
            || ![CLEAN, MALWARE, ERROR].contains(&self.verdict)
            || (self.verdict != ERROR && self.sha256 == [0; 32])
        {
            return Err("Invalid Windows filter decision".into());
        }
        let length = self
            .detection
            .iter()
            .position(|b| *b == 0)
            .ok_or("Unterminated Windows filter detection")?;
        if self.detection[length..].iter().any(|b| *b != 0)
            || !self.detection[..length]
                .iter()
                .all(|c| (0x20..=0x7e).contains(c))
            || (self.verdict == CLEAN && length != 0)
            || (self.verdict == MALWARE && length == 0)
        {
            return Err("Invalid Windows filter detection".into());
        }
        Ok(if self.verdict == MALWARE {
            Some(String::from_utf8(self.detection[..length].to_vec())?)
        } else {
            None
        })
    }
}
impl Mapping {
    pub fn validate(&self, source: &Notification) -> Result<()> {
        if self.version != VERSION
            || self.reserved != 0
            || self.request_id != source.request_id
            || self.bytes != source.bytes
            || (self.bytes == 0) != (self.section_handle == 0)
            || self.section_handle == u64::MAX
        {
            return Err("Windows filter mapping does not match its request".into());
        }
        Ok(())
    }
}

impl Status {
    pub fn validate(&self) -> Result<()> {
        if self.version != VERSION
            || self.armed > 1
            || self.connected > 1
            || self.pending > 64
            || self.instance == [0; 16]
            || (self.armed == 1 && self.policy_sha256 == [0; 32])
        {
            return Err("Invalid Windows filter status or driver instance".into());
        }
        Ok(())
    }
}
