//! Finite, approved driver-package preparation format. Nothing here installs or
//! loads a driver, proves an assigned altitude, or attests its live ABI.
use serde::{Deserialize, Serialize};
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const NAMES: [&str; 3] = [
    "athernex-filter.sys",
    "athernex-filter.inf",
    "athernex-filter.cat",
];
pub const MAGIC: &[u8; 8] = b"AXFPKG1\0";
pub const PROFILE: &str = "win11-24h2-amd64-antivirus-v1";
pub const LEGACY_PROFILE: &str = "win10-2004-through-win11-23h2-amd64-antivirus-v1";
pub const TRUST: &str = "whql-driver-policy-cache-only-v1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub schema: u32,
    pub sha256: String,
    pub bytes: u64,
    pub profile: String,
    pub trust_policy: String,
    /// Approved build provenance; offline inspection cannot prove the live ABI.
    pub source_revision: String,
    pub expected_abi: u32,
    pub driver_version: String,
    pub driver_date: String,
    /// Supplied release approval. Syntax/matching do not prove assignment.
    pub altitude: String,
    pub sys: Member,
    pub inf: Member,
    pub cat: Member,
}
fn decimal(s: &str, max: u32) -> bool {
    !s.is_empty()
        && (s.len() == 1 || !s.starts_with('0'))
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u32>().is_ok_and(|n| n <= max)
}
impl Descriptor {
    pub fn members(&self) -> [&Member; 3] {
        [&self.sys, &self.inf, &self.cat]
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        let total = self
            .members()
            .iter()
            .try_fold(32u64, |n, m| n.checked_add(m.bytes));
        let version: Vec<_> = self.driver_version.split('.').collect();
        let altitude: Vec<_> = self.altitude.split('.').collect();
        let date = self.driver_date.as_bytes();
        let valid_date = if date.len() == 10
            && date[2] == b'/'
            && date[5] == b'/'
            && date
                .iter()
                .enumerate()
                .all(|(i, b)| i == 2 || i == 5 || b.is_ascii_digit())
        {
            let month = self.driver_date[0..2].parse::<u32>().unwrap_or(0);
            let day = self.driver_date[3..5].parse::<u32>().unwrap_or(0);
            let year = self.driver_date[6..10].parse::<u32>().unwrap_or(0);
            let days = match month {
                4 | 6 | 9 | 11 => 30,
                2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
                2 => 28,
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                _ => 0,
            };
            (2000..=9999).contains(&year) && day > 0 && day <= days
        } else {
            false
        };
        if self.schema != 1
            || !crate::hex_id(&self.sha256)
            || ![PROFILE, LEGACY_PROFILE].contains(&self.profile.as_str())
            || self.trust_policy != TRUST
            || self.expected_abi != 2
            || self.source_revision.len() != 40
            || !self
                .source_revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || version.len() != 4
            || version.iter().any(|s| !decimal(s, 65535))
            || !valid_date
            || altitude.is_empty()
            || altitude.len() > 2
            || !decimal(altitude[0], 329999)
            || altitude[0].parse::<u32>().map_or(true, |n| n < 320000)
            || altitude.get(1).is_some_and(|s| {
                s.is_empty() || s.len() > 9 || !s.bytes().all(|b| b.is_ascii_digit())
            })
            || altitude[0] == "0"
            || self.altitude.len() > 20
            || self
                .members()
                .iter()
                .any(|m| m.bytes == 0 || !crate::hex_id(&m.sha256))
            || self.sys.bytes < 128
            || self.inf.bytes > 16384
            || self.cat.bytes > 16 * 1024 * 1024
            || total != Some(self.bytes)
            || self.bytes > MAX_BYTES
        {
            return Err("Invalid Windows filter package descriptor");
        }
        Ok(())
    }
    /// Exact finite INF grammar, not a permissive general INF parser. The 24H2
    /// profile is explicit; no earlier-OS registry layout is guessed.
    pub fn inf_bytes(&self) -> Vec<u8> {
        format!(concat!(
            "[Version]\nSignature=\"$WINDOWS NT$\"\nClass=AntiVirus\nClassGuid={{b1d1a169-c54f-4379-81db-bee7d88d7454}}\nProvider=\"Athernex\"\nDriverVer={},{}\nCatalogFile=athernex-filter.cat\nPnpLockdown=1\n\n",
            "[DestinationDirs]\nDriverFiles=13\n\n[DefaultInstall.NTamd64]\nCopyFiles=DriverFiles\n\n[DefaultInstall.NTamd64.Services]\nAddService=AthernexFilter,,FilterService\n\n",
            "[FilterService]\nDisplayName=\"Athernex Filter\"\nServiceBinary=%13%\\athernex-filter.sys\nServiceType=2\nStartType=3\nErrorControl=1\nLoadOrderGroup=\"FSFilter Anti-Virus\"\nDependencies=FltMgr\nAddReg=FilterInstances\n\n",
            "[FilterInstances]\nHKR,\"Parameters\\Instances\",\"DefaultInstance\",0x00000000,\"AthernexFilter\"\nHKR,\"Parameters\\Instances\\AthernexFilter\",\"Altitude\",0x00000000,\"{}\"\nHKR,\"Parameters\\Instances\\AthernexFilter\",\"Flags\",0x00010001,0\n\n",
            "[DriverFiles]\nathernex-filter.sys\n\n[SourceDisksFiles]\nathernex-filter.sys=1\n\n[SourceDisksNames]\n1=\"Athernex Filter\",,,\n"
        ),self.driver_date,self.driver_version,self.altitude).replace("Parameters\\Instances", if self.profile == LEGACY_PROFILE { "Instances" } else { "Parameters\\Instances" }).replace('\n',"\r\n").into_bytes()
    }
    pub fn unpack<'a>(&self, bytes: &'a [u8]) -> Result<[&'a [u8]; 3], &'static str> {
        self.validate()?;
        if bytes.len() as u64 != self.bytes
            || bytes.get(..8) != Some(MAGIC)
            || crate::hash(bytes) != self.sha256
        {
            return Err("Windows filter package bytes differ from approval");
        }
        let mut offset = 32usize;
        let mut output = [&[][..]; 3];
        for (i, member) in self.members().iter().enumerate() {
            let size = u64::from_le_bytes(
                bytes[8 + i * 8..16 + i * 8]
                    .try_into()
                    .map_err(|_| "Invalid package length")?,
            );
            if size != member.bytes {
                return Err("Windows filter member length differs");
            }
            let end = offset
                .checked_add(usize::try_from(size).map_err(|_| "Package length overflow")?)
                .ok_or("Package length overflow")?;
            let part = bytes
                .get(offset..end)
                .ok_or("Truncated Windows filter member")?;
            if crate::hash(part) != member.sha256 {
                return Err("Windows filter member digest differs");
            }
            output[i] = part;
            offset = end;
        }
        if offset != bytes.len() || output[1] != self.inf_bytes() {
            return Err("Unsupported Windows filter INF policy");
        }
        let sys = output[0];
        let pe = sys
            .get(60..64)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()) as usize)
            .ok_or("Invalid driver image")?;
        if sys.get(..2) != Some(b"MZ")
            || sys.get(pe..pe.saturating_add(6)) != Some(&b"PE\0\0\x64\x86"[..])
            || sys.get(pe.saturating_add(24)..pe.saturating_add(26)) != Some(&[0x0b, 0x02])
            || sys.get(pe.saturating_add(92)..pe.saturating_add(94)) != Some(&[1, 0])
        {
            return Err("Windows filter must be an AMD64 PE32+ native image");
        }
        Ok(output)
    }
}
#[cfg(test)]
mod tests;
