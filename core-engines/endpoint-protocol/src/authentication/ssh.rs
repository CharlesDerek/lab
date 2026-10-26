//! OpenSSH result parsing shared by endpoint and local-journal ingestion.
//! The caller must independently validate the journal producer's provenance.
use super::{bounded, AuthenticationOutcome};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshReport<'a> {
    pub outcome: AuthenticationOutcome,
    pub claimed_user: &'a str,
    pub invalid_user: bool,
    pub mechanism: &'a str,
    pub source_ip: IpAddr,
    pub source_port: u16,
}

/// Parse a complete reported authentication result, never certificate eligibility,
/// a partial multifactor result, or session creation. Certificate identifiers
/// remain opaque original text; they cannot supply an account, address or UID.
pub fn ssh_report(message: &str) -> Result<Option<SshReport<'_>>, &'static str> {
    if !bounded(message, 4096) {
        return Err("Invalid OpenSSH authentication message budget");
    }
    if !(message.starts_with("Accepted ") || message.starts_with("Failed ")) {
        return Ok(None);
    }
    let words = message.split(' ').collect::<Vec<_>>();
    // Eligibility/lookup and operational messages are not method results.
    if words.get(2) != Some(&"for") {
        return Ok(None);
    }
    if words.len() < 9 || words[1].is_empty() || !bounded(words[1], 64) {
        return Err("Unsupported OpenSSH authentication report");
    }
    let outcome = if words[0] == "Accepted" {
        AuthenticationOutcome::Allowed
    } else {
        AuthenticationOutcome::Denied
    };
    let invalid_user = words.get(3..5) == Some(&["invalid", "user"]);
    let offset = if invalid_user { 5 } else { 3 };
    if words.len() < offset + 6
        || words[offset].is_empty()
        || !bounded(words[offset], 256)
        || words[offset + 1] != "from"
        || words[offset + 3] != "port"
        || !["ssh2", "ssh2:"].contains(&words[offset + 5])
        || (invalid_user && outcome == AuthenticationOutcome::Allowed)
    {
        return Err("Malformed OpenSSH authentication report");
    }
    let mut suffix = &words[offset + 6..];
    if suffix.last() == Some(&"[preauth]") {
        suffix = &suffix[..suffix.len() - 1];
    }
    let supported_suffix = if words[offset + 5] == "ssh2" {
        suffix.is_empty()
    } else if suffix.first().is_some_and(|kind| kind.ends_with("-CERT")) {
        words[1] == "publickey" && certificate_suffix(suffix)
    } else {
        // Preserve the previously supported non-certificate wire grammar.
        suffix.len() == 2
            && !suffix[0].is_empty()
            && suffix[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && (suffix[1].starts_with("SHA256:") || suffix[1].starts_with("MD5:"))
            && suffix[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=:".contains(&b))
    };
    if !supported_suffix {
        return Err("Ambiguous or unsupported OpenSSH authentication suffix");
    }
    Ok(Some(SshReport {
        outcome,
        claimed_user: words[offset],
        invalid_user,
        mechanism: words[1],
        source_ip: words[offset + 2]
            .parse()
            .map_err(|_| "Invalid authentication source IP")?,
        source_port: words[offset + 4]
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or("Invalid authentication source port")?,
    }))
}

// OpenSSH 9.6p1 and 10.0p1 auth.c:format_method_key use the same certificate
// suffix. The first supported certificate profile is ED25519/SHA256, without
// appended method-specific information. Other profiles remain explicit refusals.
// https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth.c
// https://github.com/openssh/openssh-portable/blob/V_10_0_P1/auth.c
fn certificate_suffix(words: &[&str]) -> bool {
    if words.len() < 9
        || words[0] != "ED25519-CERT"
        || !sha256_fingerprint(words[1])
        || words[2] != "ID"
    {
        return false;
    }
    let tail = words.len() - 5;
    // The key ID is issuer-controlled and unquoted. Refuse a second structural
    // serial boundary rather than choosing between possible certificate tails.
    if words[tail] != "(serial"
        || words.iter().filter(|word| **word == "(serial").count() != 1
        || words[tail + 2] != "CA"
        || words[tail + 3] != "ED25519"
        || !sha256_fingerprint(words[tail + 4])
    {
        return false;
    }
    let Some(serial) = words[tail + 1].strip_suffix(')') else {
        return false;
    };
    if serial.is_empty()
        || !serial.bytes().all(|b| b.is_ascii_digit())
        || (serial.len() > 1 && serial.starts_with('0'))
        || serial.parse::<u64>().is_err()
    {
        return false;
    }
    // Spaces (including an empty ID) are retained in the original. No key-ID
    // text is searched for account, address, outcome or other normalized facts.
    let id = &words[3..tail];
    id.iter().map(|part| part.len()).sum::<usize>() + id.len() - 1 <= 1024
}

fn sha256_fingerprint(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("SHA256:") else {
        return false;
    };
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // A 32-byte digest has exactly 43 unpadded base64 symbols. The final symbol
    // contains four data bits and two zero padding bits; noncanonical aliases
    // are not accepted as certificate fingerprints.
    encoded.len() == 43
        && encoded.bytes().all(|b| ALPHABET.contains(&b))
        && ALPHABET
            .iter()
            .position(|b| Some(b) == encoded.as_bytes().last())
            .is_some_and(|index| index & 3 == 0)
}

#[cfg(test)]
mod tests;
