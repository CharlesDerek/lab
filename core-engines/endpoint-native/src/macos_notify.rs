//! Private mechanics shared by the two finite NOTIFY source profiles.
pub(crate) mod framing;
#[cfg(target_os = "macos")]
pub(crate) mod native;
pub(crate) mod owned;
#[cfg(any(target_os = "macos", test))]
pub(crate) mod queue;
pub(crate) const MAX_RECORDS: usize = 2048;
pub(crate) const MAX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_BATCH_RECORDS: usize = 64;
pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024;
#[cfg(any(target_os = "macos", test))]
pub(crate) const MAX_BATCH_BYTES: usize = MAX_FRAME_BYTES - 16 * 1024;
pub(crate) fn hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
