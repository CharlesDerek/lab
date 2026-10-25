//! Native journal reader. Cursors are tested after seeking; missing entries never
//! silently become a successful resume at the nearest retained record.
use super::{Batch, Checkpoint};
use crate::Result;
use athernex_endpoint_protocol::authentication::{from_journal, supported_producer, JournalRecord};
use std::{
    ffi::{CStr, CString},
    io, ptr,
};
type Journal = *mut libc::c_void;
#[repr(C, align(8))]
struct Id128 {
    bytes: [u8; 16],
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn checked(value: libc::c_int) -> Result<libc::c_int> {
    if value < 0 {
        Err(io::Error::from_raw_os_error(-value).into())
    } else {
        Ok(value)
    }
}
macro_rules! api {
    ($($field:ident: $ty:ty = $symbol:literal),+ $(,)?) => {
        struct Api { library: *mut libc::c_void, $($field:$ty),+ }
        impl Api {
            fn open() -> Result<Self> {
                #[cfg(target_arch="x86_64")]
                let candidates=["/usr/lib/x86_64-linux-gnu/libsystemd.so.0","/lib/x86_64-linux-gnu/libsystemd.so.0","/usr/lib64/libsystemd.so.0","/lib64/libsystemd.so.0"];
                #[cfg(target_arch="aarch64")]
                let candidates=["/usr/lib/aarch64-linux-gnu/libsystemd.so.0","/lib/aarch64-linux-gnu/libsystemd.so.0","/usr/lib64/libsystemd.so.0","/lib64/libsystemd.so.0"];
                #[cfg(not(any(target_arch="x86_64",target_arch="aarch64")))]
                let candidates=["/usr/lib/libsystemd.so.0"];
                use std::os::unix::fs::MetadataExt;
                let path=candidates.iter().find(|p|std::fs::metadata(p).is_ok_and(|m|m.is_file() && m.uid()==0 && m.mode()&0o022==0)).ok_or("A root-owned libsystemd.so.0 (version 254 or newer) is required")?;
                let path=CString::new(*path)?;
                let library=unsafe {libc::dlopen(path.as_ptr(),libc::RTLD_NOW|libc::RTLD_LOCAL)};
                if library.is_null() { return Err("Could not load the system journal library".into()); }
                // Close an opened handle even when a required symbol is missing.
                struct Loading(*mut libc::c_void);
                impl Drop for Loading { fn drop(&mut self) { unsafe {libc::dlclose(self.0);} } }
                let loading=Loading(library);
                $(let pointer=unsafe {libc::dlsym(library,concat!($symbol,"\0").as_ptr().cast())};
                  if pointer.is_null() {return Err(concat!("Required journal API missing: ",$symbol," (libsystemd >= 254 required)").into());}
                  let $field: $ty=unsafe {std::mem::transmute(pointer)};)+
                std::mem::forget(loading);
                Ok(Self {library,$($field),+})
            }
        }
        impl Drop for Api { fn drop(&mut self) {unsafe {libc::dlclose(self.library);}} }
    }
}
api! {
    open: unsafe extern "C" fn(*mut Journal,libc::c_int)->libc::c_int = "sd_journal_open",
    close: unsafe extern "C" fn(Journal) = "sd_journal_close",
    next: unsafe extern "C" fn(Journal)->libc::c_int = "sd_journal_next",
    previous: unsafe extern "C" fn(Journal)->libc::c_int = "sd_journal_previous",
    tail: unsafe extern "C" fn(Journal)->libc::c_int = "sd_journal_seek_tail",
    seek: unsafe extern "C" fn(Journal,*const libc::c_char)->libc::c_int = "sd_journal_seek_cursor",
    test: unsafe extern "C" fn(Journal,*const libc::c_char)->libc::c_int = "sd_journal_test_cursor",
    cursor: unsafe extern "C" fn(Journal,*mut *mut libc::c_char)->libc::c_int = "sd_journal_get_cursor",
    sequence: unsafe extern "C" fn(Journal,*mut u64,*mut Id128)->libc::c_int = "sd_journal_get_seqnum",
    realtime: unsafe extern "C" fn(Journal,*mut u64)->libc::c_int = "sd_journal_get_realtime_usec",
    data: unsafe extern "C" fn(Journal,*const libc::c_char,*mut *const libc::c_void,*mut usize)->libc::c_int = "sd_journal_get_data",
    threshold: unsafe extern "C" fn(Journal,usize)->libc::c_int = "sd_journal_set_data_threshold",
    process: unsafe extern "C" fn(Journal)->libc::c_int = "sd_journal_process",
    runtime: unsafe extern "C" fn(Journal)->libc::c_int = "sd_journal_has_runtime_files",
    persistent: unsafe extern "C" fn(Journal)->libc::c_int = "sd_journal_has_persistent_files",
}
pub(super) struct Reader {
    api: Api,
    journal: Journal,
    last_probe: std::time::Instant,
}
impl Drop for Reader {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.journal);
        }
    }
}
impl Reader {
    pub fn open() -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("System authentication collection requires root journal access".into());
        }
        let api = Api::open()?;
        let mut journal = ptr::null_mut();
        // All local default-namespace files, including split user journals, are
        // needed for sequence continuity. Only supported auth records are retained.
        checked(unsafe { (api.open)(&mut journal, 1) })?;
        let reader = Self {
            api,
            journal,
            last_probe: std::time::Instant::now(),
        };
        super::journal_service::probe()?;
        checked(unsafe { (reader.api.threshold)(reader.journal, 4097) })?;
        if checked(unsafe { (reader.api.runtime)(reader.journal) })? == 0
            && checked(unsafe { (reader.api.persistent)(reader.journal) })? == 0
        {
            return Err(
                "No accessible local journal files; collection cannot claim coverage".into(),
            );
        }
        Ok(reader)
    }
    fn field(&self, name: &str, maximum: usize) -> Result<Option<String>> {
        let name = CString::new(name)?;
        let mut pointer = ptr::null();
        let mut length = 0;
        let result =
            unsafe { (self.api.data)(self.journal, name.as_ptr(), &mut pointer, &mut length) };
        if result == -libc::ENOENT {
            return Ok(None);
        }
        checked(result)?;
        let prefix = name.as_bytes().len() + 1;
        if pointer.is_null() || length < prefix || length > maximum + prefix {
            return Err("Journal field exceeds authentication input budget".into());
        }
        let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
        if &bytes[..prefix - 1] != name.as_bytes() || bytes[prefix - 1] != b'=' {
            return Err("Unexpected journal field envelope".into());
        }
        Ok(Some(std::str::from_utf8(&bytes[prefix..])?.into()))
    }
    fn position(&self) -> Result<(String, String, u64, u64)> {
        let mut raw = ptr::null_mut();
        checked(unsafe { (self.api.cursor)(self.journal, &mut raw) })?;
        if raw.is_null() {
            return Err("Journal cursor is missing".into());
        }
        let value = unsafe { CStr::from_ptr(raw) }.to_bytes();
        let cursor = if value.len() <= 512 {
            std::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|_| "Invalid journal cursor")
        } else {
            Err("Journal cursor exceeds budget")
        };
        unsafe {
            libc::free(raw.cast());
        }
        let mut sequence = 0;
        let mut id = Id128 { bytes: [0; 16] };
        let mut time = 0;
        checked(unsafe { (self.api.sequence)(self.journal, &mut sequence, &mut id) })?;
        checked(unsafe { (self.api.realtime)(self.journal, &mut time) })?;
        Ok((cursor?, hex(&id.bytes), sequence, time))
    }
    pub fn baseline(&mut self) -> Result<Checkpoint> {
        checked(unsafe { (self.api.tail)(self.journal) })?;
        if checked(unsafe { (self.api.previous)(self.journal) })? == 0 {
            return Err("Journal has no baseline entry; retry after journal startup".into());
        }
        let (cursor, id, sequence, _) = self.position()?;
        Ok(Checkpoint {
            cursor,
            sequences: [(id, sequence)].into(),
            ..Default::default()
        })
    }
    pub fn batch(&mut self, previous: &Checkpoint) -> Result<Batch> {
        if self.last_probe.elapsed() >= std::time::Duration::from_secs(1) {
            super::journal_service::probe()?;
            self.last_probe = std::time::Instant::now();
        }
        checked(unsafe { (self.api.process)(self.journal) })?;
        let cursor = CString::new(previous.cursor.as_str())?;
        checked(unsafe { (self.api.seek)(self.journal, cursor.as_ptr()) })?;
        let next = checked(unsafe { (self.api.next)(self.journal) })?;
        let exact =
            next > 0 && checked(unsafe { (self.api.test)(self.journal, cursor.as_ptr()) })? > 0;
        let mut result = Batch {
            checkpoint: previous.clone(),
            ..Default::default()
        };
        if !exact && !previous.cursor_missing {
            result.loss_signals += 1;
        }
        result.checkpoint.cursor_missing = !exact;
        let mut available = if exact {
            checked(unsafe { (self.api.next)(self.journal) })?
        } else {
            next
        };
        while available > 0 && result.received_records < 64 {
            let (cursor, id, sequence, time) = self.position()?;
            if result
                .checkpoint
                .sequences
                .insert(id.clone(), sequence)
                .is_none_or(|old| old.checked_add(1) != Some(sequence))
            {
                result.loss_signals += 1;
            }
            if result.checkpoint.sequences.len() > 16 {
                let oldest = result
                    .checkpoint
                    .sequences
                    .keys()
                    .find(|key| *key != &id)
                    .cloned()
                    .unwrap();
                result.checkpoint.sequences.remove(&oldest);
            }
            result.checkpoint.cursor = cursor.clone();
            result.checkpoint.cursor_missing = false;
            result.received_records += 1;
            result.last_record_ms = time / 1000;
            let executable = self.field("_EXE", 1024)?.unwrap_or_default();
            if supported_producer(&executable) {
                let record = (|| -> Result<JournalRecord> {
                    Ok(JournalRecord {
                        cursor,
                        sequence_id: id,
                        sequence,
                        realtime_us: time,
                        machine_id: self
                            .field("_MACHINE_ID", 32)?
                            .ok_or("Missing journal machine identity")?,
                        boot_id: self
                            .field("_BOOT_ID", 32)?
                            .ok_or("Missing journal boot identity")?,
                        executable,
                        reporter_uid: self
                            .field("_UID", 20)?
                            .ok_or("Missing reporter UID")?
                            .parse()?,
                        reporter_pid: self
                            .field("_PID", 20)?
                            .ok_or("Missing reporter PID")?
                            .parse()?,
                        message: self
                            .field("MESSAGE", 4096)?
                            .ok_or("Missing authentication message")?,
                    })
                })();
                match record.and_then(|record| from_journal(&record).map_err(Into::into)) {
                    Ok(Some(event)) => result.events.push(event),
                    Ok(None) => (),
                    Err(_) => result.rejected_records += 1,
                }
            } else if executable.is_empty()
                && self.field("_COMM", 64)?.is_some_and(|comm| {
                    ["sshd", "sshd-session", "sudo", "login", "su"].contains(&comm.as_str())
                })
            {
                let comm = self.field("_COMM", 64)?.unwrap_or_default();
                let message = self.field("MESSAGE", 4096)?.unwrap_or_default();
                if super::missing_provenance(&comm, &message) {
                    // No executable identity means no authentication event.
                    // Persist uncertainty so collection cannot report complete
                    // coverage while these candidate reports are omitted.
                    result.rejected_records += 1;
                }
            } else if self.field("_TRANSPORT", 32)?.as_deref() == Some("driver")
                && self.field("MESSAGE_ID", 32)?.as_deref()
                    == Some("a596d6fe7bfa4994828e72309e95d61e")
            {
                result.loss_signals += 1;
            }
            available = checked(unsafe { (self.api.next)(self.journal) })?;
        }
        result.caught_up = available == 0;
        Ok(result)
    }
}
