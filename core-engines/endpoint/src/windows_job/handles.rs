use std::{
    fs::File,
    io,
    marker::PhantomData,
    mem::{size_of, size_of_val},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER,
        HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::ReadFile,
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE},
        Pipes::{CreatePipe, PeekNamedPipe},
        Threading::{
            DeleteProcThreadAttributeList, GetCurrentProcess, InitializeProcThreadAttributeList,
            UpdateProcThreadAttribute, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
        },
    },
};

pub(super) fn owned(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: each caller transfers exactly one fresh successful Win32 handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn inheritable(raw: HANDLE) -> io::Result<OwnedHandle> {
    let mut copy = null_mut();
    let current = unsafe { GetCurrentProcess() };
    if unsafe {
        DuplicateHandle(
            current,
            raw,
            current,
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    owned(copy)
}
fn null_input() -> io::Result<OwnedHandle> {
    inheritable(File::open("NUL")?.as_raw_handle())
}
fn standard(which: u32) -> io::Result<OwnedHandle> {
    let raw = unsafe { GetStdHandle(which) };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return inheritable(File::options().write(true).open("NUL")?.as_raw_handle());
    }
    inheritable(raw)
}
pub(super) struct Stdio {
    pub input: OwnedHandle,
    pub output: OwnedHandle,
    pub error: OwnedHandle,
}
impl Stdio {
    pub fn inherit() -> io::Result<Self> {
        Ok(Self {
            input: null_input()?,
            output: standard(STD_OUTPUT_HANDLE)?,
            error: standard(STD_ERROR_HANDLE)?,
        })
    }
    pub fn capture() -> io::Result<(Self, Pipe)> {
        let (mut read, mut write) = (null_mut(), null_mut());
        // Parent handles are never inheritable, including on error paths.
        if unsafe { CreatePipe(&mut read, &mut write, null(), 4096) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let read = owned(read)?;
        let write = owned(write)?;
        Ok((
            Self {
                input: null_input()?,
                output: inheritable(write.as_raw_handle())?,
                error: inheritable(write.as_raw_handle())?,
            },
            Pipe(read),
        ))
    }
    pub fn capture_with_input(input: &[u8]) -> io::Result<(Self, Pipe)> {
        use std::io::{Seek, SeekFrom, Write};
        if input.len() > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows worker request exceeds its byte budget",
            ));
        }
        // A small delete-on-close input file cannot block the parent waiting
        // for a child to consume a pipe. Only its stdio duplicate is inherited.
        let mut file = tempfile::tempfile()?;
        file.write_all(input)?;
        file.seek(SeekFrom::Start(0))?;
        let (mut stdio, pipe) = Self::capture()?;
        stdio.input = inheritable(file.as_raw_handle())?;
        Ok((stdio, pipe))
    }
    pub fn handles(&self) -> [HANDLE; 3] {
        [
            self.input.as_raw_handle(),
            self.output.as_raw_handle(),
            self.error.as_raw_handle(),
        ]
    }
}

pub(super) struct Pipe(OwnedHandle);
impl Pipe {
    // Only this reader accesses the synchronous pipe. Reading at most the bytes
    // reported available cannot wait for the writer. Limit work per poll so a
    // continuous producer cannot starve timeout checks. No temporary disk file.
    pub fn drain(&mut self, output: &mut Vec<u8>, limit: usize) -> io::Result<bool> {
        self.drain_inner(output, limit, false)
    }
    // Services retain bounded diagnostics while continuing to drain excess
    // output. Finite actions above still fail when their output budget is used.
    pub fn drain_diagnostics(&mut self, output: &mut Vec<u8>, limit: usize) -> io::Result<bool> {
        self.drain_inner(output, limit, true)
    }
    fn drain_inner(
        &mut self,
        output: &mut Vec<u8>,
        limit: usize,
        truncate: bool,
    ) -> io::Result<bool> {
        for _ in 0..16 {
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    self.0.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                    Ok(true)
                } else {
                    Err(error)
                };
            }
            if available == 0 {
                return Ok(true);
            }
            let mut buffer = [0u8; 4096];
            let mut read = 0;
            let amount = (available as usize).min(buffer.len()).min(if truncate {
                buffer.len()
            } else {
                limit.saturating_sub(output.len()).saturating_add(1)
            });
            if unsafe {
                ReadFile(
                    self.0.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    amount as u32,
                    &mut read,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                return Err(io::Error::other("Windows output pipe made no progress"));
            }
            if !truncate && output.len().saturating_add(read as usize) > limit {
                return Err(io::Error::other("Action exceeded its output budget"));
            }
            let retained = (read as usize).min(limit.saturating_sub(output.len()));
            output.extend_from_slice(&buffer[..retained]);
        }
        Ok(false)
    }
}

pub(super) struct Attributes<'a> {
    storage: Vec<usize>,
    _values: PhantomData<&'a [HANDLE]>,
}
impl<'a> Attributes<'a> {
    pub fn new(jobs: &'a [HANDLE], handles: &'a [HANDLE]) -> io::Result<Self> {
        let mut bytes = 0;
        let result = unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes) };
        if result != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || bytes == 0
            || bytes > 65536
        {
            return Err(io::Error::other("Invalid Windows process attribute size"));
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = Self {
            storage,
            _values: PhantomData,
        };
        for (kind, values) in [
            (PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs),
            (PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles),
        ] {
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes.as_mut_ptr(),
                    0,
                    kind as usize,
                    values.as_ptr().cast(),
                    size_of_val(values),
                    null_mut(),
                    null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(attributes)
    }
    pub fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes<'_> {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.as_mut_ptr());
        }
    }
}
