//! Owner-authenticated, bounded local scan access from the ES-exempt process.
//! No file contents, arbitrary commands, exemptions or cached verdicts are exposed.
use crate::{
    receipt::{hex_id, policy_hash},
    scanner, Policy, Result, Scan, Verdict, MAX_FILE,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const FRAME: usize = 8192;
const WORKERS: usize = 2;
const QUEUE: usize = 8;
const SOCKET: &str = "response.sock";
const BINDING: &str = "response.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema: u32,
    policy_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u32,
    nonce: String,
    policy_sha256: String,
    path: PathBuf,
    max_bytes: u64,
    timeout_ms: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema: u32,
    nonce: String,
    policy_sha256: String,
    verdict: Option<Verdict>,
    error: String,
}

pub(crate) fn trusted(path: &Path, private: bool) -> Result<()> {
    if !path.is_absolute() {
        return Err("Native response paths must be absolute".into());
    }
    let uid = unsafe { libc::geteuid() };
    for (index, p) in path.ancestors().enumerate() {
        let m = fs::symlink_metadata(p)?;
        let sticky = index > 0 && m.is_dir() && m.uid() == 0 && m.mode() & 0o1000 != 0;
        if m.file_type().is_symlink()
            || ![0, uid].contains(&m.uid())
            || (m.mode() & 0o022 != 0 && !sticky)
            || (index == 0 && private && (m.uid() != uid || m.mode() & 0o077 != 0))
        {
            return Err(
                "Native response storage must be private and owned by the service identity".into(),
            );
        }
    }
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                peer.as_mut_ptr().cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of::<libc::ucred>()
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { peer.assume_init() }.uid)
    }
    #[cfg(target_os = "macos")]
    {
        let (mut uid, mut gid) = (0, 0);
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        Err("Native response peer verification is unavailable".into())
    }
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "Native response deadline elapsed".into())
}
fn read_exact(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        let timeout = remaining(deadline)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Set native response read timeout ({timeout:?}): {e}"))?;
        let n = stream.read(bytes).map_err(|e| {
            format!(
                "Read native response bytes ({} requested): {e}",
                bytes.len()
            )
        })?;
        if n == 0 {
            return Err("Native response connection closed early".into());
        }
        bytes = &mut bytes[n..];
    }
    remaining(deadline)?;
    Ok(())
}
fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<T> {
    let mut header = [0; 4];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > FRAME {
        return Err("Native response frame exceeds its budget".into());
    }
    let mut bytes = vec![0; length];
    read_exact(stream, &mut bytes, deadline)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T, deadline: Instant) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > FRAME {
        return Err("Native response frame exceeds its budget".into());
    }
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend(bytes);
    let mut rest = frame.as_slice();
    while !rest.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let n = stream.write(rest)?;
        if n == 0 {
            return Err("Native response connection stopped accepting data".into());
        }
        rest = &rest[n..];
    }
    Ok(())
}

pub fn configured(state: &Path) -> Result<bool> {
    match fs::symlink_metadata(state.join(BINDING)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
        Ok(_) => {
            read_binding(state)?;
            Ok(true)
        }
    }
}
pub(crate) fn bound_policy_hash(state: &Path) -> Result<String> {
    Ok(read_binding(state)?.policy_sha256)
}
fn read_binding(state: &Path) -> Result<Binding> {
    let path = state.join(BINDING);
    trusted(&path, true)?;
    let file = scanner::open_file(&path)?;
    if file.metadata()?.len() > 1024 {
        return Err("Native response binding exceeds its budget".into());
    }
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err("Native response binding exceeds its budget".into());
    }
    let binding: Binding = serde_json::from_slice(&bytes)?;
    if binding.schema != 1 || !hex_id(&binding.policy_sha256) {
        return Err("Invalid native response binding".into());
    }
    Ok(binding)
}
#[cfg(target_os = "linux")]
pub fn serve_fixture(path: &Path) -> Result<()> {
    trusted(path, true)?;
    let file = scanner::open_file(path)?;
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("Native response policy exceeds its budget".into());
    }
    let policy: Policy = serde_json::from_slice(&bytes)?;
    let broker = Broker::start(policy, Arc::new(AtomicBool::new(true)))?;
    while !broker.stopped.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
    Err("Native response listener stopped".into())
}
pub fn query(state: &Path, path: &Path, timeout: Duration) -> Result<Verdict> {
    query_limited(state, path, timeout, MAX_FILE)
}
pub fn query_limited(
    state: &Path,
    path: &Path,
    timeout: Duration,
    byte_budget: u64,
) -> Result<Verdict> {
    if timeout.is_zero() {
        return Err("Native response deadline elapsed".into());
    }
    let timeout = timeout.min(Duration::from_secs(30));
    let deadline = Instant::now() + timeout;
    let binding = read_binding(state)?;
    let socket = state.join(SOCKET);
    trusted(&socket, true)?;
    if !fs::symlink_metadata(&socket)?.file_type().is_socket() {
        return Err("Native response endpoint is not a socket".into());
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)?;
    let request = Request {
        schema: 1,
        nonce: random.iter().map(|b| format!("{b:02x}")).collect(),
        policy_sha256: binding.policy_sha256,
        path: path.into(),
        max_bytes: MAX_FILE.min(byte_budget),
        timeout_ms: timeout.as_millis().max(1) as u64,
    };
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        .map_err(|e| format!("Create native response socket: {e}"))?;
    socket
        .connect_timeout(
            &socket2::SockAddr::unix(state.join(SOCKET))?,
            remaining(deadline)?,
        )
        .map_err(|e| format!("Connect native response socket: {e}"))?;
    let descriptor: std::os::fd::OwnedFd = socket.into();
    let mut stream = UnixStream::from(descriptor);
    if peer_uid(&stream).map_err(|e| format!("Read native response peer identity: {e}"))?
        != unsafe { libc::geteuid() }
    {
        return Err("Native response server identity differs from its owner".into());
    }
    write_frame(&mut stream, &request, deadline)
        .map_err(|e| format!("Write native response request: {e}"))?;
    let reply: Reply = read_frame(&mut stream, deadline)
        .map_err(|e| format!("Read native response reply: {e}"))?;
    if reply.schema != 1
        || reply.nonce != request.nonce
        || reply.policy_sha256 != request.policy_sha256
        || reply.error.len() > 256
    {
        return Err("Native response identity does not match this request".into());
    }
    if !reply.error.is_empty() {
        if reply.verdict.is_some() {
            return Err("Native response contains a contradictory verdict".into());
        }
        return Err(reply.error.into());
    }
    let verdict = reply.verdict.ok_or("Native response has no verdict")?;
    if !hex_id(&verdict.sha256)
        || verdict.bytes > request.max_bytes
        || verdict
            .detection
            .as_ref()
            .is_some_and(|d| d.is_empty() || d.len() > 256 || d.contains(char::is_control))
    {
        return Err("Invalid native scan verdict".into());
    }
    remaining(deadline)?;
    Ok(verdict)
}

struct Job {
    stream: UnixStream,
    accepted: Instant,
}
struct Service {
    policy: Policy,
    hash: String,
    scope_valid: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    roots: Vec<(PathBuf, u64, u64)>,
}
impl Service {
    fn scope(&self) -> Result<()> {
        if self.stopped.load(Ordering::Relaxed)
            || !self.scope_valid.load(Ordering::Relaxed)
            || self.roots.iter().any(|(p, d, i)| {
                !fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && m.dev() == *d && m.ino() == *i)
            })
        {
            return Err("Native authorization scope is unavailable or changed".into());
        }
        Ok(())
    }
    fn handle(&self, mut job: Job) -> Result<()> {
        // Accepted sockets inherit O_NONBLOCK on Darwin. Framed I/O below uses
        // per-operation deadlines on a blocking socket on every platform.
        job.stream.set_nonblocking(false)?;
        let request: Request = read_frame(&mut job.stream, job.accepted + Duration::from_secs(2))?;
        if request.schema != 1
            || !hex_id(&request.nonce)
            || request.timeout_ms == 0
            || request.timeout_ms > 30000
            || request.max_bytes > MAX_FILE
        {
            return Err("Invalid native response request".into());
        }
        let deadline = job.accepted + Duration::from_millis(request.timeout_ms);
        let result = (|| -> Result<Verdict> {
            remaining(deadline)?;
            self.scope()?;
            if request.policy_sha256 != self.hash
                || !self.policy.contains_observed_path(&request.path, false)
                || request
                    .path
                    .to_str()
                    .is_none_or(|p| p.len() > 1024 || p.contains(char::is_control))
            {
                return Err("Native response request is outside its pinned scope".into());
            }
            // File operations stay in the fixed worker pool, independently of
            // the client's socket deadline and the ES authorization workers.
            let file = scanner::open_file(&request.path)?;
            let metadata = file.metadata()?;
            if metadata.len() > request.max_bytes {
                return Err("Native response file exceeds its byte budget".into());
            }
            let verdict = scanner::scan(
                &Scan {
                    path: request.path,
                    identity: scanner::identity(&metadata),
                    deadline,
                },
                &self.policy.socket,
            )?;
            self.scope()?;
            Ok(verdict)
        })();
        let (verdict, error) = match result {
            Ok(v) => (Some(v), String::new()),
            Err(e) => {
                let mut error = String::new();
                for c in e
                    .to_string()
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                {
                    if error.len() + c.len_utf8() > 256 {
                        break;
                    }
                    error.push(c);
                }
                (None, error)
            }
        };
        write_frame(
            &mut job.stream,
            &Reply {
                schema: 1,
                nonce: request.nonce,
                policy_sha256: self.hash.clone(),
                verdict,
                error,
            },
            deadline,
        )
    }
}

pub struct Broker {
    _lock: File,
    stopped: Arc<AtomicBool>,
    listener: Option<thread::JoinHandle<()>>,
    path: PathBuf,
    identity: (u64, u64),
}
impl Broker {
    pub fn start(policy: Policy, scope_valid: Arc<AtomicBool>) -> Result<Self> {
        policy.validate()?;
        trusted(&policy.state, true)?;
        if !policy.state.is_dir() {
            return Err("Native response state must be a private directory".into());
        }
        let lock_path = policy.state.join("response.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&lock_path)?;
        if !lock.metadata()?.is_file() {
            return Err("Native response lock must be a regular file".into());
        }
        trusted(&lock_path, true)?;
        lock.try_lock()
            .map_err(|_| "Native response broker is already running")?;
        let path = policy.state.join(SOCKET);
        match fs::symlink_metadata(&path) {
            Ok(m) => {
                trusted(&path, true)?;
                if !m.file_type().is_socket() {
                    return Err("Unexpected file at native response socket".into());
                }
                fs::remove_file(&path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let metadata = fs::symlink_metadata(&path)?;
        let identity = (metadata.dev(), metadata.ino());
        let hash = policy_hash(&policy)?;
        let binding = serde_json::to_vec(&Binding {
            schema: 1,
            policy_sha256: hash.clone(),
        })?;
        let binding_path = policy.state.join(BINDING);
        // The private parent and broker lock serialize publication/restart. A
        // persistent binding prevents clients falling back after broker death.
        let pending = policy.state.join("response-binding.pending");
        if pending.exists() {
            trusted(&pending, true)?;
            fs::remove_file(&pending)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(&binding)?;
        file.sync_all()?;
        fs::rename(pending, binding_path)?;
        File::open(&policy.state)?.sync_all()?;
        let roots = policy
            .roots
            .iter()
            .map(|p| {
                let m = fs::symlink_metadata(p)?;
                if !m.is_dir() || p.canonicalize()? != *p {
                    return Err("Native response roots must be canonical directories".into());
                }
                Ok((p.clone(), m.dev(), m.ino()))
            })
            .collect::<Result<Vec<_>>>()?;
        let stopped = Arc::new(AtomicBool::new(false));
        let service = Arc::new(Service {
            policy,
            hash,
            scope_valid,
            stopped: stopped.clone(),
            roots,
        });
        let (send, receive) = mpsc::sync_channel::<Job>(QUEUE);
        let receive = Arc::new(Mutex::new(receive));
        for _ in 0..WORKERS {
            let service = service.clone();
            let receive = receive.clone();
            thread::spawn(move || loop {
                let Ok(lock) = receive.lock() else {
                    return;
                };
                let job = lock.recv();
                drop(lock);
                let Ok(job) = job else {
                    return;
                };
                if service.stopped.load(Ordering::Relaxed) {
                    return;
                }
                let _ = service.handle(job);
            });
        }
        let stop = stopped.clone();
        let owner = unsafe { libc::geteuid() };
        let listener = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if peer_uid(&stream).ok() == Some(owner) {
                            let _ = send.try_send(Job {
                                stream,
                                accepted: Instant::now(),
                            });
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });
        Ok(Self {
            _lock: lock,
            stopped,
            listener: Some(listener),
            path,
            identity,
        })
    }
}
impl Drop for Broker {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && (m.dev(), m.ino()) == self.identity)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests;
