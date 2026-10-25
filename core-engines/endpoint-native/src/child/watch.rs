//! A pre-exec watcher belongs to the command's process group. It starts before
//! the external program and observes both its leader and the owning process.
//! After fork this code uses only stack storage and syscall-level operations;
//! it must not allocate, log, unwind, or acquire inherited userspace locks.
use std::{
    os::unix::process::CommandExt,
    process::Command,
    sync::atomic::{AtomicI32, Ordering},
};

// Command permits repeated spawning and retains pre_exec callbacks. This is
// written only in the forked command child, never in the owning process, so
// repeated callbacks in one spawn install exactly one watcher.
static INSTALLED_FOR: AtomicI32 = AtomicI32::new(0);

unsafe fn terminate() -> ! {
    libc::kill(-libc::getpgrp(), libc::SIGKILL);
    libc::_exit(86)
}
unsafe fn errno() -> i32 {
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    {
        *libc::__error()
    }
}

#[cfg(target_os = "linux")]
unsafe fn close_inherited(keep: i32) -> bool {
    // A direct syscall avoids a newer glibc symbol requirement. Refuse startup
    // if the kernel cannot close the complete inherited descriptor range.
    libc::syscall(libc::SYS_close_range, 0u32, (keep - 1) as u32, 0u32) == 0
        && libc::syscall(libc::SYS_close_range, (keep + 1) as u32, u32::MAX, 0u32) == 0
}
#[cfg(target_os = "macos")]
unsafe fn close_inherited(keep: i32) -> bool {
    // proc_pidinfo is a thin __proc_info syscall wrapper. Enumerating actual
    // descriptors also handles descriptors above a subsequently lowered limit.
    let mut entries: [libc::proc_fdinfo; 256] = std::mem::zeroed();
    for _ in 0..4096 {
        let bytes = libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast(),
            std::mem::size_of_val(&entries) as i32,
        );
        if bytes <= 0
            || bytes as usize > std::mem::size_of_val(&entries)
            || !(bytes as usize).is_multiple_of(std::mem::size_of::<libc::proc_fdinfo>())
        {
            return false;
        }
        let count = bytes as usize / std::mem::size_of::<libc::proc_fdinfo>();
        let mut closed = false;
        for entry in &entries[..count] {
            if entry.proc_fd != keep {
                libc::close(entry.proc_fd);
                closed = true;
            }
        }
        if !closed {
            return count == 1 && entries[0].proc_fd == keep;
        }
    }
    false
}

unsafe fn ready(fd: i32) {
    let byte = 42u8;
    if libc::write(fd, (&byte as *const u8).cast(), 1) != 1 {
        terminate();
    }
    libc::close(fd);
}

#[cfg(target_os = "linux")]
unsafe fn observe(parent: i32, leader: i32, notification: i32) -> ! {
    libc::prctl(libc::PR_SET_NAME, c"athernex-watch".as_ptr());
    let owner_fd = libc::syscall(libc::SYS_pidfd_open, parent, 0u32) as i32;
    let leader_fd = libc::syscall(libc::SYS_pidfd_open, leader, 0u32) as i32;
    if owner_fd < 0 || leader_fd < 0 || libc::getppid() != leader {
        terminate();
    }
    let mut events = [
        libc::pollfd {
            fd: owner_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: leader_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    ready(notification);
    loop {
        let result = libc::poll(events.as_mut_ptr(), 2, -1);
        if result < 0 && errno() == libc::EINTR {
            continue;
        }
        terminate();
    }
}

#[cfg(target_os = "macos")]
unsafe fn observe(parent: i32, leader: i32, notification: i32) -> ! {
    let queue = libc::kqueue();
    if queue < 0 {
        terminate();
    }
    let changes = [parent, leader].map(|pid| libc::kevent {
        ident: pid as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    });
    if libc::kevent(
        queue,
        changes.as_ptr(),
        2,
        std::ptr::null_mut(),
        0,
        std::ptr::null(),
    ) < 0
        || libc::getppid() != leader
    {
        terminate();
    }
    ready(notification);
    let mut event: libc::kevent = std::mem::zeroed();
    loop {
        let result = libc::kevent(queue, std::ptr::null(), 0, &mut event, 1, std::ptr::null());
        if result < 0 && errno() == libc::EINTR {
            continue;
        }
        terminate();
    }
}

unsafe fn install(parent: i32) -> std::io::Result<()> {
    let leader = libc::getpid();
    if parent <= 0 || libc::getppid() != parent || libc::getpgrp() != leader {
        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
    }
    if INSTALLED_FOR.load(Ordering::Relaxed) == leader {
        return Ok(());
    }
    let mut pipe = [-1i32; 2];
    if libc::pipe(pipe.as_mut_ptr()) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pipe[0] < 3 || pipe[1] < 3 || pipe[1] == i32::MAX {
        terminate();
    }
    for fd in pipe {
        if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            terminate();
        }
    }
    // Linux's raw clone avoids running inherited pthread_atfork callbacks here.
    #[cfg(target_os = "linux")]
    let pid = libc::syscall(
        libc::SYS_clone,
        libc::SIGCHLD,
        0usize,
        0usize,
        0usize,
        0usize,
    ) as i32;
    #[cfg(target_os = "macos")]
    let pid = libc::fork();
    if pid < 0 {
        let error = std::io::Error::last_os_error();
        libc::close(pipe[0]);
        libc::close(pipe[1]);
        return Err(error);
    }
    if pid == 0 {
        if !close_inherited(pipe[1]) {
            terminate();
        }
        observe(parent, leader, pipe[1]);
    }
    libc::close(pipe[1]);
    let mut event = libc::pollfd {
        fd: pipe[0],
        events: libc::POLLIN,
        revents: 0,
    };
    // No executable starts until the watcher has closed inherited descriptors
    // and registered both exit notifications. EINTR also refuses startup.
    if libc::poll(&mut event, 1, 1000) != 1 {
        terminate();
    }
    let mut byte = 0u8;
    if libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1) != 1
        || byte != 42
        || libc::getppid() != parent
    {
        terminate();
    }
    libc::close(pipe[0]);
    INSTALLED_FOR.store(leader, Ordering::Relaxed);
    Ok(())
}

pub(super) fn check_support() -> crate::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let fd = libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0u32) as i32;
        if fd < 0 {
            return Err(
                "Command lifetime monitoring requires permitted pidfd_open (Linux 5.3 or later)"
                    .into(),
            );
        }
        libc::close(fd);
        // No valid descriptor can have this number; this probes the syscall
        // without closing any caller-owned descriptor.
        if libc::syscall(libc::SYS_close_range, u32::MAX, u32::MAX, 0u32) != 0 {
            return Err(
                "Command lifetime monitoring requires permitted close_range (Linux 5.9 or later)"
                    .into(),
            );
        }
    }
    Ok(())
}
pub(super) fn attach(command: &mut Command) -> crate::Result<()> {
    check_support()?;
    let parent = std::process::id() as i32;
    unsafe {
        command.pre_exec(move || install(parent));
    }
    Ok(())
}
