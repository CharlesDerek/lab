"""Linux-only, container-only read barrier for the native response fixture.

This deliberately denies every ordinary open under one fixture directory. Only
the separately running native broker may read there. It is not an AV engine or
an Endpoint Security implementation; ClamAV still supplies the broker verdicts.
"""
import ctypes
import os
from pathlib import Path
import select
import struct
import threading
import time


class ReadBarrier:
    def __init__(self, watched, broker_pid):
        watched = Path(watched).resolve(strict=True)
        if (not Path('/.dockerenv').exists() or os.geteuid() != 0
                or not watched.is_relative_to('/fixture') or not watched.is_dir()):
            raise RuntimeError('Read barriers are restricted to the isolated /fixture tree')
        self.owner = None
        self.allow(broker_pid)
        self.denied = 0
        self.allowed = 0
        self.error = None
        self.changed = threading.Condition()
        self.finished = False
        self.stop = threading.Event()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        libc.fanotify_init.restype = ctypes.c_int
        libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                      ctypes.c_int, ctypes.c_char_p]
        libc.fanotify_mark.restype = ctypes.c_int
        # FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_CONTENT; observe only direct
        # children of the private watched directory, not any host filesystem.
        self.fd = libc.fanotify_init(1 | 2 | 4, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'fanotify_init')
        if libc.fanotify_mark(self.fd, 1 | 8, 0x10000 | 0x08000000, -100,
                             os.fsencode(watched)) != 0:
            error = ctypes.get_errno()
            os.close(self.fd)
            raise OSError(error, 'fanotify_mark')
        self.thread = threading.Thread(target=self._run, name='fixture-read-barrier', daemon=True)
        self.thread.start()

    @staticmethod
    def birth(pid):
        try:
            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] in ('Z', 'X'):
                return None
            return int(fields[19])
        except (FileNotFoundError, ProcessLookupError):
            return None

    def allow(self, pid):
        born = self.birth(pid)
        if born is None:
            raise RuntimeError('Broker identity is not live')
        self.owner = (pid, born)

    def _run(self):
        try:
            while not self.stop.is_set():
                if not select.select([self.fd], [], [], .1)[0]:
                    continue
                data = os.read(self.fd, 65536)
                offset = 0
                while offset < len(data):
                    length, version, _, metadata, mask, file_fd, pid = struct.unpack_from('=IBBHQii', data, offset)
                    if version != 3 or metadata != 24 or length < 24 or offset + length > len(data):
                        raise RuntimeError('Invalid fanotify metadata')
                    if file_fd < 0 or mask & 0x4000 or not mask & 0x10000:
                        raise RuntimeError('Missing/overflowed permission event')
                    try:
                        owner = self.owner
                        allowed = pid == owner[0] and self.birth(pid) == owner[1]
                        # FAN_ALLOW=1, FAN_DENY=2. Even root is denied unless its
                        # process identity is the currently registered broker.
                        response = struct.pack('=iI', file_fd, 1 if allowed else 2)
                        if os.write(self.fd, response) != len(response):
                            raise RuntimeError('Incomplete permission response')
                        # The response can unblock the opener before this
                        # thread resumes. Publish its completed acknowledgment
                        # under the same condition used by fixture waiters.
                        with self.changed:
                            if allowed:
                                self.allowed += 1
                            else:
                                self.denied += 1
                            self.changed.notify_all()
                    finally:
                        os.close(file_fd)
                    offset += length
        except Exception as error:
            with self.changed:
                self.error = error
                self.changed.notify_all()
        finally:
            os.close(self.fd)
            with self.changed:
                self.finished = True
                self.changed.notify_all()

    def check(self):
        if self.error is not None or self.finished or not self.thread.is_alive():
            raise RuntimeError(f'Read barrier stopped: {self.error}')

    def denial_count(self):
        with self.changed:
            self.check()
            return self.denied

    def wait_for_denial(self, before, timeout=3):
        deadline = time.monotonic() + timeout
        with self.changed:
            while self.denied <= before:
                self.check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError('Read barrier denial acknowledgment timed out')
                self.changed.wait(remaining)
            self.check()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        if self.thread.is_alive() or self.error is not None:
            raise RuntimeError(f'Read barrier failed: {self.error}')
