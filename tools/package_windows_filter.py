"""Private exact three-member driver intake; no install, load, or policy changes.

The supplied approval pins source revision/ABI expectation, profile, altitude,
all three members, and the deterministic container. The candidate management
binary performs actual finite-INF and cache-only WHQL membership verification
in its bounded owned worker. This tool has no verification bypass.
"""
import hashlib
import json
import itertools
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

NAMES = ('athernex-filter.sys', 'athernex-filter.inf', 'athernex-filter.cat')
MAX_BYTES = 64 * 1024 * 1024
FIELDS = {'schema', 'sha256', 'bytes', 'profile', 'trust_policy', 'source_revision',
          'expected_abi', 'driver_version', 'driver_date', 'altitude', 'sys', 'inf', 'cat'}


def require_windows_runtime():
    # CPython 3.12.4 added the Windows mkdir0700 ACL behavior used by mkdtemp.
    # Refuse unknown implementations/backports before creating any private snapshot.
    if (os.name != 'nt' or sys.implementation.name != 'cpython'
            or sys.version_info < (3, 12, 4)):
        raise ValueError('Windows driver packaging requires CPython 3.12.4 or newer')


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate driver package metadata key')
        result[key] = value
    return result


def read_regular(path, limit):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
            or getattr(before, 'st_file_attributes', 0) & 0x400):
        raise ValueError('Driver package input is not a bounded regular file')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as source:
        current = os.fstat(source.fileno())
        if ((current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or getattr(current, 'st_file_attributes', 0) & 0x400):
            raise ValueError('Driver package input changed while opening')
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Driver package input exceeds budget')
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _snapshot(directory, approval, output):
    # Caller-created private output directory; never copy input paths or metadata
    # into public artifacts. All published bytes come from this bounded snapshot.
    try:
        descriptor = json.loads(read_regular(approval, 16384), object_pairs_hook=strict_object)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError('Invalid driver package metadata encoding') from None
    if (not isinstance(descriptor, dict) or set(descriptor) not in (FIELDS, FIELDS | {'deployment'})
            or ('deployment' in descriptor and descriptor['deployment'] != 'install-and-observe-disarmed-v1')):
        raise ValueError('Driver package metadata fields differ')
    if (type(descriptor['schema']) is not int or descriptor['schema'] != 1
            or type(descriptor['expected_abi']) is not int or descriptor['expected_abi'] != 2):
        raise ValueError('Driver package schema or expected ABI differs')
    metadata = directory.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink()
            or getattr(metadata, 'st_file_attributes', 0) & 0x400):
        raise ValueError('Driver package directory is not a regular directory')
    entries = list(itertools.islice(directory.iterdir(), 4))
    if len(entries) != 3 or {p.name for p in entries} != set(NAMES):
        raise ValueError('Driver package must contain exactly SYS INF CAT')
    contents = []
    budget = 32
    for name, key in zip(NAMES, ('sys', 'inf', 'cat')):
        member = descriptor[key]
        if (not isinstance(member, dict) or set(member) != {'bytes', 'sha256'}
                or type(member['bytes']) is not int or not 1 <= member['bytes'] <= MAX_BYTES):
            raise ValueError('Driver member metadata differs')
        budget += member['bytes']
        if budget > MAX_BYTES:
            raise ValueError('Driver package exceeds aggregate budget')
        data = read_regular(directory / name, member['bytes'])
        if len(data) != member['bytes'] or digest(data) != member['sha256']:
            raise ValueError('Driver package input differs from approval')
        contents.append(data)
    blob = b'AXFPKG1\0' + struct.pack('<QQQ', *(len(data) for data in contents)) + b''.join(contents)
    if len(blob) > MAX_BYTES or len(blob) != descriptor['bytes'] or digest(blob) != descriptor['sha256']:
        raise ValueError('Driver package container differs from approval')
    output.mkdir(mode=0o700)
    for name, data in zip(NAMES, contents):
        path = output / name
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            stream.write(data)
    receipt = output / 'descriptor.json'
    with receipt.open('xb') as stream:
        os.chmod(receipt, 0o600)
        stream.write(json.dumps(descriptor, separators=(',', ':')).encode())
    return blob, descriptor, contents


def snapshot(directory, approval, output):
    try:
        return _snapshot(directory, approval, output)
    except OSError:
        raise ValueError('Driver package private input or snapshot I/O refused') from None


def _package(directory, approval, temporary, management):
    output = temporary / 'windows-filter'
    blob, descriptor, contents = snapshot(directory, approval, output)
    # Fixed trusted candidate command. That command owns its trust subprocess in
    # a Windows Job, bounds output/time, and refuses unknown cleanup. Outer timeout
    # is a second refusal, never evidence of trust or native driver eligibility.
    verify_command(management, 'verify-windows-filter-package', output, descriptor['sha256'])
    for name, data in zip(NAMES, contents):
        if read_regular(output / name, len(data)) != data:
            raise ValueError('Driver package snapshot changed after verification')
    return blob, descriptor


def verify_command(management, verb, argument, expected):
    if verb not in ('verify-windows-filter-package', 'installer-filter-hash'):
        raise ValueError('Unsupported driver package verification operation')
    try:
        result = subprocess.run([str(management), verb, str(argument)],
                                check=True, capture_output=True, timeout=45)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raise ValueError('Driver package verifier refused or did not complete') from None
    if (result.stdout not in ((expected + '\n').encode(), (expected + '\r\n').encode())
            or result.stderr):
        raise ValueError('Driver package verifier did not return the exact digest')


def package(directory, approval, temporary, management):
    try:
        return _package(directory, approval, temporary, management)
    except OSError:
        raise ValueError('Driver package private input or snapshot I/O refused') from None


def publish_catalog(management, temporary, output, blob, expected):
    try:
        package_path = temporary / 'windows-filter.axpkg'
        with package_path.open('xb') as stream:
            os.chmod(package_path, 0o600)
            stream.write(blob)
        result = subprocess.run([str(management), 'publish-windows-filter-catalog',
                                 str(temporary), str(output.absolute())],
                                check=True, capture_output=True, timeout=90)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError('Private Windows driver catalog publication refused') from None
    if result.stdout not in ((expected + '\n').encode(), (expected + '\r\n').encode()) or result.stderr:
        raise ValueError('Private Windows driver catalog receipt differs')


def _windows_directory():
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True)
    query = kernel.GetWindowsDirectoryW
    query.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    query.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    size = query(buffer, len(buffer))
    if not 0 < size < len(buffer):
        raise ValueError('Windows system directory unavailable')
    return Path(buffer.value)


def _signature_process(command, environment, timeout=15):
    # The executable and script are fixed by windows_signature_preflight. No
    # candidate code executes here. Retain at most4096 bytes, never print them.
    import threading
    import time
    child = None
    reader = None
    try:
        child = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 bufsize=0, close_fds=True)
        output = bytearray()
        refused = threading.Event()

        def drain():
            try:
                while True:
                    block = child.stdout.read(4096)
                    if not block:
                        return
                    if len(output) + len(block) > 4096:
                        refused.set()
                        return
                    output.extend(block)
            except Exception:
                refused.set()

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if refused.is_set() or time.monotonic() >= deadline:
                raise ValueError('Independent management signature check refused')
            refused.wait(0.01)
        reader.join(timeout=2)
        if reader.is_alive() or refused.is_set() or child.returncode != 0 or output:
            raise ValueError('Independent management signature check refused')
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise ValueError('Independent signature child cleanup unconfirmed') from None
            if reader is not None and reader.ident is not None:
                reader.join(timeout=2)
                if reader.is_alive():
                    raise ValueError('Independent signature output cleanup unconfirmed')
            child.stdout.close()


def windows_signature_preflight(snapshot):
    try:
        windows = _windows_directory()
        directory = windows / 'System32' / 'WindowsPowerShell' / 'v1.0'
        command = [str(directory / 'powershell.exe'), '-NoLogo', '-NoProfile', '-NonInteractive',
                   '-Command', "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
                   "try { $s = Microsoft.PowerShell.Security\\Get-AuthenticodeSignature "
                   "-LiteralPath $env:ATHERNEX_VERIFY_BINARY; "
                   "if ($s.Status -ne [System.Management.Automation.SignatureStatus]::Valid) { exit 1 }; "
                   "exit 0 } catch { exit 1 }"]
        environment = {'SystemRoot': str(windows), 'WINDIR': str(windows),
                       'PATH': str(windows / 'System32'),
                       'PSModulePath': str(directory / 'Modules'),
                       'ATHERNEX_VERIFY_BINARY': str(snapshot.absolute())}
        _signature_process(command, environment)
    except Exception:
        raise ValueError('Independent management signature check refused') from None
