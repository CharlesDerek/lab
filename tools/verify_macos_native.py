#!/usr/bin/env python3
"""Exercise real Apple authorization on a signed, authorized Mac.

All watched files, signatures, runtime state and ad-hoc probe copies are temporary.
No launchd job or account is installed. This does not certify production readiness.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback


MAX_OUTPUT = 1024 * 1024
MAX_REPORT = 2 * 1024 * 1024
MAX_DIAGNOSTICS = 8 * 1024 * 1024
OUTPUT_BASE = Path('/private/var/tmp')
FAILURE = 'Native macOS validation failed; private diagnostics retained when available.'
CHECKS = frozenset({
    'all_clean_and_synthetic_targets_allowed_before_activation',
    'open_allowed_and_detection_denied_with_native_receipt',
    'exec_allowed_and_detection_denied_with_native_receipt',
    'mmap_allowed_and_detection_denied_with_native_receipt',
    'quarantine_and_committed_recovery_while_authorization_is_active',
    'restored_file_remains_blocked_with_native_detection_receipt',
    'supervisor_health_requires_fresh_blocking_proof_for_every_root',
    'approved_scans_recognize_exact_health_samples_while_authorization_is_active',
    'native_subscription_publishes_bound_durable_coverage',
    'supervisor_exit_cleans_owned_groups_and_removes_authorization',
    'native_restart_preserves_totals_and_marks_unknown_interval',
})


def private_run(command, **kwargs):
    """Keep command capture off public streams and bound reads into Python.

    The existing command timeout/cleanup behavior is unchanged. Temporary files
    can grow during execution; this is an acceptance/read bound, not a disk quota.
    """
    kwargs.pop('capture_output', None)
    text = kwargs.pop('text', False)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        os.fchmod(out.fileno(), 0o600); os.fchmod(err.fileno(), 0o600)
        try:
            result = subprocess.run(command, stdout=out, stderr=err, **kwargs)
        except BaseException:
            for stream in (out, err):
                stream.seek(0)
                print(stream.read(MAX_OUTPUT).decode(errors='replace'), file=sys.stderr)
            raise
        out.seek(0); err.seek(0)
        stdout = out.read(MAX_OUTPUT + 1); stderr = err.read(MAX_OUTPUT + 1)
        if len(stdout) + len(stderr) > MAX_OUTPUT:
            raise RuntimeError('Native command capture exceeded its bound')
        if text:
            stdout = stdout.decode('utf-8', errors='strict')
            stderr = stderr.decode('utf-8', errors='strict')
        return subprocess.CompletedProcess(command, result.returncode, stdout, stderr)


def private_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, 'w', encoding='utf-8')
    except BaseException:
        os.close(fd)
        raise


def owned_directory_mode(path):
    """Only for a newly created private directory, never an existing input."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        named = path.lstat()
        if (info.st_uid != os.geteuid() or not stat.S_ISDIR(info.st_mode)
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise ValueError('New private directory identity differs')
        os.fchmod(fd, 0o700); os.fsync(fd)
    finally:
        os.close(fd)


def log_tail(path):
    with path.open('rb') as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - 4096))
        return stream.read(4096).decode(errors='replace')


def protected_parent(path):
    """Open every directory without following links; never chmod/adopt it."""
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Private output needs a canonical absolute parent')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise ValueError('Private output ancestry is not protected')
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Private output parent must be owned and mode0700')
        return fd
    except BaseException:
        os.close(fd)
        raise


class DiagnosticLog:
    def __init__(self, stream):
        self.stream = stream
        self.bytes = 0

    def write(self, text):
        size = len(text.encode('utf-8', errors='backslashreplace'))
        if size > MAX_DIAGNOSTICS - self.bytes:
            raise ValueError('Private diagnostic output exceeds its bound')
        self.bytes += size
        return self.stream.write(text)

    def flush(self):
        return self.stream.flush()

    def fileno(self):
        return self.stream.fileno()

    def close(self):
        return self.stream.close()


class PrivateOutput:
    def __init__(self, requested):
        if requested is None:
            parent = Path(tempfile.mkdtemp(prefix='athernex-macos-validation-', dir=OUTPUT_BASE))
            owned_directory_mode(parent)
            requested = parent / 'report.json'
        self.path = Path(requested)
        if not self.path.is_absolute() or not self.path.name or len(self.path.name) > 128:
            raise ValueError('Private report path is invalid')
        self.parent = protected_parent(self.path.parent)
        self.identity = os.fstat(self.parent)
        self.log = None
        try:
            try:
                os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('Private report already exists')
            self.log_name = self.path.name + '.diagnostics-' + secrets.token_hex(16)
            fd = os.open(self.log_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.parent)
            try:
                os.fchmod(fd, 0o600)
                stream = os.fdopen(fd, 'w', encoding='utf-8', errors='backslashreplace')
            except BaseException:
                os.close(fd)
                raise
            self.log = DiagnosticLog(stream)
            os.fsync(self.parent)
        except BaseException:
            self.close()
            raise

    def verify_parent(self):
        fd = protected_parent(self.path.parent)
        try:
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino) != (self.identity.st_dev, self.identity.st_ino):
                raise ValueError('Private output parent changed')
        finally:
            os.close(fd)

    def publish(self, report):
        data = (json.dumps(report, indent=2) + '\n').encode()
        if len(data) > MAX_REPORT:
            raise ValueError('Private report exceeds its bound')
        self.verify_parent()
        name = '.native-report-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.parent)
        try:
            try:
                os.fchmod(fd, 0o600)
                stream = os.fdopen(fd, 'wb')
            except BaseException:
                os.close(fd)
                raise
            with stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            # Link publication refuses every existing destination. It never
            # truncates a caller-selected existing file or follows a symlink.
            os.link(name, self.path.name, src_dir_fd=self.parent, dst_dir_fd=self.parent,
                    follow_symlinks=False)
        finally:
            os.unlink(name, dir_fd=self.parent)
        os.fsync(self.parent)
        self.verify_parent()

    def close(self):
        try:
            if self.log is not None:
                self.log.close()
        finally:
            os.close(self.parent)


def public_summary(report):
    if (type(report) is not dict or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('native_authorization_exercised') is not True
            or report.get('production_readiness') is not False
            or type(report.get('checks')) is not dict or set(report['checks']) != CHECKS
            or any(value != 'passed' for value in report['checks'].values())):
        raise ValueError('Native acceptance report is incomplete')
    return dict(schema=1, suite='MacNative', status='passed', production_readiness=False,
                checks={key: 'passed' for key in sorted(CHECKS)})


def invoke(command, **kwargs):
    result = private_run(list(map(str, command)), capture_output=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{Path(str(command[0])).name} failed ({result.returncode}): '
                           + result.stderr.decode(errors='replace')[-2048:])
    return result.stdout


def write_json(path, value):
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('Private fixture record changed')
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(value)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def verify(args):
    account = pwd.getpwnam(args.scanner_user)
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise RuntimeError('An existing dedicated non-root scanner account is required')
    checks = {}
    evidence = []
    processes = []
    descriptors = []
    directory = tempfile.mkdtemp(prefix='athernex-native-validation-', dir='/private/var/tmp')
    retain = False
    try:
        root = Path(directory).resolve()
        root.chmod(0o755)
        bins = root/'bin';bins.mkdir(mode=0o700)
        adapter = bins/'adapter';agent = bins/'agent'
        for source,target in [(args.adapter,adapter),(args.agent,agent)]:
            shutil.copyfile(source,target);target.chmod(0o700)
            invoke(['/usr/bin/codesign','--verify','--strict',target])
            invoke(['/usr/sbin/spctl','--assess','--type','execute',target])
        entitlements = plistlib.loads(invoke(['/usr/bin/codesign','-d','--entitlements',':-',adapter]))
        if (entitlements.get('com.apple.developer.endpoint-security.client') is not True
                or entitlements.get('com.apple.security.get-task-allow',False) is not False):
            raise RuntimeError('The adapter needs the Endpoint Security entitlement without debug entitlement')
        engine = root/'engine';engine.mkdir(mode=0o755)
        database = engine/'db';database.mkdir(mode=0o755)
        runtime = engine/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,account.pw_uid,account.pw_gid)
        state = root/'state';(state/'protection/native').mkdir(parents=True,mode=0o700)
        state.chmod(0o700);(state/'protection').chmod(0o700)
        native = state/'protection/native'
        watched = root/'watched';watched.mkdir(mode=0o700)
        clean = watched/'clean';clean.write_bytes(b'Ordinary native authorization test')
        blocked = watched/'blocked';sample = b'ATHERNEX PUBLIC MAC AUTHORIZATION PROBE 0102030405';blocked.write_bytes(sample)
        clean_exec = watched/'clean-exec';blocked_exec = watched/'blocked-exec'
        # Re-sign our ordinary native image, not Apple's arm64e platform code.
        # probe-owned supplies --athernex-health-image, which exits without
        # starting services. Do not preserve the adapter's ES entitlements.
        for target in (clean_exec,blocked_exec):
            shutil.copyfile(adapter,target);target.chmod(0o700)
            invoke(['/usr/bin/codesign','--force','--sign','-','--identifier',
                    'com.athernex.validation.'+secrets.token_hex(16),'--options','0',target])
            invoke(['/usr/bin/codesign','--verify','--strict',target])
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        blocked_sha = digest(blocked);exec_sha = digest(blocked_exec)
        if len({exec_sha,digest(clean_exec),digest(adapter)}) != 3:
            raise RuntimeError('Executable probe bytes are not unique')
        signature = database/'fixture.hsb'
        signature.write_text(f'{blocked_sha}:{blocked.stat().st_size}:AthernexNativeProbeText\n'
                             f'{exec_sha}:{blocked_exec.stat().st_size}:AthernexNativeProbeExec\n')
        signature.chmod(0o644)
        policy = dict(roots=[str(watched)],socket=str(runtime/'clamd.sock'),state=str(native),
                      scanner_uid=account.pw_uid,scan_timeout_ms=1000)
        plan = root/'plan.json'
        write_json(plan,dict(schema=1,policy=policy,daemon=str((args.engine_prefix/'sbin/clamd').resolve()),
                             database=str(database),scanner_gid=account.pw_gid,startup_secs=120))
        fd_clean = os.open(clean,os.O_RDONLY);fd_blocked = os.open(blocked,os.O_RDONLY)
        descriptors += [fd_clean,fd_blocked]

        def probe(operation,path,fd=None,denied=False):
            nonce = secrets.token_hex(32)
            result = private_run([str(adapter),'probe-owned',str(os.getpid()),operation,str(path),
                                     '-' if fd is None else str(fd),nonce],
                                    pass_fds=() if fd is None else (fd,),start_new_session=True,
                                    capture_output=True,text=True,timeout=6)
            lines = [json.loads(line) for line in result.stdout.splitlines()]
            if not lines or lines[0].get('nonce')!=nonce or lines[0].get('operation')!=operation:
                raise AssertionError('Missing probe identity: '+result.stderr[-1024:])
            if result.returncode != (10 if denied else 0):
                raise AssertionError(f'{operation} probe had unexpected result {result.returncode}: '+result.stderr[-1024:])
            if denied or operation!='exec':
                assert len(lines)==2 and lines[1]['nonce']==nonce
                assert lines[1]['outcome']==('denied' if denied else 'allowed')
            else:
                assert len(lines)==1
            return lines[0]

        def matching_receipt(attempt,sha,detection):
            saved = native/'last-probe-attempt.json';write_json(saved,attempt)
            deadline = time.monotonic()+5
            while time.monotonic()<deadline:
                for path in (native/'verdicts').glob('*.json'):
                    event = json.loads(path.read_text())
                    if event.get('actor')!=attempt['actor'] or event.get('path')!=attempt['path'] or event.get('operation')!=attempt['operation']:
                        continue
                    invoke([adapter,'probe-evidence',plan,saved,path,sha,detection])
                    evidence.append(dict(attempt=attempt,receipt=event))
                    return
                time.sleep(.05)
            raise AssertionError('Permission denial has no matching delivered native detection receipt')

        def stopped_groups(groups):
            for group in groups:
                try: os.killpg(group,0)
                except ProcessLookupError: continue
                return False
            return True

        private = root/'diagnostics';private.mkdir(mode=0o700)
        owned_directory_mode(private)
        log_path = private/'service.log'
        service = None
        groups = []
        try:
            # Both synthetic targets must be usable before our adapter starts;
            # filesystem permissions or code-signing rejection cannot pass this test.
            for operation,path,fd in [('open',clean,None),('open',blocked,None),
                                      ('exec',clean_exec,None),('exec',blocked_exec,None),
                                      ('mmap',clean,fd_clean),('mmap',blocked,fd_blocked)]:
                probe(operation,path,fd)
            checks['all_clean_and_synthetic_targets_allowed_before_activation']='passed'
            with private_file(log_path) as log:
                # From this point onward, cleanup must positively confirm that
                # every owned worker has stopped before removing its files.
                # Keep the fixture if cleanup itself raises or journals cannot
                # be read; an exception must not turn uncertain ownership into
                # permission to remove a live service's state.
                retain = True
                service = subprocess.Popen([str(adapter),'supervise',str(plan)],stdout=log,stderr=log,start_new_session=True)
                processes.append(service)
                deadline = time.monotonic()+130
                while time.monotonic()<deadline:
                    if service.poll() is not None:
                        raise RuntimeError('Native supervisor failed: '+log_tail(log_path))
                    status_path = native/'service-status.json'
                    if status_path.exists():
                        status = json.loads(status_path.read_text())
                        groups = [p for p in [status.get('scanner_group'),status.get('adapter_group')] if p]
                        if status.get('phase') in ('running-unverified','running-verified') and (native/'native-status.json').exists():
                            result = private_run([str(adapter),'query',str(native),str(clean)],capture_output=True,timeout=6)
                            if result.returncode==0: break
                    time.sleep(.1)
                else: raise AssertionError('Native authorization startup timed out')
                for operation,clean_path,bad_path,fd_good,fd_bad,sha,detection in [
                    ('open',clean,blocked,None,None,blocked_sha,'AthernexNativeProbeText.UNOFFICIAL'),
                    ('exec',clean_exec,blocked_exec,None,None,exec_sha,'AthernexNativeProbeExec.UNOFFICIAL'),
                    ('mmap',clean,blocked,fd_clean,fd_blocked,blocked_sha,'AthernexNativeProbeText.UNOFFICIAL')]:
                    probe(operation,clean_path,fd_good)
                    attempt = probe(operation,bad_path,fd_bad,denied=True)
                    matching_receipt(attempt,sha,detection)
                    checks[operation+'_allowed_and_detection_denied_with_native_receipt']='passed'

                def mutate(intent,recover=False):
                    request=dict(nonce=secrets.token_hex(32),intent=intent,recover=recover,timeout_secs=10)
                    result=invoke([agent,'native-mutation-worker',os.getpid()],input=json.dumps(request).encode(),start_new_session=True)
                    reply=json.loads(result);assert reply['nonce']==request['nonce'];assert reply['report']['outcome']=='completed'
                    return reply['report']
                identifier=secrets.token_hex(32)
                intent=dict(schema=1,command_id=identifier,quarantine_id=identifier,operation='quarantine',
                            state=str(state),path=str(blocked),roots=[str(watched)],sha256=blocked_sha)
                quarantined=mutate(intent)
                assert not blocked.exists() and (state/'quarantine'/identifier).read_bytes()==sample
                recovered=mutate(intent,True)
                assert recovered['finished_ms']==quarantined['finished_ms']
                checks['quarantine_and_committed_recovery_while_authorization_is_active']='passed'
                restored=mutate(dict(intent,command_id=secrets.token_hex(32),operation='restore',verifier=dict(kind='retained')))
                assert restored['path']==str(blocked)
                matching_receipt(probe('open',blocked,denied=True),blocked_sha,'AthernexNativeProbeText.UNOFFICIAL')
                checks['restored_file_remains_blocked_with_native_detection_receipt']='passed'
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    observed=json.loads(invoke([adapter,'health-status',plan]))
                    if observed['runtime_protection_verified']:
                        assert observed['phase']=='running-verified' and observed['verification']['checked_ms']>0
                        break
                    time.sleep(.2)
                else:
                    raise AssertionError('Automatic native blocking health never became verified')
                checks['supervisor_health_requires_fresh_blocking_proof_for_every_root']='passed'
                manifest=json.loads((native/'health/manifest.json').read_text())
                request=dict(schema=1,nonce=secrets.token_hex(32),operation='scan',state=str(native),
                             roots=[str(watched)],path=manifest['roots'][0]['directory']['path'],timeout_secs=10)
                scan=json.loads(invoke([agent,'native-response-worker',os.getpid()],
                                       input=json.dumps(request).encode(),start_new_session=True))
                assert scan['files']==4 and scan['health_samples']==2 and not scan['detections']
                checks['approved_scans_recognize_exact_health_samples_while_authorization_is_active']='passed'
                coverage = json.loads((native/'authorization-coverage.json').read_text())
                before = coverage['evidence']
                live = json.loads((native/'native-status.json').read_text())
                assert before['subscribed'] and before['scope_valid']
                assert before['pid'] == status['adapter_group'] == live['pid']
                assert before['session'] == live['coverage_session'] and live['coverage_current']
                assert before['pidversion'] == live['pidversion']
                assert abs(time.time()*1000-coverage['checked_ms']) < 3000
                evidence.append(dict(native_authorization_coverage=before))
                checks['native_subscription_publishes_bound_durable_coverage']='passed'
                service.terminate();service.wait(timeout=10)
                deadline=time.monotonic()+10
                while not stopped_groups(groups) and time.monotonic()<deadline: time.sleep(.05)
                assert stopped_groups(groups),'Owned native workers survived supervisor exit'
                probe('open',blocked)
                checks['supervisor_exit_cleans_owned_groups_and_removes_authorization']='passed'
                # Reuse the exact state. A new process must preserve historical
                # totals and mark the unobserved tail/subscription interval.
                service = subprocess.Popen([str(adapter),'supervise',str(plan)],stdout=log,stderr=log,start_new_session=True)
                processes.append(service)
                deadline = time.monotonic()+130
                while time.monotonic()<deadline:
                    if service.poll() is not None:
                        raise RuntimeError('Native restart failed: '+log_tail(log_path))
                    status = json.loads((native/'service-status.json').read_text())
                    coverage = json.loads((native/'authorization-coverage.json').read_text())
                    after = coverage['evidence']
                    if (status['supervisor_pid']==service.pid and after['session']!=before['session']
                            and after['subscribed'] and status.get('adapter_group')==after['pid']):
                        break
                    time.sleep(.1)
                else: raise AssertionError('Native restart coverage timed out')
                groups = [p for p in [status.get('scanner_group'),status.get('adapter_group')] if p]
                assert after['lineage']==before['lineage'] and after['policy_sha256']==before['policy_sha256']
                assert after['sessions']==before['sessions']+1
                assert after['unobserved_intervals']==before['unobserved_intervals']+1
                assert after['revision']>before['revision']
                assert all(after['totals'][key]>=value for key,value in before['totals'].items())
                assert after['scope_losses']>=before['scope_losses']
                assert after['legacy_history_unknown']==before['legacy_history_unknown']
                matching_receipt(probe('open',blocked,denied=True),blocked_sha,'AthernexNativeProbeText.UNOFFICIAL')
                evidence.append(dict(native_authorization_coverage=after))
                checks['native_restart_preserves_totals_and_marks_unknown_interval']='passed'
                service.terminate();service.wait(timeout=10)
                deadline=time.monotonic()+10
                while not stopped_groups(groups) and time.monotonic()<deadline: time.sleep(.05)
                assert stopped_groups(groups),'Owned native workers survived restarted supervisor exit'
            return dict(schema=1,scope='Native macOS controlled open/exec/mmap authorization and response validation',
                        native_authorization_exercised=True,production_readiness=False,
                        checks=checks,evidence=evidence,adapter_sha256=digest(adapter),agent_sha256=digest(agent))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)
            for fd in descriptors: os.close(fd)
            # Worker journals precede external daemon startup, including when
            # startup fails before the supervisor has published the group list.
            for role in ('scanner','adapter'):
                journal=native/f'service-{role}.json'
                if journal.exists():
                    group=json.loads(journal.read_text())['record']['pgid']
                    if group not in groups: groups.append(group)
            if groups:
                deadline=time.monotonic()+10
                while not stopped_groups(groups) and time.monotonic()<deadline: time.sleep(.05)
                if not stopped_groups(groups):
                    raise RuntimeError(f'Native workers remain; retained fixture for review at {root}')
            retain = False
    finally:
        if not retain:
            shutil.rmtree(directory)
        else:
            print(f'Retained native validation fixture for review: {directory}',file=sys.stderr)


def emit_public(text, stream):
    try:
        stream.write(text); stream.flush()
        return True
    except BaseException:
        # A buffered broken pipe can otherwise print another traceback during
        # interpreter shutdown. Silence only this failed output stream.
        try:
            null = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(null, stream.fileno())
            finally:
                os.close(null)
        except BaseException:
            pass
        try:
            replacement = open(os.devnull, 'w')
            if sys.stdout is stream:
                sys.stdout = replacement
            elif sys.stderr is stream:
                sys.stderr = replacement
            else:
                replacement.close()
        except BaseException:
            pass
        return False


class PrivateArgumentParser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        if message and not emit_public(message, file or sys.stderr):
            raise SystemExit(1)

    def exit(self, status=0, message=None):
        if message and not emit_public(message, sys.stderr):
            status = 1
        raise SystemExit(status)

    def error(self, message):
        self.exit(2, 'Native macOS validation arguments refused.\n')


def native_host_allowed():
    return sys.platform == 'darwin' and os.geteuid() == 0


def main(argv=None):
    parser=PrivateArgumentParser(prog='verify_macos_native.py', description=__doc__)
    parser.add_argument('--adapter',required=True,type=Path)
    parser.add_argument('--agent',required=True,type=Path)
    parser.add_argument('--engine-prefix',type=Path,default=Path('/usr/local/clamav'))
    parser.add_argument('--scanner-user',default='_athernexav')
    parser.add_argument('--report',type=Path,help='New report in an existing owned0700 private directory')
    args=parser.parse_args(argv)
    if not native_host_allowed():
        parser.error('Run as root on an authorized Mac with signed endpoint/adapter binaries and ClamAV')
    output = None
    summary = None
    failed = False
    try:
        output = PrivateOutput(args.report)
        with contextlib.redirect_stdout(output.log), contextlib.redirect_stderr(output.log):
            try:
                report = verify(args)
                summary = public_summary(report)
                output.log.flush(); os.fsync(output.log.fileno())
                output.publish(report)
            except BaseException:
                failed = True
                traceback.print_exc(file=output.log)
                output.log.flush(); os.fsync(output.log.fileno())
    except BaseException:
        failed = True
    finally:
        if output is not None:
            try:
                output.close()
            except BaseException:
                failed = True
    if failed or summary is None:
        emit_public(FAILURE + '\n', sys.stderr)
        return 1
    return 0 if emit_public(json.dumps(summary, sort_keys=True) + '\n', sys.stdout) else 1


if __name__=='__main__': raise SystemExit(main())
