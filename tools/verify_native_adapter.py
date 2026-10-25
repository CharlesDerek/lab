#!/usr/bin/env python3
"""Exercise the native adapter's exact-byte transport with real ClamAV.

This is a Unix scanner test, not macOS Endpoint Security runtime validation.
The daemon and its private signatures live entirely in a disposable container.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import socket as socket_api
import subprocess
import sys
import time
from native_read_barrier import ReadBarrier


def inside():
    root = Path('/fixture')
    if not Path('/.dockerenv').exists() or not root.is_dir():
        raise RuntimeError('Run the fixture in its disposable container')
    binary = Path('/test/adapter')
    watched = root / 'watched'
    watched.mkdir()
    db = root / 'db'
    db.mkdir()
    sample = b'ATHERNEX PUBLIC NATIVE STREAM FIXTURE 010203040506'
    (db / 'fixture.hdb').write_text(
        f'{hashlib.md5(sample).hexdigest()}:{len(sample)}:AthernexNativeStreamFixture\n')
    socket = root / 'clamd.sock'
    config = root / 'clamd.conf'
    config.write_text(f'''Foreground yes
DatabaseDirectory {db}
TemporaryDirectory {root}
LocalSocket {socket}
LocalSocketMode 600
FixStaleSocket yes
MaxThreads 4
MaxQueue 16
StreamMaxLength 128M
MaxFileSize 128M
MaxScanSize 256M
AlertExceedsMax yes
LogTime yes
''')
    checks = {}
    log_path = root / 'clamd.log'
    with log_path.open('w') as log:
        broker = None
        barrier = None
        daemon = subprocess.Popen(['/usr/local/sbin/clamd', '--config-file', str(config)],
                                  stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while not socket.exists():
                if daemon.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Scanner startup failed: ' + log_path.read_text())
                time.sleep(.1)

            def scan(path, success=True):
                result = subprocess.run([str(binary), 'scan', str(socket), str(path)],
                                        capture_output=True, text=True, timeout=10)
                assert (result.returncode == 0) == success, (result.stdout, result.stderr)
                return json.loads(result.stdout) if success else result.stderr

            clean = watched / 'clean.txt'
            data = b'Ordinary controlled text.\n' * 12000
            clean.write_bytes(data)
            verdict = scan(clean)
            assert verdict == dict(sha256=hashlib.sha256(data).hexdigest(),
                                   detection=None, bytes=len(data)), verdict
            checks['clean_multichunk_stream_and_hash'] = 'passed'
            infected = watched / 'fixture.txt'
            infected.write_bytes(sample)
            verdict = scan(infected)
            assert verdict['sha256'] == hashlib.sha256(sample).hexdigest()
            assert verdict['bytes'] == len(sample)
            assert verdict['detection'].startswith('AthernexNativeStreamFixture'), verdict
            checks['real_signature_detection_and_hash'] = 'passed'
            link = watched / 'link.txt'
            link.symlink_to(clean)
            scan(link, success=False)
            checks['symlink_refused'] = 'passed'
            fifo = watched / 'fifo'
            os.mkfifo(fifo)
            assert 'regular file' in scan(fifo, success=False)
            checks['fifo_refused_without_blocking'] = 'passed'
            oversized = watched / 'oversized.bin'
            with oversized.open('wb') as file:
                file.truncate(128 * 1024 * 1024 + 1)
            assert '128 MiB' in scan(oversized, success=False)
            checks['oversized_file_refused'] = 'passed'
            state = root / 'endpoint'
            state.mkdir(mode=0o700)
            (state / 'protection').mkdir(mode=0o700)
            native = state / 'protection/native'
            native.mkdir(mode=0o700)
            policy = root / 'native-policy.json'
            policy.write_text(json.dumps(dict(roots=[str(watched)], socket=str(socket),
                                             state=str(native), scanner_uid=1234,
                                             scan_timeout_ms=1000)))
            policy.chmod(0o600)

            def query(path, success=True):
                result = subprocess.run([str(binary), 'query', str(native), str(path)],
                                        capture_output=True, text=True, timeout=8)
                assert (result.returncode == 0) == success, (result.stdout, result.stderr)
                return json.loads(result.stdout) if success else result.stderr

            def start_broker():
                process = subprocess.Popen([str(binary), 'serve-scanner', str(policy)],
                                           stdout=log, stderr=log)
                if barrier is not None:
                    barrier.allow(process.pid)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError('Native broker exited: ' + log_path.read_text())
                    ready = subprocess.run([str(binary), 'query', str(native), str(clean)],
                                           capture_output=True, timeout=8)
                    if ready.returncode == 0:
                        return process
                    time.sleep(.05)
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError('Native broker startup timed out')

            broker = start_broker()
            assert query(clean)['sha256'] == hashlib.sha256(data).hexdigest()
            detected = query(infected)
            assert detected['sha256'] == hashlib.sha256(sample).hexdigest()
            assert detected['detection'].startswith('AthernexNativeStreamFixture')
            checks['broker_returns_real_clean_and_detected_verdicts'] = 'passed'
            assert 'scope' in query(policy, success=False)
            checks['broker_refuses_out_of_scope_files'] = 'passed'

            def mutate(intent, recover=False, success=True):
                request = dict(nonce='d' * 64, intent=intent, recover=recover, timeout_secs=5)
                response = subprocess.run(['/test/agent', 'native-mutation-worker', str(os.getpid())],
                                          input=json.dumps(request), capture_output=True, text=True,
                                          start_new_session=True, timeout=8)
                assert (response.returncode == 0) == success, (response.stdout, response.stderr)
                return json.loads(response.stdout)['report'] if success else response.stderr

            mutation_sample = watched / 'mutation-sample'
            mutation_sample.write_bytes(sample)
            alias = watched / 'old-hardlink'
            os.link(mutation_sample, alias)
            intent = dict(schema=1, command_id='a' * 64, quarantine_id='a' * 64,
                          operation='quarantine', state=str(state), path=str(mutation_sample),
                          roots=[str(watched)], sha256=hashlib.sha256(sample).hexdigest())
            assert mutate(intent)['outcome'] == 'completed'
            retained = state / 'quarantine' / intent['quarantine_id']
            assert not mutation_sample.exists() and retained.read_bytes() == sample
            alias.write_bytes(b'changed old inode')
            assert retained.read_bytes() == sample
            checks['real_engine_quarantine_retains_independent_verified_bytes'] = 'passed'
            assert mutate(intent, recover=True)['outcome'] == 'completed'
            checks['completed_quarantine_recovers_without_replaying_source_move'] = 'passed'
            restore = dict(intent, command_id='b' * 64, operation='restore')
            mutation_sample.write_bytes(b'unrelated destination')
            mutate(restore, success=False)
            assert mutation_sample.read_bytes() == b'unrelated destination'
            assert retained.read_bytes() == sample
            checks['native_restore_refuses_existing_destination'] = 'passed'
            mutation_sample.unlink()
            restore['command_id'] = 'c' * 64
            assert mutate(restore)['outcome'] == 'completed'
            assert mutation_sample.read_bytes() == sample and not retained.exists()
            assert mutate(restore, recover=True)['outcome'] == 'completed'
            checks['native_restore_publishes_complete_bytes_and_recovers_commit'] = 'passed'


            # Relax only this disposable socket's filesystem access to exercise
            # the independent kernel peer-credential check using another UID.
            state.chmod(0o711)
            (state / 'protection').chmod(0o711)
            native.chmod(0o711)
            endpoint = native / 'response.sock'
            endpoint.chmod(0o666)
            peer_test = '''if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')
import socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(1);s.connect(sys.argv[1])
try:
    assert s.recv(1)==b''
except ConnectionResetError:
    pass
'''
            try:
                subprocess.run([sys.executable, '-c', peer_test, str(endpoint)],
                               user=65534, check=True, timeout=5)
            finally:
                endpoint.chmod(0o600)
                native.chmod(0o700)
                (state / 'protection').chmod(0o700)
                state.chmod(0o700)
            checks['broker_rejects_other_uid_even_with_socket_access'] = 'passed'
            held = []
            try:
                # Observe two occupied workers plus eight queued streams and
                # the listener, rather than assuming scheduler timing. The
                # fixture only inspects its own disposable broker process.
                def socket_count():
                    count = 0
                    for fd in Path(f'/proc/{broker.pid}/fd').iterdir():
                        try:
                            count += os.readlink(fd).startswith('socket:')
                        except FileNotFoundError:
                            pass
                    return count
                saturated = False
                for _ in range(24):
                    peer = socket_api.socket(socket_api.AF_UNIX)
                    peer.settimeout(1)
                    peer.connect(str(endpoint))
                    held.append(peer)
                    time.sleep(.01)
                    if socket_count() >= 11:
                        time.sleep(.05)
                        if socket_count() >= 11:
                            saturated = True
                            break
                assert saturated, 'Could not observe the bounded broker queue at capacity'
                query(clean, success=False)
            finally:
                for peer in held:
                    peer.close()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                ready = subprocess.run([str(binary), 'query', str(native), str(clean)],
                                       capture_output=True, timeout=8)
                if ready.returncode == 0:
                    assert json.loads(ready.stdout)['detection'] is None
                    break
                time.sleep(.05)
            else:
                raise AssertionError('Broker did not recover after queued clients disconnected')
            checks['broker_bounded_queue_recovers_after_slow_clients'] = 'passed'
            broker.kill()
            broker.wait(timeout=5)
            assert (native / 'response.json').is_file()
            query(clean, success=False)
            broker = start_broker()
            assert query(infected)['sha256'] == hashlib.sha256(sample).hexdigest()
            checks['broker_crash_and_stale_socket_restart'] = 'passed'
            protected = watched / 'blocked-response'
            protected.write_bytes(sample)
            protected.chmod(0o600)
            mapped = os.open(protected, os.O_RDONLY)
            barrier = ReadBarrier(watched, broker.pid)

            def denied(path):
                before = barrier.denied
                try:
                    path.read_bytes()
                except PermissionError as error:
                    assert error.errno in (errno.EPERM, errno.EACCES)
                else:
                    raise AssertionError('Ordinary root open bypassed the kernel read barrier')
                barrier.check()
                assert barrier.denied > before

            denied(protected)
            try:
                for operation,fd,expected in [('open',None,10),('mmap',mapped,0)]:
                    nonce='7'*64
                    response=subprocess.run([str(binary),'probe-owned',str(os.getpid()),operation,str(protected),
                                             '-' if fd is None else str(fd),nonce],
                                            pass_fds=() if fd is None else (fd,),start_new_session=True,
                                            capture_output=True,text=True,timeout=6)
                    assert response.returncode==expected,(response.stdout,response.stderr)
                    output=[json.loads(line) for line in response.stdout.splitlines()]
                    assert output[0]['operation']==operation and output[0]['nonce']==nonce
                    assert output[1]['outcome']==('denied' if operation=='open' else 'allowed')
                # An OPEN_PERM barrier must not be counted as mmap protection.
                checks['operation_probes_distinguish_open_denial_from_existing_descriptor_mapping']='passed'
            finally:
                os.close(mapped)
            assert query(protected)['sha256'] == hashlib.sha256(sample).hexdigest()
            checks['kernel_barrier_denies_root_reads_but_allows_native_broker_verdicts'] = 'passed'
            protected_intent = dict(schema=1, command_id='4'*64, quarantine_id='4'*64,
                                    operation='quarantine', state=str(state), path=str(protected),
                                    roots=[str(watched)], sha256=hashlib.sha256(sample).hexdigest())
            result = mutate(protected_intent)
            assert result['outcome'] == 'completed' and not protected.exists()
            retained = state/'quarantine'/protected_intent['quarantine_id']
            assert retained.read_bytes() == sample
            barrier.check()
            checks['broker_quarantine_captures_blocked_file_without_direct_source_reads'] = 'passed'
            recovered = mutate(protected_intent, recover=True)
            for field in ('intent_sha256','path','outcome','cleanup_pending','finished_ms'):
                assert recovered[field] == result[field], (result,recovered)
            assert retained.read_bytes() == sample
            checks['blocked_file_quarantine_recovers_committed_identity_and_time'] = 'passed'
            restore = dict(protected_intent, command_id='5'*64, operation='restore',
                           verifier=dict(kind='retained'))
            restored = mutate(restore)
            assert restored['outcome'] == 'completed' and protected.exists()
            denied(protected)
            assert query(protected)['sha256'] == hashlib.sha256(sample).hexdigest()
            checks['broker_restore_publishes_bytes_while_ordinary_access_remains_blocked'] = 'passed'
            recovered = mutate(restore, recover=True)
            for field in ('intent_sha256','path','outcome','cleanup_pending','finished_ms'):
                assert recovered[field] == restored[field], (restored,recovered)
            denied(protected)
            checks['blocked_restore_recovery_does_not_require_reopening_the_source'] = 'passed'
            broker.kill();broker.wait(timeout=5)
            failed_intent = dict(protected_intent, command_id='6'*64, quarantine_id='6'*64)
            mutate(failed_intent, success=False)
            assert protected.exists() and not (state/'quarantine'/failed_intent['quarantine_id']).exists()
            denied(protected)
            broker = start_broker()
            assert query(protected)['sha256'] == hashlib.sha256(sample).hexdigest()
            assert mutate(failed_intent, recover=True)['outcome'] == 'unconfirmed'
            assert protected.exists()
            checks['broker_failure_never_falls_back_to_direct_reads_or_replays_unstarted_capture'] = 'passed'
            barrier.check()
            barrier.close();barrier = None
            daemon.terminate()
            daemon.wait(timeout=10)
            scan(clean, success=False)
            query(clean, success=False)
            checks['missing_scanner_never_returns_clean'] = 'passed'
            version = subprocess.run(['/usr/local/sbin/clamd', '--config-file', str(config), '--version'],
                                     capture_output=True, text=True, check=True).stdout.strip()
            return dict(schema=1, scope='Unix scan transport with real ClamAV; macOS authorization not executed',
                        native_macos_runtime_verified=False, engine=version,
                        host=platform.machine(), checks=checks,
                        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                        agent_sha256=hashlib.sha256(Path('/test/agent').read_bytes()).hexdigest())
        except Exception as error:
            raise RuntimeError(f'{error}\nClamAV log:\n{log_path.read_text()}') from error
        finally:
            if barrier is not None:
                barrier.close()
            if broker is not None and broker.poll() is None:
                broker.terminate()
                broker.wait(timeout=5)
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--engine-prefix', type=Path)
    parser.add_argument('--binary', type=Path, default=Path('target/release/athernex-endpoint-native'))
    parser.add_argument('--agent', type=Path, default=Path('target/release/athernex-endpoint'))
    parser.add_argument('--image', default='athernex-native-protection-fixture:local')
    parser.add_argument('--report', type=Path,
                        default=Path('.athernex/verification/native-adapter-scanner-validation.json'))
    args = parser.parse_args()
    if args.inside:
        print(json.dumps(inside(), sort_keys=True))
        return
    if args.engine_prefix is None:
        parser.error('--engine-prefix is required')
    engine = args.engine_prefix.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    agent = args.agent.resolve(strict=True)
    command = ['docker', 'run', '--init', '--rm', '--network', 'none', '--read-only',
               '--cap-drop', 'ALL', '--cap-add', 'SETUID', '--cap-add', 'SYS_ADMIN',
               '--security-opt', 'no-new-privileges',
               '--memory', '1g', '--pids-limit', '64',
               '--tmpfs', '/fixture:rw,nosuid,nodev,size=512m',
               '-v', f'{engine}:/usr/local:ro', '-v', f'{binary}:/test/adapter:ro', '-v', f'{agent}:/test/agent:ro',
               '-v', f'{Path(__file__).resolve()}:/test/verify.py:ro',
               '-v', f'{Path(__file__).with_name("native_read_barrier.py").resolve()}:/test/native_read_barrier.py:ro',
               args.image, 'python3', '/test/verify.py', '--inside']
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
