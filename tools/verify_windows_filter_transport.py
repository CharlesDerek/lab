#!/usr/bin/env python3
"""Verify Windows filter INSTREAM code against real ClamAV in an isolated Linux container.

This does not execute the Windows driver, Filter Manager APIs, process ownership
checks or file-open prevention. Those require a native Windows validation host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def inside():
    root = Path('/fixture')
    signatures = root / 'signatures'
    signatures.mkdir(mode=0o700)
    sample = b'Athernex native Windows stream signature fixture'
    (signatures / 'fixture.hdb').write_text(
        f'{hashlib.md5(sample).hexdigest()}:{len(sample)}:AthernexWindowsStreamFixture\n')
    config = root / 'clamd.conf'
    config.write_text(f'''Foreground yes
DatabaseDirectory {signatures}
TemporaryDirectory {root}
TCPSocket 3310
TCPAddr 127.0.0.1
MaxThreads 2
MaxQueue 4
StreamMaxLength 128M
MaxFileSize 128M
MaxScanSize 256M
AlertExceedsMax yes
ReadTimeout 5
CommandReadTimeout 5
''')
    with (root / 'clamd.log').open('w') as log:
        daemon = subprocess.Popen(['/usr/local/sbin/clamd', '--config-file', str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', 3310), timeout=1) as connection:
                        connection.sendall(b'zPING\0')
                        if connection.recv(32) != b'PONG\0':
                            raise RuntimeError('Unexpected real-engine readiness reply')
                    break
                except OSError:
                    if daemon.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('Real scanner startup failed: ' + (root / 'clamd.log').read_text())
                    time.sleep(.05)
            result = subprocess.run(['/test/native-tests', '--exact', 'windows_filter::tests::real_engine_whole_stream', '--ignored', '--nocapture'],
                                    env=dict(os.environ, ATHERNEX_NATIVE_SCANNER_ADDR='127.0.0.1:3310'), capture_output=True, text=True, timeout=20)
            if result.returncode or '1 passed; 0 failed' not in result.stdout:
                raise RuntimeError(result.stdout + result.stderr)
            print(json.dumps({'schema': 1, 'scope': 'Linux execution of Windows filter INSTREAM code with real ClamAV; native Windows prevention not executed',
                              'checks': {'clean_stream': 'passed', 'signature_matched_stream': 'passed', 'exact_sha256_and_length': 'passed'},
                              'test_binary_sha256': hashlib.sha256(Path('/test/native-tests').read_bytes()).hexdigest(),
                              'native_windows_runtime_verified': False}))
        finally:
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--engine-prefix', type=Path)
    parser.add_argument('--test-binary', type=Path)
    parser.add_argument('--image', default='athernex-native-protection-fixture:local')
    parser.add_argument('--report', type=Path, default=Path('.athernex/verification/windows-filter-build/real-scanner.json'))
    args = parser.parse_args()
    if args.inside:
        inside()
        return
    if args.engine_prefix is None:
        parser.error('--engine-prefix is required')
    binary = args.test_binary
    if binary is None:
        built = subprocess.run(['cargo', 'test', '--locked', '-p', 'athernex-endpoint-native', '--lib', '--no-run', '--message-format=json'],
                               env=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='2'), capture_output=True, text=True, check=True)
        for line in built.stdout.splitlines():
            message = json.loads(line)
            if message.get('reason') == 'compiler-artifact' and message['target']['name'] == 'athernex_endpoint_native' and message.get('executable'):
                binary = Path(message['executable'])
        if binary is None:
            raise RuntimeError('Cargo did not provide the native test binary')
    binary = binary.resolve(strict=True)
    engine = args.engine_prefix.resolve(strict=True)
    result = subprocess.run(['docker', 'run', '--init', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                             '--security-opt', 'no-new-privileges', '--memory', '512m', '--pids-limit', '32',
                             '--tmpfs', '/fixture:rw,nosuid,nodev,size=64m', '-v', f'{engine}:/usr/local:ro',
                             '-v', f'{binary}:/test/native-tests:ro', '-v', f'{Path(__file__).resolve()}:/test/verify.py:ro',
                             args.image, 'python3', '/test/verify.py', '--inside'], capture_output=True, text=True, timeout=50)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
