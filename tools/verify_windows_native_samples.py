#!/usr/bin/env python3
"""Check native Windows fixture signatures against real ClamAV on Linux.

The PE is scanned as data, never executed. This validates only the fixture's
positive/negative samples; it cannot establish native Windows prevention.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inside():
    root = Path('/fixture')
    clean_pe = Path('/test/windows-fixture.exe').read_bytes()
    if not clean_pe.startswith(b'MZ') or len(clean_pe) > 128 * 1024 * 1024:
        raise RuntimeError('Expected a Windows PE fixture below 128 MiB')
    nonce = secrets.token_hex(32).encode('ascii')
    # These are the native fixture's binary prefix, text and unique PE overlay.
    sample = b'\0\xff\x7f\0Athernex harmless synthetic Windows signature ' + nonce
    marked_pe = clean_pe + nonce
    samples = {'clean.bin': b'ordinary native validation content',
               'marked.bin': sample, 'clean.exe': clean_pe, 'marked.exe': marked_pe}
    for name, data in samples.items():
        (root / name).write_bytes(data)
    database = root / 'fixture.hsb'
    database.write_text(f'{digest(sample)}:{len(sample)}:AthernexNativeText\n'
                        f'{digest(marked_pe)}:{len(marked_pe)}:AthernexNativeExec\n')
    version = subprocess.run(['/usr/local/bin/clamscan', '--version'],
                             capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    result = subprocess.run(['/usr/local/bin/clamscan', '--no-summary', '-d', str(database),
                             '--max-filesize=128M', '--max-scansize=256M', '--alert-exceeds-max=yes',
                             *[str(root / name) for name in samples]],
                            capture_output=True, text=True, timeout=60)
    expected = {'clean.bin': 'OK', 'marked.bin': 'AthernexNativeText.UNOFFICIAL FOUND',
                'clean.exe': 'OK', 'marked.exe': 'AthernexNativeExec.UNOFFICIAL FOUND'}
    if result.returncode != 1 or any(f'{root / name}: {value}' not in result.stdout.splitlines()
                                    for name, value in expected.items()):
        raise RuntimeError(f'Fixture signatures did not produce their exact controls ({result.returncode}): '
                           + (result.stdout + result.stderr)[-16000:])
    print(json.dumps({'schema': 1, 'scope': 'Real Linux ClamAV scan of Windows native fixture samples',
                      'engine': version, 'probe_executable_sha256': digest(clean_pe),
                      'database_sha256': digest(database.read_bytes()),
                      'checks': {name: {'passed': True, 'sha256': digest(data), 'bytes': len(data),
                                        'result': expected[name]} for name, data in samples.items()},
                      'native_windows_execution': False, 'windows_prevention_verified': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--probe-executable', type=Path)
    parser.add_argument('--engine-prefix', type=Path)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--image', default='athernex-native-protection-fixture:local')
    parser.add_argument('--report', type=Path,
                        default=Path('.athernex/verification/windows-native-samples-validation.json'))
    args = parser.parse_args()
    if args.inside:
        inside()
        return
    if args.probe_executable is None or args.engine_prefix is None:
        parser.error('--probe-executable and --engine-prefix are required')
    executable = args.probe_executable.resolve(strict=True)
    engine = args.engine_prefix.resolve(strict=True)
    docker = ['docker', f'--host={args.docker_host}']
    image_id = subprocess.run([*docker, 'image', 'inspect', args.image, '--format', '{{.Id}}'],
                              capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    result = subprocess.run([*docker, 'run', '--init', '--rm', '--network', 'none', '--read-only',
                             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                             '--memory', '1g', '--cpus', '2', '--pids-limit', '32',
                             '--tmpfs', '/fixture:rw,nosuid,nodev,noexec,size=512m',
                             '-v', f'{engine}:/usr/local:ro',
                             '-v', f'{executable}:/test/windows-fixture.exe:ro',
                             '-v', f'{Path(__file__).resolve()}:/test/verify.py:ro',
                             image_id, 'python3', '/test/verify.py', '--inside'],
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr)[-16000:])
    report = json.loads(result.stdout)
    report['image'] = image_id
    if report['probe_executable_sha256'] != digest(executable.read_bytes()):
        raise RuntimeError('Probe executable changed during sample validation')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
