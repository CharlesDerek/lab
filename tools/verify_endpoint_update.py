#!/usr/bin/env python3
"""Exercise signed replacement and forced-crash recovery with disposable files.

No installed service or signing credential is used. A temporary test key signs
the current agent and an intentionally unhealthy Rust readiness fixture.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def eventually(check, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.05)
    raise AssertionError('Update verification condition did not become true')


def alive(pid):
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            assert kernel.GetExitCodeProcess(handle, ctypes.byref(code))
            return code.value == 259
        finally:
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel.CloseHandle(handle)
    stat = Path(f'/proc/{pid}/stat')
    if Path('/proc').is_dir():
        try:
            return stat.read_text().rsplit(')', 1)[1].split()[0] != 'Z'
        except (FileNotFoundError, ProcessLookupError):
            return False
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True, check=False)
    return result.returncode == 0 and result.stdout.strip() and not result.stdout.strip().startswith('Z')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path, default=Path('target/release/athernex-endpoint' + ('.exe' if os.name == 'nt' else '')))
    parser.add_argument('--server', type=Path, default=Path('target/release/athernex-siem' + ('.exe' if os.name == 'nt' else '')))
    parser.add_argument('--component', choices=['agent', 'controller'], default='agent')
    args = parser.parse_args()
    prefix = 'controller-' if args.component == 'controller' else ''
    with tempfile.TemporaryDirectory(prefix='athernex-update-fixture-') as directory:
        root = Path(directory).resolve()
        agent = root / ('controller.exe' if os.name == 'nt' else 'controller')
        shutil.copy2(args.agent, agent)
        installed = root / ('installed-agent.exe' if os.name == 'nt' else 'installed-agent')
        shutil.copy2(agent, installed)
        installed.chmod(0o700)
        baseline = hashlib.sha256(installed.read_bytes()).hexdigest()
        managed = installed
        if args.component == 'controller':
            managed = root / ('managed-agent.exe' if os.name == 'nt' else 'managed-agent')
            shutil.copy2(agent, managed)
            managed.chmod(0o700)
        state = root / 'state'
        state.mkdir(mode=0o700)
        child = None
        applying = None
        log = None
        checks = {}

        def run(*arguments, ok=True, env=None):
            arguments = list(arguments)
            if arguments[0].startswith('update-'):
                arguments[0] = prefix + arguments[0]
            result = subprocess.run([str(agent), *map(str, arguments)], capture_output=True, text=True,
                                    timeout=40, env=env)
            assert (result.returncode == 0) == ok, result.stderr + result.stdout
            return result.stdout

        def sign(binary, sequence, version, expires=None):
            manifest = root / f'release-{sequence}-{time.monotonic_ns()}.json'
            run('release-sign', root / 'keys/release.pk8', binary, version, 'stable', sequence,
                expires if expires is not None else int(time.time() * 1000) + 120_000, manifest)
            return manifest

        def status():
            return json.loads(run('update-status', state))

        try:
            public = run('release-keygen', root / 'keys').strip()
            info = json.loads(run('release-check', 'a' * 64))
            config = dict(server='http://127.0.0.1:1/', endpoint_id='b' * 64, credential='c' * 64,
                          scanner=str(agent), updater=str(agent), scan_roots=[str(root)], allow_scripts=False,
                          updates=dict(public_key=public, channel='stable', install_path=str(managed),
                                       minimum_sequence=0, allow_unsigned_native=True))
            if args.component == 'controller':
                config['updates']['controller_path'] = str(installed)
            (state / 'config.json').write_text(json.dumps(config))
            (state / 'config.json').chmod(0o600)
            manifest = sign(agent, 1, info['version'])
            altered = root / 'altered'
            altered.write_bytes(agent.read_bytes() + b'altered fixture')
            run('update-stage', state, manifest, altered, ok=False)
            assert status()['highwater'] == 0
            checks['altered_release_rejected_before_sequence_admission'] = 'passed'
            run('update-stage', state, manifest, agent)
            run('update-stage', state, manifest, agent)
            checks['signed_staging_retry_is_idempotent'] = 'passed'

            log = (root / 'agent.log').open('w')
            child = subprocess.Popen([str(managed), 'run', str(state)], stdout=log, stderr=log)
            eventually(lambda: (state / 'endpoint.sqlite3').exists())
            output = subprocess.run([str(agent), prefix + 'update-apply', str(state)], capture_output=True, text=True, timeout=10)
            assert output.returncode != 0 and 'Stop the endpoint service' in output.stderr, output.stderr
            child.kill(); child.wait(timeout=10); child = None
            checks['running_agent_blocks_replacement'] = 'passed'
            run('update-apply', state)
            assert status()['installed']['release']['sequence'] == 1
            assert json.loads(subprocess.check_output([str(installed), 'release-check', 'd' * 64], text=True))['challenge'] == 'd' * 64
            checks['signed_binary_installed_and_executed'] = 'passed'
            if args.component == 'controller':
                child = subprocess.Popen([str(installed), 'supervise', str(state), str(managed)], stdout=log, stderr=log)
                lease_file = state / 'supervisor/lease.json'
                lease = eventually(lambda: json.loads(lease_file.read_text()) if lease_file.exists() and json.loads(lease_file.read_text()).get('child_pid') else None)
                managed_pid = lease['child_pid']
                assert child.poll() is None and alive(managed_pid)
                for command in ['controller-update-apply', 'controller-update-recover']:
                    output = subprocess.run([str(agent), command, str(state)], capture_output=True, text=True, timeout=10)
                    assert output.returncode != 0 and 'Stop the endpoint controller' in output.stderr, output.stderr
                child.kill(); child.wait(timeout=10); child = None
                eventually(lambda: not alive(managed_pid))
                checks['updated_controller_supervises_and_excludes_live_replacement'] = 'passed'
                wrong = subprocess.run([str(agent), 'supervise', str(state), str(managed)], capture_output=True, text=True, timeout=10)
                assert wrong.returncode != 0 and 'confirmed release ledger' in wrong.stderr, wrong.stderr
                checks['wrong_controller_entrypoint_rejected'] = 'passed'

            binaries = root / 'updated-fleet'
            binaries.mkdir()
            suffix = '.exe' if os.name == 'nt' else ''
            shutil.copy2(installed, binaries / ('athernex-endpoint' + suffix))
            shutil.copy2(args.server, binaries / ('athernex-siem' + suffix))
            subprocess.run([sys.executable, str(Path(__file__).with_name('verify_endpoint_fleet.py')),
                            '--bin-dir', str(binaries)], check=True, timeout=90, stdout=subprocess.DEVNULL)
            checks['updated_binary_completes_enrollment_response_and_recovery'] = 'passed'

            # This real executable passes preflight but fails or stalls once it
            # occupies the installed path. It is never installed on the host.
            source = root / 'unhealthy.rs'
            source.write_text(r'''
use std::{env, fs, thread, time::Duration};
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "release-check" { std::process::exit(2); }
    let installed = env::current_exe().unwrap().file_name().unwrap().to_string_lossy().starts_with("installed-agent");
    let mode = env::var("ATHERNEX_UPDATE_FIXTURE_MODE").unwrap_or_default();
    if installed || mode == "preflight_hold" {
        if mode == "hold" || mode == "preflight_hold" {
            fs::write(env::var("ATHERNEX_UPDATE_FIXTURE_MARKER").unwrap(), std::process::id().to_string()).unwrap();
            loop { thread::sleep(Duration::from_secs(1)); }
        }
        println!("invalid fixture readiness");
    } else {
        println!("{{\"challenge\":\"{}\",\"protocol\":1,\"target\":\"{}-{}\",\"version\":\"fixture\",\"controller_protocol\":1}}", args[2], env::consts::OS, env::consts::ARCH);
    }
}
''')
            unhealthy = root / ('unhealthy.exe' if os.name == 'nt' else 'unhealthy')
            subprocess.run(['rustc', '--edition=2021', str(source), '-o', str(unhealthy)], check=True, timeout=60)
            failed = sign(unhealthy, 2, 'fixture')
            run('update-stage', state, failed, unhealthy)
            run('update-apply', state, ok=False)
            assert status()['last_result'] == 'rolled_back'
            assert status()['highwater'] == 2
            assert hashlib.sha256(installed.read_bytes()).hexdigest() == baseline
            checks['failed_post_replacement_check_rolls_back'] = 'passed'
            run('update-stage', state, failed, unhealthy, ok=False)
            checks['failed_release_cannot_lower_or_reuse_sequence'] = 'passed'

            interrupted = sign(unhealthy, 3, 'fixture')
            run('update-stage', state, interrupted, unhealthy)
            marker = root / 'readiness.pid'
            with (root / 'apply.log').open('w') as output:
                applying = subprocess.Popen([str(agent), prefix + 'update-apply', str(state)], stdout=output, stderr=output,
                                            env=dict(os.environ, ATHERNEX_UPDATE_FIXTURE_MODE='hold',
                                                     ATHERNEX_UPDATE_FIXTURE_MARKER=str(marker)))
                eventually(lambda: marker.exists() and marker.read_text().strip())
                pid = int(marker.read_text())
                assert alive(pid) and applying.poll() is None
                assert status()['transaction'] is not None
                applying.kill(); applying.wait(timeout=10); applying = None
                if os.name == 'nt' or Path('/proc').is_dir():
                    eventually(lambda: not alive(pid))
                    checks['updater_death_terminates_probe'] = 'passed'
                else:
                    # macOS has no PDEATHSIG. Clean up this deliberately hung
                    # fixture; supervisor/job integration remains a release gate.
                    os.kill(pid, 9)
            run('update-recover', state)
            run('update-recover', state)
            assert status()['last_result'] == 'rolled_back' and status()['highwater'] == 3
            assert hashlib.sha256(installed.read_bytes()).hexdigest() == baseline
            assert not list(root.glob('.athernex-backup-*'))
            checks['forced_crash_recovery_is_idempotent_and_preserves_sequence'] = 'passed'

            before_swap = sign(unhealthy, 4, 'fixture')
            run('update-stage', state, before_swap, unhealthy)
            marker = root / 'preflight.pid'
            with (root / 'preflight.log').open('w') as output:
                applying = subprocess.Popen([str(agent), prefix + 'update-apply', str(state)], stdout=output, stderr=output,
                                            env=dict(os.environ, ATHERNEX_UPDATE_FIXTURE_MODE='preflight_hold',
                                                     ATHERNEX_UPDATE_FIXTURE_MARKER=str(marker)))
                eventually(lambda: marker.exists() and marker.read_text().strip())
                pid = int(marker.read_text())
                assert hashlib.sha256(installed.read_bytes()).hexdigest() == baseline
                applying.kill(); applying.wait(timeout=10); applying = None
                if args.component == 'controller':
                    refused = subprocess.run([str(installed), 'supervise', str(state), str(managed)], capture_output=True, text=True, timeout=10)
                    assert refused.returncode != 0 and 'Stop' not in refused.stderr and 'interrupted controller update' in refused.stderr, refused.stderr
                    checks['pending_controller_transaction_blocks_startup'] = 'passed'
                if os.name == 'nt' or Path('/proc').is_dir():
                    eventually(lambda: not alive(pid))
                else:
                    os.kill(pid, 9)
            run('update-recover', state)
            assert status()['highwater'] == 4
            assert not list(root.glob('.athernex-next-*'))
            assert not list(root.glob('.athernex-backup-*'))
            checks['preflight_crash_recovers_without_orphaned_candidate'] = 'passed'

            expires = int(time.time() * 1000) + 2000
            expired = sign(agent, 5, info['version'], expires)
            time.sleep(max(0, expires / 1000 - time.time()) + .1)
            run('update-stage', state, expired, agent, ok=False)
            assert status()['highwater'] == 4
            checks['expired_release_rejected'] = 'passed'
            if args.component == 'controller':
                agent_status = json.loads(subprocess.check_output([str(agent), 'update-status', str(state)], text=True))
                assert agent_status['highwater'] == 0 and agent_status['installed'] is None
                assert hashlib.sha256(managed.read_bytes()).hexdigest() == baseline
                checks['controller_upgrade_preserves_agent_bytes_and_ledger'] = 'passed'
            print(json.dumps(checks, indent=2))
        finally:
            for process in [child, applying]:
                if process is not None and process.poll() is None:
                    process.kill(); process.wait(timeout=10)
            if log is not None:
                log.close()


if __name__ == '__main__':
    main()
