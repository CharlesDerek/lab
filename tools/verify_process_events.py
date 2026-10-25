#!/usr/bin/env python3
"""Run the explicit kernel-event tests from Cargo's compiled test manifest.

The tests briefly subscribe to the real Linux process connector and report only
controlled children. No kernel rules, services or global buffer limits change.
--image runs in a disposable container sharing the initial PID/network namespaces
required by CN_PROC; all writable test state stays in a private bounded tmpfs.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile


TESTS = [
    ('unit', 'telemetry::process_events::native_test::short_lived_kernel_events_survive_stalled_transport_restart_and_exact_replay'),
    ('unit', 'telemetry::process_events::linux::tests::kernel_socket_overflow_is_reported_without_silently_claiming_complete_capture'),
    ('process', 'native_events_continue_during_stalled_heartbeat_and_expose_agent_crash_gap'),
]


def run_local_test(command, environment):
    # Own the process group so an interrupted test cannot leave its agent alive.
    child = subprocess.Popen(command, env=environment, start_new_session=True)
    try:
        result = child.wait(timeout=120)
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=10)
        raise
    if result != 0:
        raise subprocess.CalledProcessError(result, command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True,
                        help='cargo test -p athernex-endpoint --lib --test continuous_telemetry --no-run --message-format=json output')
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--image', help='Existing Docker image with Python 3; no image is pulled')
    args = parser.parse_args()
    paths = {'agent': args.agent.resolve(strict=True)}
    for line in args.manifest.read_text().splitlines():
        item = json.loads(line)
        if item.get('reason') != 'compiler-artifact' or not item.get('executable'):
            continue
        target = item['target']['name']
        key = {'athernex_endpoint': 'unit', 'continuous_telemetry': 'process'}.get(target)
        if key and item.get('profile', {}).get('test'):
            paths[key] = Path(item['executable']).resolve(strict=True)
    if set(paths) != {'agent', 'unit', 'process'}:
        parser.error('Manifest must contain the endpoint library and continuous_telemetry test executables')
    if shutil.disk_usage(tempfile.gettempdir()).free < 512 * 1024**2:
        parser.error('Temporary storage needs at least 512 MiB free')
    memory = Path('/proc/meminfo')
    if memory.exists() and int(re.search(r'^MemAvailable:\s+(\d+)', memory.read_text(), re.MULTILINE)[1]) < 2 * 1024**2:
        parser.error('At least 2 GiB available host memory required')
    with tempfile.TemporaryDirectory(prefix='athernex-process-events-') as temporary:
        root = Path(temporary)
        snapshots = {}
        for key, path in paths.items():
            copy = root/key
            shutil.copy2(path, copy)
            subprocess.run(['strip', str(copy)], check=True, timeout=30)
            snapshots[key] = copy
        print(json.dumps(dict(validation_inputs={key: hashlib.sha256(path.read_bytes()).hexdigest()
                                                 for key, path in snapshots.items()},
                              mode='container' if args.image else 'local', tests=[name for _, name in TESTS])), flush=True)
        if not args.image:
            for key in ('unit', 'process'):
                listing = subprocess.run([str(snapshots[key]), '--ignored', '--list'],
                                         check=True, capture_output=True, text=True, timeout=30).stdout.splitlines()
                for kind, name in TESTS:
                    if kind == key and name + ': test' not in listing:
                        raise RuntimeError(f'Required native test is absent: {name}')
            for key, name in TESTS:
                run_local_test([str(snapshots[key]), '--ignored', '--exact', name, '--nocapture'],
                               {**os.environ, 'ATHERNEX_NATIVE_EVENT_AGENT': str(snapshots['agent'])})
            return
        cid = root/'container.cid'
        command = ['docker', '--host=unix:///var/run/docker.sock', 'run', '--pull', 'never', '--rm', '--cidfile', str(cid),
                   '--read-only', '--pid', 'host', '--network', 'host', '--userns', 'host',
                   '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--security-opt', 'no-new-privileges',
                   '--memory', '1g', '--memory-swap', '1g', '--cpus', '2', '--pids-limit', '128',
                   '--log-driver', 'none', '--ulimit', 'core=0',
                   '--tmpfs', '/fixture:rw,exec,nosuid,nodev,size=384m,mode=0700', '--env', 'TMPDIR=/fixture',
                   '--env', 'ATHERNEX_NATIVE_EVENT_AGENT=/test/agent']
        for key, path in snapshots.items():
            command += ['--mount', f'type=bind,source={path},target=/test/{key},readonly']
        script = fixture_script()
        command += [args.image, 'python3', '-u', '-c', script]
        try:
            subprocess.run(command, check=True, timeout=390)
        finally:
            if cid.exists() and re.fullmatch(r'[0-9a-f]{64}', identifier := cid.read_text().strip()):
                subprocess.run(['docker', '--host=unix:///var/run/docker.sock', 'rm', '-f', identifier],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)


def fixture_script():
    script = "if not __debug__:\n    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')\nimport subprocess\n"
    for key in ('unit', 'process'):
        script += f'listing = subprocess.run({["/test/"+key,"--ignored","--list"]!r},check=True,capture_output=True,text=True,timeout=30).stdout.splitlines()\n'
        for kind, name in TESTS:
            if kind == key:
                script += f'assert {name + ": test"!r} in listing, {"Required native test is absent: " + name!r}\n'
    for key, name in TESTS:
        script += f'subprocess.run({["/test/"+key,"--ignored","--exact",name,"--nocapture"]!r},check=True,timeout=120)\n'
    return script


if __name__ == '__main__':
    main()
