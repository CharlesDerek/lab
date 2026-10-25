#!/usr/bin/env python3
"""Verify real conntrack collection inside disposable private network namespaces.

The endpoint only reads netfilter. These tests install tracking rules inside each
private test namespace, exercise local IPv4/IPv6 TCP/UDP, and delete only those
private tracker entries. Host networking, firewall rules and sysctls are untouched.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

TESTS = [
    'telemetry::network_events::native_test::missing_or_removed_tracking_hooks_cannot_report_healthy_coverage',
    'telemetry::network_events::native_test::real_socket_overflow_is_reported_as_a_coverage_gap',
    'telemetry::network_events::native_test::native_flows_survive_stalled_agent_transport_crash_delivery_and_exact_replay',
]
SOAK = 'telemetry::network_events::native_test::soak_test::native_sustained_delivery_outage_and_restart_are_measured'
DOCKER = ['docker', '--host=unix:///var/run/docker.sock']


def fixture_script(name, timeout):
    # This interpreter runs inside Docker and may have different startup flags.
    return '\n'.join([
        'if not __debug__:',
        "    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')",
        'from pathlib import Path', 'import subprocess',
        'assert "docker-init" in Path("/proc/1/comm").read_text()',
        'assert sorted(p.name for p in Path("/sys/class/net").iterdir()) == ["lo"]',
        'mounts = Path("/proc/mounts").read_text().splitlines()',
        'assert any(line.split()[1:3] == ["/fixture", "tmpfs"] for line in mounts)',
        f'subprocess.run({["/test/unit", "--ignored", "--exact", name, "--nocapture"]!r}, check=True, timeout={timeout})',
    ])


def run_fixture(command, timeout, diagnostics):
    # Keep complete native output in a private local file, never in CI output or
    # the measured report artifact. File-backed capture also bounds Python memory.
    with tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8', dir=diagnostics,
                                     prefix='native-', suffix='.log', delete=False) as output:
        try:
            subprocess.run(command, check=True, timeout=timeout,
                           stdout=output, stderr=subprocess.STDOUT)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            raise RuntimeError('Native network fixture failed; diagnostics retained privately') from None
        output.seek(0)
        reports = []
        try:
            for line in output:
                if line.startswith('ATHERNEX_NETWORK_SOAK_REPORT='):
                    reports.append(json.loads(line.partition('=')[2]))
        except (ValueError, UnicodeError):
            raise RuntimeError('Native network fixture produced an invalid measured report') from None
        return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True,
                        help='cargo test -p athernex-endpoint --lib --no-run --message-format=json output')
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--image', default='athernex-native-network-fixture:local')
    parser.add_argument('--soak-seconds', type=int,
                        help='Run only the measured load check; 60–600 seconds per online/recovery phase, plus a 30-second outage')
    parser.add_argument('--soak-rate', type=int, default=8,
                        help='Target flows/second in the load check (1–16; default 8)')
    parser.add_argument('--report', type=Path,
                        help='Save a successful measured load report with exact executable/image hashes')
    args = parser.parse_args()
    if args.soak_seconds is not None and not 60 <= args.soak_seconds <= 600:
        parser.error('--soak-seconds must be between 60 and 600')
    if not 1 <= args.soak_rate <= 16 or (args.report and args.soak_seconds is None):
        parser.error('--soak-rate must be between 1 and 16; --report requires --soak-seconds')
    tests = [SOAK] if args.soak_seconds is not None else TESTS
    paths = {'agent': args.agent.resolve(strict=True)}
    test_profile = None
    for line in args.manifest.read_text().splitlines():
        item = json.loads(line)
        if (item.get('reason') == 'compiler-artifact' and item.get('executable')
                and item['target']['name'] == 'athernex_endpoint' and item.get('profile', {}).get('test')):
            paths['unit'] = Path(item['executable']).resolve(strict=True)
            test_profile = item['profile']
    if set(paths) != {'agent', 'unit'}:
        parser.error('Manifest must contain the compiled endpoint library test executable')
    if args.soak_seconds is not None and test_profile.get('opt_level') == '0':
        parser.error('Measured load requires an optimized test server; build the manifest with cargo test --release')
    if shutil.disk_usage(tempfile.gettempdir()).free < 512 * 1024**2:
        parser.error('Temporary storage needs at least 512 MiB free')
    image = subprocess.run(DOCKER + ['image', 'inspect', args.image, '--format', '{{.Id}}'],
                           check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    with tempfile.TemporaryDirectory(prefix='athernex-network-events-') as temporary:
        root = Path(temporary)
        for key, path in paths.items():
            shutil.copy2(path, root/key)
            subprocess.run(['strip', str(root/key)], check=True, timeout=30)
        listing = subprocess.run([str(root/'unit'), '--ignored', '--list'], check=True,
                                 capture_output=True, text=True, timeout=30).stdout.splitlines()
        for name in tests:
            if name + ': test' not in listing:
                raise RuntimeError(f'Required native test is absent: {name}')
        inputs = dict(validation_inputs={key: hashlib.sha256((root/key).read_bytes()).hexdigest()
                                         for key in paths}, image=image, tests=tests, test_profile=test_profile)
        # mkdtemp creates a mode-0700 directory outside the selected report path.
        # It intentionally survives success/failure for local diagnosis only.
        diagnostics = Path(tempfile.mkdtemp(prefix='athernex-network-diagnostics-'))
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=diagnostics,
                                         prefix='inputs-', suffix='.json', delete=False) as saved_inputs:
            json.dump(inputs, saved_inputs)
            saved_inputs.write('\n')
        print(f'Native network validation: {len(tests)} tests', flush=True)
        for index, name in enumerate(tests):
            cid = root/f'container-{index}.cid'
            timeout = 2 * args.soak_seconds + 180 if args.soak_seconds is not None else 120
            # Isolation guards execute before test code is allowed to alter policy.
            script = fixture_script(name, timeout)
            command = DOCKER + ['run', '--pull', 'never', '--rm', '--init', '--cidfile', str(cid),
                '--read-only', '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                '--security-opt', 'no-new-privileges', '--memory', '1g', '--memory-swap', '1g',
                '--cpus', '2', '--pids-limit', '128', '--log-driver', 'none', '--ulimit', 'core=0',
                '--sysctl', 'net.netfilter.nf_conntrack_acct=1',
                '--tmpfs', '/fixture:rw,exec,nosuid,nodev,size=384m,mode=0700',
                '--tmpfs', '/run:rw,nosuid,nodev,size=8m,mode=0755',
                '--env', 'TMPDIR=/fixture', '--env', 'ATHERNEX_NETWORK_FIXTURE=private-container',
                '--env', 'ATHERNEX_NATIVE_EVENT_AGENT=/test/agent']
            if args.soak_seconds is not None:
                command += ['--env', f'ATHERNEX_NETWORK_SOAK_SECONDS={args.soak_seconds}',
                            '--env', f'ATHERNEX_NETWORK_SOAK_RATE={args.soak_rate}']
            for key in paths:
                command += ['--mount', f'type=bind,source={root/key},target=/test/{key},readonly']
            command += [image, 'python3', '-u', '-c', script]
            try:
                reports = run_fixture(command, timeout+30, diagnostics)
                if args.soak_seconds is not None:
                    if len(reports) != 1 or reports[0].get('passed') is not True:
                        raise RuntimeError('Successful load check did not produce exactly one measured report')
                    if args.report:
                        args.report.parent.mkdir(parents=True, exist_ok=True)
                        args.report.write_text(json.dumps(dict(inputs=inputs, measurement=reports[0]), indent=2)+'\n')
            except Exception:
                print(f'Native network test {index+1}/{len(tests)}: failed', flush=True)
                raise
            else:
                print(f'Native network test {index+1}/{len(tests)}: passed', flush=True)
            finally:
                if cid.exists() and re.fullmatch(r'[0-9a-f]{64}', identifier := cid.read_text().strip()):
                    subprocess.run(DOCKER + ['rm', '-f', identifier], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=False, timeout=30)
        print(f'Native network validation passed: {len(tests)} tests', flush=True)


if __name__ == '__main__':
    main()
