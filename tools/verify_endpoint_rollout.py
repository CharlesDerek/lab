#!/usr/bin/env python3
"""Verify real two-device rollout promotion, server restart and failed-canary containment.

Uses disposable controllers, loopback services and ephemeral signing keys. No
installed service, host collection or antivirus configuration is changed. A
scanner-version fixture supplies controlled health; this does not test AV detection.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from native_fixture import create_private_directory, private_fixture_root
import urllib.parse
import urllib.request
import urllib.error
import zipfile
from verify_endpoint_update import alive


def eventually(check, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.25)
    raise AssertionError('Fleet rollout condition timed out')


def main():
    if sys.platform == 'darwin':
        raise SystemExit('macOS automatic installation remains disabled')
    suffix = '.exe' if os.name == 'nt' else ''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=['agent', 'controller'], default='agent')
    parser.add_argument('--agent', type=Path, default=Path('target/release/athernex-endpoint' + suffix))
    parser.add_argument('--server', type=Path, default=Path('target/release/athernex-siem' + suffix))
    args = parser.parse_args()
    agent = args.agent.resolve()
    server_binary = args.server.resolve()
    controller_rollout = args.component == 'controller'
    health_field = 'controller_updates' if controller_rollout else 'updates'
    status_file = 'updates/controller/status.json' if controller_rollout else 'updates/status.json'
    target = ('windows' if os.name == 'nt' else 'linux') + '-' + {
        'amd64': 'x86_64', 'x86_64': 'x86_64', 'aarch64': 'aarch64', 'arm64': 'aarch64'
    }[platform.machine().lower()]
    processes = []
    states = []
    installations = []
    controllers = []
    original_configs = []
    original_agent_status = []
    with tempfile.TemporaryDirectory(prefix='athernex-rollout-fixture-') as temporary:
        root = private_fixture_root(temporary)
        controller = root / ('controller' + suffix)
        shutil.copy2(agent, controller)
        baseline = hashlib.sha256(agent.read_bytes()).hexdigest()
        catalog = root / 'catalog'
        catalog.mkdir()
        shutil.copy2(agent, catalog / ('athernex-endpoint-' + target + suffix))
        (catalog / (target + '.json')).write_text(json.dumps(dict(
            target=target, version='fixture', sha256=baseline, signing='development-unsigned')))
        public = subprocess.check_output([str(controller), 'release-keygen', str(root / 'keys')], text=True).strip()
        scanner_source = root / 'scanner.rs'
        scanner_source.write_text('fn main(){if std::env::args().nth(1).as_deref()==Some("--version"){println!("ClamAV controlled rollout-health fixture");}else{std::process::exit(64)}}')
        scanner = root / ('scanner-fixture' + suffix)
        subprocess.run(['rustc', '--edition=2021', str(scanner_source), '-o', str(scanner)], check=True, timeout=60)
        key = 'controlled-rollout-fixture-' + 'a' * 32
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        env = dict(os.environ, ATHERNEX_OPERATOR_KEY=key,
                   ATHERNEX_ENDPOINT_ARTIFACTS=str(catalog), ATHERNEX_ENDPOINT_RELEASES=str(root / 'releases'))
        env.pop('ATHERNEX_PUBLIC_ORIGIN', None)

        def request(path, body=None):
            headers = {'Authorization': 'Bearer ' + key}
            data = None
            if body is not None:
                data = urllib.parse.urlencode(body).encode()
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            try:
                with urllib.request.urlopen(urllib.request.Request(origin + path, data, headers), timeout=10) as response:
                    return response.read()
            except urllib.error.HTTPError as error:
                raise AssertionError(f'HTTP {error.code} {path}: {error.read(8192).decode(errors="replace")}') from error

        def online():
            try:
                return request('/healthz')
            except OSError:
                return False

        def spawn(args, name):
            with (root / (name + '-' + str(time.monotonic_ns()) + '.log')).open('w') as log:
                child = subprocess.Popen(list(map(str, args)), env=env, stdout=log, stderr=log)
            processes.append(child)
            return child

        def start_server():
            child = spawn([server_binary, '--no-journal', '--db', root / 'ledger.db', '--port', port], 'server')
            eventually(online, 20)
            return child

        def csrf():
            return re.search(r"name=csrf value='([^']+)'", request('/endpoints').decode()).group(1)

        def publish(binary, sequence, version):
            manifest = root / f'release-{sequence}.json'
            subprocess.run([str(controller), 'release-sign', str(root / 'keys/release.pk8'), str(binary),
                            version, 'stable', str(sequence), str(int(time.time()*1000) + 1_800_000), str(manifest)], check=True)
            return subprocess.check_output([str(controller), 'release-publish', str(manifest), str(binary), public, str(root / 'releases')], text=True).strip()

        def record(identifier):
            return json.loads(request('/api/endpoint-rollouts/' + identifier))

        def propose(release_id, name):
            body = dict(csrf=csrf(), op='propose', name=name, release_id=release_id,
                        component=args.component, batch_size=1, observe_secs=60, start_delay_minutes=0, deadline_minutes=15)
            body.update({'target_' + ids[0]: 'canary', 'target_' + ids[1]: 'later'})
            request('/endpoints/rollouts/action', body)
            rollout = json.loads(request('/api/endpoint-rollouts'))[0]
            assert rollout['state'] == 'pending'
            assert rollout['plan'].get('component', 'agent') == args.component
            assert all(m['deployment_id'] is None for m in rollout['members'])
            request('/endpoints/rollouts/action', dict(csrf=csrf(), op='approve', id=rollout['id'], plan_hash=rollout['plan_hash']))
            return rollout['id']

        def state_is(identifier, expected):
            current = record(identifier)
            assert current['state'] not in {'failed', 'expired', 'cancelled'} - {expected}, current
            return current if current['state'] == expected else False

        try:
            server = start_server()
            ids = [f'{i:064x}' for i in [1, 2]]
            for index, endpoint in enumerate(ids):
                state = root / ('state-' + str(index))
                create_private_directory(state)
                states.append(state)
                installed = root / ('installed-' + str(index) + suffix)
                shutil.copy2(agent, installed)
                installed.chmod(0o700)
                installations.append(installed)
                archive = request('/endpoints/installer', dict(csrf=csrf(), target=target, server=origin + '/'))
                with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                    bootstrap = json.loads(bundle.read('bootstrap.json'))
                bootstrap_path = root / f'bootstrap-{index}.json'
                bootstrap_path.write_text(json.dumps(bootstrap))
                config = dict(server=origin+'/', endpoint_id=endpoint, credential=f'{index+10:064x}',
                              enrollment_token=bootstrap['enrollment_token'], scanner=str(scanner),
                              updater=str(root/'no-updater'), scan_roots=[str(root)], allow_scripts=False,
                              updates=dict(managed=True, automatic=True, public_key=public, channel='stable',
                                           install_path=str(installed), minimum_sequence=0, allow_unsigned_native=True))
                if controller_rollout:
                    managed_controller = root / ('controller-' + str(index) + suffix)
                    launcher = root / ('launcher-' + str(index) + suffix)
                    for binary in [managed_controller, launcher]:
                        shutil.copy2(agent, binary)
                        binary.chmod(0o700)
                    controllers.append(managed_controller)
                    config['updates'].update(managed=False, automatic=False, controller_managed=True,
                                             controller_automatic=True, controller_path=str(managed_controller),
                                             launcher_path=str(launcher))
                (state/'config.json').write_text(json.dumps(config))
                (state/'config.json').chmod(0o600)
                subprocess.run([str(installed), 'enroll', str(bootstrap_path), str(state)], check=True, stdout=subprocess.DEVNULL)
                original_configs.append((state/'config.json').read_bytes())
                if controller_rollout:
                    original_agent_status.append(json.loads(subprocess.check_output([str(controller), 'update-status', str(state)], text=True)))
                    spawn([launcher, 'launch', state, managed_controller, installed], f'launcher-{index}')
                else:
                    spawn([controller, 'supervise', state, installed], f'controller-{index}')
            eventually(lambda: all(e['health'].get(health_field, {}).get('supervised') for e in json.loads(request('/api/endpoints'))['endpoints']), 30)
            version = json.loads(subprocess.check_output([str(agent), 'release-check', 'a'*64], text=True))['version']
            candidate = root / ('candidate' + suffix)
            candidate.write_bytes(agent.read_bytes() + b'\nDistinct signed rollout fixture\n')
            candidate.chmod(0o700)
            candidate_hash = hashlib.sha256(candidate.read_bytes()).hexdigest()
            release_id = publish(candidate, 1, version)
            identifier = propose(release_id, 'Real two-device promotion')
            eventually(lambda: record(identifier)['members'][0]['deployment_state'] == 'installed')
            before = record(identifier)
            assert before['members'][1]['deployment_id'] is None
            first_deployment = before['members'][0]['deployment_id']
            server.kill()
            server.wait(timeout=10)
            server = start_server()
            assert record(identifier)['members'][0]['deployment_id'] == first_deployment
            print('Canary installed; server restart preserved pending health observation.', flush=True)
            promoted = eventually(lambda: (current if current['members'][1]['deployment_id'] else False)
                                  if (current := record(identifier)) else False)
            canary = promoted['members'][0]
            assert canary['last_healthy_ms'] - canary['healthy_since_ms'] >= 60_000
            done = eventually(lambda: state_is(identifier, 'completed'))
            assert all(m['deployment_state'] == 'installed' and m['last_healthy_ms']-m['healthy_since_ms'] >= 60_000 for m in done['members'])
            assert len(json.loads(request('/api/endpoint-updates'))) == 2
            for index, state in enumerate(states):
                status = json.loads((state/status_file).read_text())
                assert status['installed']['release']['sequence'] == 1 and status['transaction'] is None
                updated_binary = controllers[index] if controller_rollout else installations[index]
                assert hashlib.sha256(updated_binary.read_bytes()).hexdigest() == candidate_hash
                if controller_rollout:
                    assert hashlib.sha256(installations[index].read_bytes()).hexdigest() == baseline
                    assert (state/'config.json').read_bytes() == original_configs[index]
                    assert json.loads(subprocess.check_output([str(controller), 'update-status', str(state)], text=True)) == original_agent_status[index]
            print('Both real endpoints installed; promotion required observed healthy windows.', flush=True)

            bad_source = root/'unhealthy.rs'
            bad_source.write_text(r'''
use std::env;
fn main(){let args:Vec<String>=env::args().collect();
if args.get(1).map(String::as_str)==Some("release-check") {
 println!("{{\"challenge\":\"{}\",\"protocol\":1,\"target\":\"{}-{}\",\"version\":\"rollout-bad\",\"controller_protocol\":1}}",args[2],env::consts::OS,env::consts::ARCH);
}else{std::process::exit(42)}}
''')
            bad = root/('unhealthy'+suffix)
            subprocess.run(['rustc', '--edition=2021', str(bad_source), '-o', str(bad)], check=True, timeout=60)
            failing = propose(publish(bad, 2, 'rollout-bad'), 'Failed canary containment')
            failed = eventually(lambda: state_is(failing, 'failed'))
            assert failed['members'][0]['deployment_state'] == 'rolled_back'
            assert failed['members'][1]['deployment_id'] is None
            assert len(json.loads(request('/api/endpoint-updates'))) == 3
            assert json.loads((states[1]/status_file).read_text())['highwater'] == 1
            assert hashlib.sha256((controllers[0] if controller_rollout else installations[0]).read_bytes()).hexdigest() == candidate_hash
            if controller_rollout:
                for index, state in enumerate(states):
                    assert hashlib.sha256(installations[index].read_bytes()).hexdigest() == baseline
                    assert (state/'config.json').read_bytes() == original_configs[index]
                    assert json.loads(subprocess.check_output([str(controller), 'update-status', str(state)], text=True)) == original_agent_status[index]
            print(json.dumps(dict(component=args.component, reviewed_exact_membership='passed', canary_health_gate='passed',
                                  server_restart_without_duplicate_deployments='passed',
                                  real_installation_on_both_devices='passed',
                                  agent_preserved_during_controller_replacement='passed' if controller_rollout else 'not applicable',
                                  final_group_health_window='passed', failed_canary_stops_remaining_devices='passed'), indent=2))
        except Exception:
            for log in root.glob('*.log'):
                print(log.name + ':\n' + log.read_text(errors='replace')[-8000:], file=sys.stderr)
            raise
        finally:
            for child in reversed(processes):
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
            for state in states:
                lease = state/'supervisor/lease.json'
                if lease.exists() and (pid := json.loads(lease.read_text()).get('child_pid')):
                    eventually(lambda: not alive(pid), 10)


if __name__ == '__main__':
    main()
