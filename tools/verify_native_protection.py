#!/usr/bin/env python3
"""Prove Linux on-access blocking and recovery inside a disposable container.

Build infrastructure/endpoint/tests/Dockerfile first. Supply a verified, extracted
ClamAV package prefix containing bin/clamscan and sbin/{clamd,clamonacc}.
Only the container's /fixture tmpfs is monitored; no host protection is installed.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import sqlite3
import subprocess
import sys
import time
import tempfile
import urllib.parse
import urllib.request
import zipfile


def eventually(check, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.1)
    raise AssertionError('Native verification condition did not become true')


def inside():
    if os.geteuid() != 0 or not Path('/.dockerenv').exists() or not Path('/fixture').is_dir():
        raise RuntimeError('Native fixture must run in its disposable container')
    root = Path('/fixture')
    agent = Path('/test/agent')
    server_binary = Path('/test/server')
    state = root / 'state'
    watched = root / 'watched'
    watched.mkdir()
    source = root / 'source-db'
    source.mkdir()
    sample = b'ATHERNEX PUBLIC NATIVE PREVENTION FIXTURE 010203040506'
    (source / 'fixture.ndb').write_text(f'AthernexNativeFixture:0:*:{sample.hex()}\n')
    clean = watched / 'clean.txt'
    infected = watched / 'fixture.txt'
    clean.write_bytes(b'Ordinary public file')
    infected.write_bytes(sample)
    infected.chmod(0o600)
    embedded_probe = watched / 'source-example.txt'
    embedded_probe.write_bytes(b'Example source: ATHERNEX NATIVE PROTECTION SELF TEST 2026 010203040506')
    catalog = root / 'catalog'
    catalog.mkdir()
    target='linux-'+{'x86_64':'x86_64','aarch64':'aarch64'}[platform.machine().lower()]
    binary = catalog / f'athernex-endpoint-{target}'
    binary.write_bytes(agent.read_bytes())
    binary.chmod(0o755)
    (catalog / f'{target}.json').write_text(json.dumps(dict(
        target=target, version='fixture', signing='development-unsigned',
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest())))
    key = 'public-native-fixture-' + 'x' * 32
    key_file = root / 'operator.key'
    key_file.write_text(key)
    key_file.chmod(0o600)
    port = 8798
    origin = f'http://127.0.0.1:{port}'

    def request(path, body=None, form=False, auth=True):
        headers = {'Authorization': f'Bearer {key}'} if auth else {}
        if body is not None:
            data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        else:
            data = None
        with urllib.request.urlopen(urllib.request.Request(origin + path, data, headers), timeout=10) as response:
            return response.read()

    server_log = (root / 'server.log').open('w+')
    server = subprocess.Popen([str(server_binary), '--no-journal', '--db', str(root / 'ledger.db'),
                               '--port', str(port), '--operator-key-file', str(key_file)],
                              env=dict(os.environ, ATHERNEX_ENDPOINT_ARTIFACTS=str(catalog), ATHERNEX_ENDPOINT_RELEASES=str(root / "releases")),
                              stdout=server_log, stderr=server_log)
    protection = None
    controller = None
    protection_log = (root / 'protection.log').open('w+')
    checks = {}
    try:
        def ready():
            if server.poll() is not None:
                raise RuntimeError('Fixture server exited')
            try:
                return request('/healthz', auth=False)
            except OSError:
                return False
        eventually(ready)
        html = request('/endpoints').decode()
        csrf = re.search(r"name=csrf value='([^']+)'", html).group(1)
        bundle = request('/endpoints/installer', {'csrf': csrf, 'server': origin + '/', 'target': target}, form=True)
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            bootstrap = archive.read('bootstrap.json')
        bootstrap_path = root / 'bootstrap.json'
        bootstrap_path.write_bytes(bootstrap)
        subprocess.run([str(agent), 'enroll', str(bootstrap_path), str(state)], check=True, stdout=subprocess.DEVNULL)
        config_path = state / 'config.json'
        config = json.loads(config_path.read_text())
        config.update(scanner='/usr/local/bin/clamscan', updater='/usr/local/bin/freshclam',
                      signature_database=str(source), scan_roots=[str(watched)])
        config['telemetry']['enabled'] = False
        config_path.write_text(json.dumps(config))
        subprocess.run([str(agent), 'configure-protection', str(state)], check=True)
        config = json.loads(config_path.read_text())
        assert config['protection']['engine_uid'] != 0
        checks['dedicated_scanner_account'] = 'passed'
        def status_command():
            result = subprocess.run([str(agent), 'protection-status', str(state), '--require-active'],
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode in (0, 3), result.stderr
            return result.returncode, json.loads(result.stdout)
        assert status_command()[0] == 3

        def start_protection():
            return subprocess.Popen([str(agent), 'protect', str(state)], stdout=protection_log, stderr=protection_log)

        def active():
            if protection.poll() is not None:
                protection_log.flush()
                raise RuntimeError('Protection exited: ' + (root / 'protection.log').read_text())
            path = state / 'protection/health.json'
            if not path.exists():
                return False
            status = json.loads(path.read_text())
            return status if (status['health']['state'] == 'active' and status['processes']
                              and status['processes'][0][0] == protection.pid) else False

        def cycle():
            subprocess.run([str(agent), 'run', str(state), '--once'], check=True, timeout=30, stdout=subprocess.DEVNULL)
            return json.loads(request('/api/endpoints'))

        protection = start_protection()
        status = eventually(active)
        code, reported = status_command()
        assert code == 0 and reported['state'] == 'active'
        checks['installer_readiness_requires_verified_blocking'] = 'passed'
        endpoint = config['endpoint_id']
        fleet = cycle()
        assert fleet['endpoints'][0]['health']['realtime'] is True
        assert fleet['endpoints'][0]['health']['protection']['roots'] == [str(watched)]
        checks['portal_reports_verified_protection'] = 'passed'
        assert clean.read_bytes() == b'Ordinary public file'
        try:
            infected.read_bytes()
        except OSError as error:
            assert error.errno in (errno.EPERM, errno.EACCES)
        else:
            raise AssertionError('Native prevention allowed the controlled detection fixture')
        checks['clean_allowed_malware_denied'] = 'passed'

        # A new subdirectory tests recursive watch maintenance, not just initial marks.
        nested = watched / 'new-directory'
        nested.mkdir()
        nested_sample = nested / 'fixture.txt'
        nested_sample.write_bytes(sample)
        def nested_denied():
            try:
                nested_sample.read_bytes()
                return False
            except OSError as error:
                assert error.errno in (errno.EPERM, errno.EACCES)
                return True
        eventually(nested_denied, 10)
        checks['new_subdirectory_protected'] = 'passed'

        # Hash-free log observations must never authorize a quarantine playbook.
        request('/endpoints/action', {'csrf': csrf, 'op': 'playbook', 'id': endpoint, 'action': 'automatic'}, form=True)
        def evidence_received():
            fleet=cycle()
            assert not fleet['endpoints'][0]['health']['protection']['error'], fleet['endpoints'][0]['health']['protection']
            rows = json.loads(request(f'/api/endpoints/{endpoint}/events'))
            if rows and not any(r['event']['detection'] == 'AthernexNativeFixture.UNOFFICIAL' for r in rows):
                raise AssertionError(f'Unexpected native observations: {rows}')
            return rows if any(r['event']['detection'] == 'AthernexNativeFixture.UNOFFICIAL' for r in rows) else False
        observations = eventually(evidence_received)
        native = [r for r in observations if r['event']['detection'] == 'AthernexNativeFixture.UNOFFICIAL']
        assert native and all(not r['event']['sha256'] for r in native)
        assert not any(r['event']['detection'].startswith('AthernexProtectionSelfTest') for r in observations)
        assert not json.loads(request('/api/endpoints'))['commands']
        case = native[0]['case_id']
        exported = json.loads(request(f'/api/cases/{case}/export'))
        assert exported['endpoint_observations']
        checks['durable_detection_and_case_export'] = 'passed'
        checks['self_probes_excluded_and_unknown_hash_not_quarantined'] = 'passed'

        request('/endpoints/action', {'csrf': csrf, 'op': 'playbook', 'id': endpoint, 'action': 'disabled'}, form=True)
        def propose(name, **fields):
            before = {r['command']['id'] for r in json.loads(request('/api/endpoints'))['commands']}
            request('/endpoints/action', dict(csrf=csrf, op='queue', id=endpoint, case_id=case,
                                             action=name, **fields), form=True)
            command = next(r['command']['id'] for r in json.loads(request('/api/endpoints'))['commands']
                           if r['command']['id'] not in before)
            request('/endpoints/action', {'csrf': csrf, 'op': 'approve', 'id': command}, form=True)
            return command

        def action(name, **fields):
            command = propose(name, **fields)
            cycle()
            result = next(r for r in cycle()['commands'] if r['command']['id'] == command)
            assert result['state'] == 'succeeded', result
            assert cycle()['endpoints'][0]['health']['realtime'] is True
            return result

        assert embedded_probe.read_bytes().startswith(b'Example source:')
        checks['embedded_self_test_literal_is_allowed'] = 'passed'
        inventory = json.loads(action('inventory')['receipt']['output'])
        assert inventory['health']['realtime'] is True
        checks['inventory_reports_live_protection'] = 'passed'
        scan = action('scan', path=str(watched))
        assert 'AthernexNativeFixture.UNOFFICIAL FOUND' in scan['receipt']['output']
        assert 'AthernexProtectionSelfTest' not in scan['receipt']['output']
        evidence = json.loads(request(f'/api/endpoints/{endpoint}/events'))
        assert any(r['event']['path'] == str(infected) and r['event']['sha256'] == hashlib.sha256(sample).hexdigest()
                   for r in evidence)
        checks['approved_scan_reads_private_detected_files_while_protected'] = 'passed'
        original_inode = infected.stat().st_ino
        quarantined = action('quarantine', path=str(infected), sha256=hashlib.sha256(sample).hexdigest())
        assert not infected.exists()
        checks['approved_quarantine_while_protected'] = 'passed'
        qid = quarantined['command']['id']
        retained = state / 'quarantine' / qid
        assert retained.read_bytes() == sample and retained.stat().st_ino != original_inode
        with sqlite3.connect(state / 'endpoint.sqlite3') as database:
            intent, mutation_state, report = database.execute(
                'SELECT intent,state,report FROM native_mutations WHERE command_id=?', (qid,)).fetchone()
        intent = json.loads(intent)
        assert intent['verifier'] == dict(kind='linux_protected', uid=config['protection']['engine_uid'],
                                         gid=config['protection']['engine_gid'])
        assert mutation_state == 'finished' and json.loads(report)['outcome'] == 'completed'
        journal = json.loads((state / 'quarantine/operations' / (qid + '.json')).read_text())
        assert journal['record']['phase'] == 'complete'
        checks['protected_quarantine_uses_journal_and_independent_retained_bytes'] = 'passed'

        restored = action('restore', path=quarantined['command']['id'])
        with sqlite3.connect(state / 'endpoint.sqlite3') as database:
            restore_intent, restore_state, restore_report = database.execute(
                'SELECT intent,state,report FROM native_mutations WHERE command_id=?',
                (restored['command']['id'],)).fetchone()
        assert json.loads(restore_intent)['verifier'] == dict(kind='retained')
        assert restore_state == 'finished' and json.loads(restore_report)['outcome'] == 'completed'
        assert not retained.exists()
        checks['protected_restore_uses_atomic_publication_and_durable_commit'] = 'passed'
        try:
            infected.read_bytes()
        except OSError as error:
            assert error.errno in (errno.EPERM, errno.EACCES)
        else:
            raise AssertionError('Restored fixture was allowed by prevention')
        checks['restored_detection_remains_blocked'] = 'passed'

        # Execute one real approved command through the worker, then discard its
        # reply before local admission. The next actual agent process must recover
        # the durable intent and report success through normal authenticated I/O.
        recovery_file = watched / 'recovery-fixture.txt'
        recovery_file.write_bytes(sample)
        recovery_file.chmod(0o600)
        recovery_id = propose('quarantine', path=str(recovery_file),
                              sha256=hashlib.sha256(sample).hexdigest())

        def endpoint_post(suffix):
            headers = {'Authorization': 'Bearer ' + config['credential'], 'Content-Type': 'application/json'}
            req = urllib.request.Request(origin + f'/api/endpoint/{endpoint}/' + suffix,
                                         data=b'{}', headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read())

        dispatched = next(c for c in endpoint_post('poll') if c['id'] == recovery_id)
        ordered_action = {k: dispatched['action'][k] for k in ('type', 'path', 'sha256')}
        ordered_command = {k: (ordered_action if k == 'action' else dispatched[k]) for k in
                           ('id', 'endpoint_id', 'action', 'action_hash', 'created_ms', 'expires_ms', 'timeout_secs', 'case_id')}
        recovery_intent = dict(verifier=intent['verifier'], schema=1, command_id=recovery_id,
                               quarantine_id=recovery_id, operation='quarantine', state=str(state),
                               path=str(recovery_file), roots=[str(watched)], sha256=hashlib.sha256(sample).hexdigest())
        with sqlite3.connect(state / 'endpoint.sqlite3') as database:
            database.execute('INSERT INTO work(id,payload) VALUES(?,?)',
                             (recovery_id, json.dumps(ordered_command, separators=(',', ':'))))
        assert endpoint_post(f'command/{recovery_id}/start') == dispatched
        with sqlite3.connect(state / 'endpoint.sqlite3') as database:
            database.execute("INSERT INTO quarantine VALUES(?,?,?,'preparing')",
                             (recovery_id, str(recovery_file), recovery_intent['sha256']))
            database.execute("INSERT INTO native_mutations(command_id,quarantine_id,intent,state) VALUES(?,?,?,'pending')",
                             (recovery_id, recovery_id, json.dumps(recovery_intent)))
        worker_request = dict(nonce='d' * 64, intent=recovery_intent, recover=False, timeout_secs=10)
        finished = subprocess.run([str(agent), 'native-mutation-worker', str(os.getpid())],
                                  input=json.dumps(worker_request), capture_output=True, text=True,
                                  start_new_session=True, timeout=15)
        assert finished.returncode == 0, finished.stderr
        assert not recovery_file.exists()
        # Do not consume or admit the successful stdout report.
        recovered = next(r for r in cycle()['commands'] if r['command']['id'] == recovery_id)
        assert recovered['state'] == 'succeeded', recovered
        with sqlite3.connect(state / 'endpoint.sqlite3') as database:
            assert database.execute('SELECT state FROM native_mutations WHERE command_id=?',
                                    (recovery_id,)).fetchone()[0] == 'finished'
        assert (state / 'quarantine' / recovery_id).read_bytes() == sample
        checks['protected_mutation_recovers_lost_worker_reply_through_real_agent_and_server'] = 'passed'


        # A content-bound scan may authorize the explicitly enabled SOAR policy.
        request('/endpoints/action', {'csrf': csrf, 'op': 'playbook', 'id': endpoint, 'action': 'automatic'}, form=True)
        action('scan', path=str(infected))
        results = cycle()['commands']
        automatic = [r for r in results if r['command']['action']['type'] == 'quarantine'
                     and r['command']['id'] not in {quarantined['command']['id'], recovery_id}]
        assert automatic and automatic[0]['state'] == 'succeeded', automatic
        assert not infected.exists()
        assert cycle()['endpoints'][0]['health']['realtime'] is True
        checks['verified_detection_drives_automatic_quarantine'] = 'passed'

        # Process identity checks must invalidate health immediately, before its TTL.
        monitor = status['processes'][2][0]
        os.kill(monitor, signal.SIGSTOP)
        try:
            assert cycle()['endpoints'][0]['health']['realtime'] is False
            assert status_command()[0] == 3
        finally:
            os.kill(monitor, signal.SIGCONT)
        checks['stopped_monitor_invalidates_health'] = 'passed'

        # Kill the supervisor: both privileged monitor and unprivileged scanner
        # must die, including after the scanner's privilege transition.
        children = [row[0] for row in status['processes'][1:]]
        protection.kill()
        protection.wait(timeout=10)
        def dead(pid):
            path = Path(f'/proc/{pid}/stat')
            try:
                return path.read_text().rsplit(')', 1)[1].split()[0] == 'Z'
            except (FileNotFoundError, ProcessLookupError):
                return True
        eventually(lambda: all(dead(pid) for pid in children), 10)
        assert cycle()['endpoints'][0]['health']['realtime'] is False
        checks['supervisor_crash_cleans_children_and_health'] = 'passed'
        protection = start_protection()
        eventually(active)
        assert cycle()['endpoints'][0]['health']['realtime'] is True
        assert len(list(watched.glob('.athernex-protection-check-*'))) == 1
        checks['native_restart_restores_verified_protection'] = 'passed'
        watched.rename(root/'original-watched')
        watched.mkdir()
        assert cycle()['endpoints'][0]['health']['realtime'] is False
        checks['replaced_watch_root_invalidates_health'] = 'passed'
        # Restore the original fixture identity, then hand both processes to
        # the real controller. No host service manager is involved.
        protection.kill(); protection.wait(timeout=10)
        watched.rmdir(); (root / 'original-watched').rename(watched)
        installed = root / 'installed-agent'
        installed.write_bytes(agent.read_bytes()); installed.chmod(0o700)
        public = subprocess.check_output([str(agent), 'release-keygen', str(root / 'release-keys')], text=True).strip()
        config = json.loads(config_path.read_text())
        config['updates'] = dict(managed=True, automatic=True, public_key=public, channel='stable',
                                  install_path=str(installed), minimum_sequence=0, allow_unsigned_native=True)
        config_path.write_text(json.dumps(config))
        controller_log = (root / 'controller.log').open('w+')
        def start_controller():
            return subprocess.Popen([str(agent), 'supervise', str(state), str(installed)], stdout=controller_log, stderr=controller_log)
        controller = start_controller()
        eventually(lambda: json.loads(request('/api/endpoints'))['endpoints'][0]['health'].get('updates', {}).get('supervised'), 30)
        info = json.loads(subprocess.check_output([str(agent), 'release-check', 'a' * 64], text=True))
        manifest = root / 'release.json'
        subprocess.run([str(agent), 'release-sign', str(root / 'release-keys/release.pk8'), str(agent), info['version'], 'stable', '1', str(int(time.time() * 1000) + 900000), str(manifest)], check=True)
        release_id = subprocess.check_output([str(agent), 'release-publish', str(manifest), str(agent), public, str(root / 'releases')], text=True).strip()
        request('/endpoints/updates/action', dict(csrf=csrf, op='propose', id=endpoint, release_id=release_id, install='on'), form=True)
        deployment = json.loads(request('/api/endpoint-updates'))[0]['deployment']['id']
        request('/endpoints/updates/action', dict(csrf=csrf, op='approve', id=deployment), form=True)
        def installed_and_healthy():
            if controller.poll() is not None:
                raise RuntimeError('Controller exited: ' + (root / 'controller.log').read_text())
            record = json.loads(request('/api/endpoint-updates'))[0]
            if record['installation'] is not None:
                assert record['installation']['outcome'] == 'installed', record
                return json.loads(request('/api/endpoints'))['endpoints'][0]['health']['realtime']
            return False
        eventually(installed_and_healthy, 180)
        assert status_command()[0] == 0
        update_sample = watched / 'post-update-detection.txt'
        update_sample.write_bytes(sample)
        def assert_blocking():
            assert clean.read_bytes() == b'Ordinary public file'
            try:
                update_sample.read_bytes()
            except OSError as error:
                assert error.errno in (errno.EPERM, errno.EACCES)
            else:
                raise AssertionError('Native prevention was lost across managed maintenance')
        assert_blocking()
        checks['automatic_install_confirms_native_blocking_before_commit'] = 'passed'
        native_before = json.loads((state / 'protection/health.json').read_text())['processes']
        lease_path = state / 'supervisor/lease.json'
        prior_agent = json.loads(lease_path.read_text())['child_pid']
        os.kill(prior_agent, 9)
        assert_blocking()
        eventually(lambda: json.loads(lease_path.read_text())['child_pid'] not in (None, prior_agent), 20)
        assert json.loads((state / 'protection/health.json').read_text())['processes'] == native_before
        checks['management_crash_keeps_native_prevention_running'] = 'passed'
        controller.kill(); controller.wait(timeout=10)
        eventually(lambda: all(dead(pid) for pid, _ in native_before), 10)
        assert status_command()[0] == 3
        controller = start_controller()
        eventually(lambda: status_command()[0] == 0, 30)
        assert_blocking()
        checks['controller_restart_restores_native_prevention'] = 'passed'

        # The service launcher must keep a separate recovery executable while a
        # replacement controller proves a server cycle AND real native blocking.
        native_before = json.loads((state/'protection/health.json').read_text())['processes']
        controller.kill(); controller.wait(timeout=10)
        eventually(lambda: all(dead(pid) for pid, _ in native_before), 15)
        launcher_binary = root/'launcher'; controller_binary = root/'managed-controller'
        for destination in [launcher_binary, controller_binary]:
            shutil.copy2(agent, destination); destination.chmod(0o700)
        config = json.loads(config_path.read_text())
        config['updates'].update(controller_path=str(controller_binary),launcher_path=str(launcher_binary),controller_automatic=True)
        config_path.write_text(json.dumps(config))
        original_config = config_path.read_bytes()
        agent_history = (state/'updates/status.json').read_bytes()
        def start_launcher():
            return subprocess.Popen([str(launcher_binary),'launch',str(state),str(controller_binary),str(installed)],stdout=controller_log,stderr=controller_log)
        controller = start_launcher()
        eventually(lambda: status_command()[0] == 0, 45); assert_blocking()
        prior_controller = json.loads((state/'supervisor/launcher.json').read_text())['controller_pid']
        controller_manifest = root/'controller-release.json'
        subprocess.run([str(agent),'release-sign',str(root/'release-keys/release.pk8'),str(agent),info['version'],'stable','1',str(int(time.time()*1000)+900000),str(controller_manifest)],check=True)
        staged = json.loads(subprocess.check_output([str(agent),'controller-update-stage',str(state),str(controller_manifest),str(agent)],text=True))
        controller_release_id = hashlib.sha256(json.dumps(staged['staged'],separators=(',',':')).encode()).hexdigest()
        subprocess.run([str(agent),'controller-update-request',str(state),controller_release_id,str(int(time.time()*1000)+600000)],check=True)
        def controller_confirmed():
            if controller.poll() is not None: raise AssertionError('Launcher exited during native controller trial')
            path = state/'updates/controller/maintenance.json'
            value = json.loads(path.read_text())
            if value['phase'] in ['queued','applying']: return False
            assert value['phase']=='installed',value
            return status_command()[0]==0
        eventually(controller_confirmed,180); assert_blocking()
        assert json.loads((state/'supervisor/launcher.json').read_text())['controller_pid'] != prior_controller
        assert config_path.read_bytes() == original_config
        assert (state/'updates/status.json').read_bytes() == agent_history
        checks['launcher_controller_replacement_confirms_real_blocking_and_preserves_agent_history'] = 'passed'
        native_before = json.loads((state/'protection/health.json').read_text())['processes']
        live_controller = json.loads((state/'supervisor/launcher.json').read_text())['controller_pid']
        live_agent = json.loads((state/'supervisor/lease.json').read_text())['child_pid']
        controller.kill(); controller.wait(timeout=10)
        eventually(lambda: all(dead(pid) for pid in [live_controller,live_agent,*[pid for pid,_ in native_before]]),15)
        checks['launcher_death_cleans_controller_management_and_privileged_native_children'] = 'passed'
        controller = start_launcher()
        eventually(lambda: status_command()[0]==0,45); assert_blocking()
        checks['launcher_restart_restores_confirmed_controller_and_native_prevention'] = 'passed'
        print(json.dumps(checks, indent=2))
    finally:
        if controller is not None and controller.poll() is None:
            controller.kill(); controller.wait(timeout=10)
        if protection is not None and protection.poll() is None:
            protection.kill()
            protection.wait(timeout=10)
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=10)
        if sys.exc_info()[0] is not None:
            for database,table in [('state/protection/events.sqlite3','events'),('state/endpoint.sqlite3','outbox'),('ledger.db','endpoint_events')]:
                path=root/database
                if path.is_file():
                    try:
                        with sqlite3.connect(path) as db:
                            print(database+': '+str(db.execute(f'SELECT payload FROM {table} LIMIT 4').fetchall()),file=sys.stderr)
                    except sqlite3.Error as error:
                        print(str(error),file=sys.stderr)
            with sqlite3.connect(root/'ledger.db') as db:
                print('case count: '+str(db.execute('SELECT count(*) FROM cases').fetchone()),file=sys.stderr)
                print('source: '+str(db.execute("SELECT received FROM sources WHERE id='endpoint'").fetchone()),file=sys.stderr)
            for name in ['protection.log', 'state/protection/health.json', 'server.log', 'controller.log']:
                path = root / name
                if path.is_file():
                    print(name + ': ' + path.read_text()[-4096:], file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside-container', action='store_true')
    parser.add_argument('--image', default='athernex-native-protection-fixture:local')
    parser.add_argument('--engine-prefix', type=Path)
    parser.add_argument('--agent', type=Path, default=Path('target/release/athernex-endpoint'))
    parser.add_argument('--server', type=Path, default=Path('target/release/athernex-siem'))
    args = parser.parse_args()
    if args.inside_container:
        inside()
        return
    if args.engine_prefix is None:
        parser.error('--engine-prefix must identify the verified extracted ClamAV usr/local directory')
    command = ['docker', 'run', '--init', '--rm', '--network', 'none', '--cap-add', 'SYS_ADMIN', '--cap-add', 'DAC_READ_SEARCH',
               '--memory', '1g', '--pids-limit', '128', '--tmpfs', '/fixture:rw,exec,nosuid,nodev,size=256m,mode=0755']
    # Stable copies keep /proc/self/exe usable if a concurrent build replaces a
    # target binary. A bind mount otherwise retains the deleted old inode.
    with tempfile.TemporaryDirectory(prefix='athernex-native-binaries-') as directory:
        copies = Path(directory)
        shutil.copy2(args.agent, copies / 'agent')
        shutil.copy2(args.server, copies / 'server')
        for source, target in [(copies / 'agent', '/test/agent'), (copies / 'server', '/test/server'),
                               (Path(__file__), '/test/verify.py'), (args.engine_prefix, '/usr/local')]:
            command.extend(['--mount', f'type=bind,source={source.resolve()},target={target},readonly'])
        command.extend([args.image, 'python3', '/test/verify.py', '--inside-container'])
        subprocess.run(command, check=True, timeout=480)


if __name__ == '__main__':
    main()
