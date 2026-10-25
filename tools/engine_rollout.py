"""Container-only two-endpoint engine scenario for verify_engine_update.py.

Controllers, ClamAV processes, signatures, keys and the control plane are real
but disposable. Both endpoint instances share this isolated Linux kernel; this
does not establish cross-host, platform-signing or Windows/macOS coverage.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


def inside_rollout(alive):
    from package_engine import assemble
    root = Path('/fixture')
    if os.geteuid() != 0 or not Path('/.dockerenv').exists() or not root.is_dir():
        raise RuntimeError('Engine rollout requires its disposable container')
    agent = root/'agent'
    shutil.copy2('/test/agent', agent)
    agent.chmod(0o755)
    ids = [f'{index:064x}' for index in [1, 2]]
    states = [root/f'state-{index}' for index in range(2)]
    watched = [root/f'watched-{index}' for index in range(2)]
    processes, controllers, checks = [], [], {}
    readiness = {}
    server = None
    origin = 'http://127.0.0.1:8799'
    operator = 'public-engine-rollout-fixture-'+'e'*32
    target = 'linux-'+platform.machine().lower()
    marker = b'Public two endpoint engine rollout blocking fixture'
    database = root/'signatures'
    database.mkdir(mode=0o755)
    (database/'fixture.ndb').write_text('PublicEngineRollout:0:*:'+marker.hex()+'\n')
    version = subprocess.check_output(['/usr/local/bin/clamscan', '--version'], text=True).split()[1].split('/')[0]
    os.environ['ATHERNEX_ENGINE_TEST_VERSION'] = version

    def eventually(check, timeout=45):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            value = check()
            if value:
                return value
            time.sleep(.25)
        raise AssertionError(f'Engine rollout condition timed out after {timeout} seconds')

    def run(*arguments):
        result = subprocess.run([str(agent), *map(str, arguments)], capture_output=True,
                                text=True, timeout=240)
        assert result.returncode == 0, result.stdout+result.stderr
        return result.stdout

    def api(path, value=None, form=False):
        headers = {'Authorization': 'Bearer '+operator}
        data = None
        if value is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            data = urllib.parse.urlencode(value).encode() if form else json.dumps(value).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(origin+path, data, headers), timeout=20) as response:
                raw = response.read()
                return json.loads(raw) if path.startswith('/api/') else raw
        except urllib.error.HTTPError as error:
            raise AssertionError(f'{path}: HTTP {error.code}: '+error.read(8192).decode(errors='replace')) from error

    def spawn(command, name):
        with (root/(name+'.log')).open('a') as output:
            child = subprocess.Popen(list(map(str, command)), stdout=output, stderr=output,
                                     env={**os.environ, 'ATHERNEX_OPERATOR_KEY': operator,
                                          'ATHERNEX_ENDPOINT_ARTIFACTS': str(root/'artifacts'),
                                          'ATHERNEX_ENDPOINT_RELEASES': str(root/'releases')})
        processes.append(child)
        return child

    def start_server():
        nonlocal server
        server = spawn(['/test/server', '--no-journal', '--db', root/'server.db', '--port', '8799'], 'server')
        def online():
            assert server.poll() is None, (root/'server.log').read_text()
            try:
                return api('/healthz')
            except OSError:
                return False
        eventually(online, 20)

    def restart_server():
        server.kill()
        server.wait(timeout=10)
        start_server()

    def status(index):
        return json.loads(run('engine-status', states[index]))

    def active(index):
        assert controllers[index].poll() is None, (root/f'controller-{index}.log').read_text()
        return json.loads(run('protection-status', states[index]))['state'] == 'active'

    def blocking(index):
        assert (watched[index]/'clean.txt').read_text() == 'Clean rollout control\n'
        try:
            (watched[index]/'matched.txt').read_bytes()
        except PermissionError:
            return
        raise AssertionError(f'Endpoint {index} allowed the signature-matched file')

    def ready(index):
        state = states[index]
        path = state/'supervisor/ready.json'
        if not path.exists():
            return False
        child = json.loads(path.read_text())
        owner = json.loads((state/'supervisor/lease.json').read_text())
        if (owner['controller_pid'] != controllers[index].pid or owner['child_pid'] != child['pid']
                or owner['token'] != child['token'] or not alive(child['pid'])):
            return False
        # ready.json is refreshed after every cycle. Pin the first observed
        # ready time for this exact child incarnation, then require subsequent
        # reports; chasing its newest timestamp makes two devices race forever.
        incarnation = (index, controllers[index].pid, child['pid'], child['token'])
        ready_ms = readiness.setdefault(incarnation, child['time_ms'])
        # Read only: admission and observation must use health actually sent by
        # the endpoints. Neither the fixture nor the operator injects health.
        with sqlite3.connect('file:'+str(root/'server.db')+'?mode=ro', uri=True) as ledger:
            row = ledger.execute('SELECT h.seen_ms,e.last_seen_ms,h.health,e.health FROM endpoint_engine_health h JOIN endpoints e ON e.id=h.endpoint_id WHERE e.id=?', (ids[index],)).fetchone()
        if row is None or min(row[:2]) < ready_ms or int(time.time()*1000)-min(row[:2]) > 120000:
            return False
        engine, health = json.loads(row[2]), json.loads(row[3])
        local = status(index)
        return (engine['managed'] and engine['automatic'] and engine['supervised']
                and engine['highwater'] == local['highwater'] and engine['phase'] == local['phase']
                and not health['error'] and health['realtime']
                and health.get('protection', {}).get('state') == 'active'
                and health.get('collector', {}).get('last_success_ms', 0) >= ready_ms)

    def record(identifier):
        return next(row for row in api('/api/control/engine-rollouts') if row['id'] == identifier)

    def review(identifier, action):
        api('/api/control/engine-rollouts/'+identifier+'/review',
            dict(plan_hash=record(identifier)['plan_hash'], action=action))

    def propose(release_id, name):
        eventually(lambda: all(ready(i) for i in range(2)), 90)
        now = int(time.time()*1000)
        row = api('/api/control/engine-rollouts', dict(release_id=release_id, request=dict(
            name=name, endpoint_ids=ids, canary_count=1, batch_size=1, observe_secs=60,
            not_before_ms=now+2000, deadline_ms=now+900000)))
        assert row['state'] == 'pending' and all(m['deployment_id'] is None for m in row['members'])
        review(row['id'], 'approve')
        return row['id']

    def progressing(identifier):
        row = record(identifier)
        assert row['state'] not in ['failed', 'expired', 'cancelled'], row
        if row['members'][1]['deployment_id'] is not None:
            canary = row['members'][0]
            assert canary['deployment_state'] == 'installed', row
            assert canary['healthy_since_ms'] > canary['installation_received_ms'], row
            assert canary['last_healthy_ms']-canary['healthy_since_ms'] >= 60000, row
        return row

    def acknowledged(index, deployment_id, outcome):
        row = next(r for r in api('/api/control/engines') if r['deployment']['id'] == deployment_id)
        receipt = row['installation_receipt']
        if receipt is None:
            return False
        assert receipt['outcome'] == outcome and row['staging_receipt']['outcome'] == 'staged', row
        maintenance = status(index)['maintenance']
        if not maintenance or not maintenance.get('acknowledged'):
            return False
        assert maintenance['receipt'] == receipt and maintenance['deployment'] == row['deployment']
        return row

    try:
        public = run('release-keygen', root/'keys').strip()
        (root/'engine-public.txt').write_text(public)
        artifacts = root/'artifacts'
        artifacts.mkdir()
        shutil.copy2(agent, artifacts/('athernex-endpoint-'+target))
        (artifacts/(target+'.json')).write_text(json.dumps(dict(
            target=target, version='fixture', sha256=hashlib.sha256(agent.read_bytes()).hexdigest(),
            signing='development-unsigned')))
        start_server()
        baseline_agent_status = []
        for index, state in enumerate(states):
            state.mkdir(mode=0o700)
            watched[index].mkdir(mode=0o755)
            (watched[index]/'clean.txt').write_text('Clean rollout control\n')
            (watched[index]/'matched.txt').write_bytes(marker)
            csrf = re.search(r"name=csrf value='([^']+)'", api('/endpoints').decode()).group(1)
            archive = api('/endpoints/installer', dict(csrf=csrf, target=target, server=origin+'/'), True)
            with zipfile.ZipFile(io.BytesIO(archive)) as installer:
                bootstrap = json.loads(installer.read('bootstrap.json'))
            credential = f'{index+10:064x}'
            api('/api/endpoint/enroll', dict(protocol=1, enrollment_token=bootstrap['enrollment_token'],
                endpoint_id=ids[index], credential=credential, hostname=f'Native engine rollout {index}',
                platform='linux', arch=platform.machine().lower(), version='0.1.0'))
            config = dict(server=origin+'/', endpoint_id=ids[index], credential=credential,
                scanner='/usr/local/bin/clamscan', updater='/usr/local/bin/freshclam',
                scan_roots=[str(watched[index])], allow_scripts=False, signature_database=str(database),
                telemetry=dict(enabled=True, interval_secs=1))
            path = state/'config.json'
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            run('configure-protection', state)
            config = json.loads(path.read_text())
            config['engine_updates'] = dict(public_key=public, root=str(root/f'engines-{index}'),
                allow_unsigned_native=True, automatic=True, managed=True)
            path.write_text(json.dumps(config))
            baseline_agent_status.append(json.loads(run('update-status', state)))
            controller = root/f'controller-{index}'
            shutil.copy2(agent, controller)
            controllers.append(spawn([controller, 'supervise', state, agent], f'controller-{index}'))
            eventually(lambda: active(index), 90)
            blocking(index)
        checks['two_real_controllers_enroll_and_block_with_native_clamav'] = 'passed'
        print('Both native endpoint instances are active and blocking.', flush=True)
        bundle = root/'bundle'
        assemble(Path('/usr/local'), bundle, target)

        def publish(sequence):
            manifest = root/f'engine-{sequence}.json'
            run('engine-sign', root/'keys/release.pk8', bundle/'content', bundle/'roles.json',
                target, version, 'stable', sequence, int(time.time()*1000)+1800000, manifest)
            return run('engine-publish', manifest, bundle/'content', root/'engine-public.txt',
                       root/'releases/engines').strip()

        good = publish(1)
        identifier = propose(good, 'Native engine promotion and restart')
        print('Signed engine rollout reviewed; waiting for the native canary.', flush=True)
        def first_installed():
            row = progressing(identifier)
            return row if row['members'][0]['deployment_state'] == 'installed' else False
        first = eventually(first_installed, 240)
        assert first['members'][1]['deployment_id'] is None, first
        first_id = first['members'][0]['deployment_id']
        eventually(lambda: acknowledged(0, first_id, 'installed'), 90)
        eventually(lambda: active(0), 90)
        blocking(0)
        checks['canary_installs_with_exact_reviewed_receipts_before_later_dispatch'] = 'passed'
        def observing():
            row = progressing(identifier)
            return row if row['members'][0]['healthy_since_ms'] is not None else False
        first = eventually(observing, 90)
        assert first['members'][1]['deployment_id'] is None, first
        restart_server()
        restored = progressing(identifier)
        assert restored['members'][0]['deployment_id'] == first_id
        assert restored['plan_hash'] == first['plan_hash']
        assert restored['members'][0]['healthy_since_ms'] == first['members'][0]['healthy_since_ms']
        checks['server_restart_preserves_approval_membership_and_canary_identity'] = 'passed'
        print('Native canary installed; server restarted during its health observation.', flush=True)
        def completed():
            row = progressing(identifier)
            return row if row['state'] == 'completed' else False
        completed_row = eventually(completed, 300)
        assert len(api('/api/control/engines')) == 2
        confirmed_configs = []
        for index, member in enumerate(completed_row['members']):
            assert member['last_healthy_ms']-member['healthy_since_ms'] >= 60000, member
            eventually(lambda: acknowledged(index, member['deployment_id'], 'installed'), 90)
            assert status(index)['installed'] == good and status(index)['highwater'] == 1
            eventually(lambda: active(index), 90)
            blocking(index)
            config_bytes = (states[index]/'config.json').read_bytes()
            config = json.loads(config_bytes)
            assert config['scanner'].startswith(str(root/f'engines-{index}'/good))
            raw = json.loads((states[index]/'protection/health.json').read_text())
            maps = '\n'.join(Path(f'/proc/{pid}/maps').read_text() for pid, _ in raw['processes'])
            assert any(str(root/f'engines-{index}'/good) in line and 'libclamav.so' in line for line in maps.splitlines())
            confirmed_configs.append(config_bytes)
        checks['promotion_and_completion_require_two_actual_60_second_health_windows'] = 'passed'
        checks['both_endpoints_load_private_signed_libraries_and_preserve_blocking'] = 'passed'
        checks['server_restart_creates_no_duplicate_deployments'] = 'passed'
        print('Both native endpoints installed after observed health windows.', flush=True)

        # Retain durable release history, but reclaim the completed catalog tree
        # before constructing a second full native release in bounded tmpfs.
        shutil.rmtree(root/'releases/engines'/good)
        shutil.copyfile('/test/unhealthy-daemon', bundle/'content/sbin/clamd')
        bad = publish(2)
        failure = propose(bad, 'Native failed canary contains later device')
        def failed():
            row = record(failure)
            assert row['members'][1]['deployment_id'] is None, row
            assert row['state'] not in ['completed', 'expired', 'cancelled'], row
            return row if row['state'] == 'failed' else False
        failed_row = eventually(failed, 240)
        failed_id = failed_row['members'][0]['deployment_id']
        assert failed_row['members'][0]['deployment_state'] == 'rolled_back', failed_row
        eventually(lambda: acknowledged(0, failed_id, 'rolled_back'), 90)
        for index in range(2):
            eventually(lambda: active(index), 90)
            blocking(index)
            assert (states[index]/'config.json').read_bytes() == confirmed_configs[index]
            assert status(index)['installed'] == good
        assert status(0)['highwater'] == 2 and status(1)['highwater'] == 1
        assert not (root/'engines-1'/bad).exists()
        checks['failed_native_canary_rolls_back_and_restores_blocking'] = 'passed'
        checks['failed_canary_never_downloads_or_installs_on_later_device'] = 'passed'
        restart_server()
        assert record(failure)['state'] == 'failed'
        # Wait for fresh real endpoint heartbeats after restart, then recheck
        # the scheduler's durable terminal decision and exact receipt identities.
        restarted_ms = int(time.time()*1000)
        def fresh_after_restart():
            with sqlite3.connect('file:'+str(root/'server.db')+'?mode=ro', uri=True) as ledger:
                return ledger.execute('SELECT count(*) FROM endpoints WHERE id IN (?,?) AND last_seen_ms>?',
                                      (*ids, restarted_ms)).fetchone()[0] == 2
        eventually(fresh_after_restart, 90)
        final = record(failure)
        assert final['state'] == 'failed' and final['members'][1]['deployment_id'] is None
        assert final['members'][0]['deployment_id'] == failed_id
        assert len(api('/api/control/engines')) == 3
        assert record(identifier)['state'] == 'completed'
        checks['failed_group_remains_terminal_after_restart_and_fresh_health'] = 'passed'
        for index, state in enumerate(states):
            assert json.loads(run('update-status', state)) == baseline_agent_status[index]
            assert controllers[index].poll() is None
        assert subprocess.check_output(['/usr/local/bin/clamscan', '--version'], text=True).split()[1].split('/')[0] == version
        checks['agent_history_global_engine_and_controller_ownership_preserved'] = 'passed'
        print(json.dumps(dict(checks=checks, completed_rollout=completed_row, failed_rollout=final), indent=2), flush=True)
    except Exception:
        if (root/'server.db').exists():
            with sqlite3.connect('file:'+str(root/'server.db')+'?mode=ro', uri=True) as ledger:
                for table, stamp, key in [('endpoints', 'last_seen_ms', 'id'), ('endpoint_engine_health', 'seen_ms', 'endpoint_id')]:
                    for endpoint, seen, health in ledger.execute(f'SELECT {key},{stamp},health FROM {table}'):
                        print(json.dumps(dict(diagnostic=table, endpoint=endpoint, seen_ms=seen, health=json.loads(health))), flush=True)
        for path in root.glob('*.log'):
            print(path.name+':\n'+path.read_text(errors='replace')[-5000:])
        for index, state in enumerate(states):
            if (state/'engine-updates/status.json').exists():
                print(f'Endpoint {index}: '+run('engine-status', state))
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
