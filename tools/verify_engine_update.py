#!/usr/bin/env python3
"""Exercise staged engine activation and recovery with real ClamAV in a container.

Only /fixture is watched. The vendor prefix and test executable are read-only
mounts; accounts, service processes, keys, versions and signatures are disposable.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import json
import hashlib
import io
import re
import urllib.request
import urllib.parse
import urllib.error
import zipfile
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import tempfile
import time


def eventually(check, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.01)
    raise AssertionError('Engine fixture condition did not become true')


def alive(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ['Z', 'X']
    except (FileNotFoundError, ProcessLookupError):
        return False


def inside(automatic=False, fleet=False):
    from package_engine import assemble
    if os.geteuid() != 0 or not Path('/.dockerenv').exists() or not Path('/fixture').is_dir():
        raise RuntimeError('Engine fixture requires its disposable container')
    root = Path('/fixture'); state = root/'state'; watched = root/'watched'
    state.mkdir(mode=0o700); watched.mkdir(mode=0o755)
    database = root/'signatures'; database.mkdir(mode=0o755)
    marker = b'Public engine replacement blocking fixture'
    (database/'fixture.ndb').write_text('PublicEngineFixture:0:*:'+marker.hex()+'\n')
    sample = watched/'matched.txt'; sample.write_bytes(marker)
    clean = watched/'clean.txt'; clean.write_text('Unrelated clean engine control\n')
    agent = root/'agent'; controller = root/'controller'
    for destination in [agent, controller]:
        shutil.copy2('/test/agent', destination); destination.chmod(0o755)
    processes = []; checks = {}; service = None; server = None
    log = (root/'controller.log').open('w+')

    def run(*arguments, ok=True, timeout=240):
        result = subprocess.run([str(agent), *map(str, arguments)], capture_output=True, text=True, timeout=timeout)
        assert (result.returncode == 0) == ok, result.stdout+result.stderr
        return result.stdout

    def status():
        return json.loads(run('engine-status', state))

    def active():
        if service is None or service.poll() is not None:
            raise AssertionError('Fixture controller exited: '+(root/'controller.log').read_text())
        result = subprocess.run([str(agent), 'protection-status', str(state)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        health = json.loads(result.stdout)
        return health if health['state'] == 'active' else False

    def start():
        nonlocal service
        if service is not None and service.poll() is None:
            return
        service = subprocess.Popen([str(controller), 'supervise', str(state), str(agent)], stdout=log, stderr=log)
        processes.append(service)
        eventually(active, 90)

    def stop():
        nonlocal service
        raw = json.loads((state/'protection/health.json').read_text())
        pids = [pid for pid, _ in raw['processes']]
        lease = state/'supervisor/lease.json'
        if lease.exists():
            child = json.loads(lease.read_text()).get('child_pid')
            if child:
                pids.append(child)
        service.kill(); service.wait(timeout=10); service = None
        eventually(lambda: all(not alive(pid) for pid in pids), 15)

    def blocking():
        assert clean.read_text() == 'Unrelated clean engine control\n'
        try:
            sample.read_bytes()
        except PermissionError:
            return
        raise AssertionError('Signature-matched fixture was readable')

    origin = 'http://127.0.0.1:8799'
    operator = 'public-engine-fleet-fixture-'+'e'*32
    published = {}
    readiness = {}
    last_manifest = None
    def api(path, value=None, form=False):
        headers={'Authorization':'Bearer '+operator}
        data=None
        if value is not None:
            headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
            data=urllib.parse.urlencode(value).encode() if form else json.dumps(value).encode()
        try:
            response = urllib.request.urlopen(urllib.request.Request(origin+path,data,headers),timeout=20)
        except urllib.error.HTTPError as error:
            raise AssertionError(f'{path}: HTTP {error.code}: '+error.read().decode(errors='replace')) from error
        with response:
            raw=response.read()
            return raw if form or not path.startswith('/api/') else json.loads(raw)
    def delivered(identifier, install=False, outcome=None):
        row=next(r for r in api('/api/control/engines') if r['deployment']['id']==identifier)
        receipt=row['installation_receipt' if install else 'staging_receipt']
        if receipt is None: return False
        if outcome is not None: assert receipt['outcome']==outcome, row
        if install:
            maintenance = status()['maintenance']
            if not maintenance or not maintenance.get('acknowledged'): return False
            assert maintenance['receipt'] == receipt
        return row
    def online():
        try: return api('/healthz')
        except OSError: return False
    def start_server():
        nonlocal server
        with (root/'server.log').open('a') as output:
            server=subprocess.Popen(['/test/server','--no-journal','--db',str(root/'server.db'),'--port','8799'],stdout=output,stderr=output,env={**os.environ,'ATHERNEX_OPERATOR_KEY':operator,'ATHERNEX_ENDPOINT_ARTIFACTS':str(root/'artifacts'),'ATHERNEX_ENDPOINT_RELEASES':str(root/'releases')})
        processes.append(server)
        eventually(online,20)
    def reported_ready():
        ready_path=state/'supervisor/ready.json'
        if not ready_path.exists(): return False
        ready=json.loads(ready_path.read_text())
        owner=json.loads((state/'supervisor/lease.json').read_text())
        if (owner['controller_pid'] != service.pid or owner['child_pid'] != ready['pid']
                or owner['token'] != ready['token'] or not alive(ready['pid'])): return False
        # Every successful cycle rewrites ready.json. Pin a watermark for this
        # exact child incarnation, then wait for later reports from both streams.
        ready_ms=readiness.setdefault((service.pid,ready['pid'],ready['token']),ready['time_ms'])
        with sqlite3.connect('file:'+str(root/'server.db')+'?mode=ro',uri=True) as ledger:
            row=ledger.execute('SELECT h.seen_ms,e.last_seen_ms,h.health,e.health FROM endpoint_engine_health h JOIN endpoints e ON e.id=h.endpoint_id WHERE e.id=?',('a'*64,)).fetchone()
        if row is None or min(row[:2]) < ready_ms or int(time.time()*1000)-min(row[:2]) > 120000: return False
        engine,health=json.loads(row[2]),json.loads(row[3])
        local=status()
        return (engine['managed'] and engine['supervised'] and engine['highwater']==local['highwater']
                and engine['phase']==local['phase'] and not health['error'] and health['realtime']
                and health.get('protection',{}).get('state')=='active'
                and health.get('collector',{}).get('last_success_ms',0)>=ready_ms)
    def propose(identifier, install):
        record=api('/api/control/engines',dict(endpoint='a'*64,release_id=identifier,install=install))
        api('/api/control/engines/'+record['deployment']['id']+'/review',dict(plan_hash=record['plan_hash'],approve=True))
        return record['deployment']['id']
    def stage(manifest):
        nonlocal last_manifest
        last_manifest=manifest
        if not fleet:
            run('engine-stage',state,manifest,bundle/'content'); return
        prior=service is not None and service.poll() is None
        start()
        # Require current controller ownership and both posted health streams;
        # an old ready file or elapsed sleep cannot prove recovery health.
        eventually(reported_ready, 90)
        # Earlier fixture deliveries have finished. Keep their durable manifests
        # and receipts in the server ledger, but do not retain another full copy
        # of every engine tree in this disposable transport catalog.
        catalog = root/'releases/engines'
        if catalog.exists():
            for retired in catalog.iterdir():
                if retired.is_dir() and re.fullmatch(r'[0-9a-f]{64}', retired.name):
                    assert not any(row['state'] in ['pending','approved','downloading','staged','installing'] and row['deployment']['release']['release']['sequence'] < json.loads(manifest.read_text())['release']['sequence'] for row in api('/api/control/engines'))
                    shutil.rmtree(retired)
        identifier=run('engine-publish',manifest,bundle/'content',root/'engine-public.txt',root/'releases/engines').strip()
        published[str(manifest)]=identifier
        delivery=propose(identifier,False)
        eventually(lambda: delivered(delivery, outcome='staged'),90)
        checks['signed_fleet_download_and_durable_staging_receipt']='passed'
        print('Engine fleet staged sequence '+str(json.loads(manifest.read_text())['release']['sequence']), flush=True)
        if not prior: stop()

    try:
        public = run('release-keygen', root/'keys').strip()
        if fleet:
            (root/'engine-public.txt').write_text(public)
            catalog=root/'artifacts'; catalog.mkdir()
            target='linux-'+platform.machine().lower()
            shutil.copy2(agent,catalog/('athernex-endpoint-'+target))
            (catalog/(target+'.json')).write_text(json.dumps(dict(target=target,version='fixture',sha256=hashlib.sha256(agent.read_bytes()).hexdigest(),signing='development-unsigned')))
            start_server()
            csrf=re.search(r"name=csrf value='([^']+)'",api('/endpoints').decode()).group(1)
            archive=api('/endpoints/installer',dict(csrf=csrf,target=target,server=origin+'/'),True)
            with zipfile.ZipFile(io.BytesIO(archive)) as installer:
                bootstrap=json.loads(installer.read('bootstrap.json'))
        config = dict(server='http://127.0.0.1:1/', endpoint_id='a'*64, credential='b'*64,
                      scanner='/usr/local/bin/clamscan', updater='/usr/local/bin/freshclam',
                      scan_roots=[str(watched)], allow_scripts=False, signature_database=str(database))
        if fleet:
            config.update(server=origin+'/',enrollment_token=bootstrap['enrollment_token'],telemetry=dict(enabled=True,interval_secs=1))
            api('/api/endpoint/enroll',dict(protocol=1,enrollment_token=bootstrap['enrollment_token'],endpoint_id=config['endpoint_id'],credential=config['credential'],hostname='Real engine fleet fixture',platform='linux',arch=platform.machine().lower(),version='0.1.0'))
            config['enrollment_token']=None
        (state/'config.json').write_text(json.dumps(config)); (state/'config.json').chmod(0o600)
        run('configure-protection', state)
        config = json.loads((state/'config.json').read_text())
        config['engine_updates'] = dict(public_key=public, root=str(root/'engines'), allow_unsigned_native=True,
                                        automatic=automatic, managed=fleet)
        (state/'config.json').write_text(json.dumps(config))
        baseline = (state/'config.json').read_bytes()
        version = subprocess.check_output(['/usr/local/bin/clamscan', '--version'], text=True).split()[1].split('/')[0]
        os.environ['ATHERNEX_ENGINE_TEST_VERSION'] = version
        target = 'linux-'+platform.machine().lower()
        bundle = root/'bundle'; assemble(Path('/usr/local'), bundle, target)

        def sign(sequence):
            manifest = root/f'engine-{sequence}.json'
            run('engine-sign', root/'keys/release.pk8', bundle/'content', bundle/'roles.json',
                target, version, 'stable', sequence, int(time.time()*1000)+900000, manifest)
            return manifest

        def request():
            if fleet:
                eventually(reported_ready, 90)
                delivery=propose(published[str(last_manifest)],True)
                checks['reviewed_fleet_installation_authorized_without_local_request']='passed'
                return delivery
            run('engine-request', state, status()['staged'], int(time.time()*1000)+600000)
            return None

        def terminal(sequence, phase):
            record = status()
            return (record['highwater'] == sequence and record['phase'] == phase
                    and not record['recovery_required']
                    and record['maintenance']['phase'] == phase)

        start(); blocking()
        first = sign(1)
        stage(first)
        assert (state/'config.json').read_bytes() == baseline
        assert json.loads(run('update-status', state))['highwater'] == 0
        run('engine-apply', state, ok=False)
        assert active(); blocking()
        checks['online_staging_preserves_active_prevention_and_excludes_live_activation'] = 'passed'
        if fleet:
            # An independently cancelled local request for the same release
            # must not be reused as this deployment's installation result.
            stop()
            run('engine-request',state,status()['staged'],int(time.time()*1000)+600000)
            run('engine-cancel',state,status()['staged'])
            assert status()['maintenance'].get('deployment') is None
            start(); blocking()
        if automatic:
            pid = service.pid
            delivery=request(); eventually(lambda: terminal(1, 'installed'), 240)
            if fleet:
                eventually(lambda: delivered(delivery, True, 'installed'), 60)
                assert status()['maintenance']['deployment']['id']==delivery
                checks['fleet_installation_never_adopts_an_unbound_local_result']='passed'
            eventually(active, 90); blocking()
            assert service.pid == pid and service.poll() is None
            checks['local_request_installs_without_manual_stop_or_restart'] = 'passed'
            stop()
        else:
            stop()
            run('engine-apply', state)
        first_id = status()['installed']; confirmed = (state/'config.json').read_bytes()
        installed = json.loads(confirmed)
        assert installed['scanner'].startswith(str(root/'engines'/first_id))
        assert installed['engine_updates']['active_certificates'].startswith(str(root/'engines'/first_id))
        checks['signed_engine_activates_after_scanner_database_and_native_blocking_checks'] = 'passed'
        start(); blocking()
        raw = json.loads((state/'protection/health.json').read_text())
        maps = '\n'.join(Path(f'/proc/{pid}/maps').read_text() for pid, _ in raw['processes'])
        assert any(str(root/'engines'/first_id) in line and 'libclamav.so' in line for line in maps.splitlines())
        checks['restarted_protection_loads_the_selected_private_engine_library'] = 'passed'
        stop()

        # A controlled native helper reports the expected version but fails when
        # launched as a daemon, after the configuration has switched.
        shutil.copyfile('/test/unhealthy-daemon', bundle/'content/sbin/clamd')
        second = sign(2); stage(second)
        if automatic:
            start(); pid = service.pid
            delivery=request(); eventually(lambda: terminal(2, 'rolled_back'), 240)
            if fleet: eventually(lambda: delivered(delivery, True, 'rolled_back'), 60)
            eventually(active, 90); blocking()
            assert service.pid == pid and service.poll() is None
            checks['controller_restores_active_protection_after_failed_automatic_engine_trial'] = 'passed'
            stop()
        else:
            run('engine-apply', state, ok=False)
        assert status()['phase'] == 'rolled_back' and status()['highwater'] == 2
        assert status()['installed'] == first_id and (state/'config.json').read_bytes() == confirmed
        run('engine-recover', state); run('engine-prune', state)
        checks['native_runtime_failure_restores_confirmed_configuration_and_reserves_sequence'] = 'passed'
        start(); blocking(); stop()
        checks['prior_native_protection_restarts_after_failed_engine_activation'] = 'passed'
        third = sign(3); stage(third)
        third_id = status()['staged']; candidate = root/'engines'/third_id
        marker_dir = root/'trial-marker'; marker_dir.mkdir(mode=0o755)
        os.chown(marker_dir, config['protection']['engine_uid'], config['protection']['engine_gid'])
        trial_marker = marker_dir/'pid'
        with (root/'applying.log').open('w+') as output:
            if automatic:
                os.environ['ATHERNEX_ENGINE_TEST_MODE'] = 'hold'
                os.environ['ATHERNEX_ENGINE_TEST_MARKER'] = str(trial_marker)
                start(); applying = service; delivery=request()
            else:
                applying = subprocess.Popen([str(agent), 'engine-apply', str(state)], stdout=output, stderr=output,
                                            env={**os.environ, 'ATHERNEX_ENGINE_TEST_MODE': 'hold',
                                                 'ATHERNEX_ENGINE_TEST_MARKER': str(trial_marker)})
                processes.append(applying)
            def in_trial():
                if applying.poll() is not None:
                    raise AssertionError('Engine apply ended before crash injection: '+(root/'applying.log').read_text())
                record = json.loads((state/'engine-updates/status.json').read_text())
                current = json.loads((state/'config.json').read_text())
                if record['phase'] == 'verifying' and current['scanner'].startswith(str(candidate)) and trial_marker.exists():
                    pid = int(trial_marker.read_text())
                    return [pid] if alive(pid) else False
                return False
            pids = eventually(in_trial, 90)
            assert status()['recovery_required']
            applying.kill(); applying.wait(timeout=10)
            if automatic:
                service = None
                os.environ.pop('ATHERNEX_ENGINE_TEST_MODE')
                os.environ.pop('ATHERNEX_ENGINE_TEST_MARKER')
            eventually(lambda: all(not alive(pid) for pid in pids), 15)
        assert status()['recovery_required']
        run('run', state, '--once', ok=False, timeout=20)
        if fleet:
            server.kill(); server.wait(timeout=10); server=None
        if automatic:
            start(); blocking()
            if fleet:
                recovered=status()['maintenance']
                assert recovered['phase']=='rolled_back' and not recovered['acknowledged']
                immutable=recovered['receipt']
                assert immutable['deployment_id']==delivery and immutable['outcome']=='rolled_back'
                stop()
                run('engine-prune',state,ok=False)
                assert candidate.exists()
                assert status()['maintenance']['receipt']==immutable
                start(); blocking()
                assert status()['maintenance']['receipt']==immutable
                checks['offline_recovery_preserves_receipt_and_holds_later_maintenance']='passed'
                start_server()
                row=eventually(lambda: delivered(delivery, True, 'rolled_back'), 90)
                assert row['installation_receipt']==immutable
                assert json.loads((state/'engine-updates/delivery.json').read_text())['terminal']
                receipt_url=origin+'/api/endpoint/'+config['endpoint_id']+'/engines/receipt'
                def replay(value):
                    return urllib.request.urlopen(urllib.request.Request(receipt_url,json.dumps(value).encode(),{'Authorization':'Bearer '+config['credential'],'Content-Type':'application/json'}),timeout=10)
                with replay(immutable) as response: assert json.loads(response.read())['committed']
                try:
                    replay({**immutable,'detail':'changed replay'})
                    raise AssertionError('Server accepted changed engine receipt')
                except urllib.error.HTTPError as error:
                    assert error.code==400
                checks['server_restart_commits_exact_result_and_rejects_changed_replay']='passed'
            stop()
            assert status()['maintenance']['phase'] == 'rolled_back'
            checks['controller_restart_recovers_its_interrupted_engine_without_manual_recovery'] = 'passed'
        else:
            run('engine-recover', state); run('engine-recover', state)
        assert status()['installed'] == first_id and status()['highwater'] == 3
        assert (state/'config.json').read_bytes() == confirmed
        run('engine-prune', state)
        assert not candidate.exists()
        checks['updater_death_kills_trial_and_recovery_restores_prior_engine_idempotently'] = 'passed'
        start(); blocking(); stop()

        fourth = sign(4); stage(fourth)
        candidate = root/'engines'/status()['staged']
        (candidate/'bin/clamscan').write_bytes(b'changed signed engine')
        if automatic:
            start(); delivery=request()
            if fleet:
                # A new fleet delivery revalidates the existing tree while
                # staging, so tampering is refused before installation authority.
                row=eventually(lambda: delivered(delivery, outcome='refused'), 90)
                assert row['installation_receipt'] is None
            else:
                eventually(lambda: terminal(4, 'rolled_back'), 90)
            eventually(active, 90); blocking(); stop()
        else:
            run('engine-apply', state, ok=False)
        assert status()['installed'] == first_id and status()['highwater'] == 4
        assert (state/'config.json').read_bytes() == confirmed
        # Local failed activation retires the corrupt tree and prune refuses it.
        # Fleet staging refused it earlier: it remains selected and prune is a
        # successful no-op. Both paths must retain the actual corrupt candidate.
        run('engine-prune', state, ok=fleet)
        assert candidate.exists()
        checks['tampered_candidate_cannot_activate_and_is_retained_for_review'] = 'passed'
        checks['global_engine_and_agent_update_history_remain_unchanged'] = 'passed'
        assert json.loads(run('update-status', state))['highwater'] == 0
        assert subprocess.check_output(['/usr/local/bin/clamscan', '--version'], text=True).split()[1].split('/')[0] == version
        print(json.dumps(checks, indent=2), flush=True)
    except Exception:
        for path in root.glob('*.log'):
            print(path.name+':\n'+path.read_text(errors='replace')[-5000:])
        if (state/'engine-updates/status.json').exists():
            print(run('engine-status', state))
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.kill(); process.wait(timeout=10)
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside-container', action='store_true')
    parser.add_argument('--fleet', action='store_true', help='Deliver and review real engine updates through a local SIEM server')
    parser.add_argument('--rollout', action='store_true', help='Verify two real endpoints, observed promotion and failed-canary containment')
    parser.add_argument('--server', type=Path, default=Path('target/debug/athernex-siem'))
    parser.add_argument('--automatic', action='store_true', help='Verify local controller-owned activation and restart recovery')
    parser.add_argument('--engine-prefix', type=Path)
    parser.add_argument('--agent', type=Path, default=Path('target/release/athernex-endpoint'))
    parser.add_argument('--image', default='athernex-native-protection-fixture:local')
    args = parser.parse_args()
    if args.inside_container:
        if args.rollout:
            from engine_rollout import inside_rollout
            inside_rollout(alive); return
        inside(args.automatic or args.fleet, args.fleet); return
    if args.engine_prefix is None:
        parser.error('--engine-prefix must identify the verified extracted ClamAV prefix')
    # Test state lives in tmpfs; protect the host's filesystem and RAM as well.
    # Never pull/build images or compile Cargo packages from this verifier.
    for location in [Path.cwd(), Path('/var/lib/docker')]:
        if location.exists() and shutil.disk_usage(location).free < 2 * 1024**3:
            parser.error(f'At least 2 GiB host free space required at {location}; fixture not started')
    if shutil.disk_usage(tempfile.gettempdir()).free < 256 * 1024**2:
        parser.error('Temporary directory needs 256 MiB free; fixture not started')
    memory = Path('/proc/meminfo')
    if memory.exists():
        available = int(re.search(r'^MemAvailable:\s+(\d+)', memory.read_text(), re.MULTILINE).group(1))*1024
        if available < 4 * 1024**3:
            parser.error('At least 4 GiB available host memory required; fixture not started')
    with tempfile.TemporaryDirectory(prefix='athernex-engine-test-binary-') as temporary:
        agent = Path(temporary)/'agent'; shutil.copy2(args.agent, agent)
        subprocess.run(['strip', str(agent)], check=True)
        source = Path(temporary)/'unhealthy.rs'
        source.write_text('''use std::{env,fs,thread,time::Duration};
fn main() {
    if env::args().any(|argument| argument == "--version") {
        println!("ClamAV {}", env::var("ATHERNEX_ENGINE_TEST_VERSION").unwrap());
    } else if env::var("ATHERNEX_ENGINE_TEST_MODE").unwrap_or_default() == "hold" {
        fs::write(env::var("ATHERNEX_ENGINE_TEST_MARKER").unwrap(), std::process::id().to_string()).unwrap();
        loop { thread::sleep(Duration::from_secs(1)); }
    } else { std::process::exit(42); }
}
''')
        unhealthy = Path(temporary)/'unhealthy-daemon'
        subprocess.run(['rustc', str(source), '-o', str(unhealthy)], check=True)
        verifier = Path(temporary)/'verify.py'; shutil.copy2(Path(__file__), verifier)
        packager = Path(temporary)/'package_engine.py'; shutil.copy2(Path(__file__).with_name('package_engine.py'), packager)
        inputs = dict(endpoint_sha256=hashlib.sha256(agent.read_bytes()).hexdigest(),
                      verifier_sha256=hashlib.sha256(verifier.read_bytes()).hexdigest(),
                      packager_sha256=hashlib.sha256(packager.read_bytes()).hexdigest())
        container_id = Path(temporary)/'container.cid'
        command = ['docker', '--host=unix:///var/run/docker.sock', 'run', '--pull', 'never', '--init', '--rm', '--cidfile', str(container_id), '--network', 'none', '--cap-add', 'SYS_ADMIN',
                   '--cap-add', 'DAC_READ_SEARCH', '--cap-add', 'SYS_PTRACE', '--memory', '3g' if args.rollout else '2g', '--memory-swap', '3g' if args.rollout else '2g', '--cpus', '2', '--pids-limit', '128',
                   '--log-driver', 'none', '--ulimit', 'core=0',
                   '--tmpfs', '/fixture:rw,exec,nosuid,nodev,size='+('2g' if args.rollout else '1g')+',mode=0755']
        for source, destination in [(agent, '/test/agent'), (unhealthy, '/test/unhealthy-daemon'), (args.engine_prefix, '/usr/local'),
                                    (verifier, '/test/verify.py'), (packager, '/test/package_engine.py')]:
            command += ['--mount', f'type=bind,source={source.resolve()},target={destination},readonly']
        if args.fleet or args.rollout:
            server=Path(temporary)/'server'; shutil.copy2(args.server, server)
            inputs['server_sha256']=hashlib.sha256(server.read_bytes()).hexdigest()
            command += ['--mount', f'type=bind,source={server.resolve()},target=/test/server,readonly']
        if args.rollout:
            rollout = Path(temporary)/'engine_rollout.py'
            shutil.copy2(Path(__file__).with_name('engine_rollout.py'), rollout)
            inputs['rollout_verifier_sha256'] = hashlib.sha256(rollout.read_bytes()).hexdigest()
            command += ['--mount', f'type=bind,source={rollout.resolve()},target=/test/engine_rollout.py,readonly']
        command += [args.image, 'python3', '/test/verify.py', '--inside-container']
        if args.fleet:
            command += ['--fleet']
        if args.automatic:
            command += ['--automatic']
        if args.rollout:
            command += ['--rollout']
        print(json.dumps(dict(validation_inputs=inputs)), flush=True)
        try:
            subprocess.run(command, check=True, timeout=900)
        finally:
            # A timed-out Docker client does not stop its container. Remove only
            # this invocation's exact container before releasing the test mounts.
            if container_id.exists():
                identifier=container_id.read_text().strip()
                if re.fullmatch(r'[0-9a-f]{64}', identifier):
                    subprocess.run(['docker','--host=unix:///var/run/docker.sock','rm','-f',identifier],
                                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False)


if __name__ == '__main__':
    main()
