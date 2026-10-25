#!/usr/bin/env python3
"""Exercise launcher-owned controller replacement using disposable local services."""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

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
import zipfile
from verify_endpoint_update import alive, eventually


def main():
    if sys.platform == 'darwin':
        raise SystemExit('Automatic controller replacement remains disabled on macOS')
    suffix = '.exe' if os.name == 'nt' else ''
    source = Path('target/release/athernex-endpoint'+suffix).resolve()
    server_source = Path('target/release/athernex-siem'+suffix).resolve()
    target = ('windows' if os.name == 'nt' else 'linux')+'-'+{'amd64':'x86_64','x86_64':'x86_64','aarch64':'aarch64','arm64':'aarch64'}[platform.machine().lower()]
    processes = []; checks = {}; launcher = None
    with tempfile.TemporaryDirectory(prefix='athernex-controller-maintenance-') as temporary:
        root = private_fixture_root(temporary)
        launcher_binary = root/('launcher'+suffix); controller = root/('controller'+suffix)
        agent = root/('agent'+suffix); updater = root/('updater'+suffix)
        for path in [launcher_binary, controller, agent, updater]:
            shutil.copy2(source, path); path.chmod(0o700)
        baseline = hashlib.sha256(agent.read_bytes()).hexdigest()
        state = root/'state'; create_private_directory(state)
        catalog = root/'catalog'; catalog.mkdir()
        shutil.copy2(agent, catalog/('athernex-endpoint-'+target+suffix))
        (catalog/(target+'.json')).write_text(json.dumps(dict(target=target,version='fixture',sha256=baseline,signing='development-unsigned')))
        key = 'controlled-controller-fixture-'+'a'*32
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'

        def run(*args, ok=True, env=None):
            result = subprocess.run([str(updater),*map(str,args)],capture_output=True,text=True,timeout=40,env=env)
            assert (result.returncode == 0) == ok, result.stderr+result.stdout
            return result.stdout

        def request(path, body=None):
            headers = {'Authorization':'Bearer '+key}; data = None
            if body is not None:
                data = urllib.parse.urlencode(body).encode(); headers['Content-Type'] = 'application/x-www-form-urlencoded'
            with urllib.request.urlopen(urllib.request.Request(origin+path,data,headers),timeout=10) as response:
                return response.read()

        def online():
            try: return request('/healthz')
            except OSError: return False

        def status():
            return json.loads(run('controller-update-status', state))

        def maintenance():
            return json.loads(run('controller-maintenance-status', state))

        def healthy():
            if launcher.poll() is not None:
                raise AssertionError('Launcher exited before health: '+logs[-1].read_text(errors='replace'))
            path = state/'supervisor/ready.json'; lease = state/'supervisor/lease.json'
            if not path.exists() or not lease.exists(): return False
            ready = json.loads(path.read_text()); owner = json.loads(lease.read_text())
            launched = json.loads((state/'supervisor/launcher.json').read_text())
            return (ready['token'] == owner['token'] and ready['pid'] == owner.get('child_pid')
                    and launched['controller_pid'] == owner['controller_pid'] and alive(ready['pid'])
                    and ready['time_ms'] >= launched['started_ms'])

        logs = []
        def start(mode=''):
            nonlocal launcher
            path = root/f'launcher-{len(logs)}.log'; logs.append(path)
            with path.open('w') as output:
                launcher = subprocess.Popen([str(launcher_binary),'launch',str(state),str(controller),str(agent)],stdout=output,stderr=output,
                    env={**os.environ,'ATHERNEX_CONTROLLER_FIXTURE_MODE':mode,'ATHERNEX_CONTROLLER_FIXTURE_MARKER':str(root/'candidate.pid')})
            processes.append(launcher)
            eventually(healthy, 45)

        def stop():
            nonlocal launcher
            pids = []
            for name, field in [('supervisor/launcher.json','controller_pid'),('supervisor/lease.json','child_pid')]:
                path = state/name
                if path.exists():
                    pid = json.loads(path.read_text()).get(field)
                    if pid: pids.append(pid)
            launcher.kill(); launcher.wait(timeout=10); launcher = None
            eventually(lambda: all(not alive(pid) for pid in pids), 20)

        def stage(sequence, binary, version):
            manifest = root/f'controller-{sequence}.json'
            run('release-sign',root/'keys/release.pk8',binary,version,'stable',sequence,int(time.time()*1000)+900000,manifest)
            value = json.loads(run('controller-update-stage',state,manifest,binary))
            return hashlib.sha256(json.dumps(value['staged'],separators=(',',':')).encode()).hexdigest(), manifest

        def authorize(identifier, deadline=None):
            run('controller-update-request',state,identifier,deadline if deadline is not None else int(time.time()*1000)+600000)

        def completed(outcome, sequence):
            value = maintenance()
            if value is None or value['phase'] in ['queued','applying']: return False
            assert value['phase'] == outcome, value
            record = status(); assert record['highwater'] == sequence and record['transaction'] is None
            return True

        try:
            env = {**os.environ,'ATHERNEX_OPERATOR_KEY':key,'ATHERNEX_ENDPOINT_ARTIFACTS':str(catalog)}
            env.pop('ATHERNEX_PUBLIC_ORIGIN',None)
            with (root/'server.log').open('w') as output:
                server = subprocess.Popen([str(server_source),'--no-journal','--db',str(root/'ledger.db'),'--port',str(port)],env=env,stdout=output,stderr=output)
            processes.append(server); eventually(online,20)
            csrf = re.search(r"name=csrf value='([^']+)'",request('/endpoints').decode()).group(1)
            archive = request('/endpoints/installer',dict(csrf=csrf,target=target,server=origin+'/'))
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                bootstrap = json.loads(bundle.read('bootstrap.json'))
            (root/'bootstrap.json').write_text(json.dumps(bootstrap))
            public = run('release-keygen',root/'keys').strip()
            config = dict(server=origin+'/',endpoint_id='b'*64,credential='c'*64,enrollment_token=bootstrap['enrollment_token'],
                          scanner=str(root/'absent-scanner'),updater=str(root/'absent-updater'),scan_roots=[str(root)],allow_scripts=False,
                          telemetry=dict(enabled=False,interval_secs=30),
                          updates=dict(public_key=public,channel='stable',install_path=str(agent),controller_path=str(controller),
                                       launcher_path=str(launcher_binary),controller_automatic=True,allow_unsigned_native=True))
            (state/'config.json').write_text(json.dumps(config)); (state/'config.json').chmod(0o600)
            run('enroll',root/'bootstrap.json',state)
            original_config = (state/'config.json').read_bytes()
            version = json.loads(run('release-check','a'*64))['version']
            candidate = root/('candidate'+suffix)
            candidate.write_bytes(agent.read_bytes()+b'\nPublic distinct controller fixture\n'); candidate.chmod(0o700)
            expected = hashlib.sha256(candidate.read_bytes()).hexdigest()
            identifier, _ = stage(1,candidate,version)
            # Requests can be cancelled/expire before the launcher is started.
            authorize(identifier); run('controller-update-cancel',state,identifier)
            start(); assert maintenance()['phase'] == 'cancelled'
            assert hashlib.sha256(controller.read_bytes()).hexdigest() == baseline
            stop(); authorize(identifier,int(time.time()*1000)+100); time.sleep(.2)
            start(); eventually(lambda: maintenance()['phase'] == 'refused')
            assert hashlib.sha256(controller.read_bytes()).hexdigest() == baseline
            checks['cancelled_and_expired_requests_preserve_the_running_controller'] = 'passed'
            second = subprocess.run([str(launcher_binary),'launch',str(state),str(controller),str(agent)],capture_output=True,timeout=10)
            assert second.returncode != 0 and launcher.poll() is None
            run('controller-update-apply',state,ok=False)
            checks['launcher_lock_excludes_a_second_launcher_and_offline_controller_replacement'] = 'passed'
            old_pid = json.loads((state/'supervisor/launcher.json').read_text())['controller_pid']
            authorize(identifier); eventually(lambda: completed('installed',1),90); eventually(healthy,45)
            assert hashlib.sha256(controller.read_bytes()).hexdigest() == expected
            assert json.loads((state/'supervisor/launcher.json').read_text())['controller_pid'] != old_pid
            assert launcher.poll() is None
            assert (state/'config.json').read_bytes() == original_config
            assert hashlib.sha256(agent.read_bytes()).hexdigest() == baseline
            checks['signed_controller_install_requires_its_real_managed_server_cycle'] = 'passed'
            checks['controller_install_preserves_agent_configuration_and_agent_release_history'] = 'passed'

            helper_source = root/'unhealthy.rs'
            helper_source.write_text('''use std::{env,fs,thread,time::Duration};
fn hold(){fs::write(env::var("ATHERNEX_CONTROLLER_FIXTURE_MARKER").unwrap(),std::process::id().to_string()).unwrap();loop{thread::sleep(Duration::from_secs(1));}}
fn main(){let a:Vec<String>=env::args().collect();let mode=env::var("ATHERNEX_CONTROLLER_FIXTURE_MODE").unwrap_or_default();
if a.get(1).map(String::as_str)==Some("release-check") {
 if mode=="preflight_hold" {hold();}
 println!("{{\\"challenge\\":\\"{}\\",\\"protocol\\":1,\\"target\\":\\"{}-{}\\",\\"version\\":\\"controller-fixture\\",\\"controller_protocol\\":1}}",a[2],env::consts::OS,env::consts::ARCH);
} else if mode=="hold" {hold();} else {std::process::exit(42);}}
''')
            bad = root/('unhealthy'+suffix)
            subprocess.run(['rustc','--edition=2021',str(helper_source),'-o',str(bad)],check=True,timeout=60)
            identifier, manifest = stage(2,bad,'controller-fixture'); authorize(identifier)
            eventually(lambda: completed('rolled_back',2),60); eventually(healthy,45)
            assert hashlib.sha256(controller.read_bytes()).hexdigest() == expected
            run('controller-update-stage',state,manifest,bad,ok=False)
            checks['runtime_failure_rolls_back_controller_and_reserves_failed_sequence'] = 'passed'
            stop(); start('hold')
            identifier, _ = stage(3,bad,'controller-fixture'); authorize(identifier)
            marker = root/'candidate.pid'; eventually(lambda: marker.exists() and marker.read_text().strip(),60)
            pid = int(marker.read_text()); assert alive(pid) and status()['transaction']['trial'] is not None
            stop(); eventually(lambda: not alive(pid),20)
            assert status()['transaction'] is not None
            start(); eventually(lambda: completed('rolled_back',3),45)
            assert hashlib.sha256(controller.read_bytes()).hexdigest() == expected
            stop(); start(); assert healthy(); stop()
            assert not list(root.glob('.athernex-backup-*'))
            checks['launcher_death_kills_candidate_and_restart_recovers_idempotently'] = 'passed'

            marker.unlink()
            _, _ = stage(4,bad,'controller-fixture')
            with (root/'manual.log').open('w') as output:
                applying = subprocess.Popen([str(updater),'controller-update-apply',str(state)],stdout=output,stderr=output,
                    env={**os.environ,'ATHERNEX_CONTROLLER_FIXTURE_MODE':'preflight_hold','ATHERNEX_CONTROLLER_FIXTURE_MARKER':str(marker)})
            processes.append(applying); eventually(lambda: marker.exists() and marker.read_text().strip(),40)
            pid = int(marker.read_text()); applying.kill(); applying.wait(timeout=10); eventually(lambda: not alive(pid),20)
            refused = subprocess.run([str(launcher_binary),'launch',str(state),str(controller),str(agent)],capture_output=True,timeout=15)
            assert refused.returncode != 0 and status()['transaction'] is not None
            run('controller-update-recover',state); run('controller-update-recover',state)
            start(); assert healthy()
            checks['launcher_refuses_to_adopt_a_manually_interrupted_replacement'] = 'passed'
            assert hashlib.sha256(agent.read_bytes()).hexdigest() == baseline
            assert json.loads(run('update-status',state))['highwater'] == 0
            assert (state/'config.json').read_bytes() == original_config
            stop()

            confirmed_bytes = controller.read_bytes()
            controller.write_bytes(bad.read_bytes())
            refused = subprocess.run([str(launcher_binary),'launch',str(state),str(controller),str(agent)],capture_output=True,text=True,timeout=15)
            assert refused.returncode != 0 and 'outside the signed release ledger' in refused.stderr, refused.stderr
            controller.write_bytes(confirmed_bytes)
            checks['launcher_rejects_altered_confirmed_controller_before_executing_it'] = 'passed'

            # Model the missing-destination interruption boundary after retaining
            # a verified agent backup. Recovery must happen before path opening.
            marker.unlink()
            agent_manifest = root/'agent-interruption.json'
            run('release-sign',root/'keys/release.pk8',bad,'controller-fixture','stable',1,int(time.time()*1000)+900000,agent_manifest)
            run('update-stage',state,agent_manifest,bad)
            with (root/'agent-interruption.log').open('w') as output:
                applying = subprocess.Popen([str(updater),'update-apply',str(state)],stdout=output,stderr=output,
                    env={**os.environ,'ATHERNEX_CONTROLLER_FIXTURE_MODE':'preflight_hold','ATHERNEX_CONTROLLER_FIXTURE_MARKER':str(marker)})
            processes.append(applying); eventually(lambda: marker.exists() and marker.read_text().strip(),40)
            pid = int(marker.read_text()); applying.kill(); applying.wait(timeout=10); eventually(lambda: not alive(pid),20)
            transaction = json.loads(run('update-status',state))['transaction']
            os.link(agent,transaction['backup']['path']); agent.unlink()
            assert not agent.exists()
            start(); assert healthy()
            recovered = json.loads(run('update-status',state))
            assert recovered['transaction'] is None and recovered['highwater']==1 and recovered['last_result']=='rolled_back'
            assert hashlib.sha256(agent.read_bytes()).hexdigest()==baseline
            stop()
            checks['launcher_recovers_missing_agent_destination_before_controller_startup'] = 'passed'
            print(json.dumps(dict(schema=1,checks=checks,source_sha256=baseline,native_prevention_enabled=False),indent=2),flush=True)
        except Exception:
            for path in root.glob('*.log'):
                print(path.name+':\n'+path.read_text(errors='replace')[-8000:],file=sys.stderr)
            if (state/'updates/controller/maintenance.json').exists(): print(run('controller-maintenance-status',state),file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None: process.kill(); process.wait(timeout=10)


if __name__ == '__main__':
    main()
