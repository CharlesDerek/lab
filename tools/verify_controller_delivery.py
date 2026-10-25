#!/usr/bin/env python3
"""Exercise reviewed fleet controller delivery, runtime confirmation and durable recovery receipts."""
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
import urllib.error
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
    processes = []; checks = {}; launcher = None; server = None
    with tempfile.TemporaryDirectory(prefix='athernex-controller-delivery-') as temporary:
        root = private_fixture_root(temporary)
        launcher_binary = root/('launcher'+suffix); controller = root/('controller'+suffix)
        agent = root/('agent'+suffix); updater = root/('updater'+suffix)
        for path in [launcher_binary, controller, agent, updater]:
            shutil.copy2(source, path); path.chmod(0o700)
        server_binary = root/('server'+suffix); shutil.copy2(server_source, server_binary); server_binary.chmod(0o700)
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
        def start(mode='', wait=True):
            nonlocal launcher
            path = root/f'launcher-{len(logs)}.log'; logs.append(path)
            with path.open('w') as output:
                launcher = subprocess.Popen([str(launcher_binary),'launch',str(state),str(controller),str(agent)],stdout=output,stderr=output,
                    env={**os.environ,'ATHERNEX_CONTROLLER_FIXTURE_MODE':mode,'ATHERNEX_CONTROLLER_FIXTURE_MARKER':str(root/'candidate.pid')})
            processes.append(launcher)
            if wait: eventually(healthy, 45)

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

        def publish(sequence, binary, version):
            manifest = root/f'controller-{sequence}.json'
            run('release-sign',root/'keys/release.pk8',binary,version,'stable',sequence,int(time.time()*1000)+900000,manifest)
            return run('release-publish',manifest,binary,public,root/'releases').strip()

        def rows():
            return json.loads(request('/api/endpoint-updates'))

        def propose(identifier, install=True, approve=True):
            fields = dict(csrf=csrf,op='propose',id=config['endpoint_id'],release_id=identifier,component='controller')
            if install: fields['install'] = 'on'
            request('/endpoints/updates/action', fields)
            deployment = rows()[0]['deployment']
            assert deployment['component'] == 'controller' and bool(deployment.get('install')) == install
            if approve: request('/endpoints/updates/action',dict(csrf=csrf,op='approve',id=deployment['id']))
            return deployment['id']

        def completed(identifier, outcome):
            row = next(r for r in rows() if r['deployment']['id'] == identifier)
            if row['installation'] is None: return False
            assert row['installation']['outcome'] == outcome, row
            return row

        def stage_receipt(identifier):
            row = next(r for r in rows() if r['deployment']['id'] == identifier)
            if row['receipt'] is None: return False
            assert row['receipt']['outcome'] == 'staged', row
            return row

        def endpoint_health():
            return json.loads(request('/api/endpoints'))['endpoints'][0]['health']

        def start_server():
            nonlocal server
            env = {**os.environ,'ATHERNEX_OPERATOR_KEY':key,'ATHERNEX_ENDPOINT_ARTIFACTS':str(catalog),'ATHERNEX_ENDPOINT_RELEASES':str(root/'releases')}
            env.pop('ATHERNEX_PUBLIC_ORIGIN',None)
            with (root/f'server-{len(processes)}.log').open('w') as output:
                server = subprocess.Popen([str(server_binary),'--no-journal','--db',str(root/'ledger.db'),'--port',str(port)],env=env,stdout=output,stderr=output)
            processes.append(server); eventually(online,20)

        try:
            start_server()
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
                                       launcher_path=str(launcher_binary),controller_automatic=True,controller_managed=True,allow_unsigned_native=True))
            (state/'config.json').write_text(json.dumps(config)); (state/'config.json').chmod(0o600)
            run('enroll',root/'bootstrap.json',state)
            original_config = (state/'config.json').read_bytes()
            version = json.loads(run('release-check','a'*64))['version']
            candidate = root/('candidate'+suffix)
            candidate.write_bytes(agent.read_bytes()+b'\nPublic distinct controller fixture\n'); candidate.chmod(0o700)
            expected = hashlib.sha256(candidate.read_bytes()).hexdigest()
            start()
            eventually(lambda: endpoint_health().get('controller_updates',{}).get('supervised'),30)
            assert endpoint_health()['updates']['managed'] is False
            identifier = publish(1,candidate,version)
            # Agent delivery permission must not be inferred from controller opt-in.
            try:
                request('/endpoints/updates/action',dict(csrf=csrf,op='propose',id=config['endpoint_id'],release_id=identifier,component='agent'))
                raise AssertionError('Controller permission authorized an agent deployment')
            except urllib.error.HTTPError as error:
                assert error.code == 400
            checks['controller_permission_does_not_authorize_agent_delivery'] = 'passed'
            delivery = propose(identifier,install=False)
            eventually(lambda: stage_receipt(delivery),90)
            assert maintenance() is None
            assert hashlib.sha256(controller.read_bytes()).hexdigest() == baseline
            assert json.loads(run('update-status',state))['highwater'] == 0
            checks['reviewed_staging_only_preserves_running_controller_and_agent_history'] = 'passed'
            identifier = publish(2,candidate,version)
            cancelled = propose(identifier,approve=False)
            request('/endpoints/updates/action',dict(csrf=csrf,op='cancel',id=cancelled))
            assert next(r for r in rows() if r['deployment']['id']==cancelled)['state'] == 'cancelled'
            delivery = propose(identifier)
            eventually(lambda: completed(delivery,'installed'),120)
            eventually(lambda: maintenance()['acknowledged'],30)
            eventually(healthy,45)
            assert hashlib.sha256(controller.read_bytes()).hexdigest() == expected
            assert hashlib.sha256(agent.read_bytes()).hexdigest() == baseline
            assert (state/'config.json').read_bytes() == original_config
            assert endpoint_health()['controller_updates']['installed_release'] == identifier
            assert endpoint_health()['updates']['installed_release'] is None
            row=next(r for r in rows() if r['deployment']['id']==cancelled)
            assert row['receipt'] is None and row['installation'] is None
            checks['cancelled_controller_approval_does_not_dispatch'] = 'passed'
            checks['portal_approved_controller_install_confirms_runtime_and_retains_both_receipts'] = 'passed'
            page=request('/endpoint-updates').decode()
            assert 'Controller updates' in page and 'Component: Controller' in page and 'Installation receipt: installed' in page
            checks['portal_distinguishes_controller_target_policy_and_installation_result'] = 'passed'

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
            identifier = publish(3,bad,'controller-fixture'); delivery = propose(identifier)
            eventually(lambda: completed(delivery,'rolled_back'),120)
            eventually(lambda: maintenance()['acknowledged'],30)
            eventually(healthy,45)
            assert hashlib.sha256(controller.read_bytes()).hexdigest() == expected
            assert status()['highwater'] == 3 and status()['transaction'] is None
            checks['failed_fleet_controller_rolls_back_and_reserves_sequence'] = 'passed'

            stop(); start('hold')
            identifier = publish(4,bad,'controller-fixture'); delivery = propose(identifier)
            marker = root/'candidate.pid'; eventually(lambda: marker.exists() and marker.read_text().strip(),90)
            pid = int(marker.read_text()); assert alive(pid) and status()['transaction']['trial'] is not None
            # Lose both the launcher and server while the candidate is unconfirmed.
            server.kill(); server.wait(timeout=10)
            stop(); eventually(lambda: not alive(pid),20)
            start(wait=False)
            eventually(lambda: maintenance()['phase']=='rolled_back',30)
            retained = maintenance()['receipt']; assert retained['deployment_id']==delivery
            assert maintenance()['acknowledged'] is False
            assert status()['highwater']==4 and status()['transaction'] is None
            assert hashlib.sha256(controller.read_bytes()).hexdigest()==expected
            # An undelivered result must survive another restart and must not be
            # overwritten by an unrelated local maintenance request.
            run('controller-update-request',state,identifier,int(time.time()*1000)+600000,ok=False)
            stop(); start(wait=False)
            eventually(lambda: maintenance()['receipt']==retained,15)
            checks['launcher_crash_recovers_without_server_and_retains_exact_installation_receipt'] = 'passed'
            start_server(); eventually(healthy,60)
            row=eventually(lambda: completed(delivery,'rolled_back'),90)
            eventually(lambda: maintenance()['acknowledged'],30)
            assert row['installation']==retained and row['receipt']['outcome']=='staged'
            assert maintenance()['receipt']==retained
            assert json.loads((state/'updates/controller/delivery.json').read_text())['terminal'] is True
            assert json.loads(run('update-status',state))['highwater']==0
            assert hashlib.sha256(agent.read_bytes()).hexdigest()==baseline
            assert (state/'config.json').read_bytes()==original_config
            checks['server_restart_commits_immutable_recovered_receipt_and_preserves_agent_configuration'] = 'passed'
            stop()
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
