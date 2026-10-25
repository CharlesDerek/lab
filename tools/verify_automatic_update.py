#!/usr/bin/env python3
"""Exercise reviewed automatic updates using disposable services and signing keys."""
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
from verify_endpoint_update import alive


def eventually(check, timeout=180):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=check()
        if value:
            return value
        time.sleep(.2)
    raise AssertionError('Automatic update condition timed out')


def main():
    if sys.platform=='darwin':
        raise SystemExit('macOS automatic installation remains gated on process-cleanup integration')
    suffix='.exe' if os.name=='nt' else ''
    source=Path('target/release/athernex-endpoint'+suffix).resolve()
    server_binary=Path('target/release/athernex-siem'+suffix).resolve()
    target=('windows' if os.name=='nt' else 'linux')+'-'+{'amd64':'x86_64','x86_64':'x86_64','aarch64':'aarch64','arm64':'aarch64'}[platform.machine().lower()]
    processes=[]
    with tempfile.TemporaryDirectory(prefix='athernex-automatic-fixture-') as temp:
        root=private_fixture_root(temp)
        controller=root/('controller'+suffix);installed=root/('installed'+suffix)
        shutil.copy2(source,controller);shutil.copy2(source,installed);installed.chmod(0o700)
        baseline=hashlib.sha256(installed.read_bytes()).hexdigest()
        catalog=root/'catalog';catalog.mkdir()
        shutil.copy2(source,catalog/('athernex-endpoint-'+target+suffix))
        (catalog/(target+'.json')).write_text(json.dumps(dict(target=target,version='fixture',sha256=baseline,signing='development-unsigned')))
        state=root/'state';create_private_directory(state)
        public=subprocess.check_output([str(controller),'release-keygen',str(root/'keys')],text=True).strip()
        key='controlled-automatic-fixture-'+'a'*32
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        origin=f'http://127.0.0.1:{port}'
        env=dict(os.environ,ATHERNEX_OPERATOR_KEY=key,ATHERNEX_ENDPOINT_ARTIFACTS=str(catalog),ATHERNEX_ENDPOINT_RELEASES=str(root/'releases'))
        env.pop('ATHERNEX_PUBLIC_ORIGIN',None)

        def request(path,body=None):
            headers={'Authorization':'Bearer '+key}
            data=None
            if body is not None:
                data=urllib.parse.urlencode(body).encode();headers['Content-Type']='application/x-www-form-urlencoded'
            with urllib.request.urlopen(urllib.request.Request(origin+path,data,headers),timeout=10) as response:
                return response.read()

        def online():
            try:
                return request('/healthz')
            except OSError:
                return False

        def start_controller(mode=''):
            with (root/('controller-'+str(time.monotonic_ns())+'.log')).open('w') as log:
                child=subprocess.Popen([str(controller),'supervise',str(state),str(installed)],stdout=log,stderr=log,
                    env=dict(os.environ,ATHERNEX_AUTOMATIC_FIXTURE_MODE=mode,ATHERNEX_AUTOMATIC_FIXTURE_MARKER=str(root/'candidate.pid')))
            processes.append(child);return child

        def health():
            return json.loads(request('/api/endpoints'))['endpoints'][0]['health']['updates']

        def publish(binary,sequence,version):
            manifest=root/f'release-{sequence}.json'
            subprocess.run([str(controller),'release-sign',str(root/'keys/release.pk8'),str(binary),version,'stable',str(sequence),str(int(time.time()*1000)+900000),str(manifest)],check=True)
            return subprocess.check_output([str(controller),'release-publish',str(manifest),str(binary),public,str(root/'releases')],text=True).strip()

        def propose(release_id):
            request('/endpoints/updates/action',dict(csrf=csrf,op='propose',id=endpoint,release_id=release_id,install='on'))
            deployment=json.loads(request('/api/endpoint-updates'))[0]['deployment']
            assert deployment['install'] is True
            request('/endpoints/updates/action',dict(csrf=csrf,op='approve',id=deployment['id']))
            return deployment['id']

        def completed(deployment,outcome):
            records=json.loads(request('/api/endpoint-updates'))
            record=next(r for r in records if r['deployment']['id']==deployment)
            if record['installation'] is not None:
                assert record['installation']['outcome']==outcome,record
                return record
            return False

        try:
            with (root/'server.log').open('w') as log:
                server=subprocess.Popen([str(server_binary),'--no-journal','--db',str(root/'ledger.db'),'--port',str(port)],env=env,stdout=log,stderr=log)
            processes.append(server)
            eventually(online,20)
            csrf=re.search(r"name=csrf value='([^']+)'",request('/endpoints').decode()).group(1)
            archive=request('/endpoints/installer',dict(csrf=csrf,target=target,server=origin+'/'))
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                bootstrap=json.loads(bundle.read('bootstrap.json'))
            (root/'bootstrap.json').write_text(json.dumps(bootstrap))
            config=dict(server=origin+'/',endpoint_id='b'*64,credential='c'*64,enrollment_token=bootstrap['enrollment_token'],scanner=str(root/'no-scanner'),updater=str(root/'no-updater'),scan_roots=[str(root)],allow_scripts=False,
                        telemetry=dict(enabled=True,interval_secs=2),
                        updates=dict(managed=True,automatic=True,public_key=public,channel='stable',install_path=str(installed),minimum_sequence=0,allow_unsigned_native=True))
            (state/'config.json').write_text(json.dumps(config));(state/'config.json').chmod(0o600)
            subprocess.run([str(installed),'enroll',str(root/'bootstrap.json'),str(state)],check=True,stdout=subprocess.DEVNULL)
            endpoint=config['endpoint_id']
            supervisor=start_controller()
            eventually(lambda:health().get('supervised',False),20)
            def sampled_after(timestamp):
                observations=json.loads(request('/api/endpoints/'+endpoint+'/events'))
                return any(item['event'].get('telemetry') is not None and item['event']['time_ms']>timestamp for item in observations)
            eventually(lambda:sampled_after(0),30)
            duplicate=subprocess.run([str(controller),'supervise',str(state),str(installed)],capture_output=True,text=True,timeout=10)
            assert duplicate.returncode!=0 and 'Another endpoint controller' in duplicate.stderr
            info=json.loads(subprocess.check_output([str(source),'release-check','a'*64],text=True))
            release=publish(source,1,info['version']);deployment=propose(release)
            eventually(lambda:completed(deployment,'installed'))
            # Installation receipts and periodic endpoint health are delivered
            # independently. Require the matching health report within the
            # existing deadline instead of assuming both arrive together.
            eventually(lambda:health().get('installed_release')==release)
            installed_at=int(time.time()*1000)
            # A fresh process makes a new observation possible even on a quiet
            # host. Partial snapshots are valid; require delivered evidence.
            processes.append(subprocess.Popen([sys.executable,'-c','import time; time.sleep(35)']))
            eventually(lambda:sampled_after(installed_at),30)
            print('approved automatic replacement and live health: passed',flush=True)

            bad_source=root/'unhealthy.rs'
            bad_source.write_text(r'''
use std::{env,fs,thread,time::Duration};
fn main(){let args:Vec<String>=env::args().collect();
if args.get(1).map(String::as_str)==Some("release-check") {
 println!("{{\"challenge\":\"{}\",\"protocol\":1,\"target\":\"{}-{}\",\"version\":\"runtime-fixture\"}}",args[2],env::consts::OS,env::consts::ARCH);
}else if env::var("ATHERNEX_AUTOMATIC_FIXTURE_MODE").unwrap_or_default()=="hold" {
 fs::write(env::var("ATHERNEX_AUTOMATIC_FIXTURE_MARKER").unwrap(),std::process::id().to_string()).unwrap();
 loop{thread::sleep(Duration::from_secs(1));}
}else{std::process::exit(42)}}
''')
            bad=root/('unhealthy'+suffix);subprocess.run(['rustc','--edition=2021',str(bad_source),'-o',str(bad)],check=True,timeout=60)
            release=publish(bad,2,'runtime-fixture');deployment=propose(release)
            eventually(lambda:completed(deployment,'rolled_back'))
            assert hashlib.sha256(installed.read_bytes()).hexdigest()==baseline
            assert json.loads((state/'updates/status.json').read_text())['highwater']==2
            print('readiness-only executable rejected by real runtime trial: passed',flush=True)

            supervisor.kill();supervisor.wait(timeout=10)
            supervisor=start_controller('hold')
            eventually(lambda:health().get('supervised',False) and health()['state']=='rolled_back',20)
            release=publish(bad,3,'runtime-fixture');deployment=propose(release)
            marker=root/'candidate.pid';eventually(lambda:marker.exists() and marker.read_text().strip())
            candidate_pid=int(marker.read_text())
            assert alive(candidate_pid)
            assert json.loads((state/'updates/status.json').read_text())['transaction']['trial'] is not None
            supervisor.kill();supervisor.wait(timeout=10)
            eventually(lambda:not alive(candidate_pid),10)
            supervisor=start_controller()
            eventually(lambda:completed(deployment,'rolled_back'),30)
            assert hashlib.sha256(installed.read_bytes()).hexdigest()==baseline
            status=json.loads((state/'updates/status.json').read_text());assert status['transaction'] is None and status['highwater']==3
            assert not list(root.glob('.athernex-backup-*'))
            print('controller crash kills candidate and restores confirmed agent: passed',flush=True)
            print(json.dumps(dict(automatic_install='passed',runtime_failure_rollback='passed',controller_crash_recovery='passed',failed_sequence_preserved='passed',single_controller_lock='passed',continuous_collection_across_install='passed'),indent=2))
        except Exception:
            try:
                endpoint_health=json.loads(request('/api/endpoints'))['endpoints'][0]['health']
                print('collector health: '+json.dumps(endpoint_health.get('collector')),file=sys.stderr)
            except (OSError,KeyError,IndexError,ValueError):
                pass
            for path in root.glob('*.log'):
                print(path.name+':\n'+path.read_text(errors='replace')[-10000:],file=sys.stderr)
            raise
        finally:
            for child in reversed(processes):
                if child.poll() is None:
                    child.kill();child.wait(timeout=10)
            lease=state/'supervisor/lease.json'
            if lease.exists():
                child_pid=json.loads(lease.read_text()).get('child_pid')
                if child_pid:
                    eventually(lambda:not alive(child_pid),10)


if __name__=='__main__':
    main()
