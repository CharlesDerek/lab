#!/usr/bin/env python3
"""Real scanner/service lifetime checks on Linux; Apple authorization is not run."""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def inside():
    root = Path('/fixture')
    if not Path('/.dockerenv').exists() or not root.is_dir():
        raise RuntimeError('Use the isolated fixture container')
    binaries = root / 'bin'
    binaries.mkdir()
    binary = binaries / 'adapter'
    shutil.copy2('/test/adapter', binary)
    binary.chmod(0o700)
    engine = root / 'engine'
    (engine / 'bin').mkdir(parents=True)
    (engine / 'db').mkdir()
    runtime = engine / 'runtime'
    runtime.mkdir(mode=0o700)
    os.chown(runtime, 1234, 1234)
    daemon = engine / 'bin/clamd'
    shutil.copyfile('/usr/local/sbin/clamd', daemon)
    daemon.chmod(0o755)
    endpoint = binaries / 'endpoint'
    shutil.copy2('/test/endpoint', endpoint)
    endpoint.chmod(0o700)
    endpoint_state = root / 'endpoint-state'
    endpoint_state.mkdir(mode=0o700)
    (endpoint_state / 'protection').mkdir(mode=0o700)
    state = endpoint_state / 'protection/native'
    state.mkdir(mode=0o700)
    watched = root / 'watched'
    watched.mkdir()
    sample = b'ATHERNEX PUBLIC SUPERVISED SCANNER FIXTURE 01020304'
    (engine / 'db/fixture.hdb').write_text(f'{hashlib.md5(sample).hexdigest()}:{len(sample)}:AthernexServiceFixture\n')
    clean = watched / 'clean'
    clean.write_bytes(b'Ordinary supervised service fixture')
    infected = watched / 'fixture'
    infected.write_bytes(sample)
    policy = dict(roots=[str(watched)], socket=str(runtime / 'clamd.sock'), state=str(state),
                  scanner_uid=1234, scan_timeout_ms=1000)
    plan = root / 'service.json'
    plan.write_text(json.dumps(dict(schema=1,policy=policy,daemon=str(daemon),database=str(engine / 'db'),
                                    scanner_gid=1234,startup_secs=10)))
    plan.chmod(0o600)
    env = dict(os.environ, LD_LIBRARY_PATH='/usr/local/lib')
    checks = {}
    processes = []
    orphan_ids = set()
    prepared = subprocess.run([str(binary),'prepare-health-fixture',str(plan)],
                              env=env,capture_output=True,text=True,timeout=70)
    assert prepared.returncode == 0, prepared.stderr
    health_manifest = json.loads(prepared.stdout)
    assert len(health_manifest['roots']) == 1
    checks['native_health_samples_pass_open_execute_and_preopened_mapping_baselines'] = 'passed'

    def eventually(check, seconds=12):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try: result = check()
            except (FileNotFoundError, ProcessLookupError): result = None
            if result: return result
            time.sleep(.05)
        raise AssertionError('Service condition timed out')

    def status():
        try: return json.loads((state / 'service-status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError): return {}

    def start():
        process = subprocess.Popen([str(binary),'supervise-fixture',str(plan)],env=env,
                                   stdout=subprocess.DEVNULL,stderr=log,start_new_session=True)
        processes.append(process)
        return process

    def query(path):
        result = subprocess.run([str(binary),'query',str(state),str(path)],capture_output=True,text=True,timeout=8)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def ready(process):
        if process.poll() is not None:
            raise AssertionError('Supervisor exited: '+(root / 'service.log').read_text())
        current = status()
        if current.get('supervisor_pid') != process.pid or current.get('phase') != 'running-unverified': return None
        if query(clean) is None: return None
        assert current['runtime_protection_verified'] is False
        return current

    def children(current):
        scanner = current['scanner_group']
        adapter = current['adapter_group']
        pids = Path(f'/proc/{scanner}/task/{scanner}/children').read_text().split()
        assert len(pids) == 1, pids
        child = int(pids[0])
        orphan_ids.update([scanner,adapter,child])
        return scanner,adapter,child

    def gone(pids):
        # Docker init normally reaps adopted workers. Also handle known adopted
        # workers when run without init, without consuming Popen-owned leaders.
        for pid in pids:
            try: os.waitpid(pid,os.WNOHANG)
            except ChildProcessError: pass
        return all(not Path(f'/proc/{pid}').exists() for pid in pids)

    with (root / 'service.log').open('w') as log:
        try:
            first = start()
            current = eventually(lambda: ready(first))
            group_ids = children(current)
            uid = next(line for line in Path(f'/proc/{group_ids[2]}/status').read_text().splitlines() if line.startswith('Uid:'))
            gid = next(line for line in Path(f'/proc/{group_ids[2]}/status').read_text().splitlines() if line.startswith('Gid:'))
            assert uid.split()[1:] == ['1234'] * 4 and gid.split()[1:] == ['1234'] * 4
            checks['daemon_runs_under_dedicated_uid_and_gid'] = 'passed'
            verdict = query(infected)
            assert verdict['sha256'] == hashlib.sha256(sample).hexdigest() and verdict['detection'].startswith('AthernexServiceFixture')
            checks['owned_broker_returns_real_engine_verdicts_without_claiming_realtime'] = 'passed'
            for entry in health_manifest['roots'][0]['samples']:
                verdict = query(entry['path'])
                assert verdict['sha256'] == entry['sha256'], (entry,verdict)
                assert verdict['detection'] == entry['detection'], (entry,verdict)
            checks['native_health_custom_signatures_match_only_the_exact_synthetic_samples'] = 'passed'
            def response_scan(path):
                request=dict(schema=1,nonce='a'*64,operation='scan',state=str(state),
                             roots=[str(watched)],path=str(path),timeout_secs=10)
                result=subprocess.run([str(endpoint),'native-response-worker',str(os.getpid())],
                                      input=json.dumps(request),env=env,capture_output=True,text=True,
                                      timeout=15,start_new_session=True)
                assert result.returncode==0,result.stderr
                return json.loads(result.stdout)
            health_root=health_manifest['roots'][0]
            scan=response_scan(health_root['directory']['path'])
            assert scan['files']==4 and scan['health_samples']==2 and not scan['detections'],scan
            duplicate_sample=watched/'ordinary-copy-of-health-bytes'
            duplicate_sample.write_bytes(Path(health_root['samples'][1]['path']).read_bytes())
            scan=response_scan(duplicate_sample)
            assert scan['health_samples']==0 and len(scan['detections'])==1,scan
            assert scan['detections'][0]['sha256']==health_root['samples'][1]['sha256']
            duplicate_sample.unlink()
            checks['approved_scans_distinguish_owned_health_samples_from_identical_bytes_elsewhere'] = 'passed'
            observed = subprocess.run([str(binary),'health-status',str(plan)],
                                      env=env,capture_output=True,text=True,timeout=5)
            assert observed.returncode == 0, observed.stderr
            health = json.loads(observed.stdout)
            assert health['runtime_protection_verified'] is False and health['verification'] is None
            checks['native_health_observation_refuses_to_promote_scanner_liveness'] = 'passed'
            refused = subprocess.run([str(binary),'prepare-health-fixture',str(plan)],
                                     env=env,capture_output=True,text=True,timeout=5)
            assert refused.returncode != 0
            assert json.loads((state/'health/manifest.json').read_text()) == health_manifest
            checks['native_health_preparation_refuses_a_live_service_without_changing_samples'] = 'passed'
            for role,pgid in zip(('scanner','adapter'),group_ids[:2]):
                journal = json.loads((state / f'service-{role}.json').read_text())
                assert journal['record']['pgid'] == pgid and journal['record']['plan_sha256'] == current['plan_sha256']
            checks['worker_groups_are_persisted_for_restart_admission'] = 'passed'
            duplicate = start()
            assert duplicate.wait(timeout=5) != 0
            assert first.poll() is None and status()['supervisor_pid'] == first.pid
            checks['duplicate_supervisor_cannot_replace_live_status_or_children'] = 'passed'
            unowned = subprocess.run([str(binary),'scanner-owned',str(os.getpid()),current['plan_sha256'],str(plan)],
                                     env=env,capture_output=True,text=True,timeout=5,start_new_session=True)
            assert unowned.returncode != 0 and children(current) == group_ids
            checks['worker_rejects_a_different_supervising_parent'] = 'passed'
            alternate_state = root / 'alternate-native'
            alternate_state.mkdir(mode=0o700)
            alternate = json.loads(plan.read_text())
            alternate['policy']['state'] = str(alternate_state)
            alternate_plan = root / 'alternate-plan.json'
            alternate_plan.write_text(json.dumps(alternate));alternate_plan.chmod(0o600)
            def alternate_refused():
                result = subprocess.run([str(binary),'supervise-fixture',str(alternate_plan)],env=env,
                                        capture_output=True,text=True,timeout=5,start_new_session=True)
                assert result.returncode != 0
                assert not (alternate_state / 'service-scanner.json').exists()
            alternate_refused()
            os.kill(group_ids[1],signal.SIGKILL)
            assert first.wait(timeout=10) != 0
            eventually(lambda: gone(group_ids))
            assert status()['phase'] == 'failed' and status()['runtime_protection_verified'] is False
            checks['adapter_crash_stops_scanner_and_records_failure'] = 'passed'
            alternate_refused()
            checks['runtime_owner_prevents_rebinding_before_and_after_service_exit'] = 'passed'
            second = start()
            current = eventually(lambda: ready(second))
            group_ids = children(current)
            checks['restart_after_confirmed_cleanup_restores_scanner_and_broker'] = 'passed'
            os.kill(group_ids[2],signal.SIGKILL)
            assert second.wait(timeout=10) != 0
            eventually(lambda: gone(group_ids))
            assert status()['phase'] == 'failed'
            checks['daemon_crash_stops_adapter_and_records_failure'] = 'passed'
            third = start()
            current = eventually(lambda: ready(third))
            group_ids = children(current)
            third.kill(); third.wait(timeout=5)
            eventually(lambda: gone(group_ids))
            checks['supervisor_crash_leaves_no_owned_workers_or_daemon'] = 'passed'
            fourth = start()
            current = eventually(lambda: ready(fourth))
            group_ids = children(current)
            assert query(infected)['sha256'] == hashlib.sha256(sample).hexdigest()
            checks['restart_after_supervisor_crash_reconciles_persisted_groups'] = 'passed'
            fourth.kill();fourth.wait(timeout=5)
            eventually(lambda: gone(group_ids))

            config=dict(server='http://127.0.0.1:9',endpoint_id='a'*64,credential='b'*64,
                        enrollment_token=None,scanner=str(daemon),updater='/bin/false',
                        scan_roots=[str(watched)],allow_scripts=False,
                        protection=dict(enabled=True,roots=[str(watched)],daemon=str(daemon),
                            monitor=str(binary),database=str(engine/'db'),runtime=str(runtime),
                            engine_uid=1234,engine_gid=1234))
            (endpoint_state/'config.json').write_text(json.dumps(config))
            (endpoint_state/'config.json').chmod(0o600)
            # Only the Linux fixture dispatch differs. The controller, owned
            # worker, endpoint protection wrapper and service code are real.
            wrapper=root/'managed-endpoint'
            wrapper.write_text('#!/bin/sh\nif [ "$1" = controller-owned ] && [ "$3" = protect ]; then\n'
                               '  exec /fixture/bin/endpoint native-fixture-owned "$2" "$4"\nfi\n'
                               'exec /fixture/bin/endpoint "$@"\n')
            wrapper.chmod(0o700)
            def controller_start():
                process=subprocess.Popen([str(endpoint),'supervise',str(endpoint_state),str(wrapper)],
                                         env=env,stdout=subprocess.DEVNULL,stderr=log,start_new_session=True)
                processes.append(process);return process
            def controller_ready(process):
                if process.poll() is not None: raise AssertionError('Controller exited: '+(root/'service.log').read_text())
                current=status()
                if current.get('phase')!='running-unverified' or query(clean) is None: return None
                pids=[int(p) for p in Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()]
                if len(pids)!=2: return None
                manager=next((p for p in pids if b'controller-owned' in Path(f'/proc/{p}/cmdline').read_bytes()),None)
                protector=next((p for p in pids if b'native-fixture-owned' in Path(f'/proc/{p}/cmdline').read_bytes()),None)
                if manager is None or protector is None: return None
                descendants=Path(f'/proc/{protector}/task/{protector}/children').read_text().split()
                if descendants != [str(current['supervisor_pid'])]: return None
                all_ids=[manager,protector,current['supervisor_pid'],*children(current)]
                orphan_ids.update(all_ids)
                return current,all_ids
            controller=controller_start()
            current,managed=eventually(lambda:controller_ready(controller),20)
            health=json.loads(subprocess.check_output([str(endpoint),'native-fixture-status',str(endpoint_state)],timeout=5))
            assert health['state']=='degraded' and health['backend']=='macos-endpoint-security'
            checks['controller_starts_owned_native_pair_without_claiming_verified_prevention']='passed'
            admission=subprocess.run([str(endpoint),'native-fixture-quiescent',str(endpoint_state)],capture_output=True,timeout=5)
            assert admission.returncode!=0
            checks['update_quiescence_refuses_live_native_services']='passed'
            config['protection']['enabled']=False
            (endpoint_state/'config.json').write_text(json.dumps(config))
            admission=subprocess.run([str(endpoint),'native-fixture-quiescent',str(endpoint_state)],capture_output=True,timeout=5)
            assert admission.returncode!=0
            config['protection']['enabled']=True
            (endpoint_state/'config.json').write_text(json.dumps(config))
            checks['disabling_policy_does_not_bypass_live_native_update_exclusion']='passed'
            os.kill(managed[0],signal.SIGKILL)
            def management_restarted():
                value=controller_ready(controller)
                return value if value and value[1][0]!=managed[0] else None
            after,after_ids=eventually(management_restarted,20)
            assert after['supervisor_pid']==current['supervisor_pid'] and after_ids[1:]==managed[1:]
            checks['management_restart_preserves_native_scanner_and_adapter']='passed'
            managed=after_ids
            os.kill(managed[1],signal.SIGKILL)
            eventually(lambda:gone(managed[2:]))
            def protection_restarted():
                value=controller_ready(controller)
                return value if value and value[1][1]!=managed[1] else None
            _,replacement=eventually(protection_restarted,20)
            assert replacement[0]==managed[0]
            checks['protection_wrapper_crash_cleans_owned_tree_and_controller_restarts_it']='passed'
            controller.kill();controller.wait(timeout=5)
            eventually(lambda:gone(replacement))
            checks['controller_crash_cleans_management_and_complete_native_tree']='passed'
            health=json.loads(subprocess.check_output([str(endpoint),'native-fixture-status',str(endpoint_state)],timeout=5))
            assert health['state']=='degraded' and health['error']
            subprocess.run([str(endpoint),'native-fixture-quiescent',str(endpoint_state)],check=True,capture_output=True,timeout=5)
            checks['update_quiescence_accepts_confirmed_tree_cleanup']='passed'
            controller=controller_start()
            _,managed=eventually(lambda:controller_ready(controller),20)
            assert query(infected)['sha256']==hashlib.sha256(sample).hexdigest()
            controller.kill();controller.wait(timeout=5)
            eventually(lambda:gone(managed))
            checks['controller_restart_restores_native_pair_after_crash']='passed'
            verify_setup(root,binary,endpoint,env,log,checks,processes,eventually,gone,orphan_ids)
            return dict(schema=1,scope='Linux service ownership and real ClamAV; macOS Endpoint Security not executed',
                        native_macos_runtime_verified=False,checks=checks,
                        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                        endpoint_sha256=hashlib.sha256(endpoint.read_bytes()).hexdigest())
        finally:
            for process in processes:
                if process.poll() is None: process.kill();process.wait(timeout=5)
            for pid in orphan_ids:
                try: os.waitpid(pid,os.WNOHANG)
                except ChildProcessError: pass
            if sys.exc_info()[0] is not None:
                print((root / 'service.log').read_text()[-8192:],file=sys.stderr)
                print(json.dumps(status()),file=sys.stderr)


def verify_setup(root,binary,endpoint,env,log,checks,processes,eventually,gone,orphan_ids):
    # Actual filesystem preparation and service startup; only account IDs and
    # Apple authorization are supplied by the explicit Linux fixture dispatch.
    state=root/'setup-state';state.mkdir(mode=0o700)
    source=state/'av/db';source.mkdir(parents=True)
    prefix=root/'setup-prefix';(prefix/'bin').mkdir(parents=True);(prefix/'sbin').mkdir()
    for name,folder in [('clamscan','bin'),('clamd','sbin')]:
        target=prefix/folder/name;shutil.copyfile('/usr/local/'+folder+'/'+name,target);target.chmod(0o755)
    watched=root/'setup-watched';watched.mkdir()
    sample=b'ATHERNEX PUBLIC SETUP FIXTURE 04050607'
    infected=watched/'fixture';infected.write_bytes(sample)
    signature=f'{hashlib.md5(sample).hexdigest()}:{len(sample)}:AthernexSetupFixture\n'
    config=dict(server='http://127.0.0.1:9',endpoint_id='e'*64,credential='f'*64,
                enrollment_token=None,scanner=str(prefix/'bin/clamscan'),updater=str(prefix/'bin/freshclam'),
                scan_roots=[str(watched)],allow_scripts=False,signature_database=str(source),signature_config=None,
                protection=dict(enabled=False,roots=[],daemon=None,monitor=None,database=None,runtime=None,engine_uid=None,engine_gid=None))
    path=state/'config.json';path.write_text(json.dumps(config));path.chmod(0o600)
    original=path.read_bytes()
    engine=root/'setup-engine'
    command=[str(endpoint),'configure-native-fixture',str(state),str(binary),str(engine),'2345','2345']
    outside=root/'outside.hdb';outside.write_text(signature)
    (source/'fixture.hdb').symlink_to(outside)
    failed=subprocess.run(command,capture_output=True,env=env,timeout=15)
    assert failed.returncode!=0 and path.read_bytes()==original,failed.stderr
    assert not (engine/'db/fixture.hdb').exists()
    checks['setup_rejects_linked_signatures_without_committing_policy']='passed'
    (source/'fixture.hdb').unlink();(source/'fixture.hdb').write_text(signature)
    (source/'fixture.hdb').chmod(0o666)
    refused=subprocess.run(command,capture_output=True,env=env,timeout=15)
    assert refused.returncode!=0 and path.read_bytes()==original
    assert not (engine/'db/fixture.hdb').exists()
    checks['setup_rejects_user_writable_signature_inputs']='passed'
    (source/'fixture.hdb').chmod(0o644)
    completed=subprocess.run(command,capture_output=True,env=env,timeout=15)
    assert completed.returncode==0,completed.stderr
    prepared=json.loads(path.read_text());policy=prepared['protection']
    assert policy['enabled'] and policy['engine_uid']==2345 and policy['engine_gid']==2345
    assert policy['monitor']==str(binary) and policy['daemon']==str(prefix/'sbin/clamd')
    assert (engine/'runtime').stat().st_uid==2345 and (engine/'runtime').stat().st_gid==2345
    assert (engine/'runtime').stat().st_mode&0o777==0o700
    assert (engine/'db/fixture.hdb').read_text()==signature
    assert (engine/'db/fixture.hdb').stat().st_mode&0o777==0o644
    assert prepared['signature_database']==str(engine/'db')
    assert str(engine/'db') in Path(prepared['signature_config']).read_text()
    assert state.stat().st_mode&0o777==0o700
    (source/'fixture.hdb').write_text('source changed after independent copy')
    assert (engine/'db/fixture.hdb').read_text()==signature
    checks['setup_prepares_private_runtime_independent_signatures_and_maintenance_policy']='passed'
    prepared_bytes=path.read_bytes()
    subprocess.run(command,check=True,capture_output=True,env=env,timeout=15)
    assert path.read_bytes()==prepared_bytes
    checks['setup_retry_preserves_existing_native_policy']='passed'
    wrapper=subprocess.Popen([str(endpoint),'protect-native-fixture',str(state)],env=env,
                             stdout=subprocess.DEVNULL,stderr=log,start_new_session=True)
    processes.append(wrapper)
    native=state/'protection/native'
    def ready():
        if wrapper.poll() is not None: raise AssertionError('Prepared protection failed to start')
        status_path=native/'service-status.json'
        if not status_path.exists(): return None
        current=json.loads(status_path.read_text())
        if current.get('phase')!='running-unverified': return None
        result=subprocess.run([str(binary),'query',str(native),str(infected)],capture_output=True,text=True,timeout=8)
        if result.returncode: return None
        verdict=json.loads(result.stdout)
        assert verdict['sha256']==hashlib.sha256(sample).hexdigest() and verdict['detection'].startswith('AthernexSetupFixture')
        assert current['runtime_protection_verified'] is False
        return current
    current=eventually(ready,20)
    checks['prepared_setup_starts_real_scanner_and_broker_without_claiming_blocking']='passed'
    refused=subprocess.run(command,capture_output=True,env=env,timeout=15)
    assert refused.returncode!=0 and path.read_bytes()==prepared_bytes
    checks['setup_refuses_running_protection_without_changing_policy']='passed'
    scanner=current['scanner_group'];adapter=current['adapter_group']
    descendants=list(map(int,Path(f'/proc/{scanner}/task/{scanner}/children').read_text().split()))
    ids=[current['supervisor_pid'],scanner,adapter,*descendants];orphan_ids.update(ids)
    wrapper.kill();wrapper.wait(timeout=5);eventually(lambda:gone(ids))
    prepared['protection']['enabled']=False;path.write_text(json.dumps(prepared))
    disabled=path.read_bytes()
    subprocess.run(command,check=True,capture_output=True,env=env,timeout=15)
    assert path.read_bytes()==disabled
    checks['setup_preserves_intentionally_disabled_local_policy']='passed'
    # A fresh local policy cannot claim an existing engine owned by another endpoint.
    path.write_bytes(original)
    marker=engine/'setup-owner.json';owner=json.loads(marker.read_text());owner['endpoint_id']='0'*64
    marker.write_text(json.dumps(owner))
    refused=subprocess.run(command,capture_output=True,env=env,timeout=15)
    assert refused.returncode!=0 and path.read_bytes()==original
    checks['setup_refuses_foreign_engine_ownership']='passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',action='store_true')
    parser.add_argument('--engine-prefix',type=Path)
    parser.add_argument('--binary',type=Path,default=Path('target/release/athernex-endpoint-native'))
    parser.add_argument('--endpoint-binary',type=Path,default=Path('target/release/athernex-endpoint'))
    parser.add_argument('--image',default='athernex-native-protection-fixture:local')
    parser.add_argument('--report',type=Path,default=Path('.athernex/verification/native-service-runtime.json'))
    args=parser.parse_args()
    if args.inside:
        print(json.dumps(inside(),sort_keys=True));return
    if args.engine_prefix is None: parser.error('--engine-prefix is required')
    with tempfile.TemporaryDirectory(prefix='athernex-service-binary-') as directory:
        binary=Path(directory)/'adapter';shutil.copy2(args.binary,binary)
        endpoint=Path(directory)/'endpoint';shutil.copy2(args.endpoint_binary,endpoint)
        command=['docker','run','--init','--rm','--network','none','--read-only','--cap-drop','ALL',
                 '--cap-add','SETUID','--cap-add','SETGID','--cap-add','KILL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges',
                 '--memory','1g','--pids-limit','64','--tmpfs','/fixture:rw,exec,nosuid,nodev,size=128m,mode=0755',
                 '-v',f'{args.engine_prefix.resolve()}:/usr/local:ro','-v',f'{binary}:/test/adapter:ro',
                 '-v',f'{endpoint}:/test/endpoint:ro',
                 '-v',f'{Path(__file__).resolve()}:/test/verify.py:ro',args.image,'python3','/test/verify.py','--inside']
        result=subprocess.run(command,capture_output=True,text=True,timeout=120)
    if result.returncode: raise RuntimeError(result.stdout+result.stderr)
    report=json.loads(result.stdout)
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__': main()
