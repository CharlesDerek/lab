#!/usr/bin/env python3
"""Exercise real Apple authorization on a signed, authorized Mac.

All watched files, signatures, runtime state and ad-hoc probe copies are temporary.
No launchd job or account is installed. This does not certify production readiness.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def invoke(command, **kwargs):
    result = subprocess.run(list(map(str, command)), capture_output=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{Path(str(command[0])).name} failed ({result.returncode}): '
                           + result.stderr.decode(errors='replace')[-2048:])
    return result.stdout


def write_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def verify(args):
    account = pwd.getpwnam(args.scanner_user)
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise RuntimeError('An existing dedicated non-root scanner account is required')
    checks = {}
    evidence = []
    processes = []
    descriptors = []
    directory = tempfile.mkdtemp(prefix='athernex-native-validation-', dir='/private/var/tmp')
    retain = False
    try:
        root = Path(directory).resolve()
        root.chmod(0o755)
        bins = root/'bin';bins.mkdir(mode=0o700)
        adapter = bins/'adapter';agent = bins/'agent'
        for source,target in [(args.adapter,adapter),(args.agent,agent)]:
            shutil.copyfile(source,target);target.chmod(0o700)
            invoke(['/usr/bin/codesign','--verify','--strict',target])
            invoke(['/usr/sbin/spctl','--assess','--type','execute',target])
        entitlements = plistlib.loads(invoke(['/usr/bin/codesign','-d','--entitlements',':-',adapter]))
        if (entitlements.get('com.apple.developer.endpoint-security.client') is not True
                or entitlements.get('com.apple.security.get-task-allow',False) is not False):
            raise RuntimeError('The adapter needs the Endpoint Security entitlement without debug entitlement')
        engine = root/'engine';engine.mkdir(mode=0o755)
        database = engine/'db';database.mkdir(mode=0o755)
        runtime = engine/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,account.pw_uid,account.pw_gid)
        state = root/'state';(state/'protection/native').mkdir(parents=True,mode=0o700)
        state.chmod(0o700);(state/'protection').chmod(0o700)
        native = state/'protection/native'
        watched = root/'watched';watched.mkdir(mode=0o700)
        clean = watched/'clean';clean.write_bytes(b'Ordinary native authorization test')
        blocked = watched/'blocked';sample = b'ATHERNEX PUBLIC MAC AUTHORIZATION PROBE 0102030405';blocked.write_bytes(sample)
        clean_exec = watched/'clean-exec';blocked_exec = watched/'blocked-exec'
        shutil.copyfile('/usr/bin/true',clean_exec);shutil.copyfile('/usr/bin/true',blocked_exec)
        clean_exec.chmod(0o700);blocked_exec.chmod(0o700)
        # The unique signing identifier gives this harmless private copy unique
        # bytes. The whole-file signature must never classify the installed true
        # utility or distributed agent as the synthetic detection.
        invoke(['/usr/bin/codesign','--force','--sign','-','--identifier',
                'com.athernex.validation.'+secrets.token_hex(16),'--options','0',blocked_exec])
        invoke(['/usr/bin/codesign','--verify','--strict',blocked_exec])
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        blocked_sha = digest(blocked);exec_sha = digest(blocked_exec)
        if exec_sha == digest(clean_exec):
            raise RuntimeError('Executable probe bytes are not unique')
        signature = database/'fixture.hsb'
        signature.write_text(f'{blocked_sha}:{blocked.stat().st_size}:AthernexNativeProbeText\n'
                             f'{exec_sha}:{blocked_exec.stat().st_size}:AthernexNativeProbeExec\n')
        signature.chmod(0o644)
        policy = dict(roots=[str(watched)],socket=str(runtime/'clamd.sock'),state=str(native),
                      scanner_uid=account.pw_uid,scan_timeout_ms=1000)
        plan = root/'plan.json'
        write_json(plan,dict(schema=1,policy=policy,daemon=str((args.engine_prefix/'sbin/clamd').resolve()),
                             database=str(database),scanner_gid=account.pw_gid,startup_secs=120))
        fd_clean = os.open(clean,os.O_RDONLY);fd_blocked = os.open(blocked,os.O_RDONLY)
        descriptors += [fd_clean,fd_blocked]

        def probe(operation,path,fd=None,denied=False):
            nonce = secrets.token_hex(32)
            result = subprocess.run([str(adapter),'probe-owned',str(os.getpid()),operation,str(path),
                                     '-' if fd is None else str(fd),nonce],
                                    pass_fds=() if fd is None else (fd,),start_new_session=True,
                                    capture_output=True,text=True,timeout=6)
            lines = [json.loads(line) for line in result.stdout.splitlines()]
            if not lines or lines[0].get('nonce')!=nonce or lines[0].get('operation')!=operation:
                raise AssertionError('Missing probe identity: '+result.stderr[-1024:])
            if result.returncode != (10 if denied else 0):
                raise AssertionError(f'{operation} probe had unexpected result {result.returncode}: '+result.stderr[-1024:])
            if denied or operation!='exec':
                assert len(lines)==2 and lines[1]['nonce']==nonce
                assert lines[1]['outcome']==('denied' if denied else 'allowed')
            else:
                assert len(lines)==1
            return lines[0]

        def matching_receipt(attempt,sha,detection):
            saved = native/'last-probe-attempt.json';write_json(saved,attempt)
            deadline = time.monotonic()+5
            while time.monotonic()<deadline:
                for path in (native/'verdicts').glob('*.json'):
                    event = json.loads(path.read_text())
                    if event.get('actor')!=attempt['actor'] or event.get('path')!=attempt['path'] or event.get('operation')!=attempt['operation']:
                        continue
                    invoke([adapter,'probe-evidence',plan,saved,path,sha,detection])
                    evidence.append(dict(attempt=attempt,receipt=event))
                    return
                time.sleep(.05)
            raise AssertionError('Permission denial has no matching delivered native detection receipt')

        def stopped_groups(groups):
            for group in groups:
                try: os.killpg(group,0)
                except ProcessLookupError: continue
                return False
            return True

        log_path = root/'service.log'
        service = None
        groups = []
        try:
            # Both synthetic targets must be usable before our adapter starts;
            # filesystem permissions or code-signing rejection cannot pass this test.
            for operation,path,fd in [('open',clean,None),('open',blocked,None),
                                      ('exec',clean_exec,None),('exec',blocked_exec,None),
                                      ('mmap',clean,fd_clean),('mmap',blocked,fd_blocked)]:
                probe(operation,path,fd)
            checks['all_clean_and_synthetic_targets_allowed_before_activation']='passed'
            with log_path.open('w') as log:
                # From this point onward, cleanup must positively confirm that
                # every owned worker has stopped before removing its files.
                # Keep the fixture if cleanup itself raises or journals cannot
                # be read; an exception must not turn uncertain ownership into
                # permission to remove a live service's state.
                retain = True
                service = subprocess.Popen([str(adapter),'supervise',str(plan)],stdout=log,stderr=log,start_new_session=True)
                processes.append(service)
                deadline = time.monotonic()+130
                while time.monotonic()<deadline:
                    if service.poll() is not None:
                        raise RuntimeError('Native supervisor failed: '+log_path.read_text()[-4096:])
                    status_path = native/'service-status.json'
                    if status_path.exists():
                        status = json.loads(status_path.read_text())
                        groups = [p for p in [status.get('scanner_group'),status.get('adapter_group')] if p]
                        if status.get('phase') in ('running-unverified','running-verified') and (native/'native-status.json').exists():
                            result = subprocess.run([str(adapter),'query',str(native),str(clean)],capture_output=True,timeout=6)
                            if result.returncode==0: break
                    time.sleep(.1)
                else: raise AssertionError('Native authorization startup timed out')
                for operation,clean_path,bad_path,fd_good,fd_bad,sha,detection in [
                    ('open',clean,blocked,None,None,blocked_sha,'AthernexNativeProbeText.UNOFFICIAL'),
                    ('exec',clean_exec,blocked_exec,None,None,exec_sha,'AthernexNativeProbeExec.UNOFFICIAL'),
                    ('mmap',clean,blocked,fd_clean,fd_blocked,blocked_sha,'AthernexNativeProbeText.UNOFFICIAL')]:
                    probe(operation,clean_path,fd_good)
                    attempt = probe(operation,bad_path,fd_bad,denied=True)
                    matching_receipt(attempt,sha,detection)
                    checks[operation+'_allowed_and_detection_denied_with_native_receipt']='passed'

                def mutate(intent,recover=False):
                    request=dict(nonce=secrets.token_hex(32),intent=intent,recover=recover,timeout_secs=10)
                    result=invoke([agent,'native-mutation-worker',os.getpid()],input=json.dumps(request).encode(),start_new_session=True)
                    reply=json.loads(result);assert reply['nonce']==request['nonce'];assert reply['report']['outcome']=='completed'
                    return reply['report']
                identifier=secrets.token_hex(32)
                intent=dict(schema=1,command_id=identifier,quarantine_id=identifier,operation='quarantine',
                            state=str(state),path=str(blocked),roots=[str(watched)],sha256=blocked_sha)
                quarantined=mutate(intent)
                assert not blocked.exists() and (state/'quarantine'/identifier).read_bytes()==sample
                recovered=mutate(intent,True)
                assert recovered['finished_ms']==quarantined['finished_ms']
                checks['quarantine_and_committed_recovery_while_authorization_is_active']='passed'
                restored=mutate(dict(intent,command_id=secrets.token_hex(32),operation='restore',verifier=dict(kind='retained')))
                assert restored['path']==str(blocked)
                matching_receipt(probe('open',blocked,denied=True),blocked_sha,'AthernexNativeProbeText.UNOFFICIAL')
                checks['restored_file_remains_blocked_with_native_detection_receipt']='passed'
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    observed=json.loads(invoke([adapter,'health-status',plan]))
                    if observed['runtime_protection_verified']:
                        assert observed['phase']=='running-verified' and observed['verification']['checked_ms']>0
                        break
                    time.sleep(.2)
                else:
                    raise AssertionError('Automatic native blocking health never became verified')
                checks['supervisor_health_requires_fresh_blocking_proof_for_every_root']='passed'
                manifest=json.loads((native/'health/manifest.json').read_text())
                request=dict(schema=1,nonce=secrets.token_hex(32),operation='scan',state=str(native),
                             roots=[str(watched)],path=manifest['roots'][0]['directory']['path'],timeout_secs=10)
                scan=json.loads(invoke([agent,'native-response-worker',os.getpid()],
                                       input=json.dumps(request).encode(),start_new_session=True))
                assert scan['files']==4 and scan['health_samples']==2 and not scan['detections']
                checks['approved_scans_recognize_exact_health_samples_while_authorization_is_active']='passed'
                coverage = json.loads((native/'authorization-coverage.json').read_text())
                before = coverage['evidence']
                live = json.loads((native/'native-status.json').read_text())
                assert before['subscribed'] and before['scope_valid']
                assert before['pid'] == status['adapter_group'] == live['pid']
                assert before['session'] == live['coverage_session'] and live['coverage_current']
                assert before['pidversion'] == live['pidversion']
                assert abs(time.time()*1000-coverage['checked_ms']) < 3000
                evidence.append(dict(native_authorization_coverage=before))
                checks['native_subscription_publishes_bound_durable_coverage']='passed'
                service.terminate();service.wait(timeout=10)
                deadline=time.monotonic()+10
                while not stopped_groups(groups) and time.monotonic()<deadline: time.sleep(.05)
                assert stopped_groups(groups),'Owned native workers survived supervisor exit'
                probe('open',blocked)
                checks['supervisor_exit_cleans_owned_groups_and_removes_authorization']='passed'
                # Reuse the exact state. A new process must preserve historical
                # totals and mark the unobserved tail/subscription interval.
                service = subprocess.Popen([str(adapter),'supervise',str(plan)],stdout=log,stderr=log,start_new_session=True)
                processes.append(service)
                deadline = time.monotonic()+130
                while time.monotonic()<deadline:
                    if service.poll() is not None:
                        raise RuntimeError('Native restart failed: '+log_path.read_text()[-4096:])
                    status = json.loads((native/'service-status.json').read_text())
                    coverage = json.loads((native/'authorization-coverage.json').read_text())
                    after = coverage['evidence']
                    if (status['supervisor_pid']==service.pid and after['session']!=before['session']
                            and after['subscribed'] and status.get('adapter_group')==after['pid']):
                        break
                    time.sleep(.1)
                else: raise AssertionError('Native restart coverage timed out')
                groups = [p for p in [status.get('scanner_group'),status.get('adapter_group')] if p]
                assert after['lineage']==before['lineage'] and after['policy_sha256']==before['policy_sha256']
                assert after['sessions']==before['sessions']+1
                assert after['unobserved_intervals']==before['unobserved_intervals']+1
                assert after['revision']>before['revision']
                assert all(after['totals'][key]>=value for key,value in before['totals'].items())
                assert after['scope_losses']>=before['scope_losses']
                assert after['legacy_history_unknown']==before['legacy_history_unknown']
                matching_receipt(probe('open',blocked,denied=True),blocked_sha,'AthernexNativeProbeText.UNOFFICIAL')
                evidence.append(dict(native_authorization_coverage=after))
                checks['native_restart_preserves_totals_and_marks_unknown_interval']='passed'
                service.terminate();service.wait(timeout=10)
                deadline=time.monotonic()+10
                while not stopped_groups(groups) and time.monotonic()<deadline: time.sleep(.05)
                assert stopped_groups(groups),'Owned native workers survived restarted supervisor exit'
            return dict(schema=1,scope='Native macOS controlled open/exec/mmap authorization and response validation',
                        native_authorization_exercised=True,production_readiness=False,
                        checks=checks,evidence=evidence,adapter_sha256=digest(adapter),agent_sha256=digest(agent))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)
            for fd in descriptors: os.close(fd)
            # Worker journals precede external daemon startup, including when
            # startup fails before the supervisor has published the group list.
            for role in ('scanner','adapter'):
                journal=native/f'service-{role}.json'
                if journal.exists():
                    group=json.loads(journal.read_text())['record']['pgid']
                    if group not in groups: groups.append(group)
            if groups:
                deadline=time.monotonic()+10
                while not stopped_groups(groups) and time.monotonic()<deadline: time.sleep(.05)
                if not stopped_groups(groups):
                    raise RuntimeError(f'Native workers remain; retained fixture for review at {root}')
            retain = False
    finally:
        if not retain:
            shutil.rmtree(directory)
        else:
            print(f'Retained native validation fixture for review: {directory}',file=sys.stderr)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter',required=True,type=Path)
    parser.add_argument('--agent',required=True,type=Path)
    parser.add_argument('--engine-prefix',type=Path,default=Path('/usr/local/clamav'))
    parser.add_argument('--scanner-user',default='_athernexav')
    parser.add_argument('--report',type=Path,default=Path('.athernex/verification/native-macos-runtime.json'))
    args=parser.parse_args()
    if sys.platform!='darwin' or os.geteuid()!=0:
        parser.error('Run as root on an authorized Mac with signed endpoint/adapter binaries and ClamAV')
    report=verify(args)
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(checks=report['checks'],report=str(args.report)),indent=2))


if __name__=='__main__': main()
