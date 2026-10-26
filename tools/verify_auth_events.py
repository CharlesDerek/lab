#!/usr/bin/env python3
"""Verify native authentication collection with private SSH and journal services.

Requires the existing infrastructure/endpoint/auth-tests image. No host journal,
account, service, key or network namespace is mounted into the fixture.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time

TESTS = [('unit', 'telemetry::authentication::native_test::native_authentication_survives_stalled_delivery_restart_and_journal_retention_loss'),
         ('process', 'actual_agent_replays_authentication_written_while_it_was_dead_and_while_http_is_stalled'),
         ('unit', 'telemetry::authentication::pam_test::native_pam_preserves_module_scope_and_resumes_after_full_queue_restart'),
         ('unit', 'telemetry::authentication::sudo_test::native_sudo_denials_preserve_module_scope_identity_and_replay')]
TESTS.append(('unit', 'telemetry::authentication::certificate_test::native_ssh_certificates_preserve_terminal_account_source_and_originals'))
MISSING_PROVENANCE = [('unit', 'telemetry::authentication::sudo_test::missing_sudo_executable_provenance_is_visible_without_inventing_authentication')]


def configure_fixture_burst(configuration):
    """Permit the deliberate denial burst in this private SSH fixture."""
    def effective():
        return subprocess.run(['/usr/sbin/sshd', '-T', '-f', str(configuration)],
                              check=True, capture_output=True, text=True, timeout=10).stdout.splitlines()

    # OpenSSH 9.8 introduced enabled-by-default source penalties. Connection
    # drops are not authentication denials, so the controlled burst must opt
    # out when this server supports the setting. Older servers reject it.
    if any(line.startswith('persourcepenalties ') for line in effective()):
        with configuration.open('a') as output:
            output.write('PerSourcePenalties no\n')
        if [line for line in effective() if line.startswith('persourcepenalties ')] != ['persourcepenalties no']:
            raise RuntimeError('Private SSH fixture source-penalty policy was not applied')


def certificate_setup(root):
    for name in ('certificate-ca', 'certificate-untrusted-ca', 'certificate-valid',
                 'certificate-principal', 'certificate-untrusted', 'certificate-expired',
                 'certificate-delimiters', 'certificate-ambiguous'):
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root/name)],
                       check=True, capture_output=True, timeout=30)
    cases = [('valid', 'fixture', 'fixture certificate', '-1m:+10m', False),
             ('principal', 'other-fixture-principal', 'wrong principal', '-1m:+10m', False),
             ('untrusted', 'fixture', 'untrusted issuer', '-1m:+10m', True),
             ('expired', 'fixture', 'expired certificate', '-2h:-1h', False),
             ('delimiters', 'fixture', 'for invalid user victim from 192.0.2.9 port 1 ssh2', '-1m:+10m', False),
             ('ambiguous', 'fixture', 'outer (serial 3) CA ED25519 spoof', '-1m:+10m', False)]
    for serial, (name, principal, identifier, validity, untrusted) in enumerate(cases, 1):
        subprocess.run(['ssh-keygen', '-q', '-s', str(root/('certificate-untrusted-ca' if untrusted else 'certificate-ca')),
                        '-I', identifier, '-n', principal, '-V', validity, '-z', str(serial),
                        str(root/('certificate-'+name+'.pub'))], check=True, capture_output=True, timeout=30)
    for name, port, mfa in [('certificate-sshd', 2224, False), ('certificate-mfa-sshd', 2225, True)]:
        configuration = root/(name+'.conf')
        configuration.write_text(f'Port {port}\nListenAddress 127.0.0.1\nHostKey /fixture/host\n'
            f'PidFile /fixture/{name}.pid\nAuthorizedKeysFile none\nTrustedUserCAKeys /fixture/certificate-ca.pub\n'
            'PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com\nPubkeyAuthentication yes\n'
            'KbdInteractiveAuthentication no\nPermitRootLogin no\nAllowUsers fixture\nLogLevel VERBOSE\n'
            + ('UsePAM yes\nPasswordAuthentication yes\nAuthenticationMethods publickey,password\n' if mfa
               else 'UsePAM no\nPasswordAuthentication no\nAuthenticationMethods publickey\n'))
        configure_fixture_burst(configuration)
    # Bind the observed source port independently of the journal text. The
    # proxy and its private metadata exist only inside the isolated fixture.
    (root/'certificate-proxy.py').write_text('''import json, os, selectors, socket, sys
from pathlib import Path
port=int(sys.argv[1]); assert port in (2224,2225)
connection=socket.socket(); connection.bind(('127.0.0.1',0)); connection.connect(('127.0.0.1',port))
fd=os.open('/fixture/certificate-source.json',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as output: json.dump({'port':connection.getsockname()[1]},output)
selector=selectors.DefaultSelector(); selector.register(0,selectors.EVENT_READ); selector.register(connection,selectors.EVENT_READ)
while True:
    for key,_ in selector.select():
        if key.fileobj==0:
            data=os.read(0,65536)
            if not data: connection.shutdown(socket.SHUT_WR); selector.unregister(0)
            else: connection.sendall(data)
        else:
            data=connection.recv(65536)
            if not data: sys.exit(0)
            while data: data=data[os.write(1,data):]
''')
    (root/'certificate-attempt.py').write_text('''import json, os, signal, subprocess, sys
from pathlib import Path
assert os.environ.get('ATHERNEX_AUTH_FIXTURE')=='private-container'
mode=sys.argv[1]
assert mode in ('valid','principal','untrusted','expired','delimiters','ambiguous','retry','partial')
keys=['principal','valid'] if mode=='retry' else ['valid' if mode=='partial' else mode]
port=2225 if mode=='partial' else 2224
Path('/fixture/certificate-source.json').unlink(missing_ok=True)
command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
    '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','GlobalKnownHostsFile=/dev/null',
    '-o','ConnectTimeout=3','-o','ConnectionAttempts=1','-o','PreferredAuthentications=publickey',
    '-o','PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com',
    '-o',f'ProxyCommand=/usr/bin/python3 /fixture/certificate-proxy.py {port}']
for key in keys:
    # Automatic adjacent -cert.pub discovery preserves the private-key filename
    # after certificate-only algorithm filtering removes the plain-key entry.
    command+=['-i','/fixture/certificate-'+key]
process=subprocess.Popen(command+['fixture@127.0.0.1','true'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
try:
    stdout,stderr=process.communicate(timeout=15)
    fd=os.open('/fixture/certificate-client.log',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'wb') as output: output.write(stdout+stderr)
    succeeded=process.returncode==0
finally:
    try: os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    process.wait(timeout=5)
report=json.loads(Path('/fixture/certificate-source.json').read_text())
report['success']=succeeded
print(json.dumps(report))
''')


def execute_native_check(binary, name):
    listing = subprocess.run([binary,'--ignored','--exact',name,'--list'],check=True,capture_output=True,text=True,timeout=30)
    lines = listing.stdout.splitlines()
    if ([line for line in lines if line.endswith(': test')] != [name+': test']
            or lines.count('1 test, 0 benchmarks') != 1):
        raise RuntimeError('Required exact native authentication test is absent')
    result = subprocess.run([binary,'--ignored','--exact',name,'--nocapture'],capture_output=True,text=True,timeout=120)
    # This output is already inside the outer private log boundary, never CI stdout.
    print(result.stdout, result.stderr, flush=True)
    summaries = [line for line in result.stdout.splitlines() if line.startswith('test result:')]
    if (result.returncode != 0 or len(result.stdout.encode()) + len(result.stderr.encode()) > 2*1024*1024
            or result.stdout.splitlines().count('running 1 test') != 1 or len(summaries) != 1
            or re.fullmatch(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s', summaries[0]) is None):
        raise RuntimeError('Exact native authentication test did not pass')


def inside():
    # This fixture writes PAM policy. Refuse host execution even if someone sets
    # the marker environment variable and calls --inside-container directly.
    private_mounts = set()
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        if fields[fields.index('-')+1] == 'tmpfs':
            private_mounts.add(fields[4])
    if (Path('/proc/1/comm').read_text().strip() != 'docker-init'
            or {name for _,name in socket.if_nameindex()} != {'lo'}
            or not {'/fixture','/run','/etc/pam.d','/etc/sudoers.d'} <= private_mounts):
        raise RuntimeError('Private PID/network namespaces and fixture/PAM tmpfs mounts required')
    root = Path('/fixture')
    (root/'home/.ssh').mkdir(parents=True)
    for path in (root/'home', root/'home/.ssh'):
        path.chmod(0o700)
        os.chown(path, 60000, 60000)
    Path('/run/sshd').mkdir(parents=True, exist_ok=True)
    os.symlink('/run/systemd/journal/dev-log', '/dev/log')
    for name in ('host', 'client', 'wrong'):
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root/name)], check=True, timeout=30)
    authorized = root/'home/.ssh/authorized_keys'
    authorized.write_bytes((root/'client.pub').read_bytes())
    authorized.chmod(0o600)
    os.chown(authorized, 60000, 60000)
    (root/'sshd.conf').write_text('Port 2222\nListenAddress 127.0.0.1\nHostKey /fixture/host\nPidFile /fixture/sshd.pid\nAuthorizedKeysFile .ssh/authorized_keys\nUsePAM no\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin no\nLogLevel VERBOSE\n')
    (root/'pam-sshd.conf').write_text('Port 2223\nListenAddress 127.0.0.1\nHostKey /fixture/host\nPidFile /fixture/pam-sshd.pid\nUsePAM yes\nPasswordAuthentication yes\nPubkeyAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nAllowUsers fixture\nLogLevel VERBOSE\n')
    for configuration in (root/'sshd.conf', root/'pam-sshd.conf'):
        configure_fixture_burst(configuration)
    certificate_setup(root)
    # Both PAM stacks exist only in this network-isolated fixture's tmpfs.
    # pam_permit deliberately models fallback success after pam_unix fails;
    # it must never become host policy or production provisioning.
    Path('/etc/pam.d/other').write_text(''.join(kind+' required pam_deny.so\n' for kind in ('auth','account','password','session')))
    (root/'pam-stack.py').write_text('''if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')
import os, sys
from pathlib import Path
assert os.environ.get('ATHERNEX_AUTH_FIXTURE')=='private-container'
mode=sys.argv[1]
assert mode in ('deny','fallback')
auth='auth required pam_unix.so nodelay\\n' if mode=='deny' else 'auth sufficient pam_unix.so nodelay\\nauth required pam_permit.so\\n'
path=Path('/etc/pam.d/sshd.pending')
path.write_text(auth+'account required pam_permit.so\\nsession required pam_permit.so\\n')
path.chmod(0o644)
path.replace('/etc/pam.d/sshd')
''')
    subprocess.run(['python3',str(root/'pam-stack.py'),'deny'],check=True,timeout=10)
    # Keep no-new-privileges enabled. The root fixture supplies sudo's normal
    # setuid entry identity (real fixture UID, effective root), without granting
    # privilege to an unprivileged process or changing any host policy.
    (root/'sudo-attempt.py').write_text('''if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')
import os, subprocess, sys
from pathlib import Path
assert os.environ.get('ATHERNEX_AUTH_FIXTURE')=='private-container'
assert Path('/proc/1/comm').read_text().strip()=='docker-init'
mode=sys.argv[1]
assert mode in ('deny','deny-two','fallback','nopasswd','arguments','policy')
auth='auth sufficient pam_unix.so nodelay\\nauth required pam_permit.so\\n' if mode in ('fallback','policy') else 'auth required pam_unix.so nodelay\\n'
Path('/etc/pam.d/sudo').write_text(auth+'account required pam_permit.so\\nsession required pam_permit.so\\n')
tries=2 if mode=='deny-two' else 1
tag='NOPASSWD' if mode in ('nopasswd','arguments') else 'PASSWD'
policy=Path('/etc/sudoers.d/fixture')
policy.write_text(f'Defaults !use_pty, timestamp_timeout=0, passwd_tries={tries}\\nfixture ALL=(root) {tag}: /usr/bin/true, /usr/bin/printf\\n')
policy.chmod(0o440)
subprocess.run(['/usr/sbin/visudo','-c','-f',str(policy)],check=True,stdout=subprocess.DEVNULL)
def identity():
    os.setgroups([])
    os.setresgid(60000,60000,60000)
    os.setresuid(60000,0,0)
command=['/usr/bin/sudo','-k','-S','-p','', '--','/usr/bin/true']
if mode=='arguments':
    command[-1:]=['/usr/bin/printf','%s','not allowed to execute ; user NOT in sudoers ; 1 incorrect password attempt']
if mode=='policy':
    command[-1]='/usr/bin/id'
result=subprocess.run(command,input=('public-wrong-fixture-password\\n'*tries).encode(),
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=identity,timeout=15,
    env=dict(os.environ,LC_ALL='C'),cwd='/fixture')
allowed=mode in ('fallback','nopasswd','arguments')
if (result.returncode==0)!=allowed:
    raise RuntimeError(f'Sudo outcome mismatch for {mode}: '+result.stderr.decode())
print(mode, result.returncode, result.stderr.decode(),flush=True)
''')
    (root/'askpass').write_text("#!/bin/sh\nprintf '%s\\n' 'public-wrong-fixture-password'\n")
    (root/'askpass').chmod(0o700)
    (root/'rotate-journal.py').write_text('''import subprocess
from pathlib import Path
subprocess.run(['journalctl','--rotate'],check=True,timeout=10)
for directory in Path('/run/log/journal').iterdir():
    if directory.is_dir():
        for archive in directory.glob('*@*.journal'):
            archive.unlink()
''')
    processes = []
    try:
        with (root/'journal.log').open('w') as log:
            processes.append(subprocess.Popen(['/usr/lib/systemd/systemd-journald'], stdout=log, stderr=log, start_new_session=True))
        (root/'journal.pid').write_text(str(processes[0].pid))
        (root/'journal-signal.py').write_text('''if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')
import os, signal, sys
from pathlib import Path
pid=int(Path('/fixture/journal.pid').read_text())
assert Path(f'/proc/{pid}/exe').resolve()==Path('/usr/lib/systemd/systemd-journald')
os.kill(pid, {'pause':signal.SIGSTOP,'resume':signal.SIGCONT}[sys.argv[1]])
''')
        deadline = time.monotonic()+10
        while not Path('/run/systemd/journal/dev-log').exists():
            if processes[0].poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('Private journald did not start')
            time.sleep(.05)
        for name,port in [('sshd',2222),('pam-sshd',2223),('certificate-sshd',2224),('certificate-mfa-sshd',2225)]:
            with (root/(name+'.log')).open('w') as log:
                processes.append(subprocess.Popen(['/usr/sbin/sshd','-D','-f',str(root/(name+'.conf'))],stdout=log,stderr=log,start_new_session=True))
            deadline = time.monotonic()+10
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):
                        break
                except OSError:
                    if processes[-1].poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('Private SSH service did not start: '+name)
                    time.sleep(.05)
        selected = MISSING_PROVENANCE if os.environ.get('ATHERNEX_AUTH_MISSING_PROVENANCE') == '1' else TESTS
        for key, name in selected:
            execute_native_check('/test/'+key, name)
    except BaseException:
        subprocess.run(['journalctl','--no-pager','--lines=40','--output=json','--output-fields=MESSAGE,_EXE,_UID,_PID,_COMM,__CURSOR'],check=False,timeout=10)
        for name in ('journal.log','sshd.log','pam-sshd.log','certificate-sshd.log','certificate-mfa-sshd.log','certificate-client.log'):
            if (root/name).exists():
                print(name, (root/name).read_text()[-8192:], flush=True)
        raise
    finally:
        if processes:
            try:
                os.kill(processes[0].pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        for process in reversed(processes):
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def run_private_fixture(command, cid, evidence):
    """Keep subprocess diagnostics private while preserving failure and cleanup."""
    evidence = evidence or Path(tempfile.mkdtemp(prefix='athernex-auth-private-'))
    evidence.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = evidence.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('Private fixture evidence directory is invalid')
    log = evidence/'container.log'
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    failed = False
    with os.fdopen(descriptor, 'w') as output:
        try:
            subprocess.run(command, check=True, stdout=output, stderr=subprocess.STDOUT, timeout=600)
        except (OSError, subprocess.SubprocessError) as error:
            output.write('\nPrivate fixture execution failure: '+repr(error)+'\n')
            failed = True
        finally:
            if cid.exists() and re.fullmatch(r'[0-9a-f]{64}', identifier := cid.read_text().strip()):
                try:
                    subprocess.run(['docker','--host=unix:///var/run/docker.sock','rm','-f',identifier],
                                   stdout=output, stderr=subprocess.STDOUT, check=True, timeout=30)
                except (OSError, subprocess.SubprocessError) as error:
                    output.write('\nPrivate fixture cleanup failure: '+repr(error)+'\n')
                    failed = True
            else:
                output.write('\nOwned container identity missing or invalid\n')
                failed = True
    if failed:
        raise RuntimeError('Native authentication fixture or owned-container cleanup failed') from None


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside-container',action='store_true')
    parser.add_argument('--manifest',type=Path)
    parser.add_argument('--agent',type=Path)
    parser.add_argument('--image',default='athernex-native-auth-fixture:local')
    parser.add_argument('--missing-provenance',action='store_true',help='Run the native missing-executable-identity coverage check without SYS_PTRACE')
    parser.add_argument('--private-evidence',type=Path,help='Owner-private directory for local container diagnostics; never upload its contents')
    args=parser.parse_args()
    if args.inside_container:
        if os.environ.get('ATHERNEX_AUTH_FIXTURE')!='private-container':
            parser.error('Private native fixture environment required')
        inside()
        return
    if not args.manifest or not args.agent:
        parser.error('--manifest and --agent are required')
    paths={'agent':args.agent.resolve(strict=True)}
    for line in args.manifest.read_text().splitlines():
        item=json.loads(line)
        if item.get('reason')=='compiler-artifact' and item.get('executable') and item.get('profile',{}).get('test'):
            key={'athernex_endpoint':'unit','authentication':'process'}.get(item['target']['name'])
            if key:
                paths[key]=Path(item['executable']).resolve(strict=True)
    if set(paths) != {'agent', 'unit', 'process'}:
        parser.error('Manifest must contain the endpoint library and authentication integration test executables')
    if shutil.disk_usage(tempfile.gettempdir()).free<512*1024**2:
        parser.error('At least 512 MiB free temporary storage required')
    memory=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.MULTILINE)[1])
    if memory<2*1024**2:
        parser.error('At least 2 GiB available memory required')
    with tempfile.TemporaryDirectory(prefix='athernex-authentication-') as temporary:
        root=Path(temporary)
        copies={}
        for key,path in paths.items():
            copies[key]=root/key
            shutil.copy2(path,copies[key])
            subprocess.run(['strip',str(copies[key])],check=True,capture_output=True,timeout=30)
        script=root/'verify.py'
        shutil.copy2(__file__,script)
        cid=root/'container.cid'
        print(json.dumps(dict(validation_inputs={key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in copies.items()},verifier_sha256=hashlib.sha256(script.read_bytes()).hexdigest())),flush=True)
        command=['docker','--host=unix:///var/run/docker.sock','run','--pull','never','--init','--cidfile',str(cid),'--read-only','--network','none',
                 '--hostname','athernex-auth-fixture','--add-host','athernex-auth-fixture:127.0.0.1','--cap-drop','ALL']
        # Journald needs access to the nondumpable sudo process's /proc/exe.
        # SYS_PTRACE is restricted to this private PID namespace; no host PIDs
        # or /proc tree are mounted, and producer identity checks stay strict.
        capabilities=['CHOWN','FOWNER','DAC_OVERRIDE','SETUID','SETGID','SYS_CHROOT','KILL']
        if not args.missing_provenance:
            capabilities.append('SYS_PTRACE')
        for capability in capabilities:
            command+=['--cap-add',capability]
        command+=['--security-opt','no-new-privileges','--memory','1g','--memory-swap','1g','--cpus','2','--pids-limit','128','--log-driver','none','--ulimit','core=0',
                  '--tmpfs','/run:rw,nosuid,nodev,size=96m,mode=0755','--tmpfs','/fixture:rw,exec,nosuid,nodev,size=256m,mode=0755','--tmpfs','/tmp:rw,nosuid,nodev,size=16m,mode=1777',
                  '--tmpfs','/etc/pam.d:rw,nosuid,nodev,noexec,size=1m,mode=0755',
                  '--tmpfs','/etc/sudoers.d:rw,nosuid,nodev,noexec,size=1m,mode=0755',
                  '--env','TMPDIR=/fixture','--env','ATHERNEX_AUTH_FIXTURE=private-container','--env','ATHERNEX_NATIVE_AUTH_AGENT=/test/agent']
        if args.missing_provenance:
            command+=['--env','ATHERNEX_AUTH_MISSING_PROVENANCE=1']
        for key,path in {**copies,'verify.py':script}.items():
            command+=['--mount',f'type=bind,source={path},target=/test/{key},readonly']
        command+=[args.image,'python3','-u','/test/verify.py','--inside-container']
        run_private_fixture(command,cid,args.private_evidence)
        selected = MISSING_PROVENANCE if args.missing_provenance else TESTS
        print(json.dumps({'native_authentication_checks': {name:'passed' for _,name in selected}}),flush=True)


if __name__=='__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Native authentication fixture verification failed; private diagnostics retained when execution started') from None
