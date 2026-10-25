#!/usr/bin/env python3
"""Measure native network delivery from isolated Linux endpoints to one real server.

Each endpoint gets a private Docker PID/network namespace and loopback-only test
traffic. A Unix-socket relay carries management HTTP or TLS to the fixture server; no
host firewall, sysctl, account, service or external network is modified. This is
multiple endpoint instances on one kernel, not a separate-host fleet proof.
"""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile

DOCKER = ['docker', '--host=unix:///var/run/docker.sock']


def save(path, value):
    temporary = path.with_suffix('.next')
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def until(predicate, seconds, description):
    deadline = time.monotonic() + seconds
    while True:
        result = predicate()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise RuntimeError(description)
        time.sleep(.1)


def stop(process):
    if process is not None and process.poll() is None:
        process.kill()
        process.wait(timeout=10)


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if not self.server.slots.acquire(blocking=False):
            return
        try:
            with socket.socket(self.server.destination_family, socket.SOCK_STREAM) as peer:
                peer.settimeout(10)
                peer.connect(self.server.destination)
                self.request.settimeout(10)
                sockets = {self.request: peer, peer: self.request}
                deadline = time.monotonic() + 40
                while sockets and time.monotonic() < deadline:
                    ready, _, _ = select.select(list(sockets), [], [], 1)
                    for source in ready:
                        target = sockets[source]
                        data = source.recv(65536)
                        if data:
                            target.sendall(data)
                            deadline = time.monotonic() + 40
                        else:
                            target.shutdown(socket.SHUT_WR)
                            del sockets[source]
        except OSError:
            # A killed/unavailable server is an intended transport failure.
            pass
        finally:
            self.server.slots.release()


class Relay(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, family, address, destination_family, destination):
        self.address_family = family
        self.destination_family = destination_family
        self.destination = destination
        self.slots = threading.BoundedSemaphore(64)
        super().__init__(address, RelayHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


def event_key(event):
    telemetry = event.get('telemetry') or {}
    if telemetry.get('type') == 'network_event':
        network = telemetry['event']
        return (network['protocol'], network['original']['source'], network['original']['destination'])
    return None


def address(value):
    return f'[{value[0]}]:{value[1]}' if ':' in value[0] else f'{value[0]}:{value[1]}'


def receive_exact(connection, count):
    data = b''
    while len(data) < count:
        chunk = connection.recv(count-len(data))
        if not chunk:
            raise RuntimeError('Fixture TCP peer closed before echo completed')
        data += chunk
    return data


def flow(index):
    v6 = index % 4 >= 2
    tcp = index % 2 == 0
    family = socket.AF_INET6 if v6 else socket.AF_INET
    kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    bind = ('::1' if v6 else '127.0.0.1', 0)
    with socket.socket(family, kind) as server, socket.socket(family, kind) as client:
        for item in (server, client):
            item.settimeout(3)
            item.bind(bind)
        destination = server.getsockname()
        source = client.getsockname()
        if tcp:
            server.listen(1)
            client.connect(destination)
            accepted, _ = server.accept()
            with accepted:
                accepted.settimeout(3)
                client.sendall(b'fixture')
                assert receive_exact(accepted, 7) == b'fixture'
                accepted.sendall(b'fixture')
                assert receive_exact(client, 7) == b'fixture'
        else:
            client.sendto(b'fixture', destination)
            data, peer = server.recvfrom(64)
            assert data == b'fixture'
            server.sendto(b'fixture', peer)
            assert client.recvfrom(64)[0] == b'fixture'
    protocol = 'tcp' if tcp else 'udp'
    subprocess.run(['conntrack', '-D', '-f', 'ipv6' if v6 else 'ipv4', '-p', protocol,
                    '--orig-src', source[0], '--orig-dst', destination[0],
                    '--sport', str(source[1]), '--dport', str(destination[1])],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
    return (protocol, address(source), address(destination))


def worker():
    # These guards precede all namespace policy changes and endpoint execution.
    assert 'docker-init' in Path('/proc/1/comm').read_text()
    assert sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo']
    assert any(line.split()[1:3] == ['/fixture', 'tmpfs']
               for line in Path('/proc/mounts').read_text().splitlines())
    assert os.geteuid() == 0
    for binary in ('iptables', 'ip6tables'):
        subprocess.run([binary, '-A', 'OUTPUT', '-m', 'conntrack', '--ctstate',
                        'NEW,ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=True, timeout=10)
    relay = Relay(socket.AF_INET, ('127.0.0.1', 17887), socket.AF_UNIX, '/bridge/http.sock')
    control, state = Path('/control'), Path('/fixture/state')
    state.mkdir(mode=0o700)
    bootstrap = Path('/fixture/bootstrap.json')
    bootstrap.write_bytes((control/'bootstrap.json').read_bytes())
    bootstrap.chmod(0o600)
    if (control/'ca.pem').exists():
        ca = Path('/fixture/ca.pem')
        ca.write_bytes((control/'ca.pem').read_bytes())
        ca.chmod(0o600)
        invitation = json.loads(bootstrap.read_text())
        # Configure the private trust root before even the enrollment request.
        save(state/'config.json', dict(server=invitation['server'], endpoint_id=secrets.token_hex(32),
             credential=secrets.token_hex(32), enrollment_token=invitation['enrollment_token'],
             scanner='/usr/bin/clamscan', updater='/usr/bin/freshclam', scan_roots=['/fixture'],
             allow_scripts=False, ca_file=str(ca)))
        (state/'config.json').chmod(0o600)
    subprocess.run(['/test/agent', 'enroll', str(bootstrap), str(state)], check=True, timeout=30)
    config = json.loads((state/'config.json').read_text())
    config['telemetry'] = dict(enabled=True, interval_secs=30, linux_network_events=True)
    save(state/'config.json', config)
    (state/'config.json').chmod(0o600)
    # Private fixture parent protects this test credential; it is excluded from reports.
    save(control/'enrolled.json', config)
    log = (control/'agent.log').open('w')
    agent = None
    db = None
    expected, originals, gaps, phases = {}, {}, [], []
    max_pending = max_outbox = max_rss = 0

    def start():
        return subprocess.Popen(['/test/agent', 'run', str(state)], stdout=log, stderr=log)

    def health():
        try:
            raw = db.execute("SELECT value FROM telemetry_metadata WHERE key='network_events_health'").fetchone()
            return json.loads(raw[0]) if raw else None
        except sqlite3.OperationalError:
            return None

    def sample():
        nonlocal max_pending, max_outbox, max_rss
        if agent.poll() is not None:
            raise RuntimeError('Agent unexpectedly exited')
        pending = db.execute('SELECT count(*) FROM telemetry_pending').fetchone()[0]
        outbox = db.execute('SELECT count(*) FROM outbox').fetchone()[0]
        assert pending <= 8192 and outbox <= 4096
        max_pending, max_outbox = max(max_pending, pending), max(max_outbox, outbox)
        for (payload,) in db.execute('SELECT payload FROM telemetry_pending UNION ALL SELECT payload FROM outbox'):
            event = json.loads(payload)
            if event_key(event) in expected:
                previous = originals.setdefault(event['id'], event)
                assert previous == event
        status = Path(f'/proc/{agent.pid}/status').read_text()
        rss = re.search(r'^VmHWM:\s+(\d+)', status, re.M)
        max_rss = max(max_rss, int(rss[1]) if rss else 0)

    def snapshot():
        sample()
        save(control/'originals.json', list(originals.values()))
        return dict(endpoint_id=config['endpoint_id'], health=health(), phases=phases,
                    expected=list(expected.values()), gaps=gaps,
                    queue_high_water=dict(pending=max_pending, outbox=max_outbox),
                    agent_peak_rss_kib=max_rss)

    try:
        agent = start()
        until(lambda: (state/'endpoint.sqlite3').exists(), 20, 'Agent database absent')
        db = sqlite3.connect(f'file:{state}/endpoint.sqlite3?mode=ro', uri=True, timeout=5)
        until(lambda: (health() or {}).get('state') == 'active', 20, 'Collector not active')
        assert health()['namespace'] == os.stat('/proc/self/ns/net').st_ino
        save(control/'ready.json', snapshot())
        sequence = 0
        while True:
            def command_ready():
                path = control/'command.json'
                if path.exists():
                    command = json.loads(path.read_text())
                    if command['sequence'] > sequence:
                        return command
                sample()
                return None
            command = until(command_ready, 600, 'Coordinator command timeout')
            sequence = command['sequence']
            phase = command['phase']
            began = time.monotonic_ns()
            if phase == 'crash':
                before = health()
                stop(agent)
                for index in range(8):
                    key = flow(index)
                    assert key not in expected
                    gaps.append(list(key))
                agent = start()
                until(lambda: (health() or {}).get('stream_id') != before['stream_id']
                      and (health() or {}).get('subscriptions') == 2, 20, 'Crash gap absent')
                after = health()
                assert after['loss_signals'] == 1 and after['state'] == 'degraded'
            elif phase != 'finish':
                seconds, rate = command['seconds'], command['rate']
                next_sample = 0
                for index in range(seconds * rate):
                    target = began / 1e9 + index / rate
                    time.sleep(max(0, target - time.monotonic()))
                    started = time.monotonic_ns()
                    key = flow(index)
                    assert key not in expected and list(key) not in gaps, 'Repeated tuple is ambiguous'
                    expected[key] = dict(key=list(key), phase=phase, started_ns=started)
                    if time.monotonic() >= next_sample:
                        sample()
                        next_sample = time.monotonic() + 1
                time.sleep(max(0, began / 1e9 + seconds - time.monotonic()))
                if phase == 'outage' or phase.startswith('tls_rejected_'):
                    def durable():
                        sample()
                        boundaries = {key: set() for key, value in expected.items() if value['phase'] == phase}
                        for event in originals.values():
                            if event_key(event) in boundaries:
                                boundaries[event_key(event)].add(event['telemetry']['event']['change'])
                        return all({'created', 'removed'} <= changes for changes in boundaries.values())
                    until(durable, 20, f'{phase} boundaries did not reach durable local storage')
            phases.append(dict(phase=phase, elapsed_ms=(time.monotonic_ns()-began)//1_000_000))
            save(control/f'result-{sequence}.json', snapshot())
            if phase == 'finish':
                break
    finally:
        stop(agent)
        if db:
            db.close()
        log.close()
        relay.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--image', default='athernex-native-network-fixture:local')
    parser.add_argument('--seconds', type=int, default=180, help='Seconds in each online/recovery phase (60–600)')
    parser.add_argument('--rate', type=int, default=4, help='Flows per second per endpoint (1–8)')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--tls', action='store_true', help='Exercise TLS certificate rejection and rotation before outage recovery')
    args = parser.parse_args()
    if args.worker:
        worker()
        return
    if not args.agent or not args.server or not args.report:
        parser.error('--agent, --server and --report are required')
    if not 60 <= args.seconds <= 600 or not 1 <= args.rate <= 8:
        parser.error('--seconds must be 60–600; --rate must be 1–8')
    if os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        parser.error('This native fixture currently requires Linux x86_64')
    if shutil.disk_usage(tempfile.gettempdir()).free < 1024**3:
        parser.error('At least 1 GiB temporary storage is required')
    image = subprocess.check_output(DOCKER + ['image', 'inspect', args.image, '--format', '{{.Id}}'],
                                    text=True, timeout=30).strip()
    args.report = args.report.resolve()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    # Retain private diagnostics on both success and failure, never reuse a run.
    root = Path(tempfile.mkdtemp(prefix='ax-network-fleet-'))
    print(f'Private fixture directory: {root}', flush=True)
    catalog = root/'catalog'
    catalog.mkdir()
    for source, name in ((args.agent, 'athernex-endpoint-linux-x86_64'), (args.server, 'server')):
        shutil.copy2(source.resolve(strict=True), catalog/name)
        subprocess.run(['strip', str(catalog/name)], check=True, timeout=30)
    agent = catalog/'athernex-endpoint-linux-x86_64'
    digests = {name: hashlib.sha256((catalog/name).read_bytes()).hexdigest()
               for name in ('athernex-endpoint-linux-x86_64', 'server')}
    save(catalog/'linux-x86_64.json', dict(target='linux-x86_64', version='fixture',
         sha256=digests[agent.name], signing='development-unsigned'))
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    key = 'public-network-fleet-fixture-' + 'x' * 32
    credential = root/'operator.key'
    credential.write_text(key)
    credential.chmod(0o600)
    env = dict(os.environ, ATHERNEX_ENDPOINT_ARTIFACTS=str(catalog),
               ATHERNEX_ENDPOINT_RELEASES=str(root/'releases'))
    env.pop('ATHERNEX_PUBLIC_ORIGIN', None)
    # Ignore ambient HTTP proxies for private loopback traffic.
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, body=None, *, form=False, bearer=key, endpoint_transport=False):
        headers = {'Authorization': f'Bearer {bearer}'}
        data = None
        if body is not None:
            data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        selected_origin = tls_origin if args.tls and endpoint_transport else origin
        selected_client = tls_http if args.tls and endpoint_transport else http
        with selected_client.open(urllib.request.Request(selected_origin+path, data, headers), timeout=20) as response:
            return response.read()

    server_log = (root/'server.log').open('w')
    server = relay = None
    tls = tls_http = tls_origin = None
    workers, controls, logs = [], [], []
    delivered, observed, highwater = [{}, {}], [{}, {}], [0, 0]
    report = dict(schema=1, passed=False, inputs=dict(sha256=digests, image=image,
                  fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()),
                  fixture_directory=str(root), endpoints=2, kernel=os.uname().release,
                  online_and_recovery_seconds=args.seconds, target_flows_per_second_per_endpoint=args.rate,
                  native_windows_or_macos=False, completion_claim=False)
    report['management_transport'] = 'TLS through local Unix relays' if args.tls else 'HTTP through local Unix relays'

    def start_server():
        process = subprocess.Popen([str(catalog/'server'), '--no-journal', '--db', str(root/'server.db'),
                                    '--port', str(port), '--operator-key-file', str(credential)],
                                   cwd=root, env=env, stdout=server_log, stderr=server_log)
        def ready():
            if process.poll() is not None:
                raise RuntimeError('Fixture server exited; see retained server.log')
            try:
                return request('/healthz')
            except OSError:
                return None
        try:
            until(ready, 30, 'Fixture server did not become ready')
        except BaseException:
            stop(process)
            raise
        return process

    def poll():
        for index, control in enumerate(controls):
            enrolled = control/'enrolled.json'
            if not enrolled.exists():
                continue
            endpoint = json.loads(enrolled.read_text())['endpoint_id']
            before = 2**63-1
            highest = highwater[index]
            while before > highwater[index]:
                page = json.loads(request(f'/api/endpoints/{endpoint}/events?before={before}'))
                if not page:
                    break
                before = page[-1]['evidence_id']
                for row in page:
                    if row['evidence_id'] <= highwater[index]:
                        continue
                    highest = max(highest, row['evidence_id'])
                    event = row['event']
                    if event_key(event):
                        old = delivered[index].setdefault(event['id'], row)
                        assert old == row
                        changes = observed[index].setdefault(event_key(event), {})
                        changes.setdefault(event['telemetry']['event']['change'], time.monotonic_ns())
            highwater[index] = highest

    def run_phase(sequence, phase, seconds=0, online=True):
        for index, control in enumerate(controls):
            name = 'peer_continuous' if phase == 'crash' and index == 1 else phase
            save(control/'command.json', dict(sequence=sequence, phase=name,
                 seconds=seconds, rate=args.rate))
        deadline = time.monotonic() + seconds + 60
        while not all((control/f'result-{sequence}.json').exists() for control in controls):
            for process, control in zip(workers, controls):
                if process.poll() is not None and not (
                    process.returncode == 0 and (control/f'result-{sequence}.json').exists()
                ):
                    raise RuntimeError('Fixture worker exited; see retained worker logs')
            if online:
                poll()
            if time.monotonic() > deadline:
                raise RuntimeError(f'{phase} deadline expired')
            time.sleep(1)
        result = [json.loads((control/f'result-{sequence}.json').read_text()) for control in controls]
        print(f'Completed phase {phase}: {[len(r["expected"]) for r in result]} cumulative flows', flush=True)
        return result

    try:
        server = start_server()
        bridge = root/'bridge'
        bridge.mkdir(mode=0o777)
        bridge.chmod(0o777)
        destination = ('127.0.0.1', port)
        if args.tls:
            from network_fleet_tls import certificates, Terminator
            contexts, fingerprints = certificates(root/'pki')
            tls = Terminator(destination, contexts)
            destination = tls.server_address
            tls_origin = f'https://127.0.0.1:{destination[1]}'
            tls_http = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=root/'pki/trusted.pem')))
            report['tls'] = dict(certificate_sha256=fingerprints,
                helper_sha256=hashlib.sha256(Path(__file__).with_name('network_fleet_tls.py').read_bytes()).hexdigest(),
                openssl=ssl.OPENSSL_VERSION, rejected_phases=[])
        relay = Relay(socket.AF_UNIX, str(bridge/'http.sock'), socket.AF_INET, destination)
        (bridge/'http.sock').chmod(0o777)
        html = request('/endpoints').decode()
        csrf = re.search(r"name=csrf value='([^']+)'", html)[1]
        for index in range(2):
            control = root/f'endpoint-{index}'
            control.mkdir(mode=0o777)
            control.chmod(0o777)
            controls.append(control)
            scheme = 'https' if args.tls else 'http'
            bundle = request('/endpoints/installer', dict(csrf=csrf, server=f'{scheme}://127.0.0.1:17887/',
                             target='linux-x86_64'), form=True)
            with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
                (control/'bootstrap.json').write_bytes(archive.read('bootstrap.json'))
            if args.tls:
                shutil.copyfile(root/'pki/trusted.pem', control/'ca.pem')
            log = (root/f'worker-{index}.log').open('w')
            logs.append(log)
            command = DOCKER + ['run', '--pull', 'never', '--rm', '--init', '--cidfile', str(control/'container.cid'),
                '--read-only', '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                '--security-opt', 'no-new-privileges', '--memory', '1g', '--memory-swap', '1g', '--cpus', '2',
                '--pids-limit', '128', '--log-driver', 'none', '--ulimit', 'core=0',
                '--sysctl', 'net.netfilter.nf_conntrack_acct=1',
                '--tmpfs', '/fixture:rw,exec,nosuid,nodev,size=384m,mode=0700',
                '--tmpfs', '/run:rw,nosuid,nodev,size=8m,mode=0755',
                '--env', 'TMPDIR=/fixture',
                '--mount', f'type=bind,source={agent},target=/test/agent,readonly',
                '--mount', f'type=bind,source={Path(__file__).resolve()},target=/test/verify.py,readonly',
                '--mount', f'type=bind,source={control},target=/control',
                '--mount', f'type=bind,source={bridge},target=/bridge,readonly',
                image, 'python3', '-u', '/test/verify.py', '--worker']
            workers.append(subprocess.Popen(command, stdout=log, stderr=log))
        def workers_ready():
            if any(p.poll() is not None for p in workers):
                raise RuntimeError('Worker failed during setup; see retained logs')
            return all((control/'ready.json').exists() for control in controls)
        until(workers_ready, 45, 'Workers did not become ready')
        initial = [json.loads((c/'ready.json').read_text()) for c in controls]
        assert len({r['health']['namespace'] for r in initial}) == 2
        assert os.stat('/proc/self/ns/net').st_ino not in {r['health']['namespace'] for r in initial}
        assert len({r['endpoint_id'] for r in initial}) == 2
        online = run_phase(1, 'online', args.seconds)
        poll()
        assert all(observed), 'No online network delivery from one endpoint'
        sequence = 1
        if args.tls:
            assert tls.snapshot()['trusted_original']['handshakes'] >= 2
            for label in ('untrusted_ca', 'wrong_name'):
                tls.disconnect(label)
                sequence += 1
                phase = 'tls_rejected_' + label
                rejected = run_phase(sequence, phase, 30)
                poll()
                stats = tls.snapshot()[label]
                assert sum(stats['handshake_errors'].values()) > 0, 'Agents did not attempt the rejected TLS certificate'
                assert stats['plaintext_client_bytes'] == stats['upstream_connections'] == 0, 'Untrusted TLS connection reached the server'
                for index, item in enumerate(rejected):
                    assert item['health']['loss_signals'] == 0 and item['health']['dropped_events'] == 0
                    assert all(tuple(e['key']) not in observed[index]
                               for e in item['expected'] if e['phase'] == phase), 'Rejected TLS delivered a new flow'
                report['tls']['rejected_phases'].append(dict(phase=phase, seconds=30, **stats))
            tls.disconnect('trusted_rotated')
        before_restart = [dict(rows) for rows in delivered]
        stop(server)
        outage_began = time.monotonic()
        sequence += 1
        outage = run_phase(sequence, 'outage', 30, online=False)
        assert all(r['health']['loss_signals'] == 0 for r in outage)
        sequence += 1
        crashed = run_phase(sequence, 'crash', 2, online=False)
        assert crashed[0]['health']['loss_signals'] == 1
        assert crashed[0]['health']['stream_id'] != initial[0]['health']['stream_id']
        assert crashed[1]['health']['loss_signals'] == 0
        assert crashed[1]['health']['stream_id'] == initial[1]['health']['stream_id']
        report['server_outage_ms'] = round((time.monotonic()-outage_began)*1000)
        server = start_server()
        sequence += 1
        recovered = run_phase(sequence, 'recovery', args.seconds)
        drain = time.monotonic()
        def complete():
            poll()
            return all(all({'created', 'removed'} <= observed[i].get(tuple(e['key']), {}).keys()
                           for e in item['expected'])
                       and all(e['id'] in delivered[i] for e in json.loads((controls[i]/'originals.json').read_text()))
                       for i, item in enumerate(recovered))
        until(complete, 120, 'Expected flow boundaries missing after recovery')
        report['drain_after_generation_ms'] = round((time.monotonic()-drain)*1000)
        sequence += 1
        final = run_phase(sequence, 'finish')
        for process in workers:
            assert process.wait(timeout=15) == 0
        poll()
        # Re-read the committed originals after a second hard server restart.
        stop(server)
        server = start_server()
        committed = [dict(rows) for rows in delivered]
        delivered[:] = [{}, {}]
        highwater[:] = [0, 0]
        poll()
        assert delivered == committed, 'Server restart changed or lost committed network originals'
        summaries = []
        for index, item in enumerate(final):
            keys = {tuple(e['key']) for e in item['expected']}
            selected = {eid: row for eid, row in delivered[index].items() if event_key(row['event']) in keys}
            assert all(row['case_id'] is None for row in selected.values())
            assert all(row['event']['telemetry']['namespace'] == initial[index]['health']['namespace']
                       for row in delivered[index].values()), 'Cross-namespace evidence leak'
            assert all(tuple(k) not in observed[index] for k in item['gaps']), 'Invented crash-gap events'
            assert all(delivered[index].get(eid) == row for eid, row in before_restart[index].items())
            originals = json.loads((controls[index]/'originals.json').read_text())
            assert originals and all(selected[e['id']]['event'] == e for e in originals)
            credential = json.loads((controls[index]/'enrolled.json').read_text())
            replay = [row['event'] for row in selected.values()]
            for offset in range(0, len(replay), 64):
                batch = replay[offset:offset+64]
                result = json.loads(request(f'/api/endpoint/{item["endpoint_id"]}/events', batch,
                                            bearer=credential['credential'], endpoint_transport=True))
                assert result['accepted'] == 0 and result['acknowledged'] == len(batch)
            health = item['health']
            assert health['dropped_events'] == 0 and health['loss_signals'] == (1 if index == 0 else 0)
            assert health['subscriptions'] == (2 if index == 0 else 1)
            assert health['state'] == ('degraded' if index == 0 else 'active')
            assert health['stream_id'] == crashed[index]['health']['stream_id']
            latency = {}
            for phase in sorted({e['phase'] for e in item['expected']}):
                samples = sorted(max(observed[index][tuple(e['key'])][change]
                                     for change in ('created', 'removed')) - e['started_ns']
                                 for e in item['expected'] if e['phase'] == phase)
                assert samples[0] >= 0
                latency[phase] = dict(samples=len(samples), p50_ms=samples[(len(samples)-1)//2]//1_000_000,
                    p95_ms=samples[(len(samples)-1)*95//100]//1_000_000, max_ms=samples[-1]//1_000_000)
            summaries.append(dict(endpoint_id=item['endpoint_id'], flows=len(keys), records=len(selected),
                exact_local_originals=len(originals), replayed_without_duplicates=len(replay),
                intentional_unobserved_gap_flows=len(item['gaps']), coverage=health,
                queue_high_water=item['queue_high_water'], agent_peak_rss_kib=item['agent_peak_rss_kib'],
                completion_latency_observed_upper_bound=latency, phases=item['phases']))
        report['measurements'] = summaries
        snapshot = json.loads(request('/api/export'))
        assert not any(f['rule'] == 'AX-003' for f in snapshot['findings'])
        if args.tls:
            stats = tls.snapshot()
            assert stats['trusted_rotated']['handshakes'] >= 2 and stats['trusted_rotated']['plaintext_client_bytes'] > 0
            report['tls']['connections'] = stats
            report['tls']['unchanged_agent_ca_after_rotation'] = True
        report.update(passed=True, measurements=summaries, unexpected_network_investigations=0,
                      actual_server_hard_restarts=2,
                      limits=['Two isolated endpoint namespaces on one Linux kernel, not separate physical hosts.',
                              ('TLS terminates at a private local proxy; WAN, packet loss and separate-host behavior are outside this run.'
                               if args.tls else 'Management uses local Unix relays; WAN, TLS and packet-loss behavior are outside this run.'),
                              'Synthetic benign loopback traffic does not establish a production false-positive rate.',
                              'Created/removed boundaries are independently counted; optional intermediate updates are not.',
                              'Finite measured workload and observation-limited latency; no arbitrary-load/lossless guarantee.'])
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        stop(server)
        for control in controls:
            cid = control/'container.cid'
            if cid.exists() and re.fullmatch(r'[0-9a-f]{64}', value := cid.read_text().strip()):
                subprocess.run(DOCKER + ['rm', '-f', value], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False, timeout=30)
        for process in workers:
            stop(process)
        if relay:
            relay.close()
        if tls:
            report['tls']['connections'] = tls.snapshot()
            tls.close()
        for log in logs:
            log.close()
        server_log.close()
        save(args.report, report)
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
