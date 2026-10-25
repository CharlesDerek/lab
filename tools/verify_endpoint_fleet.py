#!/usr/bin/env python3
"""Disposable native fleet journey, including forced termination and receipt recovery."""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import io
import json
import os
import platform
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, default=Path('target/debug'))
    args = parser.parse_args()
    suffix = '.exe' if sys.platform == 'win32' else ''
    system = {'win32': 'windows', 'darwin': 'macos', 'linux': 'linux'}[sys.platform]
    arch = {'amd64': 'x86_64', 'x86_64': 'x86_64', 'arm64': 'aarch64', 'aarch64': 'aarch64'}[platform.machine().lower()]
    target = f'{system}-{arch}'
    server_binary = (args.bin_dir / f'athernex-siem{suffix}').resolve()
    agent_binary = (args.bin_dir / f'athernex-endpoint{suffix}').resolve()
    with tempfile.TemporaryDirectory(prefix='athernex-fleet-fixture-') as directory:
        root = Path(directory).resolve()
        catalog = root / 'builds'
        catalog.mkdir()
        binary = catalog / f'athernex-endpoint-{target}{suffix}'
        shutil.copy2(agent_binary, binary)
        # Debug binaries can be large. Stripping this disposable copy preserves the tested executable.
        if system == 'linux':
            subprocess.run(['strip', str(binary)], check=True)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        (catalog / f'{target}.json').write_text(json.dumps(dict(target=target, version='fixture', sha256=digest, signing='development-unsigned')))
        key = 'public-fixture-key-' + 'x' * 32
        credential = root / 'operator.key'
        credential.write_text(key)
        credential.chmod(0o600)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        env = dict(os.environ, ATHERNEX_ENDPOINT_ARTIFACTS=str(catalog),
                   ATHERNEX_ENDPOINT_RELEASES=str(root / 'releases'))
        env.pop('ATHERNEX_PUBLIC_ORIGIN', None)

        def request(path, body=None, *, form=False, auth=True):
            headers = {'Authorization': f'Bearer {key}'} if auth else {}
            if body is not None:
                data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
                headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            else:
                data = None
            with urllib.request.urlopen(urllib.request.Request(origin + path, data, headers), timeout=30) as response:
                return response.read()

        def start():
            process = subprocess.Popen([str(server_binary), '--no-journal', '--db', str(root / 'ledger.db'), '--port', str(port), '--operator-key-file', str(credential)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                try:
                    request('/healthz', auth=False)
                    return process
                except OSError:
                    time.sleep(.1)
            process.kill()
            raise RuntimeError('Fixture server did not become ready')

        server = start()
        try:
            html = request('/endpoints').decode()
            csrf = re.search(r"name=csrf value='([^']+)'", html).group(1)
            bundle = request('/endpoints/installer', {'csrf': csrf, 'server': origin + '/', 'target': target}, form=True)
            unpacked = root / 'installer'
            with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
                archive.extractall(unpacked)
            downloaded_agent = unpacked / f'athernex-endpoint{suffix}'
            unpacked.chmod(0o700)
            downloaded_agent.chmod(0o700)
            with socket.socket() as telemetry_socket:
                telemetry_socket.bind(('127.0.0.1', 0))
                telemetry_socket.listen()
                telemetry_port = telemetry_socket.getsockname()[1]
                native = json.loads(subprocess.check_output([str(downloaded_agent), 'capture-telemetry', '--pid', str(os.getpid())], timeout=20))
                assert any(p['pid'] == os.getpid() for p in native['processes'])
                assert any(c['owner_pid'] == os.getpid() and c['local'] == f'127.0.0.1:{telemetry_port}' for c in native['connections'])
            state = root / 'endpoint-state'
            subprocess.run([str(downloaded_agent), 'enroll', str(unpacked / 'bootstrap.json'), str(state)], check=True, stdout=subprocess.DEVNULL)
            fixture_config = json.loads((state / 'config.json').read_text())
            fixture_config['telemetry']['enabled'] = False
            (state / 'config.json').write_text(json.dumps(fixture_config))
            original_config = (state / 'config.json').read_bytes()
            wrong_bootstrap = json.loads((unpacked / 'bootstrap.json').read_text())
            wrong_bootstrap['server'] = 'https://different-server.invalid/'
            wrong_path = root / 'wrong-bootstrap.json'
            wrong_path.write_text(json.dumps(wrong_bootstrap))
            rejected = subprocess.run([str(downloaded_agent), 'enroll', str(wrong_path), str(state)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            assert rejected.returncode != 0 and (state / 'config.json').read_bytes() == original_config
            fleet = json.loads(request('/api/endpoints'))
            assert len(fleet['endpoints']) == 1
            endpoint = fleet['endpoints'][0]['id']
            request('/cases/action', {'csrf': csrf, 'op': 'create', 'title': 'Public endpoint fixture', 'severity': '3'}, form=True)
            cases = json.loads(request('/api/state'))['cases']
            case = cases[0]['id']
            request('/endpoints/action', {'csrf': csrf, 'op': 'queue', 'id': endpoint, 'case_id': case, 'action': 'inventory'}, form=True)
            command = json.loads(request('/api/endpoints'))['commands'][0]['command']['id']
            request('/endpoints/action', {'csrf': csrf, 'op': 'approve', 'id': command}, form=True)
            for _ in range(2):
                subprocess.run([str(downloaded_agent), 'run', str(state), '--once'], check=True, stdout=subprocess.DEVNULL)
            result = json.loads(request('/api/endpoints'))['commands'][0]
            assert result['state'] == 'succeeded' and result['receipt']['command_id'] == command
            exported = json.loads(request(f'/api/cases/{case}/export'))
            assert exported['endpoint_responses'][0]['receipt'] == result['receipt']
            # Exercise actual portal review, authenticated chunk delivery and
            # signed replacement using a fresh disposable release key.
            public = subprocess.check_output([str(agent_binary), 'release-keygen', str(root / 'release-keys')], text=True).strip()
            release_info = json.loads(subprocess.check_output([str(downloaded_agent), 'release-check', 'a' * 64], text=True))
            release_manifest = root / 'signed-release.json'
            subprocess.run([str(agent_binary), 'release-sign', str(root / 'release-keys/release.pk8'),
                            str(downloaded_agent), release_info['version'], 'stable', '1',
                            str(int(time.time() * 1000) + 600_000), str(release_manifest)], check=True)
            release_id = subprocess.check_output([str(agent_binary), 'release-publish', str(release_manifest),
                                                  str(downloaded_agent), public, str(root / 'releases')], text=True).strip()
            update_config = json.loads((state / 'config.json').read_text())
            update_config['updates'] = dict(managed=True, public_key=public, channel='stable',
                                            install_path=str(downloaded_agent), minimum_sequence=0, allow_unsigned_native=True)
            (state / 'config.json').write_text(json.dumps(update_config))
            subprocess.run([str(downloaded_agent), 'run', str(state), '--once'], check=True, stdout=subprocess.DEVNULL)
            request('/endpoints/updates/action', dict(csrf=csrf, op='propose', id=endpoint, release_id=release_id), form=True)
            deployment = json.loads(request('/api/endpoint-updates'))[0]
            assert deployment['state'] == 'pending'
            request('/endpoints/updates/action', dict(csrf=csrf, op='approve', id=deployment['deployment']['id']), form=True)
            for _ in range(2):
                subprocess.run([str(downloaded_agent), 'run', str(state), '--once'], check=True, stdout=subprocess.DEVNULL)
            delivered = json.loads(request('/api/endpoint-updates'))[0]
            assert delivered['state'] == 'staged' and delivered['receipt']['release_id'] == release_id
            subprocess.run([str(agent_binary), 'update-apply', str(state)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run([str(downloaded_agent), 'run', str(state), '--once'], check=True, stdout=subprocess.DEVNULL)
            updated_health = json.loads(request('/api/endpoints'))['endpoints'][0]['health']['updates']
            assert updated_health['installed_release'] == release_id and updated_health['state'] == 'installed'
            # Kill the process rather than closing its SQLite connection gracefully.
            server.kill()
            server.wait(timeout=10)
            server = start()
            recovered = json.loads(request('/api/endpoints'))
            assert recovered['commands'][0]['receipt'] == result['receipt']
            assert len(recovered['endpoints']) == 1
            assert json.loads(request('/api/endpoint-updates'))[0]['receipt'] == delivered['receipt']
            # A complete backup must include all retained state and pass independent verification.
            server.terminate()
            server.wait(timeout=10)
            offline = subprocess.run([str(downloaded_agent), 'run', str(state), '--once'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            assert offline.returncode != 0
            backup = root / 'backup'
            subprocess.run([str(server_binary), '--db', str(root / 'ledger.db'), '--backup-dir', str(backup)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run([str(server_binary), '--verify-backup', str(backup)], check=True, stdout=subprocess.DEVNULL)
            print(json.dumps({'platform': target, 'installer_download': 'passed', 'native_process_and_socket_capture': 'passed', 'native_agent_enrollment': 'passed', 'server_identity_guard': 'passed', 'approved_inventory_and_receipt': 'passed', 'case_response_export': 'passed', 'signed_release_delivery_and_local_install': 'passed', 'deployment_receipt_restart_recovery': 'passed', 'forced_restart_recovery': 'passed', 'offline_failure_exit': 'passed', 'backup_verification': 'passed'}, indent=2))
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=10)


if __name__ == '__main__':
    main()
