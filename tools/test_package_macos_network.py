import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import package_macos_network as network
from package_endpoint import validate_binary


class NetworkPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / network.APP
        self.identity = dict(team_id='ABCDE12345', agent_identifier='invalid.example.agent',
            container_identifier='invalid.example.container', provider_identifier='invalid.example.provider',
            app_group='ABCDE12345.invalid.example.group', mach_service_name='ABCDE12345.invalid.example.group.telemetry')
        self.pin = self.root / 'identity.json'
        self.pin.write_text(json.dumps(self.identity))
        self.output = self.root / 'snapshot'
        self.output.mkdir()
        self.binary = b'\xcf\xfa\xed\xfe' + (0x100000C).to_bytes(4, 'little') + bytes(56)
        files, _, provider = network.paths(self.identity)
        for path in [network.APP + '/Contents/Info.plist', provider + '/Contents/Info.plist',
                     network.APP + '/Contents/MacOS/AthernexNetwork', provider + '/Contents/MacOS/AthernexNetworkProvider']:
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(self.binary if '/MacOS/' in path else b'fixture plist')
            destination.chmod(0o755 if '/MacOS/' in path else 0o644)

    def package(self, run=None):
        result = subprocess.CompletedProcess([], 0, json.dumps(dict(identity=self.identity, provider_cdhashes=['a' * 40])).encode())
        with patch.object(network.subprocess, 'run', side_effect=run, return_value=result):
            return network.package(self.app, self.pin, self.output, self.root / 'endpoint', 'macos-aarch64', validate_binary)

    def test_exact_signed_snapshot_and_private_manifest_are_bound(self):
        data, artifact = self.package()
        self.assertEqual(artifact['bytes'], len(data))
        self.assertEqual(artifact['sha256'], hashlib.sha256(data).hexdigest())
        manifest = bytearray()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(len(archive.infolist()), 4)
            for entry in archive.infolist():
                self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(stat.S_IFMT(entry.external_attr >> 16), stat.S_IFREG)
                content = archive.read(entry)
                mode = (entry.external_attr >> 16) & 0o777
                manifest.extend(f'{entry.filename}\0{mode:04o}\0{len(content)}\0{hashlib.sha256(content).hexdigest()}\n'.encode())
        self.assertEqual(artifact['tree_sha256'], hashlib.sha256(manifest).hexdigest())

    def test_links_unexpected_files_and_extra_roles_refuse(self):
        path = self.app / 'Contents' / 'raw.log'
        path.write_text('private runtime fixture')
        with self.assertRaisesRegex(ValueError, 'Unapproved'):
            self.package()
        path.unlink()

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink control')
    def test_symlink_cannot_enter_snapshot(self):
        path = self.app / 'Contents' / 'raw.log'
        path.symlink_to(self.pin)
        with self.assertRaisesRegex(ValueError, 'Unapproved'):
            self.package()

    def test_signed_identity_mismatch_and_changed_snapshot_refuse(self):
        def changed(*args, **kwargs):
            (self.output / network.APP / 'Contents' / 'Info.plist').write_bytes(b'changed after signature check')
            return subprocess.CompletedProcess([], 0, json.dumps(dict(identity=self.identity, provider_cdhashes=['a' * 40])).encode())
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.package(changed)

    def test_invalid_identity_never_reaches_inspector(self):
        for key, value in [('team_id', 'private team'), ('provider_identifier', 'invalid.example.provider" or true'), ('mach_service_name', 'invalid.other.service')]:
            self.pin.write_text(json.dumps(dict(self.identity, **{key:value})))
            with patch.object(network.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    self.package()
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
