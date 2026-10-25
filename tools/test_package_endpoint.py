#!/usr/bin/env python3
"""Catalog verification with controlled signatures; never claims Apple validation."""
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import package_endpoint as package


def macho(machine=0x100000C):
    return b'\xcf\xfa\xed\xfe' + struct.pack('<I', machine) + b'\0' * 56


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.main = self.root / 'agent'
        self.native = self.root / 'adapter'
        self.output = self.root / 'catalog'
        self.main.write_bytes(macho() + b'management')
        self.native.write_bytes(macho() + b'native')
        self.argv = ['package_endpoint.py', '--binary', str(self.main), '--target', 'macos-aarch64',
                     '--output', str(self.output), '--require-native-signature', '--native-adapter', str(self.native)]

    def run_package(self):
        with patch.object(sys, 'argv', self.argv):
            package.main()

    def test_verified_snapshots_are_published_even_if_inputs_change(self):
        original = self.native.read_bytes()
        inspected = []
        def verify(path, endpoint_security=False):
            inspected.append((path.read_bytes(), endpoint_security))
            self.assertNotIn(path, (self.main, self.native))
            if endpoint_security:
                self.native.write_bytes(macho() + b'changed during verification')
        with patch.object(sys, 'platform', 'darwin'), patch.object(package, 'verify_macos_signature', side_effect=verify), patch.object(package.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, hashlib.sha256(original).hexdigest().encode())):
            self.run_package()
        report = json.loads((self.output / 'macos-aarch64.json').read_text())
        self.assertEqual((self.output / 'athernex-endpoint-native-macos-aarch64').read_bytes(), original)
        self.assertEqual(report['native_adapter']['sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual([native for _, native in inspected], [False, True])

    def test_unverified_native_packaging_is_refused_before_catalog_changes(self):
        with patch.object(sys, 'platform', 'linux'):
            with self.assertRaises(ValueError): self.run_package()
        self.argv.remove('--require-native-signature')
        with patch.object(sys, 'platform', 'darwin'):
            with self.assertRaises(ValueError): self.run_package()
        self.assertFalse(self.output.exists())

    def test_wrong_architecture_is_refused_before_signature_checks(self):
        self.native.write_bytes(macho(0x1000007))
        with patch.object(sys, 'platform', 'darwin'), patch.object(package, 'verify_macos_signature') as verify:
            with self.assertRaises(ValueError): self.run_package()
            verify.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_signature_failure_does_not_publish_a_catalog(self):
        with patch.object(sys, 'platform', 'darwin'), patch.object(package, 'verify_macos_signature', side_effect=subprocess.CalledProcessError(1, 'controlled signature failure')):
            with self.assertRaises(subprocess.CalledProcessError): self.run_package()
        self.assertFalse(self.output.exists())

    def test_incompatible_management_binary_cannot_publish_native_catalog(self):
        with patch.object(sys, 'platform', 'darwin'), patch.object(package, 'verify_macos_signature'), patch.object(package.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'unsupported')):
            with self.assertRaises(ValueError): self.run_package()
        self.assertFalse(self.output.exists())

    def test_entitlements_require_boolean_true_and_no_debug_access(self):
        for entitlements in [{}, {'com.apple.developer.endpoint-security.client': False},
                             {'com.apple.developer.endpoint-security.client': 'true'},
                             {'com.apple.developer.endpoint-security.client': True, 'com.apple.security.get-task-allow': True}]:
            with self.subTest(entitlements=entitlements), patch.object(package.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, plistlib.dumps(entitlements))):
                with self.assertRaises(ValueError): package.verify_macos_signature(self.native, True)
        good = {'com.apple.developer.endpoint-security.client': True}
        with patch.object(package.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, plistlib.dumps(good))) as run:
            package.verify_macos_signature(self.native, True)
            self.assertEqual(run.call_count, 3)
            self.assertEqual(run.call_args_list[1].args[0][:2], ['/usr/sbin/spctl', '--assess'])

    def test_development_catalog_without_native_component_remains_supported(self):
        self.argv = self.argv[:-3]
        self.run_package()
        report = json.loads((self.output / 'macos-aarch64.json').read_text())
        self.assertEqual(report['signing'], 'development-unsigned')
        self.assertNotIn('native_adapter', report)
        self.assertFalse((self.output / 'athernex-endpoint-native-macos-aarch64').exists())


if __name__ == '__main__':
    unittest.main()
