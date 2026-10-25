#!/usr/bin/env python3
"""Check runtime-bundle isolation and symlink materialization without an engine."""
from pathlib import Path
import os
import tempfile
import unittest
from package_engine import assemble


class EngineBundle(unittest.TestCase):
    def link(self, destination, target):
        try:
            destination.symlink_to(target)
        except OSError as error:
            if os.name == 'nt' and getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows symlink privilege is unavailable')
            raise

    def fixture(self, base):
        prefix = base/'vendor'; prefix.mkdir()
        for name in ['bin/clamscan', 'bin/freshclam', 'sbin/clamd', 'sbin/clamonacc', 'lib/libclamav.so.12', 'lib/static.a', 'etc/certs/clamav.crt']:
            path = prefix/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(('public '+name).encode())
        return prefix

    def test_materializes_only_runtime_inputs_and_retains_independent_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); prefix = self.fixture(base)
            self.link(prefix/'lib/libclamav.so', 'libclamav.so.12')
            output = base/'bundle'; roles = assemble(prefix, output, 'linux-x86_64')
            self.assertEqual(roles['library_dirs'], ['lib'])
            self.assertEqual(roles['certificates'], 'etc/certs')
            self.assertFalse((output/'content/lib/static.a').exists())
            alias = output/'content/lib/libclamav.so'
            self.assertFalse(alias.is_symlink())
            original = alias.read_bytes(); (prefix/'lib/libclamav.so.12').write_bytes(b'changed source')
            self.assertEqual(alias.read_bytes(), original)
            with self.assertRaises(FileExistsError):
                assemble(prefix, output, 'linux-x86_64')

    def test_external_links_and_output_inside_source_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); prefix = self.fixture(base)
            outside = base/'outside'; outside.write_bytes(b'never include')
            self.link(prefix/'lib/foreign.so', outside)
            with self.assertRaisesRegex(ValueError, 'leaves the verified prefix'):
                assemble(prefix, base/'bundle', 'linux-x86_64')
            self.assertFalse((base/'bundle/manifest.json').exists())
            with self.assertRaisesRegex(ValueError, 'separate'):
                assemble(prefix, prefix/'nested-output', 'linux-x86_64')
            self.assertEqual(outside.read_bytes(), b'never include')

    @unittest.skipIf(os.name == 'nt', 'Unix directory-symlink fixture')
    def test_certificate_directory_links_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); prefix = self.fixture(base)
            (prefix/'etc/certs').rename(prefix/'certificates')
            (prefix/'etc/certs').symlink_to('../certificates', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'directories cannot be symlinks'):
                assemble(prefix, base/'bundle', 'linux-x86_64')

    def test_windows_flat_runtime_roles_exclude_unneeded_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); prefix = base/'vendor'; prefix.mkdir()
            for relative in ['clamscan.exe', 'freshclam.exe', 'clamd.exe', 'libclamav.dll', 'test.exe', 'certs/vendor.crt']:
                path = prefix/relative; path.parent.mkdir(exist_ok=True); path.write_bytes(b'public test bytes')
            roles = assemble(prefix, base/'bundle', 'windows-x86_64')
            self.assertIsNone(roles['monitor'])
            self.assertEqual(roles['library_dirs'], [])
            self.assertEqual(roles['scanner'], 'clamscan.exe')
            self.assertTrue((base/'bundle/content/libclamav.dll').is_file())
            self.assertFalse((base/'bundle/content/test.exe').exists())


if __name__ == '__main__':
    unittest.main()
