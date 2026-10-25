"""Resource preflight failures must not start tools or copy test binaries."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import verify_engine_update as fixture


class ResourcePreflight(unittest.TestCase):
    def refused(self, free, available_kib, message):
        error = io.StringIO()
        with patch('sys.argv', ['verify_engine_update.py', '--engine-prefix', '/unused']), \
                patch.object(fixture.shutil, 'disk_usage', side_effect=free), \
                patch.object(Path, 'exists', return_value=True), \
                patch.object(Path, 'read_text', return_value=f'MemAvailable: {available_kib} kB\n'), \
                patch.object(fixture.shutil, 'copy2') as copy, \
                patch.object(fixture.subprocess, 'run') as run, \
                contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as result:
            fixture.main()
        self.assertEqual(result.exception.code, 2)
        self.assertIn(message, error.getvalue())
        copy.assert_not_called()
        run.assert_not_called()

    def test_low_host_space(self):
        self.refused(lambda _path: SimpleNamespace(free=1024**3), 8 * 1024**2,
                     'At least 2 GiB host free space')

    def test_low_docker_space(self):
        self.refused(lambda path: SimpleNamespace(free=1024**3 if str(path) == '/var/lib/docker' else 8 * 1024**3),
                     8 * 1024**2, 'At least 2 GiB host free space')

    def test_low_temporary_space(self):
        self.refused(lambda path: SimpleNamespace(free=128 * 1024**2 if isinstance(path, str) else 8 * 1024**3),
                     8 * 1024**2, 'Temporary directory needs 256 MiB free')

    def test_low_available_memory(self):
        self.refused(lambda _path: SimpleNamespace(free=8 * 1024**3), 2 * 1024**2,
                     'At least 4 GiB available host memory')


if __name__ == '__main__':
    unittest.main()
