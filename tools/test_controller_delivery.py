"""Owned status-read retries cannot replace controller readiness evidence."""
import contextlib
import errno
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parent
with mock.patch.object(sys, 'path', [str(TOOLS), *sys.path]):
    SPEC = importlib.util.spec_from_file_location('controller_delivery_fixture', TOOLS/'verify_controller_delivery.py')
    FIXTURE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(FIXTURE)
    import verify_endpoint_update as UPDATE


class ControllerReadinessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        (self.state/'supervisor').mkdir()
        self.documents = {
            'ready.json': dict(token='fixture-token', pid=17, time_ms=200),
            'lease.json': dict(token='fixture-token', child_pid=17, controller_pid=23),
            'launcher.json': dict(controller_pid=23, started_ms=100),
        }
        self.write_documents()
        self.launcher = SimpleNamespace(poll=lambda: None)
        self.log = self.state/'launcher.log'
        self.log.write_text('Controlled launcher fixture')
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(FIXTURE, 'os', SimpleNamespace(name='nt')).start()
        self.alive = mock.patch.object(FIXTURE, 'alive', return_value=True).start()

    def write_documents(self):
        for name, document in self.documents.items():
            (self.state/'supervisor'/name).write_text(json.dumps(document))

    def healthy(self):
        return FIXTURE.launcher_healthy(self.launcher, self.state, self.log)

    @contextlib.contextmanager
    def read_error(self, name, error, once=False):
        original = Path.read_text
        calls = []

        def read(path, *args, **kwargs):
            if path == self.state/'supervisor'/name and (not once or not calls):
                calls.append(path)
                raise error
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, 'read_text', read):
            yield calls

    @contextlib.contextmanager
    def clock(self):
        elapsed = [0.0]

        def sleep(seconds):
            elapsed[0] += seconds

        with mock.patch.object(UPDATE, 'time', SimpleNamespace(
                monotonic=lambda: elapsed[0], sleep=sleep)):
            yield elapsed

    def test_each_owned_snapshot_can_retry_then_requires_complete_valid_health(self):
        for name in self.documents:
            with self.subTest(snapshot=name), self.clock() as elapsed, self.read_error(
                    name, PermissionError(errno.EACCES, 'Controlled denial'), once=True) as calls:
                self.assertTrue(FIXTURE.eventually(self.healthy, 45))
                self.assertEqual(len(calls), 1)
                self.assertEqual(elapsed[0], .05)

    def test_persistent_denial_fails_existing_deadline_without_health_success(self):
        with self.clock() as elapsed, self.read_error(
                'launcher.json', PermissionError(errno.EACCES, 'Controlled denial')):
            with self.assertRaisesRegex(AssertionError, 'condition did not become true'):
                FIXTURE.eventually(self.healthy, 45)
        self.assertGreaterEqual(elapsed[0], 45)
        self.assertLess(elapsed[0], 45.051)
        self.alive.assert_not_called()

    def test_only_known_windows_read_error_forms_are_retryable(self):
        for code in (5, 32, 33):
            error = OSError(errno.EACCES, 'Controlled native denial')
            error.winerror = code
            with self.subTest(code=code), self.read_error('launcher.json', error):
                self.assertFalse(self.healthy())
        errors = [OSError(errno.EIO, 'Controlled I/O failure'),
                  PermissionError(errno.EPERM, 'Controlled refusal'),
                  FileNotFoundError(errno.ENOENT, 'Controlled missing launcher')]
        unknown_native = PermissionError(errno.EACCES, 'Controlled unrelated native code')
        unknown_native.winerror = 87
        errors.append(unknown_native)
        for error in errors:
            with self.subTest(error=type(error).__name__, code=error.errno), self.read_error('launcher.json', error):
                with self.assertRaises(OSError) as raised:
                    self.healthy()
                self.assertIs(raised.exception, error)
        with mock.patch.object(FIXTURE, 'os', SimpleNamespace(name='posix')), self.read_error(
                'launcher.json', PermissionError(errno.EACCES, 'Controlled denial')):
            with self.assertRaises(PermissionError):
                self.healthy()

    def test_malformed_or_missing_readiness_facts_fail_immediately(self):
        for name in self.documents:
            with self.subTest(snapshot=name):
                (self.state/'supervisor'/name).write_text('{')
                with self.assertRaises(json.JSONDecodeError):
                    self.healthy()
                (self.state/'supervisor'/name).write_text('{}')
                with self.assertRaises(KeyError):
                    self.healthy()
                self.write_documents()

    def test_every_original_identity_and_freshness_predicate_remains_required(self):
        mutations = [('ready.json', 'token', 'different'),
                     ('ready.json', 'pid', 18),
                     ('launcher.json', 'controller_pid', 24),
                     ('ready.json', 'time_ms', 99)]
        for name, field, value in mutations:
            with self.subTest(snapshot=name, field=field):
                original = self.documents[name][field]
                self.documents[name][field] = value
                self.write_documents()
                self.assertFalse(self.healthy())
                self.documents[name][field] = original
                self.write_documents()
        self.alive.return_value = False
        self.assertFalse(self.healthy())

    def test_later_read_contention_cannot_conceal_earlier_malformed_json(self):
        for name in ('ready.json', 'lease.json'):
            with self.subTest(snapshot=name), self.read_error(
                    'launcher.json', PermissionError(errno.EACCES, 'Controlled denial')) as calls:
                (self.state/'supervisor'/name).write_text('{')
                with self.assertRaises(json.JSONDecodeError):
                    self.healthy()
                self.assertEqual(calls, [])
                self.write_documents()

    def test_exited_launcher_fails_before_any_status_read_retry(self):
        self.launcher.poll = lambda: 7
        with self.read_error('launcher.json', PermissionError(errno.EACCES, 'Controlled denial')) as calls:
            with self.assertRaisesRegex(AssertionError, 'Launcher exited before health'):
                self.healthy()
            self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
