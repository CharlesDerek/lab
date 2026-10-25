#!/usr/bin/env python3
"""Exercise native network runner output privacy without Docker or host changes."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'verify_network_events', Path(__file__).with_name('verify_network_events.py'))
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
CANARY = 'synthetic-private-native-output'
PREFIX = 'ATHERNEX_NETWORK_SOAK_REPORT='


@unittest.skipUnless(sys.platform == 'linux', 'Native network fixture requires Linux permissions')
class NetworkOutputPrivacyTests(unittest.TestCase):
    def capture(self, source, *, timeout=5):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = io.StringIO()
            error = None
            reports = None
            with contextlib.redirect_stdout(public), contextlib.redirect_stderr(public):
                try:
                    reports = VERIFIER.run_fixture(
                        [sys.executable, '-c', source], timeout, root)
                except RuntimeError as failure:
                    error = failure
            logs = list(root.glob('native-*.log'))
            self.assertEqual(len(logs), 1)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(logs[0].stat().st_mode), 0o600)
            self.assertIn(CANARY, logs[0].read_text())
            self.assertEqual(public.getvalue(), '')
            self.assertNotIn(CANARY, str(error))
            return reports, error

    def test_success_retains_native_stdout_and_stderr_only_in_private_file(self):
        measurement = {'passed': True, 'complete_flows': 3}
        reports, error = self.capture(
            f'import sys; print({CANARY!r}); print({CANARY!r}, file=sys.stderr); '
            f'print({(PREFIX + json.dumps(measurement))!r})')
        self.assertIsNone(error)
        self.assertEqual(reports, [measurement])

    def test_failed_child_cannot_pass_with_a_success_report_or_expose_command(self):
        reports, error = self.capture(
            f'import sys; print({CANARY!r}); print({(PREFIX + json.dumps(dict(passed=True)))!r}); sys.exit(7)')
        self.assertIsNone(reports)
        self.assertEqual(str(error), 'Native network fixture failed; diagnostics retained privately')
        self.assertTrue(error.__suppress_context__)

    def test_timeout_retains_output_without_exposing_command(self):
        reports, error = self.capture(
            f'import time; print({CANARY!r}, flush=True); time.sleep(10)', timeout=0.2)
        self.assertIsNone(reports)
        self.assertEqual(str(error), 'Native network fixture failed; diagnostics retained privately')
        self.assertTrue(error.__suppress_context__)

    def test_malformed_report_is_refused_without_printing_its_contents(self):
        reports, error = self.capture(f'print({(PREFIX + CANARY)!r})')
        self.assertIsNone(reports)
        self.assertEqual(str(error), 'Native network fixture produced an invalid measured report')

    def run_main(self, reports, *, exit_code=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ['agent', 'unit']:
                (root/name).write_bytes(b'synthetic fixture executable')
            manifest = root/'manifest.jsonl'
            manifest.write_text(json.dumps({
                'reason': 'compiler-artifact', 'executable': str(root/'unit'),
                'target': {'name': 'athernex_endpoint'}, 'profile': {'test': True, 'opt_level': '3'},
            })+'\n')
            report = root/'network-load.json'

            def run(command, **kwargs):
                if command[:4] == VERIFIER.DOCKER + ['image', 'inspect']:
                    return subprocess.CompletedProcess(command, 0, stdout='sha256:'+'1'*64)
                if '--list' in command:
                    return subprocess.CompletedProcess(command, 0, stdout=VERIFIER.SOAK+': test\n')
                if command[:3] == VERIFIER.DOCKER + ['run']:
                    output = kwargs['stdout']
                    output.write(CANARY+'\n')
                    for measurement in reports:
                        output.write(PREFIX+json.dumps(measurement)+'\n')
                    output.flush()
                    if exit_code:
                        raise subprocess.CalledProcessError(exit_code, command)
                return subprocess.CompletedProcess(command, 0)

            public = io.StringIO()
            error = None
            arguments = ['verify_network_events.py', '--manifest', str(manifest),
                         '--agent', str(root/'agent'), '--soak-seconds', '60', '--report', str(report)]
            with mock.patch.object(sys, 'argv', arguments), \
                    mock.patch.object(tempfile, 'tempdir', str(root)), \
                    mock.patch.object(VERIFIER.subprocess, 'run', side_effect=run), \
                    contextlib.redirect_stdout(public), contextlib.redirect_stderr(public):
                try:
                    VERIFIER.main()
                except RuntimeError as failure:
                    error = failure
            directories = list(root.glob('athernex-network-diagnostics-*'))
            self.assertEqual(len(directories), 1)
            self.assertEqual(stat.S_IMODE(directories[0].stat().st_mode), 0o700)
            private_inputs = next(directories[0].glob('inputs-*.json'))
            self.assertEqual(stat.S_IMODE(private_inputs.stat().st_mode), 0o600)
            self.assertEqual(set(json.loads(private_inputs.read_text())['validation_inputs']), {'agent', 'unit'})
            self.assertIn(CANARY, next(directories[0].glob('*.log')).read_text())
            self.assertNotIn(CANARY, public.getvalue())
            self.assertNotIn(str(directories[0]), public.getvalue())
            saved = json.loads(report.read_text()) if report.exists() else None
            if saved is not None:
                self.assertNotIn(CANARY, report.read_text())
                self.assertNotIn(str(directories[0]), report.read_text())
            return public.getvalue(), saved, error

    def test_public_summary_and_measurement_artifact_exclude_captured_diagnostics(self):
        measurement = {'passed': True, 'complete_flows': 3}
        public, saved, error = self.run_main([measurement])
        self.assertIsNone(error)
        self.assertEqual(saved['measurement'], measurement)
        self.assertEqual(set(saved['inputs']['validation_inputs']), {'agent', 'unit'})
        self.assertEqual(public.splitlines(), ['Native network validation: 1 tests',
                                             'Native network test 1/1: passed',
                                             'Native network validation passed: 1 tests'])

    def test_missing_duplicate_or_failed_measurement_cannot_create_success_artifact(self):
        for reports in [[], [{'passed': True}, {'passed': True}], [{'passed': False}]]:
            with self.subTest(reports=reports):
                public, saved, error = self.run_main(reports)
                self.assertIsNotNone(error)
                self.assertIsNone(saved)
                self.assertIn('Native network test 1/1: failed', public)
                self.assertNotIn(': passed', public)
                self.assertNotIn('validation passed', public)

    def test_native_exit_failure_cannot_create_success_artifact(self):
        public, saved, error = self.run_main([{'passed': True}], exit_code=7)
        self.assertIsNotNone(error)
        self.assertIsNone(saved)
        self.assertIn('Native network test 1/1: failed', public)
        self.assertNotIn(': passed', public)


if __name__ == '__main__':
    unittest.main()
