#!/usr/bin/env python3
"""Ensure assertion-based verifiers cannot pass with Python checks removed."""
import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parent
MESSAGE = 'Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE'
# If a guard regresses, the child must still never touch a host policy, service,
# filesystem or socket. Preload imports, then deny audited operations before
# executing the actual generated helper source.
CHILD = '''import os, sys, pathlib, signal, socket, subprocess
source = sys.stdin.read()
code = compile(source, '<native fixture helper>', 'exec')
def deny_side_effect(event, arguments):
    if event == 'open' or event.startswith(('socket.', 'subprocess.', 'os.')):
        raise RuntimeError('Unexpected fixture side effect: ' + event)
sys.addaudithook(deny_side_effect)
exec(code, {'__name__': '__main__'})
'''


def verifiers():
    found = []
    for path in sorted(TOOLS.glob('verify_*.py')):
        tree = ast.parse(path.read_text())
        if any(isinstance(node, ast.Assert) or
               (isinstance(node, ast.Constant) and isinstance(node.value, str) and 'assert ' in node.value)
               for node in ast.walk(tree)):
            found.append(path)
    return found


def module(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class VerificationGuardTests(unittest.TestCase):
    def run_python(self, arguments, *, optimization=None, source=None):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        env.pop('PYTHONOPTIMIZE', None)
        if optimization is not None:
            env['PYTHONOPTIMIZE'] = optimization
        with tempfile.TemporaryDirectory(prefix='athernex-verifier-guard-') as temporary:
            result = subprocess.run([sys.executable, *map(str, arguments)], cwd=temporary,
                                    env=env, input=source, capture_output=True, text=True, timeout=15)
            self.assertEqual(list(Path(temporary).iterdir()), [], result.stderr)
            return result

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), MESSAGE)
        self.assertEqual(result.stdout, '')

    def test_cli_optimization_refused_before_argument_parsing_or_fixture_setup(self):
        paths = verifiers()
        self.assertGreaterEqual(len(paths), 16)
        for path in paths:
            for flag in ['-O', '-OO']:
                with self.subTest(path=path.name, flag=flag):
                    self.assert_refused(self.run_python([flag, path, '--help']))

    def test_environment_optimization_is_also_refused(self):
        for path in verifiers():
            for value in ['1', '2']:
                with self.subTest(path=path.name, value=value):
                    self.assert_refused(self.run_python([path, '--help'], optimization=value))

    @unittest.skipUnless(sys.platform == 'linux', 'Some native verifier imports require Unix')
    def test_normal_import_still_works_without_starting_a_fixture(self):
        # A few legacy verifiers have no argument parser and ignore --help.
        # Load their entry points without executing main or native workloads.
        source = "import pathlib,runpy,sys; sys.path.insert(0,str(pathlib.Path(sys.argv[1]).parent)); scope=runpy.run_path(sys.argv[1]); print('loaded' if callable(scope.get('main')) else 'missing entry point')"
        for path in verifiers():
            with self.subTest(path=path.name):
                result = self.run_python(['-c', source, path])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), 'loaded')

    def test_generated_children_refuse_optimization_before_any_host_operations(self):
        sources = []
        for name in ['verify_auth_events', 'verify_native_adapter']:
            tree = ast.parse((TOOLS/(name+'.py')).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and 'assert ' in node.value:
                    sources.append((name+':'+str(node.lineno), node.value))
        sources.extend([
            ('network', module('verify_network_events').fixture_script('fixture-test', 1)),
            ('process', module('verify_process_events').fixture_script()),
        ])
        self.assertEqual(len(sources), 8)
        for name, source in sources:
            for arguments, environment in [(['-O', '-c', CHILD], None), (['-c', CHILD], '2')]:
                with self.subTest(helper=name, flags=arguments[:1], environment=environment):
                    self.assert_refused(self.run_python(arguments, optimization=environment, source=source))

    def test_process_child_requires_every_named_native_test_before_execution(self):
        verifier = module('verify_process_events')
        source = verifier.fixture_script()

        def run(command, **kwargs):
            if '--list' in command:
                kind = Path(command[0]).name
                listing = '\n'.join(name+': test' for key, name in verifier.TESTS if key == kind)
                return subprocess.CompletedProcess(command, 0, stdout=listing)
            return subprocess.CompletedProcess(command, 0)

        with mock.patch('subprocess.run', side_effect=run) as called:
            exec(compile(source, '<process helper>', 'exec'), {})
        executed = [call.args[0] for call in called.call_args_list if '--exact' in call.args[0]]
        self.assertEqual(len(executed), len(verifier.TESTS))
        self.assertEqual([c[3] for c in executed], [name for _, name in verifier.TESTS])
        with mock.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='')) as called:
            with self.assertRaisesRegex(AssertionError, 'Required native test is absent'):
                exec(compile(source, '<process helper>', 'exec'), {})
        self.assertFalse(any('--exact' in call.args[0] for call in called.call_args_list))

    def test_network_child_rejects_host_namespace_before_native_test_execution(self):
        source = module('verify_network_events').fixture_script('fixture-test', 120)
        with mock.patch('pathlib.Path.read_text', return_value='host-init'), mock.patch('subprocess.run') as called:
            with self.assertRaises(AssertionError):
                exec(compile(source, '<network helper>', 'exec'), {})
        called.assert_not_called()


if __name__ == '__main__':
    unittest.main()
