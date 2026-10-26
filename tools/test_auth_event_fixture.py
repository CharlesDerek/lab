"""Exercise private native-fixture output and owned-container cleanup boundaries."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('auth_fixture', Path(__file__).with_name('verify_auth_events.py'))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class AuthenticationFixtureTests(unittest.TestCase):
    def test_inside_refuses_host_or_missing_namespaces_before_any_mutation(self):
        required = ['/fixture','/run','/etc/pam.d','/etc/sudoers.d']
        for pid_one, interfaces, mounts in [
            ('systemd\n',[(1,'lo')],required),
            ('docker-init\n',[(1,'lo'),(2,'eth0')],required),
            ('docker-init\n',[(1,'lo')],required[:-1]),
        ]:
            def read(path, *args, **kwargs):
                if str(path) == '/proc/1/comm':
                    return pid_one
                if str(path) == '/proc/self/mountinfo':
                    return '\n'.join('1 0 0:1 / '+name+' rw - tmpfs tmpfs rw' for name in mounts)
                raise AssertionError('Unexpected pre-guard read')
            with patch.object(Path,'read_text',read), patch.object(FIXTURE.socket,'if_nameindex',return_value=interfaces), \
                 patch.object(Path,'mkdir') as mutation, patch.object(FIXTURE.subprocess,'run') as child:
                with self.assertRaisesRegex(RuntimeError,'^Private PID/network namespaces and fixture/PAM tmpfs mounts required$'):
                    FIXTURE.inside()
                mutation.assert_not_called()
                child.assert_not_called()

    def test_native_check_requires_exact_selected_execution_not_exit_zero(self):
        name = FIXTURE.TESTS[-1][1]
        listing = name+': test\n\n1 test, 0 benchmarks\n'
        good = 'running 1 test\ntest '+name+' ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.12s\n'
        cases = [
            (listing, good, 0, True),
            ('0 tests, 0 benchmarks\n', good, 0, False),
            ('other: test\n\n1 test, 0 benchmarks\n', good, 0, False),
            (listing, good.replace('running 1 test','running 0 tests').replace('1 passed','0 passed'), 0, False),
            (listing, good.replace('1 passed; 0 failed; 0 ignored','0 passed; 0 failed; 1 ignored'), 0, False),
            (listing, good.replace('1 passed; 0 failed','0 passed; 1 failed'), 0, False),
            (listing, good.replace('running 1 test','running 2 tests').replace('1 passed','2 passed'), 0, False),
            (listing, good+'test result: FAILED. 0 passed; 1 failed\n', 0, False),
            (listing, good, 7, False),
        ]
        for index, (listed, output, code, accepted) in enumerate(cases):
            with self.subTest(index=index):
                def child(command, **kwargs):
                    self.assertTrue(kwargs['capture_output'])
                    if '--list' in command:
                        self.assertEqual(command, ['/test/unit','--ignored','--exact',name,'--list'])
                        return subprocess.CompletedProcess(command,0,listed,'')
                    self.assertEqual(command, ['/test/unit','--ignored','--exact',name,'--nocapture'])
                    return subprocess.CompletedProcess(command,code,output,'private diagnostic')
                private = io.StringIO()
                with patch.object(FIXTURE.subprocess,'run',side_effect=child), contextlib.redirect_stdout(private):
                    if accepted:
                        FIXTURE.execute_native_check('/test/unit',name)
                    else:
                        with self.assertRaises(RuntimeError):
                            FIXTURE.execute_native_check('/test/unit',name)

    def run_boundary(self, failure=None, cleanup_failure=None, identifier='a'*64):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root/'private'
            cid = root/'container.cid'
            if identifier is not None:
                cid.write_text(identifier)
            calls = []

            def child(command, **kwargs):
                calls.append(command)
                self.assertIs(kwargs['stderr'], subprocess.STDOUT)
                self.assertTrue(kwargs['check'])
                kwargs['stdout'].write('private raw journal/account/certificate diagnostic\n')
                if len(calls) == 1:
                    self.assertEqual(kwargs['timeout'], 600)
                    if failure:
                        raise failure
                else:
                    self.assertEqual(command, ['docker','--host=unix:///var/run/docker.sock','rm','-f','a'*64])
                    self.assertEqual(kwargs['timeout'], 30)
                    if cleanup_failure:
                        raise cleanup_failure
                return subprocess.CompletedProcess(command, 0)

            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(FIXTURE.subprocess, 'run', side_effect=child), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                if failure or cleanup_failure or identifier != 'a'*64:
                    with self.assertRaisesRegex(RuntimeError, '^Native authentication fixture or owned-container cleanup failed$'):
                        FIXTURE.run_private_fixture(['docker','run'], cid, evidence)
                else:
                    FIXTURE.run_private_fixture(['docker','run'], cid, evidence)
            self.assertEqual(stdout.getvalue(), '')
            self.assertEqual(stderr.getvalue(), '')
            self.assertIn('private raw journal/account/certificate diagnostic', (evidence/'container.log').read_text())
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((evidence/'container.log').stat().st_mode), 0o600)
            return len(calls)

    def test_success_retains_private_output_and_requires_cleanup(self):
        self.assertEqual(self.run_boundary(), 2)

    def test_failure_timeout_and_launch_error_still_cleanup_without_public_output(self):
        for failure in [subprocess.CalledProcessError(7, ['private-command'], output='private-value'),
                        subprocess.TimeoutExpired(['private-command'], 600, output='private-value'),
                        OSError('private host detail')]:
            with self.subTest(kind=type(failure).__name__):
                self.assertEqual(self.run_boundary(failure=failure), 2)

    def test_cleanup_failure_cannot_promote_native_success(self):
        for failure in [subprocess.CalledProcessError(1, ['private-cleanup']),
                        subprocess.TimeoutExpired(['private-cleanup'], 30)]:
            with self.subTest(kind=type(failure).__name__):
                self.assertEqual(self.run_boundary(cleanup_failure=failure), 2)

    def test_invalid_container_identity_never_removes_unowned_container(self):
        for identifier in [None, '../other', 'A'*64, 'a'*64+'\nother', 'short']:
            with self.subTest(identifier=identifier):
                self.assertEqual(self.run_boundary(identifier=identifier), 1)

    def test_private_output_refuses_public_directory_symlink_or_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root/'private'
            private.mkdir(mode=0o755)
            with patch.object(FIXTURE.subprocess, 'run') as child:
                with self.assertRaises(RuntimeError):
                    FIXTURE.run_private_fixture([], root/'cid', private)
                private.chmod(0o700)
                alias = root/'alias'
                alias.symlink_to(private, target_is_directory=True)
                with self.assertRaises(RuntimeError):
                    FIXTURE.run_private_fixture([], root/'cid', alias)
                (private/'container.log').write_text('prior private evidence')
                with self.assertRaises(FileExistsError):
                    FIXTURE.run_private_fixture([], root/'cid', private)
                self.assertEqual((private/'container.log').read_text(), 'prior private evidence')
                child.assert_not_called()

    def test_default_main_is_isolated_and_only_fixed_results_are_public(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executables = {name: root/name for name in ('agent','unit','process')}
            for value in executables.values():
                value.write_bytes(b'fixture executable')
            manifest = root/'manifest.jsonl'
            manifest.write_text('\n'.join(json.dumps({'reason':'compiler-artifact','executable':str(executables[key]),
                'profile':{'test':True},'target':{'name':name}}) for key,name in [('unit','athernex_endpoint'),('process','authentication')]))
            captured = []
            def run(command, cid, evidence):
                captured.append(command)
                self.assertIsNone(evidence)
            output = io.StringIO()
            with patch('sys.argv', ['verify','--manifest',str(manifest),'--agent',str(executables['agent'])]), \
                 patch.object(FIXTURE.subprocess, 'run'), patch.object(FIXTURE, 'run_private_fixture', side_effect=run), \
                 patch.object(FIXTURE.shutil, 'disk_usage', return_value=type('Space',(),{'free':2**30})()), \
                 contextlib.redirect_stdout(output):
                FIXTURE.main()
            command = captured[0]
            for key, value in [('--network','none'),('--cap-drop','ALL'),('--log-driver','none'),('--security-opt','no-new-privileges')]:
                self.assertEqual(command[command.index(key)+1], value)
            self.assertIn('--read-only', command)
            self.assertIn('--init', command)
            self.assertNotIn('--privileged', command)
            self.assertNotIn('--rm', command)  # Explicit owned cleanup must be checked.
            mounts = [command[index+1] for index,item in enumerate(command) if item == '--mount']
            self.assertEqual(len(mounts), 4)
            self.assertTrue(all(value.startswith('type=bind,source=') and value.endswith(',readonly') and ',target=/test/' in value for value in mounts))
            tmpfs = [command[index+1].split(':')[0] for index,item in enumerate(command) if item == '--tmpfs']
            self.assertEqual(set(tmpfs), {'/run','/fixture','/tmp','/etc/pam.d','/etc/sudoers.d'})
            rows = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(set(rows[0]), {'validation_inputs','verifier_sha256'})
            self.assertEqual(set(rows[0]['validation_inputs']), {'agent','unit','process'})
            self.assertEqual(rows[1], {'native_authentication_checks': {name:'passed' for _,name in FIXTURE.TESTS}})
            self.assertEqual(len(FIXTURE.TESTS), 6)
            self.assertNotIn(str(root), output.getvalue())
            failed_output = io.StringIO()
            with patch('sys.argv', ['verify','--manifest',str(manifest),'--agent',str(executables['agent'])]), \
                 patch.object(FIXTURE.subprocess, 'run'), \
                 patch.object(FIXTURE, 'run_private_fixture', side_effect=RuntimeError('fixed fixture failure')), \
                 patch.object(FIXTURE.shutil, 'disk_usage', return_value=type('Space',(),{'free':2**30})()), \
                 contextlib.redirect_stdout(failed_output):
                with self.assertRaisesRegex(RuntimeError, '^fixed fixture failure$'):
                    FIXTURE.main()
            failed_rows = [json.loads(line) for line in failed_output.getvalue().splitlines()]
            self.assertEqual(len(failed_rows), 1)
            self.assertEqual(set(failed_rows[0]), {'validation_inputs','verifier_sha256'})


if __name__ == '__main__':
    unittest.main()
