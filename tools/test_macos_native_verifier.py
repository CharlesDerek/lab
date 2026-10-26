"""Privacy controls only: no Mac authorization, scanner, service or account setup."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('mac_verifier', Path(__file__).with_name('verify_macos_native.py'))
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
SECRET = 'PRIVATE-NATIVE-SENTINEL /private/operator/actual-source'


@contextlib.contextmanager
def private_directory():
    # macOS may advertise /var/folders through the /var symlink. Production
    # deliberately refuses symlink ancestry, so pass its actual private path.
    with tempfile.TemporaryDirectory() as directory:
        yield str(Path(directory).resolve())


def complete_report():
    return dict(schema=1, native_authorization_exercised=True, production_readiness=False,
                checks={name: 'passed' for name in verifier.CHECKS},
                evidence=[dict(private_actor=SECRET)])


class MacVerifierPrivacyTests(unittest.TestCase):
    def run_cli(self, report, effect):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(verifier.sys, 'platform', 'darwin'), \
             mock.patch.object(verifier.os, 'geteuid', return_value=os.geteuid()), \
             mock.patch.object(verifier, 'verify', side_effect=effect), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            # Permit portable tests without pretending to exercise the root-only
            # native entrypoint; the root check itself has a separate refusal test.
            with mock.patch.object(verifier, 'native_host_allowed', return_value=True):
                code = verifier.main(['--adapter', SECRET, '--agent', SECRET, '--report', str(report)])
        self.assertNotIn(SECRET, out.getvalue() + err.getvalue())
        self.assertNotIn(str(report), out.getvalue() + err.getvalue())
        return code, out.getvalue(), err.getvalue()

    def test_success_exports_only_closed_summary_and_retains_private_originals(self):
        with private_directory() as temp:
            path = Path(temp) / 'result.json'
            def body(_):
                print(SECRET); print(SECRET, file=sys.stderr)
                return complete_report()
            code, out, err = self.run_cli(path, body)
            self.assertEqual((code, err), (0, ''))
            value = json.loads(out)
            self.assertEqual(set(value), {'schema', 'suite', 'status', 'production_readiness', 'checks'})
            self.assertEqual(value['checks'], complete_report()['checks'])
            self.assertIn(SECRET, path.read_text())
            logs = list(Path(temp).glob('*.diagnostics-*'))
            self.assertEqual(len(logs), 1)
            self.assertIn(SECRET, logs[0].read_text())
            for private in [path, *logs]:
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
                self.assertEqual(private.stat().st_nlink, 1)

    def test_exception_timeout_parse_and_cleanup_failures_never_publish_success(self):
        errors = [AssertionError(SECRET), OSError(SECRET),
                  subprocess.CalledProcessError(3, [SECRET], output=SECRET, stderr=SECRET),
                  subprocess.TimeoutExpired([SECRET], 1, output=SECRET, stderr=SECRET),
                  json.JSONDecodeError(SECRET, SECRET, 0), KeyboardInterrupt(SECRET)]
        for error in errors:
            with self.subTest(kind=type(error).__name__), private_directory() as temp:
                path = Path(temp) / 'result.json'
                def body(_):
                    print(SECRET)
                    try:
                        return complete_report()
                    finally:
                        raise error  # An otherwise passing body cannot defeat cleanup failure.
                code, out, err = self.run_cli(path, body)
                self.assertEqual((code, out, err), (1, '', verifier.FAILURE + '\n'))
                self.assertFalse(path.exists())
                self.assertIn(SECRET, next(Path(temp).glob('*.diagnostics-*')).read_text())

    def test_missing_extra_failed_or_invalid_report_cannot_pass(self):
        cases = []
        for change in ('missing', 'extra', 'failed', 'native', 'readiness', 'schema'):
            report = complete_report()
            if change == 'missing': report['checks'].pop(next(iter(report['checks'])))
            elif change == 'extra': report['checks'][SECRET] = 'passed'
            elif change == 'failed': report['checks'][next(iter(report['checks']))] = 'failed'
            elif change == 'native': report['native_authorization_exercised'] = False
            elif change == 'readiness': report['production_readiness'] = True
            else: report['schema'] = True
            cases.append(report)
        for report in cases:
            with private_directory() as temp:
                path = Path(temp) / 'result.json'
                code, out, err = self.run_cli(path, lambda _: report)
                self.assertEqual((code, out, err), (1, '', verifier.FAILURE + '\n'))
                self.assertFalse(path.exists())

    def test_existing_destinations_links_fifo_and_public_parent_refuse_without_changes(self):
        for kind in ('file', 'symlink', 'hardlink', 'fifo', 'directory', 'public_parent'):
            with self.subTest(kind=kind), private_directory() as temp:
                base = Path(temp); victim = base / 'victim'; victim.write_text(SECRET)
                report = base / 'report.json'
                if kind == 'file': report.write_text(SECRET)
                elif kind == 'symlink': report.symlink_to(victim)
                elif kind == 'hardlink': os.link(victim, report)
                elif kind == 'fifo': os.mkfifo(report, 0o600)
                elif kind == 'directory': report.mkdir()
                else: base.chmod(0o755)
                with mock.patch.object(verifier, 'verify') as body:
                    code, out, err = self.run_cli(report, body)
                    body.assert_not_called()
                self.assertEqual((code, out, err), (1, '', verifier.FAILURE + '\n'))
                self.assertEqual(victim.read_text(), SECRET)
                if kind == 'file': self.assertEqual(report.read_text(), SECRET)
                if kind == 'public_parent': self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o755)

    def test_held_parent_identity_and_exclusive_publication_survive_conflicts(self):
        with private_directory() as temp:
            base = Path(temp); parent = base / 'parent'; parent.mkdir(mode=0o700)
            output = verifier.PrivateOutput(parent / 'report.json')
            try:
                parent.rename(base / 'original'); parent.mkdir(mode=0o700)
                with self.assertRaises(ValueError): output.publish(complete_report())
                self.assertFalse((parent / 'report.json').exists())
                self.assertFalse((base / 'original/report.json').exists())
            finally: output.close()
            output = verifier.PrivateOutput(parent / 'report.json')
            try:
                (parent / 'report.json').write_text(SECRET)
                with self.assertRaises(FileExistsError): output.publish(complete_report())
                self.assertEqual((parent / 'report.json').read_text(), SECRET)
            finally: output.close()

    def test_symlink_writable_and_foreign_ancestry_refuse_without_adoption(self):
        for kind in ('symlink', 'writable', 'foreign'):
            with self.subTest(kind=kind), private_directory() as temp, contextlib.ExitStack() as patches:
                base = Path(temp); ancestor = base / 'ancestor'; ancestor.mkdir(mode=0o700)
                parent = ancestor / 'private'; parent.mkdir(mode=0o700)
                report = parent / 'report.json'
                if kind == 'symlink':
                    alias = base / 'alias'; alias.symlink_to(ancestor, target_is_directory=True)
                    report = alias / 'private/report.json'
                elif kind == 'writable':
                    ancestor.chmod(0o777)
                else:
                    identity = ancestor.stat(); original = verifier.os.fstat
                    def foreign(fd):
                        actual = original(fd)
                        if (actual.st_dev, actual.st_ino) == (identity.st_dev, identity.st_ino):
                            fields = list(actual); fields[4] = os.geteuid() + 10001
                            return os.stat_result(fields)
                        return actual
                    patches.enter_context(mock.patch.object(verifier.os, 'fstat', side_effect=foreign))
                with mock.patch.object(verifier, 'verify') as body:
                    code, out, err = self.run_cli(report, body)
                    body.assert_not_called()
                self.assertEqual((code, out, err), (1, '', verifier.FAILURE + '\n'))
                self.assertEqual(list(parent.iterdir()), [])
                self.assertEqual(stat.S_IMODE(ancestor.stat().st_mode), 0o777 if kind == 'writable' else 0o700)

    def test_private_file_modes_at_creation_independent_of_umask(self):
        # Umask is changed only in a fresh ordinary Python child, never this runner.
        source = '''import importlib.util,os,stat,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('v',sys.argv[1]);v=importlib.util.module_from_spec(s);s.loader.exec_module(v)
os.umask(int(sys.argv[3]));root=Path(sys.argv[2]);p=root/'service.log'
with v.private_file(p) as f:
 assert stat.S_IMODE(os.fstat(f.fileno()).st_mode)==0o600
 f.write('private')
v.write_json(root/'plan.json',{'private':'value'})
assert stat.S_IMODE((root/'plan.json').stat().st_mode)==0o600
o=v.PrivateOutput(root/'report.json')
try:
 assert stat.S_IMODE(os.fstat(o.log.fileno()).st_mode)==0o600
 o.publish({'private':'report'})
 assert stat.S_IMODE((root/'report.json').stat().st_mode)==0o600
finally:o.close()
'''
        for mask in (0, 0o777):
            with self.subTest(mask=mask), private_directory() as temp:
                result = subprocess.run([sys.executable, '-c', source, verifier.__file__, temp, str(mask)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, 'Private mode control failed')
                self.assertEqual((result.stdout, result.stderr), ('', ''))

    def test_default_output_and_help_do_not_disclose_dynamic_paths(self):
        with private_directory() as temp, mock.patch.object(verifier, 'OUTPUT_BASE', Path(temp)), \
             mock.patch.object(verifier, 'native_host_allowed', return_value=True), \
             mock.patch.object(verifier, 'verify', return_value=complete_report()):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = verifier.main(['--adapter', SECRET, '--agent', SECRET])
                with self.assertRaises(SystemExit) as stopped:
                    verifier.main(['--help'])
            self.assertEqual((code, stopped.exception.code, err.getvalue()), (0, 0, ''))
            self.assertNotIn(temp, out.getvalue()); self.assertNotIn(SECRET, out.getvalue())
            self.assertNotIn(str(Path(verifier.__file__).parent), out.getvalue())
            directories = list(Path(temp).iterdir())
            self.assertEqual(len(directories), 1)
            self.assertTrue(directories[0].name.startswith('athernex-macos-validation-'))
            self.assertEqual(stat.S_IMODE(directories[0].stat().st_mode), 0o700)
            for private in directories[0].iterdir():
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)

    def test_real_closed_public_streams_refuse_without_shutdown_tracebacks(self):
        source = '''import importlib.util,json,os,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('v',sys.argv[1]);v=importlib.util.module_from_spec(s);s.loader.exec_module(v)
v.native_host_allowed=lambda:True
v.verify=lambda args:dict(schema=1,native_authorization_exercised=True,production_readiness=False,checks={k:'passed' for k in v.CHECKS})
mode=sys.argv[3]
if mode=='closed_stderr':sys.stderr.close()
if mode=='closed_stderr_fd':os.close(2)
sys.stdin.readline()
if mode=='help':v.main(['--help'])
elif mode.startswith('closed_stderr'):v.main(['--unknown',sys.argv[4]])
else:raise SystemExit(v.main(['--adapter',sys.argv[4],'--agent',sys.argv[4],'--report',sys.argv[2]]))
'''
        for mode in ('success', 'help', 'closed_stderr', 'closed_stderr_fd'):
            with self.subTest(mode=mode), private_directory() as temp:
                process = subprocess.Popen([sys.executable, '-c', source, verifier.__file__,
                                            str(Path(temp) / 'report.json'), mode, SECRET],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                streams = (process.stdin, process.stdout, process.stderr)
                try:
                    # Explicit handshake: the reader is gone before a final
                    # summary or argparse help can write, without a timing race.
                    if mode in ('success', 'help'):
                        process.stdout.close()
                        process.stdout = None
                    process.stdin.write('go\n'); process.stdin.flush(); process.stdin.close()
                    process.stdin = None
                    stdout, stderr = process.communicate(timeout=10)
                    self.assertNotEqual(process.returncode, 0)
                    self.assertEqual((stdout or '', stderr), ('', ''))
                finally:
                    if process.poll() is None:
                        process.kill(); process.wait(timeout=5)
                    for stream in streams: stream.close()

    def test_capture_report_and_private_storage_failures_cannot_pass(self):
        def oversized(_):
            verifier.invoke([sys.executable, '-c', 'import sys;sys.stdout.write("x"*1048577)'])
            return complete_report()
        for kind in ('capture', 'report', 'sync', 'close'):
            with self.subTest(kind=kind), private_directory() as temp, contextlib.ExitStack() as patches:
                effect = oversized if kind == 'capture' else lambda _: complete_report()
                if kind == 'report': patches.enter_context(mock.patch.object(verifier, 'MAX_REPORT', 8))
                elif kind == 'sync': patches.enter_context(mock.patch.object(verifier.os, 'fsync', side_effect=OSError(SECRET)))
                elif kind == 'close':
                    original = verifier.PrivateOutput.close
                    def close(output):
                        original(output)
                        raise OSError(SECRET)
                    patches.enter_context(mock.patch.object(verifier.PrivateOutput, 'close', close))
                code, out, err = self.run_cli(Path(temp) / 'report.json', effect)
                self.assertEqual((code, out, err), (1, '', verifier.FAILURE + '\n'))

    def test_real_child_capture_and_diagnostic_failure_remain_private(self):
        with private_directory() as temp:
            path = Path(temp) / 'report.json'
            def body(_):
                verifier.invoke([sys.executable, '-c', 'import sys;print(sys.argv[1]);print(sys.argv[1],file=sys.stderr);sys.exit(4)', SECRET])
            code, out, err = self.run_cli(path, body)
            self.assertEqual((code, out, err), (1, '', verifier.FAILURE + '\n'))
            self.assertIn(SECRET, next(Path(temp).glob('*.diagnostics-*')).read_text())
        with private_directory() as temp, mock.patch.object(verifier, 'MAX_DIAGNOSTICS', 8):
            code, out, err = self.run_cli(Path(temp) / 'report.json', lambda _: print(SECRET))
            self.assertEqual((code, out, err), (1, '', verifier.FAILURE + '\n'))

    def test_argument_and_host_refusal_precede_private_or_native_mutation(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
             mock.patch.object(verifier, 'PrivateOutput') as output, \
             mock.patch.object(verifier, 'verify') as body:
            with self.assertRaises(SystemExit): verifier.main(['--unknown', SECRET])
            with mock.patch.object(verifier, 'native_host_allowed', return_value=False):
                with self.assertRaises(SystemExit): verifier.main(['--adapter', SECRET, '--agent', SECRET])
            output.assert_not_called(); body.assert_not_called()
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn(SECRET, err.getvalue())
        self.assertEqual(err.getvalue(), 'Native macOS validation arguments refused.\n' * 2)


if __name__ == '__main__': unittest.main()
