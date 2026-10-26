import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import package_windows_filter as package
import package_endpoint as endpoint


class DriverPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / 'input'
        self.input.mkdir()
        self.approval = self.root / 'approval.json'
        parts = [b'fixture sys', b'fixture inf', b'fixture cat']
        self.parts = parts
        self.blob = b'AXFPKG1\0' + struct.pack('<QQQ', *(len(b) for b in parts)) + b''.join(parts)
        self.d = dict(schema=1, sha256=package.digest(self.blob), bytes=len(self.blob),
            profile='win11-24h2-amd64-antivirus-v1', trust_policy='whql-driver-policy-cache-only-v1',
            source_revision='a'*40, expected_abi=2, driver_version='1.2.3.4', driver_date='01/01/2025', altitude='325000.01')
        for name, key, content in zip(package.NAMES, ('sys', 'inf', 'cat'), parts):
            (self.input / name).write_bytes(content)
            self.d[key] = dict(bytes=len(content), sha256=package.digest(content))
        self.approval.write_text(json.dumps(self.d))

    def snapshot(self):
        return package.snapshot(self.input, self.approval, self.root / 'snapshot')

    def test_windows_snapshot_acl_runtime_gate_is_explicit_and_fail_closed(self):
        for name, version, implementation, accepted in [
                ('nt', (3,12,3), 'cpython', False), ('nt',(3,12,4),'cpython',True),
                ('nt',(3,13,0),'cpython',True), ('nt',(3,11,9),'cpython',False),
                ('nt',(3,13,0),'pypy',False), ('posix',(3,13,0),'cpython',False)]:
            with self.subTest(name=name,version=version,implementation=implementation):
                with patch.object(package.os,'name',name), patch.object(package.sys,'version_info',version), patch.object(package.sys,'implementation',SimpleNamespace(name=implementation)):
                    if accepted:
                        package.require_windows_runtime()
                    else:
                        with self.assertRaisesRegex(ValueError,'CPython 3.12.4'):
                            package.require_windows_runtime()

    def arguments(self):
        return SimpleNamespace(windows_filter_directory=self.input, windows_filter_approval=self.approval,
            target='windows-x86_64', require_native_signature=True, macos_network_app=None,
            macos_network_identity=None, native_adapter=None, binary=self.root/'approved.exe',
            output=self.root/'catalog', version='0.1.0')

    def test_entire_driver_operation_hides_early_io_paths(self):
        out=io.StringIO()
        with patch.object(endpoint,'os',SimpleNamespace(name='nt')), patch.object(package,'require_windows_runtime'), patch.object(endpoint,'read_binary',side_effect=OSError('private binary path')), patch.object(endpoint.tempfile,'TemporaryDirectory') as temporary, contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as error:
                endpoint.run_package(self.arguments())
            self.assertEqual(error.exception.code,'Private Windows driver package operation refused')
            temporary.assert_not_called()
        self.assertEqual(out.getvalue(),'')

    def test_success_is_after_cleanup_and_cleanup_failure_has_no_success_output(self):
        for fail in (True,False):
            with self.subTest(cleanup_fails=fail):
                snapshot=self.root/('fail-snapshot' if fail else 'pass-snapshot');snapshot.mkdir()
                order=[]
                class Snapshot:
                    def __enter__(inner):return str(snapshot)
                    def __exit__(inner,*args):
                        order.append('cleanup')
                        if fail:raise OSError('private temporary path')
                out=io.StringIO()
                with patch.object(endpoint,'os',SimpleNamespace(name='nt')), patch.object(package,'require_windows_runtime'), patch.object(endpoint,'read_binary',return_value=b'synthetic'), patch.object(endpoint.tempfile,'TemporaryDirectory',return_value=Snapshot()), patch.object(package,'windows_signature_preflight'), patch.object(package,'package',return_value=(self.blob,self.d)), patch.object(package,'verify_command'), patch.object(package,'publish_catalog',side_effect=lambda *a:order.append('published')), patch.object(endpoint,'private_catalog') as generic, patch.object(endpoint.subprocess,'run') as legacy, contextlib.redirect_stdout(out):
                    if fail:
                        with self.assertRaises(SystemExit) as error:endpoint.run_package(self.arguments())
                        self.assertEqual(error.exception.code,'Private Windows driver package operation refused')
                    else:endpoint.run_package(self.arguments())
                    generic.assert_not_called();legacy.assert_not_called()
                self.assertEqual(order,['published','cleanup'])
                self.assertEqual(out.getvalue(),'' if fail else 'Provisioned windows-x86_64: native-signature-verified, 9 bytes\n')

    def test_failed_independent_signature_never_executes_candidate(self):
        out=io.StringIO()
        with patch.object(endpoint,'os',SimpleNamespace(name='nt')), patch.object(package,'require_windows_runtime'), patch.object(endpoint,'read_binary',return_value=b'synthetic'), patch.object(package,'windows_signature_preflight',side_effect=OSError('private signature path')), patch.object(package,'package') as candidate, patch.object(package,'verify_command') as capability, patch.object(package,'publish_catalog') as publish, contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as error:endpoint.run_package(self.arguments())
            self.assertEqual(error.exception.code,'Private Windows driver package operation refused')
            candidate.assert_not_called();capability.assert_not_called();publish.assert_not_called()
        self.assertEqual(out.getvalue(),'')

    def test_independent_signature_uses_only_system_tool_and_clean_module_environment(self):
        windows=self.root/'Windows'
        with patch.object(package,'_windows_directory',return_value=windows), patch.object(package,'_signature_process') as check:
            package.windows_signature_preflight(self.root/'private.exe')
        command,environment=check.call_args.args
        self.assertEqual(command[0],str(windows/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'))
        self.assertEqual(command[1:5],['-NoLogo','-NoProfile','-NonInteractive','-Command'])
        self.assertIn('Microsoft.PowerShell.Security\\Get-AuthenticodeSignature',command[5])
        self.assertNotIn(str(self.root),command[5])
        self.assertEqual(set(environment),{'SystemRoot','WINDIR','PATH','PSModulePath','ATHERNEX_VERIFY_BINARY'})
        self.assertEqual(environment['ATHERNEX_VERIFY_BINARY'],str((self.root/'private.exe').absolute()))

    def test_independent_signature_process_has_real_output_and_time_bounds(self):
        import sys
        for code,timeout in [('import sys;sys.exit(7)',2),('print("private fixture"*1000)',2),('import time;time.sleep(5)',0.1)]:
            with self.subTest(code=code[:12]):
                with self.assertRaisesRegex(ValueError,'signature check refused') as result:
                    package._signature_process([sys.executable,'-c',code],dict(os.environ),timeout)
                self.assertNotIn('private fixture',str(result.exception))
        package._signature_process([sys.executable,'-c','pass'],dict(os.environ),2)

    def test_signature_reader_start_failure_still_reaps_exact_child(self):
        import sys
        import threading
        created=[]
        real=package.subprocess.Popen
        def spawn(*args,**kwargs):
            child=real(*args,**kwargs);created.append(child);return child
        with patch.object(package.subprocess,'Popen',side_effect=spawn), patch.object(threading.Thread,'start',side_effect=RuntimeError('synthetic thread refusal')):
            with self.assertRaises(RuntimeError):
                package._signature_process([sys.executable,'-c','import time;time.sleep(5)'],dict(os.environ),2)
        self.assertEqual(len(created),1)
        self.assertIsNotNone(created[0].poll())

    def test_approved_container_and_all_snapshot_bytes_match(self):
        blob, descriptor, contents = self.snapshot()
        self.assertEqual((blob, descriptor, contents), (self.blob, self.d, self.parts))
        for name, expected in zip(package.NAMES, self.parts):
            self.assertEqual((self.root / 'snapshot' / name).read_bytes(), expected)

    def test_changed_input_and_extra_member_refuse(self):
        (self.input / package.NAMES[0]).write_bytes(b'changed sys')
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.snapshot()
        (self.input / package.NAMES[0]).write_bytes(self.parts[0])
        (self.input / 'private.log').write_text('synthetic extra')
        with self.assertRaisesRegex(ValueError, 'exactly'):
            self.snapshot()

    def test_duplicate_unknown_metadata_and_container_hash_refuse(self):
        raw=json.dumps(self.d)
        for value in [raw[:-1] + ',"schema":1}', json.dumps(dict(self.d, installed=True)), json.dumps(dict(self.d, sha256='f'*64))]:
            with self.subTest(value=value[:20]):
                self.approval.write_text(value)
                with self.assertRaises(ValueError):
                    self.snapshot()

    @unittest.skipUnless(os.name == 'posix', 'POSIX link control')
    def test_aliases_refuse_before_native_verifier(self):
        path=self.input / package.NAMES[0]
        path.unlink()
        path.symlink_to(self.approval)
        with self.assertRaises(ValueError):
            self.snapshot()
        path.unlink()
        os.link(self.approval,path)
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_fixed_owned_verifier_command_and_exact_receipt_required(self):
        result=subprocess.CompletedProcess([],0,(self.d['sha256']+'\n').encode(),b'')
        with patch.object(package.subprocess,'run',return_value=result) as run:
            blob,_=package.package(self.input,self.approval,self.root,Path('approved.exe'))
        self.assertEqual(blob,self.blob)
        self.assertEqual(run.call_args.args[0],[str(Path('approved.exe')),'verify-windows-filter-package',str(self.root/'windows-filter')])
        self.assertEqual(run.call_args.kwargs,dict(check=True,capture_output=True,timeout=45))

    def test_native_refusal_never_returns_prepared_descriptor(self):
        with patch.object(package.subprocess,'run',side_effect=subprocess.CalledProcessError(1,[])):
            with self.assertRaisesRegex(ValueError, 'verifier refused'):
                package.package(self.input,self.approval,self.root,Path('approved.exe'))

    def test_input_io_refusal_never_echoes_private_path(self):
        with patch.object(Path,'lstat',side_effect=OSError('sensitive approval path')):
            with self.assertRaises(ValueError) as result:
                self.snapshot()
            self.assertEqual(str(result.exception),'Driver package private input or snapshot I/O refused')

    def test_directory_iteration_is_bounded_before_exact_count_refusal(self):
        touched=[]
        def entries():
            for i in range(10):
                touched.append(i)
                yield self.input / str(i)
        with patch.object(Path,'iterdir',return_value=entries()):
            with self.assertRaisesRegex(ValueError,'exactly'):
                self.snapshot()
        self.assertEqual(touched,[0,1,2,3])

    def test_command_timeout_private_output_and_arbitrary_operation_are_closed(self):
        for error in [subprocess.TimeoutExpired(['private path'],45,output=b'private output'),
                      subprocess.CalledProcessError(1,['private path'],output=b'private output'),
                      OSError('private path')]:
            with patch.object(package.subprocess,'run',side_effect=error):
                with self.assertRaises(ValueError) as result:
                    package.verify_command(Path('approved.exe'),'installer-filter-hash',self.approval,'a'*64)
                self.assertEqual(str(result.exception),'Driver package verifier refused or did not complete')
        with patch.object(package.subprocess,'run') as run:
            with self.assertRaises(ValueError):
                package.verify_command(Path('approved.exe'),'install-driver',self.approval,'a'*64)
            run.assert_not_called()

    def test_native_private_publisher_receives_live_exact_snapshot_and_closed_receipt(self):
        def publish(command, **kwargs):
            self.assertEqual(command,[str(Path('approved.exe')), 'publish-windows-filter-catalog', str(self.root), str((self.root/'catalog').absolute())])
            self.assertEqual((self.root/'windows-filter.axpkg').read_bytes(),self.blob)
            self.assertEqual(kwargs,dict(check=True,capture_output=True,timeout=90))
            return subprocess.CompletedProcess([],0,(self.d['sha256']+'\n').encode(),b'')
        with patch.object(package.subprocess,'run',side_effect=publish):
            package.publish_catalog(Path('approved.exe'),self.root,self.root/'catalog',self.blob,self.d['sha256'])

    def test_native_catalog_failure_never_echoes_command_or_private_output(self):
        with patch.object(package.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['private path'],stderr=b'private data')):
            with self.assertRaises(ValueError) as result:
                package.publish_catalog(Path('approved.exe'),self.root,self.root/'catalog',self.blob,self.d['sha256'])
            self.assertEqual(str(result.exception),'Private Windows driver catalog publication refused')

    def test_mutation_after_native_verification_refuses_publication(self):
        def inspect(*args,**kwargs):
            (self.root/'windows-filter'/package.NAMES[0]).write_bytes(b'changed sys')
            return subprocess.CompletedProcess([],0,(self.d['sha256']+'\n').encode(),b'')
        with patch.object(package.subprocess,'run',side_effect=inspect):
            with self.assertRaisesRegex(ValueError,'changed'):
                package.package(self.input,self.approval,self.root,Path('approved.exe'))

if __name__ == '__main__':
    unittest.main()
