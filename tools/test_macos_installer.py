#!/usr/bin/env python3
"""Exercise installer ordering in a private tree with controlled Apple-tool replies.

No Apple signature, entitlement, launchd or native authorization is executed.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

STUB = r'''#!/usr/bin/env python3
import hashlib,json,os,plistlib,sys
from pathlib import Path
role=Path(sys.argv[0]).name
args=sys.argv[1:]
case=os.environ['FIXTURE_CASE']
with open(os.environ['FIXTURE_LOG'],'a') as log: log.write(role+' '+json.dumps(args)+'\n')
if role=='id': print('0')
elif role=='launchctl': pass
elif role=='codesign':
    if '--verify' in args and case=='signature-failure': sys.exit(1)
    if '--verify' in args and case=='changed-input' and Path(args[-1]).name=='adapter':
        (Path(os.environ['FIXTURE_BUNDLE'])/'athernex-endpoint-native').write_bytes(b'changed after snapshot')
    if '-d' in args:
        values={'com.apple.developer.endpoint-security.client':case!='missing-entitlement'}
        if case=='debug-entitlement': values['com.apple.security.get-task-allow']=True
        sys.stdout.buffer.write(plistlib.dumps(values))
elif role=='spctl':
    if case=='gatekeeper-failure': sys.exit(1)
elif role=='PlistBuddy':
    key=args[1].removeprefix('Print :')
    values=plistlib.loads(Path(args[2]).read_bytes())
    if key not in values: sys.exit(1)
    print(str(values[key]).lower())
elif role in ('athernex-endpoint','athernex-controller'):
    if args[0]=='installer-native-hash':
        if case=='legacy': sys.exit(19)
        value=json.loads(Path(args[1]).read_text())['native_adapter']['sha256']
        print(value)
    elif args[0]=='enroll': Path(args[2]).mkdir(parents=True,exist_ok=True)
    elif args[0]=='configure-macos-process-adapter' and case=='process-pin-failure': sys.exit(1)
    elif args[0]=='configure-native-protection' and case=='native-setup-failure': sys.exit(1)
else: sys.exit('Unexpected fixture invocation: '+role)
'''


@unittest.skipUnless(os.name == 'posix' and shutil.which('shasum'), 'Requires Unix sh and shasum')
class InstallerTests(unittest.TestCase):
    def run_installer(self, case):
        temp = tempfile.TemporaryDirectory(prefix='athernex-installer-fixture-')
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        bundle = root / 'bundle with spaces'
        bundle.mkdir()
        binaries = root / 'bin'
        binaries.mkdir()
        for name in ('id','launchctl','codesign','spctl','PlistBuddy'):
            path = binaries / name
            path.write_text(STUB)
            path.chmod(0o700)
        (root / 'tmp').mkdir()
        (root / 'Library/LaunchDaemons').mkdir(parents=True)
        installed = root / 'Library/AthernexEndpoint'
        installed.mkdir()
        retained = installed / 'athernex-endpoint-native'
        retained.write_bytes(b'previous adapter')
        main = bundle / 'athernex-endpoint'
        main.write_text(STUB)
        native = b'public nonexecutable native fixture'
        if case != 'legacy':
            (bundle / 'native-adapter.required').write_text('1\n')
            (bundle / 'athernex-endpoint-native').write_bytes(native)
        if case == 'missing-component': (bundle / 'athernex-endpoint-native').unlink()
        if case == 'tampered': (bundle / 'athernex-endpoint-native').write_bytes(b'wrong bytes')
        (bundle / 'release.json').write_text(json.dumps(dict(native_adapter=dict(sha256=hashlib.sha256(native).hexdigest()))))
        (bundle / 'bootstrap.json').write_text('{}')
        script = (Path(__file__).resolve().parent.parent / 'infrastructure/endpoint/install-macos.sh').read_text()
        script = script.replace('/Library/',str(root / 'Library')+'/').replace('/private/tmp/',str(root / 'tmp')+'/')
        for original,name in [('/usr/bin/codesign','codesign'),('/usr/sbin/spctl','spctl'),('/usr/libexec/PlistBuddy','PlistBuddy')]:
            script = script.replace(original,str(binaries / name))
        path = bundle / 'install.sh'
        path.write_text(script)
        log = root / 'calls.log'
        env = dict(os.environ, PATH=str(binaries)+os.pathsep+os.environ['PATH'],
                   FIXTURE_CASE=case,FIXTURE_LOG=str(log),FIXTURE_BUNDLE=str(bundle))
        result = subprocess.run(['sh',str(path)],env=env,capture_output=True,text=True,timeout=20)
        calls = log.read_text()
        return result,calls,retained,native,installed,bundle,root

    def test_verified_native_component_is_staged_before_service_changes(self):
        result,calls,retained,native,installed,bundle,root = self.run_installer('valid')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(retained.read_bytes(),native)
        self.assertLess(calls.index('spctl'),calls.index('"bootout"'))
        self.assertIn('"bootstrap"',calls)
        self.assertLess(calls.index('"provision-antivirus"'),calls.index('"configure-native-protection"'))
        self.assertLess(calls.index('"configure-native-protection"'),calls.index('"bootstrap"'))
        self.assertLess(calls.index('"enroll"'),calls.index('"configure-macos-process-adapter"'))
        self.assertLess(calls.index('"configure-macos-process-adapter"'),calls.index('"provision-antivirus"'))
        pin = [json.loads(line.split(' ',1)[1]) for line in calls.splitlines() if '"configure-macos-process-adapter"' in line]
        self.assertEqual(len(pin),1)
        self.assertEqual(pin[0],['configure-macos-process-adapter',str(installed/'state'),str(retained),hashlib.sha256(native).hexdigest()])
        self.assertIn('real-time protection remains unverified',result.stdout)
        self.assertFalse((bundle / 'bootstrap.json').exists())
        self.assertEqual(list(installed.glob('.native.*')),[])
        self.assertEqual(list((root / 'tmp').iterdir()),[])

    def test_failed_native_checks_leave_existing_service_and_adapter_untouched(self):
        for case in ('tampered','missing-component','signature-failure','gatekeeper-failure','missing-entitlement','debug-entitlement'):
            with self.subTest(case=case):
                result,calls,retained,_,_,bundle,root = self.run_installer(case)
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn('"bootout"',calls)
                self.assertNotIn('"bootstrap"',calls)
                self.assertEqual(retained.read_bytes(),b'previous adapter')
                self.assertTrue((bundle / 'bootstrap.json').exists())
                self.assertEqual(list((root / 'tmp').iterdir()),[])

    def test_changing_bundle_during_signature_check_cannot_change_installed_bytes(self):
        result,_,retained,native,_,bundle,_ = self.run_installer('changed-input')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotEqual((bundle / 'athernex-endpoint-native').read_bytes(),native)
        self.assertEqual(retained.read_bytes(),native)

    def test_ordinary_bundle_does_not_require_new_metadata_command_or_remove_existing_adapter(self):
        result,calls,retained,_,_,_,_ = self.run_installer('legacy')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('installer-native-hash',calls)
        self.assertNotIn('configure-native-protection',calls)
        self.assertNotIn('configure-macos-process-adapter',calls)
        self.assertEqual(retained.read_bytes(),b'previous adapter')

    def test_native_setup_failure_retains_bootstrap_and_does_not_start_service(self):
        result,calls,_,_,_,bundle,_ = self.run_installer('native-setup-failure')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('"configure-native-protection"',calls)
        self.assertNotIn('"bootstrap"',calls)
        self.assertTrue((bundle/'bootstrap.json').exists())

    def test_process_pin_failure_stops_before_scanner_setup_and_service_start(self):
        result,calls,_,_,_,bundle,_ = self.run_installer('process-pin-failure')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('"configure-macos-process-adapter"',calls)
        self.assertNotIn('"provision-antivirus"',calls)
        self.assertNotIn('"bootstrap"',calls)
        self.assertTrue((bundle/'bootstrap.json').exists())


if __name__ == '__main__': unittest.main()
