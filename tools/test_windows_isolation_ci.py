#!/usr/bin/env python3
"""Check native isolation evidence validation without creating Windows objects."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('verify_windows_isolation_ci.ps1')
WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root)
$ErrorActionPreference = 'Stop'
. $Script
$checks = @(Get-IsolationChecks | ForEach-Object { $_.test })
$report = [pscustomobject]@{ schema=1; native_windows_executed=$true; production_readiness=$false;
    manifest_sha256=('a'*64); user_sid='S-1-5-18'; session_id=0; windows_version='fixture';
    checks=[pscustomobject]@{}; error=$null }
foreach ($name in $checks) { $report.checks | Add-Member -NotePropertyName $name -NotePropertyValue 'passed' }
$global:executed = 0
function Invoke-IsolationExecutable([string]$Executable, [string[]]$Arguments, [string]$Log) {
    if ($Arguments[0] -eq '--list') {
        $listing = if ($Case -eq 'missing-test') { 'different: test' } else { $checks[0] + ': test' }
        Set-Content -LiteralPath $Log -Value $listing
    } else {
        $global:executed += 1
        if ($Arguments[0] -cne '--exact' -or $Arguments[1] -cne $checks[0] -or
            $Arguments[2] -cne '--ignored' -or $Arguments[3] -cne '--test-threads=1') { throw 'Wrong test arguments' }
        if ($Case -eq 'exit-failure') { throw 'Executable failed' }
        $summary = switch ($Case) {
            'zero-tests' { 'test result: ok. 0 passed; 0 failed; 0 ignored;' }
            'ignored-test' { 'test result: ok. 0 passed; 0 failed; 1 ignored;' }
            'failed-test' { 'test result: FAILED. 0 passed; 1 failed; 0 ignored;' }
            default { 'test result: ok. 1 passed; 0 failed; 0 ignored; 72 filtered out;' }
        }
        Set-Content -LiteralPath $Log -Value $summary
    }
}
$failure = $null
try {
    switch ($Case) {
        'wrong-hash' { $report.manifest_sha256 = 'b'*64 }
        'wrong-account' { $report.user_sid = 'S-1-5-19' }
        'wrong-session' { $report.session_id = 1 }
        'not-native' { $report.native_windows_executed = $false }
        'production-claim' { $report.production_readiness = $true }
        'missing-check' { $report.checks.PSObject.Properties.Remove($checks[0]) }
        'extra-check' { $report.checks | Add-Member -NotePropertyName unexpected -NotePropertyValue passed }
        'skipped-check' { $report.checks.($checks[0]) = 'skipped' }
        'error' { $report.error = 'fixture failed' }
    }
    Assert-IsolationReport $report ('a'*64)
    Invoke-IsolationCheck 'fixture.exe' $checks[0] (Join-Path $Root 'check.log')
} catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; executed=$global:executed; count=$checks.Count } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''
WORKER_WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root)
$ErrorActionPreference = 'Stop'
. $Script
$manifest = @{ sha256=@{} }
foreach ($name in @('endpoint.exe','native.exe')) {
    $path = Join-Path $Root $name
    Set-Content -LiteralPath $path -Value 'fixture, never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
if ($Case -eq 'changed-input') { $manifest.sha256['endpoint.exe'] = 'b'*64 }
$global:executed = 0
function Invoke-IsolationCheck([string]$Executable, [string]$Name, [string]$Log) {
    $global:executed += 1
    if ($Case -eq 'first-fails' -and $global:executed -eq 1) { throw 'First independent check failed' }
}
$report = @{ checks=[ordered]@{}; failures=[ordered]@{} }
$failure = $null
try { Invoke-IsolationChecks $Root $manifest $report }
catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; executed=$global:executed;
   passed=@($report.checks.Values | Where-Object { $_ -ceq 'passed' }).Count;
   failures=$report.failures.Count } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''


class IsolationRunnerTests(unittest.TestCase):
    powershell = None

    def run_case(self, case, wrapper_source=WRAPPER):
        with tempfile.TemporaryDirectory(prefix='athernex-isolation-ci-') as temporary:
            root = Path(temporary)
            wrapper = root/'wrapper.ps1'
            wrapper.write_text(wrapper_source)
            result = subprocess.run(
                [self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                 str(wrapper), str(SCRIPT), case, str(root)],
                capture_output=True, text=True, timeout=20,
                env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT='1', POWERSHELL_UPDATECHECK='Off'))
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            value = json.loads((root/'result.json').read_text(encoding='utf-8-sig'))
            if wrapper_source == WRAPPER:
                self.assertEqual(value['count'], 8)
            return value

    def test_exact_native_identity_and_complete_report_are_required(self):
        for case in ['wrong-hash', 'wrong-account', 'wrong-session', 'not-native',
                     'production-claim', 'missing-check', 'extra-check', 'skipped-check', 'error']:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['executed'], 0)

    def test_missing_test_never_executes_and_zero_or_ignored_tests_cannot_pass(self):
        for case in ['missing-test', 'zero-tests', 'ignored-test', 'failed-test', 'exit-failure']:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['executed'], 0 if case == 'missing-test' else 1)

    def test_one_actual_success_is_required(self):
        value = self.run_case('passed')
        self.assertFalse(value['failed'], value)
        self.assertEqual(value['executed'], 1)

    def test_independent_failures_collect_remaining_checks_but_changed_input_stops_execution(self):
        for case, executed, passed, failures, failed in [
                ('passed', 8, 8, 0, False), ('first-fails', 8, 7, 1, True),
                ('changed-input', 0, 0, 0, True)]:
            with self.subTest(case=case):
                value = self.run_case(case, WORKER_WRAPPER)
                self.assertEqual((value['executed'], value['passed'], value['failures'], value['failed']),
                                 (executed, passed, failures, failed), value)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('pwsh') or shutil.which('powershell'))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; use --powershell')
    IsolationRunnerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
