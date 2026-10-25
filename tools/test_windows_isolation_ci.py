#!/usr/bin/env python3
"""Check native suite evidence validation without creating Windows objects."""
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
AUTHENTICATION_TEST = ('telemetry::windows_authentication::native_test::'
                       'security_logon_delivery_replays_and_reports_policy_gaps')
WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$SelectedSuite)
$ErrorActionPreference = 'Stop'
. $Script
$checks = @(Get-IsolationChecks $SelectedSuite | ForEach-Object { $_.test })
$report = [pscustomobject]@{ schema=1; suite=$SelectedSuite; native_windows_executed=$true; production_readiness=$false;
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
        'wrong-suite' { $report.suite = if ($SelectedSuite -ceq 'Isolation') { 'Authentication' } else { 'Isolation' } }
        'missing-suite' { $report.PSObject.Properties.Remove('suite') }
        'wrong-account' { $report.user_sid = 'S-1-5-19' }
        'wrong-session' { $report.session_id = 1 }
        'not-native' { $report.native_windows_executed = $false }
        'production-claim' { $report.production_readiness = $true }
        'missing-check' { $report.checks.PSObject.Properties.Remove($checks[0]) }
        'extra-check' { $report.checks | Add-Member -NotePropertyName unexpected -NotePropertyValue passed }
        'skipped-check' { $report.checks.($checks[0]) = 'skipped' }
        'failed-check' { $report.checks.($checks[0]) = 'failed' }
        'error' { $report.error = 'fixture failed' }
    }
    Assert-IsolationReport $report ('a'*64) $SelectedSuite
    Invoke-IsolationCheck 'fixture.exe' $checks[0] (Join-Path $Root 'check.log')
} catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; executed=$global:executed; count=$checks.Count; names=$checks } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''
GATE_WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$SelectedSuite)
$ErrorActionPreference = 'Stop'
. $Script
$failure = $null
$optIn = 'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST'
[Environment]::SetEnvironmentVariable($optIn, 'not-enabled', 'Process')
$global:executed = 0
function Invoke-IsolationChecks { $global:executed += 1 }
try {
    if ($Case -eq 'not-disposable') { Invoke-IsolationWorker $Root $false $SelectedSuite }
    elseif ($Case -eq 'default-suite') {
        $default = @(Get-IsolationChecks | ForEach-Object { $_.test })
        $explicit = @(Get-IsolationChecks Isolation | ForEach-Object { $_.test })
        if ($default.Count -ne 11 -or (Compare-Object $default $explicit)) { throw 'Default suite changed' }
    } else { $null = Get-IsolationChecks $Case }
} catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); executed=$global:executed;
   opt_in=[Environment]::GetEnvironmentVariable($optIn, 'Process');
   report_exists=(Test-Path -LiteralPath (Join-Path $Root 'authentication-validation.json')) } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''
WORKER_WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$SelectedSuite)
$ErrorActionPreference = 'Stop'
. $Script
$manifest = @{ schema=1; suite=$SelectedSuite; sha256=@{} }
foreach ($name in @('endpoint.exe','native.exe')) {
    $path = Join-Path $Root $name
    Set-Content -LiteralPath $path -Value 'fixture, never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
if ($Case -eq 'changed-input') { $manifest.sha256['endpoint.exe'] = 'b'*64 }
if ($Case -eq 'wrong-suite') { $manifest.suite = if ($SelectedSuite -ceq 'Isolation') { 'Authentication' } else { 'Isolation' } }
if ($Case -eq 'missing-suite') { $manifest.Remove('suite') }
$global:executed = 0
$global:executedNames = @()
function Invoke-IsolationCheck([string]$Executable, [string]$Name, [string]$Log) {
    $global:executed += 1
    $global:executedNames += $Name
    if ($SelectedSuite -ceq 'Authentication' -and (Split-Path -Leaf $Executable) -cne 'endpoint.exe') {
        throw 'Authentication must execute the compiled endpoint test binary'
    }
    if ($Case -eq 'first-fails' -and $global:executed -eq 1) { throw 'First independent check failed' }
}
$report = @{ checks=[ordered]@{}; failures=[ordered]@{} }
$failure = $null
try { Invoke-IsolationChecks $Root $manifest $report $SelectedSuite }
catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; executed=$global:executed;
   passed=@($report.checks.Values | Where-Object { $_ -ceq 'passed' }).Count;
   failures=$report.failures.Count; names=$global:executedNames } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''
STAGES_WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$SelectedSuite)
$ErrorActionPreference = 'Stop'
. $Script
$manifest = @{ schema=1; suite=$SelectedSuite; sha256=@{} }
foreach ($name in @('endpoint.exe','native.exe')) {
    $path = Join-Path $Root $name
    Set-Content -LiteralPath $path -Value 'fixture, never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$checks = @(Get-IsolationChecks $SelectedSuite | ForEach-Object { $_.test })
function Invoke-IsolationExecutable([string]$Executable, [string[]]$Arguments, [string]$Log) {
    if ($Arguments[0] -ceq '--list') {
        $checks | ForEach-Object { $_ + ': test' } | Set-Content -LiteralPath $Log
        return
    }
    if ($Case -ceq 'missing-log') { throw 'Fixture executable failed before output' }
    @(
        'ATHERNEX_AUTH_STAGE=guard_verified',
        'ATHERNEX_AUTH_STAGE=policy_ready',
        'ATHERNEX_AUTH_STAGE=guard_verified',
        'ATHERNEX_AUTH_STAGE=unknown_private_payload',
        'ATHERNEX_AUTH_STAGE=source_ready private_payload',
        'ATHERNEX_AUTH_STAGE=source_ready=private_payload',
        "ATHERNEX_AUTH_STAGE=source_ready$([char]0x00ad)",
        "ATHERNEX_AUTH_STAGE=source_ready$([char]0)",
        'ATHERNEX_AUTH_STAGE=SOURCE_READY',
        ' ATHERNEX_AUTH_STAGE=source_ready',
        'test fixture ... ATHERNEX_AUTH_STAGE=source_ready',
        '<Event>private_fixture_payload</Event>',
        'ATHERNEX_AUTH_STAGE=cleanup_verified'
    ) | Set-Content -LiteralPath $Log
    if ($Case -ceq 'exit-failure') { throw 'Fixture executable failed' }
    if ($Case -ceq 'skipped') {
        Add-Content -LiteralPath $Log -Value 'test result: ok. 0 passed; 0 failed; 1 ignored;'
    } elseif ($Case -cne 'no-summary') {
        Add-Content -LiteralPath $Log -Value 'test result: ok. 1 passed; 0 failed; 0 ignored;'
    }
}
$report = @{ checks=[ordered]@{}; failures=[ordered]@{} }
$failure = $null
try { Invoke-IsolationChecks $Root $manifest $report $SelectedSuite }
catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); has_stages=$report.ContainsKey('authentication_stages');
   stages=@($report.authentication_stages); failures=$report.failures.Count;
   passed=@($report.checks.Values | Where-Object { $_ -ceq 'passed' }).Count } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''


class IsolationRunnerTests(unittest.TestCase):
    powershell = None

    def run_case(self, case, wrapper_source=WRAPPER, suite='Isolation'):
        with tempfile.TemporaryDirectory(prefix='athernex-isolation-ci-') as temporary:
            root = Path(temporary)
            wrapper = root/'wrapper.ps1'
            wrapper.write_text(wrapper_source)
            result = subprocess.run(
                [self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                 str(wrapper), str(SCRIPT), case, str(root), suite],
                capture_output=True, text=True, timeout=20,
                env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT='1', POWERSHELL_UPDATECHECK='Off'))
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            value = json.loads((root/'result.json').read_text(encoding='utf-8-sig'))
            if wrapper_source == WRAPPER:
                self.assertEqual(value['count'], 11 if suite == 'Isolation' else 1)
            return value

    def test_exact_native_identity_and_complete_report_are_required(self):
        for suite in ['Isolation', 'Authentication']:
            for case in ['wrong-hash', 'wrong-suite', 'missing-suite', 'wrong-account',
                         'wrong-session', 'not-native', 'production-claim', 'missing-check',
                         'extra-check', 'skipped-check', 'failed-check', 'error']:
                with self.subTest(suite=suite, case=case):
                    value = self.run_case(case, suite=suite)
                    self.assertTrue(value['failed'], value)
                    self.assertEqual(value['executed'], 0)

    def test_missing_test_never_executes_and_zero_or_ignored_tests_cannot_pass(self):
        for suite in ['Isolation', 'Authentication']:
            for case in ['missing-test', 'zero-tests', 'ignored-test', 'failed-test', 'exit-failure']:
                with self.subTest(suite=suite, case=case):
                    value = self.run_case(case, suite=suite)
                    self.assertTrue(value['failed'], value)
                    self.assertEqual(value['executed'], 0 if case == 'missing-test' else 1)

    def test_one_actual_success_is_required(self):
        for suite in ['Isolation', 'Authentication']:
            with self.subTest(suite=suite):
                value = self.run_case('passed', suite=suite)
                self.assertFalse(value['failed'], value)
                self.assertEqual(value['executed'], 1)
                if suite == 'Authentication':
                    self.assertEqual(value['names'], [AUTHENTICATION_TEST])

    def test_independent_failures_collect_remaining_checks_but_changed_input_stops_execution(self):
        for case, executed, passed, failures, failed in [
                ('passed', 11, 11, 0, False), ('first-fails', 11, 10, 1, True),
                ('changed-input', 0, 0, 0, True)]:
            with self.subTest(case=case):
                value = self.run_case(case, WORKER_WRAPPER)
                self.assertEqual((value['executed'], value['passed'], value['failures'], value['failed']),
                                 (executed, passed, failures, failed), value)

    def test_authentication_runs_only_its_fixed_test_and_cannot_hide_failure(self):
        for case, executed, passed, failures, failed in [
                ('passed', 1, 1, 0, False), ('first-fails', 1, 0, 1, True),
                ('changed-input', 0, 0, 0, True), ('wrong-suite', 0, 0, 0, True),
                ('missing-suite', 0, 0, 0, True)]:
            with self.subTest(case=case):
                value = self.run_case(case, WORKER_WRAPPER, 'Authentication')
                self.assertEqual((value['executed'], value['passed'], value['failures'], value['failed']),
                                 (executed, passed, failures, failed), value)
                self.assertEqual(value['names'], [AUTHENTICATION_TEST] if executed else [])

    def test_isolation_rejects_unbound_or_other_suite_inputs(self):
        for case in ['wrong-suite', 'missing-suite']:
            with self.subTest(case=case):
                value = self.run_case(case, WORKER_WRAPPER)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['executed'], 0)

    def test_suite_selection_is_fixed_and_isolation_remains_the_default(self):
        self.assertFalse(self.run_case('default-suite', GATE_WRAPPER)['failed'])
        for suite in ['arbitrary-test-name', 'authentication']:
            with self.subTest(suite=suite):
                self.assertTrue(self.run_case(suite, GATE_WRAPPER)['failed'])

    def test_worker_cannot_enable_policy_changes_without_disposable_host_opt_in(self):
        value = self.run_case('not-disposable', GATE_WRAPPER, 'Authentication')
        self.assertTrue(value['failed'], value)
        self.assertEqual(value['executed'], 0)
        self.assertEqual(value['opt_in'], 'not-enabled')
        self.assertFalse(value['report_exists'])

    def test_authentication_stage_evidence_excludes_unrecognized_or_injected_log_text(self):
        value = self.run_case('passed', STAGES_WRAPPER, 'Authentication')
        self.assertFalse(value['failed'], value)
        self.assertEqual(value['passed'], 1)
        self.assertEqual(value['stages'], ['guard_verified', 'policy_ready', 'cleanup_verified'])
        self.assertTrue(value['has_stages'])
        self.assertNotIn('private_payload', json.dumps(value))

    def test_stage_markers_never_override_native_failure_or_change_isolation_evidence(self):
        for case in ['exit-failure', 'skipped', 'no-summary', 'missing-log']:
            with self.subTest(case=case):
                value = self.run_case(case, STAGES_WRAPPER, 'Authentication')
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['passed'], 0)
                self.assertEqual(value['failures'], 1)
                self.assertEqual(value['stages'], [] if case == 'missing-log' else
                                 ['guard_verified', 'policy_ready', 'cleanup_verified'])
        value = self.run_case('passed', STAGES_WRAPPER, 'Isolation')
        self.assertFalse(value['failed'], value)
        self.assertEqual(value['passed'], 11)
        self.assertFalse(value['has_stages'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('pwsh') or shutil.which('powershell'))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; use --powershell')
    IsolationRunnerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
