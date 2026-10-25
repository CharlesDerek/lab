#!/usr/bin/env python3
"""Exercise process-event evidence boundaries without privileged Windows actions."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('verify_windows_process_events_ci.ps1')
TEST = ('telemetry::windows_process_events::native_test::'
        'process_lifecycles_replay_with_visible_capture_gaps')
WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root)
$ErrorActionPreference = 'Stop'
. $Script
. (Join-Path (Split-Path -Parent $Script) 'verify_windows_isolation_ci.ps1')
$testName = Get-ProcessEventsTest
$manifest = @{ schema=1; suite='ProcessEvents'; github_sha=('a'*40); sha256=@{} }
foreach ($name in Get-ProcessEventsInputNames) {
    Set-Content -LiteralPath (Join-Path $Root $name) -Value 'fixture never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath (Join-Path $Root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifestPath = Join-Path $Root 'inputs.json'
if ($Case -ceq 'input-wrong-suite') { $manifest.suite = 'ProcessSource' }
if ($Case -ceq 'input-extra') { $manifest.sha256['unexpected'] = 'b'*64 }
if ($Case -ceq 'input-case') {
    $value = $manifest.sha256['agent.exe']; $manifest.sha256.Remove('agent.exe'); $manifest.sha256['AGENT.EXE'] = $value
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath
$digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$report = [pscustomobject]@{ schema=1; suite='ProcessEvents'; proof_scope='component_and_agent';
    native_windows_executed=$true; production_readiness=$false; manifest_sha256=$digest;
    user_sid='S-1-5-18'; session_id=0; windows_version='fixture'; error=$null;
    checks=[pscustomobject]@{}; process_events_stages=@(Get-ProcessEventsStageNames);
    process_events_failures=@(); private_payload='private_fixture_payload' }
$report.checks | Add-Member -NotePropertyName $testName -NotePropertyValue passed
$log = Join-Path $Root 'check-0.log'
function Write-Log {
    $lines = @(Get-ProcessEventsStageNames | ForEach-Object { 'ATHERNEX_PROCESS_EVENTS_STAGE=' + $_ })
    if ($Case -match 'missing-cleanup') { $lines = @($lines | Where-Object { $_ -cne 'ATHERNEX_PROCESS_EVENTS_STAGE=cleanup_verified' }) }
    if ($Case -match 'failure-marker') { $lines += 'ATHERNEX_PROCESS_EVENTS_FAILURE=native_loss' }
    $lines += 'private_fixture_payload'
    $lines += 'test result: ok. 1 passed; 0 failed; 0 ignored; 100 filtered out;'
    $lines | Set-Content -LiteralPath $log
}
function Mutate-Input([string]$Target) {
    Add-Content -LiteralPath (Join-Path $Root $Target) -Value 'changed'
}
$global:executed = 0
$global:taskCalls = 0
$global:logReads = 0
if ($Case -ceq 'worker-final-log-error') {
    function Test-Path($LiteralPath, $PathType) {
        if ($LiteralPath -ceq (Join-Path $Root 'check-0.log') -and $global:executed -gt 0) {
            $global:logReads += 1
            if ($global:logReads -ge 3) { throw 'private_fixture_payload' }
        }
        Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
    }
}
function Invoke-IsolationExecutable([string]$Executable, [string[]]$Arguments, [string]$Log) {
    if ($Arguments[0] -ceq '--list') {
        $listing = if ($Case -ceq 'worker-missing-test') { 'other: test' } else { $testName + ': test' }
        Set-Content -LiteralPath $Log -Value $listing
        return
    }
    $global:executed += 1
    if ($Executable -cne (Join-Path $Root 'endpoint.exe') -or $Arguments[0] -cne '--exact' -or
        $Arguments[1] -cne $testName -or $Arguments[2] -cne '--ignored' -or $Arguments[3] -cne '--test-threads=1' -or
        $env:ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST -cne '1' -or
        $env:ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT -cne (Join-Path $Root 'agent.exe') -or
        $env:ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST -or $env:ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST) {
        throw 'Incorrect native invocation'
    }
    Write-Log
    if ($Case -ceq 'worker-exit-failure') { throw 'private_fixture_payload' }
    if ($Case -ceq 'worker-zero-tests') { Set-Content -LiteralPath $Log -Value 'test result: ok. 0 passed; 0 failed; 0 ignored;' }
    if ($Case -ceq 'worker-ignored') { Set-Content -LiteralPath $Log -Value 'test result: ok. 0 passed; 0 failed; 1 ignored;' }
    if ($Case -ceq 'worker-post-input') { Mutate-Input 'agent.exe' }
}
function Invoke-ServiceFixtureTask($TaskName, $Action, $ResultFile, $Hash, $Timeout, $Validator) {
    $global:taskCalls += 1
    if ($Timeout -ne 840 -or $Hash -cne $digest) { throw 'Invalid task evidence binding' }
    Write-Log
    if ($Case -ceq 'publish-task-failure') { throw 'private_fixture_payload' }
    if ($Case -ceq 'publish-report-failure') { $report.process_events_failures = @('native_loss') }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile
    & $Validator $report $Hash
    if ($Case -ceq 'publish-cleanup-failure') { throw 'private_fixture_payload' }
    if ($Case.StartsWith('publish-change:')) { Mutate-Input $Case.Substring(15) }
    if ($Case -ceq 'publish-report-change') { $report.user_sid = 'S-1-5-19'; $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile }
    if ($Case -ceq 'publish-missing-report') { Remove-Item -LiteralPath $ResultFile }
}
$previous = @('ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT',
             'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST','ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST')
foreach ($name in $previous) { [Environment]::SetEnvironmentVariable($name, 'previous_value', 'Process') }
$failed = $false
$output = @{}
try {
    if ($Case.StartsWith('markers-')) {
        $lines = @()
        foreach ($stage in Get-ProcessEventsStageNames) { $lines += 'ATHERNEX_PROCESS_EVENTS_STAGE=' + $stage }
        foreach ($category in Get-ProcessEventsFailureNames) { $lines += 'ATHERNEX_PROCESS_EVENTS_FAILURE=' + $category }
        $lines += 'ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=query_trace:0'
        $lines += 'ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=stop_trace:4294967295'
        $lines += 'ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=tdh_information:1168'
        $lines += 'ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=tdh_size:122'
        $lines += 'ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=tdh_property:5'
        $lines += 'ATHERNEX_PROCESS_EVENTS_SCHEMA=3:4:64:12'
        $lines += 'ATHERNEX_PROCESS_EVENTS_SCHEMA=39:255:32:64'
        $lines += 'ATHERNEX_PROCESS_EVENTS_SCHEMA=0:0:32:1'
        $lines += 'ATHERNEX_PROCESS_EVENTS_SCHEMA=255:255:64:64'
        foreach ($property in @('process_id','parent_id','session_id','exit_status','unique_process_key')) {
            $lines += 'ATHERNEX_PROCESS_EVENTS_TDH_PROPERTY=' + $property
        }
        if ($Case -ceq 'markers-injected') {
            $lines = @($lines | ForEach-Object {
                $_ + ' private_fixture_payload'; ' ' + $_; $_ + [char]0; $_ + [char]0x00ad
                if ($_ -cne $_.ToUpperInvariant()) { $_.ToUpperInvariant() }
                else { $_.ToLowerInvariant() }
            })
            $lines += @('ATHERNEX_PROCESS_EVENTS_STAGE=unknown_private_fixture_payload',
                'ATHERNEX_PROCESS_EVENTS_FAILURE=unknown_private_fixture_payload',
                'ATHERNEX_PROCESS_EVENTS_TDH_PROPERTY=unknown_private_fixture_payload',
                'ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=unknown_private_fixture_payload:5')
            foreach ($value in @('01','+1','-1','0x5','4294967296','1.0','1e2',' 1','1 ')) {
                $lines += 'ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=query_trace:' + $value
            }
            foreach ($value in @('03:4:64:12','256:4:64:12','-1:4:64:12','3:256:64:12','3:04:64:12',
                '3:-1:64:12','3:4:16:12','3:4:064:12','3:4:64:0','3:4:64:65','3:4:64:012')) {
                $lines += 'ATHERNEX_PROCESS_EVENTS_SCHEMA=' + $value
            }
        }
        if ($Case -ceq 'markers-flood') {
            $lines = @(0..99 | ForEach-Object {
                'ATHERNEX_PROCESS_EVENTS_STAGE=passed'; 'ATHERNEX_PROCESS_EVENTS_FAILURE=other';
                'ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=query_trace:' + $_
                'ATHERNEX_PROCESS_EVENTS_SCHEMA=3:' + $_ + ':64:12'
                'ATHERNEX_PROCESS_EVENTS_TDH_PROPERTY=parent_id'
            })
        }
        $lines | Set-Content -LiteralPath $log
        $output = @{ stages=@(Get-ProcessEventsStages $log); failures=@(Get-ProcessEventsFailures $log);
                     diagnostics=@(Get-ProcessEventsDiagnostics $log); schema=@(Get-ProcessEventsSchema $log);
                     properties=@(Get-ProcessEventsProperties $log) }
    } elseif ($Case.StartsWith('worker-') -or $Case.StartsWith('input-')) {
        if ($Case.StartsWith('worker-change:')) { Mutate-Input $Case.Substring(14) }
        $workerReport = @{ manifest_sha256=$digest; checks=[ordered]@{}; error=$null }
        Invoke-ProcessEventsWorkerChecks $Root $workerReport
    } elseif ($Case.StartsWith('publish-')) {
        $source = if ($Case -ceq 'publish-wrong-source') { 'b'*40 } else { 'a'*40 }
        Invoke-ProcessEventsEvidence $Root 'fixture-task' @{} $digest $source
    } elseif ($Case -ceq 'guard') {
        Invoke-ProcessEventsWorker $Root $false
    } else {
        switch ($Case) {
            'report-hash' { $report.manifest_sha256 = 'b'*64 }
            'report-suite' { $report.suite = 'ProcessSource' }
            'report-scope' { $report.proof_scope = 'source_only' }
            'report-account' { $report.user_sid = 'S-1-5-19' }
            'report-session' { $report.session_id = 1 }
            'report-native' { $report.native_windows_executed = $false }
            'report-production' { $report.production_readiness = $true }
            'report-error' { $report.error = 'private_fixture_payload' }
            'report-no-test' { $report.checks.PSObject.Properties.Remove($testName) }
            'report-extra-test' { $report.checks | Add-Member -NotePropertyName other -NotePropertyValue passed }
            'report-skipped' { $report.checks.$testName = 'skipped' }
            'report-stage' { $report.process_events_stages = @('passed') }
            'report-failure' { $report.process_events_failures = @('native_loss') }
            'report-no-failures' { $report.PSObject.Properties.Remove('process_events_failures') }
        }
        Assert-ProcessEventsReport $report $digest
    }
} catch { $failed = $true }
$output.failed = $failed
$output.executed = $global:executed
$output.task_calls = $global:taskCalls
$output.environment_restored = @($previous | Where-Object { [Environment]::GetEnvironmentVariable($_, 'Process') -cne 'previous_value' }).Count -eq 0
if ($workerReport) { $output.worker = $workerReport }
$publicPath = Join-Path $Root 'process-events-validation.json'
if (Test-Path -LiteralPath $publicPath) { $output.public = Get-Content -LiteralPath $publicPath -Raw | ConvertFrom-Json }
$output | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''


class ProcessEventsRunnerTests(unittest.TestCase):
    powershell = None

    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='athernex-process-evidence-') as temporary:
            root = Path(temporary)
            wrapper = root/'wrapper.ps1'
            wrapper.write_text(WRAPPER)
            result = subprocess.run(
                [self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                 str(wrapper), str(SCRIPT), case, str(root)], capture_output=True, text=True,
                timeout=20, env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT='1', POWERSHELL_UPDATECHECK='Off'))
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            value = json.loads((root/'result.json').read_text(encoding='utf-8-sig'))
            self.assertNotIn('private_fixture_payload', json.dumps(value))
            self.assertTrue(value['environment_restored'], value)
            return value

    def test_worker_requires_native_guard_and_manifest_before_enabling_fixture(self):
        for case in ['guard', 'input-wrong-suite', 'input-extra', 'input-case']:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['executed'], 0)
                self.assertNotIn('public', value)

    def test_report_requires_exact_identity_scope_and_complete_native_evidence(self):
        self.assertFalse(self.run_case('report-passed')['failed'])
        for suffix in ['hash', 'suite', 'scope', 'account', 'session', 'native', 'production',
                       'error', 'no-test', 'extra-test', 'skipped', 'stage', 'failure', 'no-failures']:
            with self.subTest(suffix=suffix):
                self.assertTrue(self.run_case('report-'+suffix)['failed'])

    def test_worker_requires_one_real_test_complete_stages_and_unchanged_inputs(self):
        inputs = ['agent.exe', 'endpoint.exe', 'verify_windows_process_events_ci.ps1',
                  'verify_windows_isolation_ci.ps1', 'verify_windows_service_ci.ps1']
        for case in ['worker-passed', 'worker-missing-test', 'worker-zero-tests', 'worker-ignored',
                     'worker-exit-failure', 'worker-missing-cleanup', 'worker-failure-marker',
                     'worker-post-input', 'worker-final-log-error', *['worker-change:'+name for name in inputs]]:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertEqual(value['failed'], case != 'worker-passed', value)
                self.assertEqual(value['executed'], 0 if case.startswith('worker-change:') or case == 'worker-missing-test' else 1)
                self.assertEqual(value['worker']['error'], None if case == 'worker-passed' else 'native_worker_failed')

    def test_public_success_requires_completed_task_cleanup_and_fresh_bound_evidence(self):
        inputs = ['agent.exe', 'endpoint.exe', 'verify_windows_process_events_ci.ps1',
                  'verify_windows_isolation_ci.ps1', 'verify_windows_service_ci.ps1', 'inputs.json']
        for case in ['publish-passed', 'publish-task-failure', 'publish-cleanup-failure',
                     'publish-missing-cleanup', 'publish-failure-marker', 'publish-report-failure',
                     'publish-report-change', 'publish-missing-report', 'publish-wrong-source',
                     *['publish-change:'+name for name in inputs]]:
            with self.subTest(case=case):
                value = self.run_case(case)
                passed = case == 'publish-passed'
                self.assertEqual(value['failed'], not passed, value)
                self.assertEqual(value['task_calls'], 0 if case == 'publish-wrong-source' else 1)
                public = value['public']
                self.assertEqual(set(public), {'schema', 'suite', 'proof_scope', 'production_readiness',
                    'manifest_sha256', 'native_process_events_validation_passed', 'stages',
                    'process_events_stages', 'process_events_failures', 'process_events_diagnostics',
                    'process_events_schema', 'process_events_properties', 'checks', 'error'})
                self.assertEqual(public['checks'], {TEST: 'passed' if passed else 'not_verified'})
                self.assertIs(public['native_process_events_validation_passed'], passed)
                self.assertIs(public['production_readiness'], False)
                self.assertEqual(public['proof_scope'], 'component_and_agent')
                self.assertEqual(public['error'], None if passed else 'native_process_events_not_verified')
                if passed:
                    self.assertEqual(public['stages'], ['inputs_verified', 'task_completed_and_removed', 'report_verified'])

    def test_only_exact_fixed_markers_and_bounded_numeric_diagnostics_are_public(self):
        valid = self.run_case('markers-valid')
        self.assertEqual(len(valid['stages']), 19)
        self.assertEqual(len(valid['failures']), 32)
        self.assertEqual(valid['diagnostics'], [{'operation': 'query_trace', 'win32_error': 0},
                                              {'operation': 'stop_trace', 'win32_error': 4294967295},
                                              {'operation': 'tdh_information', 'win32_error': 1168},
                                              {'operation': 'tdh_size', 'win32_error': 122},
                                              {'operation': 'tdh_property', 'win32_error': 5}])
        self.assertEqual(valid['schema'], [{'opcode': 3, 'version': 4, 'pointer_bits': 64, 'property_count': 12},
                                          {'opcode': 39, 'version': 255, 'pointer_bits': 32, 'property_count': 64},
                                          {'opcode': 0, 'version': 0, 'pointer_bits': 32, 'property_count': 1},
                                          {'opcode': 255, 'version': 255, 'pointer_bits': 64, 'property_count': 64}])
        self.assertEqual(valid['properties'], ['process_id', 'parent_id', 'session_id', 'exit_status', 'unique_process_key'])
        injected = self.run_case('markers-injected')
        for key in ['stages', 'failures', 'diagnostics', 'schema', 'properties']:
            self.assertEqual(injected[key], [])
        flood = self.run_case('markers-flood')
        self.assertEqual(flood['stages'], ['passed'])
        self.assertEqual(flood['failures'], ['other'])
        self.assertEqual(flood['diagnostics'], [{'operation': 'query_trace', 'win32_error': i} for i in range(32)])
        self.assertEqual(flood['schema'], [{'opcode': 3, 'version': i, 'pointer_bits': 64, 'property_count': 12} for i in range(16)])
        self.assertEqual(flood['properties'], ['parent_id'])

    def test_workflow_uploads_only_public_projection_and_manifest(self):
        workflow = SCRIPT.parent.parent/'.github/workflows/endpoint.yml'
        job = workflow.read_text().split('  windows-process-events:\n', 1)[1].split('  windows-isolation:\n', 1)[0]
        self.assertIn('cargo build --locked --release -p athernex-endpoint', job)
        self.assertIn('tools/verify_windows_process_events_ci.ps1 -AgentExecutable', job)
        paths = job.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], [
            '${{ runner.temp }}/native-windows-process-events/inputs.json',
            '${{ runner.temp }}/native-windows-process-events/process-events-validation.json'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('pwsh') or shutil.which('powershell'))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; use --powershell')
    ProcessEventsRunnerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
