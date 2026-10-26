#!/usr/bin/env python3
"""Exercise workspace-recovery evidence gates without privileged Windows actions."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('verify_windows_workspace_ci.ps1')
TESTS = [
    'actual_scratch_cleanup_excludes_live_workers_and_replays_partial_image_retirement',
    'actual_preview_recovery_waits_for_workers_and_retires_scratch_before_staged_files',
    'actual_cleanup_worker_preserves_live_journals_and_replays_committed_workspace_deletion',
]
INPUTS = ['agent.exe', 'windows_workspace.exe', 'verify_windows_workspace_ci.ps1',
          'verify_windows_isolation_ci.ps1', 'verify_windows_service_ci.ps1']
STAGES = ['guard_started', 'guard_verified', 'agent_verified', 'private_ready', 'scratch_prepared',
          'scratch_spoof_refused', 'scratch_live_owner_retained', 'scratch_worker_lease_refused',
          'scratch_network_retained', 'scratch_cleanup_verified', 'scratch_retirement_replayed',
          'scratch_empty_replayed', 'preview_prepared', 'preview_supervisor_refused',
          'preview_workers_refused', 'preview_network_retained', 'preview_cleanup_verified',
          'preview_empty_replayed', 'preview_storage_empty', 'workspace_prepared',
          'workspace_spoof_refused', 'workspace_network_retained', 'workspace_cleanup_verified',
          'workspace_deletion_replayed']
FAILURES = ['bounded_cleanup_failed', 'bounded_recovery_failed', 'invalid_scratch_request',
            'invalid_workspace_request', 'scratch_live_owner', 'scratch_network_pending',
            'workspace_network_pending', 'other_private']
WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$Configuration)
$ErrorActionPreference = 'Stop'
. $Script
. (Join-Path (Split-Path -Parent $Script) 'verify_windows_isolation_ci.ps1')
$scenario = Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
$testNames = @(Get-WorkspaceRecoveryTests)
$inputNames = @(Get-WorkspaceRecoveryInputNames)
$manifest = @{ schema=1; suite='WorkspaceRecovery'; github_sha=('a'*40); sha256=@{} }
foreach ($name in $inputNames) {
    Set-Content -LiteralPath (Join-Path $Root $name) -Value 'fixture never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath (Join-Path $Root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifestPath = Join-Path $Root 'inputs.json'
switch ($Case) {
    'input-wrong-suite' { $manifest.suite = 'Isolation' }
    'input-missing-suite' { $manifest.Remove('suite') }
    'input-extra' { $manifest.sha256['unexpected'] = 'b'*64 }
    'input-missing' { $manifest.sha256.Remove('agent.exe') }
    'input-case' {
        $value = $manifest.sha256['agent.exe']; $manifest.sha256.Remove('agent.exe'); $manifest.sha256['AGENT.EXE'] = $value
    }
    'input-source' { $manifest.github_sha = 'private_fixture_payload' }
    'input-schema-string' { $manifest.schema = '1' }
    'input-schema-float' { $manifest.schema = 1.0 }
    'input-schema-bool' { $manifest.schema = $true }
    'input-suite-array' { $manifest.suite = @('WorkspaceRecovery') }
    'input-suite-object' { $manifest.suite = @{ value='WorkspaceRecovery' } }
    'input-source-array' { $manifest.github_sha = @('a'*40) }
    'input-source-object' { $manifest.github_sha = @{ value=('a'*40) } }
    'input-hash-array' { $manifest.sha256['agent.exe'] = @($manifest.sha256['agent.exe']) }
    'input-hash-object' { $manifest.sha256['agent.exe'] = @{ value=$manifest.sha256['agent.exe'] } }
    'input-suite-unicode' { $manifest.suite = 'Workspace' + [char]0x00ad + 'Recovery' }
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath
$digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($scenario.remove_input) { Remove-Item -LiteralPath (Join-Path $Root $scenario.remove_input) }
$report = [pscustomobject]@{ schema=1; suite='WorkspaceRecovery'; proof_scope='agent_cleanup_recovery';
    native_windows_executed=$true; production_readiness=$false; manifest_sha256=$digest;
    user_sid='S-1-5-18'; session_id=0; windows_version='fixture'; error=$null;
    checks=[pscustomobject]@{}; progress=[pscustomobject]@{} }
foreach ($name in $testNames) {
    $report.checks | Add-Member -NotePropertyName $name -NotePropertyValue passed
    $report.progress | Add-Member -NotePropertyName $name -NotePropertyValue completed
}
foreach ($property in $scenario.report.PSObject.Properties) {
    $report | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
}
foreach ($name in $scenario.remove_fields) { $report.PSObject.Properties.Remove($name) }
for ($index=0; $scenario.logs -and $index -lt $scenario.logs.Count; $index++) {
    if ($null -ne $scenario.logs[$index]) {
        $encoding = switch ($scenario.log_encoding) {
            'utf16le' { [Text.Encoding]::Unicode }
            'utf8bom' { [Text.UTF8Encoding]::new($true) }
            default { [Text.UTF8Encoding]::new($false) }
        }
        [IO.File]::WriteAllText((Join-Path $Root ('check-' + $index + '.log')),
            (($scenario.logs[$index] -join "`r`n") + "`r`n"), $encoding)
    }
}
function Mutate-Input([string]$Target) {
    Add-Content -LiteralPath (Join-Path $Root $Target) -Value 'changed'
}
$global:executed = @()
$global:listed = 0
$global:taskCalls = 0
$global:betweenChecksMutated = $false
$global:checkpointWrites = 0
# Only filesystem I/O boundaries are mocked. The checkpoint/parser and worker
# catch/finally remain the production implementations.
if ($scenario.checkpoint_failure) {
    function Set-Content {
        [CmdletBinding()]
        param([Parameter(ValueFromPipeline=$true)]$Value, [string]$LiteralPath, [string]$Encoding)
        begin { $values = [Collections.Generic.List[object]]::new() }
        process { $values.Add($Value) }
        end {
            if ($LiteralPath.EndsWith('workspace-recovery-worker.pending.private.json', [StringComparison]::Ordinal)) {
                $global:checkpointWrites += 1
                if ($global:checkpointWrites -eq $scenario.checkpoint_failure -or
                    ($scenario.checkpoint_persistent -and $global:checkpointWrites -ge $scenario.checkpoint_failure)) {
                    throw 'private_fixture_payload'
                }
            }
            $PSBoundParameters['Value'] = $values.ToArray()
            Microsoft.PowerShell.Management\Set-Content @PSBoundParameters
        }
    }
}
if ($scenario.log_io_failure) {
    function Get-Content {
        [CmdletBinding()]
        param([string]$LiteralPath, [switch]$Raw, [string]$Encoding)
        if (-not $Raw -and $LiteralPath -ceq (Join-Path $Root ('check-' + $scenario.log_io_index + '.log'))) {
            throw 'private_fixture_payload'
        }
        Microsoft.PowerShell.Management\Get-Content @PSBoundParameters
    }
}
# A real file hash is returned, then the filesystem changes between the first
# post-check and the next pre-check. This proves each call has its own precheck.
if ($Case -ceq 'worker-between-checks') {
    function Get-FileHash([string]$LiteralPath, [string]$Algorithm) {
        $value = Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
        if ($global:executed.Count -eq 1 -and -not $global:betweenChecksMutated -and
            $LiteralPath -ceq (Join-Path $Root 'verify_windows_service_ci.ps1')) {
            Mutate-Input 'agent.exe'
            $global:betweenChecksMutated = $true
        }
        $value
    }
}
function Invoke-IsolationExecutable([string]$Executable, [string[]]$Arguments, [string]$Log) {
    if ($Executable -cne (Join-Path $Root 'windows_workspace.exe')) { throw 'Incorrect staged executable' }
    if ($env:ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST -cne '1' -or
        $env:ATHERNEX_NATIVE_WORKSPACE_AGENT -cne (Join-Path $Root 'agent.exe') -or
        $env:ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST -or
        $env:ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST -or
        $env:ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST -or $env:ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT) {
        throw 'Incorrect disposable worker environment'
    }
    $index = $global:executed.Count
    if ($Arguments[0] -ceq '--list') {
        if (($Arguments -join '|') -cne '--list|--ignored|--format|terse') { throw 'Incorrect listing arguments' }
        $global:listed += 1
        $names = @($testNames)
        if ($Case -ceq ('worker-missing-test:' + $index)) { $names = @($names | Where-Object { $_ -cne $testNames[$index] }) }
        if ($Case -ceq ('worker-case-test:' + $index)) { $names[$index] = $names[$index].ToUpperInvariant() }
        @($names | ForEach-Object { $_ + ': test' }) | Set-Content -LiteralPath $Log
        return
    }
    if ($index -ge 3 -or ($Arguments -join '|') -cne ('--exact|' + $testNames[$index] + '|--ignored|--test-threads=1|--nocapture') -or
        $Log -cne (Join-Path $Root ('check-' + $index + '.log'))) { throw 'Incorrect exact native invocation' }
    $global:executed += $Arguments[1]
    $lines = @('private_fixture_payload', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;')
    if ($scenario.worker_markers) { $lines = @($scenario.worker_markers) + $lines }
    if ($Case -ceq ('worker-zero-tests:' + $index)) { $lines = @('test result: ok. 0 passed; 0 failed; 0 ignored;') }
    if ($Case -ceq ('worker-ignored:' + $index)) { $lines = @('test result: ok. 1 passed; 0 failed; 1 ignored;') }
    if ($Case -ceq ('worker-failed-count:' + $index)) { $lines = @('test result: ok. 1 passed; 1 failed; 0 ignored;') }
    if ($Case -ceq ('worker-two-tests:' + $index)) { $lines = @('test result: ok. 2 passed; 0 failed; 0 ignored;') }
    $lines | Set-Content -LiteralPath $Log
    if ($Case -ceq ('worker-exit-failure:' + $index)) { throw 'private_fixture_payload' }
    if ($Case.StartsWith('worker-post-input:' + $index + ':')) {
        Mutate-Input ($Case.Split(':')[2])
    }
}
function Invoke-ServiceFixtureTask($TaskName, $Action, $ResultFile, $Hash, $Timeout, $Validator) {
    $global:taskCalls += 1
    if ($Timeout -ne 840 -or $Hash -cne $digest -or $TaskName -cne 'fixture-task' -or
        $ResultFile -cne (Join-Path $Root 'workspace-recovery-worker.private.json')) { throw 'Invalid task binding' }
    if ($Case -ceq 'publish-task-failure') { throw 'private_fixture_payload' }
    if ($scenario.task_error_before) { throw $scenario.task_error_before }
    if ($Case -ceq 'publish-report-failure') { $report.checks.($testNames[1]) = 'not_verified' }
    if ($Case -ceq 'publish-report-error') { $report.error = 'private_fixture_payload' }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile
    if ($scenario.corrupt_report) { Set-Content -LiteralPath $ResultFile -Value '{invalid' }
    if ($scenario.task_error) { throw $scenario.task_error }
    & $Validator $report $Hash
    if ($scenario.cleanup_error) { throw $scenario.cleanup_error }
    if ($Case -ceq 'publish-cleanup-failure') { throw 'private_fixture_payload' }
    if ($Case.StartsWith('publish-change:')) { Mutate-Input $Case.Substring(15) }
    if ($Case -ceq 'publish-report-change') {
        $report.user_sid = 'S-1-5-19'; $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile
    }
    if ($Case -ceq 'publish-missing-report') { Remove-Item -LiteralPath $ResultFile }
}
$environment = @('ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST','ATHERNEX_NATIVE_WORKSPACE_AGENT',
    'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST','ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST',
    'ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT')
$previous = @{}
for ($index=0; $index -lt $environment.Count; $index++) {
    $value = if ($Case -ceq 'worker-empty-environment') { $null } else { 'prior-' + $index }
    [Environment]::SetEnvironmentVariable($environment[$index], $value, 'Process')
    $previous[$environment[$index]] = [Environment]::GetEnvironmentVariable($environment[$index], 'Process')
}
$failed = $false
$caught = $null
$output = @{}
try {
    if ($Case -ceq 'contract') {
        $output.tests = $testNames; $output.inputs = $inputNames
    } elseif ($Case.StartsWith('worker-') -or $Case.StartsWith('input-')) {
        if ($Case.StartsWith('worker-change:')) { Mutate-Input $Case.Substring(14) }
        $workerReport = @{ manifest_sha256=$digest; checks=[ordered]@{}; progress=[ordered]@{}; error=$null }
        foreach ($name in $testNames) { $workerReport.checks[$name] = 'not_verified'; $workerReport.progress[$name] = 'not_attempted' }
        Invoke-WorkspaceRecoveryWorkerChecks $Root $workerReport
    } elseif ($Case.StartsWith('publish-')) {
        $source = if ($Case -ceq 'publish-wrong-source') { 'b'*40 } else { 'a'*40 }
        $boundDigest = if ($Case -ceq 'publish-wrong-digest') { 'b'*64 } else { $digest }
        Invoke-WorkspaceRecoveryEvidence $Root 'fixture-task' @{} $boundDigest $source
    } elseif ($Case -ceq 'guard') {
        Invoke-WorkspaceRecoveryWorker $Root $false
    } elseif ($Case -ceq 'markers') {
        $output.markers = Get-WorkspaceRecoveryLogMarkers (Join-Path $Root 'check-0.log') -RequireLog
    } elseif ($Case -ceq 'classify') {
        $output.categories = @($scenario.messages | ForEach-Object { Get-WorkspaceRecoveryRunnerFailure $_ })
    } else {
        $validationCase = $Case -replace '^partial-', 'report-'
        switch ($validationCase) {
            'report-schema' { $report.schema = 2 }
            'report-schema-string' { $report.schema = '1' }
            'report-schema-float' { $report.schema = 1.0 }
            'report-schema-bool' { $report.schema = $true }
            'report-hash' { $report.manifest_sha256 = 'b'*64 }
            'report-hash-array' { $report.manifest_sha256 = @($digest) }
            'report-hash-object' { $report.manifest_sha256 = @{ value=$digest } }
            'report-hash-unicode' { $report.manifest_sha256 = $digest.Substring(0,1) + [char]0x00ad + $digest.Substring(1) }
            'report-suite' { $report.suite = 'Isolation' }
            'report-missing-suite' { $report.PSObject.Properties.Remove('suite') }
            'report-scope' { $report.proof_scope = 'source_only' }
            'report-account' { $report.user_sid = 'S-1-5-19' }
            'report-session' { $report.session_id = 1 }
            'report-session-string' { $report.session_id = '0' }
            'report-session-float' { $report.session_id = 0.0 }
            'report-session-bool' { $report.session_id = $false }
            'report-native' { $report.native_windows_executed = $false }
            'report-native-string' { $report.native_windows_executed = 'True' }
            'report-native-number' { $report.native_windows_executed = 1 }
            'report-production' { $report.production_readiness = $true }
            'report-production-string' { $report.production_readiness = 'False' }
            'report-production-number' { $report.production_readiness = 0 }
            'report-version' { $report.windows_version = '' }
            'report-error' { $report.error = 'private_fixture_payload' }
            'report-error-false' { $report.error = $false }
            'report-error-number' { $report.error = 0 }
            'report-error-empty' { $report.error = '' }
            'report-extra-test' { $report.checks | Add-Member -NotePropertyName other -NotePropertyValue passed }
        }
        if ($validationCase.StartsWith('report-no-test:')) { $report.checks.PSObject.Properties.Remove($testNames[[int]$validationCase.Split(':')[1]]) }
        if ($validationCase.StartsWith('report-skipped:')) { $report.checks.($testNames[[int]$validationCase.Split(':')[1]]) = 'skipped' }
        if ($validationCase.StartsWith('report-case:')) {
            $name = $testNames[[int]$validationCase.Split(':')[1]]
            $report.checks.PSObject.Properties.Remove($name)
            $report.checks | Add-Member -NotePropertyName $name.ToUpperInvariant() -NotePropertyValue passed
        }
        if ($Case.StartsWith('partial-')) { Assert-WorkspaceRecoveryPartialReport $report $digest }
        else { Assert-WorkspaceRecoveryReport $report $digest }
    }
} catch { $failed = $true; $caught = $_.Exception.Message }
$output.failed = $failed
$output.caught = $caught
$output.executed = @($global:executed)
$output.listed = $global:listed
$output.task_calls = $global:taskCalls
$output.between_checks_mutated = $global:betweenChecksMutated
$output.environment_restored = @($environment | Where-Object {
    [Environment]::GetEnvironmentVariable($_, 'Process') -cne $previous[$_]
}).Count -eq 0
if ($workerReport) { $output.worker = $workerReport }
$checkpointPath = Join-Path $Root 'workspace-recovery-worker.private.json'
if ($workerReport -and (Test-Path -LiteralPath $checkpointPath)) {
    $saved = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json
    $output.checkpoint = @{ progress=$saved.progress; checks=$saved.checks; error=$saved.error }
}
$publicPath = Join-Path $Root 'workspace-recovery-validation.json'
if (Test-Path -LiteralPath $publicPath) { $output.public = Get-Content -LiteralPath $publicPath -Raw | ConvertFrom-Json }
$output | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''


class WorkspaceRecoveryRunnerTests(unittest.TestCase):
    powershell = None
    scenarios = 0

    def run_case(self, case, scenario=None):
        type(self).scenarios += 1
        with tempfile.TemporaryDirectory(prefix='athernex-workspace-evidence-') as temporary:
            root = Path(temporary)
            wrapper = root/'wrapper.ps1'
            wrapper.write_text(WRAPPER)
            configuration = root/'scenario.json'
            configuration.write_text(json.dumps(scenario or {}))
            result = subprocess.run(
                [self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                 str(wrapper), str(SCRIPT), case, str(root), str(configuration)], capture_output=True, text=True,
                timeout=20, env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT='1', POWERSHELL_UPDATECHECK='Off'))
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertNotIn('private_fixture_payload', result.stdout+result.stderr)
            value = json.loads((root/'result.json').read_text(encoding='utf-8-sig'))
            self.assertNotIn('private_fixture_payload', json.dumps(value))
            self.assertTrue(value['environment_restored'], value)
            return value

    def test_fixed_contract_and_disposable_guard(self):
        value = self.run_case('contract')
        self.assertFalse(value['failed'], value)
        self.assertEqual(value['tests'], TESTS)
        self.assertEqual(value['inputs'], INPUTS)
        value = self.run_case('guard')
        self.assertTrue(value['failed'])
        self.assertEqual(value['executed'], [])
        self.assertEqual(value['task_calls'], 0)

    def test_manifest_and_every_staged_input_precede_fixture_execution(self):
        cases = ['input-wrong-suite', 'input-missing-suite', 'input-extra', 'input-missing',
                 'input-case', 'input-source', 'input-schema-string', 'input-schema-float', 'input-schema-bool',
                 'input-suite-array', 'input-suite-object', 'input-source-array', 'input-source-object',
                 'input-hash-array', 'input-hash-object', 'input-suite-unicode',
                 *['worker-change:'+name for name in INPUTS + ['inputs.json']]]
        for case in cases:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['executed'], [])
                self.assertEqual(value['listed'], 0)
                self.assertEqual(value['worker']['error'], 'native_worker_failed')
                self.assertEqual(value['worker']['checks'], dict.fromkeys(TESTS, 'not_verified'))
                self.assertNotIn('public', value)

    def test_private_report_requires_identity_scope_and_all_three_exact_results(self):
        self.assertFalse(self.run_case('report-passed')['failed'])
        cases = ['schema', 'hash', 'hash-array', 'hash-object', 'hash-unicode', 'suite', 'missing-suite', 'scope', 'account', 'session',
                 'native', 'production', 'version', 'error', 'extra-test',
                 'schema-string', 'schema-float', 'schema-bool',
                 'session-string', 'session-float', 'session-bool',
                 'native-string', 'native-number', 'production-string', 'production-number',
                 'error-false', 'error-number', 'error-empty']
        cases += [f'{kind}:{index}' for kind in ['no-test', 'skipped', 'case'] for index in range(3)]
        for case in cases:
            with self.subTest(case=case):
                self.assertTrue(self.run_case('report-'+case)['failed'])

    def test_each_named_test_requires_exact_listing_invocation_and_one_unskipped_success(self):
        for case in ['worker-passed', 'worker-empty-environment']:
            value = self.run_case(case)
            self.assertFalse(value['failed'], value)
            self.assertEqual(value['executed'], TESTS)
            self.assertEqual(value['listed'], 3)
            self.assertEqual(value['worker']['checks'], dict.fromkeys(TESTS, 'passed'))
            self.assertIsNone(value['worker']['error'])
        for index in range(3):
            for kind in ['missing-test', 'case-test', 'zero-tests', 'ignored', 'failed-count', 'two-tests', 'exit-failure']:
                with self.subTest(index=index, kind=kind):
                    value = self.run_case(f'worker-{kind}:{index}')
                    self.assertTrue(value['failed'], value)
                    executed = index if kind in ['missing-test', 'case-test'] else index + 1
                    self.assertEqual(value['executed'], TESTS[:executed])
                    self.assertEqual(value['worker']['error'], 'native_worker_failed')
                    self.assertEqual(value['worker']['checks'], {
                        name: 'passed' if position < index else 'not_verified'
                        for position, name in enumerate(TESTS)})

    def test_hashes_are_rechecked_after_each_test_and_before_the_next(self):
        for index in range(3):
            for name in INPUTS + ['inputs.json']:
                with self.subTest(index=index, name=name):
                    value = self.run_case(f'worker-post-input:{index}:{name}')
                    self.assertTrue(value['failed'], value)
                    self.assertEqual(value['executed'], TESTS[:index+1])
                    self.assertEqual(value['worker']['checks'], {
                        test: 'passed' if position < index else 'not_verified'
                        for position, test in enumerate(TESTS)})
        value = self.run_case('worker-between-checks')
        self.assertTrue(value['failed'], value)
        self.assertTrue(value['between_checks_mutated'], value)
        self.assertEqual(value['executed'], TESTS[:1])
        self.assertEqual(value['listed'], 1)
        self.assertEqual(value['worker']['checks'][TESTS[0]], 'passed')

    def test_public_success_requires_task_cleanup_and_fresh_bound_private_report(self):
        cases = ['publish-passed', 'publish-task-failure', 'publish-cleanup-failure',
                 'publish-report-failure', 'publish-report-error', 'publish-report-change',
                 'publish-missing-report', 'publish-wrong-source', 'publish-wrong-digest',
                 *['publish-change:'+name for name in INPUTS + ['inputs.json']]]
        for case in cases:
            with self.subTest(case=case):
                value = self.run_case(case)
                passed = case == 'publish-passed'
                self.assertEqual(value['failed'], not passed, value)
                self.assertEqual(value['task_calls'], 0 if case in ['publish-wrong-source', 'publish-wrong-digest'] else 1)
                public = value['public']
                self.assertEqual(set(public), {'schema', 'suite', 'proof_scope', 'production_readiness',
                    'manifest_sha256', 'native_workspace_recovery_validation_passed', 'stages', 'checks', 'error',
                    'runner_failure', 'diagnostics'})
                self.assertEqual(public['schema'], 1)
                self.assertEqual(public['suite'], 'WorkspaceRecovery')
                self.assertEqual(public['proof_scope'], 'agent_cleanup_recovery')
                self.assertIs(public['production_readiness'], False)
                self.assertIs(public['native_workspace_recovery_validation_passed'], passed)
                self.assertEqual(public['checks'], dict.fromkeys(TESTS, 'passed' if passed else 'not_verified'))
                self.assertEqual(public['error'], None if passed else 'native_workspace_recovery_not_verified')
                self.assertRegex(public['manifest_sha256'], r'\A[0-9a-f]{64}\Z')
                if passed:
                    self.assertEqual(public['stages'], ['inputs_verified', 'task_completed_and_removed', 'report_verified'])
                    self.assertIsNone(public['runner_failure'])
                    self.assertEqual(public['diagnostics']['status'], 'available')
                elif case in ['publish-wrong-source', 'publish-wrong-digest'] or case.startswith('publish-change:'):
                    self.assertEqual(public['diagnostics'], {'status': 'unbound', 'checks': {}})

    def test_private_progress_is_serial_consistent_and_never_authorizes_success(self):
        for states, error in [(['not_attempted']*3, None), (['attempted', 'not_attempted', 'not_attempted'], None),
                              (['completed', 'failed', 'not_attempted'], 'native_worker_failed'),
                              (['completed', 'not_attempted', 'not_attempted'], 'native_worker_failed'),
                              (['completed']*3, None)]:
            with self.subTest(states=states):
                report = {'progress': dict(zip(TESTS, states)), 'error': error,
                          'checks': {name: 'passed' if state == 'completed' else 'not_verified'
                                     for name, state in zip(TESTS, states)}}
                self.assertFalse(self.run_case('partial-passed', {'report': report})['failed'])
                if states != ['completed']*3:
                    self.assertTrue(self.run_case('report-passed', {'report': report})['failed'])
        cases = ['schema', 'hash', 'hash-array', 'hash-object', 'hash-unicode', 'suite', 'missing-suite', 'scope', 'account', 'session', 'native',
                 'production', 'version', 'error', 'extra-test', 'schema-string', 'schema-float', 'schema-bool',
                 'session-string', 'session-float', 'session-bool', 'native-string', 'native-number',
                 'production-string', 'production-number', 'error-false', 'error-number', 'error-empty']
        cases += [f'{kind}:{index}' for kind in ['no-test', 'skipped', 'case'] for index in range(3)]
        for case in cases:
            with self.subTest(case=case):
                self.assertTrue(self.run_case('partial-'+case)['failed'])
        mutations = [
            {'progress': dict(zip(TESTS, ['not_attempted', 'completed', 'completed']))},
            {'progress': dict(zip(TESTS, ['attempted', 'attempted', 'not_attempted']))},
            {'progress': dict(zip(TESTS, ['failed', 'not_attempted', 'not_attempted'])),
             'checks': dict.fromkeys(TESTS, 'not_verified')},
            {'progress': dict.fromkeys(TESTS, 'passed')},
            {'progress': dict.fromkeys(TESTS, 1)},
            {'progress': {**dict.fromkeys(TESTS, 'completed'), 'other': 'completed'}},
            {'progress': dict.fromkeys([TESTS[0].upper(), *TESTS[1:]], 'completed')},
            {'progress': dict.fromkeys(TESTS[:2], 'completed')},
            {'checks': dict.fromkeys(TESTS, True)},
            {'suite': ['WorkspaceRecovery']}, {'proof_scope': ['agent_cleanup_recovery']},
            {'user_sid': ['S-1-5-18']}, {'windows_version': ['fixture']},
            {'raw_output': 'private_fixture_payload'}, {'progress': None},
            {'progress': dict.fromkeys(TESTS, 'comple\u00adted')},
            {'error': 'native_worker_\u00adfailed'},
        ]
        for report in mutations:
            with self.subTest(fields=list(report)):
                self.assertTrue(self.run_case('partial-passed', {'report': report})['failed'])
        self.assertTrue(self.run_case('partial-passed', {'remove_fields': ['progress']})['failed'])

    def test_full_and_partial_identity_and_results_reject_collection_coercion(self):
        fields = {'suite': 'WorkspaceRecovery', 'proof_scope': 'agent_cleanup_recovery',
                  'user_sid': 'S-1-5-18', 'windows_version': 'fixture'}
        for prefix in ['report-', 'partial-']:
            for name, scalar in fields.items():
                values = [[scalar], {'value': scalar}]
                if name != 'windows_version':
                    values.append(scalar[:1]+'\u00ad'+scalar[1:])
                for value in values:
                    with self.subTest(prefix=prefix, field=name, value_type=type(value).__name__):
                        self.assertTrue(self.run_case(prefix+'passed', {'report': {name: value}})['failed'])
            for index, name in enumerate(TESTS):
                for value in [['passed'], {'value': 'passed'}, 'pass\u00aded']:
                    with self.subTest(prefix=prefix, check=index, value_type=type(value).__name__):
                        checks = {**dict.fromkeys(TESTS, 'passed'), name: value}
                        self.assertTrue(self.run_case(prefix+'passed', {'report': {'checks': checks}})['failed'])

    def test_failed_tasks_can_only_publish_bound_diagnostic_progress(self):
        errors = [
            ('Native service task failed: 1', 'task_failed_with_report'),
            ('Native service task deadline elapsed without a completed, valid report', 'task_timeout'),
            ('Fixture task ownership changed; retained for inspection', 'task_ownership_failed'),
            ('Fixture task did not stop; retained for inspection', 'task_stop_failed'),
        ]
        for message, category in errors:
            with self.subTest(category=category):
                value = self.run_case('publish-passed', {'cleanup_error': message})
                public = value['public']
                self.assertTrue(value['failed'])
                self.assertFalse(public['native_workspace_recovery_validation_passed'])
                self.assertEqual(public['checks'], dict.fromkeys(TESTS, 'not_verified'))
                self.assertEqual(public['runner_failure'], category)
                self.assertEqual(public['diagnostics']['status'], 'available')
                self.assertEqual([public['diagnostics']['checks'][name]['progress'] for name in TESTS], ['completed']*3)
        report = {'progress': dict(zip(TESTS, ['completed', 'failed', 'not_attempted'])),
                  'checks': dict(zip(TESTS, ['passed', 'not_verified', 'not_verified'])), 'error': 'native_worker_failed'}
        value = self.run_case('publish-passed', {
            'report': report, 'task_error': 'Native service task failed: 1',
            'logs': [['ATHERNEX_WORKSPACE_STAGE=guard_verified'],
                     ['ATHERNEX_WORKSPACE_STAGE=preview_prepared', 'ATHERNEX_WORKSPACE_EXIT=preview_recovery:-1',
                      'ATHERNEX_WORKSPACE_FAILURE=invalid_scratch_request', 'private_fixture_payload'],
                     ['ATHERNEX_WORKSPACE_STAGE=workspace_cleanup_verified']]})
        public = value['public']
        self.assertTrue(value['failed'])
        self.assertEqual(public['checks'], dict.fromkeys(TESTS, 'not_verified'))
        self.assertEqual(public['runner_failure'], 'task_failed_with_report')
        self.assertEqual(public['diagnostics']['checks'][TESTS[1]], {
            'progress': 'failed', 'stages': ['preview_prepared'], 'failures': ['invalid_scratch_request'],
            'exits': [{'operation': 'preview_recovery', 'exit_code': -1}]})
        self.assertEqual(public['diagnostics']['checks'][TESTS[2]], {
            'progress': 'not_attempted', 'stages': [], 'failures': [], 'exits': []})
        # A valid initialized or partial checkpoint can never satisfy the full validator.
        for states in [['not_attempted']*3, ['completed', 'attempted', 'not_attempted']]:
            report = {'progress': dict(zip(TESTS, states)),
                      'checks': {name: 'passed' if state == 'completed' else 'not_verified'
                                 for name, state in zip(TESTS, states)}}
            value = self.run_case('publish-passed', {'report': report})
            self.assertTrue(value['failed'])
            self.assertEqual(value['public']['runner_failure'], 'report_check_failed')
            self.assertEqual(value['public']['diagnostics']['status'], 'available')
            self.assertEqual(value['public']['checks'], dict.fromkeys(TESTS, 'not_verified'))

    def test_missing_corrupt_stale_and_unbound_diagnostics_are_not_projected(self):
        value = self.run_case('publish-passed', {'task_error_before': 'Native service task failed before writing its report: 4294967295'})
        self.assertEqual(value['public']['runner_failure'], 'task_failed_without_report')
        self.assertEqual(value['public']['diagnostics'], {'status': 'missing', 'checks': {}})
        cases = [{'report': {'suite': 'Isolation'}}, {'report': {'manifest_sha256': 'b'*64}},
                 {'report': {'schema': '1'}}, {'report': {'session_id': '0'}},
                 {'report': {'native_windows_executed': 'True'}}, {'report': {'production_readiness': 'False'}},
                 {'report': {'error': 'private_fixture_payload'}}, {'report': {'error': False}},
                 {'report': {'progress': dict.fromkeys(TESTS, 'private_fixture_payload')}},
                 {'remove_fields': ['progress']}, {'corrupt_report': True},
                 {'report': {key: 'private_fixture_payload' for key in ['raw_output', 'credential', 'nonce', 'state_path']}}]
        for scenario in cases:
            with self.subTest(fields=list(scenario)):
                value = self.run_case('publish-passed', {**scenario, 'task_error': 'Native service task failed: 1'})
                self.assertTrue(value['failed'])
                self.assertEqual(value['public']['diagnostics'], {'status': 'invalid', 'checks': {}})
                self.assertEqual(value['public']['checks'], dict.fromkeys(TESTS, 'not_verified'))
        value = self.run_case('publish-passed', {'cleanup_error': 'Fixture task did not stop; retained for inspection',
            'logs': [['ATHERNEX_WORKSPACE_STAGE=guard_verified']], 'log_io_failure': True, 'log_io_index': 0})
        self.assertEqual(value['public']['diagnostics'], {'status': 'unavailable', 'checks': {}})
        self.assertFalse(value['public']['native_workspace_recovery_validation_passed'])
        for name in INPUTS + ['inputs.json']:
            with self.subTest(missing_input=name):
                value = self.run_case('publish-passed', {'remove_input': name})
                self.assertTrue(value['failed'])
                self.assertEqual(value['task_calls'], 0)
                self.assertEqual(value['public']['runner_failure'],
                                 'input_manifest_invalid' if name == 'inputs.json' else 'input_file_invalid')
                self.assertEqual(value['public']['diagnostics'], {'status': 'unbound', 'checks': {}})

    def test_marker_grammar_is_closed_bounded_and_bom_aware(self):
        lines = ['ATHERNEX_WORKSPACE_STAGE='+tag for tag in STAGES]
        lines += ['ATHERNEX_WORKSPACE_FAILURE='+tag for tag in FAILURES]
        lines += ['ATHERNEX_WORKSPACE_EXIT=scratch_cleanup:-2147483648',
                  'ATHERNEX_WORKSPACE_EXIT=preview_recovery:0', 'ATHERNEX_WORKSPACE_EXIT=workspace_cleanup:2147483647']
        expected = {'stages': STAGES, 'failures': FAILURES,
                    'exits': [{'operation': 'scratch_cleanup', 'exit_code': -2147483648},
                              {'operation': 'preview_recovery', 'exit_code': 0},
                              {'operation': 'workspace_cleanup', 'exit_code': 2147483647}]}
        for encoding in ['utf8', 'utf8bom', 'utf16le']:
            with self.subTest(encoding=encoding):
                value = self.run_case('markers', {'logs': [lines], 'log_encoding': encoding})
                self.assertFalse(value['failed'])
                self.assertEqual(value['markers'], expected)
        invalid = []
        for line in lines:
            invalid += [' '+line, line+' ', line+'private_fixture_payload', line.lower(), '\t'+line,
                        line+'\x00', line+'\u200b', line.replace('ATHERNEX', 'ＡＴＨＥＲＮＥＸ')]
        invalid += ['ATHERNEX_WORKSPACE_STAGE=unknown', 'ATHERNEX_WORKSPACE_FAILURE=unknown',
                    'ATHERNEX_WORKSPACE_EXIT=private_fixture_payload:1']
        invalid += ['ATHERNEX_WORKSPACE_EXIT=scratch_cleanup:'+value for value in
                    ['-0', '+1', '01', '-01', '2147483648', '-2147483649', '99999999999',
                     '1.0', '1e2', '١', '１', '', ' 1', '1 ', '--1']]
        value = self.run_case('markers', {'logs': [invalid]})
        self.assertEqual(value['markers'], {'stages': [], 'failures': [], 'exits': []})
        value = self.run_case('markers', {'logs': [lines[:32]*4 + ['ATHERNEX_WORKSPACE_EXIT=scratch_cleanup:1']*40]})
        self.assertEqual(value['markers']['stages'], STAGES)
        self.assertEqual(value['markers']['failures'], FAILURES)
        self.assertEqual(len(value['markers']['exits']), 32)

    def test_checkpoint_and_log_io_failures_stop_work_and_restore_environment(self):
        for checkpoint in range(1, 7):
            with self.subTest(checkpoint=checkpoint):
                value = self.run_case('worker-passed', {'checkpoint_failure': checkpoint})
                self.assertTrue(value['failed'])
                self.assertEqual(value['executed'], TESTS[:checkpoint//2])
                failed_index = (checkpoint-1)//2
                states = ['completed' if i < failed_index else 'failed' if i == failed_index else 'not_attempted' for i in range(3)]
                self.assertEqual(value['worker']['progress'], dict(zip(TESTS, states)))
                self.assertEqual(value['checkpoint']['progress'], dict(zip(TESTS, states)))
                self.assertEqual(value['checkpoint']['error'], 'native_worker_failed')
        value = self.run_case('worker-passed', {'checkpoint_failure': 2, 'checkpoint_persistent': True})
        self.assertTrue(value['failed'])
        self.assertEqual(value['executed'], TESTS[:1])
        self.assertEqual(value['checkpoint']['progress'][TESTS[0]], 'attempted')
        self.assertEqual(value['checkpoint']['checks'], dict.fromkeys(TESTS, 'not_verified'))
        for index in range(3):
            with self.subTest(log_index=index):
                value = self.run_case('worker-passed', {'log_io_failure': True, 'log_io_index': index})
                self.assertTrue(value['failed'])
                self.assertEqual(value['executed'], TESTS[:index+1])
                self.assertEqual(value['worker']['progress'][TESTS[index]], 'failed')
                self.assertEqual(value['checkpoint']['error'], 'native_worker_failed')

    def test_runner_failure_categories_never_contain_exception_text(self):
        known = {
            'Workspace-recovery input manifest changed': 'input_manifest_changed',
            'Invalid workspace-recovery input manifest': 'input_manifest_invalid',
            'Staged workspace-recovery input changed': 'input_file_changed',
            'Staged workspace-recovery input invalid': 'input_file_invalid',
            'Invalid workspace-recovery worker identity or result': 'report_identity_invalid',
            'Incomplete workspace-recovery check set': 'report_check_set_invalid',
            'Workspace-recovery native check did not pass': 'report_check_failed',
            'Native service task deadline elapsed without a completed, valid report': 'task_timeout',
            'Fixture task already exists': 'task_ownership_failed',
            'Fixture task ownership changed; retained for inspection': 'task_ownership_failed',
            'Fixture task did not stop; retained for inspection': 'task_stop_failed',
            'Native service task failed: 1': 'task_failed_with_report',
            'Native service task failed: 4294967295': 'task_failed_with_report',
            'Native service task failed before writing its report: 1': 'task_failed_without_report',
        }
        invalid = [message+' private_fixture_payload' for message in known]
        invalid += ['native service task failed: 1', 'Native service task failed: 01', 'Native service task failed: -1',
                    'Native service task failed: +1', 'Native service task failed: 4294967296',
                    'Native service task failed: ١', 'Native service task failed: 1\n', 'private_fixture_payload']
        value = self.run_case('classify', {'messages': list(known)+invalid})
        self.assertEqual(value['categories'], list(known.values())+['other']*len(invalid))

    @classmethod
    def tearDownClass(cls):
        print(f'PowerShell scenarios: {cls.scenarios}')

    def test_workflow_stages_release_agent_and_only_uploads_public_projection(self):
        workflow = (SCRIPT.parent.parent/'.github/workflows/endpoint.yml').read_text()
        job = workflow.split('  windows-workspace-recovery:\n', 1)[1].split('  windows-authentication:\n', 1)[0]
        self.assertIn('cargo build --locked --release -p athernex-endpoint', job)
        self.assertIn('--test windows_workspace', job)
        self.assertIn('tools/verify_windows_workspace_ci.ps1 -AgentExecutable', job)
        paths = job.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], [
            '${{ runner.temp }}/native-windows-workspace-recovery/inputs.json',
            '${{ runner.temp }}/native-windows-workspace-recovery/workspace-recovery-validation.json'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('pwsh') or shutil.which('powershell'))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; use --powershell')
    WorkspaceRecoveryRunnerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
