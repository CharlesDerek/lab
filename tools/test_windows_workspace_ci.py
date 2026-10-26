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
WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root)
$ErrorActionPreference = 'Stop'
. $Script
. (Join-Path (Split-Path -Parent $Script) 'verify_windows_isolation_ci.ps1')
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
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath
$digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$report = [pscustomobject]@{ schema=1; suite='WorkspaceRecovery'; proof_scope='agent_cleanup_recovery';
    native_windows_executed=$true; production_readiness=$false; manifest_sha256=$digest;
    user_sid='S-1-5-18'; session_id=0; windows_version='fixture'; error=$null;
    checks=[pscustomobject]@{}; private_payload='private_fixture_payload';
    raw_output='private_fixture_payload'; process_id=1234; state_path='private_fixture_payload';
    nonce='private_fixture_payload'; credential='private_fixture_payload' }
foreach ($name in $testNames) { $report.checks | Add-Member -NotePropertyName $name -NotePropertyValue passed }
function Mutate-Input([string]$Target) {
    Add-Content -LiteralPath (Join-Path $Root $Target) -Value 'changed'
}
$global:executed = @()
$global:listed = 0
$global:taskCalls = 0
$global:betweenChecksMutated = $false
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
    if ($Case -ceq 'publish-report-failure') { $report.checks.($testNames[1]) = 'not_verified' }
    if ($Case -ceq 'publish-report-error') { $report.error = 'private_fixture_payload' }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile
    & $Validator $report $Hash
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
        $workerReport = @{ manifest_sha256=$digest; checks=[ordered]@{}; error=$null }
        foreach ($name in $testNames) { $workerReport.checks[$name] = 'not_verified' }
        Invoke-WorkspaceRecoveryWorkerChecks $Root $workerReport
    } elseif ($Case.StartsWith('publish-')) {
        $source = if ($Case -ceq 'publish-wrong-source') { 'b'*40 } else { 'a'*40 }
        $boundDigest = if ($Case -ceq 'publish-wrong-digest') { 'b'*64 } else { $digest }
        Invoke-WorkspaceRecoveryEvidence $Root 'fixture-task' @{} $boundDigest $source
    } elseif ($Case -ceq 'guard') {
        Invoke-WorkspaceRecoveryWorker $Root $false
    } else {
        switch ($Case) {
            'report-schema' { $report.schema = 2 }
            'report-schema-string' { $report.schema = '1' }
            'report-schema-float' { $report.schema = 1.0 }
            'report-schema-bool' { $report.schema = $true }
            'report-hash' { $report.manifest_sha256 = 'b'*64 }
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
        if ($Case.StartsWith('report-no-test:')) { $report.checks.PSObject.Properties.Remove($testNames[[int]$Case.Split(':')[1]]) }
        if ($Case.StartsWith('report-skipped:')) { $report.checks.($testNames[[int]$Case.Split(':')[1]]) = 'skipped' }
        if ($Case.StartsWith('report-case:')) {
            $name = $testNames[[int]$Case.Split(':')[1]]
            $report.checks.PSObject.Properties.Remove($name)
            $report.checks | Add-Member -NotePropertyName $name.ToUpperInvariant() -NotePropertyValue passed
        }
        Assert-WorkspaceRecoveryReport $report $digest
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
$publicPath = Join-Path $Root 'workspace-recovery-validation.json'
if (Test-Path -LiteralPath $publicPath) { $output.public = Get-Content -LiteralPath $publicPath -Raw | ConvertFrom-Json }
$output | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''


class WorkspaceRecoveryRunnerTests(unittest.TestCase):
    powershell = None

    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='athernex-workspace-evidence-') as temporary:
            root = Path(temporary)
            wrapper = root/'wrapper.ps1'
            wrapper.write_text(WRAPPER)
            result = subprocess.run(
                [self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                 str(wrapper), str(SCRIPT), case, str(root)], capture_output=True, text=True,
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
        cases = ['schema', 'hash', 'suite', 'missing-suite', 'scope', 'account', 'session',
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
                    'manifest_sha256', 'native_workspace_recovery_validation_passed', 'stages', 'checks', 'error'})
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
