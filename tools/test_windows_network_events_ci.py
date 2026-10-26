#!/usr/bin/env python3
"""Exercise network-events evidence gates without privileged Windows actions."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('verify_windows_network_events_ci.ps1')
TESTS = ['telemetry::windows_network_events::native_test::network_reports_replay_with_visible_capture_gaps']
INPUTS = ['agent.exe', 'endpoint-tests.exe', 'verify_windows_network_events_ci.ps1',
          'verify_windows_isolation_ci.ps1', 'verify_windows_service_ci.ps1']
STAGES = ['guard_verified', 'agent_config_verified', 'source_ready', 'tcp4_verified', 'tcp6_verified', 'udp4_verified', 'udp6_verified', 'tdh_differential_verified', 'coexistence_verified', 'source_loss_verified', 'stalled_http_verified', 'queue_loss_verified', 'crash_replay_verified', 'orphan_recovered', 'session_gap_verified', 'http_delivery_verified', 'server_replay_verified', 'export_authorization_verified', 'original_export_verified', 'portal_coverage_verified', 'rollout_gates_verified', 'server_restart_verified', 'cleanup_verified', 'token_verified', 'passed']
FAILURES = ['guard', 'token', 'configuration', 'ownership', 'source_start', 'source_stopped', 'controlled_traffic', 'tdh_schema', 'tdh_property', 'native_loss', 'durable_admission', 'transport', 'replay', 'authorization', 'original_export', 'portal', 'rollout', 'cleanup', 'timeout']
OPERATIONS = ['start_trace', 'open_trace', 'query_trace', 'stop_trace', 'process_trace', 'close_trace', 'token_query', 'tdh_information', 'tdh_format_property']
WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$Configuration)
$ErrorActionPreference = 'Stop'
. $Script
. (Join-Path (Split-Path -Parent $Script) 'verify_windows_isolation_ci.ps1')
$scenario = Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
$testNames = @(Get-NetworkEventsTests)
$inputNames = @(Get-NetworkEventsInputNames)
$manifest = @{ schema=1; suite='NetworkEvents'; github_sha=('a'*40); sha256=@{} }
foreach ($name in $inputNames) {
    Set-Content -LiteralPath (Join-Path $Root $name) -Value 'fixture never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath (Join-Path $Root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifestPath = Join-Path $Root 'inputs.json'
switch ($Case) {
    'input-wrong-suite' { $manifest.suite = 'Isolation' }
    'input-missing-suite' { $manifest.Remove('suite') }
    'input-extra' { $manifest.sha256['unexpected'] = 'b'*64 }
    'input-missing' { $manifest.sha256.Remove('endpoint-tests.exe') }
    'input-case' {
        $value = $manifest.sha256['endpoint-tests.exe']; $manifest.sha256.Remove('endpoint-tests.exe'); $manifest.sha256['ENDPOINT-TESTS.EXE'] = $value
    }
    'input-source' { $manifest.github_sha = 'private_fixture_payload' }
    'input-schema-string' { $manifest.schema = '1' }
    'input-schema-float' { $manifest.schema = 1.0 }
    'input-schema-bool' { $manifest.schema = $true }
    'input-suite-array' { $manifest.suite = @('NetworkEvents') }
    'input-suite-object' { $manifest.suite = @{ value='NetworkEvents' } }
    'input-source-array' { $manifest.github_sha = @('a'*40) }
    'input-source-object' { $manifest.github_sha = @{ value=('a'*40) } }
    'input-hash-array' { $manifest.sha256['endpoint-tests.exe'] = @($manifest.sha256['endpoint-tests.exe']) }
    'input-hash-object' { $manifest.sha256['endpoint-tests.exe'] = @{ value=$manifest.sha256['endpoint-tests.exe'] } }
    'input-suite-unicode' { $manifest.suite = 'Authentication' + [char]0x00ad + 'Agent' }
}
function Write-JsonFixture([string]$Path, $Value, [string]$Mode) {
    $raw = $Value | ConvertTo-Json -Depth 6
    switch ($Mode) {
        'duplicate' { $raw = '{"schema":1,' + $raw.Substring(1) }
        'case_alias' { $raw = '{"SCHEMA":1,' + $raw.Substring(1) }
        'escaped_key' { $raw = $raw.Replace('"schema"', '"\u0073chema"') }
        'nested_duplicate' {
            if ($Value.sha256) {
                $name = $inputNames[0]; $entry = '"' + $name + '":"' + $Value.sha256.$name + '",'
                $raw = [regex]::Replace($raw, '("sha256"\s*:\s*\{)', ('$1'+$entry))
            } else {
                $entry = '"' + $testNames[0] + '":"passed",'
                $raw = [regex]::Replace($raw, '("checks"\s*:\s*\{)', ('$1'+$entry))
            }
        }
        'unknown' { $raw = '{"unexpected":"private_fixture_payload",' + $raw.Substring(1) }
        'oversized' { $raw += (' ' * 65537) }
        'array' { $raw = '[' + $raw + ']' }
        'comment' { $raw = '/* private_fixture_payload */' + $raw }
    }
    $encoding = switch ($scenario.json_encoding) {
        'utf16le' { [Text.Encoding]::Unicode }
        'utf8bom' { [Text.UTF8Encoding]::new($true) }
        default { [Text.UTF8Encoding]::new($false) }
    }
    [IO.File]::WriteAllText($Path, $raw, $encoding)
}
Write-JsonFixture $manifestPath $manifest $scenario.manifest_mode
$digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($scenario.remove_input) { Remove-Item -LiteralPath (Join-Path $Root $scenario.remove_input) }
$report = [pscustomobject]@{ schema=1; suite='NetworkEvents'; proof_scope='component_and_agent';
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
            if ($LiteralPath.EndsWith('network-events-worker.pending.private.json', [StringComparison]::Ordinal)) {
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
function Get-FixtureSourceLines {
    $values = @(Get-NetworkEventsStageNames | ForEach-Object { 'ATHERNEX_NETWORK_EVENTS_STAGE=' + $_ })
    if ($scenario.omit_stage) { $values = @($values | Where-Object { $_ -cne ('ATHERNEX_NETWORK_EVENTS_STAGE=' + $scenario.omit_stage) }) }
    if ($scenario.source_failure) { $values += 'ATHERNEX_NETWORK_EVENTS_FAILURE=' + $scenario.source_failure }
    if ($scenario.source_markers) { $values += @($scenario.source_markers) }
    $values
}
function Invoke-IsolationExecutable([string]$Executable, [string[]]$Arguments, [string]$Log) {
    if ($Executable -cne (Join-Path $Root 'endpoint-tests.exe')) { throw 'Incorrect staged executable' }
    if ($env:ATHERNEX_WINDOWS_NETWORK_EVENTS_DISPOSABLE_HOST -cne '1' -or
        $env:ATHERNEX_NATIVE_NETWORK_EVENTS_AGENT -cne (Join-Path $Root 'agent.exe') -or
        $env:ATHERNEX_WINDOWS_AUTHENTICATION_AGENT_DISPOSABLE_HOST -or $env:ATHERNEX_NATIVE_AUTHENTICATION_AGENT -or
        $env:ATHERNEX_WINDOWS_NETWORK_EVENTS_PROBE_DISPOSABLE_HOST -or
        $env:ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST -or $env:ATHERNEX_NATIVE_WORKSPACE_AGENT -or
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
    if ($index -ge 1 -or ($Arguments -join '|') -cne ('--exact|' + $testNames[$index] + '|--ignored|--test-threads=1|--nocapture') -or
        $Log -cne (Join-Path $Root ('check-' + $index + '.log'))) { throw 'Incorrect exact native invocation' }
    $global:executed += $Arguments[1]
    $lines = @(Get-FixtureSourceLines) + @('private_fixture_payload', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;')
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
        $ResultFile -cne (Join-Path $Root 'network-events-worker.private.json')) { throw 'Invalid task binding' }
    if (-not $scenario.logs) { @(Get-FixtureSourceLines) | Set-Content -LiteralPath (Join-Path $Root 'check-0.log') }
    if ($Case -ceq 'publish-task-failure') { throw 'private_fixture_payload' }
    if ($scenario.task_error_before) { throw $scenario.task_error_before }
    if ($Case -ceq 'publish-report-failure') { $report.checks.($testNames[0]) = 'not_verified' }
    if ($Case -ceq 'publish-report-error') { $report.error = 'private_fixture_payload' }
    Write-JsonFixture $ResultFile $report $scenario.report_mode
    if ($scenario.corrupt_report) { Set-Content -LiteralPath $ResultFile -Value '{invalid' }
    if ($scenario.task_error) { throw $scenario.task_error }
    & $Validator $report $Hash
    if ($scenario.post_task_failure) { Add-Content -LiteralPath (Join-Path $Root 'check-0.log') -Value 'ATHERNEX_NETWORK_EVENTS_FAILURE=source_start' }
    if ($scenario.post_task_markers) { Add-Content -LiteralPath (Join-Path $Root 'check-0.log') -Value @($scenario.post_task_markers) }
    if ($scenario.post_task_missing_log) { Remove-Item -LiteralPath (Join-Path $Root 'check-0.log') }
    if ($scenario.cleanup_error) { throw $scenario.cleanup_error }
    if ($Case -ceq 'publish-cleanup-failure') { throw 'private_fixture_payload' }
    if ($Case.StartsWith('publish-change:')) { Mutate-Input $Case.Substring(15) }
    if ($Case -ceq 'publish-report-change') {
        $report.user_sid = 'S-1-5-19'; $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile
    }
    if ($Case -ceq 'publish-missing-report') { Remove-Item -LiteralPath $ResultFile }
}
$environment = @('ATHERNEX_WINDOWS_NETWORK_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_NETWORK_EVENTS_AGENT',
    'ATHERNEX_WINDOWS_AUTHENTICATION_AGENT_DISPOSABLE_HOST','ATHERNEX_NATIVE_AUTHENTICATION_AGENT',
    'ATHERNEX_WINDOWS_NETWORK_EVENTS_PROBE_DISPOSABLE_HOST','ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST','ATHERNEX_NATIVE_WORKSPACE_AGENT',
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
        $output.stages = @(Get-NetworkEventsStageNames); $output.failures = @(Get-NetworkEventsFailureNames); $output.operations = @(Get-NetworkEventsOperationNames)
    } elseif ($Case.StartsWith('worker-') -or $Case.StartsWith('input-')) {
        if ($Case.StartsWith('worker-change:')) { Mutate-Input $Case.Substring(14) }
        $workerReport = @{ manifest_sha256=$digest; checks=[ordered]@{}; progress=[ordered]@{}; error=$null }
        foreach ($name in $testNames) { $workerReport.checks[$name] = 'not_verified'; $workerReport.progress[$name] = 'not_attempted' }
        Invoke-NetworkEventsWorkerChecks $Root $workerReport
    } elseif ($Case.StartsWith('publish-')) {
        $source = if ($Case -ceq 'publish-wrong-source') { 'b'*40 } else { 'a'*40 }
        $boundDigest = if ($Case -ceq 'publish-wrong-digest') { 'b'*64 } else { $digest }
        Invoke-NetworkEventsEvidence $Root 'fixture-task' @{} $boundDigest $source
    } elseif ($Case -ceq 'guard') {
        Invoke-NetworkEventsWorker $Root $false
    } elseif ($Case -ceq 'markers') {
        $output.markers = Get-NetworkEventsLogMarkers (Join-Path $Root 'check-0.log') -RequireLog
    } elseif ($Case -ceq 'markers-assert') {
        @(Get-FixtureSourceLines) | Set-Content -LiteralPath (Join-Path $Root 'check-0.log')
        $markers = Get-NetworkEventsLogMarkers (Join-Path $Root 'check-0.log') -RequireLog
        foreach ($property in $scenario.marker_overrides.PSObject.Properties) { $markers[$property.Name] = $property.Value }
        Assert-NetworkEventsMarkers $markers
    } elseif ($Case -ceq 'classify') {
        $output.categories = @($scenario.messages | ForEach-Object { Get-NetworkEventsRunnerFailure $_ })
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
        if ($Case.StartsWith('partial-')) { Assert-NetworkEventsPartialReport $report $digest }
        else { Assert-NetworkEventsReport $report $digest }
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
$checkpointPath = Join-Path $Root 'network-events-worker.private.json'
if ($workerReport -and (Test-Path -LiteralPath $checkpointPath)) {
    $saved = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json
    $output.checkpoint = @{ progress=$saved.progress; checks=$saved.checks; error=$saved.error }
}
$publicPath = Join-Path $Root 'network-events-validation.json'
if (Test-Path -LiteralPath $publicPath) { $output.public = Get-Content -LiteralPath $publicPath -Raw | ConvertFrom-Json }
$output | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''


class NetworkEventsRunnerTests(unittest.TestCase):
    powershell = None
    scenarios = 0

    def run_case(self, case, scenario=None):
        type(self).scenarios += 1
        with tempfile.TemporaryDirectory(prefix='athernex-auth-agent-evidence-') as temporary:
            root = Path(temporary)
            wrapper = root/'wrapper.ps1'
            wrapper.write_text(WRAPPER)
            configuration = root/'scenario.json'
            configuration.write_text(json.dumps(scenario or {}))
            result = subprocess.run(
                [self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                 str(wrapper), str(SCRIPT), case, str(root), str(configuration)],
                capture_output=True, text=True, timeout=20,
                env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT='1', POWERSHELL_UPDATECHECK='Off'))
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertNotIn('private_fixture_payload', result.stdout+result.stderr)
            value = json.loads((root/'result.json').read_text(encoding='utf-8-sig'))
            self.assertNotIn('private_fixture_payload', json.dumps(value))
            self.assertTrue(value['environment_restored'], value)
            return value

    def assert_public_failed(self, value):
        self.assertTrue(value['failed'], value)
        public = value['public']
        self.assertIs(public['native_network_events_validation_passed'], False)
        self.assertIs(public['production_readiness'], False)
        self.assertEqual(public['checks'], dict.fromkeys(TESTS, 'not_verified'))
        self.assertEqual(public['error'], 'native_network_events_not_verified')
        self.assertIsInstance(public['runner_failure'], str)
        return public

    def test_fixed_component_and_agent_contract_and_disposable_guard(self):
        value = self.run_case('contract')
        self.assertFalse(value['failed'])
        for field, expected in [('tests', TESTS), ('inputs', INPUTS), ('stages', STAGES),
                                ('failures', FAILURES), ('operations', OPERATIONS)]:
            self.assertEqual(value[field], expected)
        value = self.run_case('guard')
        self.assertTrue(value['failed'])
        self.assertEqual(value['executed'], [])
        self.assertEqual(value['task_calls'], 0)
        self.assertNotIn('checkpoint', value)

    def test_manifest_and_every_input_are_bound_before_native_execution(self):
        cases = ['input-wrong-suite', 'input-missing-suite', 'input-extra', 'input-missing', 'input-case',
                 'input-source', 'input-schema-string', 'input-schema-float', 'input-schema-bool',
                 'input-suite-array', 'input-suite-object', 'input-source-array', 'input-source-object',
                 'input-hash-array', 'input-hash-object', 'input-suite-unicode',
                 *['worker-change:'+name for name in INPUTS+['inputs.json']]]
        for case in cases:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['executed'], [])
                self.assertEqual(value['listed'], 0)
                self.assertEqual(value['worker']['checks'], dict.fromkeys(TESTS, 'not_verified'))
                self.assertEqual(value['worker']['error'], 'native_worker_failed')

    def test_full_and_partial_reports_require_exact_typed_identity(self):
        cases = ['schema', 'hash', 'hash-array', 'hash-object', 'hash-unicode', 'suite', 'missing-suite',
                 'scope', 'account', 'session', 'native', 'production', 'version', 'error', 'extra-test',
                 'schema-string', 'schema-float', 'schema-bool', 'session-string', 'session-float',
                 'session-bool', 'native-string', 'native-number', 'production-string', 'production-number',
                 'error-false', 'error-number', 'error-empty', 'no-test:0', 'skipped:0', 'case:0']
        for prefix in ['report-', 'partial-']:
            self.assertFalse(self.run_case(prefix+'passed')['failed'])
            for case in cases:
                with self.subTest(prefix=prefix, case=case):
                    self.assertTrue(self.run_case(prefix+case)['failed'])
            for name, scalar in [('suite', 'NetworkEvents'), ('proof_scope', 'component_and_agent'), ('user_sid', 'S-1-5-18')]:
                for value in [[scalar], {'value': scalar}, scalar[:1]+'\u00ad'+scalar[1:]]:
                    with self.subTest(prefix=prefix, field=name, kind=type(value).__name__):
                        self.assertTrue(self.run_case(prefix+'passed', {'report': {name: value}})['failed'])
            for value in [['passed'], {'value': 'passed'}, 'pass\u00aded']:
                self.assertTrue(self.run_case(prefix+'passed', {'report': {'checks': {TESTS[0]: value}}})['failed'])
            for value in [['fixture'], {'value': 'fixture'}]:
                self.assertTrue(self.run_case(prefix+'passed', {'report': {'windows_version': value}})['failed'])

    def test_partial_progress_never_authorizes_success_or_private_fields(self):
        for state, error in [('not_attempted', None), ('attempted', None), ('failed', 'native_worker_failed')]:
            report = {'progress': {TESTS[0]: state}, 'checks': {TESTS[0]: 'not_verified'}, 'error': error}
            self.assertFalse(self.run_case('partial-passed', {'report': report})['failed'])
            self.assertTrue(self.run_case('report-passed', {'report': report})['failed'])
            public = self.assert_public_failed(self.run_case('publish-passed', {'report': report}))
            self.assertEqual(public['diagnostics']['status'], 'available')
            self.assertEqual(public['diagnostics']['checks'][TESTS[0]]['progress'], state)
        for report in [
            {'progress': {TESTS[0]: 'attempted'}}, {'progress': {TESTS[0]: 'comple\u00adted'}},
            {'progress': {TESTS[0]: ['completed']}}, {'progress': {TESTS[0]: 1}},
            {'progress': {TESTS[0]: 'completed', 'other': 'completed'}},
            {'progress': {TESTS[0].upper(): 'completed'}}, {'progress': None},
            {'error': 'native_worker_\u00adfailed'}, {'raw_output': 'private_fixture_payload'},
        ]:
            self.assertTrue(self.run_case('partial-passed', {'report': report})['failed'])
        self.assertTrue(self.run_case('partial-passed', {'remove_fields': ['progress']})['failed'])
        self.assertTrue(self.run_case('report-passed', {'remove_fields': ['progress']})['failed'])

    def test_exact_one_libtest_and_all_source_proof_markers_are_required(self):
        for case in ['worker-passed', 'worker-empty-environment']:
            value = self.run_case(case)
            self.assertFalse(value['failed'], value)
            self.assertEqual(value['executed'], TESTS)
            self.assertEqual(value['listed'], 1)
            self.assertEqual(value['worker']['checks'], dict.fromkeys(TESTS, 'passed'))
            self.assertEqual(value['checkpoint']['progress'], dict.fromkeys(TESTS, 'completed'))
        for kind in ['missing-test', 'case-test', 'zero-tests', 'ignored', 'failed-count', 'two-tests', 'exit-failure']:
            value = self.run_case('worker-'+kind+':0')
            self.assertTrue(value['failed'], value)
            self.assertEqual(value['executed'], [] if kind in ['missing-test', 'case-test'] else TESTS)
            self.assertEqual(value['worker']['checks'], dict.fromkeys(TESTS, 'not_verified'))
        for field, values in [('omit_stage', STAGES)]:
            for missing in values:
                with self.subTest(field=field, missing=missing):
                    worker = self.run_case('worker-passed', {field: missing})
                    self.assertTrue(worker['failed'])
                    self.assertEqual(worker['worker']['checks'], dict.fromkeys(TESTS, 'not_verified'))
                    self.assert_public_failed(self.run_case('publish-passed', {field: missing}))
        for scenario in [{'source_failure': failure} for failure in FAILURES]:
            self.assertTrue(self.run_case('worker-passed', scenario)['failed'])
            public = self.assert_public_failed(self.run_case('publish-passed', scenario))
            self.assertEqual(public['runner_failure'], 'source_proof_failed')

    def test_post_execution_hash_and_io_failures_stop_success_and_restore_environment(self):
        for name in INPUTS+['inputs.json']:
            with self.subTest(input=name):
                value = self.run_case('worker-post-input:0:'+name)
                self.assertTrue(value['failed'])
                self.assertEqual(value['executed'], TESTS)
                self.assertEqual(value['checkpoint']['progress'], dict.fromkeys(TESTS, 'failed'))
        for checkpoint in [1, 2]:
            value = self.run_case('worker-passed', {'checkpoint_failure': checkpoint})
            self.assertTrue(value['failed'])
            self.assertEqual(value['executed'], [] if checkpoint == 1 else TESTS)
            self.assertEqual(value['checkpoint']['progress'], dict.fromkeys(TESTS, 'failed'))
            self.assertEqual(value['checkpoint']['error'], 'native_worker_failed')
        value = self.run_case('worker-passed', {'checkpoint_failure': 2, 'checkpoint_persistent': True})
        self.assertTrue(value['failed'])
        self.assertEqual(value['checkpoint']['progress'], dict.fromkeys(TESTS, 'attempted'))
        self.assertEqual(value['checkpoint']['checks'], dict.fromkeys(TESTS, 'not_verified'))
        value = self.run_case('worker-passed', {'log_io_failure': True, 'log_io_index': 0})
        self.assertTrue(value['failed'])
        self.assertEqual(value['checkpoint']['progress'], dict.fromkeys(TESTS, 'failed'))

    def test_public_success_requires_full_report_task_cleanup_fresh_hashes_and_log(self):
        value = self.run_case('publish-passed')
        self.assertFalse(value['failed'], value)
        public = value['public']
        self.assertEqual(set(public), {'schema', 'suite', 'proof_scope', 'production_readiness', 'manifest_sha256',
            'native_network_events_validation_passed', 'stages', 'checks', 'error', 'runner_failure', 'diagnostics'})
        self.assertIs(public['native_network_events_validation_passed'], True)
        self.assertIs(public['production_readiness'], False)
        self.assertEqual(public['proof_scope'], 'component_and_agent')
        self.assertEqual(public['stages'], ['inputs_verified', 'task_completed_and_removed', 'report_verified'])
        self.assertEqual(public['checks'], dict.fromkeys(TESTS, 'passed'))
        self.assertIsNone(public['error'])
        self.assertIsNone(public['runner_failure'])
        self.assertEqual(public['diagnostics']['status'], 'available')
        diagnostic = public['diagnostics']['checks'][TESTS[0]]
        self.assertEqual(set(diagnostic), {'progress', 'stages', 'failures', 'api_errors'})
        self.assertEqual(diagnostic['stages'], STAGES)
        self.assertEqual(diagnostic['failures'], [])
        self.assertEqual(diagnostic['api_errors'], [])
        cases = ['publish-task-failure', 'publish-cleanup-failure', 'publish-report-failure', 'publish-report-error',
                 'publish-report-change', 'publish-missing-report', 'publish-wrong-source', 'publish-wrong-digest',
                 *['publish-change:'+name for name in INPUTS+['inputs.json']]]
        for case in cases:
            with self.subTest(case=case):
                public = self.assert_public_failed(self.run_case(case))
                if case in ['publish-wrong-source', 'publish-wrong-digest'] or case.startswith('publish-change:'):
                    self.assertEqual(public['diagnostics'], {'status': 'unbound', 'checks': {}})
        for scenario, category in [({'post_task_failure': True}, 'source_proof_failed'),
                                   ({'post_task_missing_log': True}, 'source_log_unavailable'),
                                   ({'log_io_failure': True, 'log_io_index': 0}, 'source_log_unavailable')]:
            public = self.assert_public_failed(self.run_case('publish-passed', scenario))
            self.assertEqual(public['runner_failure'], category)
        for message, category in [
            ('Native service task failed: 1', 'task_failed_with_report'),
            ('Native service task deadline elapsed without a completed, valid report', 'task_timeout'),
            ('Fixture task ownership changed; retained for inspection', 'task_ownership_failed'),
            ('Fixture task did not stop; retained for inspection', 'task_stop_failed'),
        ]:
            public = self.assert_public_failed(self.run_case('publish-passed', {'cleanup_error': message}))
            self.assertEqual(public['runner_failure'], category)
            self.assertEqual(public['diagnostics']['checks'][TESTS[0]]['progress'], 'completed')

    def test_unbound_or_malformed_private_reports_cannot_supply_public_diagnostics(self):
        public = self.assert_public_failed(self.run_case('publish-passed', {
            'task_error_before': 'Native service task failed before writing its report: 4294967295'}))
        self.assertEqual(public['runner_failure'], 'task_failed_without_report')
        self.assertEqual(public['diagnostics'], {'status': 'missing', 'checks': {}})
        cases = [{'report': {'suite': 'Isolation'}}, {'report': {'manifest_sha256': 'b'*64}},
                 {'report': {'schema': '1'}}, {'report': {'session_id': '0'}},
                 {'report': {'native_windows_executed': 'True'}}, {'report': {'production_readiness': 'False'}},
                 {'report': {'error': False}}, {'report': {'progress': {TESTS[0]: 'private_fixture_payload'}}},
                 {'remove_fields': ['progress']}, {'corrupt_report': True},
                 {'report': {key: 'private_fixture_payload' for key in ['raw_output', 'credential', 'nonce', 'state_path']}}]
        for scenario in cases:
            public = self.assert_public_failed(self.run_case('publish-passed', {
                **scenario, 'task_error': 'Native service task failed: 1'}))
            self.assertEqual(public['diagnostics'], {'status': 'invalid', 'checks': {}})
        for name in INPUTS+['inputs.json']:
            public = self.assert_public_failed(self.run_case('publish-passed', {'remove_input': name}))
            self.assertEqual(public['diagnostics'], {'status': 'unbound', 'checks': {}})






    def test_runner_failure_categories_never_publish_exception_text(self):
        known = {
            'Network-events input manifest changed': 'input_manifest_changed',
            'Invalid network-events input manifest': 'input_manifest_invalid',
            'Staged network-events input changed': 'input_file_changed',
            'Staged network-events input invalid': 'input_file_invalid',
            'Invalid network-events worker identity or result': 'report_identity_invalid',
            'Incomplete network-events check set': 'report_check_set_invalid',
            'Network-events native check did not pass': 'report_check_failed',
            'Network-events proof has contradictory failure evidence': 'source_proof_failed',
            'Network-events proof is incomplete': 'source_proof_incomplete',
            'Network-events diagnostic log unavailable': 'source_log_unavailable',
            'Native service task deadline elapsed without a completed, valid report': 'task_timeout',
            'Fixture task already exists': 'task_ownership_failed',
            'Fixture task ownership changed; retained for inspection': 'task_ownership_failed',
            'Fixture task did not stop; retained for inspection': 'task_stop_failed',
            'Native service task failed: 1': 'task_failed_with_report',
            'Native service task failed: 4294967295': 'task_failed_with_report',
            'Native service task failed before writing its report: 1': 'task_failed_without_report',
        }
        invalid = [message+' private_fixture_payload' for message in known]
        invalid += ['Native service task failed: 01', 'Native service task failed: -1',
                    'Native service task failed: 4294967296', 'Native service task failed: 1\n',
                    'native service task failed: 1', 'private_fixture_payload']
        self.assertEqual(self.run_case('classify', {'messages': list(known)+invalid})['categories'],
                         list(known.values())+['other']*len(invalid))

    def test_workflow_binds_release_agent_and_libtest_and_uploads_exact_two_public_files(self):
        workflow = (SCRIPT.parent.parent/'.github/workflows/endpoint.yml').read_text()
        job = workflow.split('  windows-network-events:\n', 1)[1].split('  windows-authentication-agent:\n', 1)[0]
        self.assertIn('cargo test --locked -p athernex-endpoint --lib --no-run', job)
        self.assertIn('cargo build --locked --release -p athernex-endpoint --bin athernex-endpoint', job)
        self.assertIn('tools/verify_windows_network_events_ci.ps1 -AgentExecutable', job)
        self.assertIn('timeout-minutes: 15', job)
        paths = job.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], [
            '${{ runner.temp }}/native-windows-network-events/inputs.json',
            '${{ runner.temp }}/native-windows-network-events/network-events-validation.json'])

    def test_fixed_markers_reject_payload_injection_and_other_fixture_prefixes(self):
        lines = ['ATHERNEX_NETWORK_EVENTS_STAGE='+tag for tag in STAGES]
        lines += ['ATHERNEX_NETWORK_EVENTS_FAILURE='+tag for tag in FAILURES]
        for encoding in ['utf8', 'utf8bom', 'utf16le']:
            markers = self.run_case('markers', {'logs': [lines*3], 'log_encoding': encoding})['markers']
            self.assertEqual(markers, {'stages': STAGES, 'failures': FAILURES, 'api_errors': []})
        invalid = []
        for line in lines:
            invalid += [' '+line, line+' ', '\t'+line, line+'private_fixture_payload', line.lower(),
                        line+'\x00', line+'\u200b', line.replace('ATHERNEX', 'ＡＴＨＥＲＮＥＸ'),
                        json.dumps([line]), json.dumps({'marker': line}), line+'\\rextra']
        invalid += ['ATHERNEX_NETWORK_EVENTS_STAGE=unknown', 'ATHERNEX_NETWORK_EVENTS_FAILURE=unknown',
                    'ATHERNEX_AUTH_STAGE=cleanup_verified', 'ATHERNEX_AUTH_STAGE=passed',
                    'ATHERNEX_NETWORK_EVENTS_STAGE=cleanup_\u00adverified',
                    'ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=source:5']
        self.assertTrue(self.run_case('markers', {'logs': [invalid]})['failed'])
        for field in ['stages', 'failures', 'api_errors']:
            for value in [None, '', {}, 0, False, ['private_fixture_payload']]:
                self.assertTrue(self.run_case('markers-assert', {'marker_overrides': {field: value}})['failed'])
        for value in [[STAGES[0]], {'value': STAGES[0]}]:
            self.assertTrue(self.run_case('markers-assert', {'marker_overrides': {'stages': [value]+STAGES[1:]}})['failed'])
        for failure in FAILURES:
            public = self.assert_public_failed(self.run_case('publish-passed', {
                'post_task_markers': ['ATHERNEX_NETWORK_EVENTS_FAILURE='+failure]}))
            self.assertEqual(public['runner_failure'], 'source_proof_failed')
            self.assertEqual(public['diagnostics']['checks'][TESTS[0]]['failures'], [failure])

    def test_failed_replay_with_verified_cleanup_never_promotes_acceptance(self):
        stages = STAGES[:STAGES.index('crash_replay_verified')] + ['cleanup_verified']
        logs = ['ATHERNEX_NETWORK_EVENTS_STAGE='+stage for stage in stages]
        logs += ['ATHERNEX_NETWORK_EVENTS_FAILURE=replay']
        scenario = {'report': {'checks': dict.fromkeys(TESTS, 'not_verified'),
            'progress': dict.fromkeys(TESTS, 'failed'), 'error': 'native_worker_failed'},
            'logs': [logs], 'task_error': 'Native service task failed: 1'}
        public = self.assert_public_failed(self.run_case('publish-passed', scenario))
        diagnostic = public['diagnostics']['checks'][TESTS[0]]
        self.assertEqual(diagnostic, {'progress': 'failed', 'stages': stages, 'failures': ['replay'], 'api_errors': []})
        self.assertNotIn('passed', diagnostic['stages'])
        self.assertNotIn('http_delivery_verified', diagnostic['stages'])
        # Even a contradictory complete worker report cannot use cleanup to
        # replace a missing body proof or erase its fixed failure category.
        self.assert_public_failed(self.run_case('publish-passed', {'logs': [logs]}))

    def test_api_diagnostics_are_canonical_bounded_and_always_refuse_acceptance(self):
        lines = ['ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC='+op+':'+str(code)
                 for op in OPERATIONS for code in [0, 4294967295]]
        expected = [{'operation': op, 'win32_error': code}
                    for op in OPERATIONS for code in [0, 4294967295]]
        for encoding in ['utf8', 'utf8bom', 'utf16le']:
            markers = self.run_case('markers', {'logs': [lines], 'log_encoding': encoding})['markers']
            self.assertEqual(markers, {'stages': [], 'failures': [], 'api_errors': expected})
        invalid = []
        for line in lines:
            invalid += [' '+line, line+' ', line+'private_fixture_payload', line.lower(), line+'\x00',
                        line+'\u200b', line.replace('ATHERNEX', 'ＡＴＨＥＲＮＥＸ'), json.dumps([line]),
                        json.dumps({'marker': line}), line+'\\rextra']
        invalid += ['ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=start_trace:'+value
                    for value in ['00', '01', '-0', '-1', '+1', '1.0', '1e1', '4294967296',
                                  '99999999999999999', '١', '１', '1\\nprivate_fixture_payload', '']]
        invalid += ['ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=unknown:1',
                    'ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=Start_trace:1',
                    'ATHERNEX_NETWORK_SOURCE_DIAGNOSTIC=start_trace:1']
        self.assertTrue(self.run_case('markers', {'logs': [invalid]})['failed'])
        bounded = self.run_case('markers', {'logs': [lines*4]})['markers']['api_errors']
        self.assertEqual(bounded, (expected*4)[:32])
        for op in OPERATIONS:
            marker = 'ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC='+op+':5'
            self.assertTrue(self.run_case('worker-passed', {'source_markers': [marker]})['failed'])
            public = self.assert_public_failed(self.run_case('publish-passed', {'post_task_markers': [marker]}))
            self.assertEqual(public['runner_failure'], 'source_proof_failed')
            self.assertEqual(public['diagnostics']['checks'][TESTS[0]]['api_errors'],
                             [{'operation': op, 'win32_error': 5}])

    def test_raw_json_duplicate_unknown_keys_and_bounds_refuse_fresh_public_success(self):
        for mode in ['duplicate', 'case_alias', 'escaped_key', 'nested_duplicate', 'unknown',
                     'oversized', 'array', 'comment']:
            with self.subTest(manifest=mode):
                value = self.run_case('publish-passed', {'manifest_mode': mode})
                public = self.assert_public_failed(value)
                self.assertEqual(public['diagnostics'], {'status': 'unbound', 'checks': {}})
                self.assertEqual(value['task_calls'], 0)
            with self.subTest(report=mode):
                public = self.assert_public_failed(self.run_case('publish-passed', {'report_mode': mode}))
                self.assertEqual(public['diagnostics'], {'status': 'invalid', 'checks': {}})
        # Scalar/object/array substitutions cannot smuggle a false passed status.
        for key in ['checks', 'progress']:
            for value in [[], [dict.fromkeys(TESTS, 'passed' if key == 'checks' else 'completed')],
                          'passed', 1, True, None]:
                self.assertTrue(self.run_case('report-passed', {'report': {key: value}})['failed'])
        for encoding in ['utf8', 'utf8bom', 'utf16le']:
            value = self.run_case('publish-passed', {'json_encoding': encoding})
            self.assertFalse(value['failed'], value)
        # Malformed own-prefix markers refuse the proof without exposing their text.
        # They cannot replace any missing required phase or a real libtest result.
        public = self.assert_public_failed(self.run_case('publish-passed', {
            'omit_stage': 'source_ready', 'post_task_markers': ['ATHERNEX_NETWORK_EVENTS_STAGE=source_ready private_fixture_payload']}))
        self.assertEqual(public['diagnostics'], {'status': 'unavailable', 'checks': {}})

    def test_own_namespace_invalid_evidence_blocks_complete_worker_and_final_proof(self):
        invalid = [
            'ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=unknown:1',
            'ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=start_trace:4294967296',
            'ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=start_trace:01',
            'ATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=start_trace:١',
            'ATHERNEX_NETWORK_EVENTS_FAILURE=unknown',
            'ATHERNEX_NETWORK_EVENTS_STAGE=passed private_fixture_payload',
            'ATHERNEX_NETWORK_EVENTS_STAGE=Passed',
            'ATHERNEX_NETWORK_EVENTS_SCHEMA=private_fixture_payload',
        ]
        for marker in invalid:
            with self.subTest(marker=marker.split('=', 1)[0]):
                worker = self.run_case('worker-passed', {'source_markers': [marker]})
                self.assertTrue(worker['failed'])
                self.assertEqual(worker['checkpoint']['progress'], dict.fromkeys(TESTS, 'failed'))
                public = self.assert_public_failed(self.run_case('publish-passed', {'post_task_markers': [marker]}))
                self.assertEqual(public['runner_failure'], 'source_proof_failed')
                self.assertEqual(public['diagnostics'], {'status': 'unavailable', 'checks': {}})
        unrelated = ['private_fixture_payload', 'ATHERNEX_NETWORK_SOURCE_DIAGNOSTIC=start_trace:5',
                     'ATHERNEX_AUTH_AGENT_FAILURE=cleanup', ' ATHERNEX_NETWORK_EVENTS_STAGE=unknown',
                     'athernex_network_events_diagnostic=unknown:1']
        self.assertEqual(self.run_case('markers', {'logs': [unrelated]})['markers'],
                         {'stages': [], 'failures': [], 'api_errors': []})

    @classmethod
    def tearDownClass(cls):
        print(f'PowerShell scenarios: {cls.scenarios}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('pwsh') or shutil.which('powershell'))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; use --powershell')
    NetworkEventsRunnerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
