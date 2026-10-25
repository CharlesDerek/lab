#!/usr/bin/env python3
"""Exercise the actual PowerShell runner with fake Task Scheduler commands.

No Windows task, service, user or ACL is created. These are runner control-flow
checks, not evidence that the six native service checks passed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('verify_windows_service_ci.ps1')
CHECKS = [
    'registration_is_stopped_local_system_and_exactly_bound',
    'scm_host_owns_actual_launcher_controller_and_agent',
    'live_host_retains_installer_exclusion',
    'clean_stop_confirms_entire_owned_tree_and_terminal_diagnostic',
    'explicit_restart_creates_a_new_owned_tree',
    'host_crash_cleans_descendants_and_scm_recovers',
]
WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$ResultFile, [string]$TraceFile)
$ErrorActionPreference = 'Stop'
. $Script
$global:trace = [Collections.Generic.List[string]]::new()
$global:registered = $false
$global:started = $false
$global:stopped = $false
$global:clock = 0
$action = [pscustomobject]@{ Execute='fixture-powershell'; Arguments='fixture-arguments' }
function New-ScheduledTaskPrincipal {
    param($UserId,$LogonType,$RunLevel)
    if ($UserId -ne 'S-1-5-18' -or $LogonType -ne 'ServiceAccount' -or $RunLevel -ne 'Highest') { throw 'Incorrect principal' }
    [pscustomobject]@{ UserId=$UserId }
}
function New-ScheduledTaskSettingsSet {
    param($ExecutionTimeLimit,$MultipleInstances)
    if ($ExecutionTimeLimit.TotalSeconds -ne 30 -or $MultipleInstances -ne 'IgnoreNew') { throw 'Incorrect task limit' }
    [pscustomobject]@{ ExecutionTimeLimit=$ExecutionTimeLimit }
}
function Register-ScheduledTask {
    param($TaskName,$Action,$Principal,$Settings,$ErrorAction)
    $global:trace.Add('register')
    if ($Case -eq 'registration-fails') { throw 'Registration failed' }
    $global:registered = $true
}
function Start-ScheduledTask {
    param($TaskName,$ErrorAction)
    $global:trace.Add('start')
    if ($Case -eq 'start-fails') { throw 'Start failed' }
    $global:started = $true
}
function Get-ScheduledTask {
    param($TaskName,$ErrorAction)
    if ($TaskName -ne 'fixture-task') { throw 'Unexpected task name' }
    if (-not $global:registered -and $Case -ne 'existing-task') { return $null }
    $state = 'Ready'
    if ($global:started -and -not $global:stopped -and $Case -in @('running-timeout','stop-fails','stop-stuck')) { $state = 'Running' }
    $observed = $action
    if ($Case -eq 'changed-task' -and $global:started) { $observed = [pscustomobject]@{ Execute='someone-else'; Arguments='foreign' } }
    [pscustomobject]@{ State=$state; Actions=@($observed) }
}
function Get-ScheduledTaskInfo {
    param($TaskName,$ErrorAction)
    [pscustomobject]@{ LastTaskResult=$(if ($Case -in @('task-fails','exit-fails')) { 1 } else { 0 });
        LastRunTime=$(if ($Case -eq 'never-started') { [datetime]::new(1999,1,1) } else { [datetime]::new(2026,1,1) }) }
}
function Disable-ScheduledTask { param($TaskName,$ErrorAction); $global:trace.Add('disable') }
function Stop-ScheduledTask {
    param($TaskName,$ErrorAction)
    $global:trace.Add('stop')
    if ($Case -eq 'stop-fails') { throw 'Stop failed' }
    if ($Case -ne 'stop-stuck') { $global:stopped = $true }
}
function Unregister-ScheduledTask {
    param($TaskName,[bool]$Confirm,$ErrorAction)
    if ($Confirm) { throw 'Interactive cleanup requested' }
    $global:trace.Add('unregister')
}
function Get-Date { $global:clock += 10; [datetime]::new(2026,1,1).AddSeconds($global:clock) }
function Start-Sleep { param($Milliseconds) }
foreach ($name in @('New-ScheduledTaskPrincipal','New-ScheduledTaskSettingsSet','Register-ScheduledTask',
    'Start-ScheduledTask','Get-ScheduledTask','Get-ScheduledTaskInfo','Disable-ScheduledTask','Stop-ScheduledTask','Unregister-ScheduledTask')) {
    if ((Get-Command $name).CommandType -ne 'Function') { throw ('Missing mock: ' + $name) }
}
$failure = $null
try {
    if ($Case -in @('custom-passed','custom-fails')) {
        Invoke-ServiceFixtureTask 'fixture-task' $action $ResultFile ('a'*64) 60 {
            param($Report, $ExpectedHash)
            $global:trace.Add('validate-custom')
            if ($Case -eq 'custom-fails' -or $Report.custom_hash -cne $ExpectedHash) { throw 'Custom report rejected' }
        }
    } else { Invoke-ServiceFixtureTask 'fixture-task' $action $ResultFile ('a'*64) 60 }
}
catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; trace=@($global:trace.ToArray()) } |
    ConvertTo-Json | Set-Content -LiteralPath $TraceFile -Encoding UTF8
if ($failure) { exit 1 }
'''

EVIDENCE_WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root)
$ErrorActionPreference = 'Stop'
. $Script
$manifest = @{ schema=1; suite='Service'; github_sha=('c'*40); runner_sha256=('d'*64); sha256=@{} }
foreach ($name in @('agent.exe','tools/verify_windows_service.ps1','core-engines/endpoint/src/installer/register.ps1')) {
    $path = Join-Path $Root $name
    $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $path))
    Set-Content -LiteralPath $path -Value 'private_fixture_payload, never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifestPath = Join-Path $Root 'inputs.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath
$hash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$digest = $manifest.sha256.'agent.exe'
if ($Case -eq 'changed-manifest') { Add-Content -LiteralPath $manifestPath -Value ' ' }
if ($Case -eq 'changed-script') { Add-Content -LiteralPath (Join-Path $Root 'tools/verify_windows_service.ps1') -Value 'changed' }
if ($Case -eq 'wrong-agent-binding') { $digest = 'e'*64 }
$global:executed = $false
function Invoke-ServiceFixtureTask($TaskName,$Action,$ResultFile,$AgentSha256) {
    $global:executed = $true
    $report = @{ schema=1; native_windows_executed=$true; production_readiness=$false;
        agent_sha256=$AgentSha256; user_sid='S-1-5-18'; session_id=0; error=$null;
        windows_version='private_fixture_payload'; fixture='private_fixture_payload';
        process_trees=@(@{ pid=999999; created=123456789; path='private_fixture_payload' });
        credential='private_fixture_payload'; raw_xml='<Event>private_fixture_payload</Event>'; checks=[ordered]@{} }
    foreach ($name in Get-ServiceChecks) { $report.checks[$name] = 'passed' }
    switch ($Case) {
        'skipped-check' { $report.checks['explicit_restart_creates_a_new_owned_tree'] = 'skipped' }
        'raw-check' { $report.checks['explicit_restart_creates_a_new_owned_tree'] = 'private_fixture_payload' }
        'extra-check' { $report.checks['private_fixture_payload'] = 'passed' }
        'raw-error' { $report.error = 'private_fixture_payload' }
        'wrong-identity' { $report.user_sid = 'private_fixture_payload' }
        'changed-after-task' { Add-Content -LiteralPath (Join-Path $Root 'agent.exe') -Value 'changed' }
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile
    'private_fixture_payload' | Set-Content -LiteralPath (Join-Path $Root 'service-validation.log')
    if ($Case -eq 'raw-exception') { throw 'private_fixture_payload' }
    if ($Case -eq 'missing-report') { Remove-Item -LiteralPath $ResultFile }
}
$failure = $null
try { Invoke-ServiceFixtureEvidence $Root 'private_fixture_payload' @{} $hash $digest }
catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; executed=$global:executed;
   manifest_sha256=$hash; agent_sha256=$digest } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'trace.json')
'''


class ServiceRunnerTests(unittest.TestCase):
    powershell = None

    def run_case(self, case, report=None):
        with tempfile.TemporaryDirectory(prefix='athernex-service-ci-') as temporary:
            root = Path(temporary)
            wrapper = root/'wrapper.ps1'
            wrapper.write_text(WRAPPER, encoding='utf-8')
            result = root/'report.json'
            if report is not None:
                result.write_text(json.dumps(report), encoding='utf-8')
            trace = root/'trace.json'
            completed = subprocess.run(
                [self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                 str(wrapper), str(SCRIPT), case, str(result), str(trace)],
                capture_output=True, text=True, timeout=20,
                env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT='1', POWERSHELL_UPDATECHECK='Off'))
            self.assertTrue(trace.exists(), completed.stdout+completed.stderr)
            value = json.loads(trace.read_text(encoding='utf-8-sig'))
            self.assertEqual(completed.returncode != 0, value['failed'], value)
            return value

    @staticmethod
    def report():
        return dict(schema=1, native_windows_executed=True, production_readiness=False,
                    agent_sha256='a'*64, user_sid='S-1-5-18', session_id=0,
                    windows_version='10.0.fixture', fixture='private-fixture', error=None,
                    checks=dict.fromkeys(CHECKS, 'passed'))

    def test_completed_native_report_and_successful_exit_are_both_required(self):
        value = self.run_case('passed', self.report())
        self.assertFalse(value['failed'], value)
        self.assertEqual(value['trace'], ['register','start','disable','unregister'])
        for case in ['exit-fails', 'never-started', 'missing-report', 'task-fails']:
            with self.subTest(case=case):
                value = self.run_case(case, self.report() if case == 'exit-fails' else None)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['trace'], ['register','start','disable','unregister'])

    def test_incomplete_failed_or_wrong_identity_reports_cannot_pass(self):
        for field, wrong in [('schema', 2), ('native_windows_executed', False),
                             ('production_readiness', True), ('agent_sha256', 'b'*64),
                             ('user_sid', 'S-1-5-32-544'), ('session_id', 1), ('error', 'cleanup failed'),
                             ('windows_version', None), ('fixture', None), ('checks', {})]:
            with self.subTest(field=field):
                report = self.report()
                report[field] = wrong
                self.assertTrue(self.run_case('invalid-report', report)['failed'])
        for check in CHECKS:
            with self.subTest(check=check):
                report = self.report()
                report['checks'][check] = 'skipped'
                self.assertTrue(self.run_case('invalid-report', report)['failed'])

    def test_registration_and_start_failures_preserve_ownership_boundary(self):
        for case, trace in [('existing-task', []), ('registration-fails', ['register']),
                            ('start-fails', ['register','start','disable','unregister'])]:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['trace'], trace)

    def test_timeout_stops_owned_task_and_never_passes(self):
        value = self.run_case('running-timeout')
        self.assertTrue(value['failed'], value)
        self.assertEqual(value['trace'], ['register','start','disable','stop','unregister'])

    def test_changed_or_unstoppable_tasks_are_retained(self):
        for case, trace in [('changed-task', ['register','start']),
                            ('stop-fails', ['register','start','disable','stop']),
                            ('stop-stuck', ['register','start','disable','stop'])]:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['trace'], trace)

    def test_custom_report_validator_is_required_and_preserves_task_cleanup(self):
        for case in ['custom-passed', 'custom-fails']:
            with self.subTest(case=case):
                value = self.run_case(case, dict(custom_hash='a'*64))
                self.assertEqual(value['failed'], case == 'custom-fails', value)
                self.assertEqual(value['trace'], ['register', 'start', 'validate-custom', 'disable', 'unregister'])

    def run_evidence_case(self, case):
        with tempfile.TemporaryDirectory(prefix='athernex-service-evidence-') as temporary:
            root = Path(temporary)
            wrapper = root/'wrapper.ps1'
            wrapper.write_text(EVIDENCE_WRAPPER, encoding='utf-8')
            completed = subprocess.run(
                [self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                 str(wrapper), str(SCRIPT), case, str(root)], capture_output=True, text=True, timeout=20,
                env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT='1', POWERSHELL_UPDATECHECK='Off'))
            self.assertEqual(completed.returncode, 0, completed.stdout+completed.stderr)
            trace = json.loads((root/'trace.json').read_text(encoding='utf-8-sig'))
            public = json.loads((root/'service-validation.json').read_text(encoding='utf-8-sig'))
            self.assertNotIn('private_fixture_payload', json.dumps(public)+json.dumps(trace)+completed.stdout+completed.stderr)
            self.assertEqual(set(public), {'schema', 'suite', 'manifest_sha256', 'agent_sha256',
                                          'native_service_validation_passed', 'production_readiness',
                                          'stages', 'checks', 'error'})
            self.assertEqual(public['manifest_sha256'], trace['manifest_sha256'])
            self.assertEqual(public['agent_sha256'], trace['agent_sha256'])
            self.assertEqual(set(public['checks']), set(CHECKS))
            self.assertFalse(public['production_readiness'])
            if trace['executed']:
                self.assertIn('private_fixture_payload', (root/'service-validation.log').read_text(encoding='utf-8-sig'))
            return trace, public

    def test_public_evidence_excludes_fixture_metadata_and_raw_logs(self):
        trace, public = self.run_evidence_case('passed')
        self.assertFalse(trace['failed'], trace)
        self.assertTrue(public['native_service_validation_passed'])
        self.assertIsNone(public['error'])
        self.assertEqual(public['checks'], dict.fromkeys(CHECKS, 'passed'))
        self.assertEqual(public['stages'], ['inputs_verified', 'task_completed', 'report_verified'])

    def test_public_failures_are_fixed_and_cannot_hide_invalid_native_evidence(self):
        for case in ['skipped-check', 'raw-check', 'extra-check', 'raw-error', 'wrong-identity',
                     'raw-exception', 'missing-report', 'changed-after-task']:
            with self.subTest(case=case):
                trace, public = self.run_evidence_case(case)
                self.assertTrue(trace['failed'], trace)
                self.assertTrue(trace['executed'])
                self.assertFalse(public['native_service_validation_passed'])
                self.assertEqual(public['error'], 'native_service_validation_failed')
                self.assertEqual(public['checks'], dict.fromkeys(CHECKS, 'not_verified'))

    def test_manifest_source_and_executable_binding_fail_before_native_execution(self):
        for case in ['changed-manifest', 'changed-script', 'wrong-agent-binding']:
            with self.subTest(case=case):
                trace, public = self.run_evidence_case(case)
                self.assertTrue(trace['failed'], trace)
                self.assertFalse(trace['executed'])
                self.assertFalse(public['native_service_validation_passed'])
                self.assertEqual(public['error'], 'native_service_validation_failed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('pwsh') or shutil.which('powershell'))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; use --powershell')
    ServiceRunnerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
