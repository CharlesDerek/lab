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
try { Invoke-ServiceFixtureTask 'fixture-task' $action $ResultFile ('a'*64) 60 }
catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; trace=@($global:trace.ToArray()) } |
    ConvertTo-Json | Set-Content -LiteralPath $TraceFile -Encoding UTF8
if ($failure) { exit 1 }
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('pwsh') or shutil.which('powershell'))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; use --powershell')
    ServiceRunnerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
