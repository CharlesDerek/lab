#!/usr/bin/env python3
"""Run production Windows installer PowerShell with mocked OS commands.

Checks guarded SCM registration and scheduled-task migration control flow.
No actual Windows service, scheduled task or endpoint installation is changed.
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

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'infrastructure/endpoint/install.ps1'
REGISTER = ROOT / 'core-engines/endpoint/src/installer/register.ps1'
WRAPPER = r'''
param([string]$Script, [string]$Mode)
$ErrorActionPreference = 'Stop'
# Let the real PowerShell/CLR initialize with the host environment. Replacing
# SystemRoot before process startup prevents Windows cryptographic DLL loading.
# Once the wrapper is running, every installer OS command below is mocked.
$env:ProgramFiles = $env:ATHERNEX_FIXTURE_PROGRAM_FILES
$env:ProgramData = $env:ATHERNEX_FIXTURE_PROGRAM_DATA
$env:SystemRoot = $env:ATHERNEX_FIXTURE_SYSTEM_ROOT
$global:trace = [Collections.Generic.List[object]]::new()
$global:serviceStopped = $false
$global:serviceStarted = $false
$global:taskStopped = $false
$global:clockCalls = 0
$global:LASTEXITCODE = 0
function Fixture-Paths {
    if ($Mode -eq 'register') {
        return @($env:ATHERNEX_INSTALL_STATE, $env:ATHERNEX_INSTALL_LAUNCHER, $env:ATHERNEX_INSTALL_CONTROLLER, $env:ATHERNEX_INSTALL_AGENT)
    }
    $folder = Join-Path $env:ProgramFiles 'Athernex Endpoint'
    @((Join-Path $env:ProgramData 'AthernexEndpoint'), (Join-Path $folder 'athernex-launcher.exe'),
      (Join-Path $folder 'athernex-controller.exe'), (Join-Path $folder 'athernex-endpoint.exe'))
}
function Invoke-Fixture {
    $global:trace.Add(@{ call = 'endpoint'; arguments = @($args) })
    $global:LASTEXITCODE = 0
    if (($args[0] -eq 'installer-check' -and $env:ATHERNEX_CASE -eq 'preflight-fails') -or
        ($args[0] -eq 'windows-install' -and $env:ATHERNEX_CASE -eq 'install-fails')) { $global:LASTEXITCODE = 1 }
}
function Get-CimInstance {
    param($ClassName, $Filter)
    if ($ClassName -ne 'Win32_Service' -or $Filter -ne "Name = 'AthernexEndpoint'") { throw 'Unexpected service query' }
    $case = $env:ATHERNEX_CASE
    if ($Mode -eq 'register') {
        if ($case -notin @('register-existing', 'register-foreign', 'register-running')) { return $null }
    } elseif ($case -in @('fresh', 'legacy', 'legacy-foreign', 'task-timeout', 'task-disable-fails')) { return $null }
    $p = Fixture-Paths
    $path = '"' + $p[1] + '" windows-service "' + $p[0] + '" "' + $p[2] + '" "' + $p[3] + '"'
    if ($case -in @('foreign-service', 'register-foreign')) { $path = 'unrelated.exe' }
    [pscustomobject]@{ PathName = $path;
        StartName = $(if ($case -eq 'foreign-account') { 'LocalService' } else { 'LocalSystem' });
        ServiceType = $(if ($case -eq 'foreign-type') { 'Share Process' } else { 'Own Process' });
        State = $(if ($Mode -eq 'register' -and $case -ne 'register-running') { 'Stopped' } else { 'Running' }) }
}
function Get-Service {
    param($Name)
    if ($Name -ne 'AthernexEndpoint') { throw 'Unexpected service lookup' }
    $status = 'Running'
    if ($global:serviceStarted) {
        if ($env:ATHERNEX_CASE -eq 'start-timeout') { $status = 'StartPending' }
    } elseif ($global:serviceStopped -and $env:ATHERNEX_CASE -ne 'service-timeout') { $status = 'Stopped' }
    [pscustomobject]@{ Status = $status }
}
function Invoke-Sc {
    if ($args[1] -ne 'AthernexEndpoint') { throw 'Unexpected sc target' }
    $operation = [string]$args[0]
    if ($Mode -eq 'register' -and $operation -in @('start','stop')) { throw 'Registration cannot start or stop a service under installer guards' }
    $global:trace.Add(@{ call = 'sc'; operation = $operation; arguments = @($args) })
    $global:LASTEXITCODE = 0
    if ($operation -eq 'stop') { $global:serviceStopped = $true }
    if ($operation -eq 'start') { $global:serviceStarted = $true }
    if (($operation -eq 'stop' -and $env:ATHERNEX_CASE -eq 'stop-fails') -or
        ($operation -eq 'start' -and $env:ATHERNEX_CASE -eq 'start-fails') -or
        ($operation -eq 'failure' -and $env:ATHERNEX_CASE -eq 'failure-config-fails') -or
        ($operation -eq 'sdset' -and $env:ATHERNEX_CASE -eq 'acl-fails')) { $global:LASTEXITCODE = 1 }
}
function New-Service {
    param($Name, $BinaryPathName, $DisplayName, $StartupType)
    if ($Mode -ne 'register') { throw 'Only guarded registration may create a service' }
    $global:trace.Add(@{ call = 'create'; name = $Name; binary = $BinaryPathName; display = $DisplayName; startup = $StartupType })
    if ($env:ATHERNEX_CASE -eq 'register-fails') { throw 'Fixture registration failure' }
}
function Set-Service {
    param($Name, $StartupType)
    if ($Mode -ne 'register') { throw 'Only guarded registration may configure a service' }
    $global:trace.Add(@{ call = 'configure'; name = $Name; startup = $StartupType })
}
function Get-ScheduledTask {
    param($TaskName, $ErrorAction)
    if ($TaskName -ne 'Athernex Endpoint') { throw 'Unexpected task lookup' }
    if ($env:ATHERNEX_CASE -notin @('legacy','both','legacy-foreign','task-timeout','task-disable-fails','register-legacy','register-legacy-running')) { return $null }
    $p = Fixture-Paths
    $execute = $p[1]
    if ($env:ATHERNEX_CASE -eq 'legacy-foreign') { $execute = 'unrelated.exe' }
    $ready = ($global:taskStopped -and $env:ATHERNEX_CASE -ne 'task-timeout') -or $env:ATHERNEX_CASE -eq 'register-legacy'
    [pscustomobject]@{ State = $(if ($ready) { 'Ready' } else { 'Running' });
        Actions = @([pscustomobject]@{ Execute = $execute; Arguments = ('launch "' + $p[0] + '" "' + $p[2] + '" "' + $p[3] + '"') }) }
}
function Disable-ScheduledTask {
    param($TaskName)
    $global:trace.Add(@{ call = 'disable-task'; name = $TaskName })
    if ($env:ATHERNEX_CASE -eq 'task-disable-fails') { throw 'Fixture disable failure' }
}
function Stop-ScheduledTask {
    param($TaskName)
    $global:trace.Add(@{ call = 'stop-task'; name = $TaskName })
    $global:taskStopped = $true
}
function Unregister-ScheduledTask {
    param($TaskName, [bool]$Confirm)
    if ($Mode -ne 'register' -or $Confirm) { throw 'Only guarded registration may remove the old task' }
    $global:trace.Add(@{ call = 'remove-task'; name = $TaskName })
}
function Get-Date {
    $global:clockCalls++
    [datetime]::new(2026,1,1).AddSeconds(25 * $global:clockCalls)
}
function Start-Sleep { param($Milliseconds) }
function Remove-Item {
    param($Path)
    if ($Path -ne '.\bootstrap.json') { throw 'Unexpected installer cleanup' }
    $global:trace.Add(@{ call = 'remove-bootstrap' })
}
$source = Join-Path (Split-Path -Parent $Script) 'athernex-endpoint.exe'
Set-Alias -Name $source -Value Invoke-Fixture
$scPath = Join-Path $env:SystemRoot 'System32\sc.exe'
Set-Alias -Name $scPath -Value Invoke-Sc
if ((Get-Command $source).Definition -ne 'Invoke-Fixture' -or (Get-Command $scPath).Definition -ne 'Invoke-Sc') {
    throw 'Fixture executable aliases are not bound; refusing to execute installer'
}
foreach ($command in @('Get-CimInstance','Get-Service','New-Service','Set-Service','Get-ScheduledTask','Disable-ScheduledTask','Stop-ScheduledTask','Unregister-ScheduledTask','Remove-Item')) {
    if ((Get-Command $command).CommandType -ne 'Function') { throw ('Fixture command is not mocked: ' + $command) }
}
$failed = $false
$detail = ''
try { & $Script } catch { $failed = $true; $detail = $_.Exception.Message }
@{ trace = @($global:trace.ToArray()); failed = $failed; detail = $detail } |
    ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $env:ATHERNEX_TRACE -Encoding UTF8
if ($failed) { exit 1 }
'''


class InstallerTests(unittest.TestCase):
    powershell = None

    def run_case(self, case, mode='installer'):
        with tempfile.TemporaryDirectory(prefix='athernex-installer-script-') as folder:
            folder = Path(folder)
            script = folder / 'install.ps1'
            shutil.copyfile(INSTALLER if mode == 'installer' else REGISTER, script)
            wrapper = folder / 'fixture.ps1'
            wrapper.write_text(WRAPPER, encoding='utf-8')
            trace = folder / 'trace.json'
            env = dict(os.environ, ATHERNEX_TRACE=str(trace), ATHERNEX_CASE=case,
                       ATHERNEX_FIXTURE_PROGRAM_FILES=str(folder / 'Program Files'),
                       ATHERNEX_FIXTURE_PROGRAM_DATA=str(folder / 'ProgramData'),
                       ATHERNEX_FIXTURE_SYSTEM_ROOT=str(folder / 'Windows'),
                       ATHERNEX_INSTALL_STATE=r'C:\ProgramData\State with spaces',
                       ATHERNEX_INSTALL_AGENT=r'C:\Program Files\Endpoint\agent.exe',
                       ATHERNEX_INSTALL_CONTROLLER=r'C:\Program Files\Endpoint\controller.exe',
                       ATHERNEX_INSTALL_LAUNCHER=r'C:\Program Files\Endpoint\launcher.exe',
                       POWERSHELL_TELEMETRY_OPTOUT='1', POWERSHELL_UPDATECHECK='Off')
            result = subprocess.run([self.powershell, '-NoLogo', '-NoProfile', '-NonInteractive',
                                     '-File', str(wrapper), str(script), mode],
                                    capture_output=True, text=True, env=env, timeout=20, check=False)
            self.assertTrue(trace.exists(), result.stdout + result.stderr)
            return result, json.loads(trace.read_text(encoding='utf-8-sig'))

    @staticmethod
    def calls(value):
        return [item['operation'] if item['call'] == 'sc' else item['call'] for item in value['trace']]

    def test_install_orders_preflight_stop_migration_coordinator_start_and_cleanup(self):
        for case, stop in [('fresh', []), ('existing', ['stop']),
                           ('legacy', ['disable-task','stop-task']), ('both', ['stop','disable-task','stop-task'])]:
            with self.subTest(case=case):
                result, value = self.run_case(case)
                self.assertEqual(result.returncode, 0, value)
                self.assertEqual(self.calls(value), ['endpoint', *stop, 'endpoint', 'start', 'remove-bootstrap'])
                endpoint = [item['arguments'] for item in value['trace'] if item['call'] == 'endpoint']
                self.assertEqual(endpoint[0][0], 'installer-check')
                self.assertEqual(endpoint[1][0], 'windows-install')
                self.assertEqual(len(endpoint[1]), 4)

    def test_failures_retain_bootstrap_and_do_not_start_after_failed_install(self):
        for case, expected in [
            ('preflight-fails', ['endpoint']),
            ('stop-fails', ['endpoint','stop']), ('service-timeout', ['endpoint','stop']),
            ('task-timeout', ['endpoint','disable-task','stop-task']),
            ('task-disable-fails', ['endpoint','disable-task']),
            ('install-fails', ['endpoint','stop','endpoint']),
            ('start-fails', ['endpoint','stop','endpoint','start']),
            ('start-timeout', ['endpoint','stop','endpoint','start']),
        ]:
            with self.subTest(case=case):
                result, value = self.run_case(case)
                self.assertNotEqual(result.returncode, 0, value)
                self.assertEqual(self.calls(value), expected)

    def test_foreign_services_and_tasks_are_never_stopped(self):
        for case in ['foreign-service','foreign-account','foreign-type','legacy-foreign']:
            with self.subTest(case=case):
                result, value = self.run_case(case)
                self.assertNotEqual(result.returncode, 0, value)
                self.assertEqual(self.calls(value), ['endpoint'])

    def test_registration_quotes_paths_and_configures_restart_and_query_only_user_access(self):
        result, value = self.run_case('register', 'register')
        self.assertEqual(result.returncode, 0, value)
        self.assertEqual(self.calls(value), ['create','description','failure','failureflag','sdset'])
        created = value['trace'][0]
        self.assertEqual(created['binary'], '"C:\\Program Files\\Endpoint\\launcher.exe" windows-service "C:\\ProgramData\\State with spaces" "C:\\Program Files\\Endpoint\\controller.exe" "C:\\Program Files\\Endpoint\\agent.exe"')
        self.assertEqual(created['name'], 'AthernexEndpoint')
        self.assertEqual(created['startup'], 'Automatic')
        self.assertEqual(value['trace'][2]['arguments'][2:], ['reset=',86400,'actions=','restart/60000/restart/60000/restart/60000'])
        self.assertEqual(value['trace'][3]['arguments'][2:], [1])
        self.assertEqual(value['trace'][4]['arguments'][2], 'O:BAG:BAD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)(A;;0x2008D;;;AU)')

    def test_existing_exact_service_is_reconciled_and_legacy_task_removed_last(self):
        for case, expected in [('register-existing', ['configure','description','failure','failureflag','sdset']),
                               ('register-legacy', ['create','description','failure','failureflag','sdset','remove-task'])]:
            result, value = self.run_case(case, 'register')
            self.assertEqual(result.returncode, 0, value)
            self.assertEqual(self.calls(value), expected)

    def test_registration_errors_never_start_or_remove_unverified_legacy_task(self):
        for case, expected in [
            ('register-foreign', []), ('register-running', []), ('register-fails', ['create']),
            ('failure-config-fails', ['create','description','failure']),
            ('acl-fails', ['create','description','failure','failureflag','sdset']),
            ('register-legacy-running', ['create','description','failure','failureflag','sdset']),
        ]:
            with self.subTest(case=case):
                result, value = self.run_case(case, 'register')
                self.assertNotEqual(result.returncode, 0, value)
                self.assertEqual(self.calls(value), expected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('powershell') or shutil.which('pwsh'))
    args, rest = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; pass --powershell with its path')
    InstallerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *rest])
