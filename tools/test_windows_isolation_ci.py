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
    if ($Case -eq 'raw-check-failure' -and $global:executed -eq 1) { throw 'private_fixture_payload' }
}
if ($Case -eq 'raw-input-failure') {
    function Get-FileHash { param($LiteralPath,$Algorithm); throw 'private_fixture_payload' }
}
$report = @{ checks=[ordered]@{}; failures=[ordered]@{}; error=$null }
$env:ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST = 'previous_fixture_value'
$failure = $null
try { Invoke-IsolationWorkerChecks $Root $manifest $report $SelectedSuite }
catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; executed=$global:executed;
   passed=@($report.checks.Values | Where-Object { $_ -ceq 'passed' }).Count;
   failures=$report.failures.Count; names=$global:executedNames;
   failure_reasons=@($report.failures.Values); worker_error=$report.error;
   opt_in=$env:ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST;
   private_log_exists=((Test-Path -LiteralPath (Join-Path $Root 'check-0.log.failure')) -or
                       (Test-Path -LiteralPath (Join-Path $Root 'worker.log'))) } |
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
        'ATHERNEX_AUTH_STAGE=security_privilege_starting',
        'ATHERNEX_AUTH_STAGE=security_privilege_verified',
        'ATHERNEX_AUTH_STAGE=policy_capture_starting',
        'ATHERNEX_AUTH_STAGE=policy_captured',
        'ATHERNEX_AUTH_STAGE=policy_readback_verified',
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
        'ATHERNEX_AUTH_DIAGNOSTIC=privilege_acquire:1300',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:1314',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_clear:5',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_apply:4294967295',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:0',
        'ATHERNEX_AUTH_DIAGNOSTIC=source_api:5',
        'ATHERNEX_AUTH_DIAGNOSTIC=source_next:1314',
        'ATHERNEX_AUTH_DIAGNOSTIC=source_seek:15011',
        'ATHERNEX_AUTH_DIAGNOSTIC=source_render_probe:122',
        'ATHERNEX_AUTH_DIAGNOSTIC=unknown_private_payload:5',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:5 private_payload',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:-1',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:+1',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:01',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:4294967296',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:0x5',
        'ATHERNEX_AUTH_DIAGNOSTIC=POLICY_QUERY:5',
        ' ATHERNEX_AUTH_DIAGNOSTIC=policy_query:5',
        'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:5:private_payload',
        "ATHERNEX_AUTH_DIAGNOSTIC=policy_query:5$([char]0x00ad)",
        "ATHERNEX_AUTH_DIAGNOSTIC=policy_query:5$([char]0)",
        "ATHERNEX_AUTH_DIAGNOSTIC=policy_query:$([char]0x0665)",
        'ATHERNEX_AUTH_SOURCE=connection_ready',
        'ATHERNEX_AUTH_SOURCE=worker_entered',
        'ATHERNEX_AUTH_SOURCE=invalid_property_type',
        'ATHERNEX_AUTH_SOURCE=startup_failed',
        'ATHERNEX_AUTH_SOURCE=connection_ready',
        'ATHERNEX_AUTH_SOURCE=unknown_private_payload',
        'ATHERNEX_AUTH_SOURCE=reader_opened private_payload',
        'ATHERNEX_AUTH_SOURCE=reader_opened:private_payload',
        'ATHERNEX_AUTH_SOURCE=READER_OPENED',
        ' ATHERNEX_AUTH_SOURCE=reader_opened',
        'test fixture ... ATHERNEX_AUTH_SOURCE=reader_opened',
        "ATHERNEX_AUTH_SOURCE=reader_opened$([char]0x00ad)",
        "ATHERNEX_AUTH_SOURCE=reader_opened$([char]0)",
        'ATHERNEX_AUTH_RENDER=bookmark_probe:2:0:128:0:0',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128:1',
        'ATHERNEX_AUTH_RENDER=unknown_private_payload:2:1:128:128:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:1:1:128:128:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:2:128:128:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128:1 private_payload',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128:1:private_payload',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:-1:128:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:+128:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:0128:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:0x80:1',
        'ATHERNEX_AUTH_RENDER=BOOKMARK_RESULT:2:1:128:128:1',
        ' ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:4294967296:128:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:4294967296:1',
        'ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128:4294967296',
        "ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128:1$([char]0x00ad)",
        "ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128:1$([char]0)",
        "ATHERNEX_AUTH_RENDER=bookmark_result:2:1:128:128:$([char]0x0661)",
        'ATHERNEX_AUTH_STAGE=cleanup_verified'
    ) | Set-Content -LiteralPath $Log
    if ($Case -ceq 'diagnostic-flood') {
        0..63 | ForEach-Object { 'ATHERNEX_AUTH_DIAGNOSTIC=policy_query:' + $_ } |
            Set-Content -LiteralPath $Log
    }
    if ($Case -ceq 'render-flood') {
        0..31 | ForEach-Object { 'ATHERNEX_AUTH_RENDER=bookmark_probe:2:0:' + $_ + ':4294967295:0' } |
            Set-Content -LiteralPath $Log
    }
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
   has_diagnostics=$report.ContainsKey('authentication_diagnostics');
   diagnostics=@($report.authentication_diagnostics);
   has_source=$report.ContainsKey('authentication_source'); source=@($report.authentication_source);
   has_render=$report.ContainsKey('authentication_render'); render=@($report.authentication_render);
   stages=@($report.authentication_stages); failures=$report.failures.Count;
   passed=@($report.checks.Values | Where-Object { $_ -ceq 'passed' }).Count } |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
'''

PHASES_WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$SelectedSuite)
$ErrorActionPreference = 'Stop'
. $Script
$stages = @('setup_position_ready','setup_clear_verified','setup_clear_observed','setup_apply_observed',
    'setup_cleanup_verified',
    'listener_ready','client_ready','heartbeat_accepted','allowed_attempt_verified',
    'denied_attempts_verified','controlled_queue_ready','stalled_cycle_verified','capture_health_verified',
    'server_replay_verified','export_authorization_verified','original_link_verified',
    'portal_coverage_verified','server_restart_verified')
$source = @('controlled_queue_empty','controlled_queue_partial','controlled_queue_extra','queue_wait_timeout',
    'capture_health_timeout','health_has_rejections','health_has_loss','health_has_error',
    'health_state_inactive','health_backpressure','health_not_caught_up',
    'rejected_xml','rejected_provenance','rejected_missing_field','rejected_numeric_field',
    'rejected_text_field','rejected_identity_mismatch','rejected_other',
    'loss_policy_health_transition','loss_log_identity_changed','loss_bookmark_anchor_missing',
    'loss_record_sequence','loss_eventlog_marker','loss_per_user_policy_marker',
    'loss_system_policy_marker','loss_policy_scope_unknown',
    'setup_barrier_timeout','setup_barrier_continuity','setup_barrier_scope_invalid',
    'setup_barrier_subject_invalid','setup_barrier_changes_invalid',
    'setup_barrier_delta_unexpected','setup_barrier_budget',
    'setup_policy_provider_mismatch','setup_policy_version_missing',
    'setup_policy_version_1','setup_policy_version_other','setup_policy_guid_invalid',
    'setup_scope_guid','setup_scope_string','setup_scope_null','setup_scope_array','setup_scope_other')
$log = Join-Path $Root 'fixture.log'
$lines = @($stages | ForEach-Object { 'ATHERNEX_AUTH_STAGE=' + $_ }) +
         @($source | ForEach-Object { 'ATHERNEX_AUTH_SOURCE=' + $_ })
if ($Case -ceq 'setup-cleanup-only') { $lines = @('ATHERNEX_AUTH_STAGE=setup_cleanup_verified') }
if ($Case -ceq 'injected') {
    $lines = @($lines | ForEach-Object {
        $_ + ':private_fixture_payload'
        $_ + ' private_fixture_payload'
        $_ + [char]0x00ad
        ' ' + $_
        $_.ToUpperInvariant()
    })
}
$lines | Set-Content -LiteralPath $log
@{ stages=@(Get-AuthenticationStages $log); source=@(Get-AuthenticationSource $log) } |
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

    def test_native_and_io_failures_remain_private_in_both_suite_reports(self):
        for suite in ['Isolation', 'Authentication']:
            for case in ['raw-check-failure', 'raw-input-failure']:
                with self.subTest(suite=suite, case=case):
                    value = self.run_case(case, WORKER_WRAPPER, suite)
                    self.assertTrue(value['failed'], value)
                    self.assertEqual(value['worker_error'], 'native_worker_failed')
                    self.assertNotIn('private_fixture_payload', json.dumps(value))
                    self.assertEqual(value['failure_reasons'], ['native_check_failed'] if case == 'raw-check-failure' else [])
                    self.assertEqual(value['executed'], (11 if suite == 'Isolation' else 1) if case == 'raw-check-failure' else 0)
                    self.assertTrue(value['private_log_exists'])
                    self.assertEqual(value['opt_in'], 'previous_fixture_value')

    def test_controlled_capture_categories_accept_only_exact_fixed_lines(self):
        value = self.run_case('valid', PHASES_WRAPPER, 'Authentication')
        self.assertEqual(value['stages'], [
            'setup_position_ready', 'setup_clear_verified', 'setup_clear_observed', 'setup_apply_observed',
            'setup_cleanup_verified',
            'listener_ready', 'client_ready', 'heartbeat_accepted', 'allowed_attempt_verified',
            'denied_attempts_verified', 'controlled_queue_ready', 'stalled_cycle_verified', 'capture_health_verified',
            'server_replay_verified', 'export_authorization_verified', 'original_link_verified',
            'portal_coverage_verified', 'server_restart_verified'])
        self.assertEqual(value['source'], [
            'controlled_queue_empty', 'controlled_queue_partial', 'controlled_queue_extra', 'queue_wait_timeout',
            'capture_health_timeout', 'health_has_rejections', 'health_has_loss', 'health_has_error',
            'health_state_inactive', 'health_backpressure', 'health_not_caught_up',
            'rejected_xml', 'rejected_provenance', 'rejected_missing_field', 'rejected_numeric_field',
            'rejected_text_field', 'rejected_identity_mismatch', 'rejected_other',
            'loss_policy_health_transition', 'loss_log_identity_changed', 'loss_bookmark_anchor_missing',
            'loss_record_sequence', 'loss_eventlog_marker', 'loss_per_user_policy_marker',
            'loss_system_policy_marker', 'loss_policy_scope_unknown',
            'setup_barrier_timeout', 'setup_barrier_continuity', 'setup_barrier_scope_invalid',
            'setup_barrier_subject_invalid', 'setup_barrier_changes_invalid',
            'setup_barrier_delta_unexpected', 'setup_barrier_budget',
            'setup_policy_provider_mismatch', 'setup_policy_version_missing',
            'setup_policy_version_1', 'setup_policy_version_other', 'setup_policy_guid_invalid',
            'setup_scope_guid', 'setup_scope_string', 'setup_scope_null', 'setup_scope_array', 'setup_scope_other'])
        self.assertEqual(self.run_case('injected', PHASES_WRAPPER, 'Authentication'), {'stages': [], 'source': []})

    def test_setup_policy_restoration_does_not_claim_account_cleanup(self):
        value = self.run_case('setup-cleanup-only', PHASES_WRAPPER, 'Authentication')
        self.assertEqual(value, {'stages': ['setup_cleanup_verified'], 'source': []})
        self.assertNotIn('cleanup_verified', value['stages'])

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
        self.assertEqual(value['stages'], ['guard_verified', 'security_privilege_starting',
                                         'security_privilege_verified', 'policy_capture_starting',
                                         'policy_captured', 'policy_readback_verified',
                                         'policy_ready', 'cleanup_verified'])
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
                                 ['guard_verified', 'security_privilege_starting',
                                  'security_privilege_verified', 'policy_capture_starting', 'policy_captured',
                                  'policy_readback_verified', 'policy_ready', 'cleanup_verified'])
                self.assertEqual(value['diagnostics'], [] if case == 'missing-log' else [
                    {'operation': 'privilege_acquire', 'win32_error': 1300},
                    {'operation': 'policy_query', 'win32_error': 1314},
                    {'operation': 'policy_clear', 'win32_error': 5},
                    {'operation': 'policy_apply', 'win32_error': 4294967295},
                    {'operation': 'policy_query', 'win32_error': 0},
                    {'operation': 'source_api', 'win32_error': 5},
                    {'operation': 'source_next', 'win32_error': 1314},
                    {'operation': 'source_seek', 'win32_error': 15011},
                    {'operation': 'source_render_probe', 'win32_error': 122},
                ])
                self.assertEqual(value['source'], [] if case == 'missing-log' else [
                    'connection_ready', 'worker_entered', 'startup_failed', 'invalid_property_type'
                ])
                self.assertEqual(len(value['render']), 0 if case == 'missing-log' else 2)
        value = self.run_case('passed', STAGES_WRAPPER, 'Isolation')
        self.assertFalse(value['failed'], value)
        self.assertEqual(value['passed'], 11)
        self.assertFalse(value['has_stages'])
        self.assertFalse(value['has_diagnostics'])
        self.assertFalse(value['has_source'])
        self.assertFalse(value['has_render'])

    def test_authentication_diagnostics_allow_only_fixed_operations_and_bounded_decimal_codes(self):
        value = self.run_case('passed', STAGES_WRAPPER, 'Authentication')
        self.assertFalse(value['failed'], value)
        self.assertTrue(value['has_diagnostics'])
        self.assertEqual(value['diagnostics'], [
            {'operation': 'privilege_acquire', 'win32_error': 1300},
            {'operation': 'policy_query', 'win32_error': 1314},
            {'operation': 'policy_clear', 'win32_error': 5},
            {'operation': 'policy_apply', 'win32_error': 4294967295},
            {'operation': 'policy_query', 'win32_error': 0},
            {'operation': 'source_api', 'win32_error': 5},
            {'operation': 'source_next', 'win32_error': 1314},
            {'operation': 'source_seek', 'win32_error': 15011},
            {'operation': 'source_render_probe', 'win32_error': 122},
        ])
        self.assertNotIn('private_payload', json.dumps(value))
        value = self.run_case('diagnostic-flood', STAGES_WRAPPER, 'Authentication')
        self.assertFalse(value['failed'], value)
        self.assertEqual(value['diagnostics'], [
            {'operation': 'policy_query', 'win32_error': code} for code in range(32)
        ])

    def test_authentication_source_evidence_excludes_raw_errors_and_unknown_or_injected_categories(self):
        value = self.run_case('passed', STAGES_WRAPPER, 'Authentication')
        self.assertFalse(value['failed'], value)
        self.assertTrue(value['has_source'])
        self.assertEqual(value['source'], [
            'connection_ready', 'worker_entered', 'startup_failed', 'invalid_property_type'
        ])
        self.assertNotIn('private_payload', json.dumps(value))

    def test_bookmark_render_evidence_preserves_only_bounded_exact_numeric_call_metadata(self):
        value = self.run_case('passed', STAGES_WRAPPER, 'Authentication')
        self.assertFalse(value['failed'], value)
        self.assertTrue(value['has_render'])
        self.assertEqual(value['render'], [
            {'stage': 'bookmark_probe', 'flags': 2, 'succeeded': 0, 'used_bytes': 128,
             'capacity_bytes': 0, 'property_count': 0},
            {'stage': 'bookmark_result', 'flags': 2, 'succeeded': 1, 'used_bytes': 128,
             'capacity_bytes': 128, 'property_count': 1},
        ])
        self.assertNotIn('private_payload', json.dumps(value))
        value = self.run_case('render-flood', STAGES_WRAPPER, 'Authentication')
        self.assertFalse(value['failed'], value)
        self.assertEqual(value['render'], [
            {'stage': 'bookmark_probe', 'flags': 2, 'succeeded': 0, 'used_bytes': count,
             'capacity_bytes': 4294967295, 'property_count': 0} for count in range(16)
        ])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell', default=shutil.which('pwsh') or shutil.which('powershell'))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error('PowerShell is required; use --powershell')
    IsolationRunnerTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
