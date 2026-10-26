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
PROCESS_SOURCE_TEST = ('telemetry::windows_process_events_probe::'
                       'owned_system_logger_reports_controlled_process_lifecycles')
SCRATCH_TEST = ('protection::windows::scratch::tests::'
                'owned_worker_formats_bounds_scanner_writes_and_recovers_only_after_exit')
SCRATCH_STAGES = [
    'fixture_entered', 'state_ready', 'worker_started', 'worker_ready',
    'health_rejections_verified', 'live_recovery_refused', 'acl_probe_completed',
    'device_probe_completed', 'foreign_logon_denied', 'scanner_bounds_verified',
    'worker_stopped', 'retained_network_refused', 'recovery_completed', 'passed',
]
PROCESS_FAILURES = [
    'schema_provenance', 'schema_identity', 'schema_bounds', 'schema_shape',
    'property_missing', 'property_type', 'property_scalar', 'property_size',
    'record_provenance', 'record_bounds', 'session_ownership', 'session_configuration',
    'session_cleanup', 'native_loss', 'callback_loss', 'consumer_lifecycle',
    'controlled_lifecycle', 'controlled_timeout', 'token_state', 'api_failure', 'other',
]
WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$SelectedSuite)
$ErrorActionPreference = 'Stop'
. $Script
$checks = @(Get-IsolationChecks $SelectedSuite | ForEach-Object { $_.test })
$report = [pscustomobject]@{ schema=1; suite=$SelectedSuite; native_windows_executed=$true; production_readiness=$false;
    manifest_sha256=('a'*64); user_sid='S-1-5-18'; session_id=0; windows_version='fixture';
    checks=[pscustomobject]@{}; error=$null }
foreach ($name in $checks) { $report.checks | Add-Member -NotePropertyName $name -NotePropertyValue 'passed' }
if ($SelectedSuite -ceq 'Isolation') {
    $report | Add-Member -NotePropertyName scratch_stages -NotePropertyValue @(Get-ScratchStageNames)
    $report | Add-Member -NotePropertyName scratch_diagnostics -NotePropertyValue valid
}
if ($SelectedSuite -ceq 'ProcessSource') {
    $report | Add-Member -NotePropertyName proof_scope -NotePropertyValue source_only
    $report | Add-Member -NotePropertyName process_source_stages -NotePropertyValue @(Get-ProcessSourceStageNames)
    $report | Add-Member -NotePropertyName process_source_failures -NotePropertyValue @()
    $report | Add-Member -NotePropertyName process_source_schema -NotePropertyValue @(@{event='start'},@{event='end'})
}
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
        'wrong-scope' { $report.proof_scope = 'production_collector' }
        'missing-cleanup' { $report.process_source_stages = @($report.process_source_stages | Where-Object { $_ -cne 'cleanup_verified' }) }
        'missing-schema' { $report.process_source_schema = @() }
        'reported-failure' { $report.process_source_failures = @('native_loss') }
        'missing-failures' { $report.PSObject.Properties.Remove('process_source_failures') }
        'missing-scratch-stages' { $report.PSObject.Properties.Remove('scratch_stages') }
        'invalid-scratch-diagnostics' { $report.scratch_diagnostics = 'invalid' }
        'wrong-scratch-stage' { $report.scratch_stages[0] = 'private_fixture_payload' }
        'nested-empty-scratch-stage' { for ($i=0; $i -lt $report.scratch_stages.Count; $i++) { $report.scratch_stages[$i] = @() } }
        'nested-singleton-scratch-stage' { $report.scratch_stages[0] = @($report.scratch_stages[0]) }
        'nonstring-scratch-stage' { $report.scratch_stages[0] = 1 }
        'nonscalar-scratch-diagnostics' { $report.scratch_diagnostics = @('valid') }
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
    if ($Name -ceq 'protection::windows::scratch::tests::owned_worker_formats_bounds_scanner_writes_and_recovers_only_after_exit') {
        Get-ScratchStageNames | ForEach-Object { 'ATHERNEX_SCRATCH_STAGE=' + $_ } | Set-Content -LiteralPath $Log
    }
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
SCRATCH_WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$SelectedSuite)
$ErrorActionPreference = 'Stop'
. $Script
$manifest = @{ schema=1; suite=$SelectedSuite; sha256=@{} }
foreach ($name in @('endpoint.exe','native.exe')) {
    $path = Join-Path $Root $name
    Set-Content -LiteralPath $path -Value 'fixture, never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$target = 'protection::windows::scratch::tests::owned_worker_formats_bounds_scanner_writes_and_recovers_only_after_exit'
function Invoke-IsolationCheck([string]$Executable, [string]$Name, [string]$Log) {
    if ($Name -cne $target) {
        # Even exact-looking markers in another test's log are not considered.
        'ATHERNEX_SCRATCH_STAGE=private_fixture_payload' | Set-Content -LiteralPath $Log
        return
    }
    $stages = @(Get-ScratchStageNames)
    $lines = @($stages | ForEach-Object { 'ATHERNEX_SCRATCH_STAGE=' + $_ })
    switch ($Case) {
        'partial' { $lines = $lines[0..3] }
        'partial-success' { $lines = $lines[0..3] }
        'duplicate' { $lines = @($lines[0]) + $lines + @($lines[-1]) }
        'unknown' { $lines += 'ATHERNEX_SCRATCH_STAGE=private_fixture_payload' }
        'suffix' { $lines += 'ATHERNEX_SCRATCH_STAGE=passed private_fixture_payload' }
        'prefix' { $lines += 'private_fixture_payload ATHERNEX_SCRATCH_STAGE=passed' }
        'wrong-case' { $lines += 'ATHERNEX_SCRATCH_STAGE=PASSED' }
        'out-of-order' { $lines = @($lines[1], $lines[0]) + $lines[2..($lines.Count-1)] }
        'raw-output' { $lines += 'private_fixture_payload path and arbitrary native error' }
        'oversized' { $lines += ('x' * 1048577) }
    }
    if ($Case -cne 'missing') { $lines | Set-Content -LiteralPath $Log }
    if ($Case -cin @('partial','contradictory','missing')) { throw 'private_fixture_payload' }
}
$report = @{ checks=[ordered]@{}; failures=[ordered]@{}; error=$null }
$failure = $null
try { Invoke-IsolationWorkerChecks $Root $manifest $report $SelectedSuite }
catch { $failure = $_.Exception.Message }
@{ failed=($null -ne $failure); error=$failure; checks=$report.checks;
    failures=$report.failures; worker_error=$report.error;
    has_scratch=$report.ContainsKey('scratch_stages'); stages=@($report.scratch_stages);
    diagnostics=$report.scratch_diagnostics } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
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
    if ($SelectedSuite -ceq 'Isolation' -and $Arguments[1] -ceq 'protection::windows::scratch::tests::owned_worker_formats_bounds_scanner_writes_and_recovers_only_after_exit') {
        Get-ScratchStageNames | ForEach-Object { 'ATHERNEX_SCRATCH_STAGE=' + $_ } | Add-Content -LiteralPath $Log
    }
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


PROCESS_WRAPPER = r'''
param([string]$Script, [string]$Case, [string]$Root, [string]$SelectedSuite)
$ErrorActionPreference = 'Stop'
. $Script
$manifest = @{ schema=1; suite='ProcessSource'; github_sha=('a'*40); sha256=@{} }
foreach ($name in @('endpoint.exe','native.exe','verify_windows_isolation_ci.ps1','verify_windows_service_ci.ps1')) {
    $path = Join-Path $Root $name
    Set-Content -LiteralPath $path -Value 'controlled fixture, never executed'
    $manifest.sha256[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifestPath = Join-Path $Root 'inputs.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath
$digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$name = (Get-IsolationChecks ProcessSource).test
$report = @{ schema=1; suite='ProcessSource'; native_windows_executed=$true; production_readiness=$false;
    proof_scope='source_only'; manifest_sha256=$digest; user_sid='S-1-5-18'; session_id=0;
    windows_version='private_fixture_payload'; checks=[ordered]@{}; failures=[ordered]@{}; error=$null;
    process_source_stages=@(Get-ProcessSourceStageNames); process_source_failures=@();
    process_source_schema=@(@{event='start'},@{event='end'}) }
$report.checks[$name] = 'passed'
$log = Join-Path $Root 'check-0.log'
$lines = @((Get-ProcessSourceStageNames) | ForEach-Object { 'ATHERNEX_PROCESS_PROBE_STAGE=' + $_ }) + @(
    ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:0:32:1:' + ('a'*64)),
    ('ATHERNEX_PROCESS_PROBE_SCHEMA=end:255:64:64:' + ('b'*64)),
    'ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=close_trace:0',
    'ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=query_trace:4294967295',
    'private_fixture_payload')
if ($Case -in @('worker-no-cleanup','publish-no-cleanup')) {
    $lines = @($lines | Where-Object { $_ -cne 'ATHERNEX_PROCESS_PROBE_STAGE=cleanup_verified' })
}
if ($Case -in @('worker-no-schema','publish-no-schema')) {
    $lines = @($lines | Where-Object { -not $_.StartsWith('ATHERNEX_PROCESS_PROBE_SCHEMA=end:') })
}
if ($Case -in @('worker-failure-marker','publish-failure-marker')) {
    $lines += 'ATHERNEX_PROCESS_PROBE_FAILURE=native_loss'
}
if ($Case -ceq 'publish-failure-report') { $report.process_source_failures = @('callback_loss') }
$global:executed = 0
$global:taskCalls = 0
$env:ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST = 'previous_authentication'
$env:ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST = 'previous_process'
$failure = $null
$result = @{}
if ($Case.StartsWith('markers-')) {
    $failureTags = @('schema_provenance','schema_identity','schema_bounds','schema_shape',
        'property_missing','property_type','property_scalar','property_size',
        'record_provenance','record_bounds','session_ownership','session_configuration',
        'session_cleanup','native_loss','callback_loss','consumer_lifecycle',
        'controlled_lifecycle','controlled_timeout','token_state','api_failure','other')
    $lines += @($failureTags + $failureTags | ForEach-Object { 'ATHERNEX_PROCESS_PROBE_FAILURE=' + $_ })
    if ($Case -ceq 'markers-injected') {
        $good = @($lines | Where-Object { $_ -cne 'private_fixture_payload' })
        $lines = @($good | ForEach-Object {
            ' ' + $_
            'test fixture ... ' + $_
            $_ + ':private_fixture_payload'
            $_ + ' private_fixture_payload'
            $_ + [char]0
            $_ + [char]0x00ad
            $_.ToUpperInvariant()
        })
    }
    if ($Case -ceq 'markers-invalid-fields') {
        $lines = @(
            'ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=unknown:0',
            'ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=start_trace:4294967296',
            'ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=start_trace:00',
            'ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=start_trace:-1',
            'ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=start_trace:+1',
            ('ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=start_trace:' + [char]0x0661),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:256:64:1:' + ('a'*64)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:00:64:1:' + ('a'*64)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:1:128:1:' + ('a'*64)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:1:64:0:' + ('a'*64)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:1:64:65:' + ('a'*64)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:1:64:01:' + ('a'*64)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:1:64:1:' + ('A'*64)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:1:64:1:' + ('a'*63)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=other:1:64:1:' + ('a'*64)),
            ('ATHERNEX_PROCESS_PROBE_SCHEMA=start:' + [char]0x0661 + ':64:1:' + ('a'*64)),
            'ATHERNEX_PROCESS_PROBE_STAGE=unknown',
            'ATHERNEX_PROCESS_PROBE_FAILURE=unknown',
            'ATHERNEX_PROCESS_PROBE_FAILURE=',
            'ATHERNEX_PROCESS_PROBE_FAILURE=native_loss:private_fixture_payload')
    }
    if ($Case -ceq 'markers-flood') {
        $lines = @(0..63 | ForEach-Object { 'ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=query_trace:' + $_ }) +
            @(0..63 | ForEach-Object { 'ATHERNEX_PROCESS_PROBE_SCHEMA=start:' + $_ + ':64:1:' + ('a'*64) }) +
            @(0..63 | ForEach-Object { 'ATHERNEX_PROCESS_PROBE_STAGE=passed' }) +
            @(0..63 | ForEach-Object { 'ATHERNEX_PROCESS_PROBE_FAILURE=other' })
    }
    $lines | Set-Content -LiteralPath $log
    $result = @{ stages=@(Get-ProcessSourceStages $log); failures=@(Get-ProcessSourceFailures $log); diagnostics=@(Get-ProcessSourceDiagnostics $log);
        schema=@(Get-ProcessSourceSchema $log) }
} elseif ($Case.StartsWith('worker-')) {
    $report.checks.Clear()
    if ($Case -ceq 'worker-input-change') { Set-Content -LiteralPath (Join-Path $Root 'endpoint.exe') -Value changed }
    if ($Case -ceq 'worker-runner-change') { Set-Content -LiteralPath (Join-Path $Root 'verify_windows_isolation_ci.ps1') -Value changed }
    if ($Case -ceq 'worker-helper-change') { Set-Content -LiteralPath (Join-Path $Root 'verify_windows_service_ci.ps1') -Value changed }
    function Invoke-IsolationExecutable([string]$Executable, [string[]]$Arguments, [string]$Log) {
        if ((Split-Path -Leaf $Executable) -cne 'endpoint.exe') { throw 'Wrong source proof executable' }
        if ($Arguments[0] -ceq '--list') {
            $listing = if ($Case -ceq 'worker-missing-test') { 'other: test' } else { $name + ': test' }
            Set-Content -LiteralPath $Log -Value $listing
            return
        }
        $global:executed += 1
        if ($Arguments[0] -cne '--exact' -or $Arguments[1] -cne $name -or
            $Arguments[2] -cne '--ignored' -or $Arguments[3] -cne '--test-threads=1' -or
            $env:ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST -cne '1' -or
            $env:ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST) { throw 'Source proof scope escaped' }
        $summary = if ($Case -ceq 'worker-zero-tests') { 'test result: ok. 0 passed; 0 failed; 0 ignored;' }
            else { 'test result: ok. 1 passed; 0 failed; 0 ignored;' }
        @($lines) + @($summary) | Set-Content -LiteralPath $Log
        if ($Case -ceq 'worker-exit-failure') { throw 'private_fixture_payload' }
    }
    try { Invoke-IsolationWorkerChecks $Root $manifest $report ProcessSource }
    catch { $failure = $_.Exception.Message }
    $result = @{ failed=($null -ne $failure); error=$failure; executed=$global:executed;
        worker_error=$report.error; checks=$report.checks;
        stages=$report.process_source_stages; failures=$report.process_source_failures; diagnostics=$report.process_source_diagnostics;
        schema=$report.process_source_schema;
        authentication_opt_in=$env:ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST;
        process_opt_in=$env:ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST }
} else {
    function Invoke-ServiceFixtureTask($TaskName, $Action, $ResultFile, $AgentSha256, $TimeoutSeconds, $ValidateReport) {
        $global:taskCalls += 1
        if ($Case -ceq 'publish-task-fails') { throw 'private_fixture_payload' }
        $lines | Set-Content -LiteralPath $log
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile
        $parsed = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json
        & $ValidateReport $parsed $AgentSha256
        if ($Case -ceq 'publish-cleanup-fails') { throw 'private_fixture_payload' }
        if ($Case -ceq 'publish-input-change') { Set-Content -LiteralPath (Join-Path $Root 'endpoint.exe') -Value changed }
        if ($Case -ceq 'publish-runner-change') { Set-Content -LiteralPath (Join-Path $Root 'verify_windows_isolation_ci.ps1') -Value changed }
        if ($Case -ceq 'publish-helper-change') { Set-Content -LiteralPath (Join-Path $Root 'verify_windows_service_ci.ps1') -Value changed }
        if ($Case -ceq 'publish-manifest-change') { Add-Content -LiteralPath $manifestPath -Value ' ' }
        if ($Case -ceq 'publish-report-change') {
            $report.checks[$name] = 'skipped'
            $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultFile
        }
        if ($Case -ceq 'publish-missing-report') { Remove-Item -LiteralPath $ResultFile }
    }
    $source = if ($Case -ceq 'publish-wrong-source') { 'b'*40 } else { 'a'*40 }
    try { Invoke-ProcessSourceEvidence $Root fixture-task $null $digest $source }
    catch { $failure = $_.Exception.Message }
    $public = Get-Content -LiteralPath (Join-Path $Root 'process-source-validation.json') -Raw | ConvertFrom-Json
    $result = @{ failed=($null -ne $failure); error=$failure; task_calls=$global:taskCalls; public=$public }
}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Root 'result.json') -Encoding UTF8
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
        for suite in ['Isolation', 'Authentication', 'ProcessSource']:
            for case in ['wrong-hash', 'wrong-suite', 'missing-suite', 'wrong-account',
                         'wrong-session', 'not-native', 'production-claim', 'missing-check',
                         'extra-check', 'skipped-check', 'failed-check', 'error']:
                with self.subTest(suite=suite, case=case):
                    value = self.run_case(case, suite=suite)
                    self.assertTrue(value['failed'], value)
                    self.assertEqual(value['executed'], 0)

    def test_missing_test_never_executes_and_zero_or_ignored_tests_cannot_pass(self):
        for suite in ['Isolation', 'Authentication', 'ProcessSource']:
            for case in ['missing-test', 'zero-tests', 'ignored-test', 'failed-test', 'exit-failure']:
                with self.subTest(suite=suite, case=case):
                    value = self.run_case(case, suite=suite)
                    self.assertTrue(value['failed'], value)
                    self.assertEqual(value['executed'], 0 if case == 'missing-test' else 1)

    def test_one_actual_success_is_required(self):
        for suite in ['Isolation', 'Authentication', 'ProcessSource']:
            with self.subTest(suite=suite):
                value = self.run_case('passed', suite=suite)
                self.assertFalse(value['failed'], value)
                self.assertEqual(value['executed'], 1)
                if suite == 'Authentication':
                    self.assertEqual(value['names'], [AUTHENTICATION_TEST])
                if suite == 'ProcessSource':
                    self.assertEqual(value['names'], [PROCESS_SOURCE_TEST])

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

    def test_scratch_projection_keeps_only_ordered_fixed_milestones_for_its_exact_test(self):
        for case in ['passed', 'duplicate', 'raw-output']:
            with self.subTest(case=case):
                value = self.run_case(case, SCRATCH_WRAPPER)
                self.assertFalse(value['failed'], value)
                self.assertEqual(value['diagnostics'], 'valid')
                self.assertEqual(value['stages'], SCRATCH_STAGES)
                self.assertEqual(len(value['checks']), 11)
                self.assertEqual(set(value['checks'].values()), {'passed'})
                self.assertNotIn('private_fixture_payload', json.dumps(value))
        value = self.run_case('partial', SCRATCH_WRAPPER)
        self.assertTrue(value['failed'])
        self.assertEqual(value['checks'][SCRATCH_TEST], 'failed')
        self.assertEqual(value['stages'], SCRATCH_STAGES[:4])
        self.assertEqual(value['diagnostics'], 'valid')
        self.assertEqual(value['failures'], {SCRATCH_TEST: 'native_check_failed'})
        self.assertNotIn('private_fixture_payload', json.dumps(value))
        value = self.run_case('passed', SCRATCH_WRAPPER, 'Authentication')
        self.assertFalse(value['has_scratch'])

    def test_scratch_markers_cannot_hide_failure_or_publish_arbitrary_payloads(self):
        for case in ['unknown', 'prefix', 'suffix', 'wrong-case', 'out-of-order',
                     'partial-success', 'contradictory', 'missing', 'oversized']:
            with self.subTest(case=case):
                value = self.run_case(case, SCRATCH_WRAPPER)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['checks'][SCRATCH_TEST], 'failed')
                self.assertEqual(value['stages'], [])
                self.assertEqual(value['diagnostics'],
                                 'unavailable' if case in ['missing', 'oversized'] else 'invalid')
                self.assertEqual(value['worker_error'], 'native_worker_failed')
                self.assertNotIn('private_fixture_payload', json.dumps(value))
        for case in ['missing-scratch-stages', 'invalid-scratch-diagnostics', 'wrong-scratch-stage']:
            value = self.run_case(case)
            self.assertTrue(value['failed'], value)
            self.assertEqual(value['executed'], 0)

    def test_scratch_report_requires_scalar_string_stages_and_status(self):
        for case in ['nested-empty-scratch-stage', 'nested-singleton-scratch-stage',
                     'nonstring-scratch-stage', 'nonscalar-scratch-diagnostics']:
            with self.subTest(case=case):
                value = self.run_case(case)
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['executed'], 0)

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

    def test_process_source_requires_explicit_scope_cleanup_and_both_schemas(self):
        for case in ['wrong-scope', 'missing-cleanup', 'missing-schema', 'reported-failure', 'missing-failures']:
            with self.subTest(case=case):
                value = self.run_case(case, suite='ProcessSource')
                self.assertTrue(value['failed'], value)
                self.assertEqual(value['executed'], 0)

    def test_process_markers_reject_injection_and_noncanonical_or_out_of_range_fields(self):
        value = self.run_case('markers-valid', PROCESS_WRAPPER, 'ProcessSource')
        self.assertEqual(value['stages'], [
            'guard_verified', 'token_verified', 'session_owned', 'consumer_ready',
            'children_exited', 'lifecycle_verified', 'schema_verified', 'cleanup_verified', 'passed'])
        self.assertEqual(value['failures'], PROCESS_FAILURES)
        self.assertEqual(value['diagnostics'], [
            {'operation': 'close_trace', 'win32_error': 0},
            {'operation': 'query_trace', 'win32_error': 4294967295}])
        self.assertEqual(value['schema'], [
            {'event': 'start', 'version': 0, 'pointer_bits': 32, 'property_count': 1, 'metadata_sha256': 'a'*64},
            {'event': 'end', 'version': 255, 'pointer_bits': 64, 'property_count': 64, 'metadata_sha256': 'b'*64}])
        self.assertNotIn('private_fixture_payload', json.dumps(value))
        for case in ['markers-injected', 'markers-invalid-fields']:
            with self.subTest(case=case):
                self.assertEqual(self.run_case(case, PROCESS_WRAPPER, 'ProcessSource'),
                                 {'stages': [], 'failures': [], 'diagnostics': [], 'schema': []})
        value = self.run_case('markers-flood', PROCESS_WRAPPER, 'ProcessSource')
        self.assertEqual(value['stages'], ['passed'])
        self.assertEqual(value['failures'], ['other'])
        self.assertEqual(len(value['diagnostics']), 32)
        self.assertEqual(len(value['schema']), 32)
        self.assertEqual([entry['win32_error'] for entry in value['diagnostics']], list(range(32)))
        self.assertEqual([entry['version'] for entry in value['schema']], list(range(32)))

    def test_process_worker_binds_all_inputs_and_restores_separate_opt_ins(self):
        for case, executed in [
                ('worker-passed', 1), ('worker-exit-failure', 1), ('worker-zero-tests', 1),
                ('worker-missing-test', 0), ('worker-no-cleanup', 1), ('worker-no-schema', 1), ('worker-failure-marker', 1),
                ('worker-input-change', 0), ('worker-runner-change', 0), ('worker-helper-change', 0)]:
            with self.subTest(case=case):
                value = self.run_case(case, PROCESS_WRAPPER, 'ProcessSource')
                self.assertEqual(value['failed'], case != 'worker-passed', value)
                self.assertEqual(value['executed'], executed)
                self.assertEqual(value['authentication_opt_in'], 'previous_authentication')
                self.assertEqual(value['process_opt_in'], 'previous_process')
                self.assertNotIn('private_fixture_payload', json.dumps(value))
                self.assertEqual(value['failures'], ['native_loss'] if case == 'worker-failure-marker' else [])
                if value['failed']:
                    self.assertEqual(value['worker_error'], 'native_worker_failed')
                else:
                    self.assertEqual(value['checks'], {PROCESS_SOURCE_TEST: 'passed'})

    def test_process_public_success_requires_task_cleanup_source_inputs_and_revalidated_report(self):
        for case in ['publish-passed', 'publish-task-fails', 'publish-cleanup-fails',
                     'publish-no-cleanup', 'publish-no-schema', 'publish-wrong-source',
                     'publish-input-change', 'publish-runner-change', 'publish-helper-change',
                     'publish-manifest-change', 'publish-report-change', 'publish-missing-report',
                     'publish-failure-marker', 'publish-failure-report']:
            with self.subTest(case=case):
                value = self.run_case(case, PROCESS_WRAPPER, 'ProcessSource')
                passed = case == 'publish-passed'
                self.assertEqual(value['failed'], not passed, value)
                self.assertEqual(value['task_calls'], 0 if case == 'publish-wrong-source' else 1)
                public = value['public']
                self.assertEqual(public['suite'], 'ProcessSource')
                self.assertEqual(public['proof_scope'], 'source_only')
                self.assertIs(public['production_readiness'], False)
                self.assertEqual(public['native_process_source_validation_passed'], passed)
                self.assertEqual(public['checks'], {PROCESS_SOURCE_TEST: 'passed' if passed else 'not_verified'})
                self.assertEqual(public['error'], None if passed else 'native_process_source_not_verified')
                self.assertEqual(public['process_source_failures'], ['native_loss'] if case == 'publish-failure-marker' else [])
                self.assertNotIn('private_fixture_payload', json.dumps(value))
                if passed:
                    self.assertEqual(public['stages'], ['inputs_verified', 'task_completed_and_removed', 'report_verified'])

    def test_process_workflow_uploads_only_bound_source_proof_projection(self):
        workflow = SCRIPT.parent.parent/'.github/workflows/endpoint.yml'
        job = workflow.read_text().split('  windows-process-source:\n', 1)[1].split('  windows-process-events:\n', 1)[0]
        self.assertIn('-Suite ProcessSource', job)
        self.assertIn('Source proof only: no production collector or replay support claim.', job)
        self.assertIn('-DisposableHost', job)
        paths = job.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
        self.assertEqual(paths.split(), [
            '${{', 'runner.temp', '}}/native-windows-process-source/inputs.json',
            '${{', 'runner.temp', '}}/native-windows-process-source/process-source-validation.json'])

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
