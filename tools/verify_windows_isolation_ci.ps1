<#
Run fixed opt-in native checks as LocalSystem on a disposable hosted VM.
No driver is loaded. Scratch tests create only private 256 MiB VHDX files; the
worker test formats and fills its own new volume. No existing disk is adopted. WFP rules are scoped
to fresh fixture images. Failed checks retain their private recovery journals.
The Authentication suite temporarily changes logon auditing and creates a private
fixture account; its test owns restoration. Dot-sourcing defines helpers only.
#>
param([string]$EndpointTests, [string]$NativeTests, [string]$OutputDirectory,
      [switch]$DisposableHost, [switch]$Worker,
      [ValidateSet('Isolation','Authentication', IgnoreCase=$false)][string]$Suite = 'Isolation')

function Get-IsolationChecks([ValidateSet('Isolation','Authentication', IgnoreCase=$false)][string]$Suite = 'Isolation') {
    if ($Suite -ceq 'Authentication') {
        return @{ binary='endpoint.exe'; test='telemetry::windows_authentication::native_test::security_logon_delivery_replays_and_reports_policy_gaps' }
    }
    @(
        @{ binary='endpoint.exe'; test='windows_job::tests::scanner_launch_has_checked_identity_job_limits_and_owned_cleanup' },
        @{ binary='native.exe'; test='windows_scanner::tests::scanner_reads_copies_writes_scratch_and_cannot_read_private_state_or_change_engine' },
        @{ binary='native.exe'; test='windows_state::cleanup::tests::cleanup_preserves_external_links_streams_attributes_and_retries_pinned_entries' },
        @{ binary='native.exe'; test='windows_state::cleanup::tests::cleanup_refuses_root_redirection_and_reclaims_only_empty_unrecorded_orphans' },
        @{ binary='endpoint.exe'; test='protection::windows::scratch::tests::recovery_preserves_live_corrupt_changed_and_pinned_images_and_replays_deletion' },
        @{ binary='endpoint.exe'; test='windows_job::tests::scanner_network_rules_survive_owner_exit_and_allow_only_configured_loopback_service' },
        @{ binary='endpoint.exe'; test='protection::windows::scratch::tests::owned_worker_formats_bounds_scanner_writes_and_recovers_only_after_exit' },
        @{ binary='endpoint.exe'; test='protection::windows::recovery::tests::recovery_reconciles_aborted_installs_owner_crashes_and_committed_deletions' },
        @{ binary='native.exe'; test='windows_scratch::tests::fixed_image_capacity_identity_and_detached_recovery_are_verified' },
        @{ binary='native.exe'; test='windows_scratch::tests::fresh_disk_gpt_and_discovered_volume_remain_bound_to_the_created_image' },
        @{ binary='native.exe'; test='windows_scratch::tests::owner_process_exit_releases_the_nonpermanent_scratch_attachment' }
    )
}

function Assert-IsolationReport($Report, [string]$ManifestSha256,
                                [ValidateSet('Isolation','Authentication', IgnoreCase=$false)][string]$Suite = 'Isolation') {
    if ($Report.schema -ne 1 -or $Report.native_windows_executed -cne $true -or
        $Report.suite -cne $Suite -or
        $Report.production_readiness -cne $false -or $Report.manifest_sha256 -cne $ManifestSha256 -or
        $Report.user_sid -cne 'S-1-5-18' -or $Report.session_id -cne 0 -or $Report.error -or
        -not $Report.windows_version) { throw 'Native isolation report identity or result is invalid' }
    $expected = @(Get-IsolationChecks $Suite | ForEach-Object { $_.test })
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne $expected.Count) { throw 'Native isolation report has an incomplete check set' }
    foreach ($name in $expected) {
        if ($names -cnotcontains $name -or $Report.checks.$name -cne 'passed') { throw ('Native isolation check did not pass: ' + $name) }
    }
}

function Invoke-IsolationExecutable([string]$Executable, [string[]]$Arguments, [string]$Log) {
    # Windows PowerShell represents native stderr as ErrorRecord objects. Keep
    # diagnostics in the private log and judge the actual executable exit code.
    $ErrorActionPreference = 'Continue'
    & $Executable @Arguments > $Log 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw ('Isolation executable failed with exit code ' + $code) }
}

function Invoke-IsolationCheck([string]$Executable, [string]$Name, [string]$Log) {
    Invoke-IsolationExecutable $Executable @('--list','--ignored','--format','terse') ($Log + '.list')
    $listing = Get-Content -LiteralPath ($Log + '.list') -Raw
    if ($listing -cnotmatch ('(?m)^' + [regex]::Escape($Name) + ': test\r?$')) {
        throw ('Requested ignored test is absent: ' + $Name)
    }
    Invoke-IsolationExecutable $Executable @('--exact',$Name,'--ignored','--test-threads=1','--nocapture') $Log
    $output = Get-Content -LiteralPath $Log -Raw
    if ($output -cnotmatch '(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;') {
        throw ('Native test did not report exactly one executed success: ' + $Name)
    }
}

function Get-AuthenticationStages([string]$Log) {
    # Only return constants whose complete marker line occurred. Never copy a
    # captured line, suffix, exception, XML value, or account into public evidence.
    $allowed = @('guard_verified','security_privilege_starting','security_privilege_verified',
        'policy_capture_starting','policy_captured',
        'policy_clear_starting','policy_cleared','policy_apply_starting','policy_applied',
        'policy_readback_verified','setup_position_ready','setup_clear_verified',
        'setup_clear_observed','setup_apply_observed','setup_cleanup_verified',
        'policy_ready','account_ready','source_starting',
        'source_ready','listener_ready','client_ready','heartbeat_accepted','allowed_attempt_verified',
        'denied_attempts_verified','controlled_queue_ready','stalled_cycle_verified','capture_health_verified',
        'stalled_http_verified','backpressure_verified','crash_replay_verified',
        'policy_gap_verified','anchor_mismatch_verified','http_delivery_verified',
        'server_replay_verified','export_authorization_verified','original_link_verified',
        'original_export_verified','portal_coverage_verified','server_restart_verified',
        'detection_verified','cleanup_verified')
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    foreach ($stage in $allowed) {
        foreach ($line in $lines) {
            if ([string]::Equals($line, ('ATHERNEX_AUTH_STAGE=' + $stage), [StringComparison]::Ordinal)) {
                $stage
                break
            }
        }
    }
}

function Get-AuthenticationDiagnostics([string]$Log) {
    # Numeric API failures only, under fixed operation names. This field is
    # diagnostic evidence and cannot make a failed or skipped test pass.
    $allowed = @('privilege_acquire','policy_query','policy_clear','policy_apply',
        'source_api','source_next','source_seek','source_render_probe')
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    $count = 0
    foreach ($line in $lines) {
        foreach ($operation in $allowed) {
            $pattern = '\A' + [regex]::Escape('ATHERNEX_AUTH_DIAGNOSTIC=' + $operation + ':') + '(0|[1-9][0-9]{0,9})\z'
            $match = [regex]::Match($line, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
            [uint32]$code = 0
            if ($match.Success -and [uint32]::TryParse($match.Groups[1].Value,
                [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$code)) {
                @{ operation=$operation; win32_error=$code }
                $count += 1
                if ($count -ge 32) { return }
                break
            }
        }
    }
}

function Get-AuthenticationSource([string]$Log) {
    # A bounded set of observed milestones/error categories, in canonical order.
    # The fixture classifies private errors locally; no error text is accepted.
    $allowed = @('connection_ready','worker_entered','durable_state_ready','initial_health_saved',
        'reader_opened','log_opened','log_identity_ready','audit_policy_checked','channel_health_checked',
        'baseline_query_ready','baseline_record_ready','baseline_identity_ready','baseline_bookmark_ready',
        'baseline_committed','worker_ready','collector_started','startup_timeout','startup_disconnected',
        'startup_failed','health_read_failed','health_missing','health_incomplete','worker_failed',
        'invalid_property_type','invalid_native_identity','invalid_render_size','invalid_render_text',
        'invalid_log_metadata','invalid_bookmark','empty_baseline','source_error_other',
        'controlled_queue_empty','controlled_queue_partial','controlled_queue_extra','queue_wait_timeout',
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
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    foreach ($category in $allowed) {
        foreach ($line in $lines) {
            if ([string]::Equals($line, ('ATHERNEX_AUTH_SOURCE=' + $category), [StringComparison]::Ordinal)) {
                $category
                break
            }
        }
    }
}

function Get-AuthenticationRender([string]$Log) {
    # Each record describes one bookmark-render API call. Only the exact stages,
    # bookmark flag, success bit and bounded numeric metadata can be published.
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    $number = '(0|[1-9][0-9]{0,9})'
    $count = 0
    foreach ($line in $lines) {
        foreach ($stage in @('bookmark_probe','bookmark_result')) {
            $pattern = '\A' + [regex]::Escape('ATHERNEX_AUTH_RENDER=' + $stage + ':2:') + '([01]):' + $number + ':' + $number + ':' + $number + '\z'
            $match = [regex]::Match($line, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
            if (-not $match.Success) { continue }
            $values = @()
            $valid = $true
            foreach ($index in 2..4) {
                [uint32]$value = 0
                if (-not [uint32]::TryParse($match.Groups[$index].Value,
                    [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$value)) {
                    $valid = $false
                    break
                }
                $values += $value
            }
            if ($valid) {
                @{ stage=$stage; flags=2; succeeded=[int]$match.Groups[1].Value;
                    used_bytes=$values[0]; capacity_bytes=$values[1]; property_count=$values[2] }
                $count += 1
                if ($count -ge 16) { return }
                break
            }
        }
    }
}

function Invoke-IsolationChecks([string]$OutputDirectory, $Manifest, $Report,
                                [ValidateSet('Isolation','Authentication', IgnoreCase=$false)][string]$Suite = 'Isolation') {
    if ($Manifest.schema -ne 1 -or $Manifest.suite -cne $Suite) { throw 'Invalid native check input manifest suite' }
    $position = 0
    foreach ($check in Get-IsolationChecks $Suite) {
        $executable = Join-Path $OutputDirectory $check.binary
        # A changed input is a trust failure: stop before executing anything else.
        if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Manifest.sha256.($check.binary)) {
            throw 'Staged isolation executable hash changed'
        }
        $log = Join-Path $OutputDirectory ('check-' + $position + '.log')
        try {
            Invoke-IsolationCheck $executable $check.test $log
            $Report.checks[$check.test] = 'passed'
        } catch {
            $Report.checks[$check.test] = 'failed'
            $Report.failures[$check.test] = 'native_check_failed'
            try { $_ | Out-File -LiteralPath ($log + '.failure') -Append -ErrorAction Stop } catch { }
        } finally {
            if ($Suite -ceq 'Authentication') {
                $Report.authentication_stages = @(Get-AuthenticationStages $log)
                $Report.authentication_diagnostics = @(Get-AuthenticationDiagnostics $log)
                $Report.authentication_source = @(Get-AuthenticationSource $log)
                $Report.authentication_render = @(Get-AuthenticationRender $log)
            }
        }
        # Each test runs in a separate process with fresh fixture paths. WFP
        # rules name only that test's private image, never the runner binary.
        $position += 1
    }
    if ($Report.failures.Count) { throw 'One or more native isolation checks failed' }
}

function Invoke-IsolationWorkerChecks([string]$OutputDirectory, $Manifest, $Report,
                                      [ValidateSet('Isolation','Authentication', IgnoreCase=$false)][string]$Suite = 'Isolation') {
    $authenticationOptIn = 'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST'
    $previousOptIn = [Environment]::GetEnvironmentVariable($authenticationOptIn, 'Process')
    try {
        if ($manifest.schema -ne 1 -or $manifest.suite -cne $Suite) { throw 'Invalid native check input manifest suite' }
        # Set this only after the disposable LocalSystem worker and its suite
        # manifest have been verified. The native fixture repeats identity checks.
        $optIn = if ($Suite -ceq 'Authentication') { '1' } else { $null }
        [Environment]::SetEnvironmentVariable($authenticationOptIn, $optIn, 'Process')
        Invoke-IsolationChecks $OutputDirectory $manifest $report $Suite
    } catch {
        $Report.error = 'native_worker_failed'
        try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'worker.log') -Append -ErrorAction Stop } catch { }
        throw 'Native worker failed; private evidence retained on worker'
    } finally {
        [Environment]::SetEnvironmentVariable($authenticationOptIn, $previousOptIn, 'Process')
    }
}

function Invoke-IsolationWorker([string]$OutputDirectory, [bool]$DisposableHost,
                                [ValidateSet('Isolation','Authentication', IgnoreCase=$false)][string]$Suite = 'Isolation') {
    $ErrorActionPreference = 'Stop'
    if (-not $DisposableHost -or [Environment]::OSVersion.Platform -ne 'Win32NT' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'Isolation worker requires native LocalSystem in session zero'
    }
    $manifestPath = Join-Path $OutputDirectory 'inputs.json'
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $report = @{ schema=1; suite=$Suite; native_windows_executed=$true; production_readiness=$false;
        manifest_sha256=$manifestHash; user_sid='S-1-5-18'; session_id=0;
        windows_version=[Environment]::OSVersion.Version.ToString(); checks=[ordered]@{};
        failures=[ordered]@{}; error=$null }
    if ($Suite -ceq 'Authentication') {
        $report.authentication_stages = @()
        $report.authentication_diagnostics = @()
        $report.authentication_source = @()
        $report.authentication_render = @()
    }
    try { Invoke-IsolationWorkerChecks $OutputDirectory $manifest $report $Suite }
    finally {
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory ($Suite.ToLowerInvariant() + '-validation.json')) -Encoding UTF8
    }
}

function Invoke-IsolationCi([string]$EndpointTests, [string]$NativeTests, [string]$OutputDirectory, [bool]$DisposableHost,
                            [ValidateSet('Isolation','Authentication', IgnoreCase=$false)][string]$Suite = 'Isolation') {
    $ErrorActionPreference = 'Stop'
    if (-not $DisposableHost -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
        [Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Requires an explicitly disposable GitHub-hosted Windows runner' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Requires an elevated runner'
    }
    $sources = @{ 'endpoint.exe'=(Resolve-Path -LiteralPath $EndpointTests).Path;
                  'native.exe'=(Resolve-Path -LiteralPath $NativeTests).Path }
    if (-not $OutputDirectory) { throw 'OutputDirectory is required' }
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    if ((Test-Path -LiteralPath $OutputDirectory) -or -not (Test-Path -LiteralPath (Split-Path -Parent $OutputDirectory) -PathType Container)) {
        throw 'OutputDirectory must be new and have an existing parent directory'
    }
    $null = New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $OutputDirectory -AclObject $acl
    $manifest = @{ schema=1; suite=$Suite; github_sha=$env:GITHUB_SHA; sha256=@{} }
    foreach ($name in $sources.Keys) {
        $digest = (Get-FileHash -LiteralPath $sources[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $sources[$name] -Destination (Join-Path $OutputDirectory $name)
        if ((Get-FileHash -LiteralPath (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
            throw 'Staged executable differs from compiled isolation tests'
        }
        $manifest.sha256[$name] = $digest
    }
    $manifestPath = Join-Path $OutputDirectory 'inputs.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixture = Join-Path $OutputDirectory 'verify_windows_isolation_ci.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $fixture
    $parameters = @{ Fixture=$fixture; OutputDirectory=$OutputDirectory; Suite=$Suite } | ConvertTo-Json -Compress
    $literal = $parameters.Replace("'", "''")
    $code = @'
$ErrorActionPreference = 'Stop'
$p = ConvertFrom-Json '__PARAMETERS__'
try { & $p.Fixture -OutputDirectory $p.OutputDirectory -Suite $p.Suite -Worker -DisposableHost; exit 0 }
catch { $_ | Out-File -LiteralPath (Join-Path $p.OutputDirectory 'worker.log') -Append; exit 1 }
'@.Replace('__PARAMETERS__', $literal)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encoded)
    $taskName = 'Athernex' + $Suite + 'Validation-' + [Guid]::NewGuid().ToString('N')
    # Import into a child scope so the service script's parameters cannot replace
    # this runner's paths or switches when it is dot-sourced.
    & {
        param($IsolationTask, $IsolationAction, $IsolationResult, $IsolationDigest, $IsolationSuite, $Helper)
        . $Helper
        Invoke-ServiceFixtureTask $IsolationTask $IsolationAction $IsolationResult $IsolationDigest 540 {
            param($Report, $ManifestSha256)
            Assert-IsolationReport $Report $ManifestSha256 $IsolationSuite
        }
    } $taskName $action (Join-Path $OutputDirectory ($Suite.ToLowerInvariant() + '-validation.json')) $digest $Suite (Join-Path $PSScriptRoot 'verify_windows_service_ci.ps1')
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Worker) { Invoke-IsolationWorker $OutputDirectory $DisposableHost.IsPresent $Suite }
    else {
        try { Invoke-IsolationCi $EndpointTests $NativeTests $OutputDirectory $DisposableHost.IsPresent $Suite }
        catch {
            try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'runner.log') -Append -ErrorAction Stop } catch { }
            throw 'Native suite validation failed; private evidence retained on worker when available'
        }
    }
}
