<#
Run fixed opt-in native checks as LocalSystem on a disposable hosted VM.
No driver is loaded. Scratch tests create only private 256 MiB VHDX files; the
worker test formats and fills its own new volume. No existing disk is adopted. WFP rules are scoped
to fresh fixture images. Failed checks retain their private recovery journals.
The Authentication suite temporarily changes logon auditing and creates a private
fixture account; its test owns restoration. Dot-sourcing defines helpers only.
ProcessSource is a test-only ETW source proof, not a production collector.
#>
param([string]$EndpointTests, [string]$NativeTests, [string]$OutputDirectory,
      [switch]$DisposableHost, [switch]$Worker,
      [ValidateSet('Isolation','Authentication','ProcessSource', IgnoreCase=$false)][string]$Suite = 'Isolation')

function Get-IsolationChecks([ValidateSet('Isolation','Authentication','ProcessSource', IgnoreCase=$false)][string]$Suite = 'Isolation') {
    if ($Suite -ceq 'Authentication') {
        return @{ binary='endpoint.exe'; test='telemetry::windows_authentication::native_test::security_logon_delivery_replays_and_reports_policy_gaps' }
    }
    if ($Suite -ceq 'ProcessSource') {
        return @{ binary='endpoint.exe'; test='telemetry::windows_process_events_probe::owned_system_logger_reports_controlled_process_lifecycles' }
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
                                [ValidateSet('Isolation','Authentication','ProcessSource', IgnoreCase=$false)][string]$Suite = 'Isolation') {
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
    if ($Suite -ceq 'Isolation') {
        $stages = @(Get-ScratchStageNames)
        if ($Report.scratch_diagnostics -isnot [string] -or
            -not [string]::Equals($Report.scratch_diagnostics, 'valid', [StringComparison]::Ordinal) -or
            $Report.scratch_stages -isnot [array] -or $Report.scratch_stages.Count -ne $stages.Count) {
            throw 'Scratch milestone evidence is incomplete'
        }
        for ($i = 0; $i -lt $stages.Count; $i++) {
            if ($Report.scratch_stages[$i] -isnot [string] -or
                -not [string]::Equals($Report.scratch_stages[$i], $stages[$i], [StringComparison]::Ordinal)) {
                throw 'Scratch milestone evidence is invalid'
            }
        }
        $children = @(Get-ScratchChildStageNames)
        if ($Report.scratch_child_stages -isnot [array] -or
            $Report.scratch_child_stages.Count -ne $children.Count) { throw 'Scratch child evidence is incomplete' }
        for ($i = 0; $i -lt $children.Count; $i++) {
            if ($Report.scratch_child_stages[$i] -isnot [string] -or
                -not [string]::Equals($Report.scratch_child_stages[$i], $children[$i], [StringComparison]::Ordinal)) {
                throw 'Scratch child evidence is invalid'
            }
        }
        if (-not (Test-ScratchExpectedError $Report.scratch_errors)) { throw 'Scratch native error evidence is invalid' }
    }
    if ($Suite -ceq 'ProcessSource') {
        if ($Report.proof_scope -cne 'source_only') { throw 'Process source report claims unsupported scope' }
        Assert-ProcessSourceMarkers $Report
    }
}

function Get-ProcessSourceStageNames {
    @('guard_verified','token_verified','session_owned','consumer_ready','children_exited',
      'lifecycle_verified','schema_verified','cleanup_verified','passed')
}

function Get-ScratchStageNames {
    @('fixture_entered','state_ready','worker_started','worker_ready',
      'health_rejections_verified','live_recovery_refused','acl_probe_completed',
      'device_probe_completed','foreign_logon_denied','existing_proof_written',
      'own_scanner_entered','own_path_checked','own_devices_checked','own_workspace_created',
      'own_fixture_staged','own_command_ready','own_scanner_started','own_scanner_exited',
      'own_scanner_succeeded','own_output_verified','own_workspace_identified',
      'own_workspace_removed','own_health_verified','scanner_bounds_verified',
      'worker_stopped','retained_network_refused','recovery_completed','passed')
}

function Get-ScratchChildStageNames {
    @('entered','raw_devices_denied','capacity_created','capacity_limit_reached',
      'root_rename_denied','parent_listing_denied','root_write_denied','capacity_removed','passed')
}

function Test-ScratchExpectedError($Errors) {
    if ($Errors -isnot [array] -or $Errors.Count -ne 1) { return $false }
    $value = $Errors[0]
    if ($null -eq $value -or $value -is [array]) { return $false }
    $names = @($value.PSObject.Properties.Name)
    if ($value -is [Collections.IDictionary]) { $names = @($value.Keys) }
    if ($names.Count -ne 2 -or $names -cnotcontains 'operation' -or $names -cnotcontains 'native_error') { return $false }
    return ($value.operation -is [string] -and
        [string]::Equals($value.operation, 'capacity_write', [StringComparison]::Ordinal) -and
        ($value.native_error -is [int] -or $value.native_error -is [long]) -and
        $value.native_error -eq 112)
}

function Get-ScratchStages([string]$Log, [bool]$CheckPassed) {
    # Only this fixture's fixed milestone vocabulary may leave the private log.
    # A complete marker sequence cannot turn a failed executable into a pass.
    $result = @{ status='unavailable'; stages=@(); child_stages=@(); errors=@() }
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return $result }
    try {
        if ((Get-Item -LiteralPath $Log -ErrorAction Stop).Length -gt 1048576) { throw 'Oversized private log' }
        $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop)
    } catch { return $result }
    $allowed = @(Get-ScratchStageNames)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $stages = [Collections.Generic.List[string]]::new()
    $allowedChildren = @(Get-ScratchChildStageNames)
    $seenChildren = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $children = [Collections.Generic.List[string]]::new()
    $allowedErrors = @('existing_proof_write','own_device_open','own_fixture_open',
        'capacity_create','capacity_write','capacity_cleanup')
    $errors = [Collections.Generic.List[object]]::new()
    $seenErrors = @{}
    $valid = $true
    foreach ($line in $lines) {
        if ($line.IndexOf('ATHERNEX_SCRATCH_', [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        if ($line.StartsWith('ATHERNEX_SCRATCH_STAGE=', [StringComparison]::Ordinal)) {
            $stage = $line.Substring('ATHERNEX_SCRATCH_STAGE='.Length)
            if ($allowed -cnotcontains $stage) { $valid = $false; break }
            if ($seen.Contains($stage)) { continue }
            if ($stages.Count -ge $allowed.Count -or $stage -cne $allowed[$stages.Count]) { $valid = $false; break }
            $null = $seen.Add($stage)
            $stages.Add($stage)
        } elseif ($line.StartsWith('ATHERNEX_SCRATCH_CHILD_STAGE=', [StringComparison]::Ordinal)) {
            $stage = $line.Substring('ATHERNEX_SCRATCH_CHILD_STAGE='.Length)
            if (-not $seen.Contains('own_scanner_started') -or $allowedChildren -cnotcontains $stage) { $valid = $false; break }
            if ($seenChildren.Contains($stage)) { continue }
            if ($seen.Contains('own_scanner_exited') -or
                ($stage -ceq 'capacity_limit_reached' -and
                    (-not $seenErrors.ContainsKey('capacity_write') -or $seenErrors['capacity_write'] -cne '112'))) { $valid = $false; break }
            if ($children.Count -ge $allowedChildren.Count -or $stage -cne $allowedChildren[$children.Count]) { $valid = $false; break }
            $null = $seenChildren.Add($stage)
            $children.Add($stage)
        } elseif ($line.StartsWith('ATHERNEX_SCRATCH_ERROR=', [StringComparison]::Ordinal)) {
            $raw = $line.Substring('ATHERNEX_SCRATCH_ERROR='.Length)
            if ($raw -cnotmatch '^([a-z_]+):(none|0|[1-9][0-9]*|-[1-9][0-9]*)$') { $valid = $false; break }
            $operation = $Matches[1]; $code = $Matches[2]
            if ($allowedErrors -cnotcontains $operation -or
                ($operation.StartsWith('capacity_', [StringComparison]::Ordinal) -and -not $seen.Contains('own_scanner_started'))) { $valid = $false; break }
            $nativeError = $null
            if ($code -cne 'none') {
                $number = 0
                if (-not [int]::TryParse($code, [Globalization.NumberStyles]::AllowLeadingSign,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { $valid = $false; break }
                $nativeError = $number
            }
            if ($seenErrors.ContainsKey($operation)) {
                if ($seenErrors[$operation] -cne $code) { $valid = $false; break }
                continue
            }
            # Each first error belongs to the still-uncompleted operation.
            # Exact duplicates from a failed child's private panic may recur.
            $position = switch ($operation) {
                'existing_proof_write' { $seen.Contains('foreign_logon_denied') -and -not $seen.Contains('existing_proof_written') }
                'own_device_open' { $seen.Contains('own_path_checked') -and -not $seen.Contains('own_devices_checked') }
                'own_fixture_open' { $seen.Contains('own_workspace_created') -and -not $seen.Contains('own_fixture_staged') }
                'capacity_create' { $seenChildren.Contains('raw_devices_denied') -and -not $seenChildren.Contains('capacity_created') }
                'capacity_write' { $seenChildren.Contains('capacity_created') -and -not $seenChildren.Contains('capacity_limit_reached') }
                'capacity_cleanup' { $seenChildren.Contains('root_write_denied') -and -not $seenChildren.Contains('capacity_removed') }
            }
            if (-not $position -or
                ($operation.StartsWith('capacity_', [StringComparison]::Ordinal) -and $seen.Contains('own_scanner_exited'))) { $valid = $false; break }
            $seenErrors[$operation] = $code
            $errors.Add(@{ operation=$operation; native_error=$nativeError })
        } else { $valid = $false; break }
    }
    if (($CheckPassed -and ($stages.Count -ne $allowed.Count -or
            $children.Count -ne $allowedChildren.Count -or
            -not (Test-ScratchExpectedError @($errors.ToArray())))) -or
        (-not $CheckPassed -and $seen.Contains('passed'))) { $valid = $false }
    if (-not $valid) { return @{ status='invalid'; stages=@(); child_stages=@(); errors=@() } }
    return @{ status='valid'; stages=@($stages.ToArray()); child_stages=@($children.ToArray()); errors=@($errors.ToArray()) }
}

function Get-ProcessSourceStages([string]$Log) {
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    foreach ($stage in Get-ProcessSourceStageNames) {
        foreach ($line in $lines) {
            if ([string]::Equals($line, ('ATHERNEX_PROCESS_PROBE_STAGE=' + $stage), [StringComparison]::Ordinal)) {
                $stage
                break
            }
        }
    }
}

function Get-ProcessSourceFailures([string]$Log) {
    # Emit each fixed category at most once, never the captured line or error.
    $allowed = @('schema_provenance','schema_identity','schema_bounds','schema_shape',
        'property_missing','property_type','property_scalar','property_size',
        'record_provenance','record_bounds','session_ownership','session_configuration',
        'session_cleanup','native_loss','callback_loss','consumer_lifecycle',
        'controlled_lifecycle','controlled_timeout','token_state','api_failure','other')
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    foreach ($category in $allowed) {
        foreach ($line in $lines) {
            if ([string]::Equals($line, ('ATHERNEX_PROCESS_PROBE_FAILURE=' + $category), [StringComparison]::Ordinal)) {
                $category
                break
            }
        }
    }
}

function Get-ProcessSourceDiagnostics([string]$Log) {
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    $count = 0
    foreach ($line in $lines) {
        foreach ($operation in @('start_trace','open_trace','process_trace','query_trace','stop_trace','close_trace',
                                  'tdh_information','tdh_size','tdh_property','token_query')) {
            $pattern = '\A' + [regex]::Escape('ATHERNEX_PROCESS_PROBE_DIAGNOSTIC=' + $operation + ':') + '(0|[1-9][0-9]{0,9})\z'
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

function Get-ProcessSourceSchema([string]$Log) {
    # Hashes describe initialized/canonical TDH metadata only, never event values.
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    $count = 0
    foreach ($line in $lines) {
        $match = [regex]::Match($line,
            '\AATHERNEX_PROCESS_PROBE_SCHEMA=(start|end):(0|[1-9][0-9]{0,2}):(32|64):([1-9][0-9]?):([0-9a-f]{64})\z',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        [byte]$version = 0
        [byte]$properties = 0
        if ($match.Success -and [byte]::TryParse($match.Groups[2].Value,
            [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$version) -and
            [byte]::TryParse($match.Groups[4].Value,
            [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$properties) -and
            $properties -ge 1 -and $properties -le 64) {
            @{ event=$match.Groups[1].Value; version=$version; pointer_bits=[int]$match.Groups[3].Value;
                property_count=$properties; metadata_sha256=$match.Groups[5].Value }
            $count += 1
            if ($count -ge 32) { return }
        }
    }
}

function Assert-ProcessSourceMarkers($Report) {
    if ($null -eq $Report.process_source_failures -or @($Report.process_source_failures).Count -ne 0) {
        throw 'Process source proof has missing or contradictory failure evidence'
    }
    $expected = @(Get-ProcessSourceStageNames)
    if (@($Report.process_source_stages).Count -ne $expected.Count) { throw 'Process source proof is incomplete' }
    foreach ($stage in $expected) {
        if (@($Report.process_source_stages) -cnotcontains $stage) { throw 'Process source proof is incomplete' }
    }
    foreach ($event in @('start','end')) {
        if (@($Report.process_source_schema.event) -cnotcontains $event) { throw 'Process source schema proof is incomplete' }
    }
}

function Assert-ProcessSourceInputs([string]$OutputDirectory, [string]$ManifestSha256, [string]$ExpectedSource = '') {
    $path = Join-Path $OutputDirectory 'inputs.json'
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) {
        throw 'Process source input manifest changed'
    }
    $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $expected = @('endpoint.exe','native.exe','verify_windows_isolation_ci.ps1','verify_windows_service_ci.ps1')
    if ($manifest.schema -ne 1 -or $manifest.suite -cne 'ProcessSource' -or
        $manifest.github_sha -cnotmatch '\A[0-9a-f]{40}\z' -or
        ($ExpectedSource -and $manifest.github_sha -cne $ExpectedSource) -or
        @($manifest.sha256.PSObject.Properties.Name).Count -ne $expected.Count) { throw 'Invalid process source input manifest' }
    foreach ($name in $expected) {
        if ($manifest.sha256.$name -cnotmatch '\A[0-9a-f]{64}\z' -or
            (Get-FileHash -LiteralPath (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.sha256.$name) {
            throw 'Staged process source input changed'
        }
    }
    $manifest
}

function Invoke-ProcessSourceEvidence([string]$OutputDirectory, [string]$TaskName, $Action,
                                     [string]$ManifestSha256, [string]$ExpectedSource) {
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $ExpectedSource -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Invalid process source evidence binding'
    }
    $result = Join-Path $OutputDirectory 'process-source-worker.private.json'
    $log = Join-Path $OutputDirectory 'check-0.log'
    $public = @{ schema=1; suite='ProcessSource'; proof_scope='source_only'; production_readiness=$false;
        manifest_sha256=$ManifestSha256; native_process_source_validation_passed=$false;
        stages=@(); process_source_stages=@(); process_source_failures=@(); process_source_diagnostics=@(); process_source_schema=@();
        checks=[ordered]@{}; error='native_process_source_not_verified' }
    foreach ($check in Get-IsolationChecks ProcessSource) { $public.checks[$check.test] = 'not_verified' }
    try {
        $null = Assert-ProcessSourceInputs $OutputDirectory $ManifestSha256 $ExpectedSource
        $public.stages += 'inputs_verified'
        Invoke-ServiceFixtureTask $TaskName $Action $result $ManifestSha256 540 {
            param($Report, $Digest)
            Assert-IsolationReport $Report $Digest ProcessSource
        }
        # The helper returns only after task ownership and cleanup checks pass.
        $public.stages += 'task_completed_and_removed'
        $null = Assert-ProcessSourceInputs $OutputDirectory $ManifestSha256 $ExpectedSource
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-IsolationReport $report $ManifestSha256 ProcessSource
        $public.process_source_stages = @(Get-ProcessSourceStages $log)
        $public.process_source_failures = @(Get-ProcessSourceFailures $log)
        $public.process_source_schema = @(Get-ProcessSourceSchema $log)
        Assert-ProcessSourceMarkers $public
        $public.stages += 'report_verified'
        foreach ($check in Get-IsolationChecks ProcessSource) { $public.checks[$check.test] = 'passed' }
        $public.native_process_source_validation_passed = $true
        $public.error = $null
    } catch {
        try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'process-source-validation.private.log') -Append -ErrorAction Stop } catch { }
    }
    # These are bounded projections of complete fixed marker lines, even on failure.
    $public.process_source_stages = @(Get-ProcessSourceStages $log)
    $public.process_source_failures = @(Get-ProcessSourceFailures $log)
    $public.process_source_diagnostics = @(Get-ProcessSourceDiagnostics $log)
    $public.process_source_schema = @(Get-ProcessSourceSchema $log)
    if ($public.native_process_source_validation_passed) {
        try { Assert-ProcessSourceMarkers $public }
        catch {
            $public.native_process_source_validation_passed = $false
            $public.error = 'native_process_source_not_verified'
            foreach ($check in Get-IsolationChecks ProcessSource) { $public.checks[$check.test] = 'not_verified' }
        }
    }
    $public | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'process-source-validation.json') -Encoding UTF8
    if (-not $public.native_process_source_validation_passed) { throw 'Native process source proof failed; private evidence retained on worker' }
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
                                [ValidateSet('Isolation','Authentication','ProcessSource', IgnoreCase=$false)][string]$Suite = 'Isolation') {
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
            if ($Suite -ceq 'Isolation' -and $check.test -ceq 'protection::windows::scratch::tests::owned_worker_formats_bounds_scanner_writes_and_recovers_only_after_exit') {
                $passed = $Report.checks[$check.test] -ceq 'passed'
                $projection = Get-ScratchStages $log $passed
                $Report.scratch_stages = @($projection.stages)
                $Report.scratch_child_stages = @($projection.child_stages)
                $Report.scratch_errors = @($projection.errors)
                $Report.scratch_diagnostics = $projection.status
                if ($passed -and $projection.status -cne 'valid') {
                    $Report.checks[$check.test] = 'failed'
                    $Report.failures[$check.test] = 'scratch_diagnostics_invalid'
                }
            }
            if ($Suite -ceq 'Authentication') {
                $Report.authentication_stages = @(Get-AuthenticationStages $log)
                $Report.authentication_diagnostics = @(Get-AuthenticationDiagnostics $log)
                $Report.authentication_source = @(Get-AuthenticationSource $log)
                $Report.authentication_render = @(Get-AuthenticationRender $log)
            }
            if ($Suite -ceq 'ProcessSource') {
                $Report.process_source_stages = @(Get-ProcessSourceStages $log)
                $Report.process_source_failures = @(Get-ProcessSourceFailures $log)
                $Report.process_source_diagnostics = @(Get-ProcessSourceDiagnostics $log)
                $Report.process_source_schema = @(Get-ProcessSourceSchema $log)
            }
        }
        # Each test runs in a separate process with fresh fixture paths. WFP
        # rules name only that test's private image, never the runner binary.
        $position += 1
    }
    if ($Report.failures.Count) { throw 'One or more native isolation checks failed' }
    if ($Suite -ceq 'ProcessSource') { Assert-ProcessSourceMarkers $Report }
}

function Invoke-IsolationWorkerChecks([string]$OutputDirectory, $Manifest, $Report,
                                      [ValidateSet('Isolation','Authentication','ProcessSource', IgnoreCase=$false)][string]$Suite = 'Isolation') {
    $authenticationOptIn = 'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST'
    $previousOptIn = [Environment]::GetEnvironmentVariable($authenticationOptIn, 'Process')
    $processOptIn = 'ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST'
    $previousProcessOptIn = [Environment]::GetEnvironmentVariable($processOptIn, 'Process')
    try {
        if ($manifest.schema -ne 1 -or $manifest.suite -cne $Suite) { throw 'Invalid native check input manifest suite' }
        # Set this only after the disposable LocalSystem worker and its suite
        # manifest have been verified. The native fixture repeats identity checks.
        $optIn = if ($Suite -ceq 'Authentication') { '1' } else { $null }
        [Environment]::SetEnvironmentVariable($authenticationOptIn, $optIn, 'Process')
        if ($Suite -ceq 'ProcessSource') {
            $null = Assert-ProcessSourceInputs $OutputDirectory $Report.manifest_sha256
            [Environment]::SetEnvironmentVariable($processOptIn, '1', 'Process')
        } else {
            [Environment]::SetEnvironmentVariable($processOptIn, $null, 'Process')
        }
        Invoke-IsolationChecks $OutputDirectory $manifest $report $Suite
    } catch {
        $Report.error = 'native_worker_failed'
        try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'worker.log') -Append -ErrorAction Stop } catch { }
        throw 'Native worker failed; private evidence retained on worker'
    } finally {
        [Environment]::SetEnvironmentVariable($authenticationOptIn, $previousOptIn, 'Process')
        [Environment]::SetEnvironmentVariable($processOptIn, $previousProcessOptIn, 'Process')
    }
}

function Invoke-IsolationWorker([string]$OutputDirectory, [bool]$DisposableHost,
                                [ValidateSet('Isolation','Authentication','ProcessSource', IgnoreCase=$false)][string]$Suite = 'Isolation') {
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
    if ($Suite -ceq 'Isolation') {
        $report.scratch_stages = @()
        $report.scratch_child_stages = @()
        $report.scratch_errors = @()
        $report.scratch_diagnostics = 'unavailable'
    }
    if ($Suite -ceq 'Authentication') {
        $report.authentication_stages = @()
        $report.authentication_diagnostics = @()
        $report.authentication_source = @()
        $report.authentication_render = @()
    }
    if ($Suite -ceq 'ProcessSource') {
        $report.proof_scope = 'source_only'
        $report.process_source_stages = @()
        $report.process_source_failures = @()
        $report.process_source_diagnostics = @()
        $report.process_source_schema = @()
    }
    try { Invoke-IsolationWorkerChecks $OutputDirectory $manifest $report $Suite }
    finally {
        $filename = if ($Suite -ceq 'ProcessSource') { 'process-source-worker.private.json' } else { $Suite.ToLowerInvariant() + '-validation.json' }
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory $filename) -Encoding UTF8
    }
}

function Invoke-IsolationCi([string]$EndpointTests, [string]$NativeTests, [string]$OutputDirectory, [bool]$DisposableHost,
                            [ValidateSet('Isolation','Authentication','ProcessSource', IgnoreCase=$false)][string]$Suite = 'Isolation') {
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
    if ($Suite -ceq 'ProcessSource') {
        if ($env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z') { throw 'Process source commit binding is missing' }
        $sources['verify_windows_isolation_ci.ps1'] = $PSCommandPath
        $sources['verify_windows_service_ci.ps1'] = Join-Path $PSScriptRoot 'verify_windows_service_ci.ps1'
    }
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
    if ($Suite -ceq 'ProcessSource') {
        $null = Assert-ProcessSourceInputs $OutputDirectory $digest $env:GITHUB_SHA
        & {
            param($ProofDirectory, $ProofTask, $ProofAction, $ProofDigest, $ProofSource)
            . (Join-Path $ProofDirectory 'verify_windows_service_ci.ps1')
            Invoke-ProcessSourceEvidence $ProofDirectory $ProofTask $ProofAction $ProofDigest $ProofSource
        } $OutputDirectory $taskName $action $digest $env:GITHUB_SHA
        return
    }
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
