<#
Prove bounded Windows ETW network collection and the actual release-agent loop
on a disposable LocalSystem worker. Raw records, tuples and worker reports remain private.
This is an acceptance fixture, not SCM or production-readiness proof.
Dot-sourcing defines helpers only.
#>
param([string]$AgentExecutable, [string]$EndpointTests, [string]$OutputDirectory,
      [switch]$DisposableHost, [switch]$Worker)

function Get-NetworkEventsTests {
    @('telemetry::windows_network_events::native_test::network_reports_replay_with_visible_capture_gaps')
}

function Get-NetworkEventsInputNames {
    @('agent.exe','endpoint-tests.exe','verify_windows_network_events_ci.ps1',
      'verify_windows_isolation_ci.ps1','verify_windows_service_ci.ps1')
}

function Test-NetworkEventsLiteral($Value, [string]$Expected) {
    $Value -is [string] -and [StringComparer]::Ordinal.Equals($Value, $Expected)
}

# ConvertFrom-Json can discard repeated properties. Check bounded JSON tokens
# first, refusing duplicate/case-alias/escaped property names in each object.
# Values remain private; this returns only the parsed object, never source text.
function Read-NetworkEventsJson([string]$Path) {
    try {
        if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 64KB) { throw 'Bound' }
        $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
        if (-not $json -or -not $json.TrimStart().StartsWith('{', [StringComparison]::Ordinal)) { throw 'Object' }
        $tokens = [regex]'\G(?:[ \t\r\n]+|"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|[{}\[\],:]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)'
        $stack = [Collections.Generic.List[object]]::new()
        $position = 0
        while ($position -lt $json.Length) {
            $match = $tokens.Match($json, $position)
            if (-not $match.Success -or $match.Index -ne $position) { throw 'Token' }
            $token = $match.Value; $position += $match.Length
            if ($token -match '\A[ \t\r\n]+\z') { continue }
            $frame = if ($stack.Count) { $stack[$stack.Count - 1] } else { $null }
            if ($token -ceq '{' -or $token -ceq '[') {
                if ($stack.Count -ge 32) { throw 'Depth' }
                $stack.Add(@{ kind=$token; key=$true; names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) })
            } elseif ($token -ceq '}' -or $token -ceq ']') {
                if (-not $frame -or ($token -ceq '}' -and $frame.kind -cne '{') -or ($token -ceq ']' -and $frame.kind -cne '[')) { throw 'Container' }
                $stack.RemoveAt($stack.Count - 1)
            } elseif ($token -ceq ',') {
                if ($frame -and $frame.kind -ceq '{') { $frame.key = $true }
            } elseif ($token.StartsWith('"', [StringComparison]::Ordinal) -and $frame -and $frame.kind -ceq '{' -and $frame.key) {
                $name = $token.Substring(1, $token.Length - 2)
                if ($name.Contains('\') -or -not $frame.names.Add($name)) { throw 'Duplicate property' }
                $frame.key = $false
            }
        }
        if ($stack.Count) { throw 'Container' }
        $value = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        if ($value -isnot [pscustomobject]) { throw 'Object' }
        $value
    } catch { throw 'Invalid network-events private JSON' }
}

function Test-NetworkEventsFields($Object, [string[]]$Expected) {
    if ($Object -isnot [pscustomobject]) { return $false }
    $names = @($Object.PSObject.Properties.Name)
    $names.Count -eq $Expected.Count -and @($Expected | Where-Object { [Array]::IndexOf([string[]]$names, $_) -lt 0 }).Count -eq 0
}

function Assert-NetworkEventsInputs([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource = '') {
    $path = Join-Path $ProofDirectory 'inputs.json'
    try { $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { throw 'Invalid network-events input manifest' }
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $actual -cne $ManifestSha256) {
        throw 'Network-events input manifest changed'
    }
    try { $manifest = Read-NetworkEventsJson $path }
    catch { throw 'Invalid network-events input manifest' }
    $expected = @(Get-NetworkEventsInputNames)
    if (-not (Test-NetworkEventsFields $manifest @('schema','suite','github_sha','sha256')) -or
        -not (Test-NetworkEventsFields $manifest.sha256 $expected) -or
        ($manifest.schema -isnot [int] -and $manifest.schema -isnot [long]) -or
        $manifest.schema -ne 1 -or -not (Test-NetworkEventsLiteral $manifest.suite 'NetworkEvents') -or
        $manifest.github_sha -isnot [string] -or $manifest.github_sha -cnotmatch '\A[0-9a-f]{40}\z' -or
        ($ExpectedSource -and $manifest.github_sha -cne $ExpectedSource) -or
        @($manifest.sha256.PSObject.Properties.Name).Count -ne $expected.Count) {
        throw 'Invalid network-events input manifest'
    }
    foreach ($name in $expected) {
        if ([Array]::IndexOf([string[]]@($manifest.sha256.PSObject.Properties.Name), $name) -lt 0 -or
            $manifest.sha256.$name -isnot [string] -or $manifest.sha256.$name -cnotmatch '\A[0-9a-f]{64}\z') {
            throw 'Staged network-events input changed'
        }
        try { $actual = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
        catch { throw 'Staged network-events input invalid' }
        if ($actual -cne $manifest.sha256.$name) { throw 'Staged network-events input changed' }
    }
    $manifest
}

function Assert-NetworkEventsReport($Report, [string]$ManifestSha256) {
    $fields = @('schema','suite','native_windows_executed','production_readiness','proof_scope',
        'manifest_sha256','user_sid','session_id','windows_version','checks','progress','error')
    if (-not (Test-NetworkEventsFields $Report $fields) -or
        -not (Test-NetworkEventsFields $Report.checks @(Get-NetworkEventsTests)) -or
        -not (Test-NetworkEventsFields $Report.progress @(Get-NetworkEventsTests))) {
        throw 'Invalid network-events worker identity or result'
    }
    if (($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or
        $Report.schema -ne 1 -or -not (Test-NetworkEventsLiteral $Report.suite 'NetworkEvents') -or
        $Report.native_windows_executed -isnot [bool] -or $Report.production_readiness -isnot [bool] -or
        $Report.native_windows_executed -cne $true -or $Report.production_readiness -cne $false -or
        -not (Test-NetworkEventsLiteral $Report.proof_scope 'component_and_agent') -or
        -not (Test-NetworkEventsLiteral $Report.manifest_sha256 $ManifestSha256) -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or
        -not (Test-NetworkEventsLiteral $Report.user_sid 'S-1-5-18') -or $Report.session_id -cne 0 -or
        $Report.windows_version -isnot [string] -or -not $Report.windows_version -or
        $null -ne $Report.error) { throw 'Invalid network-events worker identity or result' }
    $expected = @(Get-NetworkEventsTests)
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne $expected.Count) { throw 'Incomplete network-events check set' }
    foreach ($name in $expected) {
        if ([Array]::IndexOf([string[]]$names, $name) -lt 0 -or -not (Test-NetworkEventsLiteral $Report.checks.$name 'passed')) {
            throw 'Network-events native check did not pass'
        }
    }
    $progress = @($Report.progress.PSObject.Properties.Name)
    if ($progress.Count -ne 1 -or [Array]::IndexOf([string[]]$progress, $expected[0]) -lt 0 -or
        -not (Test-NetworkEventsLiteral $Report.progress.($expected[0]) 'completed')) {
        throw 'Network-events native check did not pass'
    }
}

# This validator authorizes diagnostic projection only, never native success.
function Assert-NetworkEventsPartialReport($Report, [string]$ManifestSha256) {
    $fields = @('schema','suite','native_windows_executed','production_readiness','proof_scope',
        'manifest_sha256','user_sid','session_id','windows_version','checks','progress','error')
    $names = @($Report.PSObject.Properties.Name)
    if (-not (Test-NetworkEventsFields $Report $fields) -or $names.Count -ne $fields.Count -or @($fields | Where-Object { [Array]::IndexOf([string[]]$names, $_) -lt 0 }).Count -ne 0 -or
        ($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or $Report.schema -ne 1 -or
        -not (Test-NetworkEventsLiteral $Report.suite 'NetworkEvents') -or
        -not (Test-NetworkEventsLiteral $Report.proof_scope 'component_and_agent') -or
        $Report.native_windows_executed -isnot [bool] -or -not $Report.native_windows_executed -or
        $Report.production_readiness -isnot [bool] -or $Report.production_readiness -or
        -not (Test-NetworkEventsLiteral $Report.manifest_sha256 $ManifestSha256) -or
        -not (Test-NetworkEventsLiteral $Report.user_sid 'S-1-5-18') -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or $Report.session_id -ne 0 -or
        $Report.windows_version -isnot [string] -or -not $Report.windows_version -or
        ($null -ne $Report.error -and -not (Test-NetworkEventsLiteral $Report.error 'native_worker_failed'))) {
        throw 'Invalid network-events diagnostic identity'
    }
    $expected = @(Get-NetworkEventsTests)
    $checks = @($Report.checks.PSObject.Properties.Name)
    $progress = @($Report.progress.PSObject.Properties.Name)
    if (-not (Test-NetworkEventsFields $Report.checks $expected) -or -not (Test-NetworkEventsFields $Report.progress $expected) -or $checks.Count -ne 1 -or $progress.Count -ne 1) { throw 'Invalid network-events diagnostic check set' }
    $closed = $false
    foreach ($name in $expected) {
        $state = $Report.progress.$name
        if ([Array]::IndexOf([string[]]$checks, $name) -lt 0 -or [Array]::IndexOf([string[]]$progress, $name) -lt 0 -or
            $state -isnot [string] -or $state -cnotmatch '\A(not_attempted|attempted|completed|failed)\z' -or
            $Report.checks.$name -isnot [string] -or
            ($state -ceq 'completed' -and -not (Test-NetworkEventsLiteral $Report.checks.$name 'passed')) -or
            ($state -cne 'completed' -and -not (Test-NetworkEventsLiteral $Report.checks.$name 'not_verified')) -or
            ($state -ceq 'failed' -and $Report.error -cne 'native_worker_failed') -or
            ($closed -and $state -cne 'not_attempted')) { throw 'Invalid network-events diagnostic progress' }
        if ($state -cne 'completed') { $closed = $true }
    }
}

function Save-NetworkEventsCheckpoint([string]$ProofDirectory, $Report) {
    $pending = Join-Path $ProofDirectory 'network-events-worker.pending.private.json'
    $destination = Join-Path $ProofDirectory 'network-events-worker.private.json'
    try {
        $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $pending -Encoding UTF8 -ErrorAction Stop
        # Same protected directory: readers see either the preceding or new complete checkpoint.
        if (Test-Path -LiteralPath $destination) { [IO.File]::Replace($pending, $destination, [System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($pending, $destination) }
    } catch { throw 'Network-events private checkpoint failed' }
}

function Get-NetworkEventsStageNames {
    @('guard_verified','agent_config_verified','source_ready','tcp4_verified','tcp6_verified','udp4_verified','udp6_verified','tdh_differential_verified','coexistence_verified','source_loss_verified','stalled_http_verified','queue_loss_verified','crash_replay_verified','orphan_recovered','session_gap_verified','http_delivery_verified','server_replay_verified','export_authorization_verified','original_export_verified','portal_coverage_verified','rollout_gates_verified','server_restart_verified','cleanup_verified','token_verified','passed')
}

function Get-NetworkEventsFailureNames {
    @('guard','token','configuration','ownership','source_start','source_stopped','controlled_traffic','tdh_schema','tdh_property','native_loss','durable_admission','transport','replay','authorization','original_export','portal','rollout','cleanup','timeout')
}

function Get-NetworkEventsOperationNames {
    @('start_trace','open_trace','query_trace','stop_trace','process_trace','close_trace','token_query','tdh_information','tdh_format_property')
}

function Get-NetworkEventsLogMarkers([string]$Log, [switch]$RequireLog) {
    $stages = @(Get-NetworkEventsStageNames)
    $failures = @(Get-NetworkEventsFailureNames)
    $operations = @(Get-NetworkEventsOperationNames)
    $result = @{ stages=@(); failures=@(); api_errors=@() }
    $invalid = $false
    try {
        if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) {
            if ($RequireLog) { throw 'Missing network-events diagnostic log' }
            return $result
        }
        if ((Get-Item -LiteralPath $Log -ErrorAction Stop).Length -gt 16MB) { throw 'Oversized network-events diagnostic log' }
        foreach ($line in Get-Content -LiteralPath $Log -Encoding UTF8 -ErrorAction Stop) {
            $recognized = $false
            foreach ($tag in $stages) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_NETWORK_EVENTS_STAGE=' + $tag))) {
                    $recognized = $true
                    if ($result.stages -cnotcontains $tag) { $result.stages += $tag }
                }
            }
            if ($line -cmatch '\AATHERNEX_NETWORK_EVENTS_DIAGNOSTIC=([a-z_]+):(0|[1-9][0-9]{0,9})\z') {
                $operation = $Matches[1]; $code = [uint32]0
                if ([Array]::IndexOf([string[]]$operations, $operation) -ge 0 -and [uint32]::TryParse($Matches[2], [ref]$code)) {
                    $recognized = $true
                    if ($result.api_errors.Count -lt 32) { $result.api_errors += @{ operation=$operation; win32_error=$code } }
                }
            }
            foreach ($tag in $failures) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_NETWORK_EVENTS_FAILURE=' + $tag))) {
                    $recognized = $true
                    if ($result.failures -cnotcontains $tag) { $result.failures += $tag }
                }
            }
            if ($line.StartsWith('ATHERNEX_NETWORK_EVENTS_', [StringComparison]::Ordinal) -and -not $recognized) { $invalid = $true }
        }
    } catch { throw 'Network-events diagnostic log unavailable' }
    # Own-prefix malformed evidence is a refusal, not an ignored success signal.
    # Never retain or project the unrecognized line.
    if ($invalid) { throw 'Network-events proof has contradictory failure evidence' }
    $result
}

function Assert-NetworkEventsMarkers($Markers) {
    if ($Markers.failures -isnot [array] -or $Markers.failures.Count -ne 0 -or
        $Markers.api_errors -isnot [array] -or $Markers.api_errors.Count -ne 0) {
        throw 'Network-events proof has contradictory failure evidence'
    }
    $expected = @(Get-NetworkEventsStageNames)
    if ($Markers.stages -isnot [array] -or $Markers.stages.Count -ne $expected.Count) {
        throw 'Network-events proof is incomplete'
    }
    foreach ($value in $Markers.stages) {
        if ($value -isnot [string]) { throw 'Network-events proof is incomplete' }
    }
    foreach ($stage in $expected) {
        if ([Array]::IndexOf([string[]]$Markers.stages, $stage) -lt 0) { throw 'Network-events proof is incomplete' }
    }
}

function Get-NetworkEventsRunnerFailure([string]$Message) {
    $known = @{
        'Network-events input manifest changed'='input_manifest_changed'
        'Invalid network-events input manifest'='input_manifest_invalid'
        'Staged network-events input changed'='input_file_changed'
        'Staged network-events input invalid'='input_file_invalid'
        'Invalid network-events worker identity or result'='report_identity_invalid'
        'Incomplete network-events check set'='report_check_set_invalid'
        'Network-events native check did not pass'='report_check_failed'
        'Native service task deadline elapsed without a completed, valid report'='task_timeout'
        'Fixture task already exists'='task_ownership_failed'
        'Fixture task ownership changed; retained for inspection'='task_ownership_failed'
        'Fixture task did not stop; retained for inspection'='task_stop_failed'
        'Network-events proof has contradictory failure evidence'='source_proof_failed'
        'Network-events proof is incomplete'='source_proof_incomplete'
        'Network-events diagnostic log unavailable'='source_log_unavailable'
    }
    foreach ($item in $known.GetEnumerator()) {
        if ([StringComparer]::Ordinal.Equals($Message, $item.Key)) { return $item.Value }
    }
    if ($Message -cmatch '\ANative service task failed( before writing its report)?: (0|[1-9][0-9]{0,9})\z') {
        $withoutReport = $Matches[1]
        $code = [uint32]0
        if ([uint32]::TryParse($Matches[2], [ref]$code)) {
            if ($withoutReport) { return 'task_failed_without_report' }
            return 'task_failed_with_report'
        }
    }
    'other'
}

function Get-NetworkEventsDiagnostics([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource) {
    $result = @{ status='unbound'; checks=[ordered]@{} }
    try { $null = Assert-NetworkEventsInputs $ProofDirectory $ManifestSha256 $ExpectedSource } catch { return $result }
    $path = Join-Path $ProofDirectory 'network-events-worker.private.json'
    try {
        $result.status = 'unavailable'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $result.status = 'missing'; return $result }
        $result.status = 'invalid'
        if ((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 64KB) { return $result }
        $report = Read-NetworkEventsJson $path
        Assert-NetworkEventsPartialReport $report $ManifestSha256
        $result.status = 'unavailable'
        $projected = [ordered]@{}
        $position = 0
        foreach ($name in Get-NetworkEventsTests) {
            $markers = @{ stages=@(); failures=@(); api_errors=@() }
            if ($report.progress.$name -cne 'not_attempted') {
                $markers = Get-NetworkEventsLogMarkers (Join-Path $ProofDirectory ('check-' + $position + '.log'))
            }
            $projected[$name] = @{ progress=$report.progress.$name; stages=$markers.stages; failures=$markers.failures; api_errors=$markers.api_errors }
            $position += 1
        }
        # Recheck after reading diagnostic files as well as before projecting them.
        $result.status = 'unbound'
        $null = Assert-NetworkEventsInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $result.checks = $projected
        $result.status = 'available'
    } catch { }
    $result
}

function Invoke-NetworkEventsWorkerChecks([string]$ProofDirectory, $Report) {
    $environment = @('ATHERNEX_WINDOWS_NETWORK_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_NETWORK_EVENTS_AGENT',
        'ATHERNEX_WINDOWS_AUTHENTICATION_AGENT_DISPOSABLE_HOST','ATHERNEX_NATIVE_AUTHENTICATION_AGENT',
        'ATHERNEX_WINDOWS_NETWORK_EVENTS_PROBE_DISPOSABLE_HOST',
        'ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST','ATHERNEX_NATIVE_WORKSPACE_AGENT',
        'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST','ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST',
        'ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT')
    $previous = @{}
    foreach ($name in $environment) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $active = $null
    try {
        $null = Assert-NetworkEventsInputs $ProofDirectory $Report.manifest_sha256
        [Environment]::SetEnvironmentVariable($environment[0], '1', 'Process')
        [Environment]::SetEnvironmentVariable($environment[1], (Join-Path $ProofDirectory 'agent.exe'), 'Process')
        foreach ($name in $environment[2..($environment.Count - 1)]) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
        $position = 0
        foreach ($name in Get-NetworkEventsTests) {
            $null = Assert-NetworkEventsInputs $ProofDirectory $Report.manifest_sha256
            $log = Join-Path $ProofDirectory ('check-' + $position + '.log')
            $active = $name
            $Report.progress[$name] = 'attempted'
            Save-NetworkEventsCheckpoint $ProofDirectory $Report
            Invoke-IsolationCheck (Join-Path $ProofDirectory 'endpoint-tests.exe') $name $log
            $markers = Get-NetworkEventsLogMarkers $log -RequireLog
            Assert-NetworkEventsMarkers $markers
            $null = Assert-NetworkEventsInputs $ProofDirectory $Report.manifest_sha256
            $Report.checks[$name] = 'passed'
            $Report.progress[$name] = 'completed'
            Save-NetworkEventsCheckpoint $ProofDirectory $Report
            $active = $null
            $position += 1
        }
    } catch {
        $Report.error = 'native_worker_failed'
        if ($active) { $Report.checks[$active] = 'not_verified'; $Report.progress[$active] = 'failed' }
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'worker.log') -Append -ErrorAction Stop } catch { }
        try { Save-NetworkEventsCheckpoint $ProofDirectory $Report } catch { }
        throw 'Native network-events worker failed; private evidence retained on worker'
    } finally {
        foreach ($name in $environment) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    }
}

function Invoke-NetworkEventsWorker([string]$ProofDirectory, [bool]$AllowDisposable) {
    $ErrorActionPreference = 'Stop'
    if (-not $AllowDisposable -or [Environment]::OSVersion.Platform -ne 'Win32NT' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'Network-events worker requires disposable native LocalSystem in session zero'
    }
    $digest = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory 'inputs.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = Assert-NetworkEventsInputs $ProofDirectory $digest
    $report = @{ schema=1; suite='NetworkEvents'; native_windows_executed=$true; production_readiness=$false;
        proof_scope='component_and_agent'; manifest_sha256=$digest; user_sid='S-1-5-18'; session_id=0;
        windows_version=[Environment]::OSVersion.Version.ToString(); checks=[ordered]@{}; progress=[ordered]@{}; error=$null }
    foreach ($name in Get-NetworkEventsTests) { $report.checks[$name] = 'not_verified'; $report.progress[$name] = 'not_attempted' }
    Save-NetworkEventsCheckpoint $ProofDirectory $report
    # Import parameters cannot overwrite these deliberately distinct local names.
    . (Join-Path $ProofDirectory 'verify_windows_isolation_ci.ps1')
    Invoke-NetworkEventsWorkerChecks $ProofDirectory $report
}

function Invoke-NetworkEventsEvidence([string]$ProofDirectory, [string]$ProofTask, $ProofAction,
                                         [string]$ManifestSha256, [string]$ExpectedSource) {
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $ExpectedSource -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Invalid network-events evidence binding'
    }
    $result = Join-Path $ProofDirectory 'network-events-worker.private.json'
    $public = @{ schema=1; suite='NetworkEvents'; proof_scope='component_and_agent'; production_readiness=$false;
        manifest_sha256=$ManifestSha256; native_network_events_validation_passed=$false;
        stages=@(); checks=[ordered]@{}; error='native_network_events_not_verified'; runner_failure=$null;
        diagnostics=@{ status='unavailable'; checks=[ordered]@{} } }
    foreach ($name in Get-NetworkEventsTests) { $public.checks[$name] = 'not_verified' }
    try {
        $null = Assert-NetworkEventsInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $public.stages += 'inputs_verified'
        Invoke-ServiceFixtureTask $ProofTask $ProofAction $result $ManifestSha256 840 {
            param($Report, $Digest)
            Assert-NetworkEventsReport $Report $Digest
        }
        $public.stages += 'task_completed_and_removed'
        $null = Assert-NetworkEventsInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Read-NetworkEventsJson $result
        Assert-NetworkEventsReport $report $ManifestSha256
        $markers = Get-NetworkEventsLogMarkers (Join-Path $ProofDirectory 'check-0.log') -RequireLog
        Assert-NetworkEventsMarkers $markers
        $null = Assert-NetworkEventsInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Read-NetworkEventsJson $result
        Assert-NetworkEventsReport $report $ManifestSha256
        # Publish the exact marker snapshot that passed the agent proof; never
        # replace it with a later diagnostic read after authorizing success.
        $public.diagnostics = @{ status='available'; checks=[ordered]@{} }
        $public.diagnostics.checks[@(Get-NetworkEventsTests)[0]] = @{ progress='completed';
            stages=$markers.stages; failures=$markers.failures; api_errors=$markers.api_errors }
        $public.stages += 'report_verified'
        foreach ($name in Get-NetworkEventsTests) { $public.checks[$name] = 'passed' }
        $public.native_network_events_validation_passed = $true
        $public.error = $null
    } catch {
        $public.runner_failure = Get-NetworkEventsRunnerFailure $_.Exception.Message
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'network-events-validation.private.log') -Append -ErrorAction Stop } catch { }
        $public.diagnostics = Get-NetworkEventsDiagnostics $ProofDirectory $ManifestSha256 $ExpectedSource
    }
    $public | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ProofDirectory 'network-events-validation.json') -Encoding UTF8
    if (-not $public.native_network_events_validation_passed) { throw 'Native network-events validation failed; private evidence retained on worker' }
}

function Invoke-NetworkEventsCi([string]$AgentPath, [string]$TestsPath, [string]$ProofDirectory, [bool]$AllowDisposable) {
    $ErrorActionPreference = 'Stop'
    if (-not $AllowDisposable -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
        [Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Requires an explicitly disposable GitHub-hosted Windows runner' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Requires an elevated runner'
    }
    if (-not $AgentPath -or -not $TestsPath -or -not $ProofDirectory -or $env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Requires exact tests, destination and source revision'
    }
    $sources = @{ 'agent.exe'=(Resolve-Path -LiteralPath $AgentPath).Path;
        'endpoint-tests.exe'=(Resolve-Path -LiteralPath $TestsPath).Path;
        'verify_windows_network_events_ci.ps1'=$PSCommandPath;
        'verify_windows_isolation_ci.ps1'=(Join-Path $PSScriptRoot 'verify_windows_isolation_ci.ps1');
        'verify_windows_service_ci.ps1'=(Join-Path $PSScriptRoot 'verify_windows_service_ci.ps1') }
    $ProofDirectory = [IO.Path]::GetFullPath($ProofDirectory)
    if ((Test-Path -LiteralPath $ProofDirectory) -or -not (Test-Path -LiteralPath (Split-Path -Parent $ProofDirectory) -PathType Container)) {
        throw 'OutputDirectory must be new and have an existing parent directory'
    }
    $null = New-Item -ItemType Directory -Path $ProofDirectory -ErrorAction Stop
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $ProofDirectory -AclObject $acl
    $sourceRevision = $env:GITHUB_SHA
    $manifest = @{ schema=1; suite='NetworkEvents'; github_sha=$sourceRevision; sha256=@{} }
    foreach ($name in Get-NetworkEventsInputNames) {
        $digest = (Get-FileHash -LiteralPath $sources[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $sources[$name] -Destination (Join-Path $ProofDirectory $name)
        if ((Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
            throw 'Staged network-events input differs from source'
        }
        $manifest.sha256[$name] = $digest
    }
    $manifestPath = Join-Path $ProofDirectory 'inputs.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixture = Join-Path $ProofDirectory 'verify_windows_network_events_ci.ps1'
    $parameters = @{ Fixture=$fixture; ProofDirectory=$ProofDirectory } | ConvertTo-Json -Compress
    $literal = $parameters.Replace("'", "''")
    $code = @'
$ErrorActionPreference = 'Stop'
$p = ConvertFrom-Json '__PARAMETERS__'
try { & $p.Fixture -OutputDirectory $p.ProofDirectory -Worker -DisposableHost; exit 0 }
catch { $_ | Out-File -LiteralPath (Join-Path $p.ProofDirectory 'worker.log') -Append; exit 1 }
'@.Replace('__PARAMETERS__', $literal)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encoded)
    $taskName = 'AthernexNetworkEventsValidation-' + [Guid]::NewGuid().ToString('N')
    $null = Assert-NetworkEventsInputs $ProofDirectory $digest $sourceRevision
    . (Join-Path $ProofDirectory 'verify_windows_service_ci.ps1')
    Invoke-NetworkEventsEvidence $ProofDirectory $taskName $action $digest $sourceRevision
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Worker) { Invoke-NetworkEventsWorker $OutputDirectory $DisposableHost.IsPresent }
    else {
        try { Invoke-NetworkEventsCi $AgentExecutable $EndpointTests $OutputDirectory $DisposableHost.IsPresent }
        catch {
            try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'runner.log') -Append -ErrorAction Stop } catch { }
            throw 'Native network-events validation failed; private evidence retained on worker when available'
        }
    }
}
