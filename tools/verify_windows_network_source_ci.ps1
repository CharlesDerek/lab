<#
Prove a bounded TCP/UDP ETW source on an explicitly disposable Windows
LocalSystem worker. Raw records, endpoint values, errors and worker reports remain
in the protected VM directory. This does not validate a production collector.
Dot-sourcing defines helpers only.
#>
param([string]$EndpointTests, [string]$OutputDirectory,
      [switch]$DisposableHost, [switch]$Worker)

function Get-NetworkSourceTests {
    @('telemetry::windows_network_events_probe::owned_network_source_reports_controlled_tcp_udp')
}

function Get-NetworkSourceInputNames {
    @('endpoint-tests.exe','verify_windows_network_source_ci.ps1',
      'verify_windows_isolation_ci.ps1','verify_windows_service_ci.ps1')
}

function Test-NetworkSourceLiteral($Value, [string]$Expected) {
    $Value -is [string] -and [StringComparer]::Ordinal.Equals($Value, $Expected)
}

function Assert-NetworkSourceInputs([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource = '') {
    $path = Join-Path $ProofDirectory 'inputs.json'
    try { $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { throw 'Invalid network-source input manifest' }
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $actual -cne $ManifestSha256) {
        throw 'Network-source input manifest changed'
    }
    try { $manifest = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Invalid network-source input manifest' }
    $expected = @(Get-NetworkSourceInputNames)
    if (($manifest.schema -isnot [int] -and $manifest.schema -isnot [long]) -or
        $manifest.schema -ne 1 -or -not (Test-NetworkSourceLiteral $manifest.suite 'NetworkSource') -or
        $manifest.github_sha -isnot [string] -or $manifest.github_sha -cnotmatch '\A[0-9a-f]{40}\z' -or
        ($ExpectedSource -and $manifest.github_sha -cne $ExpectedSource) -or
        @($manifest.sha256.PSObject.Properties.Name).Count -ne $expected.Count) {
        throw 'Invalid network-source input manifest'
    }
    foreach ($name in $expected) {
        if ([Array]::IndexOf([string[]]@($manifest.sha256.PSObject.Properties.Name), $name) -lt 0 -or
            $manifest.sha256.$name -isnot [string] -or $manifest.sha256.$name -cnotmatch '\A[0-9a-f]{64}\z') {
            throw 'Staged network-source input changed'
        }
        try { $actual = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
        catch { throw 'Staged network-source input invalid' }
        if ($actual -cne $manifest.sha256.$name) { throw 'Staged network-source input changed' }
    }
    $manifest
}

function Assert-NetworkSourceReport($Report, [string]$ManifestSha256) {
    if (($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or
        $Report.schema -ne 1 -or -not (Test-NetworkSourceLiteral $Report.suite 'NetworkSource') -or
        $Report.native_windows_executed -isnot [bool] -or $Report.production_readiness -isnot [bool] -or
        $Report.native_windows_executed -cne $true -or $Report.production_readiness -cne $false -or
        -not (Test-NetworkSourceLiteral $Report.proof_scope 'source_only') -or
        -not (Test-NetworkSourceLiteral $Report.manifest_sha256 $ManifestSha256) -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or
        -not (Test-NetworkSourceLiteral $Report.user_sid 'S-1-5-18') -or $Report.session_id -cne 0 -or
        $Report.windows_version -isnot [string] -or -not $Report.windows_version -or
        $null -ne $Report.error) { throw 'Invalid network-source worker identity or result' }
    $expected = @(Get-NetworkSourceTests)
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne $expected.Count) { throw 'Incomplete network-source check set' }
    foreach ($name in $expected) {
        if ([Array]::IndexOf([string[]]$names, $name) -lt 0 -or -not (Test-NetworkSourceLiteral $Report.checks.$name 'passed')) {
            throw 'Network-source native check did not pass'
        }
    }
    $progress = @($Report.progress.PSObject.Properties.Name)
    if ($progress.Count -ne 1 -or [Array]::IndexOf([string[]]$progress, $expected[0]) -lt 0 -or
        -not (Test-NetworkSourceLiteral $Report.progress.($expected[0]) 'completed')) {
        throw 'Network-source native check did not pass'
    }
}

# This validator authorizes diagnostic projection only, never native success.
function Assert-NetworkSourcePartialReport($Report, [string]$ManifestSha256) {
    $fields = @('schema','suite','native_windows_executed','production_readiness','proof_scope',
        'manifest_sha256','user_sid','session_id','windows_version','checks','progress','error')
    $names = @($Report.PSObject.Properties.Name)
    if ($names.Count -ne $fields.Count -or @($fields | Where-Object { [Array]::IndexOf([string[]]$names, $_) -lt 0 }).Count -ne 0 -or
        ($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or $Report.schema -ne 1 -or
        -not (Test-NetworkSourceLiteral $Report.suite 'NetworkSource') -or
        -not (Test-NetworkSourceLiteral $Report.proof_scope 'source_only') -or
        $Report.native_windows_executed -isnot [bool] -or -not $Report.native_windows_executed -or
        $Report.production_readiness -isnot [bool] -or $Report.production_readiness -or
        -not (Test-NetworkSourceLiteral $Report.manifest_sha256 $ManifestSha256) -or
        -not (Test-NetworkSourceLiteral $Report.user_sid 'S-1-5-18') -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or $Report.session_id -ne 0 -or
        $Report.windows_version -isnot [string] -or -not $Report.windows_version -or
        ($null -ne $Report.error -and -not (Test-NetworkSourceLiteral $Report.error 'native_worker_failed'))) {
        throw 'Invalid network-source diagnostic identity'
    }
    $expected = @(Get-NetworkSourceTests)
    $checks = @($Report.checks.PSObject.Properties.Name)
    $progress = @($Report.progress.PSObject.Properties.Name)
    if ($checks.Count -ne 1 -or $progress.Count -ne 1) { throw 'Invalid network-source diagnostic check set' }
    $closed = $false
    foreach ($name in $expected) {
        $state = $Report.progress.$name
        if ([Array]::IndexOf([string[]]$checks, $name) -lt 0 -or [Array]::IndexOf([string[]]$progress, $name) -lt 0 -or
            $state -isnot [string] -or $state -cnotmatch '\A(not_attempted|attempted|completed|failed)\z' -or
            $Report.checks.$name -isnot [string] -or
            ($state -ceq 'completed' -and -not (Test-NetworkSourceLiteral $Report.checks.$name 'passed')) -or
            ($state -cne 'completed' -and -not (Test-NetworkSourceLiteral $Report.checks.$name 'not_verified')) -or
            ($state -ceq 'failed' -and $Report.error -cne 'native_worker_failed') -or
            ($closed -and $state -cne 'not_attempted')) { throw 'Invalid network-source diagnostic progress' }
        if ($state -cne 'completed') { $closed = $true }
    }
}

function Save-NetworkSourceCheckpoint([string]$ProofDirectory, $Report) {
    $pending = Join-Path $ProofDirectory 'network-source-worker.pending.private.json'
    $destination = Join-Path $ProofDirectory 'network-source-worker.private.json'
    try {
        $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $pending -Encoding UTF8 -ErrorAction Stop
        # Same protected directory: readers see either the preceding or new complete checkpoint.
        if (Test-Path -LiteralPath $destination) { [IO.File]::Replace($pending, $destination, [System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($pending, $destination) }
    } catch { throw 'Network-source private checkpoint failed' }
}

function Get-NetworkSourceStageNames {
    @('guard_verified','session_ready','coexistence_verified','tcp4_verified','tcp6_verified',
      'udp4_verified','udp6_verified','tdh_verified','source_loss_verified','token_verified','cleanup_verified','passed')
}

function Get-NetworkSourceFailureNames {
    @('guard','token','session_ownership','session_start','consumer_start','callback_bounds','callback_overflow',
      'traffic','timeout','tdh_schema','tdh_property','controlled_match','source_loss','session_cleanup','consumer_shutdown')
}

function Get-NetworkSourceSchemaKinds {
    @('tcp4_connect','tcp4_accept','tcp4_send','tcp4_receive','tcp4_disconnect',
      'tcp6_connect','tcp6_accept','tcp6_send','tcp6_receive','tcp6_disconnect',
      'udp4_send','udp4_receive','udp6_send','udp6_receive')
}

function Get-NetworkSourceApiOperations {
    @('start_trace','open_trace','process_trace','query_trace','stop_trace','close_trace',
      'tdh_information','tdh_property_size','tdh_property')
}

function Get-NetworkSourceOwnershipNames {
    @('process_intent','process_identity','process_configuration','process_controller',
      'network_identity','network_configuration','network_controller')
}

function Get-NetworkSourceLogMarkers([string]$Log, [switch]$RequireLog) {
    $stages = @(Get-NetworkSourceStageNames)
    $failures = @(Get-NetworkSourceFailureNames)
    $operations = @(Get-NetworkSourceApiOperations)
    $kinds = @(Get-NetworkSourceSchemaKinds)
    $ownership = @(Get-NetworkSourceOwnershipNames)
    $result = @{ stages=@(); failures=@(); api_errors=@(); schemas=@(); ownership=@(); configuration=@() }
    $schemaSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    try {
        if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) {
            if ($RequireLog) { throw 'Missing network-source diagnostic log' }
            return $result
        }
        if ((Get-Item -LiteralPath $Log -ErrorAction Stop).Length -gt 16MB) { throw 'Oversized network-source diagnostic log' }
        foreach ($line in Get-Content -LiteralPath $Log -Encoding UTF8 -ErrorAction Stop) {
            foreach ($tag in $stages) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_NETWORK_SOURCE_STAGE=' + $tag)) -and $result.stages -cnotcontains $tag) {
                    $result.stages += $tag
                }
            }
            foreach ($tag in $failures) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_NETWORK_SOURCE_FAILURE=' + $tag)) -and $result.failures -cnotcontains $tag) {
                    $result.failures += $tag
                }
            }
            foreach ($tag in $ownership) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_NETWORK_SOURCE_OWNERSHIP=' + $tag)) -and
                    [Array]::IndexOf([string[]]$result.ownership, $tag) -lt 0) {
                    $result.ownership += $tag
                }
            }
            if ($result.configuration.Count -lt 16 -and $line -cmatch '\AATHERNEX_NETWORK_SOURCE_CONFIGURATION=(process|network):(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9}):(0|1):(0|1)\z') {
                $mode = [uint32]0
                $flags = [uint32]0
                $context = [uint32]0
                if ([uint32]::TryParse($Matches[2], [Globalization.NumberStyles]::None,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$mode) -and
                    [uint32]::TryParse($Matches[3], [Globalization.NumberStyles]::None,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$flags) -and
                    [uint32]::TryParse($Matches[4], [Globalization.NumberStyles]::None,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$context)) {
                    $result.configuration += @{ scope=$Matches[1]; log_file_mode=$mode; enable_flags=$flags;
                        client_context=$context; logfile_present=[int]$Matches[5]; logfile_offset_valid=[int]$Matches[6] }
                }
            }
            if ($result.api_errors.Count -lt 32 -and $line -cmatch '\AATHERNEX_NETWORK_SOURCE_DIAGNOSTIC=([a-z_]+):(0|[1-9][0-9]{0,9})\z') {
                $operation = $Matches[1]
                $code = [uint32]0
                if ([Array]::IndexOf([string[]]$operations, $operation) -ge 0 -and
                    [uint32]::TryParse($Matches[2], [Globalization.NumberStyles]::None,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$code)) {
                    $result.api_errors += @{ operation=$operation; win32_error=$code }
                }
            }
            if ($result.schemas.Count -lt 32 -and $line -cmatch '\AATHERNEX_NETWORK_SOURCE_SCHEMA=([a-z0-9_]+):(0|[1-9][0-9]{0,2}):(32|64):([1-9][0-9]?):([0-9a-f]{64})\z') {
                $kind = $Matches[1]
                $version = [byte]0
                $properties = [int]$Matches[4]
                if ([Array]::IndexOf([string[]]$kinds, $kind) -ge 0 -and $properties -le 64 -and
                    [byte]::TryParse($Matches[2], [Globalization.NumberStyles]::None,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$version) -and $schemaSeen.Add($line)) {
                    $result.schemas += @{ kind=$kind; version=$version; pointer_bits=[int]$Matches[3];
                        property_count=$properties; sha256=$Matches[5] }
                }
            }
        }
    } catch { throw 'Network-source diagnostic log unavailable' }
    $result
}

function Assert-NetworkSourceMarkers($Markers) {
    if ($null -eq $Markers.failures -or $null -eq $Markers.api_errors -or
        @($Markers.failures).Count -ne 0 -or @($Markers.api_errors).Count -ne 0 -or
        $Markers.ownership -isnot [array] -or $Markers.configuration -isnot [array] -or
        $Markers.ownership.Count -ne 0 -or $Markers.configuration.Count -ne 0) {
        throw 'Network-source proof has contradictory failure evidence'
    }
    $expected = @(Get-NetworkSourceStageNames)
    if (@($Markers.stages).Count -ne $expected.Count) { throw 'Network-source proof is incomplete' }
    foreach ($stage in $expected) {
        if ([Array]::IndexOf([string[]]@($Markers.stages), $stage) -lt 0) { throw 'Network-source proof is incomplete' }
    }
    foreach ($kind in Get-NetworkSourceSchemaKinds) {
        if (@($Markers.schemas | Where-Object { Test-NetworkSourceLiteral $_.kind $kind }).Count -eq 0) {
            throw 'Network-source schema proof is incomplete'
        }
    }
}

function Get-NetworkSourceRunnerFailure([string]$Message) {
    $known = @{
        'Network-source input manifest changed'='input_manifest_changed'
        'Invalid network-source input manifest'='input_manifest_invalid'
        'Staged network-source input changed'='input_file_changed'
        'Staged network-source input invalid'='input_file_invalid'
        'Invalid network-source worker identity or result'='report_identity_invalid'
        'Incomplete network-source check set'='report_check_set_invalid'
        'Network-source native check did not pass'='report_check_failed'
        'Native service task deadline elapsed without a completed, valid report'='task_timeout'
        'Fixture task already exists'='task_ownership_failed'
        'Fixture task ownership changed; retained for inspection'='task_ownership_failed'
        'Fixture task did not stop; retained for inspection'='task_stop_failed'
        'Network-source proof has contradictory failure evidence'='source_proof_failed'
        'Network-source proof is incomplete'='source_proof_incomplete'
        'Network-source schema proof is incomplete'='source_schema_incomplete'
        'Network-source diagnostic log unavailable'='source_log_unavailable'
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

function Get-NetworkSourceDiagnostics([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource) {
    $result = @{ status='unbound'; checks=[ordered]@{} }
    try { $null = Assert-NetworkSourceInputs $ProofDirectory $ManifestSha256 $ExpectedSource } catch { return $result }
    $path = Join-Path $ProofDirectory 'network-source-worker.private.json'
    try {
        $result.status = 'unavailable'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $result.status = 'missing'; return $result }
        $result.status = 'invalid'
        if ((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 64KB) { return $result }
        $report = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        Assert-NetworkSourcePartialReport $report $ManifestSha256
        $result.status = 'unavailable'
        $projected = [ordered]@{}
        $position = 0
        foreach ($name in Get-NetworkSourceTests) {
            $markers = @{ stages=@(); failures=@(); api_errors=@(); schemas=@(); ownership=@(); configuration=@() }
            if ($report.progress.$name -cne 'not_attempted') {
                $markers = Get-NetworkSourceLogMarkers (Join-Path $ProofDirectory ('check-' + $position + '.log'))
            }
            $projected[$name] = @{ progress=$report.progress.$name; stages=$markers.stages; failures=$markers.failures;
                api_errors=$markers.api_errors; schemas=$markers.schemas; ownership=$markers.ownership; configuration=$markers.configuration }
            $position += 1
        }
        # Recheck after reading diagnostic files as well as before projecting them.
        $result.status = 'unbound'
        $null = Assert-NetworkSourceInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $result.checks = $projected
        $result.status = 'available'
    } catch { }
    $result
}

function Invoke-NetworkSourceWorkerChecks([string]$ProofDirectory, $Report) {
    $environment = @('ATHERNEX_WINDOWS_NETWORK_EVENTS_PROBE_DISPOSABLE_HOST',
        'ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST','ATHERNEX_NATIVE_WORKSPACE_AGENT',
        'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST','ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST',
        'ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT')
    $previous = @{}
    foreach ($name in $environment) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $active = $null
    try {
        $null = Assert-NetworkSourceInputs $ProofDirectory $Report.manifest_sha256
        [Environment]::SetEnvironmentVariable($environment[0], '1', 'Process')
        foreach ($name in $environment[1..6]) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
        $position = 0
        foreach ($name in Get-NetworkSourceTests) {
            $null = Assert-NetworkSourceInputs $ProofDirectory $Report.manifest_sha256
            $log = Join-Path $ProofDirectory ('check-' + $position + '.log')
            $active = $name
            $Report.progress[$name] = 'attempted'
            Save-NetworkSourceCheckpoint $ProofDirectory $Report
            Invoke-IsolationCheck (Join-Path $ProofDirectory 'endpoint-tests.exe') $name $log
            $markers = Get-NetworkSourceLogMarkers $log -RequireLog
            Assert-NetworkSourceMarkers $markers
            $null = Assert-NetworkSourceInputs $ProofDirectory $Report.manifest_sha256
            $Report.checks[$name] = 'passed'
            $Report.progress[$name] = 'completed'
            Save-NetworkSourceCheckpoint $ProofDirectory $Report
            $active = $null
            $position += 1
        }
    } catch {
        $Report.error = 'native_worker_failed'
        if ($active) { $Report.checks[$active] = 'not_verified'; $Report.progress[$active] = 'failed' }
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'worker.log') -Append -ErrorAction Stop } catch { }
        try { Save-NetworkSourceCheckpoint $ProofDirectory $Report } catch { }
        throw 'Native network-source worker failed; private evidence retained on worker'
    } finally {
        foreach ($name in $environment) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    }
}

function Invoke-NetworkSourceWorker([string]$ProofDirectory, [bool]$AllowDisposable) {
    $ErrorActionPreference = 'Stop'
    if (-not $AllowDisposable -or [Environment]::OSVersion.Platform -ne 'Win32NT' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'Network-source worker requires disposable native LocalSystem in session zero'
    }
    $digest = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory 'inputs.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = Assert-NetworkSourceInputs $ProofDirectory $digest
    $report = @{ schema=1; suite='NetworkSource'; native_windows_executed=$true; production_readiness=$false;
        proof_scope='source_only'; manifest_sha256=$digest; user_sid='S-1-5-18'; session_id=0;
        windows_version=[Environment]::OSVersion.Version.ToString(); checks=[ordered]@{}; progress=[ordered]@{}; error=$null }
    foreach ($name in Get-NetworkSourceTests) { $report.checks[$name] = 'not_verified'; $report.progress[$name] = 'not_attempted' }
    Save-NetworkSourceCheckpoint $ProofDirectory $report
    # Import parameters cannot overwrite these deliberately distinct local names.
    . (Join-Path $ProofDirectory 'verify_windows_isolation_ci.ps1')
    Invoke-NetworkSourceWorkerChecks $ProofDirectory $report
}

function Invoke-NetworkSourceEvidence([string]$ProofDirectory, [string]$ProofTask, $ProofAction,
                                         [string]$ManifestSha256, [string]$ExpectedSource) {
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $ExpectedSource -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Invalid network-source evidence binding'
    }
    $result = Join-Path $ProofDirectory 'network-source-worker.private.json'
    $public = @{ schema=1; suite='NetworkSource'; proof_scope='source_only'; production_readiness=$false;
        manifest_sha256=$ManifestSha256; native_network_source_validation_passed=$false;
        stages=@(); checks=[ordered]@{}; error='native_network_source_not_verified'; runner_failure=$null;
        diagnostics=@{ status='unavailable'; checks=[ordered]@{} } }
    foreach ($name in Get-NetworkSourceTests) { $public.checks[$name] = 'not_verified' }
    try {
        $null = Assert-NetworkSourceInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $public.stages += 'inputs_verified'
        Invoke-ServiceFixtureTask $ProofTask $ProofAction $result $ManifestSha256 840 {
            param($Report, $Digest)
            Assert-NetworkSourceReport $Report $Digest
        }
        $public.stages += 'task_completed_and_removed'
        $null = Assert-NetworkSourceInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-NetworkSourceReport $report $ManifestSha256
        $markers = Get-NetworkSourceLogMarkers (Join-Path $ProofDirectory 'check-0.log') -RequireLog
        Assert-NetworkSourceMarkers $markers
        $null = Assert-NetworkSourceInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-NetworkSourceReport $report $ManifestSha256
        # Publish the exact marker snapshot that passed the source proof; never
        # replace it with a later diagnostic read after authorizing success.
        $public.diagnostics = @{ status='available'; checks=[ordered]@{} }
        $public.diagnostics.checks[@(Get-NetworkSourceTests)[0]] = @{ progress='completed';
            stages=$markers.stages; failures=$markers.failures; api_errors=$markers.api_errors; schemas=$markers.schemas;
            ownership=$markers.ownership; configuration=$markers.configuration }
        $public.stages += 'report_verified'
        foreach ($name in Get-NetworkSourceTests) { $public.checks[$name] = 'passed' }
        $public.native_network_source_validation_passed = $true
        $public.error = $null
    } catch {
        $public.runner_failure = Get-NetworkSourceRunnerFailure $_.Exception.Message
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'network-source-validation.private.log') -Append -ErrorAction Stop } catch { }
        $public.diagnostics = Get-NetworkSourceDiagnostics $ProofDirectory $ManifestSha256 $ExpectedSource
    }
    $public | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ProofDirectory 'network-source-validation.json') -Encoding UTF8
    if (-not $public.native_network_source_validation_passed) { throw 'Native network-source validation failed; private evidence retained on worker' }
}

function Invoke-NetworkSourceCi([string]$TestsPath, [string]$ProofDirectory, [bool]$AllowDisposable) {
    $ErrorActionPreference = 'Stop'
    if (-not $AllowDisposable -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
        [Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Requires an explicitly disposable GitHub-hosted Windows runner' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Requires an elevated runner'
    }
    if (-not $TestsPath -or -not $ProofDirectory -or $env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Requires exact tests, destination and source revision'
    }
    $sources = @{ 'endpoint-tests.exe'=(Resolve-Path -LiteralPath $TestsPath).Path;
        'verify_windows_network_source_ci.ps1'=$PSCommandPath;
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
    $manifest = @{ schema=1; suite='NetworkSource'; github_sha=$sourceRevision; sha256=@{} }
    foreach ($name in Get-NetworkSourceInputNames) {
        $digest = (Get-FileHash -LiteralPath $sources[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $sources[$name] -Destination (Join-Path $ProofDirectory $name)
        if ((Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
            throw 'Staged network-source input differs from source'
        }
        $manifest.sha256[$name] = $digest
    }
    $manifestPath = Join-Path $ProofDirectory 'inputs.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixture = Join-Path $ProofDirectory 'verify_windows_network_source_ci.ps1'
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
    $taskName = 'AthernexNetworkSourceValidation-' + [Guid]::NewGuid().ToString('N')
    $null = Assert-NetworkSourceInputs $ProofDirectory $digest $sourceRevision
    . (Join-Path $ProofDirectory 'verify_windows_service_ci.ps1')
    Invoke-NetworkSourceEvidence $ProofDirectory $taskName $action $digest $sourceRevision
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Worker) { Invoke-NetworkSourceWorker $OutputDirectory $DisposableHost.IsPresent }
    else {
        try { Invoke-NetworkSourceCi $EndpointTests $OutputDirectory $DisposableHost.IsPresent }
        catch {
            try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'runner.log') -Append -ErrorAction Stop } catch { }
            throw 'Native network-source validation failed; private evidence retained on worker when available'
        }
    }
}
