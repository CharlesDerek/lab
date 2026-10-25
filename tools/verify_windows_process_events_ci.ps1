<#
Validate Windows process-event collection with the release agent and a fixed
native fixture on a disposable LocalSystem worker. Raw event bytes, paths,
commands, errors and worker reports stay in the protected VM directory.
Dot-sourcing defines helpers only.
#>
param([string]$AgentExecutable, [string]$EndpointTests, [string]$OutputDirectory,
      [switch]$DisposableHost, [switch]$Worker)

function Get-ProcessEventsTest {
    'telemetry::windows_process_events::native_test::process_lifecycles_replay_with_visible_capture_gaps'
}

function Get-ProcessEventsStageNames {
    @('guard_verified','agent_config_verified','source_ready','lifecycle_verified','rundown_verified',
      'tdh_differential_verified','stalled_http_verified','queue_loss_verified','crash_replay_verified',
      'orphan_recovered','session_gap_verified','http_delivery_verified','server_replay_verified',
      'export_authorization_verified','original_export_verified','portal_coverage_verified',
      'server_restart_verified','cleanup_verified','passed')
}

function Get-ProcessEventsFailureNames {
    @('configuration','ownership','source_start','source_stopped','native_loss','callback_loss',
      'normalization','durable_admission','controlled_lifecycle','rundown','tdh_mismatch','transport',
      'replay','authorization','original_export','portal','cleanup','timeout','other',
      'tdh_schema_provenance','tdh_schema_identity','tdh_schema_bounds','tdh_schema_shape',
      'tdh_property_missing','tdh_property_type','tdh_property_scalar','tdh_property_size',
      'tdh_record_provenance','tdh_api','tdh_other','tdh_scalar_mismatch','tdh_expected_shape')
}

function Get-ProcessEventsMarkers([string]$Log, [string]$Prefix, [string[]]$Allowed) {
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    # Only constants leave this function. Ordinal whole-line equality excludes
    # suffixes, control characters and culturally equivalent Unicode text.
    foreach ($value in $Allowed) {
        foreach ($line in $lines) {
            if ([string]::Equals($line, ($Prefix + $value), [StringComparison]::Ordinal)) {
                $value
                break
            }
        }
    }
}

function Get-ProcessEventsStages([string]$Log) {
    Get-ProcessEventsMarkers $Log 'ATHERNEX_PROCESS_EVENTS_STAGE=' @(Get-ProcessEventsStageNames)
}

function Get-ProcessEventsFailures([string]$Log) {
    Get-ProcessEventsMarkers $Log 'ATHERNEX_PROCESS_EVENTS_FAILURE=' @(Get-ProcessEventsFailureNames)
}

function Get-ProcessEventsProperties([string]$Log) {
    Get-ProcessEventsMarkers $Log 'ATHERNEX_PROCESS_EVENTS_TDH_PROPERTY=' @(
        'process_id','parent_id','session_id','exit_status','unique_process_key')
}

function Get-ProcessEventsDiagnostics([string]$Log) {
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    $count = 0
    foreach ($line in $lines) {
        foreach ($operation in @('start_trace','open_trace','process_trace','query_trace','stop_trace',
                                  'close_trace','token_query','tdh_information','tdh_size','tdh_property')) {
            $pattern = '\A' + [regex]::Escape('ATHERNEX_PROCESS_EVENTS_DIAGNOSTIC=' + $operation + ':') + '(0|[1-9][0-9]{0,9})\z'
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

function Get-ProcessEventsSchema([string]$Log) {
    if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) { return }
    try { $lines = @(Get-Content -LiteralPath $Log -ErrorAction Stop) }
    catch { return }
    $count = 0
    foreach ($line in $lines) {
        $match = [regex]::Match($line,
            '\AATHERNEX_PROCESS_EVENTS_SCHEMA=(0|[1-9][0-9]{0,2}):(0|[1-9][0-9]{0,2}):(32|64):([1-9][0-9]?)\z',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        [byte]$opcode = 0
        [byte]$version = 0
        [byte]$properties = 0
        if ($match.Success -and [byte]::TryParse($match.Groups[1].Value,
            [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$opcode) -and
            [byte]::TryParse($match.Groups[2].Value,
            [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$version) -and
            [byte]::TryParse($match.Groups[4].Value,
            [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$properties) -and
            $properties -ge 1 -and $properties -le 64) {
            @{ opcode=$opcode; version=$version; pointer_bits=[int]$match.Groups[3].Value;
                property_count=$properties }
            $count += 1
            if ($count -ge 16) { return }
        }
    }
}

function Assert-ProcessEventsMarkers($Report) {
    if ($null -eq $Report.process_events_failures -or @($Report.process_events_failures).Count -ne 0) {
        throw 'Process-event proof has missing or contradictory failure evidence'
    }
    $expected = @(Get-ProcessEventsStageNames)
    if (@($Report.process_events_stages).Count -ne $expected.Count) { throw 'Process-event proof is incomplete' }
    foreach ($stage in $expected) {
        if (@($Report.process_events_stages) -cnotcontains $stage) { throw 'Process-event proof is incomplete' }
    }
}

function Assert-ProcessEventsReport($Report, [string]$ManifestSha256) {
    if ($Report.schema -ne 1 -or $Report.suite -cne 'ProcessEvents' -or
        $Report.native_windows_executed -cne $true -or $Report.production_readiness -cne $false -or
        $Report.proof_scope -cne 'component_and_agent' -or $Report.manifest_sha256 -cne $ManifestSha256 -or
        $Report.user_sid -cne 'S-1-5-18' -or $Report.session_id -cne 0 -or
        -not $Report.windows_version -or $Report.error) { throw 'Invalid process-event worker identity or result' }
    $name = Get-ProcessEventsTest
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne 1 -or $names[0] -cne $name -or $Report.checks.$name -cne 'passed') {
        throw 'Process-event native check did not pass'
    }
    Assert-ProcessEventsMarkers $Report
}

function Get-ProcessEventsInputNames {
    @('agent.exe','endpoint.exe','verify_windows_process_events_ci.ps1',
      'verify_windows_isolation_ci.ps1','verify_windows_service_ci.ps1')
}

function Assert-ProcessEventsInputs([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource = '') {
    $path = Join-Path $ProofDirectory 'inputs.json'
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) {
        throw 'Process-event input manifest changed'
    }
    $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $expected = @(Get-ProcessEventsInputNames)
    if ($manifest.schema -ne 1 -or $manifest.suite -cne 'ProcessEvents' -or
        $manifest.github_sha -cnotmatch '\A[0-9a-f]{40}\z' -or
        ($ExpectedSource -and $manifest.github_sha -cne $ExpectedSource) -or
        @($manifest.sha256.PSObject.Properties.Name).Count -ne $expected.Count) {
        throw 'Invalid process-event input manifest'
    }
    foreach ($name in $expected) {
        if (@($manifest.sha256.PSObject.Properties.Name) -cnotcontains $name -or
            $manifest.sha256.$name -cnotmatch '\A[0-9a-f]{64}\z' -or
            (Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.sha256.$name) {
            throw 'Staged process-event input changed'
        }
    }
    $manifest
}

function Invoke-ProcessEventsWorkerChecks([string]$ProofDirectory, $Report) {
    $environment = @('ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT',
        'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST','ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST')
    $previous = @{}
    foreach ($name in $environment) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $log = Join-Path $ProofDirectory 'check-0.log'
    try {
        $null = Assert-ProcessEventsInputs $ProofDirectory $Report.manifest_sha256
        [Environment]::SetEnvironmentVariable($environment[0], '1', 'Process')
        [Environment]::SetEnvironmentVariable($environment[1], (Join-Path $ProofDirectory 'agent.exe'), 'Process')
        [Environment]::SetEnvironmentVariable($environment[2], $null, 'Process')
        [Environment]::SetEnvironmentVariable($environment[3], $null, 'Process')
        Invoke-IsolationCheck (Join-Path $ProofDirectory 'endpoint.exe') (Get-ProcessEventsTest) $log
        $null = Assert-ProcessEventsInputs $ProofDirectory $Report.manifest_sha256
        $Report.process_events_stages = @(Get-ProcessEventsStages $log)
        $Report.process_events_failures = @(Get-ProcessEventsFailures $log)
        Assert-ProcessEventsMarkers $Report
        $Report.checks[(Get-ProcessEventsTest)] = 'passed'
    } catch {
        $Report.error = 'native_worker_failed'
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'worker.log') -Append -ErrorAction Stop } catch { }
        throw 'Native process-event worker failed; private evidence retained on worker'
    } finally {
        try {
            $Report.process_events_stages = @(Get-ProcessEventsStages $log)
            $Report.process_events_failures = @(Get-ProcessEventsFailures $log)
            $Report.process_events_diagnostics = @(Get-ProcessEventsDiagnostics $log)
            $Report.process_events_schema = @(Get-ProcessEventsSchema $log)
            $Report.process_events_properties = @(Get-ProcessEventsProperties $log)
        } catch {
            $Report.error = 'native_worker_failed'
            throw 'Native process-event diagnostics could not be verified'
        } finally {
            foreach ($name in $environment) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
        }
    }
}

function Invoke-ProcessEventsWorker([string]$ProofDirectory, [bool]$AllowDisposable) {
    $ErrorActionPreference = 'Stop'
    if (-not $AllowDisposable -or [Environment]::OSVersion.Platform -ne 'Win32NT' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'Process-event worker requires disposable native LocalSystem in session zero'
    }
    $digest = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory 'inputs.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = Assert-ProcessEventsInputs $ProofDirectory $digest
    # These imports have parameters of their own. ProofDirectory/AllowDisposable
    # are deliberately distinct and cannot be overwritten by dot-sourcing.
    . (Join-Path $ProofDirectory 'verify_windows_isolation_ci.ps1')
    $report = @{ schema=1; suite='ProcessEvents'; native_windows_executed=$true; production_readiness=$false;
        proof_scope='component_and_agent'; manifest_sha256=$digest; user_sid='S-1-5-18'; session_id=0;
        windows_version=[Environment]::OSVersion.Version.ToString(); checks=[ordered]@{}; error=$null;
        process_events_stages=@(); process_events_failures=@(); process_events_diagnostics=@(); process_events_schema=@();
        process_events_properties=@() }
    $report.checks[(Get-ProcessEventsTest)] = 'not_verified'
    try { Invoke-ProcessEventsWorkerChecks $ProofDirectory $report }
    finally {
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ProofDirectory 'process-events-worker.private.json') -Encoding UTF8
    }
}

function Invoke-ProcessEventsEvidence([string]$ProofDirectory, [string]$ProofTask, $ProofAction,
                                     [string]$ManifestSha256, [string]$ExpectedSource) {
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $ExpectedSource -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Invalid process-event evidence binding'
    }
    $result = Join-Path $ProofDirectory 'process-events-worker.private.json'
    $log = Join-Path $ProofDirectory 'check-0.log'
    $public = @{ schema=1; suite='ProcessEvents'; proof_scope='component_and_agent'; production_readiness=$false;
        manifest_sha256=$ManifestSha256; native_process_events_validation_passed=$false;
        stages=@(); process_events_stages=@(); process_events_failures=@(); process_events_diagnostics=@();
        process_events_schema=@(); process_events_properties=@();
        checks=[ordered]@{}; error='native_process_events_not_verified' }
    $public.checks[(Get-ProcessEventsTest)] = 'not_verified'
    try {
        $null = Assert-ProcessEventsInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $public.stages += 'inputs_verified'
        Invoke-ServiceFixtureTask $ProofTask $ProofAction $result $ManifestSha256 840 {
            param($Report, $Digest)
            Assert-ProcessEventsReport $Report $Digest
        }
        $public.stages += 'task_completed_and_removed'
        $null = Assert-ProcessEventsInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-ProcessEventsReport $report $ManifestSha256
        $public.process_events_stages = @(Get-ProcessEventsStages $log)
        $public.process_events_failures = @(Get-ProcessEventsFailures $log)
        Assert-ProcessEventsMarkers $public
        $public.stages += 'report_verified'
        $public.checks[(Get-ProcessEventsTest)] = 'passed'
        $public.native_process_events_validation_passed = $true
        $public.error = $null
    } catch {
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'process-events-validation.private.log') -Append -ErrorAction Stop } catch { }
    }
    $public.process_events_stages = @(Get-ProcessEventsStages $log)
    $public.process_events_failures = @(Get-ProcessEventsFailures $log)
    $public.process_events_diagnostics = @(Get-ProcessEventsDiagnostics $log)
    $public.process_events_schema = @(Get-ProcessEventsSchema $log)
    $public.process_events_properties = @(Get-ProcessEventsProperties $log)
    if ($public.native_process_events_validation_passed) {
        try { Assert-ProcessEventsMarkers $public }
        catch {
            $public.native_process_events_validation_passed = $false
            $public.error = 'native_process_events_not_verified'
            $public.checks[(Get-ProcessEventsTest)] = 'not_verified'
        }
    }
    $public | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ProofDirectory 'process-events-validation.json') -Encoding UTF8
    if (-not $public.native_process_events_validation_passed) { throw 'Native process-event validation failed; private evidence retained on worker' }
}

function Invoke-ProcessEventsCi([string]$AgentPath, [string]$TestsPath, [string]$ProofDirectory, [bool]$AllowDisposable) {
    $ErrorActionPreference = 'Stop'
    if (-not $AllowDisposable -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
        [Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Requires an explicitly disposable GitHub-hosted Windows runner' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Requires an elevated runner'
    }
    if (-not $AgentPath -or -not $TestsPath -or -not $ProofDirectory -or $env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Requires exact agent, tests, destination and source revision'
    }
    $sources = @{ 'agent.exe'=(Resolve-Path -LiteralPath $AgentPath).Path;
        'endpoint.exe'=(Resolve-Path -LiteralPath $TestsPath).Path;
        'verify_windows_process_events_ci.ps1'=$PSCommandPath;
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
    $manifest = @{ schema=1; suite='ProcessEvents'; github_sha=$sourceRevision; sha256=@{} }
    foreach ($name in Get-ProcessEventsInputNames) {
        $digest = (Get-FileHash -LiteralPath $sources[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $sources[$name] -Destination (Join-Path $ProofDirectory $name)
        if ((Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
            throw 'Staged process-event input differs from source'
        }
        $manifest.sha256[$name] = $digest
    }
    $manifestPath = Join-Path $ProofDirectory 'inputs.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixture = Join-Path $ProofDirectory 'verify_windows_process_events_ci.ps1'
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
    $taskName = 'AthernexProcessEventsValidation-' + [Guid]::NewGuid().ToString('N')
    $null = Assert-ProcessEventsInputs $ProofDirectory $digest $sourceRevision
    . (Join-Path $ProofDirectory 'verify_windows_service_ci.ps1')
    Invoke-ProcessEventsEvidence $ProofDirectory $taskName $action $digest $sourceRevision
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Worker) { Invoke-ProcessEventsWorker $OutputDirectory $DisposableHost.IsPresent }
    else {
        try { Invoke-ProcessEventsCi $AgentExecutable $EndpointTests $OutputDirectory $DisposableHost.IsPresent }
        catch {
            try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'runner.log') -Append -ErrorAction Stop } catch { }
            throw 'Native process-event validation failed; private evidence retained on worker when available'
        }
    }
}
