<#
Prove the actual release-agent Security authentication loop on a disposable
LocalSystem worker. Raw XML, accounts, errors and worker reports remain private.
This is an acceptance fixture, not SCM or production-readiness proof.
Dot-sourcing defines helpers only.
#>
param([string]$AgentExecutable, [string]$EndpointTests, [string]$OutputDirectory,
      [switch]$DisposableHost, [switch]$Worker)

function Get-AuthenticationAgentTests {
    @('telemetry::windows_authentication::native_test::agent_test::release_agent_logon_delivery_replays_and_reports_policy_gaps')
}

function Get-AuthenticationAgentInputNames {
    @('agent.exe','endpoint-tests.exe','verify_windows_authentication_agent_ci.ps1',
      'verify_windows_isolation_ci.ps1','verify_windows_service_ci.ps1')
}

function Test-AuthenticationAgentLiteral($Value, [string]$Expected) {
    $Value -is [string] -and [StringComparer]::Ordinal.Equals($Value, $Expected)
}

function Assert-AuthenticationAgentInputs([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource = '') {
    $path = Join-Path $ProofDirectory 'inputs.json'
    try { $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { throw 'Invalid authentication-agent input manifest' }
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $actual -cne $ManifestSha256) {
        throw 'Authentication-agent input manifest changed'
    }
    try { $manifest = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Invalid authentication-agent input manifest' }
    $expected = @(Get-AuthenticationAgentInputNames)
    if (($manifest.schema -isnot [int] -and $manifest.schema -isnot [long]) -or
        $manifest.schema -ne 1 -or -not (Test-AuthenticationAgentLiteral $manifest.suite 'AuthenticationAgent') -or
        $manifest.github_sha -isnot [string] -or $manifest.github_sha -cnotmatch '\A[0-9a-f]{40}\z' -or
        ($ExpectedSource -and $manifest.github_sha -cne $ExpectedSource) -or
        @($manifest.sha256.PSObject.Properties.Name).Count -ne $expected.Count) {
        throw 'Invalid authentication-agent input manifest'
    }
    foreach ($name in $expected) {
        if ([Array]::IndexOf([string[]]@($manifest.sha256.PSObject.Properties.Name), $name) -lt 0 -or
            $manifest.sha256.$name -isnot [string] -or $manifest.sha256.$name -cnotmatch '\A[0-9a-f]{64}\z') {
            throw 'Staged authentication-agent input changed'
        }
        try { $actual = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
        catch { throw 'Staged authentication-agent input invalid' }
        if ($actual -cne $manifest.sha256.$name) { throw 'Staged authentication-agent input changed' }
    }
    $manifest
}

function Assert-AuthenticationAgentReport($Report, [string]$ManifestSha256) {
    if (($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or
        $Report.schema -ne 1 -or -not (Test-AuthenticationAgentLiteral $Report.suite 'AuthenticationAgent') -or
        $Report.native_windows_executed -isnot [bool] -or $Report.production_readiness -isnot [bool] -or
        $Report.native_windows_executed -cne $true -or $Report.production_readiness -cne $false -or
        -not (Test-AuthenticationAgentLiteral $Report.proof_scope 'actual_agent') -or
        -not (Test-AuthenticationAgentLiteral $Report.manifest_sha256 $ManifestSha256) -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or
        -not (Test-AuthenticationAgentLiteral $Report.user_sid 'S-1-5-18') -or $Report.session_id -cne 0 -or
        $Report.windows_version -isnot [string] -or -not $Report.windows_version -or
        $null -ne $Report.error) { throw 'Invalid authentication-agent worker identity or result' }
    $expected = @(Get-AuthenticationAgentTests)
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne $expected.Count) { throw 'Incomplete authentication-agent check set' }
    foreach ($name in $expected) {
        if ([Array]::IndexOf([string[]]$names, $name) -lt 0 -or -not (Test-AuthenticationAgentLiteral $Report.checks.$name 'passed')) {
            throw 'Authentication-agent native check did not pass'
        }
    }
    $progress = @($Report.progress.PSObject.Properties.Name)
    if ($progress.Count -ne 1 -or [Array]::IndexOf([string[]]$progress, $expected[0]) -lt 0 -or
        -not (Test-AuthenticationAgentLiteral $Report.progress.($expected[0]) 'completed')) {
        throw 'Authentication-agent native check did not pass'
    }
}

# This validator authorizes diagnostic projection only, never native success.
function Assert-AuthenticationAgentPartialReport($Report, [string]$ManifestSha256) {
    $fields = @('schema','suite','native_windows_executed','production_readiness','proof_scope',
        'manifest_sha256','user_sid','session_id','windows_version','checks','progress','error')
    $names = @($Report.PSObject.Properties.Name)
    if ($names.Count -ne $fields.Count -or @($fields | Where-Object { [Array]::IndexOf([string[]]$names, $_) -lt 0 }).Count -ne 0 -or
        ($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or $Report.schema -ne 1 -or
        -not (Test-AuthenticationAgentLiteral $Report.suite 'AuthenticationAgent') -or
        -not (Test-AuthenticationAgentLiteral $Report.proof_scope 'actual_agent') -or
        $Report.native_windows_executed -isnot [bool] -or -not $Report.native_windows_executed -or
        $Report.production_readiness -isnot [bool] -or $Report.production_readiness -or
        -not (Test-AuthenticationAgentLiteral $Report.manifest_sha256 $ManifestSha256) -or
        -not (Test-AuthenticationAgentLiteral $Report.user_sid 'S-1-5-18') -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or $Report.session_id -ne 0 -or
        $Report.windows_version -isnot [string] -or -not $Report.windows_version -or
        ($null -ne $Report.error -and -not (Test-AuthenticationAgentLiteral $Report.error 'native_worker_failed'))) {
        throw 'Invalid authentication-agent diagnostic identity'
    }
    $expected = @(Get-AuthenticationAgentTests)
    $checks = @($Report.checks.PSObject.Properties.Name)
    $progress = @($Report.progress.PSObject.Properties.Name)
    if ($checks.Count -ne 1 -or $progress.Count -ne 1) { throw 'Invalid authentication-agent diagnostic check set' }
    $closed = $false
    foreach ($name in $expected) {
        $state = $Report.progress.$name
        if ([Array]::IndexOf([string[]]$checks, $name) -lt 0 -or [Array]::IndexOf([string[]]$progress, $name) -lt 0 -or
            $state -isnot [string] -or $state -cnotmatch '\A(not_attempted|attempted|completed|failed)\z' -or
            $Report.checks.$name -isnot [string] -or
            ($state -ceq 'completed' -and -not (Test-AuthenticationAgentLiteral $Report.checks.$name 'passed')) -or
            ($state -cne 'completed' -and -not (Test-AuthenticationAgentLiteral $Report.checks.$name 'not_verified')) -or
            ($state -ceq 'failed' -and $Report.error -cne 'native_worker_failed') -or
            ($closed -and $state -cne 'not_attempted')) { throw 'Invalid authentication-agent diagnostic progress' }
        if ($state -cne 'completed') { $closed = $true }
    }
}

function Save-AuthenticationAgentCheckpoint([string]$ProofDirectory, $Report) {
    $pending = Join-Path $ProofDirectory 'authentication-agent-worker.pending.private.json'
    $destination = Join-Path $ProofDirectory 'authentication-agent-worker.private.json'
    try {
        $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $pending -Encoding UTF8 -ErrorAction Stop
        # Same protected directory: readers see either the preceding or new complete checkpoint.
        if (Test-Path -LiteralPath $destination) { [IO.File]::Replace($pending, $destination, [System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($pending, $destination) }
    } catch { throw 'Authentication-agent private checkpoint failed' }
}

function Get-AuthenticationAgentStageNames {
    @('guard_verified','policy_ready','account_ready','agent_config_verified','source_ready',
      'stalled_http_verified','originals_verified','queues_filled','backpressure_observed','backpressure_verified','crash_replay_verified',
      'policy_gap_verified','bookmark_anchor_verified','http_delivery_verified','server_replay_verified',
      'export_authorization_verified','original_export_verified','original_link_verified',
      'device_separation_verified','detection_verified','portal_coverage_verified','server_restart_verified',
      'cleanup_verified','passed')
}

function Get-AuthenticationAgentFailureNames {
    @('configuration','token','policy','account','source','transport','original','backpressure','replay',
      'policy_gap','authorization','device_separation','detection','portal','cleanup','timeout','other')
}

function Get-AuthenticationAgentLogMarkers([string]$Log, [switch]$RequireLog) {
    $stages = @(Get-AuthenticationAgentStageNames)
    $failures = @(Get-AuthenticationAgentFailureNames)
    $result = @{ stages=@(); failures=@() }
    try {
        if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) {
            if ($RequireLog) { throw 'Missing authentication-agent diagnostic log' }
            return $result
        }
        if ((Get-Item -LiteralPath $Log -ErrorAction Stop).Length -gt 16MB) { throw 'Oversized authentication-agent diagnostic log' }
        foreach ($line in Get-Content -LiteralPath $Log -Encoding UTF8 -ErrorAction Stop) {
            foreach ($tag in $stages) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_AUTH_AGENT_STAGE=' + $tag)) -and $result.stages -cnotcontains $tag) {
                    $result.stages += $tag
                }
            }
            foreach ($tag in $failures) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_AUTH_AGENT_FAILURE=' + $tag)) -and $result.failures -cnotcontains $tag) {
                    $result.failures += $tag
                }
            }
        }
    } catch { throw 'Authentication-agent diagnostic log unavailable' }
    $result
}

function Assert-AuthenticationAgentMarkers($Markers) {
    if ($Markers.failures -isnot [array] -or $Markers.failures.Count -ne 0) {
        throw 'Authentication-agent proof has contradictory failure evidence'
    }
    $expected = @(Get-AuthenticationAgentStageNames)
    if ($Markers.stages -isnot [array] -or $Markers.stages.Count -ne $expected.Count) {
        throw 'Authentication-agent proof is incomplete'
    }
    foreach ($stage in $expected) {
        if ([Array]::IndexOf([string[]]$Markers.stages, $stage) -lt 0) { throw 'Authentication-agent proof is incomplete' }
    }
}

function Get-AuthenticationAgentRunnerFailure([string]$Message) {
    $known = @{
        'Authentication-agent input manifest changed'='input_manifest_changed'
        'Invalid authentication-agent input manifest'='input_manifest_invalid'
        'Staged authentication-agent input changed'='input_file_changed'
        'Staged authentication-agent input invalid'='input_file_invalid'
        'Invalid authentication-agent worker identity or result'='report_identity_invalid'
        'Incomplete authentication-agent check set'='report_check_set_invalid'
        'Authentication-agent native check did not pass'='report_check_failed'
        'Native service task deadline elapsed without a completed, valid report'='task_timeout'
        'Fixture task already exists'='task_ownership_failed'
        'Fixture task ownership changed; retained for inspection'='task_ownership_failed'
        'Fixture task did not stop; retained for inspection'='task_stop_failed'
        'Authentication-agent proof has contradictory failure evidence'='source_proof_failed'
        'Authentication-agent proof is incomplete'='source_proof_incomplete'
        'Authentication-agent diagnostic log unavailable'='source_log_unavailable'
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

function Get-AuthenticationAgentDiagnostics([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource) {
    $result = @{ status='unbound'; checks=[ordered]@{} }
    try { $null = Assert-AuthenticationAgentInputs $ProofDirectory $ManifestSha256 $ExpectedSource } catch { return $result }
    $path = Join-Path $ProofDirectory 'authentication-agent-worker.private.json'
    try {
        $result.status = 'unavailable'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $result.status = 'missing'; return $result }
        $result.status = 'invalid'
        if ((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 64KB) { return $result }
        $report = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        Assert-AuthenticationAgentPartialReport $report $ManifestSha256
        $result.status = 'unavailable'
        $projected = [ordered]@{}
        $position = 0
        foreach ($name in Get-AuthenticationAgentTests) {
            $markers = @{ stages=@(); failures=@() }
            if ($report.progress.$name -cne 'not_attempted') {
                $markers = Get-AuthenticationAgentLogMarkers (Join-Path $ProofDirectory ('check-' + $position + '.log'))
            }
            $projected[$name] = @{ progress=$report.progress.$name; stages=$markers.stages; failures=$markers.failures }
            $position += 1
        }
        # Recheck after reading diagnostic files as well as before projecting them.
        $result.status = 'unbound'
        $null = Assert-AuthenticationAgentInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $result.checks = $projected
        $result.status = 'available'
    } catch { }
    $result
}

function Invoke-AuthenticationAgentWorkerChecks([string]$ProofDirectory, $Report) {
    $environment = @('ATHERNEX_WINDOWS_AUTHENTICATION_AGENT_DISPOSABLE_HOST','ATHERNEX_NATIVE_AUTHENTICATION_AGENT',
        'ATHERNEX_WINDOWS_NETWORK_EVENTS_PROBE_DISPOSABLE_HOST',
        'ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST','ATHERNEX_NATIVE_WORKSPACE_AGENT',
        'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST','ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST',
        'ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT')
    $previous = @{}
    foreach ($name in $environment) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $active = $null
    try {
        $null = Assert-AuthenticationAgentInputs $ProofDirectory $Report.manifest_sha256
        [Environment]::SetEnvironmentVariable($environment[0], '1', 'Process')
        [Environment]::SetEnvironmentVariable($environment[1], (Join-Path $ProofDirectory 'agent.exe'), 'Process')
        foreach ($name in $environment[2..8]) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
        $position = 0
        foreach ($name in Get-AuthenticationAgentTests) {
            $null = Assert-AuthenticationAgentInputs $ProofDirectory $Report.manifest_sha256
            $log = Join-Path $ProofDirectory ('check-' + $position + '.log')
            $active = $name
            $Report.progress[$name] = 'attempted'
            Save-AuthenticationAgentCheckpoint $ProofDirectory $Report
            Invoke-IsolationCheck (Join-Path $ProofDirectory 'endpoint-tests.exe') $name $log
            $markers = Get-AuthenticationAgentLogMarkers $log -RequireLog
            Assert-AuthenticationAgentMarkers $markers
            $null = Assert-AuthenticationAgentInputs $ProofDirectory $Report.manifest_sha256
            $Report.checks[$name] = 'passed'
            $Report.progress[$name] = 'completed'
            Save-AuthenticationAgentCheckpoint $ProofDirectory $Report
            $active = $null
            $position += 1
        }
    } catch {
        $Report.error = 'native_worker_failed'
        if ($active) { $Report.checks[$active] = 'not_verified'; $Report.progress[$active] = 'failed' }
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'worker.log') -Append -ErrorAction Stop } catch { }
        try { Save-AuthenticationAgentCheckpoint $ProofDirectory $Report } catch { }
        throw 'Native authentication-agent worker failed; private evidence retained on worker'
    } finally {
        foreach ($name in $environment) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    }
}

function Invoke-AuthenticationAgentWorker([string]$ProofDirectory, [bool]$AllowDisposable) {
    $ErrorActionPreference = 'Stop'
    if (-not $AllowDisposable -or [Environment]::OSVersion.Platform -ne 'Win32NT' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'Authentication-agent worker requires disposable native LocalSystem in session zero'
    }
    $digest = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory 'inputs.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = Assert-AuthenticationAgentInputs $ProofDirectory $digest
    $report = @{ schema=1; suite='AuthenticationAgent'; native_windows_executed=$true; production_readiness=$false;
        proof_scope='actual_agent'; manifest_sha256=$digest; user_sid='S-1-5-18'; session_id=0;
        windows_version=[Environment]::OSVersion.Version.ToString(); checks=[ordered]@{}; progress=[ordered]@{}; error=$null }
    foreach ($name in Get-AuthenticationAgentTests) { $report.checks[$name] = 'not_verified'; $report.progress[$name] = 'not_attempted' }
    Save-AuthenticationAgentCheckpoint $ProofDirectory $report
    # Import parameters cannot overwrite these deliberately distinct local names.
    . (Join-Path $ProofDirectory 'verify_windows_isolation_ci.ps1')
    Invoke-AuthenticationAgentWorkerChecks $ProofDirectory $report
}

function Invoke-AuthenticationAgentEvidence([string]$ProofDirectory, [string]$ProofTask, $ProofAction,
                                         [string]$ManifestSha256, [string]$ExpectedSource) {
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $ExpectedSource -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Invalid authentication-agent evidence binding'
    }
    $result = Join-Path $ProofDirectory 'authentication-agent-worker.private.json'
    $public = @{ schema=1; suite='AuthenticationAgent'; proof_scope='actual_agent'; production_readiness=$false;
        manifest_sha256=$ManifestSha256; native_authentication_agent_validation_passed=$false;
        stages=@(); checks=[ordered]@{}; error='native_authentication_agent_not_verified'; runner_failure=$null;
        diagnostics=@{ status='unavailable'; checks=[ordered]@{} } }
    foreach ($name in Get-AuthenticationAgentTests) { $public.checks[$name] = 'not_verified' }
    try {
        $null = Assert-AuthenticationAgentInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $public.stages += 'inputs_verified'
        Invoke-ServiceFixtureTask $ProofTask $ProofAction $result $ManifestSha256 840 {
            param($Report, $Digest)
            Assert-AuthenticationAgentReport $Report $Digest
        }
        $public.stages += 'task_completed_and_removed'
        $null = Assert-AuthenticationAgentInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-AuthenticationAgentReport $report $ManifestSha256
        $markers = Get-AuthenticationAgentLogMarkers (Join-Path $ProofDirectory 'check-0.log') -RequireLog
        Assert-AuthenticationAgentMarkers $markers
        $null = Assert-AuthenticationAgentInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-AuthenticationAgentReport $report $ManifestSha256
        # Publish the exact marker snapshot that passed the agent proof; never
        # replace it with a later diagnostic read after authorizing success.
        $public.diagnostics = @{ status='available'; checks=[ordered]@{} }
        $public.diagnostics.checks[@(Get-AuthenticationAgentTests)[0]] = @{ progress='completed';
            stages=$markers.stages; failures=$markers.failures }
        $public.stages += 'report_verified'
        foreach ($name in Get-AuthenticationAgentTests) { $public.checks[$name] = 'passed' }
        $public.native_authentication_agent_validation_passed = $true
        $public.error = $null
    } catch {
        $public.runner_failure = Get-AuthenticationAgentRunnerFailure $_.Exception.Message
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'authentication-agent-validation.private.log') -Append -ErrorAction Stop } catch { }
        $public.diagnostics = Get-AuthenticationAgentDiagnostics $ProofDirectory $ManifestSha256 $ExpectedSource
    }
    $public | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ProofDirectory 'authentication-agent-validation.json') -Encoding UTF8
    if (-not $public.native_authentication_agent_validation_passed) { throw 'Native authentication-agent validation failed; private evidence retained on worker' }
}

function Invoke-AuthenticationAgentCi([string]$AgentPath, [string]$TestsPath, [string]$ProofDirectory, [bool]$AllowDisposable) {
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
        'verify_windows_authentication_agent_ci.ps1'=$PSCommandPath;
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
    $manifest = @{ schema=1; suite='AuthenticationAgent'; github_sha=$sourceRevision; sha256=@{} }
    foreach ($name in Get-AuthenticationAgentInputNames) {
        $digest = (Get-FileHash -LiteralPath $sources[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $sources[$name] -Destination (Join-Path $ProofDirectory $name)
        if ((Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
            throw 'Staged authentication-agent input differs from source'
        }
        $manifest.sha256[$name] = $digest
    }
    $manifestPath = Join-Path $ProofDirectory 'inputs.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixture = Join-Path $ProofDirectory 'verify_windows_authentication_agent_ci.ps1'
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
    $taskName = 'AthernexAuthenticationAgentValidation-' + [Guid]::NewGuid().ToString('N')
    $null = Assert-AuthenticationAgentInputs $ProofDirectory $digest $sourceRevision
    . (Join-Path $ProofDirectory 'verify_windows_service_ci.ps1')
    Invoke-AuthenticationAgentEvidence $ProofDirectory $taskName $action $digest $sourceRevision
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Worker) { Invoke-AuthenticationAgentWorker $OutputDirectory $DisposableHost.IsPresent }
    else {
        try { Invoke-AuthenticationAgentCi $AgentExecutable $EndpointTests $OutputDirectory $DisposableHost.IsPresent }
        catch {
            try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'runner.log') -Append -ErrorAction Stop } catch { }
            throw 'Native authentication-agent validation failed; private evidence retained on worker when available'
        }
    }
}
