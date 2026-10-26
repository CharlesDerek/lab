<#
Validate three actual-agent cleanup protocols on an explicitly disposable Windows
LocalSystem worker. Raw state, nonces, paths, errors and worker reports remain in
the protected VM directory. This does not validate formatted scratch capacity.
Dot-sourcing defines helpers only.
#>
param([string]$AgentExecutable, [string]$WorkspaceTests, [string]$OutputDirectory,
      [switch]$DisposableHost, [switch]$Worker)

function Get-WorkspaceRecoveryTests {
    @('actual_scratch_cleanup_excludes_live_workers_and_replays_partial_image_retirement',
      'actual_preview_recovery_waits_for_workers_and_retires_scratch_before_staged_files',
      'actual_cleanup_worker_preserves_live_journals_and_replays_committed_workspace_deletion')
}

function Get-WorkspaceRecoveryInputNames {
    @('agent.exe','windows_workspace.exe','verify_windows_workspace_ci.ps1',
      'verify_windows_isolation_ci.ps1','verify_windows_service_ci.ps1')
}

function Test-WorkspaceRecoveryLiteral($Value, [string]$Expected) {
    $Value -is [string] -and [StringComparer]::Ordinal.Equals($Value, $Expected)
}

function Assert-WorkspaceRecoveryInputs([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource = '') {
    $path = Join-Path $ProofDirectory 'inputs.json'
    try { $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { throw 'Invalid workspace-recovery input manifest' }
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $actual -cne $ManifestSha256) {
        throw 'Workspace-recovery input manifest changed'
    }
    try { $manifest = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Invalid workspace-recovery input manifest' }
    $expected = @(Get-WorkspaceRecoveryInputNames)
    if (($manifest.schema -isnot [int] -and $manifest.schema -isnot [long]) -or
        $manifest.schema -ne 1 -or -not (Test-WorkspaceRecoveryLiteral $manifest.suite 'WorkspaceRecovery') -or
        $manifest.github_sha -isnot [string] -or $manifest.github_sha -cnotmatch '\A[0-9a-f]{40}\z' -or
        ($ExpectedSource -and $manifest.github_sha -cne $ExpectedSource) -or
        @($manifest.sha256.PSObject.Properties.Name).Count -ne $expected.Count) {
        throw 'Invalid workspace-recovery input manifest'
    }
    foreach ($name in $expected) {
        if ([Array]::IndexOf([string[]]@($manifest.sha256.PSObject.Properties.Name), $name) -lt 0 -or
            $manifest.sha256.$name -isnot [string] -or $manifest.sha256.$name -cnotmatch '\A[0-9a-f]{64}\z') {
            throw 'Staged workspace-recovery input changed'
        }
        try { $actual = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
        catch { throw 'Staged workspace-recovery input invalid' }
        if ($actual -cne $manifest.sha256.$name) { throw 'Staged workspace-recovery input changed' }
    }
    $manifest
}

function Assert-WorkspaceRecoveryReport($Report, [string]$ManifestSha256) {
    if (($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or
        $Report.schema -ne 1 -or -not (Test-WorkspaceRecoveryLiteral $Report.suite 'WorkspaceRecovery') -or
        $Report.native_windows_executed -isnot [bool] -or $Report.production_readiness -isnot [bool] -or
        $Report.native_windows_executed -cne $true -or $Report.production_readiness -cne $false -or
        -not (Test-WorkspaceRecoveryLiteral $Report.proof_scope 'agent_cleanup_recovery') -or
        -not (Test-WorkspaceRecoveryLiteral $Report.manifest_sha256 $ManifestSha256) -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or
        -not (Test-WorkspaceRecoveryLiteral $Report.user_sid 'S-1-5-18') -or $Report.session_id -cne 0 -or
        $Report.windows_version -isnot [string] -or -not $Report.windows_version -or
        $null -ne $Report.error) { throw 'Invalid workspace-recovery worker identity or result' }
    $expected = @(Get-WorkspaceRecoveryTests)
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne $expected.Count) { throw 'Incomplete workspace-recovery check set' }
    foreach ($name in $expected) {
        if ([Array]::IndexOf([string[]]$names, $name) -lt 0 -or -not (Test-WorkspaceRecoveryLiteral $Report.checks.$name 'passed')) {
            throw 'Workspace-recovery native check did not pass'
        }
    }
}

# This validator authorizes diagnostic projection only, never native success.
function Assert-WorkspaceRecoveryPartialReport($Report, [string]$ManifestSha256) {
    $fields = @('schema','suite','native_windows_executed','production_readiness','proof_scope',
        'manifest_sha256','user_sid','session_id','windows_version','checks','progress','error')
    $names = @($Report.PSObject.Properties.Name)
    if ($names.Count -ne $fields.Count -or @($fields | Where-Object { [Array]::IndexOf([string[]]$names, $_) -lt 0 }).Count -ne 0 -or
        ($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or $Report.schema -ne 1 -or
        -not (Test-WorkspaceRecoveryLiteral $Report.suite 'WorkspaceRecovery') -or
        -not (Test-WorkspaceRecoveryLiteral $Report.proof_scope 'agent_cleanup_recovery') -or
        $Report.native_windows_executed -isnot [bool] -or -not $Report.native_windows_executed -or
        $Report.production_readiness -isnot [bool] -or $Report.production_readiness -or
        -not (Test-WorkspaceRecoveryLiteral $Report.manifest_sha256 $ManifestSha256) -or
        -not (Test-WorkspaceRecoveryLiteral $Report.user_sid 'S-1-5-18') -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or $Report.session_id -ne 0 -or
        $Report.windows_version -isnot [string] -or -not $Report.windows_version -or
        ($null -ne $Report.error -and -not (Test-WorkspaceRecoveryLiteral $Report.error 'native_worker_failed'))) {
        throw 'Invalid workspace-recovery diagnostic identity'
    }
    $expected = @(Get-WorkspaceRecoveryTests)
    $checks = @($Report.checks.PSObject.Properties.Name)
    $progress = @($Report.progress.PSObject.Properties.Name)
    if ($checks.Count -ne 3 -or $progress.Count -ne 3) { throw 'Invalid workspace-recovery diagnostic check set' }
    $closed = $false
    foreach ($name in $expected) {
        $state = $Report.progress.$name
        if ([Array]::IndexOf([string[]]$checks, $name) -lt 0 -or [Array]::IndexOf([string[]]$progress, $name) -lt 0 -or
            $state -isnot [string] -or $state -cnotmatch '\A(not_attempted|attempted|completed|failed)\z' -or
            $Report.checks.$name -isnot [string] -or
            ($state -ceq 'completed' -and -not (Test-WorkspaceRecoveryLiteral $Report.checks.$name 'passed')) -or
            ($state -cne 'completed' -and -not (Test-WorkspaceRecoveryLiteral $Report.checks.$name 'not_verified')) -or
            ($state -ceq 'failed' -and $Report.error -cne 'native_worker_failed') -or
            ($closed -and $state -cne 'not_attempted')) { throw 'Invalid workspace-recovery diagnostic progress' }
        if ($state -cne 'completed') { $closed = $true }
    }
}

function Save-WorkspaceRecoveryCheckpoint([string]$ProofDirectory, $Report) {
    $pending = Join-Path $ProofDirectory 'workspace-recovery-worker.pending.private.json'
    $destination = Join-Path $ProofDirectory 'workspace-recovery-worker.private.json'
    try {
        $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $pending -Encoding UTF8 -ErrorAction Stop
        # Same protected directory: readers see either the preceding or new complete checkpoint.
        if (Test-Path -LiteralPath $destination) { [IO.File]::Replace($pending, $destination, [System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($pending, $destination) }
    } catch { throw 'Workspace-recovery private checkpoint failed' }
}

function Get-WorkspaceRecoveryLogMarkers([string]$Log, [switch]$RequireLog) {
    $stages = @('guard_started','guard_verified','agent_verified','private_ready','scratch_prepared',
        'scratch_spoof_refused','scratch_live_owner_retained','scratch_worker_lease_refused',
        'scratch_network_retained','scratch_cleanup_verified','scratch_retirement_replayed','scratch_empty_replayed',
        'preview_prepared','preview_supervisor_refused','preview_workers_refused','preview_network_retained',
        'preview_cleanup_verified','preview_empty_replayed','preview_storage_empty','workspace_prepared',
        'workspace_spoof_refused','workspace_network_retained','workspace_cleanup_verified','workspace_deletion_replayed')
    $failures = @('bounded_cleanup_failed','bounded_recovery_failed','invalid_scratch_request','invalid_workspace_request',
        'scratch_live_owner','scratch_network_pending','workspace_network_pending','other_private')
    $result = @{ stages=@(); failures=@(); exits=@() }
    try {
        if (-not (Test-Path -LiteralPath $Log -PathType Leaf)) {
            if ($RequireLog) { throw 'Missing workspace-recovery diagnostic log' }
            return $result
        }
        if ((Get-Item -LiteralPath $Log -ErrorAction Stop).Length -gt 16MB) { throw 'Oversized workspace-recovery diagnostic log' }
        foreach ($line in Get-Content -LiteralPath $Log -Encoding UTF8 -ErrorAction Stop) {
            foreach ($tag in $stages) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_WORKSPACE_STAGE=' + $tag)) -and $result.stages -cnotcontains $tag) {
                    $result.stages += $tag
                }
            }
            foreach ($tag in $failures) {
                if ([StringComparer]::Ordinal.Equals($line, ('ATHERNEX_WORKSPACE_FAILURE=' + $tag)) -and $result.failures -cnotcontains $tag) {
                    $result.failures += $tag
                }
            }
            if ($result.exits.Count -lt 32 -and $line -cmatch '\AATHERNEX_WORKSPACE_EXIT=(scratch_cleanup|preview_recovery|workspace_cleanup):(0|[1-9][0-9]{0,9}|-[1-9][0-9]{0,9})\z') {
                $operation = $Matches[1]
                $code = 0
                if ([int]::TryParse($Matches[2], [Globalization.NumberStyles]::AllowLeadingSign,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$code)) {
                    $result.exits += @{ operation=$operation; exit_code=$code }
                }
            }
        }
    } catch { throw 'Workspace-recovery diagnostic log unavailable' }
    $result
}

function Get-WorkspaceRecoveryRunnerFailure([string]$Message) {
    $known = @{
        'Workspace-recovery input manifest changed'='input_manifest_changed'
        'Invalid workspace-recovery input manifest'='input_manifest_invalid'
        'Staged workspace-recovery input changed'='input_file_changed'
        'Staged workspace-recovery input invalid'='input_file_invalid'
        'Invalid workspace-recovery worker identity or result'='report_identity_invalid'
        'Incomplete workspace-recovery check set'='report_check_set_invalid'
        'Workspace-recovery native check did not pass'='report_check_failed'
        'Native service task deadline elapsed without a completed, valid report'='task_timeout'
        'Fixture task already exists'='task_ownership_failed'
        'Fixture task ownership changed; retained for inspection'='task_ownership_failed'
        'Fixture task did not stop; retained for inspection'='task_stop_failed'
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

function Get-WorkspaceRecoveryDiagnostics([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource) {
    $result = @{ status='unbound'; checks=[ordered]@{} }
    try { $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $ManifestSha256 $ExpectedSource } catch { return $result }
    $path = Join-Path $ProofDirectory 'workspace-recovery-worker.private.json'
    try {
        $result.status = 'unavailable'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $result.status = 'missing'; return $result }
        $result.status = 'invalid'
        if ((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 64KB) { return $result }
        $report = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        Assert-WorkspaceRecoveryPartialReport $report $ManifestSha256
        $result.status = 'unavailable'
        $projected = [ordered]@{}
        $position = 0
        foreach ($name in Get-WorkspaceRecoveryTests) {
            $markers = @{ stages=@(); failures=@(); exits=@() }
            if ($report.progress.$name -cne 'not_attempted') {
                $markers = Get-WorkspaceRecoveryLogMarkers (Join-Path $ProofDirectory ('check-' + $position + '.log'))
            }
            $projected[$name] = @{ progress=$report.progress.$name; stages=$markers.stages; failures=$markers.failures; exits=$markers.exits }
            $position += 1
        }
        # Recheck after reading diagnostic files as well as before projecting them.
        $result.status = 'unbound'
        $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $result.checks = $projected
        $result.status = 'available'
    } catch { }
    $result
}

function Invoke-WorkspaceRecoveryWorkerChecks([string]$ProofDirectory, $Report) {
    $environment = @('ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST','ATHERNEX_NATIVE_WORKSPACE_AGENT',
        'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST','ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST',
        'ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT')
    $previous = @{}
    foreach ($name in $environment) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $active = $null
    try {
        $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $Report.manifest_sha256
        [Environment]::SetEnvironmentVariable($environment[0], '1', 'Process')
        [Environment]::SetEnvironmentVariable($environment[1], (Join-Path $ProofDirectory 'agent.exe'), 'Process')
        foreach ($name in $environment[2..5]) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
        $position = 0
        foreach ($name in Get-WorkspaceRecoveryTests) {
            $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $Report.manifest_sha256
            $log = Join-Path $ProofDirectory ('check-' + $position + '.log')
            $active = $name
            $Report.progress[$name] = 'attempted'
            Save-WorkspaceRecoveryCheckpoint $ProofDirectory $Report
            Invoke-IsolationCheck (Join-Path $ProofDirectory 'windows_workspace.exe') $name $log
            $null = Get-WorkspaceRecoveryLogMarkers $log -RequireLog
            $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $Report.manifest_sha256
            $Report.checks[$name] = 'passed'
            $Report.progress[$name] = 'completed'
            Save-WorkspaceRecoveryCheckpoint $ProofDirectory $Report
            $active = $null
            $position += 1
        }
    } catch {
        $Report.error = 'native_worker_failed'
        if ($active) { $Report.checks[$active] = 'not_verified'; $Report.progress[$active] = 'failed' }
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'worker.log') -Append -ErrorAction Stop } catch { }
        try { Save-WorkspaceRecoveryCheckpoint $ProofDirectory $Report } catch { }
        throw 'Native workspace-recovery worker failed; private evidence retained on worker'
    } finally {
        foreach ($name in $environment) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    }
}

function Invoke-WorkspaceRecoveryWorker([string]$ProofDirectory, [bool]$AllowDisposable) {
    $ErrorActionPreference = 'Stop'
    if (-not $AllowDisposable -or [Environment]::OSVersion.Platform -ne 'Win32NT' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'Workspace-recovery worker requires disposable native LocalSystem in session zero'
    }
    $digest = (Get-FileHash -LiteralPath (Join-Path $ProofDirectory 'inputs.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $digest
    $report = @{ schema=1; suite='WorkspaceRecovery'; native_windows_executed=$true; production_readiness=$false;
        proof_scope='agent_cleanup_recovery'; manifest_sha256=$digest; user_sid='S-1-5-18'; session_id=0;
        windows_version=[Environment]::OSVersion.Version.ToString(); checks=[ordered]@{}; progress=[ordered]@{}; error=$null }
    foreach ($name in Get-WorkspaceRecoveryTests) { $report.checks[$name] = 'not_verified'; $report.progress[$name] = 'not_attempted' }
    Save-WorkspaceRecoveryCheckpoint $ProofDirectory $report
    # Import parameters cannot overwrite these deliberately distinct local names.
    . (Join-Path $ProofDirectory 'verify_windows_isolation_ci.ps1')
    Invoke-WorkspaceRecoveryWorkerChecks $ProofDirectory $report
}

function Invoke-WorkspaceRecoveryEvidence([string]$ProofDirectory, [string]$ProofTask, $ProofAction,
                                         [string]$ManifestSha256, [string]$ExpectedSource) {
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $ExpectedSource -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Invalid workspace-recovery evidence binding'
    }
    $result = Join-Path $ProofDirectory 'workspace-recovery-worker.private.json'
    $public = @{ schema=1; suite='WorkspaceRecovery'; proof_scope='agent_cleanup_recovery'; production_readiness=$false;
        manifest_sha256=$ManifestSha256; native_workspace_recovery_validation_passed=$false;
        stages=@(); checks=[ordered]@{}; error='native_workspace_recovery_not_verified'; runner_failure=$null;
        diagnostics=@{ status='unavailable'; checks=[ordered]@{} } }
    foreach ($name in Get-WorkspaceRecoveryTests) { $public.checks[$name] = 'not_verified' }
    try {
        $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $public.stages += 'inputs_verified'
        Invoke-ServiceFixtureTask $ProofTask $ProofAction $result $ManifestSha256 840 {
            param($Report, $Digest)
            Assert-WorkspaceRecoveryReport $Report $Digest
        }
        $public.stages += 'task_completed_and_removed'
        $public.diagnostics = Get-WorkspaceRecoveryDiagnostics $ProofDirectory $ManifestSha256 $ExpectedSource
        $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-WorkspaceRecoveryReport $report $ManifestSha256
        $public.stages += 'report_verified'
        foreach ($name in Get-WorkspaceRecoveryTests) { $public.checks[$name] = 'passed' }
        $public.native_workspace_recovery_validation_passed = $true
        $public.error = $null
    } catch {
        $public.runner_failure = Get-WorkspaceRecoveryRunnerFailure $_.Exception.Message
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'workspace-recovery-validation.private.log') -Append -ErrorAction Stop } catch { }
        $public.diagnostics = Get-WorkspaceRecoveryDiagnostics $ProofDirectory $ManifestSha256 $ExpectedSource
    }
    $public | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ProofDirectory 'workspace-recovery-validation.json') -Encoding UTF8
    if (-not $public.native_workspace_recovery_validation_passed) { throw 'Native workspace-recovery validation failed; private evidence retained on worker' }
}

function Invoke-WorkspaceRecoveryCi([string]$AgentPath, [string]$TestsPath, [string]$ProofDirectory, [bool]$AllowDisposable) {
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
        'windows_workspace.exe'=(Resolve-Path -LiteralPath $TestsPath).Path;
        'verify_windows_workspace_ci.ps1'=$PSCommandPath;
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
    $manifest = @{ schema=1; suite='WorkspaceRecovery'; github_sha=$sourceRevision; sha256=@{} }
    foreach ($name in Get-WorkspaceRecoveryInputNames) {
        $digest = (Get-FileHash -LiteralPath $sources[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $sources[$name] -Destination (Join-Path $ProofDirectory $name)
        if ((Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
            throw 'Staged workspace-recovery input differs from source'
        }
        $manifest.sha256[$name] = $digest
    }
    $manifestPath = Join-Path $ProofDirectory 'inputs.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixture = Join-Path $ProofDirectory 'verify_windows_workspace_ci.ps1'
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
    $taskName = 'AthernexWorkspaceRecoveryValidation-' + [Guid]::NewGuid().ToString('N')
    $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $digest $sourceRevision
    . (Join-Path $ProofDirectory 'verify_windows_service_ci.ps1')
    Invoke-WorkspaceRecoveryEvidence $ProofDirectory $taskName $action $digest $sourceRevision
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Worker) { Invoke-WorkspaceRecoveryWorker $OutputDirectory $DisposableHost.IsPresent }
    else {
        try { Invoke-WorkspaceRecoveryCi $AgentExecutable $WorkspaceTests $OutputDirectory $DisposableHost.IsPresent }
        catch {
            try { $_ | Out-File -LiteralPath (Join-Path $OutputDirectory 'runner.log') -Append -ErrorAction Stop } catch { }
            throw 'Native workspace-recovery validation failed; private evidence retained on worker when available'
        }
    }
}
