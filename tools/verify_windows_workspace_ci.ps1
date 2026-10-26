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

function Assert-WorkspaceRecoveryInputs([string]$ProofDirectory, [string]$ManifestSha256, [string]$ExpectedSource = '') {
    $path = Join-Path $ProofDirectory 'inputs.json'
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) {
        throw 'Workspace-recovery input manifest changed'
    }
    $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $expected = @(Get-WorkspaceRecoveryInputNames)
    if (($manifest.schema -isnot [int] -and $manifest.schema -isnot [long]) -or
        $manifest.schema -ne 1 -or $manifest.suite -cne 'WorkspaceRecovery' -or
        $manifest.github_sha -cnotmatch '\A[0-9a-f]{40}\z' -or
        ($ExpectedSource -and $manifest.github_sha -cne $ExpectedSource) -or
        @($manifest.sha256.PSObject.Properties.Name).Count -ne $expected.Count) {
        throw 'Invalid workspace-recovery input manifest'
    }
    foreach ($name in $expected) {
        if (@($manifest.sha256.PSObject.Properties.Name) -cnotcontains $name -or
            $manifest.sha256.$name -cnotmatch '\A[0-9a-f]{64}\z' -or
            (Get-FileHash -LiteralPath (Join-Path $ProofDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.sha256.$name) {
            throw 'Staged workspace-recovery input changed'
        }
    }
    $manifest
}

function Assert-WorkspaceRecoveryReport($Report, [string]$ManifestSha256) {
    if (($Report.schema -isnot [int] -and $Report.schema -isnot [long]) -or
        $Report.schema -ne 1 -or $Report.suite -cne 'WorkspaceRecovery' -or
        $Report.native_windows_executed -isnot [bool] -or $Report.production_readiness -isnot [bool] -or
        $Report.native_windows_executed -cne $true -or $Report.production_readiness -cne $false -or
        $Report.proof_scope -cne 'agent_cleanup_recovery' -or $Report.manifest_sha256 -cne $ManifestSha256 -or
        ($Report.session_id -isnot [int] -and $Report.session_id -isnot [long]) -or
        $Report.user_sid -cne 'S-1-5-18' -or $Report.session_id -cne 0 -or
        -not $Report.windows_version -or $null -ne $Report.error) { throw 'Invalid workspace-recovery worker identity or result' }
    $expected = @(Get-WorkspaceRecoveryTests)
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne $expected.Count) { throw 'Incomplete workspace-recovery check set' }
    foreach ($name in $expected) {
        if ($names -cnotcontains $name -or $Report.checks.$name -cne 'passed') {
            throw 'Workspace-recovery native check did not pass'
        }
    }
}

function Invoke-WorkspaceRecoveryWorkerChecks([string]$ProofDirectory, $Report) {
    $environment = @('ATHERNEX_WINDOWS_WORKSPACE_DISPOSABLE_HOST','ATHERNEX_NATIVE_WORKSPACE_AGENT',
        'ATHERNEX_WINDOWS_AUTHENTICATION_DISPOSABLE_HOST','ATHERNEX_WINDOWS_PROCESS_EVENTS_PROBE_DISPOSABLE_HOST',
        'ATHERNEX_WINDOWS_PROCESS_EVENTS_DISPOSABLE_HOST','ATHERNEX_NATIVE_PROCESS_EVENTS_AGENT')
    $previous = @{}
    foreach ($name in $environment) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    try {
        $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $Report.manifest_sha256
        [Environment]::SetEnvironmentVariable($environment[0], '1', 'Process')
        [Environment]::SetEnvironmentVariable($environment[1], (Join-Path $ProofDirectory 'agent.exe'), 'Process')
        foreach ($name in $environment[2..5]) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
        $position = 0
        foreach ($name in Get-WorkspaceRecoveryTests) {
            $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $Report.manifest_sha256
            $log = Join-Path $ProofDirectory ('check-' + $position + '.log')
            Invoke-IsolationCheck (Join-Path $ProofDirectory 'windows_workspace.exe') $name $log
            $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $Report.manifest_sha256
            $Report.checks[$name] = 'passed'
            $position += 1
        }
    } catch {
        $Report.error = 'native_worker_failed'
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'worker.log') -Append -ErrorAction Stop } catch { }
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
    # Import parameters cannot overwrite these deliberately distinct local names.
    . (Join-Path $ProofDirectory 'verify_windows_isolation_ci.ps1')
    $report = @{ schema=1; suite='WorkspaceRecovery'; native_windows_executed=$true; production_readiness=$false;
        proof_scope='agent_cleanup_recovery'; manifest_sha256=$digest; user_sid='S-1-5-18'; session_id=0;
        windows_version=[Environment]::OSVersion.Version.ToString(); checks=[ordered]@{}; error=$null }
    foreach ($name in Get-WorkspaceRecoveryTests) { $report.checks[$name] = 'not_verified' }
    try { Invoke-WorkspaceRecoveryWorkerChecks $ProofDirectory $report }
    finally {
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ProofDirectory 'workspace-recovery-worker.private.json') -Encoding UTF8
    }
}

function Invoke-WorkspaceRecoveryEvidence([string]$ProofDirectory, [string]$ProofTask, $ProofAction,
                                         [string]$ManifestSha256, [string]$ExpectedSource) {
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $ExpectedSource -cnotmatch '\A[0-9a-f]{40}\z') {
        throw 'Invalid workspace-recovery evidence binding'
    }
    $result = Join-Path $ProofDirectory 'workspace-recovery-worker.private.json'
    $public = @{ schema=1; suite='WorkspaceRecovery'; proof_scope='agent_cleanup_recovery'; production_readiness=$false;
        manifest_sha256=$ManifestSha256; native_workspace_recovery_validation_passed=$false;
        stages=@(); checks=[ordered]@{}; error='native_workspace_recovery_not_verified' }
    foreach ($name in Get-WorkspaceRecoveryTests) { $public.checks[$name] = 'not_verified' }
    try {
        $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $public.stages += 'inputs_verified'
        Invoke-ServiceFixtureTask $ProofTask $ProofAction $result $ManifestSha256 840 {
            param($Report, $Digest)
            Assert-WorkspaceRecoveryReport $Report $Digest
        }
        $public.stages += 'task_completed_and_removed'
        $null = Assert-WorkspaceRecoveryInputs $ProofDirectory $ManifestSha256 $ExpectedSource
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-WorkspaceRecoveryReport $report $ManifestSha256
        $public.stages += 'report_verified'
        foreach ($name in Get-WorkspaceRecoveryTests) { $public.checks[$name] = 'passed' }
        $public.native_workspace_recovery_validation_passed = $true
        $public.error = $null
    } catch {
        try { $_ | Out-File -LiteralPath (Join-Path $ProofDirectory 'workspace-recovery-validation.private.log') -Append -ErrorAction Stop } catch { }
    }
    $public | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ProofDirectory 'workspace-recovery-validation.json') -Encoding UTF8
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
