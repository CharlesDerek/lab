<#
Run the SCM fixture as LocalSystem on a disposable GitHub-hosted Windows VM.
Dot-sourcing defines the helpers without creating files, tasks or services.
#>
param([string]$Agent, [string]$OutputDirectory, [switch]$DisposableHost)

function Get-ServiceChecks {
    @(
        'registration_is_stopped_local_system_and_exactly_bound',
        'scm_host_owns_actual_launcher_controller_and_agent',
        'live_host_retains_installer_exclusion',
        'clean_stop_confirms_entire_owned_tree_and_terminal_diagnostic',
        'explicit_restart_creates_a_new_owned_tree',
        'host_crash_cleans_descendants_and_scm_recovers'
    )
}

function Assert-ServiceFixtureReport($Report, [string]$AgentSha256) {
    $expected = @(Get-ServiceChecks)
    if ($Report.schema -ne 1 -or $Report.native_windows_executed -cne $true -or
        $Report.production_readiness -cne $false -or $Report.agent_sha256 -cne $AgentSha256 -or
        $Report.user_sid -cne 'S-1-5-18' -or $Report.session_id -cne 0 -or $Report.error -or
        -not $Report.windows_version -or -not $Report.fixture) { throw 'Native service report identity or result is invalid' }
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne $expected.Count) { throw 'Native service report has an incomplete check set' }
    foreach ($name in $expected) {
        if ($names -cnotcontains $name -or $Report.checks.$name -cne 'passed') { throw ('Native service check did not pass: ' + $name) }
    }
}

function Invoke-ServiceFixtureTask([string]$TaskName, $Action, [string]$ResultFile, [string]$AgentSha256,
                                   [int]$TimeoutSeconds = 540, [scriptblock]$ValidateReport = $null) {
    $registered = $false
    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw 'Fixture task already exists' }
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSeconds - 30)) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
            # Ready immediately after Start-ScheduledTask can still mean "not run".
            # A report in this fresh private directory proves that the fixture ran.
            if ($task.State -notin @('Running', 'Queued') -and (Test-Path -LiteralPath $ResultFile)) {
                if ($info.LastTaskResult -ne 0) { throw ('Native service task failed: ' + $info.LastTaskResult) }
                $report = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json
                if ($ValidateReport) { & $ValidateReport $report $AgentSha256 }
                else { Assert-ServiceFixtureReport $report $AgentSha256 }
                return
            }
            if ($task.State -notin @('Running', 'Queued') -and $info.LastRunTime -gt [datetime]::new(2000,1,1) -and
                $info.LastTaskResult -ne 0) { throw ('Native service task failed before writing its report: ' + $info.LastTaskResult) }
            Start-Sleep -Milliseconds 250
        }
        throw 'Native service task deadline elapsed without a completed, valid report'
    } finally {
        if ($registered) {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $Action.Execute -or
                $task.Actions[0].Arguments -cne $Action.Arguments) { throw 'Fixture task ownership changed; retained for inspection' }
            Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
            if ($task.State -in @('Running', 'Queued')) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop }
            $deadline = (Get-Date).AddSeconds(15)
            while ((Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State -in @('Running','Queued')) {
                if ((Get-Date) -ge $deadline) { throw 'Fixture task did not stop; retained for inspection' }
                Start-Sleep -Milliseconds 100
            }
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        }
    }
}

function Assert-ServiceInputs([string]$OutputDirectory, [string]$ManifestSha256) {
    $path = Join-Path $OutputDirectory 'inputs.json'
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) {
        throw 'Service input manifest changed'
    }
    $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $expected = @('agent.exe', 'tools/verify_windows_service.ps1', 'core-engines/endpoint/src/installer/register.ps1')
    if ($manifest.schema -ne 1 -or $manifest.suite -cne 'Service' -or
        $manifest.github_sha -cnotmatch '\A[0-9a-f]{40}\z' -or
        $manifest.runner_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        @($manifest.sha256.PSObject.Properties.Name).Count -ne $expected.Count) { throw 'Invalid service input manifest' }
    foreach ($name in $expected) {
        if ($manifest.sha256.$name -cnotmatch '\A[0-9a-f]{64}\z' -or
            (Get-FileHash -LiteralPath (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.sha256.$name) {
            throw 'Staged service input changed'
        }
    }
    $manifest
}

function Invoke-ServiceFixtureEvidence([string]$OutputDirectory, [string]$TaskName, $Action,
                                       [string]$ManifestSha256, [string]$AgentSha256) {
    # The fixture report and every captured stream remain private. Public output
    # is constructed from constants and validated hashes, never copied fields.
    if ($ManifestSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $AgentSha256 -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'Invalid service evidence binding'
    }
    $result = Join-Path $OutputDirectory 'service-validation.private.json'
    $log = Join-Path $OutputDirectory 'service-validation.log'
    $public = @{ schema=1; suite='Service'; manifest_sha256=$ManifestSha256; agent_sha256=$AgentSha256;
        native_service_validation_passed=$false; production_readiness=$false;
        stages=@(); checks=[ordered]@{}; error='native_service_validation_failed' }
    foreach ($name in Get-ServiceChecks) { $public.checks[$name] = 'not_verified' }
    try {
        $manifest = Assert-ServiceInputs $OutputDirectory $ManifestSha256
        if ($manifest.sha256.'agent.exe' -cne $AgentSha256) { throw 'Service executable binding differs' }
        $public.stages += 'inputs_verified'
        Invoke-ServiceFixtureTask $TaskName $Action $result $AgentSha256
        $public.stages += 'task_completed'
        $null = Assert-ServiceInputs $OutputDirectory $ManifestSha256
        $report = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Assert-ServiceFixtureReport $report $AgentSha256
        $public.stages += 'report_verified'
        foreach ($name in Get-ServiceChecks) { $public.checks[$name] = 'passed' }
        $public.native_service_validation_passed = $true
        $public.error = $null
    } catch {
        # Even an I/O exception can contain a path or arbitrary fixture content.
        try { $_ | Out-File -LiteralPath $log -Append -ErrorAction Stop } catch { }
    }
    $public | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'service-validation.json') -Encoding UTF8
    if (-not $public.native_service_validation_passed) { throw 'Native service validation failed; private evidence retained on worker' }
}

function Invoke-ServiceFixtureCi([string]$Agent, [string]$OutputDirectory, [bool]$DisposableHost) {
    $ErrorActionPreference = 'Stop'
    if (-not $DisposableHost -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
        [Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Requires an explicitly disposable GitHub-hosted Windows runner' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Requires an elevated runner' }
    if (-not $Agent -or -not $OutputDirectory) { throw 'Agent and OutputDirectory are required' }
    $Agent = (Resolve-Path -LiteralPath $Agent).Path
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
    # Stage the exact executable and scripts below the same private directory.
    # SYSTEM never executes a script from a user-writable checkout.
    $sourceRoot = Split-Path -Parent $PSScriptRoot
    if ($env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z') { throw 'Invalid service source revision' }
    $manifest = @{ schema=1; suite='Service'; github_sha=$env:GITHUB_SHA;
        runner_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant(); sha256=@{} }
    foreach ($relative in @('tools/verify_windows_service.ps1', 'core-engines/endpoint/src/installer/register.ps1')) {
        $source = Join-Path $sourceRoot $relative
        $manifest.sha256[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        $destination = Join-Path $OutputDirectory $relative
        $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
        Copy-Item -LiteralPath $source -Destination $destination
    }
    $stagedAgent = Join-Path $OutputDirectory 'agent.exe'
    Copy-Item -LiteralPath $Agent -Destination $stagedAgent
    $digest = (Get-FileHash -LiteralPath $Agent -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath $stagedAgent -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'Staged agent hash differs' }
    $manifest.sha256['agent.exe'] = $digest
    $manifestPath = Join-Path $OutputDirectory 'inputs.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = Assert-ServiceInputs $OutputDirectory $manifestHash
    $fixture = Join-Path $OutputDirectory 'tools/verify_windows_service.ps1'
    $result = Join-Path $OutputDirectory 'service-validation.private.json'
    $log = Join-Path $OutputDirectory 'service-validation.log'
    # JSON is data inside a quoted PowerShell string; quotes in paths remain literal.
    $arguments = @{ Agent=$stagedAgent; AgentSha256=$digest; ResultFile=$result; Fixture=$fixture; Log=$log } | ConvertTo-Json -Compress
    $literal = $arguments.Replace("'", "''")
    $code = @'
$ErrorActionPreference = 'Stop'
$p = ConvertFrom-Json '__PARAMETERS__'
try {
    & $p.Fixture -Agent $p.Agent -AgentSha256 $p.AgentSha256 -ResultFile $p.ResultFile -DisposableHost *> $p.Log
    exit 0
} catch {
    $_ | Out-File -LiteralPath $p.Log -Append
    exit 1
}
'@.Replace('__PARAMETERS__', $literal)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encoded)
    $taskName = 'AthernexServiceValidation-' + [Guid]::NewGuid().ToString('N')
    Invoke-ServiceFixtureEvidence $OutputDirectory $taskName $action $manifestHash $digest
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-ServiceFixtureCi $Agent $OutputDirectory $DisposableHost.IsPresent }
    catch { throw 'Native service validation failed; private evidence retained on worker when available' }
}
