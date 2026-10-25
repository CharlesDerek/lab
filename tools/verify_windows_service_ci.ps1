<#
Run the SCM fixture as LocalSystem on a disposable GitHub-hosted Windows VM.
Dot-sourcing defines the helpers without creating files, tasks or services.
#>
param([string]$Agent, [string]$OutputDirectory, [switch]$DisposableHost)

function Assert-ServiceFixtureReport($Report, [string]$AgentSha256) {
    $expected = @(
        'registration_is_stopped_local_system_and_exactly_bound',
        'scm_host_owns_actual_launcher_controller_and_agent',
        'live_host_retains_installer_exclusion',
        'clean_stop_confirms_entire_owned_tree_and_terminal_diagnostic',
        'explicit_restart_creates_a_new_owned_tree',
        'host_crash_cleans_descendants_and_scm_recovers'
    )
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
    foreach ($relative in @('tools/verify_windows_service.ps1', 'core-engines/endpoint/src/installer/register.ps1')) {
        $destination = Join-Path $OutputDirectory $relative
        $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
        Copy-Item -LiteralPath (Join-Path $sourceRoot $relative) -Destination $destination
    }
    $stagedAgent = Join-Path $OutputDirectory 'agent.exe'
    Copy-Item -LiteralPath $Agent -Destination $stagedAgent
    $digest = (Get-FileHash -LiteralPath $Agent -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath $stagedAgent -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'Staged agent hash differs' }
    $fixture = Join-Path $OutputDirectory 'tools/verify_windows_service.ps1'
    $result = Join-Path $OutputDirectory 'service-validation.json'
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
    $runner = @{ schema=1; task=$taskName; agent_sha256=$digest; github_sha=$env:GITHUB_SHA;
        github_run_id=$env:GITHUB_RUN_ID; native_service_validation_passed=$false; error=$null }
    try {
        Invoke-ServiceFixtureTask $taskName $action $result $digest
        $runner.native_service_validation_passed = $true
    } catch {
        $runner.error = $_.Exception.Message
        throw
    } finally {
        $runner | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'runner.json') -Encoding UTF8
        if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log }
        Write-Host ('Retained native service evidence: ' + $OutputDirectory)
    }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-ServiceFixtureCi $Agent $OutputDirectory $DisposableHost.IsPresent }
