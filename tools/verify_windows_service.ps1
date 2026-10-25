#Requires -RunAsAdministrator
<#
Exercises the real SCM host on an explicitly disposable Windows machine.
Requires LocalSystem in session zero and no existing Athernex service/task.
Retains its private fixture and report. Does not install antivirus or a driver.
#>
param(
    [Parameter(Mandatory=$true)][string]$Agent,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$AgentSha256,
    [string]$ResultFile,
    [switch]$DisposableHost
)
$ErrorActionPreference = 'Stop'
if (-not $DisposableHost) { throw 'Explicit -DisposableHost is required' }
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
    throw 'Run this fixture as LocalSystem in service session zero'
}
$Name = 'AthernexEndpoint'
$Sc = Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe'
$Agent = (Resolve-Path -LiteralPath $Agent).Path
if ((Get-FileHash -LiteralPath $Agent -Algorithm SHA256).Hash.ToLowerInvariant() -ne $AgentSha256) { throw 'Agent hash mismatch' }
if ($ResultFile) {
    $ResultFile = [IO.Path]::GetFullPath($ResultFile)
    if ((Test-Path -LiteralPath $ResultFile) -or -not (Test-Path -LiteralPath (Split-Path -Parent $ResultFile) -PathType Container)) {
        throw 'Result file must be new and have an existing parent directory'
    }
}
if ((Get-CimInstance Win32_Service -Filter "Name = 'AthernexEndpoint'") -or
    (Get-ScheduledTask -TaskName 'Athernex Endpoint' -ErrorAction SilentlyContinue)) {
    throw 'Existing Athernex service/task found; this fixture never adopts an installed endpoint'
}
$Root = Join-Path $env:ProgramData ('AthernexServiceFixture-' + [Guid]::NewGuid().ToString('N'))
$Checks = [ordered]@{}
$Trees = [Collections.Generic.List[object]]::new()
$Created = $false
$Failure = $null
$BinaryPath = $null
$OldEnvironment = @{}

function Invoke-Sc([string[]]$Arguments) {
    $output = & $Sc @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('SCM command failed: ' + $Arguments[0] + ': ' + ($output -join ' ')) }
    $output
}
function Read-Service { Get-CimInstance Win32_Service -Filter "Name = 'AthernexEndpoint'" }
function Wait-Stopped {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ((Read-Service).State -ne 'Stopped') {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'SCM stop deadline elapsed' }
        Start-Sleep -Milliseconds 100
    }
}
function Read-Tree([int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $held = [Collections.Generic.List[object]]::new()
        try {
            $service = Read-Service
            if ($service.PathName -ne $BinaryPath -or $service.StartName -ne 'LocalSystem') { throw 'Service identity changed' }
            $hostState = Get-Content -LiteralPath (Join-Path $State 'supervisor\windows-service.json') -Raw | ConvertFrom-Json
            $launcherState = Get-Content -LiteralPath (Join-Path $State 'supervisor\launcher.json') -Raw | ConvertFrom-Json
            $controllerState = Get-Content -LiteralPath (Join-Path $State 'supervisor\lease.json') -Raw | ConvertFrom-Json
            if ($service.State -ne 'Running' -or $hostState.phase -ne 'running' -or
                $hostState.runtime_protection_verified -ne $false -or $hostState.host_pid -ne $service.ProcessId -or
                $hostState.launcher_pid -ne $launcherState.launcher_pid -or
                $launcherState.controller_pid -ne $controllerState.controller_pid) { throw 'Process tree is not ready' }
            $ids = @([int]$service.ProcessId, [int]$hostState.launcher_pid,
                     [int]$controllerState.controller_pid, [int]$controllerState.child_pid)
            if (@($ids | Select-Object -Unique).Count -ne 4 -or @($ids | Where-Object { $_ -le 4 }).Count -ne 0) { throw 'Incomplete tree identity' }
            $paths = @($Launcher, $Launcher, $Controller, $InstalledAgent)
            $identity = @()
            for ($index=0; $index -lt 4; $index++) {
                $process = [Diagnostics.Process]::GetProcessById($ids[$index])
                $null = $process.Handle # Retain a real handle; never kill/recheck by an old PID.
                $held.Add($process)
                $observed = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $ids[$index])
                if ($observed.ExecutablePath -ne $paths[$index] -or $process.HasExited -or
                    ($index -gt 0 -and $observed.ParentProcessId -ne $ids[$index-1])) { throw 'Process executable or creating parent changed' }
                $identity += @{ pid=$process.Id; created=$process.StartTime.ToFileTimeUtc(); path=$observed.ExecutablePath }
            }
            return [pscustomobject]@{ Processes=$held; Identity=$identity }
        } catch {
            foreach ($process in $held) { $process.Dispose() }
            Start-Sleep -Milliseconds 100
        }
    }
    throw 'Owned service/launcher/controller/agent tree did not become observable'
}
function Assert-TreeExited($Tree) {
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    foreach ($process in $Tree.Processes) {
        while (-not $process.HasExited) {
            if ([DateTime]::UtcNow -ge $deadline) { throw ('Owned descendant survived: ' + $process.Id) }
            Start-Sleep -Milliseconds 50
        }
    }
}

try {
    $null = [IO.Directory]::CreateDirectory($Root)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Root -AclObject $acl
    $Bin = Join-Path $Root 'bin'; $State = Join-Path $Root 'state'; $Watch = Join-Path $Root 'watch'
    foreach ($directory in @($Bin,$State,$Watch)) { $null = [IO.Directory]::CreateDirectory($directory) }
    $Launcher = Join-Path $Bin 'athernex-launcher.exe'
    $Controller = Join-Path $Bin 'athernex-controller.exe'
    $InstalledAgent = Join-Path $Bin 'athernex-endpoint.exe'
    foreach ($destination in @($Launcher,$Controller,$InstalledAgent)) { Copy-Item -LiteralPath $Agent -Destination $destination }
    $config = @{ server='http://127.0.0.1:9/'; endpoint_id=('a'*64); credential=('b'*64);
        enrollment_token=$null; scanner=$InstalledAgent; updater=$InstalledAgent;
        scan_roots=@($Watch); allow_scripts=$false; ca_file=$null }
    [IO.File]::WriteAllText((Join-Path $State 'config.json'), ($config | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $BinaryPath = '"' + $Launcher + '" windows-service "' + $State + '" "' + $Controller + '" "' + $InstalledAgent + '"'
    $values = @{ ATHERNEX_INSTALL_STATE=$State; ATHERNEX_INSTALL_LAUNCHER=$Launcher;
                 ATHERNEX_INSTALL_CONTROLLER=$Controller; ATHERNEX_INSTALL_AGENT=$InstalledAgent }
    foreach ($key in $values.Keys) {
        $OldEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, $values[$key], 'Process')
    }
    $register = Join-Path $PSScriptRoot '..\core-engines\endpoint\src\installer\register.ps1'
    # Track ownership before registration so partial configuration is also cleaned.
    $Created = $true
    & $register
    $service = Read-Service
    if ($service.PathName -ne $BinaryPath -or $service.State -ne 'Stopped' -or $service.StartMode -ne 'Auto') { throw 'Registered service differs from fixture plan' }
    $Checks.registration_is_stopped_local_system_and_exactly_bound = 'passed'
    Invoke-Sc @('start',$Name) | Out-Null
    $first = Read-Tree 30; $Trees.Add($first)
    $Checks.scm_host_owns_actual_launcher_controller_and_agent = 'passed'
    $lock = [IO.File]::Open((Join-Path $State 'windows-service.lock'), 'Open', 'ReadWrite', 'ReadWrite')
    try {
        $blocked = $false
        try { $lock.Lock(0,1); $lock.Unlock(0,1) } catch [IO.IOException] { $blocked = $true }
        if (-not $blocked) { throw 'Live host did not retain the installation exclusion lock' }
    } finally { $lock.Dispose() }
    $Checks.live_host_retains_installer_exclusion = 'passed'
    Invoke-Sc @('stop',$Name) | Out-Null
    Wait-Stopped
    Assert-TreeExited $first
    $stopped = Get-Content -LiteralPath (Join-Path $State 'supervisor\windows-service.json') -Raw | ConvertFrom-Json
    if ($stopped.phase -ne 'stopped' -or $stopped.host_pid -ne $first.Identity[0].pid) { throw 'Stop diagnostic was not committed before SCM completion' }
    $Checks.clean_stop_confirms_entire_owned_tree_and_terminal_diagnostic = 'passed'
    Invoke-Sc @('start',$Name) | Out-Null
    $second = Read-Tree 30; $Trees.Add($second)
    if ($second.Identity[0].created -eq $first.Identity[0].created) { throw 'Restart reused the previous host identity' }
    $Checks.explicit_restart_creates_a_new_owned_tree = 'passed'
    $second.Processes[0].Kill()
    Assert-TreeExited $second
    $third = Read-Tree 100; $Trees.Add($third)
    if ($third.Identity[0].created -eq $second.Identity[0].created) { throw 'SCM recovery did not create a new host' }
    $Checks.host_crash_cleans_descendants_and_scm_recovers = 'passed'
    Invoke-Sc @('stop',$Name) | Out-Null
    Wait-Stopped
    Assert-TreeExited $third
} catch {
    $Failure = $_.Exception.Message
} finally {
    try {
        if ($Created) {
            $service = Read-Service
            if ($service) {
                if ($service.PathName -ne $BinaryPath -or $service.StartName -ne 'LocalSystem') { throw 'Cleanup ownership changed; service and fixture retained' }
                # Disable future starts, including queued failure recovery, before removal.
                Set-Service -Name $Name -StartupType Disabled
                if ($service.State -ne 'Stopped') { Invoke-Sc @('stop',$Name) | Out-Null; Wait-Stopped }
                foreach ($tree in $Trees) { Assert-TreeExited $tree }
                Invoke-Sc @('delete',$Name) | Out-Null
            }
        }
    } catch { $Failure = "$Failure Cleanup: $($_.Exception.Message)" }
    foreach ($tree in $Trees) { foreach ($process in $tree.Processes) { $process.Dispose() } }
    foreach ($key in $OldEnvironment.Keys) { [Environment]::SetEnvironmentVariable($key, $OldEnvironment[$key], 'Process') }
    if (Test-Path -LiteralPath $Root) {
        $report = @{ schema=1; scope='Native SCM lifecycle only; no antivirus prevention or protected-service claim';
            agent_sha256=$AgentSha256; native_windows_executed=$true; production_readiness=$false;
            user_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
            session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId;
            windows_version=[Environment]::OSVersion.Version.ToString();
            checks=$Checks; process_trees=@($Trees | ForEach-Object { $_.Identity }); error=$Failure; fixture=$Root }
        $json = $report | ConvertTo-Json -Depth 10
        [IO.File]::WriteAllText((Join-Path $Root 'service-validation.json'), $json, [Text.UTF8Encoding]::new($false))
        if ($ResultFile) { [IO.File]::WriteAllText($ResultFile, $json, [Text.UTF8Encoding]::new($false)) }
        Write-Host ('Retained fixture and report: ' + $Root)
    }
}
if ($Failure) { throw $Failure }
