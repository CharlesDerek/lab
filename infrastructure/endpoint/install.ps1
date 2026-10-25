#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$AgentDir = Join-Path $env:ProgramFiles 'Athernex Endpoint'
$StateDir = Join-Path $env:ProgramData 'AthernexEndpoint'
$SourceBinary = Join-Path $PSScriptRoot 'athernex-endpoint.exe'
& $SourceBinary installer-check $StateDir $SourceBinary
if ($LASTEXITCODE -ne 0) { throw 'Existing update state requires recovery or a signed agent update before reinstalling' }
$Launcher = Join-Path $AgentDir 'athernex-launcher.exe'
$Controller = Join-Path $AgentDir 'athernex-controller.exe'
$Agent = Join-Path $AgentDir 'athernex-endpoint.exe'
$BinaryPath = '"' + $Launcher + '" windows-service "' + $StateDir + '" "' + $Controller + '" "' + $Agent + '"'
$Sc = Join-Path $env:SystemRoot 'System32\sc.exe'
$ExistingService = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'AthernexEndpoint'"
if ($ExistingService) {
    if ($ExistingService.PathName -ne $BinaryPath -or $ExistingService.StartName -ne 'LocalSystem' -or $ExistingService.ServiceType -ne 'Own Process') {
        throw 'Existing AthernexEndpoint service belongs to another configuration; refusing to stop it'
    }
    $Service = Get-Service -Name 'AthernexEndpoint'
    if ($Service.Status -ne 'Stopped') {
        # sc submits the control without Stop-Service's unbounded terminal wait
        # or ServiceController.Stop's recursive stop of dependent services.
        & $Sc stop 'AthernexEndpoint' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Endpoint service refused its stop request' }
        $StopDeadline = (Get-Date).AddSeconds(20)
        while ((Get-Service -Name 'AthernexEndpoint').Status -ne 'Stopped') {
            if ((Get-Date) -ge $StopDeadline) { throw 'Existing endpoint service did not stop' }
            Start-Sleep -Milliseconds 250
        }
    }
}
$ExistingTask = Get-ScheduledTask -TaskName 'Athernex Endpoint' -ErrorAction SilentlyContinue
if ($ExistingTask) {
    $ExpectedArguments = 'launch "' + $StateDir + '" "' + $Controller + '" "' + $Agent + '"'
    if (@($ExistingTask.Actions).Count -ne 1 -or $ExistingTask.Actions[0].Execute -ne $Launcher -or $ExistingTask.Actions[0].Arguments -ne $ExpectedArguments) {
        throw 'Legacy endpoint task belongs to another configuration; refusing to stop it'
    }
    Disable-ScheduledTask -TaskName 'Athernex Endpoint' | Out-Null
    Stop-ScheduledTask -TaskName 'Athernex Endpoint'
    $StopDeadline = (Get-Date).AddSeconds(20)
    while ((Get-ScheduledTask -TaskName 'Athernex Endpoint').State -eq 'Running') {
        if ((Get-Date) -ge $StopDeadline) { throw 'Existing endpoint task did not stop' }
        Start-Sleep -Milliseconds 250
    }
}
& $SourceBinary windows-install $PSScriptRoot $AgentDir $StateDir
if ($LASTEXITCODE -ne 0) { throw 'Installation incomplete; bootstrap retained. Resolve the reported error and rerun this bundle.' }
& $Sc start 'AthernexEndpoint' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Endpoint service refused its start request' }
$StartDeadline = (Get-Date).AddSeconds(20)
while ((Get-Service -Name 'AthernexEndpoint').Status -ne 'Running') {
    if ((Get-Date) -ge $StartDeadline) { throw 'Endpoint service did not reach Running; inspect its SCM error and private supervisor status' }
    Start-Sleep -Milliseconds 250
}
Remove-Item '.\bootstrap.json'
Write-Host 'Installed. Configure ClamAV paths and approved folders in the private config.json. Existing antivirus is preserved.'
