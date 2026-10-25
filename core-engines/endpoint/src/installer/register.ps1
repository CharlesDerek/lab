$ErrorActionPreference = 'Stop'
$ServiceName = 'AthernexEndpoint'
$BinaryPath = '"' + $env:ATHERNEX_INSTALL_LAUNCHER + '" windows-service "' + $env:ATHERNEX_INSTALL_STATE + '" "' + $env:ATHERNEX_INSTALL_CONTROLLER + '" "' + $env:ATHERNEX_INSTALL_AGENT + '"'
$Existing = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'AthernexEndpoint'"
if ($Existing) {
    if ($Existing.PathName -ne $BinaryPath -or $Existing.StartName -ne 'LocalSystem' -or
        $Existing.ServiceType -ne 'Own Process' -or $Existing.State -ne 'Stopped') {
        throw 'Existing AthernexEndpoint service has different ownership/configuration or is still running'
    }
    Set-Service -Name $ServiceName -StartupType Automatic
} else {
    New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName 'Athernex Endpoint' -StartupType Automatic | Out-Null
}
$Sc = Join-Path $env:SystemRoot 'System32\sc.exe'
& $Sc description $ServiceName 'Owns the Athernex launcher and its endpoint process tree. Service status does not establish antivirus readiness.' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service description configuration failed' }
& $Sc failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service restart configuration failed' }
& $Sc failureflag $ServiceName 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service failure reporting configuration failed' }
# Ordinary users may query/interrogate, but cannot start, stop or reconfigure.
# Administrators remain administrators: this is not PPL/ELAM tamper resistance.
& $Sc sdset $ServiceName 'O:BAG:BAD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)(A;;0x2008D;;;AU)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service access policy configuration failed' }
$Legacy = Get-ScheduledTask -TaskName 'Athernex Endpoint' -ErrorAction SilentlyContinue
if ($Legacy) {
    $ExpectedArguments = 'launch "' + $env:ATHERNEX_INSTALL_STATE + '" "' + $env:ATHERNEX_INSTALL_CONTROLLER + '" "' + $env:ATHERNEX_INSTALL_AGENT + '"'
    if (@($Legacy.Actions).Count -ne 1 -or $Legacy.Actions[0].Execute -ne $env:ATHERNEX_INSTALL_LAUNCHER -or
        $Legacy.Actions[0].Arguments -ne $ExpectedArguments -or $Legacy.State -eq 'Running') {
        throw 'Legacy endpoint task identity or stopped state changed during migration'
    }
    Unregister-ScheduledTask -TaskName 'Athernex Endpoint' -Confirm:$false
}
# The guarded installer commits its complete journal before the outer script
# starts the service. Never start it while the installation/host leases are held.
