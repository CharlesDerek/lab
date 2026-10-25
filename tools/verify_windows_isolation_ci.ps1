<#
Run the existing opt-in isolation checks as LocalSystem on a disposable hosted VM.
No driver is loaded and no disk is attached or formatted. WFP rules are scoped to
a fresh fixture image. A failed check retains its private recovery journals.
Dot-sourcing defines helpers only.
#>
param([string]$EndpointTests, [string]$NativeTests, [string]$OutputDirectory,
      [switch]$DisposableHost, [switch]$Worker)

function Get-IsolationChecks {
    @(
        @{ binary='endpoint.exe'; test='windows_job::tests::scanner_launch_has_checked_identity_job_limits_and_owned_cleanup' },
        @{ binary='native.exe'; test='windows_scanner::tests::scanner_reads_copies_writes_scratch_and_cannot_read_private_state_or_change_engine' },
        @{ binary='native.exe'; test='windows_state::cleanup::tests::cleanup_preserves_external_links_streams_attributes_and_retries_pinned_entries' },
        @{ binary='native.exe'; test='windows_state::cleanup::tests::cleanup_refuses_root_redirection_and_reclaims_only_empty_unrecorded_orphans' },
        @{ binary='endpoint.exe'; test='protection::windows::scratch::tests::recovery_preserves_live_corrupt_changed_and_pinned_images_and_replays_deletion' },
        @{ binary='endpoint.exe'; test='windows_job::tests::scanner_network_rules_survive_owner_exit_and_allow_only_configured_loopback_service' }
    )
}

function Assert-IsolationReport($Report, [string]$ManifestSha256) {
    if ($Report.schema -ne 1 -or $Report.native_windows_executed -cne $true -or
        $Report.production_readiness -cne $false -or $Report.manifest_sha256 -cne $ManifestSha256 -or
        $Report.user_sid -cne 'S-1-5-18' -or $Report.session_id -cne 0 -or $Report.error -or
        -not $Report.windows_version) { throw 'Native isolation report identity or result is invalid' }
    $expected = @(Get-IsolationChecks | ForEach-Object { $_.test })
    $names = @($Report.checks.PSObject.Properties.Name)
    if ($names.Count -ne $expected.Count) { throw 'Native isolation report has an incomplete check set' }
    foreach ($name in $expected) {
        if ($names -cnotcontains $name -or $Report.checks.$name -cne 'passed') { throw ('Native isolation check did not pass: ' + $name) }
    }
}

function Invoke-IsolationExecutable([string]$Executable, [string[]]$Arguments, [string]$Log) {
    # Windows PowerShell represents native stderr as ErrorRecord objects. Keep
    # diagnostics in the private log and judge the actual executable exit code.
    $ErrorActionPreference = 'Continue'
    & $Executable @Arguments > $Log 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw ('Isolation executable failed with exit code ' + $code) }
}

function Invoke-IsolationCheck([string]$Executable, [string]$Name, [string]$Log) {
    Invoke-IsolationExecutable $Executable @('--list','--ignored','--format','terse') ($Log + '.list')
    $listing = Get-Content -LiteralPath ($Log + '.list') -Raw
    if ($listing -cnotmatch ('(?m)^' + [regex]::Escape($Name) + ': test\r?$')) {
        throw ('Requested ignored test is absent: ' + $Name)
    }
    Invoke-IsolationExecutable $Executable @('--exact',$Name,'--ignored','--test-threads=1','--nocapture') $Log
    $output = Get-Content -LiteralPath $Log -Raw
    if ($output -cnotmatch '(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;') {
        throw ('Native test did not report exactly one executed success: ' + $Name)
    }
}

function Invoke-IsolationWorker([string]$OutputDirectory) {
    $ErrorActionPreference = 'Stop'
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'Isolation worker requires native LocalSystem in session zero'
    }
    $manifestPath = Join-Path $OutputDirectory 'inputs.json'
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $report = @{ schema=1; native_windows_executed=$true; production_readiness=$false;
        manifest_sha256=$manifestHash; user_sid='S-1-5-18'; session_id=0;
        windows_version=[Environment]::OSVersion.Version.ToString(); checks=[ordered]@{}; error=$null }
    try {
        if ($manifest.schema -ne 1) { throw 'Invalid isolation input manifest' }
        $position = 0
        foreach ($check in Get-IsolationChecks) {
            $executable = Join-Path $OutputDirectory $check.binary
            if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.sha256.($check.binary)) {
                throw 'Staged isolation executable hash changed'
            }
            $log = Join-Path $OutputDirectory ('check-' + $position + '.log')
            Invoke-IsolationCheck $executable $check.test $log
            $report.checks[$check.test] = 'passed'
            $position += 1
        }
    } catch {
        $report.error = $_.Exception.Message
        throw
    } finally {
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'isolation-validation.json') -Encoding UTF8
    }
}

function Invoke-IsolationCi([string]$EndpointTests, [string]$NativeTests, [string]$OutputDirectory, [bool]$DisposableHost) {
    $ErrorActionPreference = 'Stop'
    if (-not $DisposableHost -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
        [Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Requires an explicitly disposable GitHub-hosted Windows runner' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Requires an elevated runner'
    }
    $sources = @{ 'endpoint.exe'=(Resolve-Path -LiteralPath $EndpointTests).Path;
                  'native.exe'=(Resolve-Path -LiteralPath $NativeTests).Path }
    if (-not $OutputDirectory) { throw 'OutputDirectory is required' }
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
    $manifest = @{ schema=1; github_sha=$env:GITHUB_SHA; sha256=@{} }
    foreach ($name in $sources.Keys) {
        $digest = (Get-FileHash -LiteralPath $sources[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $sources[$name] -Destination (Join-Path $OutputDirectory $name)
        if ((Get-FileHash -LiteralPath (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
            throw 'Staged executable differs from compiled isolation tests'
        }
        $manifest.sha256[$name] = $digest
    }
    $manifestPath = Join-Path $OutputDirectory 'inputs.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixture = Join-Path $OutputDirectory 'verify_windows_isolation_ci.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $fixture
    $parameters = @{ Fixture=$fixture; OutputDirectory=$OutputDirectory } | ConvertTo-Json -Compress
    $literal = $parameters.Replace("'", "''")
    $code = @'
$ErrorActionPreference = 'Stop'
$p = ConvertFrom-Json '__PARAMETERS__'
try { & $p.Fixture -OutputDirectory $p.OutputDirectory -Worker; exit 0 }
catch { $_ | Out-File -LiteralPath (Join-Path $p.OutputDirectory 'worker.log') -Append; exit 1 }
'@.Replace('__PARAMETERS__', $literal)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encoded)
    $taskName = 'AthernexIsolationValidation-' + [Guid]::NewGuid().ToString('N')
    # Import into a child scope so the service script's parameters cannot replace
    # this runner's paths or switches when it is dot-sourced.
    & {
        param($IsolationTask, $IsolationAction, $IsolationResult, $IsolationDigest, $Helper)
        . $Helper
        Invoke-ServiceFixtureTask $IsolationTask $IsolationAction $IsolationResult $IsolationDigest 540 {
            param($Report, $ManifestSha256)
            Assert-IsolationReport $Report $ManifestSha256
        }
    } $taskName $action (Join-Path $OutputDirectory 'isolation-validation.json') $digest (Join-Path $PSScriptRoot 'verify_windows_service_ci.ps1')
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Worker) { Invoke-IsolationWorker $OutputDirectory }
    else { Invoke-IsolationCi $EndpointTests $NativeTests $OutputDirectory $DisposableHost.IsPresent }
}
