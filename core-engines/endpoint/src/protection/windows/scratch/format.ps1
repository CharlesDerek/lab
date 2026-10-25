# Input is generated from a live, newly created VHDX guard. No disk-number or
# drive-letter mutation is used; the caller retains the image/device handles.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
Set-StrictMode -Version Latest
try {
    [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false, $true)
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false, $true)
    foreach ($module in @('Microsoft.PowerShell.Utility', 'CimCmdlets', 'Storage')) {
        $manifest = [IO.Path]::Combine($PSHOME, 'Modules', $module, ($module + '.psd1'))
        Import-Module -Name $manifest -ErrorAction Stop
    }
    function Assert-Fields($value, [string[]]$names) {
        if ($null -eq $value -or @($value.PSObject.Properties).Count -ne $names.Count) {
            throw 'Invalid scratch formatter fields'
        }
        foreach ($name in $names) {
            if ($null -eq $value.PSObject.Properties[$name]) { throw 'Missing scratch formatter field' }
        }
    }
    $buffer = [char[]]::new(16385)
    $length = [Console]::In.ReadBlock($buffer, 0, $buffer.Length)
    if ($length -gt 16384) { throw 'Scratch format request exceeds its budget' }
    $request = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([string]::new($buffer, 0, $length))
    Assert-Fields $request @('schema', 'nonce', 'target')
    $target = $request.target
    Assert-Fields $target @('schema', 'volume', 'partition_id', 'disk_number', 'offset', 'bytes')
    if ($request.schema -ne 1 -or $target.schema -ne 1 -or
        $request.nonce -cnotmatch '\A[0-9a-f]{64}\z' -or
        $target.volume -cnotmatch '\A\\\\\?\\Volume\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}\\\z' -or
        $target.partition_id -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z' -or
        $target.disk_number -lt 0 -or $target.disk_number -gt [uint32]::MaxValue -or
        $target.offset -lt 1MB -or $target.bytes -lt 64MB -or
        $target.offset + $target.bytes -gt 4GB) { throw 'Invalid scratch format target' }

    function Get-CheckedScratchVolume {
        $volumes = @(Storage\Get-Volume -Path $target.volume -ErrorAction Stop)
        if ($volumes.Count -ne 1 -or
            -not [string]::Equals($volumes[0].Path, $target.volume, [StringComparison]::OrdinalIgnoreCase) -or
            [int]$volumes[0].DriveLetter -ne 0) { throw 'Scratch volume GUID changed or acquired a drive letter' }
        $partitions = @(Storage\Get-Partition -Volume $volumes[0] -ErrorAction Stop)
        if ($partitions.Count -ne 1) { throw 'Scratch volume is not a single partition' }
        $partition = $partitions[0]
        if ([guid]$partition.Guid -ne [guid]$target.partition_id -or
            [guid]$partition.GptType -ne [guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' -or
            $partition.DiskNumber -ne $target.disk_number -or $partition.PartitionNumber -ne 2 -or
            $partition.Offset -ne $target.offset -or $partition.Size -ne $target.bytes -or
            [int]$partition.DriveLetter -ne 0 -or -not $partition.NoDefaultDriveLetter -or
            $partition.IsBoot -or $partition.IsSystem -or $partition.IsReadOnly -or $partition.IsOffline) {
            throw 'Scratch partition identity, extent or state changed'
        }
        return $volumes[0]
    }
    $volume = Get-CheckedScratchVolume
    if (-not [string]::IsNullOrEmpty($volume.FileSystem) -and $volume.FileSystem -ne 'RAW') {
        throw 'Scratch formatter refuses an existing filesystem'
    }
    $null = Storage\Format-Volume -InputObject $volume -FileSystem NTFS -AllocationUnitSize 4096 `
        -NewFileSystemLabel 'AthernexScratch' -ShortFileNameSupport $false -Force -Confirm:$false -ErrorAction Stop
    $volume = Get-CheckedScratchVolume
    if ($volume.FileSystem -ne 'NTFS' -or $volume.Size -gt $target.bytes -or $volume.Size -lt 64MB) {
        throw 'Scratch filesystem format result differs from the requested volume'
    }
    $reply = @{ schema = 1; nonce = $request.nonce; volume = $target.volume }
    [Console]::Write((Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $reply -Compress))
    exit 0
} catch {
    [Console]::Error.WriteLine('Scratch formatting failed: ' + $_.Exception.Message)
    exit 1
}
