#!/usr/bin/env python3
"""Execute the real formatter with a mock Storage module; never format a disk.

These tests check PowerShell validation and request handling. They do not prove
native Windows storage behavior. Use --powershell for an isolated pwsh binary,
or Windows PowerShell 5.1 to check the production interpreter on Windows.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "core-engines/endpoint/src/protection/windows/scratch/format.ps1"
WRAPPER = r"""
param([string]$Formatter)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility
$mock = New-Module -Name Storage -ScriptBlock {
    $script:fixture = Microsoft.PowerShell.Utility\ConvertFrom-Json $env:ATHERNEX_FORMAT_FIXTURE
    $script:formatted = $false
    function Get-Volume {
        param($Path, $ErrorAction)
        for ($i=0; $i -lt $script:fixture.volumes; $i++) {
            [pscustomobject]@{
                Path=$script:fixture.volume; DriveLetter=$script:fixture.letter
                FileSystem=$(if ($script:formatted) { $script:fixture.after_fs } else { $script:fixture.before_fs })
                Size=$script:fixture.bytes
            }
        }
    }
    function Get-Partition {
        param($Volume, $ErrorAction)
        for ($i=0; $i -lt $script:fixture.partitions; $i++) {
            [pscustomobject]@{
                Guid=$script:fixture.partition_id; GptType='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
                DiskNumber=$script:fixture.disk_number; PartitionNumber=2
                Offset=$script:fixture.offset; Size=$script:fixture.bytes
                DriveLetter=$script:fixture.letter; NoDefaultDriveLetter=$script:fixture.no_letter
                IsBoot=$script:fixture.boot; IsSystem=$false; IsReadOnly=$false; IsOffline=$false
            }
        }
    }
    function Format-Volume {
        param($InputObject, $FileSystem, $AllocationUnitSize, $NewFileSystemLabel,
              $ShortFileNameSupport, [switch]$Force, [switch]$Confirm, $ErrorAction)
        if ($null -eq $InputObject -or $FileSystem -ne 'NTFS' -or $AllocationUnitSize -ne 4096) {
            throw 'Unexpected mock format invocation'
        }
        [IO.File]::WriteAllText($env:ATHERNEX_FORMAT_MARKER, $InputObject.Path)
        $script:formatted = $true
    }
    Export-ModuleMember -Function Get-Volume, Get-Partition, Format-Volume
}
Microsoft.PowerShell.Core\Import-Module $mock
if ((Microsoft.PowerShell.Core\Get-Command 'Storage\Format-Volume').Module.Guid -ne $mock.Guid) {
    throw 'Fixture did not bind the fake Storage module'
}
# Suppress OS Storage/CIM imports. The production script itself is unmodified;
# its module-qualified Storage calls can reach only the above fake module.
function Import-Module {
    param([string]$Name, [string]$ErrorAction)
    if ($Name.EndsWith('Storage.psd1') -or $Name.EndsWith('CimCmdlets.psd1')) { return }
    Microsoft.PowerShell.Core\Import-Module -Name $Name -ErrorAction Stop
}
& $Formatter
exit $LASTEXITCODE
"""
VOLUME = "\\\\?\\Volume{01234567-89ab-cdef-8123-456789abcdef}\\"
TARGET = dict(schema=1, volume=VOLUME, partition_id="01234567-89ab-8def-8123-456789abcdef",
              disk_number=8, offset=17 * 1024**2, bytes=238 * 1024**2)
FIXTURE = dict(volume=VOLUME, partition_id=TARGET["partition_id"], disk_number=8,
               offset=TARGET["offset"], bytes=TARGET["bytes"], volumes=1, partitions=1,
               letter=0, no_letter=True, boot=False, before_fs="", after_fs="NTFS")


class FormatterTests(unittest.TestCase):
    powershell = None

    def run_case(self, *, target=None, fixture=None, request=None, text=None):
        request = request if request is not None else dict(schema=1, nonce="a" * 64, target=target or copy.deepcopy(TARGET))
        with tempfile.TemporaryDirectory(prefix="athernex-scratch-format-test-") as folder:
            wrapper = Path(folder) / "wrapper.ps1"
            wrapper.write_text(WRAPPER, encoding="utf-8")
            marker = Path(folder) / "formatted"
            env = os.environ.copy()
            env.update(ATHERNEX_FORMAT_FIXTURE=json.dumps(fixture or FIXTURE), ATHERNEX_FORMAT_MARKER=str(marker),
                       POWERSHELL_TELEMETRY_OPTOUT="1", POWERSHELL_UPDATECHECK="Off")
            completed = subprocess.run([self.powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(wrapper), str(SCRIPT)],
                                       input=text if text is not None else json.dumps(request), text=True, capture_output=True,
                                       env=env, timeout=20, check=False)
            return completed, marker.read_text() if marker.exists() else None

    def test_correct_owned_volume_formats_and_acknowledges(self):
        result, formatted = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(formatted, VOLUME)
        self.assertEqual(json.loads(result.stdout), dict(schema=1, nonce="a" * 64, volume=VOLUME))

    def test_drive_device_descendant_and_malformed_targets_never_format(self):
        changes = [dict(volume=value) for value in ["C:\\", "\\\\.\\PhysicalDrive8", VOLUME + "scratch", VOLUME + "\0", "\\\\server\\share\\"]]
        changes += [dict(schema=2), dict(partition_id="01234567-89ab-4def-8123-456789abcdef"),
                    dict(offset=0), dict(bytes=5 * 1024**3), dict(disk_number=-1)]
        for change in changes:
            with self.subTest(change=change):
                result, formatted = self.run_case(target={**TARGET, **change})
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(formatted)

    def test_unexpected_volume_or_partition_never_formats(self):
        changes = [dict(volumes=0), dict(volumes=2), dict(partitions=2), dict(volume="C:\\"),
                   dict(partition_id="11234567-89ab-8def-8123-456789abcdef"), dict(disk_number=9),
                   dict(offset=18 * 1024**2), dict(bytes=239 * 1024**2), dict(letter=65),
                   dict(no_letter=False), dict(boot=True), dict(before_fs="NTFS")]
        for change in changes:
            with self.subTest(change=change):
                result, formatted = self.run_case(fixture={**FIXTURE, **change})
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(formatted)

    def test_wrong_format_result_is_not_acknowledged(self):
        result, formatted = self.run_case(fixture={**FIXTURE, "after_fs": "FAT32"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(formatted, VOLUME)
        self.assertEqual(result.stdout, "")

    def test_bad_request_fields_or_size_never_format(self):
        for request in [dict(schema=1, nonce="bad", target=TARGET), dict(schema=1, nonce="a" * 64, target=TARGET, unknown=True),
                        dict(schema=1, nonce="a" * 64, target={**TARGET, "unknown": True}), dict(schema=1, nonce="a" * 64)]:
            with self.subTest(request=request):
                result, formatted = self.run_case(request=request)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(formatted)
        result, formatted = self.run_case(text=" " * 16385)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(formatted)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--powershell", default=shutil.which("pwsh") or shutil.which("powershell.exe"))
    args, remaining = parser.parse_known_args()
    if not args.powershell:
        parser.error("--powershell is required when PowerShell is not on PATH")
    FormatterTests.powershell = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
