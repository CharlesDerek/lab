#!/usr/bin/env python3
"""Compile the development Windows minifilter against the actual WDK and SDK.

This creates an unsigned binary only. It does not install a driver, change boot
policy, assign a filter altitude, or attest to Windows runtime behavior.
"""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wdk', type=Path, required=True,
                        help='WDK NuGet c/ directory or Windows Kits/10')
    parser.add_argument('--sdk', type=Path, required=True,
                        help='SDK NuGet c/ directory or Windows Kits/10')
    parser.add_argument('--kit-version', default='10.0.26100.0')
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--linker', type=Path, required=True,
                        help='lld-link or rust-lld (flavor link is selected automatically)')
    parser.add_argument('--output', type=Path,
                        default=Path('.athernex/verification/windows-filter-build'))
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / 'infrastructure/endpoint/windows-filter'
    wdk, sdk = args.wdk.resolve(strict=True), args.sdk.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    compiler = args.clang.resolve(strict=True)
    linker = args.linker.resolve(strict=True)
    linker_flags = ['-flavor', 'link'] if linker.name.startswith('rust-lld') else []
    versions = {
        'compiler': subprocess.run([str(compiler), '--version'], check=True, capture_output=True, text=True).stdout.strip(),
        'linker': subprocess.run([str(linker), *linker_flags, '--version'], check=True, capture_output=True, text=True).stdout.strip(),
    }
    includes = [wdk / 'Include' / args.kit_version / 'km',
                wdk / 'Include' / args.kit_version / 'km/crt',
                sdk / 'Include' / args.kit_version / 'shared',
                sdk / 'Include' / args.kit_version / 'ucrt']
    for directory in includes:
        if not directory.is_dir():
            raise SystemExit(f'Missing actual kit headers: {directory}')
    # SDK header spelling assumes a Windows filesystem. A case-insensitive VFS
    # overlays only these exact kit files; do not rewrite Microsoft's headers.
    overlay = output / 'kit-vfs.json'
    overlay.write_text(json.dumps({'version': 0, 'case-sensitive': False, 'roots': [
        {'type': 'file', 'name': str(path), 'external-contents': str(path)}
        for directory in includes for path in directory.rglob('*') if path.is_file()
    ]}))
    command = [str(compiler), '--target=x86_64-pc-windows-msvc',
               '-fms-extensions', '-fms-compatibility', '-fms-compatibility-version=19.40',
               '-ffreestanding', '-fno-builtin', '-mno-red-zone', '-fstack-protector-strong',
               '-Xclang', '-cfguard', '-O2', '-D_AMD64_', '-D_WIN64', '-D_KERNEL_MODE',
               '-D_WIN32_WINNT=0x0A00', '-DNTDDI_VERSION=0x0A000008',
               '-ivfsoverlay', str(overlay), '-I', str(source), '-Wall', '-Wextra', '-Werror']
    for directory in includes:
        command.extend(['-isystem', str(directory)])
    objects = []
    for name in ['driver', 'scan', 'create', 'communication', 'policy']:
        obj = output / f'{name}.obj'
        subprocess.run([*command, '-c', str(source / f'{name}.c'), '-o', str(obj)], check=True)
        objects.append(str(obj))
    libraries = wdk / 'Lib' / args.kit_version / 'km/x64'
    available = {path.name.lower(): path for path in libraries.glob('*.lib')}
    imports = [available[name] for name in ['ntoskrnl.lib', 'fltmgr.lib', 'bufferoverflowfastfailk.lib']]
    driver = output / 'athernex-filter.sys'
    subprocess.run([str(linker), *linker_flags, '/driver', '/subsystem:native', '/entry:GsDriverEntry',
                    '/nodefaultlib', '/machine:x64', '/dynamicbase', '/nxcompat', '/guard:cf',
                    '/integritycheck', '/opt:ref', '/Brepro', f'/out:{driver}',
                    *objects, *map(str, imports)], check=True)
    report = {'schema': 1, 'status': 'development-unsigned', 'native_runtime_verified': False,
              'build_host': platform.system(), 'tool_versions': versions,
              'kit_headers': args.kit_version, 'driver_sha256': hashlib.sha256(driver.read_bytes()).hexdigest(),
              'driver_bytes': driver.stat().st_size,
              'source_sha256': {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted(source.glob('*')) if p.suffix in {'.h', '.c'}}}
    (output / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
