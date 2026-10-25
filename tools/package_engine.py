#!/usr/bin/env python3
"""Assemble and sign a ClamAV runtime tree from an already verified vendor prefix.

Only runtime executables, shared libraries and database certificates are copied.
File symlinks are materialized inside the bundle; links outside the prefix fail.
This does not install packages, download code, or contain the signing key.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess


def assemble(prefix: Path, output: Path, target: str) -> dict:
    prefix = prefix.resolve(strict=True)
    if output.resolve().is_relative_to(prefix):
        raise ValueError('Bundle output must be separate from its verified input prefix')
    output.mkdir(mode=0o700)
    content = output / 'content'
    content.mkdir(mode=0o755)
    windows = target.startswith('windows-')
    roles = dict(scanner='clamscan.exe' if windows else 'bin/clamscan',
                 updater='freshclam.exe' if windows else 'bin/freshclam',
                 daemon='clamd.exe' if windows else 'sbin/clamd',
                 monitor='sbin/clamonacc' if target.startswith('linux-') else None,
                 library_dirs=[])
    selected = {roles[name] for name in ['scanner', 'updater', 'daemon', 'monitor'] if roles[name]}
    entries = 0
    for directory in ['lib', 'lib64', 'bin'] if not windows else ['.']:
        source = prefix / directory
        if not source.is_dir():
            continue
        if source.is_symlink():
            raise ValueError('Engine library directories cannot be symlinks')
        libraries = []
        for path in source.rglob('*'):
            entries += 1
            if entries > 1024:
                raise ValueError('Engine prefix exceeds its directory-entry budget')
            if path.is_dir():
                if path.is_symlink():
                    raise ValueError('Engine library directories cannot be symlinks')
                continue
            name = path.name.lower()
            if name.endswith(('.dll', '.dylib', '.so')) or '.so.' in name:
                libraries.append(path.relative_to(prefix).as_posix())
        if libraries:
            selected.update(libraries)
            if not windows:
                roles['library_dirs'].append(directory)
    certificates = next((p for p in [prefix/'etc/certs', prefix/'certs'] if p.is_dir()), None)
    if certificates is None:
        raise ValueError('The ClamAV prefix must include its database-verification certificates')
    roles['certificates'] = certificates.relative_to(prefix).as_posix()
    for path in certificates.rglob('*'):
        entries += 1
        if entries > 1024:
            raise ValueError('Engine prefix exceeds its directory-entry budget')
        if path.is_dir() and path.is_symlink():
            raise ValueError('Engine certificate directories cannot be symlinks')
        if path.is_file():
            selected.add(path.relative_to(prefix).as_posix())
    if len(selected) > 128:
        raise ValueError('Engine bundle exceeds 128 files')
    total = 0
    executable = {roles[name] for name in ['scanner', 'updater', 'daemon', 'monitor'] if roles[name]}
    for relative in sorted(selected):
        for parent in (prefix / relative).parents:
            if parent == prefix:
                break
            if parent.is_symlink():
                raise ValueError('Engine runtime directories cannot be symlinks')
        source = (prefix / relative).resolve(strict=True)
        if not source.is_relative_to(prefix) or not source.is_file():
            raise ValueError('Engine file leaves the verified prefix or is not regular: ' + relative)
        size = source.stat().st_size
        total += size
        if not 0 < size <= 128 * 1024 * 1024 or total > 512 * 1024 * 1024:
            raise ValueError('Engine bundle exceeds its byte budget')
        destination = content / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(source, destination)
        destination.chmod(0o755 if relative in executable else 0o644)
    (output / 'roles.json').write_text(json.dumps(roles, indent=2) + '\n')
    return roles


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', required=True, choices=['linux-x86_64', 'linux-aarch64', 'windows-x86_64', 'macos-x86_64', 'macos-aarch64'])
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--channel', default='stable', choices=['stable', 'preview'])
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--expires-ms', type=int, required=True)
    args = parser.parse_args()
    assemble(args.prefix, args.output, args.target)
    subprocess.run([str(args.agent.resolve()), 'engine-sign', str(args.key.resolve()),
                    str((args.output/'content').resolve()), str((args.output/'roles.json').resolve()),
                    args.target, args.version, args.channel, str(args.sequence), str(args.expires_ms),
                    str((args.output/'manifest.json').resolve())], check=True)
    manifest = json.loads((args.output/'manifest.json').read_text())
    print(json.dumps(dict(target=args.target, version=args.version,
                         files=len(manifest['release']['files']),
                         bytes=sum(f['bytes'] for f in manifest['release']['files'])), indent=2))


if __name__ == '__main__':
    main()
