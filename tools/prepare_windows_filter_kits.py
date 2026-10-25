#!/usr/bin/env python3
"""Fetch hash-pinned Microsoft kit files for an unsigned Windows filter build.

Extracts into the requested directory only; installs no host packages, services,
certificates or drivers. A C compiler and PE linker must be supplied separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import urllib.request
import zipfile

VERSION = '10.0.26100.6584'
KIT = '10.0.26100.0'
PACKAGES = {
    'microsoft.windows.wdk.x64': (
        110872506, 'c393d03dfb640b5c92f546b32f6770ef68cd3aaf691956e7d66d8e2c28a1b55e',
        [f'c/Include/{KIT}/km/', f'c/Lib/{KIT}/km/x64/']),
    'microsoft.windows.sdk.cpp': (
        160036542, '5d31b38205bdd9ac761b4cb39fbbc6b7209b01c11194324afc674d7d119483a0',
        [f'c/Include/{KIT}/shared/', f'c/Include/{KIT}/ucrt/']),
}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def package(cache, name, size, sha256):
    filename = f'{name}.{VERSION}.nupkg'
    path = cache / filename
    if not path.exists():
        url = f'https://api.nuget.org/v3-flatcontainer/{name}/{VERSION}/{filename}'
        fd, temporary = tempfile.mkstemp(prefix=f'.{name}-', dir=cache)
        try:
            with os.fdopen(fd, 'wb') as output, urllib.request.urlopen(url, timeout=30) as response:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > size:
                        raise ValueError(f'Package exceeds pinned size: {name}')
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            candidate = Path(temporary)
            if candidate.stat().st_size != size or digest(candidate) != sha256:
                raise ValueError(f'Package does not match pinned bytes: {name}')
            os.replace(candidate, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    if not path.is_file() or path.stat().st_size != size or digest(path) != sha256:
        raise ValueError(f'Cached package does not match pinned bytes: {path}')
    return path


def extract(archive, destination, prefixes):
    total, count = 0, 0
    with zipfile.ZipFile(archive) as package_file:
        seen = set()
        for info in package_file.infolist():
            if info.is_dir() or not any(info.filename.startswith(prefix) for prefix in prefixes):
                continue
            relative = PurePosixPath(info.filename)
            key = info.filename.casefold()
            if relative.is_absolute() or '..' in relative.parts or '\\' in info.filename or ':' in info.filename:
                raise ValueError('Invalid package path')
            if key in seen or ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError('Duplicate path or symbolic link in package')
            seen.add(key)
            count += 1
            total += info.file_size
            if count > 20000 or total > 512 * 1024 * 1024:
                raise ValueError('Kit extraction exceeds its budget')
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with package_file.open(info) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
    if not count:
        raise ValueError('Package contains none of the required kit files')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New directory for extracted headers and libraries')
    parser.add_argument('--package-cache', type=Path, required=True)
    args = parser.parse_args()
    cache = args.package_cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
    if output.exists():
        raise SystemExit('Output already exists; use a new build-owned directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.windows-kits-', dir=output.parent))
    try:
        for name, (size, sha256, prefixes) in PACKAGES.items():
            extract(package(cache, name, size, sha256), temporary / name, prefixes)
        manifest = {'schema': 1, 'package_version': VERSION, 'kit_version': KIT,
                    'packages': {name: {'bytes': data[0], 'sha256': data[1]} for name, data in PACKAGES.items()},
                    'files': {str(path.relative_to(temporary)).replace('\\', '/'): digest(path)
                              for path in sorted(temporary.rglob('*')) if path.is_file()}}
        (temporary / 'kits.json').write_text(json.dumps(manifest, indent=2) + '\n')
        temporary.rename(output)
        print(json.dumps({'wdk': str(output / 'microsoft.windows.wdk.x64/c'),
                          'sdk': str(output / 'microsoft.windows.sdk.cpp/c'),
                          'manifest': str(output / 'kits.json')}, indent=2))
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


if __name__ == '__main__':
    main()
