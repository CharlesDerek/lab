#!/usr/bin/env python3
"""Verify and extract the pinned official ClamAV DEB for native Linux tests."""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import subprocess
import urllib.request


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    arch={'x86_64':'x86_64','aarch64':'aarch64'}[platform.machine().lower()]
    manifest=Path(__file__).resolve().parent.parent/'infrastructure/endpoint/antivirus-packages.json'
    package=next(p for p in json.loads(manifest.read_text()) if p['platform']=='linux' and p['arch']==arch and p['format']=='deb')
    args.output.mkdir(mode=0o700,parents=True,exist_ok=True)
    archive=args.output/'clamav.deb'
    if not archive.exists():
        temporary=args.output/'clamav.deb.pending'
        size=0
        with urllib.request.urlopen(package['url'],timeout=60) as response,temporary.open('wb') as output:
            while chunk:=response.read(1024*1024):
                size+=len(chunk)
                if size>package['bytes']:
                    raise ValueError('Download exceeds pinned package size')
                output.write(chunk)
        temporary.replace(archive)
    if archive.stat().st_size!=package['bytes']:
        raise ValueError('Pinned package size mismatch')
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=package['sha256']:
            raise ValueError('Pinned package digest mismatch')
    subprocess.run(['dpkg-deb','-x',str(archive),str(args.output/'engine')],check=True)
    print(f"Verified ClamAV {package['version']} for {arch}; prefix: {args.output/'engine/usr/local'}")


if __name__=='__main__':
    main()
