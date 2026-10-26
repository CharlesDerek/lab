#!/usr/bin/env python3
"""Publish a compiled endpoint artifact into the portal's private build catalog."""
import argparse
import hashlib
import json
import os
import plistlib
from pathlib import Path
import struct
import stat
import subprocess
import sys
import tempfile
import package_macos_network

TARGETS = ("linux-x86_64", "linux-aarch64", "windows-x86_64", "macos-x86_64", "macos-aarch64")
MAX_BYTES = 64 * 1024 * 1024


def private_catalog(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Catalog directory cannot be a symlink")
    parent = path.parent.resolve(strict=True)
    directory = parent / path.name
    if os.name == 'posix':
        for ancestor in [parent, *parent.parents]:
            metadata = ancestor.stat()
            if (metadata.st_uid not in (0, os.geteuid()) or
                    (metadata.st_mode & 0o022 and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX))):
                raise ValueError("Catalog parent is not protected against replacement")
    directory.mkdir(mode=0o700, exist_ok=True)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or (os.name == 'posix' and metadata.st_uid != os.geteuid()):
        raise ValueError("Catalog directory ownership differs")
    if os.name == 'posix':
        directory.chmod(0o700)
    return directory


def private_publish(path: Path, data: bytes, mode: int = 0o600) -> None:
    # mkstemp creates0600 atomically; replace replaces a symlink, never its target.
    descriptor, name = tempfile.mkstemp(prefix='.catalog-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            if os.name == 'posix':
                os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def read_binary(path: Path, target: str) -> bytes:
    with path.open('rb') as source:
        data = source.read(MAX_BYTES + 1)
    if not 64 <= len(data) <= MAX_BYTES:
        raise ValueError("Executable is outside the artifact size budget")
    validate_binary(data, target)
    return data


def verify_macos_signature(path: Path, endpoint_security: bool = False) -> None:
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)],
                   check=True, timeout=60)
    subprocess.run(["/usr/sbin/spctl", "--assess", "--type", "execute", str(path)],
                   check=True, timeout=120)
    if endpoint_security:
        result = subprocess.run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(path)],
                                check=True, capture_output=True, timeout=30)
        if len(result.stdout) > 65536:
            raise ValueError("Native adapter entitlements exceed their byte budget")
        entitlements = plistlib.loads(result.stdout)
        if (not isinstance(entitlements, dict)
                or entitlements.get('com.apple.developer.endpoint-security.client') is not True
                or entitlements.get('com.apple.security.get-task-allow', False) is not False):
            raise ValueError("Native adapter needs the Endpoint Security entitlement and no debug entitlement")


def validate_binary(data: bytes, target: str) -> None:
    if target.startswith("linux"):
        machine = 62 if target.endswith("x86_64") else 183
        valid = data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == machine
    elif target.startswith("windows"):
        offset = struct.unpack_from("<I", data, 60)[0] if data[:2] == b"MZ" else 0
        valid = data[offset:offset + 4] == b"PE\0\0" and struct.unpack_from("<H", data, offset + 4)[0] == 0x8664
    else:
        machine = 0x1000007 if target.endswith("x86_64") else 0x100000C
        valid = data[:4] == b"\xcf\xfa\xed\xfe" and struct.unpack_from("<I", data, 4)[0] == machine
    if not valid:
        raise ValueError("Executable format/architecture does not match the requested target")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--output", type=Path, default=Path(".athernex/endpoint-artifacts"))
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--require-native-signature", action="store_true")
    parser.add_argument("--native-adapter", type=Path,
                        help="Include a signed and entitled macOS authorization adapter")
    parser.add_argument("--macos-network-app", type=Path, help="Approved signed network app bundle; never activates it")
    parser.add_argument("--macos-network-identity", type=Path, help="Private approved structured signing-role identities")
    args = parser.parse_args()
    if (args.macos_network_app is None) != (args.macos_network_identity is None):
        raise ValueError("Network app and private identity must be supplied together")
    if args.macos_network_app is not None and not (args.target.startswith('macos-')
            and sys.platform == 'darwin' and args.require_native_signature):
        raise ValueError("Network bundle packaging requires macOS and --require-native-signature")
    network_data = network_artifact = None
    data = read_binary(args.binary, args.target)
    native_data = None
    if args.native_adapter is not None:
        if not (args.target.startswith('macos-') and sys.platform == 'darwin'
                and args.require_native_signature):
            raise ValueError("Native adapter packaging requires macOS and --require-native-signature")
        native_data = read_binary(args.native_adapter, args.target)
        if len(data) + len(native_data) > MAX_BYTES:
            raise ValueError("Combined endpoint executables exceed the artifact size budget")
    signing = "development-unsigned"
    # Native tools inspect private snapshots; publish those same bytes even if
    # an independent build replaces the original input while inspection runs.
    with tempfile.TemporaryDirectory(prefix='athernex-package-check-') as directory:
        snapshot = Path(directory) / ('endpoint.exe' if args.target.startswith('windows') else 'endpoint')
        snapshot.write_bytes(data)
        snapshot.chmod(0o700)
        if args.require_native_signature:
            if args.target.startswith("macos") and sys.platform == "darwin":
                verify_macos_signature(snapshot)
                if native_data is not None:
                    native_snapshot = Path(directory) / 'native-adapter'
                    native_snapshot.write_bytes(native_data)
                    native_snapshot.chmod(0o700)
                    verify_macos_signature(native_snapshot, endpoint_security=True)
                    digest = hashlib.sha256(native_data).hexdigest()
                    manifest = Path(directory) / 'release.json'
                    manifest.write_text(json.dumps(dict(target=args.target, version=args.version,
                        sha256=hashlib.sha256(data).hexdigest(), signing='native-signature-verified',
                        native_adapter=dict(backend='macos-endpoint-security', sha256=digest,
                                            signing='native-signature-verified'))))
                    readiness = subprocess.run([str(snapshot), 'installer-native-hash', str(manifest)],
                                               check=True, capture_output=True, timeout=30)
                    if readiness.stdout.strip() != digest.encode('ascii'):
                        raise ValueError("Management binary does not support this native adapter catalog")
            elif args.target.startswith("windows") and os.name == "nt":
                env = dict(os.environ, ATHERNEX_VERIFY_BINARY=str(snapshot.resolve()))
                subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                "if ((Get-AuthenticodeSignature -LiteralPath $env:ATHERNEX_VERIFY_BINARY).Status -ne 'Valid') { exit 1 }"], env=env, check=True, timeout=60)
            else:
                raise ValueError("Native signature verification requires a matching macOS or Windows runner")
            signing = "native-signature-verified"
        if args.macos_network_app is not None:
            network_data, network_artifact = package_macos_network.package(
                args.macos_network_app, args.macos_network_identity, Path(directory),
                snapshot, args.target, validate_binary)
            if len(data) + len(native_data or b'') + len(network_data) > MAX_BYTES:
                raise ValueError("Combined endpoint and network artifacts exceed budget")
            release = Path(directory) / 'network-release.json'
            release.write_text(json.dumps(dict(target=args.target, version=args.version,
                sha256=hashlib.sha256(data).hexdigest(), signing=signing, macos_network=network_artifact)))
            result = subprocess.run([str(snapshot), 'installer-network-hash', str(release)],
                                    check=True, capture_output=True, timeout=30)
            if result.stdout.strip() != network_artifact['sha256'].encode('ascii'):
                raise ValueError("Management binary does not support the required network component")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output = private_catalog(args.output)
    filename = f"athernex-endpoint-{args.target}" + (".exe" if args.target.startswith("windows") else "")
    private_publish(args.output / filename, data, 0o700)
    manifest = {"target": args.target, "version": args.version, "sha256": hashlib.sha256(data).hexdigest(), "signing": signing}
    if native_data is not None:
        native_name = f'athernex-endpoint-native-{args.target}'
        private_publish(args.output / native_name, native_data, 0o700)
        manifest['native_adapter'] = dict(backend='macos-endpoint-security',
                                         sha256=hashlib.sha256(native_data).hexdigest(),
                                         signing='native-signature-verified')
    if network_data is not None:
        network_path = args.output / f'athernex-macos-network-{args.target}.zip'
        private_publish(network_path, network_data)
        manifest['macos_network'] = network_artifact
    private_publish(args.output / f"{args.target}.json", (json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
    print(f"Provisioned {args.target}: {signing}, {len(data)} bytes")


if __name__ == "__main__":
    main()
