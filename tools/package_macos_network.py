"""Bounded private snapshots of an approved signed macOS network app bundle."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import zipfile

LIMIT = 64 * 1024 * 1024
APP = 'AthernexNetwork.app'
POLICY = 'faf8a5d37afe9cdc39b09b3562832b0db72b9c0b03281dd1ce701fc889f1dc64'
IDENTITY_FIELDS = {'team_id', 'agent_identifier', 'container_identifier',
                   'provider_identifier', 'app_group', 'mach_service_name'}


def identity(path):
    with path.open('rb') as source:
        raw = source.read(4097)
    if len(raw) > 4096:
        raise ValueError('Network identity exceeds budget')
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != IDENTITY_FIELDS:
        raise ValueError('Network identity fields differ')
    for key, text in value.items():
        if not isinstance(text, str) or not text.isascii():
            raise ValueError('Invalid network identity')
        if key == 'team_id':
            valid = len(text) == 10 and all(c.isupper() or c.isdigit() for c in text)
        else:
            valid = (len(text) <= 255 and '.' in text and all(
                1 <= len(part) <= 63 and all(c.isalnum() or c == '-' for c in part)
                for part in text.split('.')))
        if not valid:
            raise ValueError('Invalid network identity')
    if (not value['mach_service_name'].startswith(value['app_group'] + '.')
            or len({value[k] for k in ['agent_identifier', 'container_identifier', 'provider_identifier']}) != 3):
        raise ValueError('Network role identities differ')
    return value


def paths(value):
    provider = APP + '/Contents/Library/SystemExtensions/' + value['provider_identifier'] + '.systemextension'
    files = {base + '/' + suffix for base in [APP, provider] for suffix in [
        'Contents/Info.plist', 'Contents/PkgInfo', 'Contents/_CodeSignature/CodeResources',
        'Contents/embedded.provisionprofile']}
    files.update([APP + '/Contents/MacOS/AthernexNetwork', provider + '/Contents/MacOS/AthernexNetworkProvider'])
    directories = {str(p) for name in files for p in Path(name).parents if str(p) != '.'}
    return files, directories, provider


def snapshot(source, destination, expected, validate_binary, target):
    allowed, directories, provider = paths(expected)
    tree = {}
    total = 0

    def visit(path, relative):
        nonlocal total
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            if relative not in directories:
                raise ValueError('Unapproved network bundle directory')
            for i, child in enumerate(path.iterdir()):
                if i >= 512:
                    raise ValueError('Network bundle entry budget exceeded')
                visit(child, relative + '/' + child.name)
            return
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or relative not in allowed
                or mode not in (0o644, 0o755) or info.st_size > LIMIT):
            raise ValueError('Unapproved network bundle file')
        with path.open('rb') as stream:
            data = stream.read(LIMIT - total + 1)
        total += len(data)
        if total > LIMIT or len(tree) >= 512:
            raise ValueError('Network bundle byte budget exceeded')
        tree[relative] = (mode, data)

    visit(source, APP)
    container = APP + '/Contents/MacOS/AthernexNetwork'
    executable = provider + '/Contents/MacOS/AthernexNetworkProvider'
    for name in [container, executable]:
        if name not in tree or tree[name][0] != 0o755:
            raise ValueError('Network executable missing or mode differs')
        validate_binary(tree[name][1], target)
    for prefix in [APP, provider]:
        if prefix + '/Contents/Info.plist' not in tree:
            raise ValueError('Network Info.plist is missing')
    for relative, (mode, data) in sorted(tree.items()):
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    return tree, container, executable


def encode(tree):
    manifest = bytearray()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for path, (mode, data) in sorted(tree.items()):
            manifest.extend(f'{path}\0{mode:04o}\0{len(data)}\0{hashlib.sha256(data).hexdigest()}\n'.encode())
            entry = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(entry, data)
    data = output.getvalue()
    if len(data) > LIMIT:
        raise ValueError('Network archive byte budget exceeded')
    return data, hashlib.sha256(manifest).hexdigest()


def package(app, identity_file, directory, management, target, validate_binary):
    expected = identity(identity_file)
    tree, container, provider = snapshot(app, directory, expected, validate_binary, target)
    pin = directory / 'network-identity.json'
    pin.write_text(json.dumps(expected), encoding='utf-8')
    pin.chmod(0o600)
    result = subprocess.run([str(management), 'inspect-macos-network-bundle',
                             str(directory / APP), str(pin)], check=True,
                            capture_output=True, timeout=120)
    if len(result.stdout) > 4096:
        raise ValueError('Network inspection exceeds budget')
    inspected = json.loads(result.stdout)
    if (not isinstance(inspected, dict) or set(inspected) != {'identity', 'provider_cdhashes'}
            or inspected['identity'] != expected):
        raise ValueError('Signed network identity differs')
    hashes = inspected['provider_cdhashes']
    if (not isinstance(hashes, list) or not 1 <= len(hashes) <= 4
            or any(not isinstance(h, str) or len(h) != 40
                   or any(c not in '0123456789abcdef' for c in h) for h in hashes)
            or len(set(hashes)) != len(hashes)):
        raise ValueError('Invalid signed network code hashes')
    # The signed snapshot must still be the precise bytes we inspected/encode.
    again, _, _ = snapshot(directory / APP, directory / 'recheck', expected, validate_binary, target)
    if again != tree:
        raise ValueError('Network snapshot changed during signature inspection')
    data, digest = encode(tree)
    artifact = dict(schema=1, backend='macos-network-extension', signing='native-signature-verified',
                    sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), tree_sha256=digest,
                    container_sha256=hashlib.sha256(tree[container][1]).hexdigest(),
                    provider_sha256=hashlib.sha256(tree[provider][1]).hexdigest(),
                    source_policy_sha256=POLICY, provider_cdhashes=sorted(hashes), **expected)
    return data, artifact
