#!/usr/bin/env python3
"""Pull and verify SIEM audit records into an independently controlled archive.

Run this on the audit host with a named viewer credential. Immutable pages and
fsync precede acknowledgment. Keep the resulting checkpoint outside SIEM's
administrative boundary; this program cannot make two directories independent.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import urllib.parse
import urllib.request

ZERO = dict(sequence=0, sha256='0'*64)
MAX_PAGE = 8 * 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
MIN_FREE = 1024 * 1024 * 1024


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def verify(records, start):
    head = start.copy()
    if not isinstance(records, list) or len(records) > 1000:
        raise ValueError('Invalid audit page size')
    for row in records:
        if set(row) != {'sequence', 'time_ms', 'action', 'detail', 'previous', 'sha256'}:
            raise ValueError('Unknown audit record schema')
        if (type(row['sequence']) is not int or type(row['time_ms']) is not int
                or not 0 <= row['time_ms'] < 2**63
                or row['sequence'] != head['sequence'] + 1
                or row['previous'] != head['sha256']):
            raise ValueError('Audit sequence or prefix differs from the retained checkpoint')
        if not isinstance(row['action'], str) or not isinstance(row['detail'], str):
            raise ValueError('Invalid audit text')
        checksum = hashlib.sha256(canonical([row['sequence'], row['time_ms'], row['action'], row['detail'], row['previous']])).hexdigest()
        if row['sha256'] != checksum:
            raise ValueError('Audit record integrity failed')
        head = dict(sequence=row['sequence'], sha256=checksum)
    return head


def read_page(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_PAGE:
        raise ValueError('Archive member is not a bounded regular file')
    with path.open('rb') as source:
        raw = source.read(MAX_PAGE + 1)
    if len(raw) > MAX_PAGE:
        raise ValueError('Archive member exceeds its budget')
    return json.loads(raw)


def checkpoint(archive):
    head = ZERO.copy()
    paths = sorted(archive.glob('*.json'))
    if len(paths) > 100000:
        raise ValueError('Archive page capacity reached')
    for path in paths:
        page = read_page(path)
        if page['start'] != head:
            raise ValueError('Archive pages are missing or forked')
        end = verify(page['records'], head)
        if end == head or page['end'] != end or path.name != f"{end['sequence']:012d}-{end['sha256']}.json":
            raise ValueError('Archive checkpoint or filename mismatch')
        head = end
    return head


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError('Audit endpoint redirected; credentials were not forwarded')


def fetch(origin, credential, after):
    parsed = urllib.parse.urlsplit(origin)
    if (parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1', '::1'})) or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'', '/'}:
        raise ValueError('Use an HTTPS server origin, or loopback HTTP for a local fixture')
    url = origin.rstrip('/') + '/api/control/audit?' + urllib.parse.urlencode(dict(after=after))
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + credential, 'Accept': 'application/json'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        raw = response.read(MAX_PAGE + 1)
    if len(raw) > MAX_PAGE:
        raise ValueError('Remote audit page exceeds its budget')
    return json.loads(raw)


def append(archive, start, records, end):
    payload = canonical(dict(start=start, records=records, end=end))
    if len(payload) > MAX_PAGE:
        raise ValueError('Archive page exceeds its budget')
    used = sum(path.stat().st_size for path in archive.glob('*.json'))
    if used + len(payload) > MAX_ARCHIVE:
        raise ValueError('Audit archive reached its 128 MiB capacity; export and rotate it')
    if shutil.disk_usage(archive).free < MIN_FREE + len(payload):
        raise ValueError('Audit replication requires 1 GiB free after this page; source remains unacknowledged')
    destination = archive / f"{end['sequence']:012d}-{end['sha256']}.json"
    descriptor, name = tempfile.mkstemp(prefix='.pending-', dir=archive)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(payload); output.flush(); os.fsync(output.fileno())
        # Never overwrite an existing checkpoint, including on concurrent runs.
        os.link(name, destination)
        directory = os.open(archive, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(name)


def replicate(origin, credential, archive):
    archive.mkdir(mode=0o700, parents=True, exist_ok=True)
    if archive.is_symlink():
        raise ValueError('Audit archive must not be a symlink')
    head = checkpoint(archive)
    # Fetch the retained terminal record as well: detect truncation or a fork
    # even when the source has no new records after our checkpoint.
    probe = fetch(origin, credential, max(0, head['sequence'] - 1))
    if head['sequence']:
        if not probe['records'] or probe['records'][0]['sequence'] != head['sequence'] or probe['records'][0]['sha256'] != head['sha256']:
            raise ValueError('Source no longer contains the independently retained checkpoint')
        row = probe['records'][0]
        if verify([row], dict(sequence=head['sequence']-1, sha256=row['previous'])) != head:
            raise ValueError('Source terminal record differs from its checkpoint')
    target = probe['checkpoint']
    if type(target['sequence']) is not int or not 0 <= target['sequence'] <= 100000:
        raise ValueError('Source checkpoint exceeds its record budget')
    if target['sequence'] < head['sequence']:
        raise ValueError('Source audit history was truncated')
    while head['sequence'] < target['sequence']:
        page = fetch(origin, credential, head['sequence'])
        records = [r for r in page['records'] if r['sequence'] <= target['sequence']]
        end = verify(records, head)
        if end == head:
            raise ValueError('Source stopped before its advertised checkpoint')
        if end['sequence'] == target['sequence'] and end != target:
            raise ValueError('Source changed its advertised checkpoint')
        append(archive, head, records, end)
        head = end
    return head


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--url')
    parser.add_argument('--credential-file', type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if args.verify:
        if not args.archive.is_dir():
            parser.error('Archive does not exist')
        result = checkpoint(args.archive)
    else:
        if not args.url or not args.credential_file:
            parser.error('--url and --credential-file are required for replication')
        credential = args.credential_file.read_text().strip()
        if len(credential) != 64 or any(c not in '0123456789abcdef' for c in credential):
            parser.error('Use a named viewer credential file')
        result = replicate(args.url, credential, args.archive)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
