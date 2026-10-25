#!/usr/bin/env python3
"""Verify named identity recovery and independently retained audit against a real server."""
if not __debug__:
    raise SystemExit('Validation requires Python assertions; do not use -O or PYTHONOPTIMIZE')

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from replicate_audit import replicate, checkpoint, canonical


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--server',type=Path,default=Path('target/release/athernex-siem'));args=parser.parse_args()
    binary=args.server.resolve();process=None
    with tempfile.TemporaryDirectory(prefix='athernex-audit-recovery-') as directory:
        root=Path(directory);database=root/'original.db';archive=root/'audit-host';bootstrap='public-recovery-fixture-'+'a'*40
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        origin=f'http://127.0.0.1:{port}'
        def api(path,value=None,token=bootstrap):
            data=None if value is None else json.dumps(value).encode()
            with urllib.request.urlopen(urllib.request.Request(origin+path,data,{'authorization':'Bearer '+token,'content-type':'application/json'}),timeout=10) as response:return json.loads(response.read())
        def start(path):
            nonlocal process
            process=subprocess.Popen([str(binary),'--no-journal','--db',str(path),'--port',str(port)],env={**os.environ,'ATHERNEX_OPERATOR_KEY':bootstrap},stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            for _ in range(100):
                if process.poll() is not None:raise AssertionError(process.stderr.read().decode())
                try:api('/healthz');return
                except OSError:time.sleep(.05)
            raise AssertionError('Fixture server did not become ready')
        def stop():
            nonlocal process
            process.terminate();process.wait(timeout=30)
            if process.returncode!=0:raise AssertionError(process.stderr.read().decode())
            process.stderr.close();process=None
        def issue(name):return api('/api/control',dict(operation='issue_operator',id=name,role='viewer',expires_ms=int(time.time()*1000)+600000))['token']
        try:
            start(database);reader=issue('independent-audit-reader');revoked=issue('revoked-viewer')
            first=replicate(origin,reader,archive)
            api('/api/control',dict(operation='revoke_operator',id='revoked-viewer'))
            anchored=replicate(origin,reader,archive);assert anchored['sequence']>first['sequence'];stop()
            subprocess.run([str(binary),'--db',str(database),'--backup-dir',str(root/'backup')],check=True,capture_output=True)
            subprocess.run([str(binary),'--restore-backup',str(root/'backup'),'--restore-dir',str(root/'restored')],check=True,capture_output=True)
            restored=root/'restored/ledger.sqlite3';start(restored)
            try:api('/api/control',token=revoked)
            except urllib.error.HTTPError as error:assert error.code==401
            else:raise AssertionError('Revoked credential became valid after recovery')
            recovered=replicate(origin,reader,archive);assert recovered['sequence']>=anchored['sequence'];stop()
            # An attacker who controls the source database can rewrite and
            # recompute a valid local chain. The independent archive must reject it.
            db=sqlite3.connect(restored);previous='0'*64
            for sequence,at,action,detail in db.execute('SELECT sequence,time_ms,action,detail FROM audit_chain ORDER BY sequence').fetchall():
                if sequence==1:detail='Privileged source rewrite fixture'
                digest=hashlib.sha256(canonical([sequence,at,action,detail,previous])).hexdigest()
                db.execute('UPDATE audit_chain SET detail=?,previous=?,sha256=? WHERE sequence=?',(detail,previous,digest,sequence));previous=digest
            db.commit();db.close();start(restored)
            try:replicate(origin,reader,archive)
            except ValueError as error:assert 'retained checkpoint' in str(error)
            else:raise AssertionError('Independent checkpoint accepted rewritten history')
            assert checkpoint(archive)==recovered
            report=dict(real_http_replication=True,checkpoint_resume=True,verified_backup_restore=True,revocation_survives_restore=True,privileged_rewrite_rejected=True,archive_unchanged_after_rejection=True)
            output=Path('.athernex/verification');output.mkdir(parents=True,exist_ok=True);(output/'ecosystem-recovery.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
        finally:
            if process is not None:stop()


if __name__=='__main__':main()
