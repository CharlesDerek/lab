import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import replicate_audit as audit


def rows():
    head=audit.ZERO.copy(); result=[]
    for i in range(1, 4):
        row=dict(sequence=i,time_ms=1800000000000,action='fixture',detail='unicode ✓ and "escaped"\n',previous=head['sha256'])
        row['sha256']=hashlib.sha256(audit.canonical([row[k] for k in ['sequence','time_ms','action','detail','previous']])).hexdigest()
        head=dict(sequence=i,sha256=row['sha256']);result.append(row)
    return result,head


class Replication(unittest.TestCase):
    def test_resume_preserves_checkpoint_and_rejects_fork_and_truncation(self):
        records,end=rows()
        with tempfile.TemporaryDirectory() as directory:
            archive=Path(directory)/'separate-audit-host'
            def fetch(_url,_token,after):
                return dict(records=records[after:after+2], checkpoint=end)
            with patch.object(audit,'fetch',fetch):
                self.assertEqual(audit.replicate('https://fixture','unused',archive),end)
                self.assertEqual(audit.replicate('https://fixture','unused',archive),end)
            self.assertEqual(audit.checkpoint(archive),end)
            records[-1]['sha256']='f'*64
            with patch.object(audit,'fetch',fetch),self.assertRaisesRegex(ValueError,'retained checkpoint'):
                audit.replicate('https://fixture','unused',archive)
            records.clear()
            with patch.object(audit,'fetch',fetch),self.assertRaisesRegex(ValueError,'retained checkpoint'):
                audit.replicate('https://fixture','unused',archive)

    def test_torn_write_is_ignored_committed_tamper_is_rejected(self):
        records,end=rows()
        with tempfile.TemporaryDirectory() as directory:
            archive=Path(directory)
            (archive/'.pending-interrupted').write_text('{')
            audit.append(archive,audit.ZERO,records,end)
            self.assertEqual(audit.checkpoint(archive),end)
            with self.assertRaises(FileExistsError): audit.append(archive,audit.ZERO,records,end)
            path=next(archive.glob('*.json'));page=json.loads(path.read_text());page['records'][0]['detail']='rewritten';path.write_text(json.dumps(page))
            with self.assertRaisesRegex(ValueError,'integrity'):audit.checkpoint(archive)

    def test_no_credential_redirect_or_plaintext_remote_source(self):
        with self.assertRaises(ValueError):audit.NoRedirect().redirect_request(None,None,None,None,None,None)
        with self.assertRaises(ValueError):audit.fetch('http://remote.example','secret',0)

    def test_disk_and_archive_budgets_refuse_before_writing(self):
        records,end=rows()
        with tempfile.TemporaryDirectory() as directory:
            archive=Path(directory)
            with patch.object(audit,'MAX_ARCHIVE',1),self.assertRaisesRegex(ValueError,'128 MiB'):
                audit.append(archive,audit.ZERO,records,end)
            self.assertEqual(list(archive.iterdir()),[])
            with patch.object(audit.shutil,'disk_usage',return_value=type('Usage',(),{'free':1})()),self.assertRaisesRegex(ValueError,'1 GiB free'):
                audit.append(archive,audit.ZERO,records,end)
            self.assertEqual(list(archive.iterdir()),[])


if __name__=='__main__':unittest.main()
