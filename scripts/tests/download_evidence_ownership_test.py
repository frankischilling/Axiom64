#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Publish actual root-created download bytes without changing modes or outside links."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

HELPER = Path(__file__).resolve().parents[1] / 'ci/storage_evidence.sh'
NAMES = ('http-downloads','http-download-controls','http-download-normal','http-download-normal-audit')


class DownloadOwnership(unittest.TestCase):
    def test_all_download_evidence_roots_publish_actual_private_bytes(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-download-owner-') as temporary:
            work = Path(temporary)
            work.chmod(0o755)
            (work / 'build').mkdir()
            (work / 'build').chmod(0o755)
            outside = work / 'build/outside'
            outside.write_bytes(b'outside ownership must stay root\n')
            outside.chmod(0o600)
            before = (outside.stat().st_uid,outside.stat().st_gid,outside.stat().st_mode & 0o777,outside.read_bytes())
            paths = []
            for name in NAMES:
                directory = work / 'build' / name
                directory.mkdir(mode=0o700)
                path = directory / 'native.log'
                path.write_bytes(('actual '+name+' evidence\n').encode())
                path.chmod(0o600)
                (directory / 'outside-link').symlink_to('../outside')
                paths.append(path)
            command = ['bash',str(HELPER),'60011','60011',*('build/'+name for name in NAMES)]
            subprocess.run(command,cwd=work,check=True,capture_output=True)
            self.assertEqual((outside.stat().st_uid,outside.stat().st_gid,outside.stat().st_mode & 0o777,outside.read_bytes()),before)
            for path in paths:
                self.assertEqual((path.stat().st_uid,path.stat().st_gid,path.stat().st_mode & 0o777),(60011,60011,0o600))
            upload = work / 'upload'
            upload.mkdir()
            os.chown(upload,60011,60011)
            archive = upload / 'actual.zip'
            program = '''import sys,zipfile
with zipfile.ZipFile(sys.argv[1],'w') as archive:
    for name in sys.argv[2:]: archive.write(name,name.rsplit('/',2)[-2]+'/native.log')
'''
            subprocess.run(['setpriv','--reuid','60011','--regid','60011','--clear-groups',
                            sys.executable,'-c',program,str(archive),*(str(path) for path in paths)],check=True,capture_output=True)
            with zipfile.ZipFile(archive) as saved:
                self.assertEqual(set(saved.namelist()),{name+'/native.log' for name in NAMES})
                for path in paths:
                    self.assertEqual(saved.read(path.parent.name+'/native.log'),path.read_bytes())

    def test_unsafe_roots_fail_before_any_ownership_change(self):
        for invalid in ('build/http-downloads-extra','build/../http-downloads','/tmp/http-downloads',
                        'build/http-downloads/child','build/http-downloads/../outside','build/other',
                        'build/http-downloads-link'):
            with self.subTest(path=invalid), tempfile.TemporaryDirectory(prefix='axiom64-download-owner-') as temporary:
                work = Path(temporary)
                directory = work / 'build/http-downloads'
                directory.mkdir(parents=True)
                marker = directory / 'retained'
                marker.write_bytes(b'unchanged actual evidence\n')
                (work / 'build/http-downloads-link').symlink_to(directory,target_is_directory=True)
                before = (marker.stat().st_uid,marker.read_bytes())
                result = subprocess.run(['bash',str(HELPER),'60011','60011','build/http-downloads',invalid],
                                        cwd=work,capture_output=True)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual((marker.stat().st_uid,marker.read_bytes()),before)


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit(subprocess.run(['sudo','-n',sys.executable,str(Path(__file__).resolve()),*sys.argv[1:]]).returncode)
    unittest.main()
