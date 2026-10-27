#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check real unprivileged writes after a privileged shared-fixture replacement."""
from contextlib import nullcontext
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ipv4_multicast_test as producer


@unittest.skipUnless(os.geteuid() == 0, 'requires real root/unprivileged ownership transitions')
class FixtureOwnerTests(unittest.TestCase):
    def writer(self, path):
        def drop():
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)

        return subprocess.run([sys.executable, '-c',
            'import sys; f=open(sys.argv[1], "r+b"); b=f.read(1); f.seek(0); f.write(b); f.close()',
            str(path)], preexec_fn=drop, capture_output=True, text=True,
            env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1'})

    def exercise(self, failed=False, existing=True):
        with tempfile.TemporaryDirectory(prefix='axiom-multicast-fixture-owner-') as name:
            work = Path(name)
            work.chmod(0o755)
            build = work / 'build'
            build.mkdir(mode=0o755)
            os.chown(build, 65534, 65534)
            target = build / 'rootfs-network.cpio'
            neighbor = build / 'retained-evidence'
            neighbor.write_bytes(b'unchanged evidence')
            neighbor.chmod(0o600)
            if existing:
                target.write_bytes(b'previous fixture')
                os.chown(target, 65534, 65534)
                target.chmod(0o640)
            before = neighbor.stat()
            guard = getattr(producer, 'shared_fixture_owner', lambda path: nullcontext())
            try:
                with guard(target):
                    replacement = build / 'root-created.cpio'
                    replacement.write_bytes(b'actual replacement bytes')
                    replacement.chmod(0o600)
                    os.replace(replacement, target)
                    denied = self.writer(target)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertIn('PermissionError', denied.stderr)
                    if failed:
                        raise ValueError('injected producer failure after replacement')
            except ValueError as error:
                self.assertTrue(failed)
                self.assertEqual(str(error), 'injected producer failure after replacement')
            else:
                self.assertFalse(failed)
            result = self.writer(target)
            self.assertEqual(result.returncode, 0,
                'the real unprivileged fixture writer must work after the producer: ' + result.stderr)
            metadata = target.stat()
            self.assertEqual((metadata.st_uid, metadata.st_gid), (65534, 65534))
            self.assertEqual(metadata.st_mode & 0o777, 0o640 if existing else 0o600)
            self.assertEqual(target.read_bytes(), b'actual replacement bytes')
            after = neighbor.stat()
            self.assertEqual((before.st_uid, before.st_gid, before.st_mode),
                             (after.st_uid, after.st_gid, after.st_mode))
            self.assertEqual(neighbor.read_bytes(), b'unchanged evidence')

    def test_original_owner_and_mode_after_success(self):
        self.exercise()

    def test_original_metadata_and_exception_after_failure(self):
        self.exercise(failed=True)

    def test_new_fixture_uses_build_directory_owner(self):
        self.exercise(existing=False)


if __name__ == '__main__':
    unittest.main()
