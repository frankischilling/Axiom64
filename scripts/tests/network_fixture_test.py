# SPDX-License-Identifier: GPL-3.0-or-later
"""Preserve earlier linked initramfs bytes across successful or failed publication."""
import errno
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import network_test


def members(data):
    result = {}
    offset = 0
    while True:
        header = data[offset:offset + 110]
        if len(header) != 110 or header[:6] != b'070701':
            raise ValueError('invalid newc header')
        fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        name = data[offset + 110:offset + 110 + namesize]
        if not name or not name.endswith(b'\0'):
            raise ValueError('incomplete newc name')
        offset = (offset + 110 + namesize + 3) & ~3
        payload = data[offset:offset + size]
        if len(payload) != size:
            raise ValueError('incomplete newc payload')
        offset = (offset + size + 3) & ~3
        if name == b'TRAILER!!!\0':
            if offset != len(data):
                raise ValueError('bytes after newc trailer')
            return result
        result[name[:-1].decode()] = payload


class FixturePublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, data in [('build/init', b'fixture-init'), ('build/net-tests', b'fixture-client'),
                           ('build/busybox-1.37.0/busybox', b'fixture-busybox'),
                           ('userspace/tests/net/run.sh', b'#!/bin/sh\nexit 0\n')]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.original = b'previous independently retained fixture bytes'
        self.destination = self.root / 'build/rootfs-network.cpio'
        self.destination.write_bytes(self.original)
        self.link = self.root / 'build/earlier-staging.cpio'
        os.link(self.destination, self.link)
        self.root_patch = patch.object(network_test, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        compiler_patch = patch.object(network_test.subprocess, 'run')
        self.compiler = compiler_patch.start()
        self.addCleanup(compiler_patch.stop)

    def test_completed_publication_preserves_old_inode_and_payloads(self):
        network_test.fixture(environment={'AXIOM64_FIXTURE_VALUE': 'one two'})
        self.assertEqual(self.link.read_bytes(), self.original)
        self.assertNotEqual(self.destination.stat().st_ino, self.link.stat().st_ino)
        archive = members(self.destination.read_bytes())
        self.assertEqual(archive['sbin/init'], b'fixture-init')
        self.assertEqual(archive['bin/net-tests'], b'fixture-client')
        self.assertEqual(archive['bin/busybox'], b'fixture-busybox')
        self.assertEqual(archive['etc/net-test.sh'],
                         b"export AXIOM64_FIXTURE_VALUE='one two'\n#!/bin/sh\nexit 0\n")
        self.assertEqual(list((self.root / 'build').glob('.network-root-*')), [])
        self.compiler.assert_called_once()

    def test_failed_publication_preserves_previous_archive_and_links(self):
        with patch.object(network_test.os, 'replace', side_effect=OSError(errno.ENOSPC, 'injected')):
            with self.assertRaises(OSError):
                network_test.fixture()
        self.assertEqual(self.destination.read_bytes(), self.original)
        self.assertEqual(self.link.read_bytes(), self.original)
        self.assertEqual(self.destination.stat().st_ino, self.link.stat().st_ino)
        self.assertEqual(list((self.root / 'build').glob('.network-root-*')), [])

    def test_output_symlink_cannot_modify_retained_target(self):
        self.destination.unlink()
        self.destination.symlink_to(self.link)
        network_test.fixture()
        self.assertFalse(self.destination.is_symlink())
        self.assertEqual(self.link.read_bytes(), self.original)
        self.assertEqual(members(self.destination.read_bytes())['sbin/init'], b'fixture-init')


if __name__ == '__main__':
    unittest.main()
