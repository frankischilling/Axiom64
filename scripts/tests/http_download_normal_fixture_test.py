#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Resolve the actual installed libcurl link shape and reject broken fixture links."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from http_download.normal_fixture import contents


class InstalledDependencies(unittest.TestCase):
    def test_installed_soname_link_checks_its_target_bytes(self):
        # This is the name, mode and target retained in the actual normal image.
        files = {'usr/lib/libcurl.so.4': (0o120777, b'libcurl.so.4.8.0'),
                 'usr/lib/libcurl.so.4.8.0': (0o100755, b'actual library bytes')}
        self.assertEqual(contents(files, 'usr/lib/libcurl.so.4'), b'actual library bytes')

    def test_absolute_and_parent_relative_links_stay_in_the_archive(self):
        files = {'usr/lib/libc.so': (0o120777, b'../../lib/ld-musl-x86_64.so.1'),
                 'lib/ld-musl-x86_64.so.1': (0o120777, b'/lib/loader'),
                 'lib/loader': (0o100755, b'loader bytes')}
        self.assertEqual(contents(files, 'usr/lib/libc.so'), b'loader bytes')

    def test_missing_and_cyclic_links_fail(self):
        for target in (b'missing', b'libcurl.so.4'):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'missing or cyclic'):
                contents({'usr/lib/libcurl.so.4': (0o120777, target)}, 'usr/lib/libcurl.so.4')


if __name__ == '__main__':
    unittest.main()
