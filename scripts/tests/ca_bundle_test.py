#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real offline CA conversion and reject altered or missing proof bytes."""
from pathlib import Path
import copy
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ca_bundle
import fetch


class PinnedTrustBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ca_bundle.ensure()
        cls.original = ca_bundle.ROOT

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom64-ca-proof-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ('downloads/' + fetch.LOCK['ca_bundle']['archive'],
                     'downloads/' + fetch.LOCK['curl']['archive'],
                     'downloads/sources/ca-bundle/certdata.txt',
                     'downloads/sources/ca-bundle/MPL-2.0.txt'):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.original / name, target)
        for module in (ca_bundle, fetch):
            replacement = patch.object(module, 'ROOT', self.root)
            replacement.start()
            self.addCleanup(replacement.stop)

    def test_actual_source_reconverts_every_pinned_certificate(self):
        destination = ca_bundle.ensure()
        certificates = ca_bundle.certificates((destination / fetch.LOCK['ca_bundle']['archive']).read_bytes())
        self.assertEqual(len(certificates), 121)
        self.assertEqual(ca_bundle.ensure(), destination)

    def test_changed_published_bundle_is_rejected(self):
        path = self.root / 'downloads' / fetch.LOCK['ca_bundle']['archive']
        path.write_bytes(path.read_bytes() + b'changed\n')
        with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
            ca_bundle.ensure()

    def test_changed_mozilla_source_is_rejected(self):
        path = self.root / 'downloads/sources/ca-bundle/certdata.txt'
        path.write_bytes(path.read_bytes() + b'changed\n')
        with self.assertRaisesRegex(RuntimeError, 'CA bundle input checksum differs: certdata.txt'):
            ca_bundle.ensure()

    def test_changed_license_is_rejected(self):
        path = self.root / 'downloads/sources/ca-bundle/MPL-2.0.txt'
        path.write_bytes(path.read_bytes() + b'changed\n')
        with self.assertRaisesRegex(RuntimeError, 'CA bundle input checksum differs: MPL-2.0.txt'):
            ca_bundle.ensure()

    def test_changed_cached_bundle_is_rejected(self):
        destination = ca_bundle.ensure()
        path = destination / fetch.LOCK['ca_bundle']['archive']
        path.write_bytes(path.read_bytes() + b'changed\n')
        with self.assertRaisesRegex(RuntimeError, 'CA bundle cached product changed'):
            ca_bundle.ensure()

    def test_missing_cached_source_is_rejected(self):
        destination = ca_bundle.ensure()
        (destination / 'certdata.txt').unlink()
        with self.assertRaises(FileNotFoundError):
            ca_bundle.ensure()

    def test_wrong_publication_date_cannot_relabel_the_dated_file(self):
        lock = copy.deepcopy(fetch.LOCK)
        lock['ca_bundle']['source_date_epoch'] += 1
        with patch.object(ca_bundle, 'LOCK', lock), patch.object(fetch, 'LOCK', lock):
            with self.assertRaisesRegex(RuntimeError, 'dated CA bundle differs from its independently converted source bytes'):
                ca_bundle.ensure()


if __name__ == '__main__':
    unittest.main()
