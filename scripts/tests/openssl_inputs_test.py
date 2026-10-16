#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the actual completed OpenSSL producer manifest and damaged controls."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_openssl import OUTPUT, digest
from fetch import ROOT
from random_crypto import inputs


class ProductReaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidates = []
        for manifest in (OUTPUT / 'runtime').glob('*/manifest.json'):
            value = json.loads(manifest.read_text())
            if value['recipe_sha256'] == digest(ROOT / 'scripts/build_openssl.py'):
                candidates.append((manifest.parent, value))
        if len(candidates) != 1:
            raise RuntimeError('build exactly one current runtime OpenSSL provider before this test')
        cls.original, cls.data = candidates[0]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='openssl-reader-')
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.directory = self.output / 'runtime' / self.data['identity']
        self.directory.mkdir(parents=True)
        self.manifest = copy.deepcopy(self.data)
        for relative in self.manifest['products']:
            target = self.directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(self.original / relative)
        for relative, target in self.manifest['symlinks'].items():
            link = self.directory / relative
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(target)
        self.save()
        self.override = patch.object(inputs, 'OUTPUT', self.output)
        self.override.start()
        self.addCleanup(self.override.stop)

    def save(self):
        (self.directory / 'manifest.json').write_text(json.dumps(self.manifest) + '\n')

    def test_actual_current_producer_products(self):
        directory, manifest = inputs.provider('runtime')
        self.assertEqual(directory, self.directory)
        self.assertEqual(manifest, self.data)

    def test_changed_uapi_recipe_invalidates_identity(self):
        self.manifest['uapi_recipe_sha256'] = '0' * 64
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'product identity differs'):
            inputs.provider('runtime')

    def test_refingerprinted_old_uapi_recipe_is_rejected(self):
        self.manifest['uapi_recipe_sha256'] = '0' * 64
        keys = ('dependency', 'provider', 'compiler', 'target', 'libc_identity',
                'native_inputs', 'uapi', 'recipe_sha256', 'uapi_recipe_sha256')
        identity = {key: self.manifest[key] for key in keys}
        self.manifest['identity'] = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        replacement = self.directory.with_name(self.manifest['identity'])
        self.directory.rename(replacement)
        self.directory = replacement
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'UAPI recipe changed'):
            inputs.provider('runtime')

    def test_changed_product_is_rejected(self):
        name = 'static/stage/usr/bin/openssl'
        product = self.directory / name
        product.unlink()
        product.write_bytes((self.original / name).read_bytes() + b'changed\n')
        with self.assertRaisesRegex(RuntimeError, 'product changed: ' + name):
            inputs.provider('runtime')

    def test_changed_product_link_is_rejected(self):
        name, target = next(iter(self.manifest['symlinks'].items()))
        link = self.directory / name
        link.unlink()
        link.symlink_to(target + '-changed')
        with self.assertRaisesRegex(RuntimeError, 'product link changed: ' + name):
            inputs.provider('runtime')

    def test_wrong_directory_identity_is_rejected(self):
        replacement = self.directory.with_name('0' * 64)
        self.directory.rename(replacement)
        self.directory = replacement
        with self.assertRaisesRegex(RuntimeError, 'product identity differs'):
            inputs.provider('runtime')


if __name__ == '__main__':
    unittest.main()
