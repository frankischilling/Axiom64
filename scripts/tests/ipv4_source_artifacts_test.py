#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen file-only publication archives without losing runtime inventory checks."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv4_source_route.artifacts import providers


class RuntimePublicationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='source-runtime-publication-')
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_static_inventory_survives_file_only_zip_publication(self):
        original = self.directory / 'original'
        (original / 'runtime').mkdir(parents=True)
        (original / 'runtime.json').write_text(json.dumps(dict(providers={})))
        (original / 'runtime-maps.txt').write_text('')
        providers(original, dict(providers={}), '', 'static', [], '')
        archive = self.directory / 'published.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            for path in original.rglob('*'):
                if path.is_file():
                    output.write(path, path.relative_to(original))
        restored = self.directory / 'restored'
        with zipfile.ZipFile(archive) as source:
            source.extractall(restored)
        self.assertFalse((restored / 'runtime').exists())
        providers(restored, json.loads((restored / 'runtime.json').read_text()),
                  (restored / 'runtime-maps.txt').read_text(), 'static', [], '')

    def test_static_inventory_rejects_an_unlisted_provider(self):
        (self.directory / 'runtime').mkdir()
        (self.directory / 'runtime/unlisted.so').write_bytes(b'unlisted provider')
        with self.assertRaises(ValueError):
            providers(self.directory, dict(providers={}), '', 'static', [], '')

    def test_dynamic_inventory_requires_its_declared_loader(self):
        runtime = dict(providers={'runtime/ld-musl-x86_64.so.1': dict(
            source='/lib/ld-musl-x86_64.so.1', sha256='0' * 64)})
        with self.assertRaises(ValueError):
            providers(self.directory, runtime, '', 'dynamic', [], '/lib/ld-musl-x86_64.so.1')

    def test_native_inventory_requires_its_declared_library(self):
        runtime = dict(providers={'runtime/libc.so.6': dict(
            source='/lib/libc.so.6', inode=42, sha256='0' * 64)})
        with self.assertRaises(ValueError):
            providers(self.directory, runtime, '', 'native', [], '')

    def test_static_runtime_path_cannot_be_a_file(self):
        (self.directory / 'runtime').write_bytes(b'not a provider directory')
        with self.assertRaises(ValueError):
            providers(self.directory, dict(providers={}), '', 'static', [], '')

    def test_static_runtime_path_cannot_be_a_directory_alias(self):
        (self.directory / 'elsewhere').mkdir()
        (self.directory / 'runtime').symlink_to(self.directory / 'elsewhere', target_is_directory=True)
        with self.assertRaises(ValueError):
            providers(self.directory, dict(providers={}), '', 'static', [], '')


if __name__ == '__main__':
    unittest.main()
