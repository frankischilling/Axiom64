#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reproduce source capture from the exported tree restored by hosted TCP6 jobs."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp6 import inputs


class ExportedSourceTests(unittest.TestCase):
    def test_actual_export_without_git_keeps_public_inputs_and_excludes_outputs(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-tcp6-export-') as temporary:
            root = Path(temporary) / 'source'
            root.mkdir()
            public = {'Makefile': b'all:\n', 'README.md': b'public\n',
                      'userspace/tests/net/client.c': b'int main(void) { return 0; }\n',
                      'scripts/tests/fixtures/wire.pcap': bytes(range(64)),
                      '.github/workflows/build.yml': b'name: fixture\n'}
            private = {'build/program': b'ELF', 'downloads/package.tar': b'archive',
                       '.local/answers.md': b'private', 'unknown/private.txt': b'private',
                       'scripts/__pycache__/input.pyc': b'generated'}
            for name, data in {**public, **private}.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            output = root / 'build/proof'
            output.mkdir()
            self.assertFalse((root / '.git').exists())
            with patch.object(inputs, 'ROOT', root):
                receipt = inputs.freeze(output)
            with zipfile.ZipFile(output / 'source.zip') as archive:
                self.assertEqual(set(archive.namelist()), set(public))
                for name, data in public.items():
                    self.assertEqual(archive.read(name), data)
            records = json.loads((output / 'source-inputs.json').read_text())
            self.assertEqual(set(records), set(public))
            self.assertEqual(receipt['files'], len(public))
            self.assertEqual(receipt['enumeration'], 'exported-public-roots')

    def test_exported_source_cannot_follow_a_private_alias(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-tcp6-export-') as temporary:
            root = Path(temporary)
            (root / 'Makefile').write_text('all:\n')
            (root / '.local').mkdir()
            (root / '.local/answers.md').write_text('private\n')
            (root / 'scripts').mkdir()
            (root / 'scripts/alias.py').symlink_to(root / '.local/answers.md')
            with patch.object(inputs, 'ROOT', root), self.assertRaisesRegex(ValueError, 'escapes public inputs'):
                inputs.source_names()


if __name__ == '__main__':
    unittest.main()
