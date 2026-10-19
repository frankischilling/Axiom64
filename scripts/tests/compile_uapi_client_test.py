# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind real compiler products to every client translation unit and local header."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import compile_uapi_client as client


class CompileInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'build').mkdir()
        (self.root / 'local.h').write_text('#define RESULT 0\n')
        (self.root / 'fixture.c').write_text('#include "local.h"\nint main(void) { return RESULT; }\n')
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        for target, value in [('compiler_args', ['gcc']), ('uapi_headers', (self.root, {}))]:
            stub = patch.object(client, target, return_value=value)
            stub.start()
            self.addCleanup(stub.stop)
        arguments = patch.object(sys, 'argv', ['compile_uapi_client.py', '--output', 'build/probe',
                                             '--', '-std=c11', '-Wall', '-Werror', 'fixture.c'])
        arguments.start()
        self.addCleanup(arguments.stop)
        self.binary = self.root / 'build/probe'

    def test_actual_product_and_all_dependencies_are_bound(self):
        client.main()
        saved = client.audit_compile(self.binary, self.root)
        self.assertEqual(set(saved['sources']), {'fixture.c', 'local.h'})
        subprocess.run([str(self.binary)], check=True)
        manifest = self.binary.with_suffix('.inputs.json')
        del saved['sources']['local.h']
        manifest.write_text(json.dumps(saved))
        with self.assertRaisesRegex(ValueError, 'source changed'):
            client.audit_compile(self.binary, self.root)

    def test_changed_header_and_executable_are_rejected(self):
        client.main()
        (self.root / 'local.h').write_text('#define RESULT 1\n')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            client.audit_compile(self.binary, self.root)
        self.binary.write_bytes(b'other executable')
        with self.assertRaisesRegex(ValueError, 'does not match executable'):
            client.audit_compile(self.binary, self.root)

    def test_source_changed_during_real_compile_has_no_manifest(self):
        run = subprocess.run
        def compile_then_change(*args, **kwargs):
            result = run(*args, **kwargs)
            if '-MM' not in args[0]:
                (self.root / 'local.h').write_text('#define RESULT 1\n')
            return result
        with patch.object(client.subprocess, 'run', side_effect=compile_then_change):
            with self.assertRaisesRegex(ValueError, 'changed during compilation'):
                client.main()
        self.assertFalse(self.binary.with_suffix('.inputs.json').exists())


if __name__ == '__main__':
    unittest.main()
