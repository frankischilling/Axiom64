# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify exported native observations retain their real runtime libraries."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tcp_icmp_inputs as inputs
from tcp_icmp_capture import audit_inputs


class NativeLibraries(unittest.TestCase):
    def test_native_library_products_survive_an_export(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-tcp-library-export-') as temporary:
            root = Path(temporary) / 'original'
            (root / 'build').mkdir(parents=True)
            (root / 'fixture.c').write_text('int main(void) { return 0; }\n')
            subprocess.run(['gcc', str(root / 'fixture.c'), '-o', str(root / 'build/probe-native')], check=True)
            with patch.object(inputs, 'ROOT', root):
                name = inputs.record('native', native=True, program='probe', sources=('fixture.c',))
            value = json.loads((root / 'build' / name).read_text())
            exported = Path(temporary) / 'exported'
            root.rename(exported)
            for library in value['host_libraries'].values():
                self.assertEqual(value['products'][library['retained']], library['sha256'])
                library['path'] = '/unavailable-original-host/library'
            audit_inputs(value, input_root=exported)
            changed = deepcopy(value)
            changed['host_libraries']['libc.so.6']['retained'] = value['host_libraries']['ld-linux-x86-64.so.2']['retained']
            with self.assertRaisesRegex(ValueError, 'retained native shared library fingerprint'):
                audit_inputs(changed, input_root=exported)
            for name, library in value['host_libraries'].items():
                with self.subTest(library=name):
                    retained = exported / library['retained']
                    original = retained.read_bytes()
                    retained.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                    with self.assertRaisesRegex(ValueError, 'actual products input'):
                        audit_inputs(value, input_root=exported)
                    retained.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
