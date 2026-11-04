# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep native control evidence separate from the prebuilt client file."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_lifetimes import cohort, native


class BuildReached(Exception):
    pass


class LifetimeOutputOwnership(unittest.TestCase):
    def test_native_output_preserves_the_existing_client(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'build').mkdir()
            program = root / 'build/ipv4-address-lifetimes-native'
            original = b'prebuilt client bytes'
            program.write_bytes(original)
            output = root / 'build' / cohort.CONTROL_NATIVE
            with patch.object(native, 'ROOT', root), patch.object(native.subprocess, 'run', side_effect=BuildReached):
                with self.assertRaises(BuildReached):
                    native.produce(output)
            self.assertTrue(output.is_dir())
            self.assertEqual(program.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
