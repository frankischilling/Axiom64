#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Execute a copied fixture on Linux storage, where execute bits are enforced."""
from pathlib import Path
import os
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from random_administration_test import copy_executable


class ExecutableCopy(unittest.TestCase):
    def test_retains_exact_bytes_and_real_execute_permission(self):
        # /tmp and RUNNER_TEMP are Linux storage even for a Windows-mounted checkout.
        with tempfile.TemporaryDirectory(dir=os.environ.get('RUNNER_TEMP', '/tmp')) as temporary:
            source, destination = Path(temporary) / 'source', Path(temporary) / 'destination'
            source.write_bytes(b'#!/bin/sh\nprintf "COPIED_FIXTURE_EXECUTED\\n"\n')
            source.chmod(0o755)
            copy_executable(source, destination)
            self.assertEqual(source.read_bytes(), destination.read_bytes())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
            result = subprocess.run([str(destination)], capture_output=True, check=True)
            self.assertEqual(result.stdout, b'COPIED_FIXTURE_EXECUTED\n')


if __name__ == '__main__':
    unittest.main()
