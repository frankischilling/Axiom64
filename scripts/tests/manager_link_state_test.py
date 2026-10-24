# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep disabled-profile expectations consistent with Linux operational flags."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ManagerLinkState(unittest.TestCase):
    def test_actual_observer_requires_the_selected_operational_state(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-manager-link-state-') as temporary:
            program = Path(temporary) / 'observer'
            build = subprocess.run(['g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                '-ffunction-sections', '-fdata-sections', '-Iuserspace',
                'userspace/tests/net/manager_link_state_model.cpp', '-Wl,--gc-sections',
                '-o', str(program)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(build.returncode, 0, build.stdout.decode(errors='replace'))
            for name in ('enabled-up', 'enabled-not-running', 'disabled-up', 'disabled-activated',
                         'disabled-running', 'disabled-down', 'carrier-down', 'carrier-still-up',
                         'ordinary-observation'):
                with self.subTest(name=name):
                    result = subprocess.run([str(program), name], stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, timeout=2)
                    self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
