#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check full worker completion and cleanup across source-cohort failures."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv4_source_route.window import run


class SourceWindowTest(unittest.TestCase):
    def setUp(self):
        (ROOT / 'build').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='source-window-test-', dir=ROOT / 'build')
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_both_workers_start_before_either_finishes(self):
        commands = {}
        for name, other in (('filters', 'routing'), ('routing', 'filters')):
            source = ('import pathlib,time; base=pathlib.Path(' + repr(str(self.directory)) + '); '
                      '(base/' + repr(name) + ').touch(); deadline=time.monotonic()+5\n'
                      'while not (base/' + repr(other) + ').exists():\n'
                      ' assert time.monotonic()<deadline\n time.sleep(.01)\n'
                      'print(' + repr(name + '_COMPLETE') + ',flush=True)')
            commands[name] = [sys.executable, '-B', '-c', source]
        proof = run(self.directory / 'parallel', commands)
        self.assertTrue(proof['passed'])
        for name in commands:
            self.assertEqual((self.directory / 'parallel' / (name + '.log')).read_text().strip(), name + '_COMPLETE')

    def test_failure_preserves_other_workers_complete_output(self):
        finished = self.directory / 'finished'
        commands = dict(filters=[sys.executable, '-c', 'raise SystemExit(7)'],
                        routing=[sys.executable, '-c', 'import pathlib,time; time.sleep(.1); pathlib.Path(' +
                                 repr(str(finished)) + ').write_text("complete"); print("ALL_CASES_COMPLETE")'])
        with self.assertRaisesRegex(ValueError, 'both complete source cohorts'):
            run(self.directory / 'failed', commands)
        self.assertEqual(finished.read_text(), 'complete')
        self.assertIn('ALL_CASES_COMPLETE', (self.directory / 'failed/routing.log').read_text())
        records = json.loads((self.directory / 'failed/processes.json').read_text())
        self.assertEqual(records['filters']['returncode'], 7)
        self.assertEqual(records['routing']['returncode'], 0)

    def test_exited_worker_cannot_leave_a_live_descendant(self):
        pidfile = self.directory / 'child.pid'
        source = ('import subprocess,sys,pathlib; child=subprocess.Popen([sys.executable,"-c",'
                  '"import time; time.sleep(60)"]); pathlib.Path(' + repr(str(pidfile)) +
                  ').write_text(str(child.pid)); raise SystemExit(9)')
        commands = dict(filters=[sys.executable, '-c', source], routing=[sys.executable, '-c', 'print("COMPLETE")'])
        with self.assertRaisesRegex(ValueError, 'both complete source cohorts'):
            run(self.directory / 'orphan', commands)
        child = Path('/proc') / pidfile.read_text()
        self.assertTrue(not child.exists() or (child / 'stat').read_text().split()[2] == 'Z')


if __name__ == '__main__':
    unittest.main()
