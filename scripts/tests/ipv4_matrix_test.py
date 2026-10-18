# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual matrix worker isolation, evidence rejection and group cleanup."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ipv4_matrix


WORKER = '''import argparse,json,os,socket,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--worker',nargs=2)
p.add_argument('--prepared-image',type=Path)
p.add_argument('--image-sha256')
p.add_argument('--result-file',type=Path)
p.add_argument('--timeout')
p.add_argument('--fault',action='store_true')
a=p.parse_args()
mode=os.environ.get('AXIOM64_IPV4_MATRIX_CONTROL','normal')
with socket.socket() as listener:
 listener.bind(('127.0.0.1',0));listener.listen(1)
 time.sleep(.3)
 if mode=='orphan':
  child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
  a.result_file.with_suffix('.orphan').write_text(str(child.pid))
 selected=a.worker==['bios','modern']
 if mode=='changed-image' and selected:
  with a.prepared_image.open('ab') as output:output.write(b'changed')
 if mode!='missing' or not selected:
  a.result_file.write_text(json.dumps([dict(firmware=a.worker[0],transport=a.worker[1],
   fault=a.fault,passed=True,gdb_port=listener.getsockname()[1],worker_pid=os.getpid())]))
 raise SystemExit(7 if mode=='false-exit' and selected else 0)
'''


class MatrixTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom64-ipv4-matrix-controls-')
        self.root = Path(self.temporary.name)
        (self.root / 'build').mkdir()
        (self.root / 'build/axiom64-ipv4-normal.iso').write_bytes(b'original immutable image')
        (self.root / 'build/axiom64.elf').write_bytes(b'original matching debugger kernel')
        worker = self.root / 'worker.py'
        worker.write_text(WORKER)
        self.original_root, self.original_script = ipv4_matrix.ROOT, ipv4_matrix.__file__
        ipv4_matrix.ROOT, ipv4_matrix.__file__ = self.root, str(worker)
        self.previous_control = os.environ.get('AXIOM64_IPV4_MATRIX_CONTROL')
        self.results = []

    def tearDown(self):
        ipv4_matrix.ROOT, ipv4_matrix.__file__ = self.original_root, self.original_script
        if self.previous_control is None:
            os.environ.pop('AXIOM64_IPV4_MATRIX_CONTROL', None)
        else:
            os.environ['AXIOM64_IPV4_MATRIX_CONTROL'] = self.previous_control
        self.temporary.cleanup()

    def run_phase(self, mode):
        os.environ['AXIOM64_IPV4_MATRIX_CONTROL'] = mode
        ipv4_matrix.phase(False, 2, self.results, self.root / 'build/ipv4-results.json')

    def test_actual_workers_overlap_and_keep_exact_profiles(self):
        self.run_phase('normal')
        rows = json.loads((self.root / 'build/ipv4-normal-worker-results.json').read_text())['cases']
        self.assertEqual(len(rows), 4)
        self.assertEqual(len({row['pid'] for row in rows}), 4)
        self.assertLess(max(row['started_monotonic_ns'] for row in rows[:2]),
                        min(row['finished_monotonic_ns'] for row in rows[:2]))
        self.assertTrue(all(row['terminal'] and row['passed'] for row in rows))
        self.assertEqual([(row['firmware'], row['transport']) for row in self.results],
                         [('bios', 'modern'), ('uefi', 'modern'), ('bios', 'legacy'), ('uefi', 'legacy')])

    def test_nonzero_worker_cannot_claim_success(self):
        with self.assertRaises(RuntimeError):
            self.run_phase('false-exit')
        self.assertFalse(self.results[0]['passed'])
        self.assertEqual(len(self.results), 4)

    def test_missing_result_cannot_claim_success(self):
        with self.assertRaises(RuntimeError):
            self.run_phase('missing')
        self.assertFalse(self.results[0]['passed'])

    def test_changed_shared_image_rejects_every_result(self):
        with self.assertRaises(ValueError):
            self.run_phase('changed-image')
        self.assertEqual(len(self.results), 4)
        self.assertTrue(all(not row['passed'] for row in self.results))

    def test_completed_worker_cannot_leave_live_descendants(self):
        self.run_phase('orphan')
        paths = list((self.root / 'build').glob('*.orphan'))
        self.assertEqual(len(paths), 4)
        for path in paths:
            stat = Path('/proc') / path.read_text() / 'stat'
            if stat.exists():
                self.assertIn(stat.read_text().rsplit(')', 1)[1].split()[0], ('Z', 'X'))


if __name__ == '__main__':
    unittest.main()
