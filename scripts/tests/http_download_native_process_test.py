#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe partial output and detached-descendant retirement on a real timeout."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from http_download.native_process import run


class NativeProcessEvidence(unittest.TestCase):
    def test_timeout_retains_output_and_stops_detached_worker(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-native-lifetime-') as temporary:
            work = Path(temporary)
            heartbeat = work / 'heartbeat'
            child = work / 'child.py'
            child.write_text("import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\nwhile True:\n p.write_text(str(time.monotonic_ns()))\n time.sleep(.02)\n")
            controller = work / 'controller.py'
            controller.write_text("import subprocess,sys,time\nsubprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]],start_new_session=True)\nprint('partial stdout',flush=True)\nprint('partial stderr',file=sys.stderr,flush=True)\ntime.sleep(20)\n")
            result = run([sys.executable,str(controller),str(child),str(heartbeat)],work / 'stdout',work / 'stderr',.5)
            self.assertTrue(result['timed_out'] and result['owned_namespace_retired'])
            self.assertEqual((work / 'stdout').read_bytes(),b'partial stdout\n')
            self.assertEqual((work / 'stderr').read_bytes(),b'partial stderr\n')
            before = heartbeat.read_bytes()
            time.sleep(.15)
            self.assertEqual(heartbeat.read_bytes(),before)

    def test_nonzero_exit_keeps_actual_status_and_combined_output(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-native-failure-') as temporary:
            path = Path(temporary) / 'log'
            result = run([sys.executable,'-c',"import sys;print('actual failure',flush=True);sys.exit(7)"],path,None,2)
            self.assertFalse(result['timed_out'])
            self.assertEqual(result['returncode'],7)
            self.assertEqual(path.read_bytes(),b'actual failure\n')


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit(subprocess.run(['sudo','-n',sys.executable,str(Path(__file__).resolve()),*sys.argv[1:]]).returncode)
    unittest.main()
