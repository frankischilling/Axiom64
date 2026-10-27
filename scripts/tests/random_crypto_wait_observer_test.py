#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise serial barrier timing with real subprocesses and the native clock."""
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import random_crypto_wait_test as observer


PEER = r"""
import sys
import time
print('CRYPTO_WAIT_START mode=absent pid=7', flush=True)
print('sys pid=7 nr=318 a=0 b=20 c=0', flush=True)
print('sys result=-4096', flush=True)
assert sys.stdin.buffer.read(1) == b'B'
# This peer tests the observer protocol, not guest clock or entropy acceptance.
time.sleep(.02)
print('CRYPTO_WAIT_BLOCKED mode=absent pid=7 elapsed_ns=500000000 credit=0', flush=True)
if sys.argv[1] == 'early':
    print('CRYPTO_WAIT_PASS mode=absent signal=15 credit=0', flush=True)
    sys.exit(0)
if sys.argv[1] == 'fail':
    print('CRYPTO_WAIT_FAIL operation=controlled-peer error=1', flush=True)
    sys.exit(1)
assert sys.stdin.buffer.read(1) == b'R'
if sys.argv[1] == 'unconfirmed':
    sys.exit(0)
print('CRYPTO_WAIT_CONFIRMED mode=absent pid=7 credit=0', flush=True)
print('CRYPTO_WAIT_PASS mode=absent signal=15 credit=0', flush=True)
print('AXIOM64_TESTS_PASS', flush=True)
print('AXIOM64_EXIT status=0', flush=True)
"""


class ObserverTests(unittest.TestCase):
    def run_peer(self, mode='pending', delay=False):
        original = subprocess.Popen

        class DelayedInput:
            def __init__(self, stream):
                self.stream = stream
                self.last = None

            def write(self, data):
                self.last = data
                return self.stream.write(data)

            def flush(self):
                self.stream.flush()
                if self.last == b'B':
                    time.sleep(.15)

            def close(self):
                self.stream.close()

        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            if delay:
                process.stdin = DelayedInput(process.stdin)
            return process

        with tempfile.TemporaryDirectory() as name, patch.object(observer.subprocess, 'Popen', spawn):
            return observer.guest_run([sys.executable, '-u', '-c', PEER, mode], Path(name), 'absent')

    def test_guest_marker_cannot_release_native_interval(self):
        row, text = self.run_peer()
        observer.observe(row, text, 'absent', False)
        barrier = row['blocking_barrier']
        self.assertGreaterEqual(barrier['release_ns'], barrier['guest_blocked_ns'])
        self.assertGreaterEqual(barrier['release_elapsed_ns'], 500_000_000)
        self.assertGreaterEqual(barrier['elapsed_ns'], 500_000_000)

    def test_delay_after_delivery_remains_inside_interval(self):
        row, text = self.run_peer(delay=True)
        observer.observe(row, text, 'absent', False)
        self.assertGreaterEqual(row['blocking_barrier']['release_elapsed_ns'], 500_000_000)

    def test_early_completion_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'released before the host barrier'):
            self.run_peer('early')

    def test_failure_while_held_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.run_peer('fail')

    def test_missing_real_confirmation_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'failed before observation'):
            self.run_peer('unconfirmed')


if __name__ == '__main__':
    unittest.main()
