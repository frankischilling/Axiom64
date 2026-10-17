# SPDX-License-Identifier: GPL-3.0-or-later
"""Require fresh debugger readiness when a profile reuses an output label."""
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tcp_reconnect_fault as observer


class ObserverReadiness(unittest.TestCase):
    def test_repeated_label_waits_for_the_new_debugger(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-reconnect-readiness-') as temporary:
            directory = Path(temporary)
            clock, ready, saves = [0.0], [False], []
            controller = SimpleNamespace(root=directory, label='repeated-profile', pid=None,
                debug_port=12345, kernel_path=directory / 'kernel.elf',
                peers=[SimpleNamespace(flows=[SimpleNamespace(local_port=49080)])],
                save=lambda: saves.append(ready[0]))
            hold = observer.OutputHold(controller, 0)
            armed = hold.base.with_suffix('.armed')
            armed.write_text('previous observer was ready')

            def start(*args, **kwargs):
                self.assertFalse(armed.exists(), 'old readiness must not release the new payload')
                return SimpleNamespace(pid=123456, poll=lambda: None)

            def sleep(seconds):
                clock[0] += seconds
                if clock[0] >= .02:
                    armed.write_text('new observer is ready')
                    ready[0] = True

            try:
                with patch.object(observer.subprocess, 'Popen', side_effect=start), \
                     patch.object(observer.time, 'monotonic', side_effect=lambda: clock[0]), \
                     patch.object(observer.time, 'sleep', side_effect=sleep):
                    hold.arm()
            finally:
                if hold.stream is not None:
                    hold.stream.close()
            self.assertTrue(ready[0])
            self.assertEqual(saves, [True])


if __name__ == '__main__':
    unittest.main()
