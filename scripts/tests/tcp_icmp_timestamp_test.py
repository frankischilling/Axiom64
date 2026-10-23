# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the packet-arrival clock reader independently of dequeue scheduling."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_icmp_capture import capture_receipts, within


class PacketArrivalClock(unittest.TestCase):
    def log(self, arrival=54650000000, dequeue=54870):
        # Reader-only clock fixture reproducing the delayed-read relationship.
        # It is not a substitute for an actual packet capture or execution.
        offset = 1700000000000000000
        return (
            f'ICMP_CAPTURE_CLOCK phase=begin monotonic_before_ns=54000000000 '
            f'realtime_ns={offset + 54000000000} monotonic_after_ns=54000000000\n'
            f'ICMP_FRAME lane=0 index=1 length=70 kind=0 hash=0123456789abcdef '
            f'monotonic_ms={arrival // 1000000} packet_realtime_ns={offset + arrival} '
            f'dequeue_ms={dequeue}\n'
            f'ICMP_CAPTURE_CLOCK phase=end monotonic_before_ns=55000000000 '
            f'realtime_ns={offset + 55000000000} monotonic_after_ns=55000000000\n')

    def test_delayed_dequeue_uses_queued_arrival(self):
        receipt, = capture_receipts(self.log())
        self.assertEqual(receipt['driver_ms'], 54650)
        self.assertEqual(receipt['dequeue_ms'], 54870)
        self.assertTrue(within(receipt, 54580, 54760))
        self.assertFalse(within(dict(receipt, driver_lower_ms=54870,
                                     driver_upper_ms=54870), 54580, 54760))

    def test_actual_late_arrival_still_fails_original_window(self):
        receipt, = capture_receipts(self.log(arrival=54870000000))
        self.assertFalse(within(receipt, 54580, 54760))

    def test_logged_mapping_cannot_be_replaced_with_dequeue(self):
        with self.assertRaisesRegex(ValueError, 'packet arrival mapping'):
            capture_receipts(self.log().replace('monotonic_ms=54650', 'monotonic_ms=54870'))

    def test_wall_step_and_missing_anchors_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'stable packet arrival clock'):
            capture_receipts(self.log().replace('1700000055000000000', '1700000055001000000'))
        with self.assertRaisesRegex(ValueError, 'both packet arrival clock anchors'):
            capture_receipts(self.log().split('\n', 1)[1])

    def test_future_arrival_and_legacy_receipt_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'arrival precedes dequeue'):
            capture_receipts(self.log(dequeue=54640))
        text = self.log().replace(' packet_realtime_ns=1700000054650000000 dequeue_ms=54870', '')
        with self.assertRaisesRegex(ValueError, 'complete packet arrival receipts'):
            capture_receipts(text)

    def test_complete_uncertainty_interval_must_fit(self):
        self.assertFalse(within(dict(driver_lower_ms=54579, driver_upper_ms=54650),
                                54580, 54760))
        self.assertFalse(within(dict(driver_lower_ms=54650, driver_upper_ms=54761),
                                54580, 54760))


if __name__ == '__main__':
    unittest.main()
