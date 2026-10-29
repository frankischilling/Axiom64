# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise hot removal while a stopped guest has a PCI read in progress."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from manager_link_hardware import Hardware


class StoppedGuest:
    def __init__(self, affected, transport, address):
        self.affected = affected
        self.address = self.saved_address = address
        self.identities = [0x10411af4 if transport == 'modern' else 0x10001af4, 0x100e8086]
        self.pending = self.removed = self.stopped = False
        self.events = []
        self.response = b''
        self.enumeration_error = False
        self.resumed_address = None

    def command(self, name, arguments=None):
        self.events.append(name)
        if name == 'stop':
            self.stopped = True
        elif name == 'cont':
            self.resumed_address = self.address
            self.stopped = False
        elif name == 'device_del':
            self.pending = True
        elif name == 'query-pci':
            if self.enumeration_error:
                raise RuntimeError('enumeration failed')
            return [{'devices': [{'slot': 5 - self.affected}]}]
        else:
            raise AssertionError(name)

    def write(self, data):
        self.assert_stopped()
        words = data.decode().split()
        operation, port = words[0], int(words[1], 0)
        self.events.append(data.decode().strip())
        result = 'OK'
        if operation == 'inl' and port == 0xcf8:
            result += f' {self.address:#x}'
        elif operation == 'inl' and port == 0xcfc:
            lane = ((self.address >> 11) & 31) - 4
            value = 0xffffffff if self.removed and lane == self.affected else self.identities[lane]
            result += f' {value:#x}'
        elif operation == 'outl' and port == 0xcf8:
            self.address = int(words[2], 0)
        elif operation == 'outl' and port == 0xae08:
            assert self.pending and int(words[2], 0) == 1 << (self.affected + 4)
            self.removed = True
        else:
            assert operation == 'outl' and port == 0xae0c and int(words[2], 0) == 0
        self.response = (result + '\n').encode()

    def assert_stopped(self):
        if not self.stopped:
            raise AssertionError('fixture must preserve state while the guest is stopped')

    def flush(self):
        pass

    def readline(self):
        return self.response


class RemovalTests(unittest.TestCase):
    def test_carrier_receipts_require_the_actual_qmp_acknowledgment(self):
        class Monitor:
            def __init__(self, result):
                self.result, self.calls = result, []

            def command(self, name, arguments):
                self.calls.append((name, arguments))
                return self.result

        for lane in (0, 1):
            for up in (False, True):
                with self.subTest(lane=lane, up=up):
                    hardware = Hardware.__new__(Hardware)
                    hardware.affected, hardware.records = lane, []
                    hardware.monitor = Monitor({})
                    hardware.carrier(up)
                    self.assertEqual(hardware.monitor.calls,
                                     [('set_link', dict(name=f'nic{lane}', up=up))])
                    self.assertEqual(hardware.records[0]['qmp_result'], {})
                    for invalid in (None, True, {'unexpected': 1}):
                        hardware.monitor = Monitor(invalid)
                        hardware.records = []
                        with self.assertRaisesRegex(RuntimeError, 'carrier command succeeded'):
                            hardware.carrier(up)
                        self.assertEqual(hardware.records, [])

    def fixture(self, affected=1, transport='modern', address=0x80002000):
        guest = StoppedGuest(affected, transport, address)
        hardware = Hardware.__new__(Hardware)
        hardware.monitor = hardware.stream = guest
        hardware.affected, hardware.transport = affected, transport
        hardware.records = []
        return hardware, guest

    def test_interrupted_guest_read_resumes_with_original_pci_address(self):
        for affected in (0, 1):
            for transport in ('modern', 'legacy'):
                for address in (0, 0x80002000, 0x80002800, 0x8000210c):
                    with self.subTest(affected=affected, transport=transport, address=address):
                        hardware, guest = self.fixture(affected, transport, address)
                        hardware.remove()
                        self.assertEqual(guest.resumed_address, guest.saved_address)
                        self.assertTrue(guest.removed)
                        self.assertFalse(guest.stopped)
                        removal = next(row for row in hardware.records if row.get('operation') == 'remove')
                        self.assertEqual(removal['after'][affected], 0xffffffff)
                        self.assertEqual(removal['after'][1 - affected], removal['before'][1 - affected])

    def test_verified_removal_can_keep_the_command_observer_stopped(self):
        for affected in (0, 1):
            for transport in ('modern', 'legacy'):
                with self.subTest(affected=affected, transport=transport):
                    hardware, guest = self.fixture(affected, transport, 0x8000210c)
                    hardware.remove(resume=False)
                    self.assertTrue(guest.removed)
                    self.assertTrue(guest.stopped)
                    self.assertEqual(guest.address, guest.saved_address)
                    self.assertIsNone(guest.resumed_address)
                    guest.command('cont')
                    self.assertFalse(guest.stopped)
                    self.assertEqual(guest.resumed_address, guest.saved_address)

    def test_failed_deferred_removal_still_restores_and_resumes(self):
        hardware, guest = self.fixture(address=0x8000210c)
        guest.enumeration_error = True
        with self.assertRaisesRegex(RuntimeError, 'enumeration failed'):
            hardware.remove(resume=False)
        self.assertFalse(guest.stopped)
        self.assertEqual(guest.resumed_address, guest.saved_address)

    def test_failed_enumeration_preserves_interrupted_read_before_resuming(self):
        hardware, guest = self.fixture()
        guest.enumeration_error = True
        with self.assertRaisesRegex(RuntimeError, 'enumeration failed'):
            hardware.remove()
        self.assertEqual(guest.resumed_address, guest.saved_address)
        self.assertFalse(guest.stopped)

    def test_rejected_identity_preserves_interrupted_read_before_resuming(self):
        hardware, guest = self.fixture(address=0x80002800)
        guest.identities[0] = 0xffff
        with self.assertRaisesRegex(RuntimeError, 'identities match'):
            hardware.remove()
        self.assertEqual(guest.resumed_address, guest.saved_address)
        self.assertFalse(guest.stopped)


if __name__ == '__main__':
    unittest.main()
