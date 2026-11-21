# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual TCG observation and reject fabricated or mismatched acceleration evidence."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guest_kernel_test import run_build_vm
from qemu_acceleration import Acceleration
from qmp import Qmp


class Monitor:
    def __init__(self, state):
        self.state = state

    def command(self, name):
        assert name == 'query-kvm'
        return self.state


class AcceleratorEvidence(unittest.TestCase):
    def test_default_is_tcg_and_invalid_configuration_fails(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertEqual(Acceleration().requested, 'tcg')
        with patch.dict('os.environ', {'AXIOM64_QEMU_ACCELERATOR': 'bogus'}):
            with self.assertRaises(ValueError):
                Acceleration()

    def test_required_acceleration_cannot_be_relabelled(self):
        for requested, enabled in (('kvm', False), ('tcg', True)):
            with self.assertRaisesRegex(ValueError, 'required configuration'):
                Acceleration(requested).observe(Monitor(dict(enabled=enabled, present=True)))

    def test_auto_records_actual_choice_and_rejects_incomplete_state(self):
        for enabled in (True, False):
            result = Acceleration('auto').observe(Monitor(dict(enabled=enabled, present=True)))
            self.assertEqual(result['used'], 'kvm' if enabled else 'tcg')
            self.assertEqual(result['requested'], 'auto')
        for state in ({}, {'enabled': 1, 'present': True}, {'enabled': False}, None):
            with self.assertRaisesRegex(ValueError, 'valid accelerator state'):
                Acceleration('auto').observe(Monitor(state))

    def test_real_tcg_monitor_records_the_initialized_accelerator(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-accel-') as directory:
            control = Path(directory) / 'qmp.sock'
            acceleration = Acceleration('tcg')
            command = ['qemu-system-x86_64', '-machine', acceleration.machine, '-cpu', 'max',
                       '-m', '32M', '-nodefaults', '-display', 'none', '-S',
                       '-qmp', f'unix:{control},server=on,wait=off']
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            monitor = None
            try:
                deadline = time.monotonic() + 5
                while not control.exists():
                    self.assertIsNone(process.poll(), process.stderr.read() if process.poll() is not None else '')
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.01)
                monitor = Qmp(control)
                self.assertEqual(acceleration.observe(monitor)['used'], 'tcg')
                monitor.command('quit')
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if monitor:
                    monitor.close()
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stderr.close()

    def test_build_vm_uses_the_reported_auto_accelerator_to_run_guest_code(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-build-accel-') as directory:
            disk = Path(directory) / 'boot.img'
            # The BIOS boot sector writes 0x2e to the debug-exit port.
            instructions = bytes.fromhex('ba f4 00 66 b8 2e 00 00 00 66 ef f4')
            disk.write_bytes(instructions.ljust(510, b'\0') + b'\x55\xaa')
            serial = Path(directory) / 'build-serial.log'
            acceleration = Acceleration('auto')
            command = ['qemu-system-x86_64', '-machine', acceleration.machine, '-cpu', 'max',
                       '-smp', '2', '-m', '64M', '-boot', 'a', '-nic', 'none',
                       '-drive', f'if=floppy,format=raw,readonly=on,file={disk}',
                       '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
                       '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            status, _ = run_build_vm(command, serial, acceleration, 10)
            self.assertEqual(status, 93, serial.read_text(errors='replace'))
            report = json.loads((serial.parent / 'build-accelerator.json').read_text())
            self.assertEqual(report, acceleration.evidence)
            self.assertEqual(report['requested'], 'auto')
            self.assertIn(report['used'], ('kvm', 'tcg'))


if __name__ == '__main__':
    unittest.main()
