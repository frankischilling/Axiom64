# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen real native and UEFI device evidence, including serialized damage."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_device_capture import inspect
from ipv6_device_damage import controls, GUEST_CONTROLS

FIXTURES = Path(__file__).resolve().parent / 'fixtures/ipv6-device'
ARCHIVE = None


class ActualDeviceCapture(unittest.TestCase):
    def fixture(self, label):
        manifest = json.loads((FIXTURES / 'manifest.json').read_text())
        self.assertEqual(manifest['schema'], 1)
        value = manifest['cases'][label]
        self.assertTrue(value['independently_opened_and_qualified'])
        self.assertTrue(value['original_packet_and_serial_bytes_unchanged'])
        self.assertFalse(value['full_F12_complete'])
        for name, record in value['files'].items():
            self.assertEqual(Path(name).name, name)
            data = (FIXTURES / label / name).read_bytes()
            self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                             (record['bytes'], record['sha256']))
        return FIXTURES / label, value

    def test_actual_native_and_guest_device_transitions(self):
        for provider in ('linux7', 'axiom'):
            for action in ('administrative', 'mtu', 'carrier'):
                with self.subTest(provider=provider, action=action):
                    directory, value = self.fixture(provider + '-' + action)
                    statistics = json.loads((directory / 'statistics.json').read_text()) if value['native'] else None
                    for lane in range(2):
                        result = inspect(directory / f'lane{lane}.pcap', lane,
                                         (directory / 'serial.log').read_text(), action,
                                         value['native'], statistics, value['kernel_release'])
                        self.assertTrue(result['passed'])
                        self.assertEqual(result['probes'], 1 if action == 'carrier' else 2)

    def test_serialized_guest_controls_and_real_timing(self):
        for action in ('administrative', 'mtu', 'carrier'):
            with self.subTest(action=action):
                directory, _ = self.fixture('axiom-' + action)
                archive = ARCHIVE.with_name(ARCHIVE.stem + '-' + action + ARCHIVE.suffix) if ARCHIVE else None
                result = controls(directory, action, archive)
                self.assertEqual([row['variant'] for row in result], list(GUEST_CONTROLS))
                rejected = {row['variant']: row['rejection'] for row in result}
                self.assertEqual(rejected['quiet-short'],
                                 'full real four-second unavailable interval follows actual query and ACK')
                self.assertEqual(rejected['DAD-fast'],
                                 'original initial DAD completes within the real one-to-two-point-one-second bound')
                self.assertEqual(rejected['DAD-subsecond'], rejected['DAD-fast'])
                self.assertEqual(rejected['post-BEGIN-firmware'], 'bounded native-only multicast traffic')

    def test_native_original_clock_and_loss_are_required(self):
        directory, value = self.fixture('linux7-carrier')
        for variant in ('timestamp', 'drop'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / 'changed'
                shutil.copytree(directory, target)
                statistics = json.loads((target / 'statistics.json').read_text())
                if variant == 'timestamp':
                    path = target / 'lane0.pcap'
                    data = bytearray(path.read_bytes())
                    seconds = struct.unpack_from('<I', data, 24)[0]
                    struct.pack_into('<I', data, 24, seconds + 1)
                    path.write_bytes(data)
                else:
                    statistics[0]['dropped'] = 1
                with self.assertRaises(ValueError):
                    inspect(target / 'lane0.pcap', 0, (target / 'serial.log').read_text(),
                            'carrier', True, statistics, value['kernel_release'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--archive', type=Path)
    arguments, remaining = parser.parse_known_args()
    ARCHIVE = arguments.archive
    unittest.main(argv=[sys.argv[0], *remaining])
