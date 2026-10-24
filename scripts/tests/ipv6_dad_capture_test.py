# SPDX-License-Identifier: GPL-3.0-or-later
"""Use actual guest and Linux 7 captures to reject incomplete or changed DAD evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_dad_capture import inspect
from ipv6_dad_damage import controls, LABELS

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
ARCHIVE = None


class ActualDadCapture(unittest.TestCase):
    def fixture(self, name):
        manifest = json.loads((FIXTURES / f'ipv6-dad-{name}.json').read_text())
        for filename, metadata in manifest['files'].items():
            self.assertEqual(Path(filename).name, filename)
            data = (FIXTURES / filename).read_bytes()
            self.assertEqual(len(data), metadata['bytes'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), metadata['sha256'])
        self.assertTrue(manifest['original_packet_timestamps_unchanged'])
        return manifest, (FIXTURES / f'ipv6-dad-{name}.log').read_text()

    def test_complete_actual_guest_and_Linux7_captures(self):
        for name in ('axiom', 'linux7'):
            manifest, text = self.fixture(name)
            for lane in range(2):
                with self.subTest(provider=name, lane=lane):
                    result = inspect(FIXTURES / f'ipv6-dad-{name}-lane{lane}.pcap', lane, text,
                                     linux_vm=manifest['linux_vm'])
                    self.assertTrue(result['passed'])
                    self.assertEqual((result['DAD_probes'], result['conflicts'], result['tentative_inventories']),
                                     (20, 12, 14))
                    self.assertFalse(result['retained_exhausted_prefix_policy'])

    def test_serialized_corruptions_cannot_replace_actual_evidence(self):
        _, text = self.fixture('axiom')
        outcomes = controls(FIXTURES / 'ipv6-dad-axiom-lane0.pcap', 0, text, archive=ARCHIVE)
        self.assertEqual([row['control'] for row in outcomes], list(LABELS))
        self.assertEqual(len(outcomes), 39)
        self.assertTrue(all(row['rejection'] for row in outcomes))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--archive', type=Path)
    arguments, remaining = parser.parse_known_args()
    ARCHIVE = arguments.archive
    unittest.main(argv=[sys.argv[0], *remaining])
