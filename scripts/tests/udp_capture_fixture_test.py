# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen actual UDP frames and archived corruptions through the public reader."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
from ipv4_expiry_capture import read_capture, encode_capture
from udp_capture import audit_capture
from udp_capture_test import damage_cases, raw_damage_cases

FIXTURE = Path(__file__).parent / 'fixtures/udp-wire'
ARCHIVE = None


class ActualUDP(unittest.TestCase):
    def test_original_captures_and_recorded_source_epoch(self):
        manifest = json.loads((FIXTURE / 'manifest.json').read_text())
        self.assertEqual(len(manifest['cases']), 2)
        for case in manifest['cases']:
            self.assertTrue(case['original_producer_passed'])
            self.assertFalse(case['full_matrix_acceptance'])
            folder = FIXTURE / ('fault' if case['fault'] else 'normal')
            for name, value in case['files'].items():
                data = (folder / name).read_bytes()
                self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                                 (value['bytes'], value['sha256']))
            for lane in range(2):
                result = audit_capture(folder / f'lane{lane}.pcap', lane, case['fault'])
                self.assertTrue(result['passed'])
                self.assertEqual(result['outgoing_datagrams'], (0 if lane == 0 else 1) if case['fault'] else 103)
                self.assertEqual(result['incoming_frames'], (0 if lane == 0 else 1) if case['fault'] else 97)

    def test_archived_corruptions_reject_after_fresh_extraction(self):
        controls = []
        originals = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in FIXTURE.rglob('*') if path.is_file()}
        with tempfile.TemporaryDirectory(prefix='udp-actual-fixture-') as temporary:
            temporary = Path(temporary)
            archive = ARCHIVE or temporary / 'damaged.zip'
            archive.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
                for fault in (False, True):
                    folder = FIXTURE / ('fault' if fault else 'normal')
                    for lane in range(2):
                        rows = read_capture(folder / f'lane{lane}.pcap')
                        companion = read_capture(folder / 'lane1.pcap')
                        candidates = [(label, encode_capture(changed), expected)
                                      for label, changed, expected in damage_cases(rows, lane, fault, companion)]
                        candidates += raw_damage_cases((folder / f'lane{lane}.pcap').read_bytes())
                        for label, data, expected in candidates:
                            candidate = temporary / 'candidate.pcap'
                            candidate.write_bytes(data)
                            with self.assertRaises(ValueError) as rejection:
                                audit_capture(candidate, lane, fault)
                            reason = str(rejection.exception)
                            if expected is not None:
                                self.assertIn(expected, reason)
                            name = ('fault' if fault else 'normal') + f'-lane{lane}-' + label
                            value = dict(lane=lane, fault=fault, expected=reason,
                                         sha256=hashlib.sha256(data).hexdigest())
                            saved.writestr(name + '/capture.pcap', data)
                            saved.writestr(name + '/case.json', json.dumps(value) + '\n')
                            controls.append(name)
            self.assertEqual(len(controls), 244)
            fresh = temporary / 'fresh'
            with zipfile.ZipFile(archive) as saved:
                self.assertIsNone(saved.testzip())
                saved.extractall(fresh)
            for name in controls:
                folder = fresh / name
                value = json.loads((folder / 'case.json').read_text())
                candidate = folder / 'capture.pcap'
                self.assertEqual(hashlib.sha256(candidate.read_bytes()).hexdigest(), value['sha256'])
                with self.assertRaises(ValueError) as rejection:
                    audit_capture(candidate, value['lane'], value['fault'])
                self.assertEqual(str(rejection.exception), value['expected'])
        self.assertTrue(all(hashlib.sha256(Path(name).read_bytes()).hexdigest() == value
                            for name, value in originals.items()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--archive', type=Path)
    arguments, remaining = parser.parse_known_args()
    ARCHIVE = arguments.archive
    unittest.main(argv=[sys.argv[0], *remaining])
