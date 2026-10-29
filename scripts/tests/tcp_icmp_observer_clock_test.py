# SPDX-License-Identifier: GPL-3.0-or-later
"""Check native queue delivery against two original packet observation points."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_capture_clock import bind_native_clock
from tcp_capture_link import ethernet_records, fnv
from tcp_icmp_capture import (audit_driver_receipt_clocks, audit_native_observer_clocks,
                              capture_receipts)

FIXTURE = Path(__file__).parent / 'fixtures/icmp-observer-clock'


def fixture(text=None):
    manifest = json.loads((FIXTURE / 'manifest.json').read_text())
    for name, value in manifest['files'].items():
        raw = (FIXTURE / name).read_bytes()
        assert len(raw) == value['bytes'] and hashlib.sha256(raw).hexdigest() == value['sha256']
    original = list(ethernet_records(FIXTURE / manifest['capture']))
    rows = [original[index] for index in manifest['selected_physical_record_indices']]
    statistics = json.loads((FIXTURE / 'capture-statistics.json').read_text())
    bind_native_clock(FIXTURE / manifest['capture'], rows, statistics, include_realtime=True)
    text = (FIXTURE / 'serial.log').read_text() if text is None else text
    receipts = capture_receipts(text)
    assert len(rows) == len(receipts) == 2
    for row in rows:
        receipt, = [value for value in receipts if value['digest'] == fnv(row['frame'])]
        row.update(receipt)
        row['outgoing'] = row['frame'][6:12] == bytes.fromhex('525400123410')
    return rows, receipts, text


def verify(text, native=True):
    rows, receipts, _ = fixture(text)
    audit_driver_receipt_clocks(receipts, native)
    if native:
        audit_native_observer_clocks(rows)


class ObserverClock(unittest.TestCase):
    candidates = []

    def test_original_delivery_reverses_arrival_order(self):
        rows, receipts, text = fixture()
        self.assertGreater(receipts[0]['packet_realtime_ns'], receipts[1]['packet_realtime_ns'])
        self.assertLess(receipts[0]['dequeue_ms'], receipts[1]['dequeue_ms'])
        verify(text)

    def test_realtime_metadata_is_opt_in_and_preserves_originals(self):
        manifest = json.loads((FIXTURE / 'manifest.json').read_text())
        source = list(ethernet_records(FIXTURE / manifest['capture']))
        original = [source[index] for index in manifest['selected_physical_record_indices']]
        statistics = json.loads((FIXTURE / 'capture-statistics.json').read_text())
        ordinary, detailed = deepcopy(original), deepcopy(original)
        before = bind_native_clock(FIXTURE / manifest['capture'], ordinary, statistics)
        after = bind_native_clock(FIXTURE / manifest['capture'], detailed, statistics, include_realtime=True)
        self.assertEqual(before, after)
        clocks = [json.loads(line) for line in
                  (FIXTURE / statistics['monotonic_receipts']).read_text().splitlines()]
        for index, (plain, exact) in enumerate(zip(ordinary, detailed)):
            self.assertNotIn('capture_realtime_ns', plain)
            self.assertEqual(exact['capture_realtime_ns'],
                             clocks[original[index]['record_index']]['kernel_realtime_ns'])
            self.assertEqual({key: value for key, value in exact.items()
                              if key != 'capture_realtime_ns'}, plain)

    def reject(self, label, text, native, expected):
        with self.assertRaisesRegex(ValueError, expected):
            verify(text, native)
        self.candidates.append(dict(label=label, text=text, native=native, expected=expected))

    def test_guest_arrival_order_stays_required(self):
        _, _, text = fixture()
        self.reject('guest-order', text, False, 'ordered guest driver packet clocks')

    def test_reversed_dequeue_is_rejected(self):
        _, receipts, text = fixture()
        line = next(value for value in text.splitlines() if 'hash=' + receipts[0]['digest'] in value)
        changed = re.sub(r'dequeue_ms=\d+', 'dequeue_ms=' + str(receipts[1]['dequeue_ms'] + 1), line)
        self.reject('dequeue-order', text.replace(line, changed, 1), True,
                    'ordered native driver dequeue clocks')

    def test_both_physical_directions_own_their_clocks(self):
        rows, _, text = fixture()
        anchor = re.search(r'phase=begin monotonic_before_ns=(\d+) realtime_ns=(\d+) '
                           r'monotonic_after_ns=(\d+)', text)
        before, realtime, after = map(int, anchor.groups())
        for outgoing in (False, True):
            row, = [value for value in rows if value['outgoing'] == outgoing]
            changed_rt = row['capture_realtime_ns'] + (1 if outgoing else -1)
            mapped = changed_rt - realtime + before + (after - before) // 2
            line = next(value for value in text.splitlines() if 'hash=' + row['digest'] in value)
            changed = re.sub(r'packet_realtime_ns=\d+', 'packet_realtime_ns=' + str(changed_rt), line)
            changed = re.sub(r'monotonic_ms=\d+', 'monotonic_ms=' + str(mapped // 1000000), changed)
            expected = ('native outgoing driver stamp precedes independent receive' if outgoing else
                        'native incoming driver stamp follows independent transmit')
            self.reject('outgoing-clock' if outgoing else 'incoming-clock',
                        text.replace(line, changed, 1), True, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path)
    args, remaining = parser.parse_known_args()
    result = unittest.TextTestRunner(verbosity=2 if '-v' in remaining else 1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ObserverClock))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.archive:
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.archive, 'x', zipfile.ZIP_DEFLATED) as saved:
            for candidate in ObserverClock.candidates:
                saved.writestr(candidate['label'] + '/serial.log', candidate['text'])
                saved.writestr(candidate['label'] + '/case.json', json.dumps(
                    {key: value for key, value in candidate.items() if key != 'text'}) + '\n')
        with tempfile.TemporaryDirectory(prefix='icmp-observer-clocks-') as temporary:
            root = Path(temporary)
            with zipfile.ZipFile(args.archive) as saved:
                saved.extractall(root)
            for folder in root.iterdir():
                candidate = json.loads((folder / 'case.json').read_text())
                try:
                    verify((folder / 'serial.log').read_text(), candidate['native'])
                except ValueError as error:
                    if str(error) != candidate['expected']:
                        raise AssertionError('reopened observer clock rejection changed') from error
                else:
                    raise AssertionError('reopened observer clock corruption accepted')
        print('ICMP_OBSERVER_CLOCK_ARCHIVE_PASS cases=' + str(len(ObserverClock.candidates)))


if __name__ == '__main__':
    main()
