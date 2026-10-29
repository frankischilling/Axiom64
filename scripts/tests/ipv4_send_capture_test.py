# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen actual mixed native retirement output without weakening guest checks."""
from pathlib import Path
import copy
import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_send_wire_capture import verify
from ipv4_send_wire_controls import frame_change
from ipv4_send_wire_records import read


class SendCaptureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'fixtures/ipv4-send-mixed-lifetime.zip'
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            expected = {'client.log', 'results.json', 'provenance.json'}
            expected |= {f'lane{lane}{suffix}' for lane in (0, 1)
                         for suffix in ('.pcap', '.clocks.jsonl', '-frames.json')}
            assert len(names) == len(expected) and set(names) == expected
            assert sum(item.file_size for item in archive.infolist()) < 3 * 1024**2
            cls.original = {name: archive.read(name) for name in names}
        provenance = json.loads(cls.original['provenance.json'])
        assert set(provenance['files']) == expected - {'provenance.json'}
        assert all(hashlib.sha256(cls.original[name]).hexdigest() == value
                   for name, value in provenance['files'].items())

    def audit(self, changes=None, *, native=True):
        files = dict(self.original)
        files.update(changes or {})
        # Serialize every candidate, then reopen it with the production reader.
        with tempfile.TemporaryDirectory(prefix='send-capture-regression-') as temporary:
            directory = Path(temporary)
            saved = directory / 'candidate.zip'
            with zipfile.ZipFile(saved, 'x', zipfile.ZIP_DEFLATED) as archive:
                for name, body in files.items():
                    archive.writestr(name, body)
            fresh = directory / 'reopened'
            fresh.mkdir()
            with zipfile.ZipFile(saved) as archive:
                archive.extractall(fresh)
            metadata = json.loads((fresh / 'results.json').read_bytes())
            records = read((fresh / 'client.log').read_text(), True, metadata['firmware'])
            metadata['native'] = native
            return verify(fresh, metadata, records)

    def changed_packet(self, change=None, *, drop=False):
        """Alter one held packet while retaining every original clock value."""
        files = self.original
        original = files['lane0.pcap']
        self.assertEqual(original[:4], b'\xd4\xc3\xb2\xa1')
        encoded = bytearray(original[:24])
        receipts = [json.loads(line) for line in files['lane0.clocks.jsonl'].splitlines()]
        updated_receipts = []
        at, ordinal, changed = 24, 0, 0
        phase = 1 if drop else 3
        while at < len(original):
            header = original[at:at + 16]
            length = struct.unpack_from('<I', header, 8)[0]
            at += 16
            frame = original[at:at + length]
            at += length
            selected = (len(frame) > 50 and frame[12:14] == b'\x08\0' and
                        frame[42:49] == b'SWIR' + bytes((0, 58, phase)) and frame[50] == 0)
            receipt = copy.deepcopy(receipts[ordinal])
            ordinal += 1
            if selected:
                changed += 1
                if drop:
                    continue
                frame = frame_change(frame, 58, phase, change)
                receipt['sha256'] = hashlib.sha256(frame).hexdigest()
            receipt['frame'] = len(updated_receipts)
            updated_receipts.append(receipt)
            encoded.extend(header + frame)
        self.assertEqual(changed, 1)
        self.assertEqual(ordinal, len(receipts))
        rows = json.loads(files['lane0-frames.json'])
        updated_rows, changed = [], 0
        for row in rows:
            frame = bytes.fromhex(row['data'])
            selected = (len(frame) > 50 and frame[12:14] == b'\x08\0' and
                        frame[42:49] == b'SWIR' + bytes((0, 58, phase)) and frame[50] == 0)
            if selected:
                changed += 1
                if drop:
                    continue
                row['data'] = frame_change(frame, 58, phase, change).hex()
            updated_rows.append(row)
        self.assertEqual(changed, 1)
        clocks = ''.join(json.dumps(row) + '\n' for row in updated_receipts).encode()
        metadata = json.loads(files['results.json'])
        statistics = metadata['capture_statistics'][0]
        statistics['packets'] = statistics['receipt_frames'] = len(updated_receipts)
        statistics['monotonic_receipts_sha256'] = hashlib.sha256(clocks).hexdigest()
        return {'lane0.pcap': bytes(encoded), 'lane0.clocks.jsonl': clocks,
                'lane0-frames.json': json.dumps(updated_rows).encode(),
                'results.json': json.dumps(metadata).encode()}

    def test_actual_native_capture_records_each_retired_selection(self):
        result = self.audit()
        self.assertEqual(result['physical_barriers'], 816)
        self.assertEqual(len(result['retired_route_observations']), 8)
        observed = {(row['lane'], row['case']): row['emitted']
                    for row in result['lifetime_route_observations']}
        expected = {(lane, case): case in (51, 54, 57, 60) or (lane == 0 and case == 58)
                    for lane in (0, 1) for case in (51, 52, 54, 55, 57, 58, 60, 61)}
        self.assertEqual(observed, expected)

    def test_retained_native_packet_still_requires_its_original_ttl(self):
        changed = self.changed_packet(lambda frame: frame.__setitem__(22, 38))
        with self.assertRaisesRegex(ValueError, 'actual retained route/source/interface/TTL/TOS'):
            self.audit(changed)

    def test_retained_native_packet_still_requires_its_original_payload(self):
        changed = self.changed_packet(lambda frame: frame.__setitem__(-1, frame[-1] ^ 1))
        with self.assertRaisesRegex(ValueError, 'complete original payload at its required copy point'):
            self.audit(changed)

    def test_mixed_native_output_does_not_allow_a_missing_later_baseline(self):
        with self.assertRaisesRegex(ValueError, 'all original selected/default data packets'):
            self.audit(self.changed_packet(drop=True))

    def test_native_capture_does_not_exempt_a_guest_retired_selection(self):
        with self.assertRaisesRegex(ValueError,
                'a retired FIB selection cannot emit a guest datagram|failed or interrupted send cannot emit a datagram'):
            self.audit(native=False)

    def test_mixed_native_output_still_requires_lossless_capture(self):
        metadata = json.loads(self.original['results.json'])
        metadata['capture_statistics'][0]['dropped'] = 1
        with self.assertRaisesRegex(ValueError, 'complete lossless native capture and clock counts'):
            self.audit({'results.json': json.dumps(metadata).encode()})


if __name__ == '__main__':
    unittest.main()
