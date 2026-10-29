# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep malicious protocol candidates clock-consistent without modifying originals."""
from collections import Counter, defaultdict, deque
from copy import deepcopy
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import struct
from tcp_capture_clock import ClockEvidenceError, native_clock_offset, raw_records


def reversed_clock_delta(items, path, statistics=None):
    """Reverse both packet and measured read ordering in a copied candidate."""
    assert len(items) >= 3
    delta = items[0]['stamp'] - items[2]['stamp'] - 1
    if statistics is not None:
        path = Path(path)
        encoded = (path.parent / statistics['monotonic_receipts']).read_bytes()
        assert hashlib.sha256(encoded).hexdigest() == statistics['monotonic_receipts_sha256']
        receipts = [json.loads(line) for line in encoded.splitlines()]
        records = list(raw_records(path))
        assert len(records) == len(receipts) == statistics['packets']
        for ordinal in (0, 2):
            item = items[ordinal]
            index = item['record_index']
            assert records[index]['frame'] == item['frame'] and records[index]['stamp'] == item['stamp']
            assert receipts[index]['frame'] == index
        before = receipts[items[0]['record_index']]['receipt_monotonic_ns']
        after = receipts[items[2]['record_index']]['receipt_monotonic_after_ns']
        # Kernel packet stamps and read delays can have different spacing.
        # Reverse the whole observed read interval, including its uncertainty.
        delta = min(delta, (before - after) // 1000 - 1)
        assert after + delta * 1000 < before
    assert items[2]['stamp'] + delta < items[0]['stamp']
    return delta


class MutationClock:
    """Express hostile timing changes in the same clock as the actual auditor."""
    def __init__(self, path, statistics):
        path = Path(path)
        if statistics is None:
            # QEMU uses a 65536-byte snap length. Reuse the guest test reader
            # rather than applying the native writer's narrower format here.
            from tcp_fault_capture_test import records
            data = path.read_bytes()
            endian, entries = records(data)
            self.original = {}
            for offset, _ in entries:
                seconds, micros = struct.unpack_from(endian + 'II', data, offset)
                self.original[offset] = (seconds * 1000000 + micros) / 1000
            self.times = dict(self.original)
            return
        packets = list(raw_records(path))
        if statistics is not None:
            data = (path.parent / statistics['monotonic_receipts']).read_bytes()
            assert hashlib.sha256(data).hexdigest() == statistics['monotonic_receipts_sha256']
            receipts = [json.loads(line) for line in data.splitlines()]
            assert len(receipts) == len(packets)
        else:
            receipts = [None] * len(packets)
        translation, _ = native_clock_offset([*receipts, statistics['clock_start'], statistics['clock_end']])
        self.times, self.original = {}, {}
        offset = 24
        for packet, receipt in zip(packets, receipts):
            self.original[offset] = packet['stamp'] / 1000
            self.times[offset] = ((receipt['kernel_realtime_ns'] - translation) / 1000000 if receipt else
                                  self.original[offset])
            offset += 16 + len(packet['frame'])

    def milliseconds(self, offset):
        return self.times[offset]

    def pcap_ms(self, offset, desired):
        return None if desired is None else self.original[offset] + desired - self.times[offset]


def reordered_frame_owners(packets, changed):
    """Keep exact records and moved unchanged frames with their own receipts."""
    if Counter(packet['frame'] for packet in packets) != Counter(packet['frame'] for packet in changed):
        return None
    exact = defaultdict(deque)
    for owner, packet in enumerate(packets):
        exact[packet['stamp'], packet['frame']].append(owner)
    owners = []
    for packet in changed:
        matches = exact[packet['stamp'], packet['frame']]
        owners.append(matches.popleft() if matches else None)
    unused = set(range(len(packets))) - {owner for owner in owners if owner is not None}
    remaining = defaultdict(deque)
    for owner in sorted(unused):
        remaining[packets[owner]['frame']].append(owner)
    for index, owner in enumerate(owners):
        if owner is None:
            owners[index] = remaining[changed[index]['frame']].popleft()
    return owners


def candidate_verifier(verifier, original, statistics, *, reschedule_reordered=False):
    original = Path(original)
    if statistics is None:
        def guest(path, lane, evidence, native=False):
            assert not native, 'native protocol controls require original receipt statistics'
            return verifier(path, lane, evidence, native)
        return guest
    packets = list(raw_records(original))
    sidecar = original.parent / statistics['monotonic_receipts']
    encoded = sidecar.read_bytes()
    assert hashlib.sha256(encoded).hexdigest() == statistics['monotonic_receipts_sha256']
    receipts = [json.loads(line) for line in encoded.splitlines()]
    assert len(packets) == len(receipts) == statistics['packets']
    tokens = [(packet['stamp'], packet['frame']) for packet in packets]

    def check(path, lane, evidence, native=False):
        path = Path(path)
        if not native:
            return verifier(path, lane, evidence, False)
        if path.resolve() == original.resolve():
            return verifier(path, lane, evidence, True, statistics)
        clock_path = path.parent / sidecar.name
        assert clock_path.resolve() != sidecar.resolve(), 'candidate clocks cannot overwrite original observations'
        clock_path.write_bytes(encoded)
        try:
            changed = list(raw_records(path))
        except ValueError:
            # Let the original protocol reader diagnose truncated/malformed
            # captures before any clock binding; do not fabricate a repair.
            return verifier(path, lane, evidence, True, statistics)
        reordered = False
        if len(changed) == len(packets):
            owners = reordered_frame_owners(packets, changed)
            if owners is None:
                owners = list(range(len(packets)))
            else:
                reordered = owners != list(range(len(packets)))
        else:
            owners = [None] * len(changed)
            changed_tokens = [(packet['stamp'], packet['frame']) for packet in changed]
            for kind, left, end, start, stop in SequenceMatcher(None, tokens, changed_tokens, autojunk=False).get_opcodes():
                for index in range(start, stop):
                    owners[index] = (left + index - start if kind == 'equal' else
                                     min(left + index - start, end - 1) if end > left else max(0, left - 1))
                    if kind == 'replace':
                        # Protocol readers may omit unrelated ARP or IPv6 records.
                        # A changed TCP frame still owns its original timestamp,
                        # rather than the first omitted frame in this block.
                        matching = [owner for owner in range(left, end)
                                    if packets[owner]['stamp'] == changed[index]['stamp']]
                        if len(matching) == 1:
                            owners[index] = matching[0]
        values, timing_changed = [], False
        for index, (packet, owner) in enumerate(zip(changed, owners)):
            assert owner is not None
            receipt = deepcopy(receipts[owner])
            delta = (packet['stamp'] - packets[owner]['stamp']) * 1000
            timing_changed |= bool(delta)
            receipt.update(frame=index, sha256=hashlib.sha256(packet['frame']).hexdigest())
            for field in ('kernel_realtime_ns', 'receipt_monotonic_ns', 'receipt_realtime_ns',
                          'receipt_monotonic_after_ns'):
                receipt[field] += delta
            values.append(receipt)
        if timing_changed and reordered and reschedule_reordered:
            # A reordered candidate may put packets closer than their original
            # read delays. Delay only copied receipt pairs, preserving their
            # clock offset and every candidate kernel packet timestamp.
            for previous, receipt in zip(values, values[1:]):
                delay = previous['receipt_monotonic_ns'] - receipt['receipt_monotonic_ns']
                if delay > 0:
                    for field in ('receipt_monotonic_ns', 'receipt_realtime_ns',
                                  'receipt_monotonic_after_ns'):
                        receipt[field] += delay
        data = ''.join(json.dumps(value) + '\n' for value in values).encode()
        clock_path.write_bytes(data)
        metadata = deepcopy(statistics)
        metadata.update(packets=len(values), receipt_frames=len(values),
                        monotonic_receipts_sha256=hashlib.sha256(data).hexdigest())
        if timing_changed:
            # Synthetic timing candidates retain a coherent capture bracket;
            # the original producer's anchors and receipts remain untouched.
            start, end = metadata['clock_start'], metadata['clock_end']
            early = min(0, min(row['receipt_monotonic_ns'] for row in values) -
                        start['receipt_monotonic_after_ns'],
                        min(row['kernel_realtime_ns'] for row in values) - start['receipt_realtime_ns'])
            late = max(0, max(row['receipt_monotonic_after_ns'] for row in values) -
                       end['receipt_monotonic_ns'],
                       max(row['kernel_realtime_ns'] for row in values) - end['receipt_realtime_ns'])
            for anchor, delta in ((start, early), (end, late)):
                for field in anchor:
                    anchor[field] += delta
        check.timing_changed = timing_changed
        try:
            return verifier(path, lane, evidence, True, metadata)
        except ClockEvidenceError as error:
            # Packet-semantic controls must reach their protocol checks. Only
            # deliberate timestamp mutations may fail the clock invariants.
            if not timing_changed:
                raise AssertionError(f'protocol candidate has inconsistent clock setup: {error}') from error
            raise
    check.timing_changed = False
    return check


def candidate_auditor(auditor, original_root, original_row, *, reschedule_reordered=False):
    """Repair only test-candidate clock bindings before auditing a copied row."""
    original_root = Path(original_root)
    if 'client_namespace' not in original_row:
        return auditor
    metadata = lambda path, lane, evidence, native=False, statistics=None: statistics
    checks = [candidate_verifier(metadata, original_root / name, statistics,
                                 reschedule_reordered=reschedule_reordered)
              for name, statistics in zip(original_row['captures'], original_row['capture_statistics'])]

    def check(root, row, *args, **kwargs):
        root = Path(root)
        candidate = deepcopy(row)
        candidate['capture_statistics'] = [
            verify(root / name, lane, None, True) for lane, (name, verify) in
            enumerate(zip(candidate['captures'], checks))]
        check.last_row = candidate
        timing_changed = any(verify.timing_changed for verify in checks)
        try:
            return auditor(root, candidate, *args, **kwargs)
        except ClockEvidenceError as error:
            if not timing_changed:
                raise AssertionError(f'protocol candidate has inconsistent clock setup: {error}') from error
            raise
    return check
