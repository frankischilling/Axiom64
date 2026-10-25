# SPDX-License-Identifier: GPL-3.0-or-later
"""Match untouched native PCAP records to independently observed monotonic receipts."""
from collections import defaultdict, deque
import hashlib
import itertools
import json
from pathlib import Path
import re
import struct


class ClockEvidenceError(ValueError):
    pass


def require(value, reason):
    if not value:
        raise ClockEvidenceError(reason)


def raw_records(path):
    with Path(path).open('rb') as source:
        header = source.read(24)
        require(len(header) == 24 and header[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'),
                'native clock PCAP header')
        endian = '<' if header[:4] == b'\xd4\xc3\xb2\xa1' else '>'
        version, minor, _, _, snap, link = struct.unpack_from(endian + 'HHIIII', header, 4)
        require((version, minor, link) == (2, 4, 1) and 1514 <= snap <= 65535,
                'native clock Ethernet PCAP format')
        count = 0
        while True:
            header = source.read(16)
            if not header:
                break
            require(len(header) == 16, 'complete native clock PCAP record')
            seconds, micros, size, original = struct.unpack(endian + 'IIII', header)
            require(micros < 1000000 and 14 <= size == original <= snap,
                    'complete original native clock frame bounds')
            frame = source.read(size)
            require(len(frame) == size, 'complete original native clock frame')
            yield dict(stamp=seconds * 1000000 + micros, frame=frame)
            count += 1
        require(count, 'nonempty original native clock capture')


def native_clock_offset(receipts):
    """Choose one translation supported by every paired clock observation."""
    lower = max(row['receipt_realtime_ns'] - row['receipt_monotonic_after_ns'] for row in receipts)
    upper = min(row['receipt_realtime_ns'] - row['receipt_monotonic_ns'] for row in receipts)
    require(lower <= upper, 'one stable native realtime-to-monotonic offset')
    return (lower + upper) // 2, upper - lower

def bind_native_clock(path, rows, statistics, *, include_realtime=False):
    """Attach monotonic_ns without changing decoded frame, stamp or ms fields.

    Opting into include_realtime also exposes the exact validated capture
    timestamp, without changing the default decoded records.

    Every raw frame remains bound to its original kernel timestamp and receipt.
    One constant clock translation preserves every kernel packet interval.
    Latency checks apply to the decoded workload, preserving existing exclusions
    for unrelated IPv6 control traffic whose timestamps may predate veth delivery.
    """
    path = Path(path)
    require(isinstance(statistics, dict) and statistics.get('original_packet_times_not_rescaled') is True,
            'native capture has original packet clocks and independent receipts')
    name = statistics.get('monotonic_receipts')
    require(isinstance(name, str) and name and Path(name).name == name and
            '/' not in name and '\\' not in name and name.endswith('.clocks.jsonl'),
            'bounded independent native clock receipt path')
    receipt_path = path.parent / name
    require(receipt_path.is_file() and not receipt_path.is_symlink(), 'original native clock receipt file')
    encoded = receipt_path.read_bytes()
    require(hashlib.sha256(encoded).hexdigest() == statistics.get('monotonic_receipts_sha256'),
            'exact original native clock receipt fingerprint')
    for key in ('packets', 'dropped', 'receipt_frames'):
        require(type(statistics.get(key)) is int and statistics[key] >= 0,
                'integer native capture and clock counts')
    require(statistics['dropped'] == 0 and statistics['packets'] == statistics['receipt_frames'] > 0,
            'complete lossless native capture and clock counts')
    receipts = encoded.splitlines()
    require(len(receipts) == statistics['receipt_frames'], 'one native receipt for every captured frame')
    anchors = []
    clock_keys = {'receipt_monotonic_ns', 'receipt_realtime_ns', 'receipt_monotonic_after_ns'}
    for name in ('clock_start', 'clock_end'):
        anchor = statistics.get(name)
        require(isinstance(anchor, dict) and set(anchor) == clock_keys and
                all(type(anchor[key]) is int and anchor[key] >= 0 for key in clock_keys),
                'native capture has paired clock anchors')
        before, after = anchor['receipt_monotonic_ns'], anchor['receipt_monotonic_after_ns']
        require(before <= after and after - before <= 100000000,
                'ordered bounded native capture clock anchors')
        anchors.append(anchor)
    start, end = anchors
    require(start['receipt_monotonic_after_ns'] <= end['receipt_monotonic_ns'],
            'ordered native capture clock bracket')
    by_frame = defaultdict(deque)
    observations = []
    previous, first_offset, last_offset, count = None, None, None, 0
    keys = {'frame', 'sha256', 'kernel_realtime_ns', 'receipt_monotonic_ns',
            'receipt_realtime_ns', 'receipt_monotonic_after_ns'}
    for index, (packet, encoded_receipt) in enumerate(itertools.zip_longest(raw_records(path), receipts)):
        require(packet is not None and encoded_receipt is not None,
                'one native receipt for every original PCAP record')
        receipt = json.loads(encoded_receipt)
        require(isinstance(receipt, dict) and set(receipt) == keys,
                'complete independent native clock receipt fields')
        require(all(type(receipt[key]) is int and receipt[key] >= 0 for key in keys - {'sha256'}),
                'integer independent native clock observations')
        require(receipt['frame'] == index and isinstance(receipt['sha256'], str) and
                re.fullmatch('[0-9a-f]{64}', receipt['sha256']) and
                hashlib.sha256(packet['frame']).hexdigest() == receipt['sha256'],
                'one exact original frame per independent native receipt')
        require(receipt['kernel_realtime_ns'] // 1000 == packet['stamp'],
                'unchanged original native kernel packet timestamp')
        before, after = receipt['receipt_monotonic_ns'], receipt['receipt_monotonic_after_ns']
        require(before <= after and after - before <= 100000000 and
                (previous is None or before >= previous), 'ordered bounded native monotonic receipt pairs')
        require(start['receipt_monotonic_after_ns'] <= before <= after <= end['receipt_monotonic_ns'],
                'every native receipt lies inside its capture clock bracket')
        previous = before
        offset = receipt['receipt_realtime_ns'] - before
        if first_offset is None:
            first_offset = offset
        last_offset = offset
        by_frame[(packet['stamp'], receipt['sha256'])].append(receipt)
        observations.append(receipt)
        count += 1
    require(count == statistics['packets'], 'actual native capture count matches its clock records')
    offset, uncertainty = native_clock_offset([*anchors, *observations])
    delays = []
    for row in rows:
        require(type(row.get('stamp')) is int and isinstance(row.get('frame'), bytes),
                'decoded native frame retains its original PCAP timestamp')
        key = row['stamp'], hashlib.sha256(row['frame']).hexdigest()
        require(key in by_frame and by_frame[key], 'every decoded native workload packet has one independent receipt')
        receipt = by_frame[key].popleft()
        require(start['receipt_realtime_ns'] <= receipt['kernel_realtime_ns'] <= end['receipt_realtime_ns'],
                'every native workload packet lies inside its capture clock bracket')
        delay = receipt['receipt_realtime_ns'] - receipt['kernel_realtime_ns']
        require(0 <= delay <= 1000000000, 'bounded independent native workload reader latency')
        # Reader scheduling can delay or batch recvmsg returns. It must not
        # enlarge or compress the independently captured wire interval.
        row['monotonic_ns'] = receipt['kernel_realtime_ns'] - offset
        if include_realtime:
            row['capture_realtime_ns'] = receipt['kernel_realtime_ns']
        delays.append(delay)
    require(delays, 'nonempty independently timed native workload')
    return dict(frames=count, timed_frames=len(delays),
                realtime_to_monotonic_offset_ns=offset, offset_uncertainty_ns=uncertainty,
                max_reader_latency_ms=max(delays) / 1000000,
                realtime_offset_change_ms=(last_offset - first_offset) / 1000000,
                original_packet_times_not_rescaled=True)


def microseconds(row):
    if 'monotonic_ns' in row:
        return row['monotonic_ns'] // 1000
    return row['stamp'] if 'stamp' in row else round(row['ms'] * 1000)


def milliseconds(row):
    if 'monotonic_ns' in row:
        return row['monotonic_ns'] / 1000000
    return row['stamp'] / 1000 if 'stamp' in row else row['ms']
