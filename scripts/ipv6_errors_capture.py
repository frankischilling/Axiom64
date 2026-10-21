# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind actual extended-error bytes and payloads to original transmitted quotes."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import zipfile
from ipv4_expiry_capture import checksum, encode_capture, read_capture
from ipv6_pmtu_capture import inspect as inspect_packets, require, stamp
from tcp_capture_clock import bind_native_clock


def address(lane, host, scoped):
    return ipaddress.IPv6Address(f'fe80::{host:x}' if scoped else f'2001:db8:{lane + 1}::{host:x}').packed


def sockaddr(value, port=0, scope=0):
    return struct.pack('<H', 10) + struct.pack('!H', port) + bytes(4) + value + struct.pack('<I', scope)


def application(log, lane, interface_index):
    require(log.count('IPV6_ERRORS_PASS adapters=2 wire=120 local=30 admission=96 options=26 lifetime=4 vectors=8') == 1 and
            'IPV6_ERRORS_FAIL' not in log, 'actual complete error-queue client')
    for marker in ('IPV6_ERRORS_OPTIONS_PASS cases=26', 'IPV6_ERRORS_LOCAL_PASS cases=30',
                   'IPV6_ERRORS_ADMISSION_PASS cases=96', 'IPV6_ERRORS_LIFETIME_PASS cases=4', 'IPV6_ERRORS_VECTORS_PASS cases=8',
                   f'IPV6_ERRORS_WIRE_PASS lane={lane} cases=60'):
        require(log.count(marker) == 1, 'complete actual local and wire error inventory')
    local = re.findall(r'^IPV6_ERRORS_LOCAL case=(\d+) result=(-?\d+) errno=(\d+) flags=([0-9a-f]+) name=(\d+) control=(\d+)$', log, re.MULTILINE)
    require(len(local) == 30 and {int(row[0]) for row in local} == set(range(30)), 'all actual local receive cases')
    capacities = (0, 15, 16, 20, 59, 60, 61, 63, 64)
    for encoded in local:
        number, result, error = map(int, encoded[:3])
        flags, name, control = int(encoded[3], 16), int(encoded[4]), int(encoded[5])
        expected_error = 22 if number == 18 else 14 if number in (15, 16, 20, 21, 22) else 11 if number == 29 else 0
        expected_result = -1 if expected_error else 3 if number in (1, 2) else 0 if number in (24, 25) else 32
        expected_flags = 0x13579 if expected_error else (0x2000 | (0x40000000 if number == 27 else 0) |
            (0x20 if number in (1, 2, 24, 25) else 0) | (8 if number in (4, 5, 6, 7, 8, 13) else 0))
        expected_control = 128 if expected_error else 0 if number in (4, 5, 13, 14, 23) else capacities[number - 4] if number in range(6, 13) else 64
        require((result, error, flags, name, control) == (expected_result, expected_error, expected_flags,
                4294967295 if number in (18, 19) else 28, expected_control), 'native receive fault and truncation contract')
    vectors = re.findall(r'^IPV6_ERRORS_VECTOR case=(\d+) result=(-?\d+) errno=(\d+) flags=([0-9a-f]+) first=(\d+) events=([0-9a-f]+)$', log, re.MULTILINE)
    require(len(vectors) == 8 and {int(row[0]) for row in vectors} == set(range(8)), 'all actual wide-vector receives')
    for row in vectors:
        number, result, error = map(int, row[:3])
        flags, first, events = int(row[3], 16), int(row[4]), int(row[5], 16)
        success = number in (3, 6)
        require((result, error, flags, first, events) ==
                ((32, 0, 0x2008, 3, 4) if success else (-1, 22 if number in (2, 4, 7) else 14, 0, 0, 12)),
                'native wide-vector import, address-span and dequeue boundaries')
    admissions = re.findall(r'^IPV6_ERRORS_ADMIT type=(\d+) case=(\d+) pointer=(\d+) bytes=(\d+) result=(-?\d+) errno=(\d+)$', log, re.MULTILINE)
    require(len(admissions) == 96, 'complete actual output admission inventory')
    sizes = (0, 1, 2, 3, 4, 1232, 1233, 1252, 1253, 1300, 65527, 65528, 65535, 65536, 2147483647, 2147483648)
    seen = set()
    for encoded in admissions:
        kind, number, pointer, length, result, error = map(int, encoded)
        require(kind in (2, 3) and number in range(16) and pointer in range(3) and
                (kind, number, pointer) not in seen and length == sizes[number], 'unique actual admission case')
        large = length + (48 if kind == 2 else 40) > 1280
        wanted = 14 if kind == 3 and (length < 2 or pointer == 1) else 90 if large else (
            14 if (pointer == 1 and length) or (pointer == 2 and length > 2) else 22 if kind == 3 and length < 4 else 0)
        require((result, error) == ((-1, wanted) if wanted else (length, 0)), 'native output fault and local-error admission order')
        seen.add((kind, number, pointer))
    records = re.findall(r'^IPV6_ERRORS_WIRE lane=(\d+) case=(\d+) type=(\d+) scope=(\d+) mode=(\d+) mtu=(\d+) error=(\d+) queued=(\d+) result=(-?\d+) flags=([0-9a-f]+) name=([0-9a-f]+) control=([0-9a-f]+) payload=([0-9a-f]+)$', log, re.MULTILINE)
    require(len(records) == 120, 'every actual wire error result and copied byte')
    seen = set()
    for encoded in records:
        link, sequence, kind, scoped, mode, mtu, error, queued, result = map(int, encoded[:9])
        flags = int(encoded[9], 16)
        name, control, payload = map(bytes.fromhex, encoded[10:])
        require(link in (0, 1) and sequence in range(60) and (link, sequence) not in seen and
                (len(name), len(control), len(payload)) == (28, 64, 64), 'bounded unique error result and metadata')
        seen.add((link, sequence))
        pmtu = sequence < 24
        wanted_kind = sequence // 12 + 2 if pmtu else (sequence - 24) // 13 + 2 if sequence < 50 else (sequence - 50) // 5 + 2
        wanted_scope, wanted_mode = (sequence % 12 // 6, sequence % 6) if pmtu else (0, 1)
        wanted_queue = sequence < 50 and not (pmtu and wanted_kind == 2 and wanted_mode >= 4)
        wanted_error = 0 if not wanted_queue else 90 if pmtu else (101, 13, 113, 113, 111, 13, 13, 71, 113, 113, 71, 71, 71)[(sequence - 24) % 13]
        wanted_mtu = 1280 if pmtu and (wanted_kind == 3 or wanted_mode < 4) else 1500
        quoted = (48 if kind == 2 else 56) if pmtu else 16
        capacity = 0 if sequence % 4 == 0 else 3 if sequence % 4 == 1 else 64
        copied = min(quoted, capacity)
        wanted_result = copied if wanted_queue else -1
        wanted_flags = (0x2000 | (0x20 if copied < quoted else 0)) if wanted_queue else 0
        require((kind, scoped, mode, mtu, error, queued, result, flags) ==
                (wanted_kind, wanted_scope, wanted_mode, wanted_mtu, wanted_error, int(wanted_queue), wanted_result, wanted_flags),
                'native extended-error result and policy')
        wanted_name, wanted_control, wanted_payload = bytes([0xa7]) * 28, bytes([0xa7]) * 64, bytes([0xa7]) * 64
        if wanted_queue:
            index = interface_index if link == lane else interface_index + (link - lane)
            # The guest exposes two ordered devices; isolated native namespaces
            # record both actual consecutive interface indices before execution.
            scope_index = index if scoped else 0
            remote, source, router = address(link, 16 + sequence, scoped), address(link, 2, scoped), address(link, 250, scoped)
            wanted_name = sockaddr(remote, 48000 + sequence if kind == 2 else 0, scope_index)
            typ = 2 if pmtu else ((1,) * 8 + (3, 3, 4, 4, 4))[(sequence - 24) % 13]
            code = 0 if pmtu else (0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 0, 1, 2)[(sequence - 24) % 13]
            wanted_control = (struct.pack('<QiiIBBBBII', 60, 41, 25, wanted_error, 3, typ, code, 0, 1280 if pmtu else 0, 0) +
                              sockaddr(router, scope=scope_index) + bytes([0xa7]) * 4)
            length = 1300 if pmtu else 16
            data = bytearray((n * 19 + sequence * 3 + link) & 255 for n in range(length))
            if kind == 3:
                data[:4] = b'\x81\0\0\0'
                data[2:4] = checksum(source + remote + struct.pack('!I3xB', length, 58) + data).to_bytes(2, 'big')
            wanted_payload = bytes(data[:copied]) + bytes([0xa7]) * (64 - copied)
        require((name, control, payload) == (wanted_name, wanted_control, wanted_payload),
                'every copied destination, extended-error, offender, payload and untouched padding byte')
    sends = re.findall(r'^IPV6_ERRORS_SEND lane=(\d+) case=(\d+) result=(-?\d+) errno=(\d+)$', log, re.MULTILINE)
    require(len(sends) == 48, 'all subsequent real send results')
    seen = set()
    for encoded in sends:
        link, sequence, result, error = map(int, encoded)
        require(link in (0, 1) and sequence in range(24) and (link, sequence) not in seen and
                (result, error) == ((-1, 90) if sequence % 6 == 2 else (1300, 0)), 'unchanged post-error output behavior')
        seen.add((link, sequence))


def inspect(rows, lane, log, native=False, interface_index=None, native_copy_order='length-first'):
    index = interface_index if interface_index is not None else lane + 1
    from ipv6_error_metadata_capture import boundary, inspect as inspect_metadata
    result, proof = inspect_packets(rows[:boundary(rows, lane)], lane, log, native,
                           application=lambda text, link: application(text, link, index),
                           barrier_protocol=b'\x88\xbc', barrier_magic=b'IP6E', quote_length=96)
    metadata, _ = inspect_metadata(rows, lane, log, native, index, native_copy_order)
    result['metadata'] = metadata
    return result, proof


def verify_capture(path, lane, log_path, archive, native=False, statistics=None, interface_index=None, native_copy_order='length-first'):
    path, log_path = Path(path), Path(log_path)
    original, original_log = path.read_bytes(), log_path.read_bytes()
    rows, log = read_capture(path), original_log.decode(errors='replace')
    clock = None
    if native:
        require(interface_index is not None, 'actual native error-queue interface identity')
        selected = []
        for row in rows:
            if row['frame'][12:14] == b'\x86\xdd' and len(row['frame']) > 20 and row['frame'][20] == 0:
                continue
            row['stamp'] = row['ns'] // 1000
            selected.append(row)
        clock = bind_native_clock(path, selected, statistics)
    result, proof = inspect(rows, lane, log, native, interface_index, native_copy_order)
    names = ('missing-data', 'duplicate-data', 'missing-quote', 'valid-checksum-foreign-quote',
             'wrong-control', 'wrong-payload', 'wrong-destination', 'missing-local-case',
             'wrong-admission', 'wrong-vector', 'wrong-truncation', 'short-observation', 'fragment-offset', 'fragment-id')
    rejected = []
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as saved:
        for name in names:
            changed, changed_log = copy.deepcopy(rows), log
            index = proof['data'][0]
            if name == 'missing-data':
                del changed[index]
            elif name == 'duplicate-data':
                changed.insert(index, copy.deepcopy(changed[index]))
            elif name == 'missing-quote':
                del changed[proof['quotes'][0]]
            elif name == 'valid-checksum-foreign-quote':
                index = proof['quotes'][0]
                frame = bytearray(changed[index]['frame'])
                frame[104] ^= 1
                frame[56:58] = bytes(2)
                size = int.from_bytes(frame[18:20], 'big')
                frame[56:58] = checksum(bytes(frame[22:54]) + struct.pack('!I3xB', size, 58) + bytes(frame[54:54 + size])).to_bytes(2, 'big')
                changed[index]['frame'] = bytes(frame)
            elif name in ('wrong-control', 'wrong-payload', 'wrong-destination'):
                sequence = 2 if name == 'wrong-payload' else 0
                record = next(row for row in log.splitlines() if row.startswith(f'IPV6_ERRORS_WIRE lane={lane} case={sequence} '))
                key = {'wrong-control':'control', 'wrong-payload':'payload', 'wrong-destination':'name'}[name]
                encoded = re.search(key + r'=([0-9a-f]+)', record).group(1)
                damaged = bytearray.fromhex(encoded)
                damaged[16 if name == 'wrong-control' else 0] ^= 1
                changed_log = changed_log.replace(record, record.replace(key + '=' + encoded, key + '=' + damaged.hex()), 1)
            elif name == 'missing-local-case':
                changed_log = '\n'.join(row for row in log.splitlines() if not row.startswith('IPV6_ERRORS_LOCAL case=0 '))
            elif name == 'wrong-admission':
                changed_log = changed_log.replace('IPV6_ERRORS_ADMIT type=2 case=0 pointer=0 bytes=0 result=0 errno=0',
                                                  'IPV6_ERRORS_ADMIT type=2 case=0 pointer=0 bytes=0 result=-1 errno=14', 1)
            elif name == 'wrong-vector':
                changed_log = changed_log.replace('IPV6_ERRORS_VECTOR case=0 result=-1 errno=14',
                                                  'IPV6_ERRORS_VECTOR case=0 result=-1 errno=22', 1)
            elif name == 'wrong-truncation':
                record = next(row for row in log.splitlines() if row.startswith(f'IPV6_ERRORS_WIRE lane={lane} case=1 '))
                changed_log = changed_log.replace(record, record.replace('flags=2020', 'flags=2000'), 1)
            elif name == 'short-observation':
                a, b = proof['intervals'][0]
                changed[b]['ns'] = changed[a]['ns'] + 49000000
                changed[b]['monotonic_ns'] = stamp(changed[a]) + 49000000
            else:
                index = proof['fragments'][0]
                frame = bytearray(changed[index]['frame'])
                frame[57 if name == 'fragment-offset' else 58] ^= 8
                changed[index]['frame'] = bytes(frame)
            saved.writestr(name + '.pcap', encode_capture(changed))
            saved.writestr(name + '.log', changed_log)
            try:
                inspect(changed, lane, changed_log, native, interface_index, native_copy_order)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('accepted damaged IPv6 error-queue evidence: ' + name)
        saved.writestr('rejections.json', json.dumps(rejected, indent=2))
    require(path.read_bytes() == original and log_path.read_bytes() == original_log, 'original error-queue evidence unchanged')
    from ipv6_error_metadata_capture import verify_capture as verify_metadata
    metadata = verify_metadata(path, lane, log_path,
                               Path(archive).with_name(Path(archive).stem + '-metadata.zip'),
                               native, interface_index, native_copy_order)
    metadata['native_clock_qualified'] = bool(clock)
    result.update(damaged_rejected=len(rejected), native_clock=clock,
                  metadata=metadata,
                  original_sha256=hashlib.sha256(original).hexdigest(),
                  archive_sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest())
    return result
