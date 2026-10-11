# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject synchronized DNS capture, endpoint and driver receipt corruption."""
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import tarfile
import tempfile
from dns_tcp_capture import records, decode, verify, verify_report
from tcp_capture import checksum


def repair(frame):
    result = bytearray(frame)
    ip_at, header = 14, (frame[14] & 15) * 4
    total = int.from_bytes(frame[16:18], 'big')
    result[24:26] = b'\0\0'
    result[24:26] = struct.pack('!H', checksum(result[ip_at:ip_at + header]))
    body = ip_at + header
    check_at = body + (16 if frame[23] == 6 else 6)
    result[check_at:check_at + 2] = b'\0\0'
    pseudo = frame[26:34] + struct.pack('!BBH', 0, frame[23], total - header)
    result[check_at:check_at + 2] = struct.pack('!H', checksum(pseudo + result[body:ip_at + total]))
    return bytes(result)


def hash_frame(frame):
    value = 0xcbf29ce484222325
    for byte in frame:
        value = (value ^ byte) * 0x100000001b3 & 0xffffffffffffffff
    return f'{value:016x}'


def synchronize(rows, evidence, text, lane, changes, scale=False):
    adjusted = copy.deepcopy(evidence)
    entries = adjusted['frames']
    log = text
    updated = []
    for index, row in enumerate(rows):
        frame = row['frame']
        changed = changes.get(index, frame)
        if changed != frame:
            matches = [entry for entry in entries if entry['frame'] == frame.hex()]
            assert len(matches) == 1, 'a selected packet is unique in the retained peer evidence'
            if changed is None:
                entries.remove(matches[0])
            else:
                matches[0]['frame'] = changed.hex()
            digest = hash_frame(frame)
            pattern = (r'^DNS_FRAME linkage=\w+ index=' + str(lane + 1) + r' length=' + str(len(frame)) +
                       r' hash=' + digest + r' packet_type=\d+ monotonic_ms=\d+\r?\n')
            matches_log = re.findall(pattern, log, re.M)
            assert len(matches_log) == 1, 'one synchronized actual driver receipt'
            line = matches_log[0]
            replacement = '' if changed is None else line.replace('hash=' + digest, 'hash=' + hash_frame(changed))
            log = log.replace(line, replacement)
        if changed is not None:
            updated.append(dict(row, frame=changed))
    if scale:
        origin = rows[0]['ms']
        updated = [dict(row, ms=origin + (row['ms'] - origin) / 10) for row in updated]
        for entry in entries:
            entry['ms'] /= 10
        log = re.sub(r'monotonic_ms=(\d+)', lambda match: 'monotonic_ms=' + str(int(match[1]) // 10), log)
    count = sum(decode(row['frame'], lane) is not None for row in updated)
    log = re.sub(r'(DNS_CAPTURE_PASS linkage=\w+ index=' + str(lane + 1) + r' packets=)\d+',
                 lambda match: match[1] + str(count), log)
    return updated, adjusted, log


def write_capture(path, rows):
    with path.open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for row in rows:
            usecs = round(row['ms'] * 1000)
            frame = row['frame']
            output.write(struct.pack('<IIII', usecs // 1000000, usecs % 1000000, len(frame), len(frame)) + frame)


def damage(path, lane, evidence, text, linkage, destination):
    rows = records(path)
    decoded = [(index, decode(row['frame'], lane)) for index, row in enumerate(rows)]
    incoming = [(index, row) for index, row in decoded if row is not None and
                row['protocol'] == 'tcp' and not row['outgoing'] and row['data']]
    first, positive = incoming[0]
    large = next((index, row) for index, row in incoming if len(row['data']) == 536)
    query = next((index, row) for index, row in decoded if row is not None and
                 row['protocol'] == 'tcp' and row['outgoing'] and len(row['data']) > 15)

    def body_change(index, row, at, value):
        frame = bytearray(rows[index]['frame'])
        offset = 14 + (frame[14] & 15) * 4
        offset += (int.from_bytes(frame[offset + 12:offset + 14], 'big') >> 12) * 4
        frame[offset + at] ^= value
        return {index: repair(bytes(frame))}

    future_ack = bytearray(rows[first]['frame'])
    tcp_at = 14 + (future_ack[14] & 15) * 4
    struct.pack_into('!I', future_ack, tcp_at + 8, (positive['ack'] + 1) & 0xffffffff)
    mutations = [
        ('poisoned-address', body_change(first, positive, len(positive['data']) - 1, 1), False),
        ('answer-id', body_change(first, positive, 3, 1), False),
        ('query-owner', body_change(query[0], query[1], 15, 1), False),
        ('framed-length', body_change(large[0], large[1], 1, 1), False),
        ('missing-body', {large[0]: None}, False),
        ('unsent-ack', {first: repair(bytes(future_ack))}, False),
        ('shortened-clocks', {}, True),
    ]
    results = []
    for name, changes, scale in mutations:
        candidate_rows, adjusted, log = synchronize(rows, evidence, text, lane, changes, scale)
        directory = destination / path.stem / name
        directory.mkdir(parents=True)
        candidate = directory / path.name
        write_capture(candidate, candidate_rows)
        (directory / 'peer.json').write_text(json.dumps(adjusted, indent=2) + '\n')
        (directory / 'guest.log').write_text(log)
        # Establish that the synchronized packets still decode with correct
        # checksums and match the endpoint bytes before testing semantics.
        actual = Counter(row['frame'] for row in candidate_rows if decode(row['frame'], lane) is not None)
        reported = Counter(bytes.fromhex(row['frame']) for row in adjusted['frames']
                           if decode(bytes.fromhex(row['frame']), lane) is not None)
        assert actual == reported
        try:
            verify(candidate, lane, adjusted, log, linkage)
        except ValueError as error:
            results.append(dict(file=path.name, mutation=name, rejected=True, reason=str(error),
                                sha256=hashlib.sha256(candidate.read_bytes()).hexdigest()))
        else:
            raise AssertionError(f'synchronized DNS damage accepted: {name}')
    return results


def main():
    root = Path(__file__).resolve().parents[1] / 'build'
    verify_report(root, 'dns-tcp-results.json')
    results = []
    with tempfile.TemporaryDirectory(prefix='axiom64-dns-damaged-') as temporary:
        destination = Path(temporary)
        for result in json.loads((root / 'dns-tcp-results.json').read_text()):
            evidence = json.loads((root / result['peer']).read_text())
            text = (root / result['log']).read_text()
            for lane in range(2):
                results.extend(damage(root / result['captures'][lane], lane, evidence[lane], text,
                                      result['linkage'], destination))
        with tarfile.open(root / 'dns-tcp-damaged.tar.gz', 'w:gz') as archive:
            for path in sorted(destination.iterdir()):
                archive.add(path, arcname=path.name)
    (root / 'dns-tcp-damage-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'DNS_TCP_DAMAGE_PASS negatives={len(results)}')


if __name__ == '__main__':
    main()
