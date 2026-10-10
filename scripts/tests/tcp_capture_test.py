# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify that acceptance rejects deliberately damaged actual guest TCP captures."""
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_capture import checksum, verify


def segments(data):
    offset = 24
    while offset < len(data):
        size = struct.unpack_from('<I', data, offset + 8)[0]
        frame = offset + 16
        offset = frame + size
        if data[frame + 12:frame + 14] != b'\x08\x00' or size < 54 or data[frame + 23] != 6:
            continue
        ip = frame + 14
        tcp = ip + (data[ip] & 15) * 4
        end = ip + int.from_bytes(data[ip + 2:ip + 4], 'big')
        header = (data[tcp + 12] >> 4) * 4
        yield ip, tcp, end, header


def repair(data, ip, tcp, end):
    data[tcp + 16:tcp + 18] = b'\0\0'
    pseudo = bytes(data[ip + 12:ip + 20]) + struct.pack('!BBH', 0, 6, end - tcp)
    struct.pack_into('!H', data, tcp + 16, checksum(pseudo + bytes(data[tcp:end])))


def main():
    results = json.loads((ROOT / 'build/tcp-wire-results.json').read_text())
    if len(results) != 8 or not all(item['passed'] for item in results):
        raise ValueError('capture checker requires the complete eight-guest interoperability matrix')
    captures = 0
    for result in results:
        for capture in result['captures']:
            port = next(flow['remote_port'] for flow in capture['flows'] if flow['role'] == 'client')
            verify(ROOT / 'build' / capture['file'], capture['lane'], port)
            captures += 1
    capture = results[0]['captures'][0]
    port = next(flow['remote_port'] for flow in capture['flows'] if flow['role'] == 'client')
    original = (ROOT / 'build' / capture['file']).read_bytes()
    if original[:4] != b'\xd4\xc3\xb2\xa1':
        raise ValueError('mutation fixture expects the QEMU little-endian capture format')
    records = list(segments(original))
    ip, tcp, end, header = next(item for item in records if item[2] - item[1] > item[3])
    bad_checksum = bytearray(original)
    bad_checksum[tcp + header] ^= 1
    wrong_data = bytearray(bad_checksum)
    repair(wrong_data, ip, tcp, end)
    ip, tcp, end, header = next(item for item in records if original[item[1] + 13] & 2)
    malformed = bytearray(original)
    # The first outgoing SYN has an MSS as its sole option.
    if malformed[tcp + 20:tcp + 22] != b'\x02\x04':
        raise ValueError('mutation fixture lacks the expected real SYN MSS option')
    malformed[tcp + 21] = 3
    repair(malformed, ip, tcp, end)
    ip, tcp, end, header = next(item for item in records if original[item[1] + 13] & 1)
    early_fin = bytearray(original)
    sequence = int.from_bytes(early_fin[tcp + 4:tcp + 8], 'big')
    struct.pack_into('!I', early_fin, tcp + 4, (sequence - 1) & 0xffffffff)
    repair(early_fin, ip, tcp, end)
    ip, tcp, end, header = next(item for item in records if original[item[1] + 13] == 0x12)
    early_reset = bytearray(original)
    early_reset[tcp + 13] = 4
    early_reset[tcp + 20:tcp + header] = b'\x01' * (header - 20)
    repair(early_reset, ip, tcp, end)
    cases = {'checksum': (bad_checksum, 'checksum'), 'wrong-data': (wrong_data, 'payload'),
             'malformed-option': (malformed, 'MSS'), 'premature-fin': (early_fin, 'FIN'),
             'early-reset': (early_reset, 'reset'), 'truncated': (original[:-1], 'truncated')}
    with tempfile.TemporaryDirectory(prefix='axiom64-tcp-capture-') as temporary:
        for name, (data, reason) in cases.items():
            path = Path(temporary) / f'{name}.pcap'
            path.write_bytes(data)
            try:
                verify(path, capture['lane'], port)
            except ValueError as exception:
                if reason.lower() not in str(exception).lower():
                    raise ValueError(f'{name} rejected for the wrong reason: {exception}') from exception
            else:
                raise ValueError(f'capture checker accepted damaged {name} fixture')
    print(f'TCP_CAPTURE_CHECKER_PASS captures={captures} negative_cases={len(cases)}', flush=True)


if __name__ == '__main__':
    main()
