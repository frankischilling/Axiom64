# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain and reopen damaged versions of actual TCP option observations."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from ipv4_options_evidence import checksum, require, tcp_observations


def replace_packet(text, phase, sample, change, *, last=True, repair=False, flags=None):
    pattern = (r'^IPV4_TCP_OPTIONS_BYTES uid=0 phase=' + phase + ' case=' + str(sample) +
               r' label=packet length=\d+ bytes=([0-9a-f]+)$')
    matches = list(re.finditer(pattern, text, re.M))
    if flags is not None:
        matches = [match for match in matches if (lambda data: data[(data[0] & 15) * 4 + 13] & 63)(
            bytes.fromhex(match[1])) == flags]
    require(matches, 'actual packet for damaged-evidence control')
    match = matches[-1 if last else 0]
    data = bytearray.fromhex(match[1])
    change(data)
    if repair:
        header = (data[0] & 15) * 4
        tcp = bytearray(data[header:])
        tcp[16:18] = bytes(2)
        pseudo = data[12:20] + bytes((0, 6)) + len(tcp).to_bytes(2, 'big')
        tcp[16:18] = checksum(bytes(pseudo + tcp)).to_bytes(2, 'big')
        data[header:] = tcp
        data[10:12] = bytes(2)
        original = bytearray(data[:header])
        at = 20
        while at < header:
            kind = original[at]
            if kind == 0:
                break
            if kind == 1:
                at += 1
                continue
            size = original[at + 1]
            if kind in (7, 68):
                stride = 8 if kind == 68 and original[at + 3] & 15 == 1 else 4
                original[at + 2] -= stride
                start = at + original[at + 2] - 1
                original[start:start + stride] = bytes(stride)
            at += size
        data[10:12] = checksum(bytes(original)).to_bytes(2, 'big')
    line = match[0][:match[0].index('length=')] + f'length={len(data)} bytes={data.hex()}'
    return text[:match.start()] + line + text[match.end():]


def controls(text):
    def flip(at):
        return lambda data: data.__setitem__(at, data[at] ^ 1)

    def add_options(data):
        data[0] += 1
        data[20:20] = b'\1' * 4
        data[2:4] = len(data).to_bytes(2, 'big')

    def invalid_stamp(data):
        data[24:28] = (86400000).to_bytes(4, 'big')

    def changed_query(value):
        pattern = r'(^IPV4_TCP_OPTIONS_BYTES uid=0 phase=listener case=3 label=query length=32 bytes=)([0-9a-f]{64})$'
        match = re.search(pattern, value, re.M)
        require(match is not None, 'actual accepted query for ownership control')
        changed = bytearray.fromhex(match[2])
        changed[2] ^= 4
        return value[:match.start(2)] + changed.hex() + value[match.end(2):]

    return {
        'reset-sequence-repaired': replace_packet(text, 'reset', 0, flip(24), repair=True),
        'reset-acknowledgment-repaired': replace_packet(text, 'reset', 0, flip(28), repair=True),
        'reset-ports-repaired': replace_packet(text, 'reset', 0, flip(20), repair=True),
        'reset-options-repaired': replace_packet(text, 'reset', 0, add_options, repair=True),
        'reset-transport-checksum': replace_packet(text, 'reset', 0, flip(36)),
        'reset-ip-checksum': replace_packet(text, 'reset', 0, flip(10)),
        'timestamp-outside-day': replace_packet(text, 'reset', 4, invalid_stamp, repair=True),
        'accepted-query-ownership': changed_query(text),
        'time-wait-acknowledgment-repaired': replace_packet(text, 'time-wait-retained', 0, flip(60), repair=True),
        'time-wait-sequence-repaired': replace_packet(text, 'time-wait-compacted', 1, flip(56), repair=True),
        'time-wait-missing-close-origin': replace_packet(text, 'close', 0, flip(24), repair=True, flags=17),
        'time-wait-lifetime-form': text.replace('uid=0 phase=time-wait-retained case=0',
                                               'uid=0 phase=time-wait-compacted case=0'),
        'missing-credential-scope': text.replace('uid=65534 reset_cases=6', 'uid=65533 reset_cases=6'),
        'incomplete-summary': text.replace('IPV4_TCP_OPTIONS_PASS scopes=2 cases=36',
                                           'IPV4_TCP_OPTIONS_PASS scopes=2 cases=35'),
    }


def verify_controls(directory, destination):
    destination.mkdir(parents=True, exist_ok=False)
    names = ['linux-tcp-' + profile for profile in ('native', 'static', 'dynamic')]
    names += [profile + '-' + firmware for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi')]
    rows = []
    for name in names:
        text = (directory / name / 'client.log').read_text()
        tcp_observations(text)
        for control, changed in controls(text).items():
            require(changed != text, 'damaged control changes an actual observation')
            path = destination / (name + '-' + control + '.log')
            path.write_text(changed)
            try:
                tcp_observations(path.read_text())
            except ValueError as error:
                rows.append(dict(profile=name, control=control, path=path.name,
                                 sha256=hashlib.sha256(path.read_bytes()).hexdigest(), reason=str(error)))
            else:
                raise ValueError('accepted damaged original TCP option evidence: ' + path.name)
    require(len(rows) == 98, 'all fourteen damaged controls in all seven actual TCP profiles')
    result = dict(passed=True, rejected=len(rows), controls=rows)
    (destination / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--directory', type=Path, required=True, dest='destination')
    args = parser.parse_args()
    record = verify_controls(args.directory, args.destination)
    print(json.dumps(dict(passed=record['passed'], rejected=record['rejected'])))


if __name__ == '__main__':
    main()
