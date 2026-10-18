# SPDX-License-Identifier: GPL-3.0-or-later
"""Require the PMTU auditor to reject damage derived from every real profile."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_clock_mutations import candidate_auditor, candidate_verifier
from tcp_capture_clock import ClockEvidenceError, microseconds
from fetch import ROOT
from tcp_icmp_capture import checksum, packets, require, tcp_fields
from tcp_pmtu_capture import audit_row, verify_flow


def update(item, body, repair=True):
    body = bytearray(body)
    if repair:
        offset = 16 if item['protocol'] == 6 else 2
        body[offset:offset + 2] = b'\0\0'
        pseudo = (item['ip'][12:20] + bytes([0, 6]) + len(body).to_bytes(2, 'big')
                  if item['protocol'] == 6 else b'')
        body[offset:offset + 2] = checksum(pseudo + body).to_bytes(2, 'big')
    ip = item['ip'][:20] + body
    padding = item['frame'][14 + len(item['ip']):]
    item.update(ip=bytes(ip), body=bytes(body), frame=item['frame'][:14] + ip + padding)


def write_capture(path, items):
    with path.open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for item in items:
            stamp, frame = item['stamp'], item['frame']
            output.write(struct.pack('<IIII', stamp // 1000000, stamp % 1000000,
                                     len(frame), len(frame)) + frame)


def rejected(action, label, expected):
    try:
        action()
    except ValueError as error:
        require(expected in str(error), f'{label}: rejection must identify the intended damage: {error}')
        return str(error)
    raise ValueError(f'{label}: damaged evidence was accepted')


def flow_items(items, case):
    remote = bytes([10, 23, 1, 10 + case])
    return [item for item in items if remote in (item['ip'][12:16], item['ip'][16:20])]


def damage_wire(items, label):
    case = 4 if label == 'short-silence' else 0
    rows = flow_items(items, case)
    tcp = [item for item in rows if item['protocol'] == 6]
    quotes = [item for item in rows if item['protocol'] == 1]
    outgoing = [item for item in tcp if item['outgoing']]
    if label == 'missing-hints':
        for item in quotes:
            items.remove(item)
    elif label == 'unowned-quote':
        body = bytearray(quotes[0]['body'])
        body[-1] ^= 0x40
        update(quotes[0], body)
    elif label in ('payload', 'checksum'):
        item = next(item for item in outgoing if tcp_fields(item)['data'])
        body = bytearray(item['body'])
        body[(body[12] >> 4) * 4] ^= 1
        update(item, body, repair=label != 'checksum')
    elif label == 'missing-close':
        for item in tcp:
            if tcp_fields(item)['flags'] & 1:
                items.remove(item)
    elif label == 'future-ack':
        item = next(item for item in tcp if not item['outgoing'] and not tcp_fields(item)['flags'] & 2)
        origin = (tcp_fields(next(value for value in outgoing if tcp_fields(value)['flags'] & 2))['sequence'] + 1) & 0xffffffff
        body = bytearray(item['body'])
        body[8:12] = ((origin + 5000) & 0xffffffff).to_bytes(4, 'big')
        update(item, body)
    elif label == 'changed-mss':
        item = next(item for item in tcp if not item['outgoing'] and tcp_fields(item)['flags'] & 2)
        body = bytearray(item['body'])
        require(body[20:22] == b'\x02\x04', 'actual peer SYN begins with its MSS')
        body[22:24] = (536).to_bytes(2, 'big')
        update(item, body)
    elif label == 'short-silence':
        difference = microseconds(quotes[1]) - microseconds(quotes[0]) - 10000
        require(difference > 0, 'original actual observation exceeds the damaged silence')
        threshold = microseconds(quotes[1])
        for item in items:
            if microseconds(item) >= threshold:
                item['stamp'] -= difference
                if 'monotonic_ns' in item:
                    item['monotonic_ns'] -= difference * 1000
    return case


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', type=Path, nargs='*')
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--host-libraries', type=Path)
    args = parser.parse_args()
    libraries = ({path.name: path.read_bytes() for path in args.host_libraries.iterdir()}
                 if args.host_libraries else None)
    auditor = lambda directory, row: audit_row(directory, row, args.input_root, libraries)
    reports = args.reports or [
        ROOT / 'build/tcp-pmtu-native-results.json', ROOT / 'build/tcp-pmtu-results.json']
    destination = ROOT / 'build/tcp-pmtu-damaged'
    destination.mkdir(exist_ok=True)
    observations = []
    controls = {'missing-hints': 'both complete recovered streams',
                'unowned-quote': 'quote owns exact earlier', 'payload': 'actual independent per-tuple payload',
                'missing-close': 'cumulative ACK owns only', 'future-ack': 'cumulative ACK owns only',
                'changed-mss': 'both peers advertise', 'short-silence': 'real damaged-hint silence',
                'checksum': 'actual TCP header'}
    for report in reports:
        root = report.parent
        for row in json.loads(report.read_text()):
            auditor(root, row)
            native = 'client_namespace' in row
            checked = candidate_auditor(auditor, root, row)
            name = ('linux-' + row['linkage'] if native else
                    '-'.join(row[key] for key in ('linkage', 'firmware', 'transport')))
            statistics = row['capture_statistics'][0] if native else None
            original = packets(root / row['captures'][0], statistics)
            for item in original:
                item['outgoing'] = item['frame'][6:12] == bytes.fromhex('525400123410')
            for label, expected in controls.items():
                changed = deepcopy(original)
                case = damage_wire(changed, label)
                path = destination / (name + '-' + label + '.pcap')
                write_capture(path, changed)
                def validate(candidate, lane, case, native=False, statistics=None):
                    try:
                        decoded = packets(candidate, statistics)
                    except ClockEvidenceError as error:
                        assert label == 'short-silence' and 'ordered bounded' in str(error)
                        # The stricter global order check may reject first.
                        # Also exercise the original PMTU silence predicate
                        # with the same byte-identical, shortened flow clocks.
                        verify_flow(changed, lane, case, native)
                        raise AssertionError('false PMTU silence passed its original semantic guard')
                    for item in decoded:
                        item['outgoing'] = item['frame'][6:12] == bytes.fromhex('525400123410')
                    verify_flow(decoded, lane, case, native)
                validate = candidate_verifier(validate, root / row['captures'][0], statistics)
                reason = rejected(lambda: validate(path, 0, case, native), label, expected)
                observations.append(dict(profile=name, control=label, reason=reason,
                                         artifact=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            for label in ('status', 'reported-bytes'):
                changed = deepcopy(row)
                if label == 'status':
                    changed['returncode'] = 99
                else:
                    changed['peers'][0]['flows'][0]['bytes_received'] -= 1
                expected = 'actual native or QEMU exit status' if label == 'status' else 'complete reported peer cases'
                reason = rejected(lambda: auditor(root, changed), label, expected)
                observations.append(dict(profile=name, control=label, reason=reason))
            with tempfile.TemporaryDirectory(prefix='pmtu-damage-') as scratch:
                scratch = Path(scratch)
                for filename in [*row['captures'], row['inputs'], row['log']]:
                    (scratch / filename).write_bytes((root / filename).read_bytes())
                text = (root / row['log']).read_text()
                for label in ('driver-receipt', 'driver-drop', 'maxseg-missing',
                              'maxseg-duplicate', 'maxseg-stale', 'maxseg-wrong-tuple',
                              'maxseg-wire-limit'):
                    if label == 'driver-receipt':
                        changed = re.sub(r'(PMTU_FRAME .*?hash=)[0-9a-f]{16}', r'\g<1>0000000000000000', text, count=1)
                        expected = 'every original IPv4 wire byte'
                    elif label == 'driver-drop':
                        changed = re.sub(r'(PMTU_CAPTURE_PASS .*?dropped=)0', r'\g<1>1', text, count=1)
                        expected = 'driver identity and zero drops'
                    else:
                        query = re.search(r'^TCP_PMTU_MAXSEG lane=0 case=' +
                                          ('2' if label == 'maxseg-wire-limit' else '0') +
                                          r' stage=recovered value=(\d+)\r?\n', text, re.M)
                        require(query is not None, 'actual recovered MSS query is present')
                        replacement = {'maxseg-missing': '',
                                       'maxseg-duplicate': query[0] * 2,
                                       'maxseg-stale': query[0].replace('value=536', 'value=1460'),
                                       'maxseg-wrong-tuple': query[0].replace('lane=0', 'lane=1'),
                                       'maxseg-wire-limit': query[0].replace('value=' + query[1],
                                                                            'value=' + str(int(query[1]) + 1))}[label]
                        changed = text[:query.start()] + replacement + text[query.end():]
                        expected = 'actual socket MSS follows negotiated and recovered wire limits'
                    require(changed != text, 'an actual driver observation was damaged')
                    (scratch / row['log']).write_text(changed)
                    reason = rejected(lambda: checked(scratch, row), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason))
                (scratch / row['log']).write_text(text)
                inputs = json.loads((root / row['inputs']).read_text())
                inputs['sources']['userspace/tests/net/tcp_pmtu.c'] = '0' * 64
                (scratch / row['inputs']).write_text(json.dumps(inputs))
                reason = rejected(lambda: checked(scratch, row), 'source-fingerprint', 'actual sources input:')
                observations.append(dict(profile=name, control='source-fingerprint', reason=reason))
    value = dict(passed=True, rejected=len(observations), observations=observations)
    (destination / 'results.json').write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps(dict(passed=True, rejected=len(observations))))


if __name__ == '__main__':
    main()
