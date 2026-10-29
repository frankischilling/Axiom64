# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject forged ownership, payload, clocks and source data from real pressure runs."""
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
from tcp_clock_mutations import candidate_auditor, candidate_verifier, reversed_clock_delta
from tcp_capture_profiles import require_complete_profiles
from tcp_capture_link import write_ipv4_candidate
from tcp_capture_clock import ClockEvidenceError, microseconds
from fetch import ROOT
from tcp_icmp_capture import checksum, require, tcp_fields
from tcp_pressure_capture import audit_row, packets, companion, datagrams, verify_expiry


def update(item, body, repair=True):
    body = bytearray(body)
    if repair:
        offset = 16 if item['protocol'] == 6 else 6
        body[offset:offset + 2] = b'\0\0'
        value = checksum(item['ip'][12:20] + struct.pack('!BBH', 0, item['protocol'], len(body)) + body)
        body[offset:offset + 2] = (value or 0xffff).to_bytes(2, 'big')
    ip = item['ip'][:20] + body
    item.update(body=bytes(body), ip=bytes(ip),
                frame=item['frame'][:14] + ip + item['frame'][14 + len(item['ip']):])


def rejected(action, label, expected):
    try:
        action()
    except ValueError as error:
        require(expected in str(error), f'{label}: wrong rejection: {error}')
        return str(error)
    raise ValueError(f'{label}: damaged evidence was accepted')


def decoded(path, statistics=None):
    items = packets(path, statistics)
    for item in items:
        item['outgoing'] = item['frame'][6:12] == bytes.fromhex('525400123410')
    return items


def mutate(items, label):
    tcp = [item for item in items if item['protocol'] == 6]
    udp = [item for item in items if item['protocol'] == 17]
    if label in ('checksum', 'TCP-bytes'):
        item = next(item for item in tcp if item['outgoing'] and tcp_fields(item)['data'])
        body = bytearray(item['body'])
        body[(body[12] >> 4) * 4] ^= 1
        update(item, body, repair=label != 'checksum')
    elif label in ('reset', 'future-ACK'):
        item = next(item for item in tcp if not item['outgoing'] and not tcp_fields(item)['flags'] & 2)
        body = bytearray(item['body'])
        if label == 'reset':
            body[13] |= 4
        else:
            syn = next(item for item in tcp if item['outgoing'] and tcp_fields(item)['flags'] & 2)
            body[8:12] = ((tcp_fields(syn)['sequence'] + 1000) & 0xffffffff).to_bytes(4, 'big')
        update(item, body)
    elif label == 'missing-close':
        for item in tcp:
            if tcp_fields(item)['flags'] & 1:
                items.remove(item)
    elif label == 'missing-UDP':
        items.remove(next(item for item in udp if item['outgoing']))
    elif label == 'UDP-bytes':
        item = next(item for item in udp if item['outgoing'])
        body = bytearray(item['body'])
        body[12] ^= 1
        update(item, body)
    elif label == 'reply-owner':
        first, other = [item for item in udp if not item['outgoing']][:2]
        body = bytearray(first['body'])
        require(body[2:4] != other['body'][2:4], 'original live UDP owners are distinct')
        body[2:4] = other['body'][2:4]
        update(first, body)
    elif label == 'reused-UDP-port':
        first, other = [item for item in udp if item['outgoing']][:2]
        body = bytearray(first['body'])
        body[:2] = other['body'][:2]
        update(first, body)
        reply = next(item for item in udp if not item['outgoing'])
        body = bytearray(reply['body'])
        body[2:4] = other['body'][:2]
        update(reply, body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', nargs='*', type=Path)
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--host-libraries', type=Path)
    args = parser.parse_args()
    reports = args.reports or [ROOT / 'build/tcp-pressure-native-results.json', ROOT / 'build/tcp-pressure-results.json']
    libraries = ({name: (args.host_libraries / name).read_bytes() for name in ('libc.so.6', 'ld-linux-x86-64.so.2')}
                 if args.host_libraries else None)
    destination = ROOT / 'build/tcp-pressure-damaged'
    destination.mkdir(exist_ok=True)
    observations = []
    controls = {'checksum': 'pressure transport pseudo-header checksum',
                'TCP-bytes': 'exact independent companion bytes', 'reset': 'unrelated pressure never resets',
                'future-ACK': 'companion ACK owns only', 'missing-close': 'companion ACK owns only',
                'missing-UDP': 'every fresh UDP endpoint', 'UDP-bytes': 'exact independently generated pressure UDP bytes',
                'reply-owner': 'UDP reply targets its original socket',
                'reused-UDP-port': 'sixteen simultaneously held UDP ports'}
    for report in reports:
        root = report.parent
        rows = json.loads(report.read_text())
        require_complete_profiles(rows)
        for row in rows:
            audit_row(root, row, args.input_root, libraries)
            native = 'client_namespace' in row
            checked = candidate_auditor(audit_row, root, row)
            name = 'linux-' + row['linkage'] if native else '-'.join(row[key] for key in ('linkage', 'firmware', 'transport'))
            statistics = row['capture_statistics'][0] if native else None
            original = decoded(root / row['captures'][0], statistics)
            for label, expected in controls.items():
                changed = deepcopy(original)
                mutate(changed, label)
                path = destination / (name + '-' + label + '.pcap')
                write_ipv4_candidate(path, changed, root / row['captures'][0])
                def verify(candidate, lane, evidence, native=False, statistics=None):
                    values = decoded(candidate, statistics)
                    companion(values, 0, 2)
                    datagrams(values, 0, 2)
                verify = candidate_verifier(verify, root / row['captures'][0], statistics)
                reason = rejected(lambda: verify(path, 0, None, native), label, expected)
                observations.append(dict(profile=name, control=label, reason=reason, artifact=path.name,
                                         sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            for label in ('status', 'peer-result'):
                changed = deepcopy(row)
                if label == 'status':
                    changed['returncode'] = 99
                    expected = 'actual pressure client or QEMU exit status'
                else:
                    changed['peers'][0]['datagrams'] -= 1
                    expected = 'reported pressure peers agree'
                reason = rejected(lambda: audit_row(root, changed, args.input_root, libraries), label, expected)
                observations.append(dict(profile=name, control=label, reason=reason))
            with tempfile.TemporaryDirectory(prefix='pressure-damage-') as directory:
                scratch = Path(directory)
                for filename in [*row['captures'], row['inputs'], row['log']]:
                    (scratch / filename).write_bytes((root / filename).read_bytes())
                text = (root / row['log']).read_text()
                for label in ('driver-receipt', 'driver-drop', 'short-C-wait', 'missing-listener-mode'):
                    if label == 'driver-receipt':
                        changed = re.sub(r'(PRESSURE_FRAME .*?hash=)[0-9a-f]{16}', r'\g<1>0000000000000000', text, count=1)
                        expected = 'every original pressure IPv4 frame'
                    elif label == 'driver-drop':
                        changed = re.sub(r'(PRESSURE_CAPTURE_PASS .*?dropped=)0', r'\g<1>1', text, count=1)
                        expected = 'correct pressure driver identity and zero drops'
                    elif label == 'short-C-wait':
                        match = re.search(r'TCP_PRESSURE_EXPIRY_END start_ms=(\d+) end_ms=(\d+) elapsed_ms=(\d+)', text)
                        require(match is not None, 'original full expiry observation exists')
                        start = int(match[1])
                        changed = text[:match.start()] + f'TCP_PRESSURE_EXPIRY_END start_ms={start} end_ms={start + 119000} elapsed_ms=119000' + text[match.end():]
                        expected = 'complete real expiry and independent host duration'
                    else:
                        changed = re.sub(r'^TCP_PRESSURE_LISTENER_MODE_PASS mode=3 .*\n', '', text, count=1, flags=re.M)
                        expected = 'all listener, queued-child, unread-reset and backlog reclamation cycles finish'
                    require(changed != text, 'an original actual observation was damaged')
                    (scratch / row['log']).write_text(changed)
                    reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), label, expected)
                    observations.append(dict(profile=name, control=label, reason=reason))
                (scratch / row['log']).write_text(text)
                changed = deepcopy(original)
                require(len(changed) >= 3 and changed[0]['stamp'] > 0, 'original pressure packet clocks exist')
                changed[2]['stamp'] += reversed_clock_delta(changed, root / row['captures'][0], statistics)
                write_ipv4_candidate(scratch / row['captures'][0], changed, root / row['captures'][0])
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries),
                                  'reversed-packet-clock', ('ordered bounded native monotonic receipt pairs' if native else
                                                            'monotonic pressure packet clock'))
                observations.append(dict(profile=name, control='reversed-packet-clock', reason=reason))
                changed = deepcopy(original)
                syn = next(item for item in changed if item['protocol'] == 6 and item['outgoing'] and tcp_fields(item)['flags'] & 2)
                origin = (tcp_fields(syn)['sequence'] + 1) & 0xffffffff
                recovered = next(item for item in changed if item['protocol'] == 6 and item['outgoing'] and
                                 tcp_fields(item)['data'] and ((tcp_fields(item)['sequence'] - origin) & 0xffffffff) == 32)
                last_udp = max(microseconds(item) for item in changed if item['protocol'] == 17 and
                               (item['body'][9] ^ (0 if item['outgoing'] else 0x80)) == 0)
                threshold = microseconds(recovered)
                difference = threshold - last_udp - 10000000
                require(difference > 0, 'original packet clock observes the complete wait')
                for item in changed:
                    if microseconds(item) >= threshold:
                        item['stamp'] -= difference
                        if 'monotonic_ns' in item:
                            item['monotonic_ns'] -= difference * 1000
                write_ipv4_candidate(scratch / row['captures'][0], changed, root / row['captures'][0])
                def short_wait():
                    try:
                        checked(scratch, row, args.input_root, libraries)
                    except ClockEvidenceError as error:
                        require('ordered bounded' in str(error), 'intended shortened pressure clock order')
                        # Also prove the original full-expiry predicate when
                        # the stricter global receipt-order check rejects first.
                        verify_expiry(companion(changed, 0, 2), datagrams(changed, 0, 2))
                        raise AssertionError('false pressure wait passed its original semantic guard')
                reason = rejected(short_wait, 'short-packet-wait',
                                  'independent packet clock observes the full expiry interval')
                observations.append(dict(profile=name, control='short-packet-wait', reason=reason))
                (scratch / row['captures'][0]).write_bytes((root / row['captures'][0]).read_bytes())
                inputs = json.loads((root / row['inputs']).read_text())
                inputs['sources']['userspace/tests/net/tcp_pressure.c'] = '0' * 64
                (scratch / row['inputs']).write_text(json.dumps(inputs))
                reason = rejected(lambda: checked(scratch, row, args.input_root, libraries), 'source-fingerprint', 'actual sources input:')
                observations.append(dict(profile=name, control='source-fingerprint', reason=reason))
    value = dict(passed=True, rejected=len(observations), observations=observations)
    (destination / 'results.json').write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps(dict(passed=True, rejected=len(observations))))


if __name__ == '__main__':
    main()
