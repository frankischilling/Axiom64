# SPDX-License-Identifier: GPL-3.0-or-later
"""Check user-timeout errors and disabled-timeout recovery from independent evidence."""
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
from tcp_fault_capture import MASK, decode as decode_tcp, packets as read_tcp, require


def ports(lane):
    return (44000 + lane, 45000 + lane, 44020 + lane, 45020 + lane)


def identify(row):
    if row is not None:
        row['control'], row['role'] = divmod(row['role'], 2)
    return row


def decode(frame, lane):
    return identify(decode_tcp(frame, lane, ports(lane)))


def packets(path, lane):
    return [identify(row) for row in read_tcp(path, lane, ports(lane))]


def period(rows, lane, role, control, native):
    origin = (next(row['seq'] for row in rows if row['outgoing'] and row['flags'] & 2) + 1) & MASK
    closed = next((index for index, row in enumerate(rows) if not row['outgoing'] and
                   row['flags'] & 16 and not row['flags'] & 2 and not row['window']), None)
    require(closed is not None, 'actual timeout receiver closes')
    acknowledgment = (origin + 1072) & MASK
    require(rows[closed]['ack'] == acknowledgment and
            any(not row['outgoing'] and row['ack'] == (origin + 536) & MASK and row['window'] == 536
                for row in rows[:closed]), 'two clean acknowledged segments precede closure')
    opened = next((index for index in range(closed + 1, len(rows)) if not rows[index]['outgoing'] and
                   rows[index]['flags'] & 16 and rows[index]['window']), None)
    require((opened is not None) == bool(control), 'only the disabled-timeout control reopens')
    if control:
        require(rows[opened]['window'] == 8192 and rows[opened]['ack'] == acknowledgment and
                3500 <= rows[opened]['ms'] - rows[closed]['ms'] < 10000,
                'control reopens after the configured deadline without invented progress')
    stopped = rows[closed + 1:opened]
    probes = []
    for index, row in enumerate(stopped):
        if not row['outgoing']:
            require(not row['data'] and row['flags'] == 16 and not row['window'] and
                    row['ack'] == acknowledgment, 'zero ACKs never accept queued bytes')
            continue
        if row['flags'] & 4:
            require(not control and row['ms'] - rows[closed]['ms'] >= 2300, 'no premature reset')
            continue
        require(row['flags'] & 16 and not row['flags'] & 7, 'established stopped sender has no FIN')
        if not row['data'] and row['seq'] == acknowledgment:
            continue
        expected = ((1072 * 29) ^ (1072 >> 7) ^ (lane * 53) ^ (role * 97) ^ (control * 41)) & 255
        require((native and not row['data'] and row['seq'] == (acknowledgment - 1) & MASK) or
                (not native and row['data'] == bytes([expected]) and row['seq'] == acknowledgment),
                'actual native empty or guest one-byte probe')
        require(any(not answer['outgoing'] and answer['flags'] == 16 and not answer['window'] and
                    answer['ack'] == acknowledgment for answer in stopped[index + 1:
                    next((end for end in range(index + 1, len(stopped)) if stopped[end]['outgoing']), len(stopped))]),
                'each actual probe has a real non-progress answer')
        probes.append(row['ms'])
    require(len(probes) >= (3 if native else (2 if control else 1)), 'required real probes before timeout/recovery')
    intervals = [now - then for now, then in zip(probes, [rows[closed]['ms'], *probes[:-1]])]
    require((180 if native else 850) <= intervals[0] < 1500 and
            all(now + 100 >= before * 1.6 and now <= before * 3 + 500
                for before, now in zip(intervals, intervals[1:])), 'actual bounded probe backoff')
    size = 2048 if control else 1072
    data, present = bytearray(size), bytearray(size)
    for index, row in enumerate(rows):
        if not row['outgoing'] or not row['data'] or closed < index and (opened is None or index < opened):
            continue
        offset = (row['seq'] - origin) & MASK
        require(offset + len(row['data']) <= size, 'actual accepted payload bounds')
        for at, value in enumerate(row['data'], offset):
            expected = ((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (role * 97) ^ (control * 41)) & 255
            require(value == expected and (not present[at] or data[at] == value), 'exact accepted payload bytes')
            data[at], present[at] = value, 1
    require(all(present), 'every required accepted payload byte is captured')
    if control:
        peer_origin = (next(row['seq'] for row in rows if not row['outgoing'] and row['flags'] & 2) + 1) & MASK
        require(any(not row['outgoing'] and row['data'] == b'K' and row['flags'] & 1 and
                    row['seq'] == peer_origin for row in rows[opened:]), 'actual recovery response and FIN')
        require(any(row['outgoing'] and row['flags'] & 1 and row['seq'] == (origin + 2048) & MASK
                    for row in rows[opened:]) and
                any(not row['outgoing'] and row['ack'] == (origin + 2049) & MASK for row in rows[opened:]) and
                any(row['outgoing'] and row['ack'] == (peer_origin + 2) & MASK for row in rows[opened:]),
                'both control FINs acknowledged after exact data')
    return dict(closed_at=rows[closed]['ms'], reopened_at=rows[opened]['ms'] if control else None,
                probes=probes, intervals_ms=[round(value, 3) for value in intervals],
                delivered=size, sha256=hashlib.sha256(data).hexdigest())


def verify(path, lane, evidence, native=False):
    rows = packets(path, lane)
    require(evidence['lane'] == lane and len(evidence['flows']) == 4, 'actual timeout lane and four flows')
    records, frames = [], Counter()
    for entry in evidence['frames']:
        row = decode(bytes.fromhex(entry['frame']), lane)
        if row is not None:
            require(entry['direction'] == ('receive' if row['outgoing'] else 'send'), 'independent packet direction')
            frames[row['frame']] += 1
            records.append(dict(row, ms=entry['ms']))
    require(Counter(row['frame'] for row in rows) == frames, 'exact PCAP and peer packet multiset')
    checked = []
    for control, role in itertools.product(range(2), repeat=2):
        capture = period([row for row in rows if (row['control'], row['role']) == (control, role)],
                         lane, role, control, native)
        observed = period([row for row in records if (row['control'], row['role']) == (control, role)],
                          lane, role, control, native)
        reported = [flow for flow in evidence['flows'] if (flow['control'], flow['role']) == (control, role)]
        require(len(reported) == 1, 'one independent timeout flow result')
        reported = reported[0]
        application = reported['application']
        require(abs(reported['closed_at'] - observed['closed_at']) < 10 and
                reported['probe_ms'] == observed['probes'] and
                ((reported['reopened_at'] is None and observed['reopened_at'] is None) or
                 (reported['reopened_at'] is not None and observed['reopened_at'] is not None and
                  abs(reported['reopened_at'] - observed['reopened_at']) < 10)) and
                reported['received'] == observed['delivered'],
                'reported timeout/recovery matches actual peer packets')
        elapsed = application['ms'] - observed['closed_at']
        require(application['option_ms'] == (0 if control else 2500) and
                application['error'] == (0 if control else 110) and
                application['consumed'] == ('none' if control else ('SO_ERROR' if role else 'recv')),
                'actual option and error consumption contract')
        lower, upper = (3500, 10000) if control else (2300, 4500)
        require(lower <= elapsed < upper and lower <= application['elapsed_ms'] < upper and
                abs(elapsed - application['elapsed_ms']) < 500 and
                observed['probes'][-1] <= application['ms'], 'actual independent and application elapsed deadline')
        if not control:
            anchor = observed['probes'][0] if native else observed['closed_at']
            require(2300 <= application['ms'] - anchor < 3300,
                    'configured deadline uses measured native/guest timer anchor')
        checked.append(dict(role=role, control=control, capture=capture, peer=observed,
                            application=application, passed=True))
    return dict(file=path.name, lane=lane, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                packets=len(rows), flows=checked, passed=True)


def peer_evidence(directory, row):
    require(Path(row['peer']).name == row['peer'], 'bounded timeout peer path')
    peers = json.loads((directory / row['peer']).read_text())
    require(len(peers) == 2 and len(row['peers']) == 2, 'both independent timeout peers')
    require(Path(row['log']).name == row['log'], 'bounded timeout application log path')
    lines = (directory / row['log']).read_text().splitlines()
    for lane, peer in enumerate(peers):
        require(peer['lane'] == lane and row['peers'][lane]['lane'] == lane, 'timeout peer lane identity')
        peer['flows'] = row['peers'][lane]['flows']
        require(len(peer['flows']) == 4, 'four actual timeout application records per lane')
        for flow in peer['flows']:
            app = flow['application']
            marker = (f"TCP_TIMEOUT_FLOW_PASS lane={lane} role={flow['role']} control={flow['control']} "
                      f"option_ms={app['option_ms']} queued=2048 elapsed_ms={app['elapsed_ms']} "
                      f"error={app['error']} consumed={app['consumed']}")
            require(lines.count(marker) == 1, 'one complete actual application error/recovery log record')
    require(lines.count('TCP_TIMEOUT_PASS flows=8 queued_each=2048') == 1 and
            not any('TCP_TIMEOUT_FAIL' in line for line in lines), 'actual timeout application completes')
    return peers


def check_results(directory):
    verified, reports = [], {}
    for name in ('tcp-timeout-native-results.json', 'tcp-timeout-results.json'):
        path = directory / name
        require(path.is_file(), 'both complete timeout reports exist')
        reports[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        rows = json.loads(path.read_text())
        native = name == 'tcp-timeout-native-results.json'
        expected = {'native', 'static', 'dynamic'} if native else set(itertools.product(
            ('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
        actual = {row['linkage'] if native else (row['linkage'], row['firmware'], row['transport']) for row in rows}
        require(len(rows) == len(expected) and actual == expected, 'complete native/guest timeout profiles')
        for row in rows:
            require(row['wire'] == 'timeout' and row['passed'] and not row['error'] and not row['missing'],
                    'actual timeout profile passes')
            if native:
                require(len(row['capture_statistics']) == 2 and all(stat['dropped'] == 0 and stat['packets'] > 0
                        and stat['buffer_bytes'] >= 4 * 1024 * 1024 for stat in row['capture_statistics']),
                        'native capture has no drops')
            require(Path(row['peer']).name == row['peer'] and len(row['captures']) == 2, 'bounded evidence paths')
            peers = peer_evidence(directory, row)
            for lane, name in enumerate(row['captures']):
                require(Path(name).name == name, 'bounded capture path')
                verified.append(verify(directory / name, lane, peers[lane], native))
    require(len(verified) == 22, 'all 22 timeout captures')
    output = dict(captures=verified, flows=88, reports=reports, passed=True)
    (directory / 'tcp-timeout-capture-results.json').write_text(json.dumps(output, indent=2) + '\n')
    print('TCP_TIMEOUT_CAPTURE_PASS captures=22 flows=88 actual_probes configured_deadline error_consumption control_recovery')
    return output


if __name__ == '__main__':
    check_results(Path(__file__).resolve().parents[1] / 'build')
