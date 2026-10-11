# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently prove complete default lifetime, socket failure and exact recovery."""
import argparse
from collections import Counter, defaultdict
import hashlib
import itertools
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_fault_capture import MASK, decode as decode_tcp, packets as read_tcp, require
from tcp_lifetime.peer import DEFAULT_MS, LONGER_MS, CASES, RECOVERY_BYTES


def ports(lane):
    return tuple(base + lane + kind * 20 for kind in range(CASES) for base in (44000, 45000))


def identify(row):
    if row is not None:
        row['kind'], row['role'] = divmod(row['role'], 2)
    return row


def decode(frame, lane):
    return identify(decode_tcp(frame, lane, ports(lane)))


def packets(path, lane):
    return [identify(row) for row in read_tcp(path, lane, ports(lane))]


def pattern(lane, role, kind):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (role * 97) ^ (kind * 41)) & 255
                 for at in range(RECOVERY_BYTES))


def stream(rows, origin, expected):
    received, present = bytearray(len(expected)), bytearray(len(expected))
    for row in rows:
        offset = (row['seq'] - origin) & MASK
        if not row['data']:
            continue
        require(offset + len(row['data']) <= len(expected), 'lifetime recovered payload sequence bounds')
        for at, value in enumerate(row['data'], offset):
            require(value == expected[at] and (not present[at] or received[at] == value),
                    'exact lifetime recovered bytes and consistent duplicates')
            received[at], present[at] = value, 1
    require(all(present), 'every lifetime recovered byte actually appears')
    return hashlib.sha256(received).hexdigest()


def period(rows, lane, role, kind, native):
    require(rows and all(b['ms'] >= a['ms'] for a, b in zip(rows, rows[1:])),
            'lifetime clock records preserve actual packet order')
    guest_syn = [row for row in rows if row['outgoing'] and row['flags'] & 2]
    peer_syn = [row for row in rows if not row['outgoing'] and row['flags'] & 2]
    require(len(guest_syn) == len(peer_syn) == 1 and
            guest_syn[0]['flags'] == (18 if role else 2) and peer_syn[0]['flags'] == (2 if role else 18),
            'one successful actual active/passive lifetime handshake')
    origin, remote = (guest_syn[0]['seq'] + 1) & MASK, (peer_syn[0]['seq'] + 1) & MASK
    require(not guest_syn[0]['data'] and not peer_syn[0]['data'] and
            (guest_syn[0]['ack'] == remote if role else peer_syn[0]['ack'] == origin),
            'lifetime SYN acknowledges only the owned sequence')
    closed = kind in (2, 3, 5)
    require(peer_syn[0]['window'] == (0 if closed else 8192), 'actual initial lifetime window')
    synchronized = max(rows.index(guest_syn[0]), rows.index(peer_syn[0])) + 1
    # A passive peer's final ACK has the same closed/open window as its SYN.
    if role:
        require(synchronized < len(rows) and not rows[synchronized]['outgoing'] and
                rows[synchronized]['flags'] == 16 and rows[synchronized]['ack'] == origin and
                rows[synchronized]['window'] == (0 if closed else 8192),
                'actual passive lifetime handshake completes')
        synchronized += 1
    body = rows[synchronized:]
    opened = next((index for index, row in enumerate(body) if not row['outgoing'] and row['window']), None)
    require((opened is not None) == (kind == 3), 'only responsive lifetime control reopens')
    stopped = body[:opened] if opened is not None else body
    attempts = []
    expected = pattern(lane, role, kind)
    for index, row in enumerate(stopped):
        if not row['outgoing']:
            require(kind == 3 and row['flags'] == 16 and not row['data'] and not row['window'] and
                    row['seq'] == remote and row['ack'] == origin,
                    'only responsive probes receive non-progress zero-window answers')
            continue
        require(row['flags'] & 16 and row['ack'] == remote, 'lifetime sender ACK preserves peer edge')
        if row['flags'] & 4:
            require(kind != 3 and attempts, 'no reset interrupts responsive lifetime control')
            minimum = 2300 if kind == 5 else (LONGER_MS if kind == 4 else DEFAULT_MS)
            require(row['ms'] - attempts[0] >= minimum - 1100, 'no reset shortens full lifetime')
            continue
        if kind in (0, 4):
            if not row['data']:
                require(row['flags'] == 16 and row['seq'] == origin, 'only synchronization ACK before data')
                continue
            require(row['data'] == expected[:1] and row['seq'] == origin and not row['flags'] & 7,
                    'only the original unanswered byte is retransmitted')
        elif kind == 1:
            require(not row['data'] and row['seq'] in (origin, (origin + 1) & MASK),
                    'pure FIN has no hidden payload or sequence progress')
            if not row['flags'] & 1:
                require(row['flags'] == 16, 'only an ordinary pure-FIN synchronization ACK')
                continue
            require(row['seq'] == origin and row['flags'] == 17, 'pure FIN retains its owned sequence')
        else:
            require(not row['flags'] & 7, 'closed-window observation contains probes and no FIN')
            if not row['data'] and row['seq'] == origin:
                continue
            require((native and not row['data'] and row['seq'] == (origin - 1) & MASK) or
                    (not native and kind == 5 and not row['data'] and row['seq'] == (origin - 1) & MASK) or
                    (not native and kind != 5 and row['data'] == expected[:1] and row['seq'] == origin),
                    'actual unanswered native/guest persist probe bytes and sequence')
        attempts.append(row['ms'])
        if kind == 3:
            end = next((at for at in range(index + 1, len(stopped)) if stopped[at]['outgoing']), len(stopped))
            require(any(not answer['outgoing'] and answer['flags'] == 16 and not answer['window'] and
                        answer['ack'] == origin for answer in stopped[index + 1:end]),
                    'every responsive lifetime probe has a real non-progress answer')
    require(len(attempts) >= ((3 if native else 2) if kind == 5 else (15 if native else 18)),
            'complete required real retry/probe sequence')
    intervals = [b - a for a, b in zip(attempts, attempts[1:])]
    initial_minimum = (300 if native else 1700) if closed else (180 if native else 850)
    require(initial_minimum <= intervals[0] < 4000, 'first actual retry/probe interval')
    cap = 120000 if native else 60000
    require(all(0 < interval <= cap * 1.15 + 500 for interval in intervals) and
            all(previous * 1.6 - 100 <= current <= previous * 2.6 + 500
                if previous < cap * .75 else cap * .85 <= current <= cap * 1.15 + 500
                for previous, current in zip(intervals, intervals[1:])),
            'complete exponential retries and capped actual intervals')
    output = dict(attempts_ms=attempts, intervals_ms=intervals, reopened_at=None,
                  received=0, sent=0, hashes={})
    if kind == 3:
        reopening = body[opened]
        require(reopening['flags'] == 16 and not reopening['data'] and reopening['window'] == 8192 and
                reopening['ack'] == origin and reopening['ms'] - attempts[0] >= LONGER_MS,
                'responsive default survives full default interval plus sixty seconds')
        recovery = body[opened:]
        outgoing = [row for row in recovery if row['outgoing']]
        incoming = [row for row in recovery if not row['outgoing']]
        require(not any(row['flags'] & 4 for row in recovery), 'no reset substitutes for exact lifetime recovery')
        output['hashes'] = dict(sent=stream(outgoing, origin, expected),
                                received=stream(incoming, remote, bytes(value ^ 0xa5 for value in expected)))
        require(remote > MASK - RECOVERY_BYTES and
                any(row['flags'] & 1 and row['seq'] + len(row['data']) & MASK ==
                    (origin + RECOVERY_BYTES) & MASK for row in outgoing) and
                any(row['flags'] & 1 and row['seq'] + len(row['data']) & MASK ==
                    (remote + RECOVERY_BYTES) & MASK for row in incoming) and
                any(row['ack'] == (remote + RECOVERY_BYTES + 1) & MASK for row in outgoing) and
                any(row['ack'] == (origin + RECOVERY_BYTES + 1) & MASK for row in incoming),
                'both recovered FINs acknowledged through real wrapped peer sequence')
        output.update(reopened_at=reopening['ms'], received=RECOVERY_BYTES, sent=RECOVERY_BYTES)
    return output


def verify(path, lane, evidence, native=False):
    rows = packets(path, lane)
    require(evidence['lane'] == lane and len(evidence['flows']) == CASES * 2, 'twelve actual lifetime flows per NIC')
    records, clocks = [], defaultdict(lambda: ([], []))
    for entry in evidence['frames']:
        row = decode(bytes.fromhex(entry['frame']), lane)
        if row is not None:
            require(row['outgoing'] == (entry['direction'] == 'receive'), 'actual lifetime packet direction')
            records.append(dict(row, ms=entry['ms']))
            clocks[row['frame']][1].append(entry['ms'])
    require(Counter(row['frame'] for row in rows) == Counter(row['frame'] for row in records),
            'every PCAP and peer lifetime packet is identical')
    for row in rows:
        clocks[row['frame']][0].append(row['ms'])
    differences = [a - b for captured, observed in clocks.values() for a, b in zip(captured, observed)]
    require(max(differences) - min(differences) <= 100,
            'kernel packet and independent monotonic clocks agree throughout the full interval')
    checked = []
    for kind, role in itertools.product(range(CASES), range(2)):
        captured = period([row for row in rows if (row['kind'], row['role']) == (kind, role)], lane, role, kind, native)
        observed = period([row for row in records if (row['kind'], row['role']) == (kind, role)], lane, role, kind, native)
        reports = [flow for flow in evidence['flows'] if (flow['kind'], flow['role']) == (kind, role)]
        require(len(reports) == 1, 'one actual lifetime tuple result')
        report = reports[0]
        reopening_matches = (report['reopened_at'] is None and observed['reopened_at'] is None) or (
            report['reopened_at'] is not None and observed['reopened_at'] is not None and
            abs(report['reopened_at'] - observed['reopened_at']) < 10)
        require(report['attempts_ms'] == observed['attempts_ms'] and report['received'] == observed['received'] and
                report['sent'] == observed['sent'] and reopening_matches and report['passed'],
                'reported lifetime events match independently decoded packets')
        app, start = report['application'], report['started']
        option = LONGER_MS if kind == 4 else (2500 if kind == 5 else 0)
        require(app['option_ms'] == start['option_ms'] == option and app['error'] == (0 if kind == 3 else 110) and
                app['consumed'] == ('none' if kind == 3 else ('SO_ERROR' if role else 'recv')) and
                app['reclaimed'] == int(kind != 3), 'actual default/configured option, error consumption and owner release')
        elapsed = app['ms'] - start['ms']
        require(abs(elapsed - app['elapsed_ms']) < 500 and
                observed['attempts_ms'][0] >= start['ms'] - 100 and observed['attempts_ms'][-1] <= app['ms'],
                'actual application and independent full lifetime clocks agree')
        if kind == 3:
            require(app['elapsed_ms'] >= LONGER_MS and 0 <= app['ms'] - observed['reopened_at'] < 20000,
                    'default responsive lifetime control recovers after its full observation')
        else:
            threshold = 2500 if kind == 5 else (LONGER_MS if kind == 4 else DEFAULT_MS)
            upper = 6000 if kind == 5 else (1200000 if native else threshold + 5000)
            require(threshold - (200 if kind == 5 else 100) <= app['elapsed_ms'] < upper,
                    'actual unshortened default or authoritative configured socket deadline')
            anchored = app['ms'] - observed['attempts_ms'][0]
            require(threshold - 100 <= anchored < (3500 if kind == 5 else upper),
                    'default/configured failure observes first actual owned output')
        checked.append(dict(kind=kind, role=role, capture=captured, peer=observed, application=app, passed=True))
    return dict(file=path.name, lane=lane, packets=len(rows), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                clock_variation_ms=max(differences) - min(differences), flows=checked, passed=True)


def peer_evidence(directory, row):
    require(Path(row['peer']).name == row['peer'] and Path(row['log']).name == row['log'], 'bounded lifetime evidence paths')
    peers = json.loads((directory / row['peer']).read_text())
    require(len(peers) == len(row['peers']) == 2, 'both lifetime NIC peers')
    lines = (directory / row['log']).read_text().splitlines()
    for lane, peer in enumerate(peers):
        require(peer['lane'] == row['peers'][lane]['lane'] == lane, 'actual lifetime NIC identity')
        peer['flows'] = row['peers'][lane]['flows']
        require(len(peer['flows']) == CASES * 2, 'all lifetime application tuples')
        for flow in peer['flows']:
            app, start = flow['application'], flow['started']
            identity = f"lane={lane} role={flow['role']} kind={flow['kind']}"
            require(lines.count(f"TCP_LIFETIME_STARTED {identity} option_ms={start['option_ms']}") == 1 and
                    lines.count(f"TCP_LIFETIME_FLOW_PASS {identity} option_ms={app['option_ms']} "
                                f"elapsed_ms={app['elapsed_ms']} error={app['error']} consumed={app['consumed']} "
                                f"reclaimed={app['reclaimed']}") == 1, 'one complete actual start and result log for every tuple')
    require(lines.count('TCP_LIFETIME_PASS flows=24 default_ms=924600 longer_ms=984600') == 1 and
            not any('TCP_LIFETIME_FAIL' in line for line in lines), 'actual lifetime application completes all contracts')
    return peers


REPORTS = ['tcp-lifetime-native-results.json', *[f'tcp-lifetime-{firmware}-{transport}-results.json'
           for firmware, transport in itertools.product(('bios', 'uefi'), ('modern', 'legacy'))]]


def check_results(directory, names=None):
    names = REPORTS if names is None else names
    require(names and len(names) == len(set(names)) and set(names) <= set(REPORTS), 'explicit complete lifetime report scopes')
    verified, hashes = [], {}
    for name in names:
        path = directory / name
        rows = json.loads(path.read_text())
        native = name == REPORTS[0]
        expected = {'native', 'static', 'dynamic'} if native else {
            (linkage, *name.removeprefix('tcp-lifetime-').removesuffix('-results.json').split('-'))
            for linkage in ('static', 'dynamic')}
        identities = {row['linkage'] if native else (row['linkage'], row['firmware'], row['transport']) for row in rows}
        require(len(rows) == len(expected) and identities == expected, 'every native/guest linkage in the requested scope')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for row in rows:
            require(row['wire'] == 'lifetime' and row['passed'] and not row['error'] and not row['missing'] and
                    row['returncode'] == (0 if native else 1), 'actual complete lifetime observation succeeds')
            if native:
                require(bool(row['kernel']) and len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3 and
                        row['defaults'] == dict(tcp_retries1=3, tcp_retries2=15, tcp_syn_retries=6, tcp_synack_retries=5) and
                        not row['host_configuration_changed'] and len(row['capture_statistics']) == 2 and
                        all(stat['dropped'] == 0 and stat['packets'] > 0 and stat['buffer_bytes'] >= 4 * 1024 * 1024
                            for stat in row['capture_statistics']), 'unaltered native defaults and complete zero-drop isolated captures')
            require(len(row['captures']) == 2 and all(Path(item).name == item for item in row['captures']),
                    'both bounded complete lifetime capture paths')
            peers = peer_evidence(directory, row)
            verified += [verify(directory / item, lane, peers[lane], native) for lane, item in enumerate(row['captures'])]
    output = dict(captures=verified, reports=hashes, flows=len(verified) * CASES * 2,
                  complete_matrix=set(names) == set(REPORTS), passed=True)
    (directory / 'tcp-lifetime-capture-results.json').write_text(json.dumps(output, indent=2) + '\n')
    print(f'TCP_LIFETIME_CAPTURE_PASS captures={len(verified)} flows={output["flows"]} complete_matrix={output["complete_matrix"]}')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', nargs='+', choices=REPORTS)
    args = parser.parse_args()
    check_results(Path(__file__).resolve().parents[2] / 'build', args.report)
