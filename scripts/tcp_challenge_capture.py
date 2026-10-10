# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently verify mixed control bursts, complete silence and exact stream recovery."""
from collections import Counter, defaultdict, deque
import hashlib
import itertools
import json
import re
from pathlib import Path
from tcp_fault_capture import BYTES, MASK, decode, packets, require, stream


def shape(kind, receive, send):
    flags, sequence, acknowledgment, data = 17, receive, send, b'bad'
    if kind == 0:
        acknowledgment = (send - 8193) & MASK
    elif kind == 1:
        acknowledgment = (send + 1) & MASK
    elif kind in (2, 3, 6):
        flags = 18
        if kind == 3:
            sequence = (receive + 0x40000000) & MASK
        if kind == 6:
            data = b''
    elif kind in (4, 7):
        flags, sequence = 4, (receive + 1) & MASK
        if kind == 7:
            data = b''
    elif kind == 5:
        flags, sequence, data = 16, (receive + 0x40000000) & MASK, b''
    return flags, sequence, acknowledgment, data


def verify(path, lane, peer_rows, native=False):
    rows = packets(path, lane)
    require(peer_rows['lane'] == lane, 'challenge lane identity')
    reported = defaultdict(deque)
    for record in peer_rows['frames']:
        row = decode(bytes.fromhex(record['frame']), lane)
        if row is not None:
            require(record['direction'] in ('send', 'receive') and
                    row['outgoing'] == (record['direction'] == 'receive') and
                    record.get('role', row['role']) == row['role'], 'actual challenge direction and role')
            reported[row['frame']].append(record)
    require(Counter(row['frame'] for row in rows) ==
            Counter({frame: len(records) for frame, records in reported.items()}),
            'challenge capture includes every actual peer/guest TCP frame')
    for row in rows:
        row['record'] = reported[row['frame']].popleft()
    results, first_responses = [], []
    for role in range(2):
        flow = [row for row in rows if row['role'] == role]
        positions = {id(row): at for at, row in enumerate(flow)}

        def position(row):
            return positions[id(row)]

        attacks = [row for row in flow if 'attack' in row['record']]
        challenges = [row for row in flow if 'challenge' in row['record']]
        require(len(attacks) == 136 and [row['record']['challenge'] for row in challenges] == list(range(1, 9)),
                'eight complete actual challenge responses and all 136 mixed injections')
        attack_ids = {id(row) for row in attacks}
        benign = [row for row in flow if not row['outgoing'] and id(row) not in attack_ids]
        guest = [row for row in flow if row['outgoing']]
        syns = [row for row in guest if row['flags'] & 2]
        peer_syns = [row for row in benign if row['flags'] & 2]
        require(len(syns) >= 2 and peer_syns and
                all(row['seq'] == syns[0]['seq'] and bool(row['flags'] & 16) == bool(role) for row in syns),
                'actual retransmitted active and accepted handshake')
        guest_origin, peer_origin = (syns[0]['seq'] + 1) & MASK, (peer_syns[0]['seq'] + 1) & MASK
        send = (guest_origin + BYTES + 1) & MASK
        require(peer_origin >= MASK - BYTES and not any(row['flags'] & 4 for row in guest + benign),
                'actual wrapped peer stream and no valid-stream resets')
        first_data = next(row for row in benign if row['data'])
        require(first_data['seq'] == peer_origin, 'recovery starts at the unchanged receive edge')
        barriers = []
        for number, response in enumerate(challenges, 1):
            group = [row for row in attacks if row['record']['attack'] == number]
            expected = [(number - 1, 0)] + [(kind, wave) for wave in (1, 2) for kind in range(8)]
            require([(row['record']['kind'], row['record']['wave']) for row in group] == expected,
                    'each round has the exact trigger and two complete eight-kind bursts')
            trigger = group[0]
            require(position(trigger) < position(response) < position(group[1]) and
                    response['flags'] == 16 and not response['data'] and response['seq'] == send and
                    response['ack'] == peer_origin, 'causal challenge rejects all poison sequence space')
            prior = [row for row in benign if position(row) < position(trigger)]
            require(prior and max(row['window'] for row in prior) == 8192 and
                    next(row for row in reversed(prior) if row['flags'] & 16)['ack'] == send and
                    any(row['flags'] & 1 and (row['seq'] + len(row['data']) + 1) & MASK == send
                        for row in guest if position(row) < position(trigger)),
                    'actually acknowledged guest FIN and learned window precede attack')
            for row in group:
                require(not row['outgoing'] and row['window'] == 65535 and
                        (row['flags'], row['seq'], row['ack'], row['data']) ==
                        shape(row['record']['kind'], peer_origin, send), 'exact invalid control injection shape')
            end = attacks[number * 17] if number < 8 else first_data
            start_index, end_index = position(response), position(end)
            require(position(group[-1]) < end_index and
                    not any(row['outgoing'] or id(row) not in attack_ids
                            for row in flow[start_index + 1:end_index]),
                    'complete observed silence includes all bursts and no concealed extra replies')
            for clock in ('ms', 'peer'):
                def timestamp(row):
                    return row['record']['ms'] if clock == 'peer' else row['ms']
                reply_at = timestamp(response)
                require(0 <= reply_at - timestamp(trigger) <= 250,
                        'actual challenge follows trigger promptly in both clocks')
                require(all(0 <= timestamp(row) - reply_at <= 250 for row in group[1:]) and
                        timestamp(group[9]) - reply_at >= 95,
                        'both complete bursts occur within the interval on both clocks')
                require(timestamp(end) - reply_at >= (650 if clock == 'peer' else 645),
                        'each silence barrier retains the full real elapsed wait on both clocks')
            barriers.append(dict(round=number, injections=17,
                                 silence_ms=round(end['record']['ms'] - response['record']['ms'], 3), passed=True))
        require(position(first_data) > position(challenges[-1]), 'valid data follows all challenge barriers')
        hashes = (stream(guest, guest_origin, lane, role, 0), stream(benign, peer_origin, lane, role, 1))
        drops = [row for row in guest if 'drop' in row['record']]
        require(len(drops) == 3 and {row['record']['drop'] for row in drops} == {'handshake', 'data', 'fin'},
                'challenge profile retains all three actual loss injections')
        retries = {}
        for dropped in drops:
            same = [row for row in guest if row['seq'] == dropped['seq'] and row['data'] == dropped['data'] and
                    (row['flags'] & 3) == (dropped['flags'] & 3)]
            label = dropped['record']['drop']
            minimum = (180 if native else 850) if label == 'fin' else (2850 if label == 'data' else 850)
            require(len(same) >= 2 and same[0] is dropped and
                    same[1]['record']['ms'] - dropped['record']['ms'] >= minimum and
                    same[1]['ms'] - dropped['ms'] >= minimum - 5, 'actual loss retry in both clocks')
            edge = (dropped['seq'] + len(dropped['data']) + int(bool(dropped['flags'] & 3))) & MASK
            require(not any(not row['outgoing'] and row['flags'] & 16 and
                            ((row['ack'] - edge) & MASK) < (1 << 31)
                            for row in flow[position(dropped) + 1:position(same[1])]),
                    'lost sequence is unacknowledged before its actual retry')
            retries[label] = round(same[1]['record']['ms'] - dropped['record']['ms'], 3)
        for outgoing, origin, opposite in ((guest, guest_origin, benign), (benign, peer_origin, guest)):
            finishes = [row for row in outgoing if row['flags'] & 1]
            require(finishes and all((row['seq'] + len(row['data'])) & MASK == (origin + BYTES) & MASK
                                     for row in finishes) and
                    any(row['flags'] & 16 and row['ack'] == (origin + BYTES + 1) & MASK for row in opposite),
                    'exact recovered stream includes FIN and final acknowledgment')
        first_responses.append(challenges[0])
        results.append(dict(role=role, bytes_each=BYTES, guest_sha256=hashes[0], peer_sha256=hashes[1],
                            sequence_wrap=True, retries_ms=retries, challenge=barriers, passed=True))
    require(abs(first_responses[0]['record']['ms'] - first_responses[1]['record']['ms']) < 450 and
            abs(first_responses[0]['ms'] - first_responses[1]['ms']) < 450,
            'independent connections both respond within one 500 ms interval on both clocks')
    return dict(file=path.name, lane=lane, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                packets=len(rows), flows=results, passed=True)


def check_results(directory):
    verified, reports = [], {}
    for name, native in (('tcp-challenge-native-results.json', True), ('tcp-challenge-results.json', False)):
        path = directory / name
        require(path.is_file(), 'both complete native and guest challenge reports exist')
        reports[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        rows = json.loads(path.read_text())
        if native:
            require(len(rows) == 3 and {row['linkage'] for row in rows} == {'native', 'static', 'dynamic'},
                    'all three native challenge libc profiles')
        else:
            expected = set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
            require(len(rows) == 8 and {(row['linkage'], row['firmware'], row['transport']) for row in rows} == expected,
                    'all eight guest challenge firmware/transport/linkage cases')
        for row in rows:
            require(row['wire'] == 'challenge' and row['passed'] and not row['error'] and not row['missing'] and
                    row['returncode'] == (0 if native else 1), 'actual challenge client and peer success')
            if native:
                require(len({row['parent_namespace'], row['peer_namespace'], row['client_namespace']}) == 3 and
                        len(row['capture_statistics']) == 2 and
                        all(stat['dropped'] == 0 and stat['packets'] > 0 and stat['buffer_bytes'] >= 4 * 1024 * 1024
                            for stat in row['capture_statistics']), 'isolated native challenge captures without drops')
            require(Path(row['peer']).name == row['peer'] and Path(row['log']).name == row['log'],
                    'challenge report evidence path bounds')
            text = (directory / row['log']).read_text()
            require('TCP_FAULT_PASS flows=4 bytes_each=65536' in text and
                    all(f'TCP_FAULT_FLOW_PASS lane={lane} role={role} bytes_each=65536' in text
                        for lane, role in itertools.product(range(2), range(2))) and
                    not any(marker in text for marker in ('TCP_FAULT_FAIL', 'PANIC:', 'FAULT pid=')),
                    'actual socket logs recover all concurrent bidirectional streams')
            if not native:
                setup = re.findall(r'TCP_CHALLENGE_SETUP_WAIT_PASS elapsed_ms=(\d+)', text)
                require(len(setup) == 1 and int(setup[0]) >= 1200,
                        'actual concurrent guest observes the complete adapter setup wait')
                require(all(marker in text for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                            f'Firmware: {row["firmware"].upper()}',
                            f'virtio-net: index=1 transport={row["transport"]}', 'e1000: index=2 model=82540EM')),
                        'actual guest firmware and both NIC drivers')
            peers = json.loads((directory / row['peer']).read_text())
            require(len(peers) == len(row['captures']) == 2, 'both independent challenge adapter captures')
            for lane, name in enumerate(row['captures']):
                require(Path(name).name == name, 'challenge capture path bounds')
                verified.append(verify(directory / name, lane, peers[lane], native))
    require(len(verified) == 22, 'all twenty-two complete challenge captures')
    output = dict(captures=verified, flows=44, attacks=5984, challenges=352, reports=reports, passed=True)
    (directory / 'tcp-challenge-capture-results.json').write_text(json.dumps(output, indent=2) + '\n')
    print('TCP_CHALLENGE_CAPTURE_PASS captures=22 flows=44 attacks=5984 challenges=352 silence independent exact_bytes')
    return output


if __name__ == '__main__':
    check_results(Path(__file__).resolve().parents[1] / 'build')
