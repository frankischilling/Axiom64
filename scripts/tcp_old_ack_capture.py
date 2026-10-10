# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify rejected old ACKs, unchanged receive sequence and exact subsequent streams."""
from collections import Counter, defaultdict, deque
import hashlib
import itertools
import json
from pathlib import Path
from tcp_fault_capture import BYTES, MASK, decode, packets, require, stream


def verify(path, lane, peer_rows, native=False):
    rows = packets(path, lane)
    require(peer_rows['lane'] == lane, 'old-ACK capture and independent peer lane')
    reported = defaultdict(deque)
    for record in peer_rows['frames']:
        row = decode(bytes.fromhex(record['frame']), lane)
        if row is not None:
            require(record['direction'] in ('send', 'receive') and
                    row['outgoing'] == (record['direction'] == 'receive'), 'old-ACK peer direction')
            reported[row['frame']].append(record)
    require(Counter(row['frame'] for row in rows) == Counter({frame: len(records) for frame, records in reported.items()}),
            'old-ACK capture matches every actual peer/guest TCP frame')
    for row in rows:
        row['record'] = reported[row['frame']].popleft()
    results = []
    for role in range(2):
        flow = [row for row in rows if row['role'] == role]
        guest = [row for row in flow if row['outgoing']]
        peer = [row for row in flow if not row['outgoing']]
        require(guest and peer and not any(row['flags'] & 4 for row in flow), 'old-ACK stream has no resets')
        syns = [row for row in guest if row['flags'] & 2]
        peer_syns = [row for row in peer if row['flags'] & 2]
        require(len(syns) >= 2 and peer_syns and
                all(row['seq'] == syns[0]['seq'] and bool(row['flags'] & 16) == bool(role) for row in syns),
                'old-ACK actual active/passive retransmitted handshake')
        guest_origin = (syns[0]['seq'] + 1) & MASK
        peer_origin = (peer_syns[0]['seq'] + 1) & MASK
        require(peer_origin >= MASK - BYTES, 'old-ACK original peer stream actually wraps')
        snd_una = (guest_origin + BYTES + 1) & MASK
        attacks = [row for row in flow if 'attack' in row['record']]
        challenges = [row for row in flow if 'challenge' in row['record']]
        require([row['record']['attack'] for row in attacks] == [1, 2, 3] and
                [row['record']['challenge'] for row in challenges] == [1, 2, 3],
                'three complete actual old-ACK injection/response barriers')
        attack_ids = {id(row) for row in attacks}
        benign = [row for row in peer if id(row) not in attack_ids]
        barriers = []
        for number, (attack, challenge, shape) in enumerate(zip(attacks, challenges,
                                                               ((16, b'bad'), (17, b''), (17, b'bad')))):
            start, end = flow.index(attack), flow.index(challenge)
            previous = [row for row in flow[:start] if not row['outgoing'] and id(row) not in attack_ids]
            require(previous and max(row['window'] for row in previous) == 8192 and
                    next(row for row in reversed(previous) if row['flags'] & 16)['ack'] == snd_una,
                    'actual maximum peer window and acknowledged guest FIN precede injection')
            require(any(row['outgoing'] and row['flags'] & 1 and
                        (row['seq'] + len(row['data']) + 1) & MASK == snd_una for row in flow[:start]),
                    'old-ACK bound follows actually transmitted guest sequence space')
            require(not attack['outgoing'] and (attack['flags'], attack['data']) == shape and
                    attack['seq'] == peer_origin and attack['window'] == 65535 and
                    attack['ack'] == (snd_una - 8192 - 1) & MASK,
                    'in-window poison payload/FIN is exactly one byte outside the learned ACK bound')
            require(challenge['outgoing'] and challenge['flags'] == 16 and not challenge['data'] and
                    challenge['seq'] == snd_una and challenge['ack'] == peer_origin and start < end and
                    challenge['record']['ms'] >= attack['record']['ms'] and challenge['ms'] >= attack['ms'],
                    'actual causal challenge ACK preserves both sequence edges')
            require(not any(row['outgoing'] or row['data'] or row['flags'] & 1
                            for row in flow[start + 1:end]), 'challenge is the first actual guest response to poison')
            if number:
                earlier = challenges[number - 1]
                require(flow.index(earlier) < start and attack['record']['ms'] - earlier['record']['ms'] >= 1200 and
                        attack['ms'] - earlier['ms'] >= 1195,
                        'old-ACK injections retain actual wait between response barriers')
            barriers.append(dict(attack=number + 1, lower_bound=(snd_una - 8192) & MASK,
                                 acknowledgment=attack['ack'], receive_next=challenge['ack'], passed=True))
        first_data = next(row for row in benign if row['data'])
        require(flow.index(first_data) > flow.index(challenges[-1]) and first_data['seq'] == peer_origin,
                'original stream starts at unchanged receive sequence after all rejected injections')
        guest_hash = stream(guest, guest_origin, lane, role, 0)
        peer_hash = stream(benign, peer_origin, lane, role, 1)
        drops = [row for row in flow if 'drop' in row['record']]
        require(len(drops) == 3 and {row['record']['drop'] for row in drops} == {'handshake', 'data', 'fin'},
                'old-ACK profile retains all three actual loss injections')
        retries = {}
        for dropped in drops:
            same = [row for row in guest if row['seq'] == dropped['seq'] and row['data'] == dropped['data'] and
                    (row['flags'] & 3) == (dropped['flags'] & 3)]
            require(len(same) >= 2 and same[0] is dropped, 'old-ACK lost sequence/bytes actually retry')
            label = dropped['record']['drop']
            minimum = (180 if native else 850) if label == 'fin' else (2850 if label == 'data' else 850)
            elapsed = same[1]['record']['ms'] - dropped['record']['ms']
            require(elapsed >= minimum and same[1]['ms'] - dropped['ms'] >= minimum - 5,
                    'old-ACK profile retains actual independent loss retry clocks')
            before, after = flow.index(same[0]), flow.index(same[1])
            edge = (dropped['seq'] + len(dropped['data']) + int(bool(dropped['flags'] & 3))) & MASK
            require(not any(not row['outgoing'] and row['flags'] & 16 and
                            ((row['ack'] - edge) & MASK) < (1 << 31) for row in flow[before + 1:after]),
                    'old-ACK discarded guest sequence remains unacknowledged until actual retry')
            retries[label] = round(elapsed, 3)
        for outgoing, origin, opposite in ((guest, guest_origin, benign), (benign, peer_origin, guest)):
            finishes = [row for row in outgoing if row['flags'] & 1]
            require(finishes and all((row['seq'] + len(row['data'])) & MASK == (origin + BYTES) & MASK
                                     for row in finishes), 'old-ACK valid FIN follows every original byte')
            require(any(row['flags'] & 16 and row['ack'] == (origin + BYTES + 1) & MASK for row in opposite),
                    'old-ACK exact recovery includes final FIN acknowledgment')
        results.append(dict(role=role, bytes_each=BYTES, guest_sha256=guest_hash, peer_sha256=peer_hash,
                            sequence_wrap=True, retries_ms=retries, old_ack=barriers, passed=True))
    return dict(file=path.name, lane=lane, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                packets=len(rows), flows=results, passed=True)


def check_results(directory):
    verified, reports = [], {}
    for name, native in (('tcp-old-ack-native-results.json', True), ('tcp-old-ack-results.json', False)):
        path = directory / name
        require(path.is_file(), 'both complete native and guest old-ACK reports exist')
        reports[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        rows = json.loads(path.read_text())
        if native:
            require(len(rows) == 3 and {row['linkage'] for row in rows} == {'native', 'static', 'dynamic'},
                    'all three native old-ACK libc profiles')
        else:
            expected = set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
            require(len(rows) == 8 and {(row['linkage'], row['firmware'], row['transport']) for row in rows} == expected,
                    'all eight guest old-ACK firmware/transport/linkage cases')
        for row in rows:
            require(row['wire'] == 'old-ack' and row['passed'] and not row['error'] and not row['missing'] and
                    row['returncode'] == (0 if native else 1), 'successful actual old-ACK client and peer result')
            if native:
                require(len({row['parent_namespace'], row['peer_namespace'], row['client_namespace']}) == 3 and
                        len(row['capture_statistics']) == 2 and
                        all(stat['dropped'] == 0 and stat['packets'] > 0 and stat['buffer_bytes'] >= 4 * 1024 * 1024
                            for stat in row['capture_statistics']), 'isolated native old-ACK capture without drops')
            require(Path(row['peer']).name == row['peer'] and Path(row['log']).name == row['log'],
                    'old-ACK peer/log evidence path bounds')
            text = (directory / row['log']).read_text()
            require('TCP_FAULT_PASS flows=4 bytes_each=65536' in text and
                    all(f'TCP_FAULT_FLOW_PASS lane={lane} role={role} bytes_each=65536' in text
                        for lane, role in itertools.product(range(2), range(2))) and
                    not any(marker in text for marker in ('TCP_FAULT_FAIL', 'PANIC:', 'FAULT pid=')),
                    'actual socket logs recover every original bidirectional stream')
            if not native:
                require(all(marker in text for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                            f'Firmware: {row["firmware"].upper()}',
                            f'virtio-net: index=1 transport={row["transport"]}', 'e1000: index=2 model=82540EM')),
                        'old-ACK actual guest firmware and both NIC drivers')
            peers = json.loads((directory / row['peer']).read_text())
            require(len(peers) == len(row['captures']) == 2, 'both independent old-ACK adapter captures')
            for lane, name in enumerate(row['captures']):
                require(Path(name).name == name, 'old-ACK capture path bounds')
                verified.append(verify(directory / name, lane, peers[lane], native))
    require(len(verified) == 22, 'all twenty-two complete old-ACK captures')
    output = dict(captures=verified, flows=44, attacks=132, reports=reports, passed=True)
    (directory / 'tcp-old-ack-capture-results.json').write_text(json.dumps(output, indent=2) + '\n')
    print('TCP_OLD_ACK_CAPTURE_PASS captures=22 flows=44 attacks=132 challenge_acks=132 exact_bytes loss wrap FIN')
    return output


if __name__ == '__main__':
    check_results(Path(__file__).resolve().parents[1] / 'build')
