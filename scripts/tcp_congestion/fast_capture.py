# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct duplicate-ACK inflation and deflation from original captured bytes."""
from tcp_congestion.window_capture import require, MASK, MSS, expected, observe_wait
from tcp_capture_clock import milliseconds

def reconstruct(rows, lane, native):
    syn = [row for row in rows if row['outgoing'] and row['flags'] & 2]
    synack = [row for row in rows if not row['outgoing'] and row['flags'] & 2]
    require(len(syn) == len(synack) == 1 and not any(row['flags'] & 4 for row in rows),
            'one valid active fast-recovery handshake without resets')
    origin, reverse = (syn[0]['seq'] + 1) & MASK, (synack[0]['seq'] + 1) & MASK
    require(synack[0]['ack'] == origin and synack[0]['frame'][54:58] == bytes.fromhex('020405b4'),
            'actual fast-recovery handshake negotiates MSS1460')
    acks = [(index, row) for index, row in enumerate(rows) if not row['outgoing'] and row['flags'] == 16
            and not row['data'] and ((row['ack'] - origin) & MASK) > 0]
    require(len(acks) >= 8 and all(((row['ack'] - origin) & MASK) == MSS and row['window'] == 65535
            for _, row in acks[:5]) and ((acks[5][1]['ack'] - origin) & MASK) > MSS and
            [row['window'] for _, row in acks[5:8]] == [65535, 1024, 65535],
            'one advancing ACK, exactly four duplicates, recovery ACK and actual window gates')
    boundaries = [acks[at][0] for at in (0, 3, 4, 5, 6, 7)]
    stages = ['opening', 'growth', 'fast', 'extra', 'recovery', 'receiver', 'complete']
    maximum = {name: 0 for name in stages}
    frontier = acked = 0
    window, stage, threshold = 65535, 0, None
    present, reply_present = bytearray(65536), bytearray(16)
    retries = []
    own_fin = peer_fin = own_fin_ack = peer_fin_ack = False
    for index, row in enumerate(rows):
        if not row['outgoing']:
            if row['flags'] & 16:
                acknowledged = (row['ack'] - origin) & MASK
                require(acked <= acknowledged <= frontier + int(own_fin), 'fast-recovery ACK owns actual emitted bytes and FIN')
                acked, window = acknowledged, row['window']
            if index in boundaries:
                stage += 1
                if stage == 2:
                    threshold = max((frontier - acked) // 2, 2 * MSS)
                elif stage >= 4:
                    require(acked == frontier, 'recovery/window ACK owns the complete independently observed prefix')
            if row['data']:
                at = (row['seq'] - reverse) & MASK
                require(at + len(row['data']) <= 16 and row['data'] == expected(lane, 1, at, len(row['data'])),
                        'fast-recovery exact reverse application bytes')
                reply_present[at:at + len(row['data'])] = b'\1' * len(row['data'])
            if row['flags'] & 1:
                require(((row['seq'] - reverse) & MASK) == 16 and all(reply_present), 'reverse FIN follows exact reply')
                peer_fin = True
            if row['flags'] & 16 and row['ack'] == (origin + 65537) & MASK:
                require(own_fin, 'actual forward FIN precedes its acknowledgment')
                own_fin_ack = True
            continue
        if row['flags'] & 16:
            acknowledged = (row['ack'] - reverse) & MASK
            require(acknowledged <= sum(reply_present) + int(peer_fin), 'reverse ACK owns only actual reply and FIN')
            if acknowledged == 17:
                peer_fin_ack = True
        if row['data']:
            at, size = (row['seq'] - origin) & MASK, len(row['data'])
            require(size <= MSS and at + size <= 65536 and row['data'] == expected(lane, 0, at, size),
                    'exact fast-recovery payload and negotiated segment bounds')
            require(at >= acked and at + size <= acked + window, 'fast-recovery emission respects actual receive ownership')
            repeated = all(present[at:at + size])
            if repeated:
                require(stage in (2, 3) and at == MSS and size == MSS, 'only the actual oldest segment is fast retransmitted')
                retries.append(row)
            else:
                require(at == frontier, 'fast-recovery new bytes extend the actual contiguous frontier')
            present[at:at + size] = b'\1' * size
            frontier = max(frontier, at + size)
            flight = frontier - acked
            name = stages[stage]
            maximum[name] = max(maximum[name], flight)
            if native:
                # Linux may use two-MSS Limited Transmit before fast recovery;
                # retain that allowance without treating it as Reno's guest cwnd.
                bound = dict(opening=14600, growth=16060 + 2 * MSS, fast=16060 + 2 * MSS,
                             extra=16060 + 3 * MSS, recovery=14600, receiver=1024).get(name)
            else:
                bound = dict(opening=4380, growth=5840, fast=(threshold or 0) + 3 * MSS,
                             extra=(threshold or 0) + 4 * MSS, recovery=threshold, receiver=1024).get(name)
            require(bound is None or flight <= bound, name + ' duplicate-ACK flight obeys independent congestion bound')
        if row['flags'] & 1:
            require(((row['seq'] + len(row['data']) - origin) & MASK) == 65536 and all(present),
                    'forward FIN follows the complete exact fast-recovery stream')
            own_fin = True
    require(len(retries) == 1 and boundaries[1] < rows.index(retries[0]) < boundaries[2],
            'three actual duplicate ACKs precede one oldest-segment retry before the fourth')
    response = milliseconds(retries[0]) - milliseconds(acks[3][1])
    require(0 <= response < 100, 'actual duplicate-ACK retry arrives before a retransmission timer could account for it')
    require(all(present) and all(reply_present) and own_fin_ack and peer_fin_ack and
            maximum['receiver'] == 1024 and maximum['recovery'] < maximum['extra'],
            'actual fast recovery deflates, obeys small window, and closes both exact streams')
    first_data = next(row for row in rows if row['outgoing'] and row['data'])
    observe_wait(first_data, acks[0][1], 100)
    observe_wait(acks[0][1], acks[1][1], 100)
    observe_wait(acks[5][1], acks[6][1], 100)
    observe_wait(acks[6][1], acks[7][1], 350)
    return dict(passed=True, maximum_flight=maximum, guest_loss_threshold=None if native else threshold,
                actual_retry_response_ms=response, bytes=65536, reply_bytes=16, both_FINs_acknowledged=True)
