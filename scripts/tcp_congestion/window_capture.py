# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct real RTO flight and receiver-window ownership from original packets."""
import hashlib
from tcp_fault_capture import packets, decode, require, MASK
from tcp_capture_clock import milliseconds

MSS, SIZE = 1460, 65536


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected(lane, direction, offset, size):
    return bytes(((at * 29) ^ (at >> 7) ^ (lane * 53) ^ (direction * 41)) & 255
                 for at in range(offset, offset + size))


def observe_wait(start, finish, minimum):
    require(milliseconds(finish) - milliseconds(start) >= minimum - 5,
            'original capture retains the full ACK-gated observation interval')
    if 'peer_ms' in start and 'peer_ms' in finish:
        require(finish['peer_ms'] - start['peer_ms'] >= minimum,
                'independent peer retains the full ACK-gated observation interval')


def reconstruct(rows, lane, native=False):
    """Use only independently decoded captured packets to determine bounds."""
    guest = [row for row in rows if row['outgoing']]
    peer = [row for row in rows if not row['outgoing']]
    require(guest and peer and not any(row['flags'] & 4 for row in rows), 'unreset bidirectional stream')
    syn = [row for row in guest if row['flags'] & 2]
    synack = [row for row in peer if row['flags'] & 2]
    require(len(syn) == len(synack) == 1 and syn[0]['flags'] == 2 and synack[0]['flags'] == 18,
            'one complete active handshake')
    origin, reverse = (syn[0]['seq'] + 1) & MASK, (synack[0]['seq'] + 1) & MASK
    require(synack[0]['ack'] == origin and synack[0]['window'] == 65535 and
            synack[0]['frame'][54:58] == bytes.fromhex('020405b4'), 'captured MSS and nonbinding receive window')
    boundaries = [(index, row) for index, row in enumerate(rows)
                  if not row['outgoing'] and row['flags'] == 16 and not row['data'] and
                  (row['ack'] - origin) & MASK > 0]
    require(len(boundaries) >= 4, 'all four independent ACK gates are captured')
    gates = boundaries[:4]
    owned = [(row['ack'] - origin) & MASK for _, row in gates]
    require(owned[0] == MSS and all(a < b for a, b in zip(owned, owned[1:])) and
            [row['window'] for _, row in gates] == [65535, 65535, 1024, 65535],
            'advancing ACK gates and actual receiver-window transition')
    positions = [index for index, _ in gates]
    limits = dict(opening=14600 if native else 4380,
                  growth=16060 if native else 5840)
    # The native comparison may use CUBIC and Linux loss-recovery undo. Its
    # recovery is measured independently; Axiom64's conservative sender has a
    # separately checked two-MSS ceiling after the full RTO recovery ACK.
    present = [bytearray(SIZE), bytearray(16)]
    frontier, acked, window = 0, 0, 65535
    stages = ['opening', 'growth', 'recovery', 'receiver', 'complete']
    maximum = {name: 0 for name in stages}
    retries, before_loss, recovery_limit = [], None, None
    first_data, previous_ack, last_gate = None, None, -1
    guest_fin = peer_fin = guest_fin_ack = peer_fin_ack = False
    for index, row in enumerate(rows):
        if not row['outgoing']:
            if row['flags'] & 16:
                acknowledged = (row['ack'] - origin) & MASK
                require(acknowledged <= frontier + int(guest_fin), 'ACK owns only actually emitted bytes and FIN')
                require(acknowledged >= acked, 'nondecreasing observed cumulative acknowledgment')
                acked, window = acknowledged, row['window']
                previous_ack = row
                if index in positions:
                    last_gate += 1
                    require(last_gate == positions.index(index), 'causal four-gate ordering')
                    if last_gate == 1:
                        require(len(retries) == 2 and before_loss is not None and acked == before_loss,
                                'full prefix acknowledgment follows both actual RTO retransmissions')
                        flight = before_loss - MSS
                        recovery_limit = max(flight // 2, 2 * MSS)
                    elif last_gate in (2, 3):
                        require(acked == frontier, 'window gate acknowledges the full observed prefix')
            if row['data']:
                offset = (row['seq'] - reverse) & MASK
                require(offset + len(row['data']) <= 16 and
                        row['data'] == expected(lane, 1, offset, len(row['data'])), 'exact reverse application bytes')
                present[1][offset:offset + len(row['data'])] = b'\1' * len(row['data'])
            if row['flags'] & 1:
                require((row['seq'] - reverse) & MASK == 16 and all(present[1]), 'reverse FIN follows exact reply')
                peer_fin = True
            if row['flags'] & 16 and (row['ack'] - origin) & MASK == SIZE + 1:
                require(guest_fin, 'captured forward FIN precedes its final acknowledgment')
                guest_fin_ack = True
            continue
        if row['flags'] & 16:
            acknowledged = (row['ack'] - reverse) & MASK
            require(acknowledged <= sum(present[1]) + int(peer_fin), 'reverse ACK owns only captured reply and FIN')
            if acknowledged == 17:
                require(peer_fin, 'captured reverse FIN precedes its final acknowledgment')
                peer_fin_ack = True
        if row['data']:
            offset, length = (row['seq'] - origin) & MASK, len(row['data'])
            require(length <= MSS and offset + length <= SIZE and
                    row['data'] == expected(lane, 0, offset, length), 'exact forward application bytes and negotiated MSS')
            require(offset >= acked and offset + length <= acked + window, 'every emitted byte remains inside actual receive window')
            repeated = all(present[0][offset:offset + length])
            if not repeated:
                require(offset == frontier, 'new data extends a contiguous independently observed frontier')
            stage = stages[last_gate + 1]
            if repeated and stage == 'growth':
                require(offset == MSS and length == MSS, 'RTO retransmits exact oldest unacknowledged segment')
                if not retries:
                    before_loss = frontier
                retries.append(row)
            if before_loss is not None and last_gate == 0:
                require(offset + length <= before_loss, 'no new flight escapes while RTO recovery remains unacknowledged')
            present[0][offset:offset + length] = b'\1' * length
            frontier = max(frontier, offset + length)
            flight = frontier - acked
            maximum[stage] = max(maximum[stage], flight)
            if stage in limits:
                require(flight <= limits[stage], f'{stage} flight obeys independently derived congestion bound')
            elif stage == 'recovery':
                require(recovery_limit is not None and flight <= (14600 if native else recovery_limit),
                        'post-RTO recovery flight obeys independent congestion bound')
            elif stage == 'receiver':
                require(flight <= 1024, 'advertised small receive window bounds actual flight')
            if first_data is None:
                first_data = row
        if row['flags'] & 1:
            require((row['seq'] + len(row['data']) - origin) & MASK == SIZE and all(present[0]),
                    'forward FIN follows all exact captured data')
            guest_fin = True
    require(all(present[0]) and all(present[1]) and guest_fin_ack and peer_fin_ack,
            'both exact application streams and acknowledged FINs complete')
    require(maximum['opening'] >= 2920 and maximum['growth'] > maximum['opening'] and
            maximum['receiver'] == 1024, 'fixture exercises opening, advancing ACK growth and actual small window')
    require(maximum['recovery'] < maximum['growth'], 'actual loss recovery contracts measured flight')
    require(len(retries) == 2 and previous_ack is not None and first_data is not None,
            'both withheld-ACK retransmissions remain captured')
    rto1 = milliseconds(retries[0]) - milliseconds(gates[0][1])
    rto2 = milliseconds(retries[1]) - milliseconds(retries[0])
    require(rto2 > rto1 > 0, 'unchanged clocks show an increasing actual retransmission interval')
    observe_wait(first_data, gates[0][1], 100)
    observe_wait(gates[1][1], gates[2][1], 100)
    observe_wait(gates[2][1], gates[3][1], 350)
    return dict(passed=True, packets=len(rows), bytes=SIZE, reply_bytes=16, maximum_flight=maximum,
                initial_bound=limits['opening'], growth_bound=limits['growth'],
                recovery_bound=14600 if native else recovery_limit,
                original_retry_intervals_ms=[rto1, rto2],
                elapsed_deadline_acceptance_remains_in_existing_suites=True,
                timing_clock='independent monotonic receipts' if native else 'original PCAP',
                both_FINs_acknowledged=True)
