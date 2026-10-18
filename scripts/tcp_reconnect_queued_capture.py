# SPDX-License-Identifier: GPL-3.0-or-later
"""Check original queued-copy, successor and companion evidence independently."""
import hashlib
import json
from pathlib import Path
import re
from tcp_capture_clock import microseconds
from tcp_fault_capture import decode as decode_frame
from tcp_icmp_capture import require

MASK = 0xffffffff


def expected(lane, phase, direction, size):
    return bytes(((offset * 29) ^ (offset // 128) ^ (lane * 53) ^ (4 * 97) ^
                  (phase * 71) ^ (direction * 41)) & 255 for offset in range(size))


def stream(values, lane, native):
    rows = [item for item in values if item['role'] == 4]
    starts = []
    for index, item in enumerate(rows):
        if item['outgoing'] and item['flags'] & 2:
            if not starts or item['sequence'] != rows[starts[-1]]['sequence']:
                starts.append(index)
    require(len(starts) == 2 and starts[0] == 0, 'two owned queued-copy opens on the exact original tuple')
    initials = [rows[index]['sequence'] for index in starts]
    origins = [[(initial + 1) & MASK, (0xfffffff1 + phase * 0x100000) & MASK]
               for phase, initial in enumerate(initials)]
    old_prefix, total = (16 if lane == 0 else 64), (576 if lane == 0 else 528)
    old_end = (origins[0][0] + old_prefix + 512) & MASK
    delta = (initials[1] - old_end) & MASK
    require(65537 <= delta < 0x80000000,
            'queued successor excludes every old pending byte and advertised window')
    wanted = [[expected(lane, 0, 0, old_prefix + (512 if native else 0)),
               expected(lane, 0, 1, old_prefix) + b'Q'],
              [expected(lane, 1, direction, total) for direction in range(2)]]
    covered = [[bytearray(len(body)) for body in phase] for phase in wanted]
    present = [[set(), set()] for _ in range(2)]
    prefix, acked, finishes = [[0, 0], [0, 0]], [[0, 0], [0, 0]], [[False, False], [False, False]]
    times = [[{}, {}], [{}, {}]]
    stamps = [[{}, {}], [{}, {}]]
    syns, answers, resets, late = [set(), set()], [set(), set()], 0, []
    for index, item in enumerate(rows):
        direction = 0 if item['outgoing'] else 1
        opposite = 1 - direction
        flags, data = item['flags'], item['data']
        if flags & 2:
            if direction == 0:
                require(item['sequence'] in initials and not flags & 16 and not data,
                        'stable actual queued-copy client SYN')
                phase = initials.index(item['sequence'])
                syns[phase].add(item['sequence'])
            else:
                matches = [phase for phase in range(2) if item['acknowledgment'] == origins[phase][0]]
                require(len(matches) == 1, 'queued SYN-ACK owns its actual emitted SYN')
                phase = matches[0]
                require(flags & 16 and item['sequence'] == (origins[phase][1] - 1) & MASK and
                        item['window'] == 65535 and not data, 'queued-copy peer advertises the complete unscaled window')
                answers[phase].add(item['sequence'])
            continue
        old_position = (item['sequence'] - origins[0][direction]) & MASK
        old_limit = old_prefix + (512 if direction == 0 else 1)
        phase = 0 if old_position <= old_limit else 1
        position = (item['sequence'] - origins[phase][direction]) & MASK
        require(position <= (old_prefix + 512 if phase == direction == 0 else
                             len(wanted[phase][direction]) + int(finishes[phase][direction])),
                'queued packet owns only its old or successor sequence interval')
        if data:
            require(position + len(data) <= len(wanted[phase][direction]) and
                    data == wanted[phase][direction][position:position + len(data)],
                    'exact independent queued old, successor and companion bytes')
            covered[phase][direction][position:position + len(data)] = data
            present[phase][direction].update(range(position, position + len(data)))
            for at in range(position, position + len(data)):
                times[phase][direction].setdefault(at, microseconds(item))
                stamps[phase][direction].setdefault(at, item['stamp'])
            while prefix[phase][direction] in present[phase][direction]:
                prefix[phase][direction] += 1
            if phase == direction == 0 and position >= old_prefix:
                require(native and index > starts[1], 'old native copy reaches the wire only after the successor opens')
                late.append(item)
        if flags & 1:
            require(phase == 1 and position + len(data) == total and prefix[phase][direction] == total,
                    'queued successor FIN follows every exact byte')
            finishes[phase][direction] = True
        if flags & 16:
            value = (item['acknowledgment'] - origins[phase][opposite]) & MASK
            require(value <= prefix[phase][opposite] + int(finishes[phase][opposite]),
                    'queued ACK owns only actual captured bytes and FIN')
            acked[phase][opposite] = max(acked[phase][opposite], value)
        if flags & 4:
            require(phase == direction == 0 and not data and not flags & 1 and position == old_prefix + 512,
                    'queued disconnect reset owns only the abandoned old sequence')
            resets += 1
    require(all(len(value) == 1 for value in syns + answers), 'both complete independently observed queued handshakes')
    require(prefix == [[len(body) for body in phase] for phase in wanted] and
            covered == [[bytearray(body) for body in phase] for phase in wanted],
            'all exact queued old, successor and companion streams are captured')
    require(resets > 0 and not any(finishes[0]) and acked[0][0] >= old_prefix and acked[0][1] >= old_prefix and
            all(finishes[1]) and acked[1] == [total + 1, total + 1],
            'old abort and both fully acknowledged successor FINs complete')
    if native:
        require(late and min(microseconds(item) for item in late) > max(times[1][0][at] for at in range(512)),
                'the successor transfers real bytes before every old native copy arrives')
    return dict(lane=lane, old_prefix=old_prefix, total=total, origins=origins,
                initials=initials, delta=delta, times=times, stamps=stamps, late=late, opening=rows[starts[1]])


def named(root, name):
    require(isinstance(name, str) and name and Path(name).name == name and '/' not in name and '\\' not in name,
            'bounded actual queued-copy evidence filename')
    path = root / name
    require(path.is_file() and not path.is_symlink(), 'original actual queued-copy evidence file')
    return path


def physical(root, row, native, streams):
    claims = [peer['queued_copy'] for peer in row['peers']]
    require(claims[0] == claims[1] and claims[0]['native'] is native and claims[0]['complete'] is True and
            type(claims[0]['queued_each']) is int and claims[0]['queued_each'] == 512 and
            claims[0]['debugger_timing_excluded'] is (not native),
            'one shared actual queued-copy controller owns both NICs')
    claim = claims[0]
    encoded = named(root, claim['metadata']).read_bytes()
    require(hashlib.sha256(encoded).hexdigest() == claim['sha256'], 'exact physical queued-copy metadata fingerprint')
    value = json.loads(encoded)
    require(value['native'] is native and value['stages'] == ['completed', 'completed'] and
            len(value['holds']) == len(value['successors']) == 2, 'both physical queued-copy observations complete')
    events = value['events']
    require(len(events) == 8 and [(event['stage'], event['lane']) for event in events] ==
            [(stage, lane) for lane in range(2) for stage in ('ARM', 'HELD', 'UNSPEC', 'DONE')],
            'ordered actual queued-copy cancellation and successor observations')
    previous = 0
    for event in events:
        require(type(event['lane']) is int and type(event['monotonic_ns']) is int and
                previous <= event['monotonic_ns'], 'actual queued-copy observation clocks are ordered')
        previous = event['monotonic_ns']
    require((type(value['native_pid']) is int and value['native_pid'] > 0) if native else value['native_pid'] is None,
            'actual isolated native owner or guest observer identity')
    traces = claim['traces']
    require(traces == [] if native else len(traces) == 2 and {trace['lane'] for trace in traces} == {0, 1},
            'complete guest queued-copy observer traces')
    for lane, observed in enumerate(streams):
        arm, held, cancelled, done = [event['monotonic_ns'] for event in events[lane * 4:lane * 4 + 4]]
        successor = value['successors'][lane]
        require(type(successor['monotonic_ns']) is int and cancelled <= successor['monotonic_ns'] <= done and
                successor['syn_sha256'] == hashlib.sha256(observed['opening']['frame']).hexdigest(),
                'actual successor overlaps the old-copy lifetime on its original captured SYN')
        holds = value['holds'][lane]
        markers = [entry for entry in holds if 'stage' in entry]
        expected_stages = ['held_before_cancel', 'cancelled_with_old_copy_pending', 'completed']
        if not native:
            expected_stages.insert(0, 'armed')
        require([entry['stage'] for entry in markers] == expected_stages,
                'actual queued-copy hold remains confirmed through cancellation')
        timed = markers if native else markers[1:]
        require(all(type(entry['monotonic_ns']) is int for entry in timed) and
                arm <= timed[0]['monotonic_ns'] <= held <= timed[1]['monotonic_ns'] <= cancelled and
                timed[1]['monotonic_ns'] <= timed[2]['monotonic_ns'] <= done,
                'physical hold and cancellation agree with actual controller clocks')
        if native:
            pid = value['native_pid']
            prefix = ['nsenter', '-t', str(pid), '-n', 'tc']
            commands = [entry for entry in holds if 'command' in entry]
            expected_commands = [
                ['qdisc', 'add', 'dev', f'eth{lane}', 'root', 'handle', '1:', 'prio', 'bands', '3',
                 'priomap', *(['0'] * 16)],
                ['qdisc', 'add', 'dev', f'eth{lane}', 'parent', '1:3', 'handle', '30:', 'netem', 'delay', '10000ms'],
                ['filter', 'add', 'dev', f'eth{lane}', 'protocol', 'ip', 'parent', '1:', 'pref', '10', 'u32',
                 'match', 'ip', 'protocol', '6', '0xff', 'match', 'ip', 'dport', str(49080 + lane),
                 '0xffff', 'flowid', '1:3'],
                ['-j', '-s', 'qdisc', 'show', 'dev', f'eth{lane}'],
                ['-j', '-s', 'qdisc', 'show', 'dev', f'eth{lane}'],
                ['filter', 'del', 'dev', f'eth{lane}', 'parent', '1:', 'protocol', 'ip', 'pref', '10'],
                ['-j', '-s', 'qdisc', 'show', 'dev', f'eth{lane}'],
                ['qdisc', 'del', 'dev', f'eth{lane}', 'root']]
            require(len(commands) == len(expected_commands) and all(
                entry['command'] == prefix + arguments and entry['returncode'] == 0 and not entry['stderr']
                for entry, arguments in zip(commands, expected_commands)),
                'exact successful native old-copy queue and future-packet classifier operations')
            for ordinal, index in enumerate((3, 4, 6)):
                rows = json.loads(commands[index]['stdout'])
                queues = [item for item in rows if item.get('kind') == 'netem' and item.get('handle') == '30:']
                require(len(queues) == 1 and queues[0].get('parent') == '1:3' and queues[0].get('drops') == 0 and
                        type(queues[0].get('backlog')) is int and type(queues[0].get('qlen')) is int and
                        ((queues[0]['backlog'] >= 512 and queues[0]['qlen'] >= 1) if ordinal < 2 else
                         (queues[0]['backlog'] == queues[0]['qlen'] == 0)),
                        'actual old native payload remains queued through cancellation and drains without drops')
            require(abs(microseconds(observed['opening']) * 1000 - successor['monotonic_ns']) <= 1000000000 and
                    min(microseconds(item) for item in observed['late']) * 1000 >= arm + 10000000000 and
                    min(observed['times'][1][0][at] for at in range(512, 528)) * 1000 >= arm + 11000000000,
                    'independent native packets observe the full real old-copy delay and successor recovery')
        else:
            trace = next(trace for trace in traces if trace['lane'] == lane)
            text = {}
            for kind in ('script', 'log'):
                data = named(root, trace[kind]).read_bytes()
                require(hashlib.sha256(data).hexdigest() == trace[kind + '_sha256'],
                        'exact original queued-copy observer script and trace fingerprint')
                text[kind] = data.decode()
            require(text['script'].count('return (int)-11') == 1 and
                    f'break *ax::net_send if $rdi == {lane + 1} && $rdx == 566' in text['script'] and
                    '$seq == $old_seq' in text['script'] and
                    f'item.index == {lane + 1} && item.length == 566' in text['script'] and
                    'break kernel/net/ipv4/core.cpp:' in text['script'],
                    'observer holds only the selected old physical copy until its actual expiry')
            captures = [re.findall(rf'^TCP_RECONNECT_QUEUED_{stage}_FRAME ([0-9a-f]+)\r?$', text['log'], re.M)
                        for stage in ('HELD', 'EXPIRED')]
            require(all(len(values) == 1 for values in captures) and captures[0] == captures[1],
                    'the exact held guest copy is independently observed at expiry')
            frame = bytes.fromhex(captures[0][0])
            decoded = decode_frame(frame, lane, (49080 + lane,))
            require(decoded is not None and decoded['outgoing'] and len(frame) == 566 and
                    frame[:12] == bytes([2, 0x41, 0x58, 0x54, 0x43, lane,
                                         0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane]) and
                    int.from_bytes(frame[34:36], 'big') == 48080 + lane and
                    decoded['seq'] == (observed['origins'][0][0] + observed['old_prefix']) & MASK and
                    decoded['data'] == expected(lane, 0, 0, observed['old_prefix'] + 512)[observed['old_prefix']:],
                    'actual held and expired copy owns the exact abandoned tuple, sequence and bytes')
            held_frames = re.findall(rf'^TCP_RECONNECT_QUEUED_PHYSICAL_HELD index={lane + 1} sequence=(\d+) length=566\r?$',
                                     text['log'], re.M)
            require(len(held_frames) == 1 and int(held_frames[0]) == decoded['seq'],
                    'actual physical hold identifies its exact old packet')
            expired = re.findall(rf'^TCP_RECONNECT_QUEUED_OLD_COPY_EXPIRED index={lane + 1} owner=([0-9a-fx]+) held=(\d+) length=566\r?$',
                                 text['log'], re.M)
            require(len(expired) == 1 and int(expired[0][0], 0) == 0 and int(expired[0][1]) > 0,
                    'expired old copy has no callback owner that can reach its successor')
            clocks = [re.findall(rf'^TCP_RECONNECT_QUEUED_{stage}_MONOTONIC_NS (\d+)\r?$', text['log'], re.M)
                      for stage in ('HELD', 'EXPIRED')]
            require(all(len(values) == 1 for values in clocks) and
                    arm <= int(clocks[0][0]) <= held and
                    successor['monotonic_ns'] < int(clocks[1][0]) <= timed[2]['monotonic_ns'],
                    'actual guest successor is alive while its ownerless old copy expires')
    return events


def audit_queued(root, row, values, text):
    native = 'client_namespace' in row
    calls = re.findall(r'^TCP_RECONNECT_QUEUED_(ARM|HELD|UNSPEC|DONE) lane=([01])(?: ([^\r\n]+))?\r?$', text, re.M)
    require([(stage, int(lane)) for stage, lane, _ in calls] ==
            [(stage, lane) for lane in range(2) for stage in ('ARM', 'HELD', 'UNSPEC', 'DONE')],
            'every actual queued-copy application barrier completes in order')
    for stage, lane, arguments in calls:
        if stage == 'ARM':
            require(arguments == f'old_prefix={16 if lane == "0" else 64}', 'actual exact old queued prefix')
        elif stage == 'HELD':
            require(arguments == 'queued=512', 'actual full old queued write')
        elif stage == 'UNSPEC':
            require(not arguments, 'actual exact description cancellation')
        else:
            observed = re.fullmatch(r'elapsed_ms=(\d+) successor=528', arguments)
            require(observed and int(observed[1]) >= 11000, 'actual full queued-copy lifetime and successor wait')
    streams = [stream(values[lane], lane, native) for lane in range(2)]
    physical(root, row, native, streams)
    for lane, observed in enumerate(streams):
        companion = streams[1 - lane]
        phase, base = (0, 16) if lane == 0 else (1, 528)
        # Separate native readers can receive causally ordered packets in the
        # opposite order. Original kernel packet stamps establish cross-NIC
        # packet order; the independent monotonic receipts still govern every
        # elapsed-time check above. Neither clock is changed or rescaled.
        healthy = companion['stamps'][phase][1]
        require(max(healthy[at] for at in range(base + 16, base + 32)) <= observed['opening']['stamp'] and
                max(healthy[at] for at in range(base + 32, base + 48)) <=
                min(observed['stamps'][1][0][at] for at in range(512, 528)),
                'independent healthy companion replies precede successor open and final recovery')
        reported = next(peer for peer in row['peers'] if peer['lane'] == lane)['flows'][-1]
        require(reported['role'] == 4 and reported['done'] is True and reported['old_reset'] is True and
                reported['old_prefix'] == observed['old_prefix'] and reported['successor_delta'] == observed['delta'] and
                reported['late_old_bytes'] == (512 if native else 0) and len(reported['phases']) == 2 and
                all(given['initial'] == initial for given, initial in zip(reported['phases'], observed['initials'])) and
                reported['phases'][0]['received'] == observed['old_prefix'] and
                reported['phases'][0]['sent'] == observed['old_prefix'] + 1 and
                observed['old_prefix'] <= reported['phases'][0]['acknowledged'] <= observed['old_prefix'] + 1 and
                reported['phases'][0]['closed'] is True and
                reported['phases'][1]['received'] == reported['phases'][1]['sent'] == observed['total'] and
                reported['phases'][1]['acknowledged'] == observed['total'] + 1 and
                reported['phases'][1]['closed'] is True,
                'queued peer results agree with independently captured ownership and exact streams')
    return [dict(lane=value['lane'], role=4, same_tuple=True, queued=512,
                 old_prefix=value['old_prefix'], successor_bytes_each=value['total'],
                 reuse_delta=value['delta'], late_old_bytes=512 if native else 0)
            for value in streams]
