# SPDX-License-Identifier: GPL-3.0-or-later
"""Read original DAD captures and address inventories without the live peer's state."""
import hashlib
import ipaddress
import re
import struct

from ipv6_router_capture import checksum, qemu_records, require
from ipv6_dad_policy import retain_exhausted_prefix
from tcp_capture_clock import bind_native_clock, microseconds, raw_records


def inspect(path, lane, text, native=False, statistics=None, linux_vm=False, native_kernel_release=None):
    retain_routes = retain_exhausted_prefix(native_kernel_release) if native else False
    guest = bytes.fromhex(f'5254001234{16 + lane:02x}')
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    control = bytes([2, ord('I'), ord('P'), ord('6'), lane, 0])
    router = ipaddress.IPv6Address('fe80::42').packed
    all_nodes = ipaddress.IPv6Address('ff02::1').packed
    prefixes = {number: ipaddress.IPv6Address(f'2001:db8:{0x40 + lane:x}:{number:x}::').packed
                for number in range(1, 7)}
    plan = [(0, 0, 0)]
    for scenario in range(1, 7):
        if scenario in (4, 5):
            plan.append((6, scenario, 0))
        plan.append((1, scenario, 0))
        count = 4 if scenario in (2, 3) else 2 if scenario in (1, 6) else 1
        plan.extend((3 if scenario in (1, 6) and trial == 1 else 2, scenario, trial)
                    for trial in range(count))
        plan.append((4, scenario, 0))
        if scenario == 5:
            plan.append((5, 5, 0))
    plan.append((9, 0, 0))
    rows = list(raw_records(path) if native else qemu_records(path))
    require(len(rows) <= 2048, 'bounded complete DAD capture')
    requests, replies, observations = [], [], {}
    advertisements, probes, conflicts, neighbors, datagrams = [], {}, {}, [], []
    timed, prelude, mld, active, link = [], [], [], False, []
    for index, row in enumerate(rows):
        row['index'] = index
        frame = row['frame']
        if frame[12:14] == b'\x88\xc2':
            require(len(frame) == 60 and frame[14:19] == b'IP6D' + bytes([lane]),
                    'captured complete DAD control identity')
            phase = frame[19]
            if frame[6:12] == guest:
                require(frame[:6] == control and phase == len(requests) and phase < len(plan) and
                        tuple(frame[20:23]) == plan[phase] and
                        frame[23] == (int(retain_routes) if phase == 0 else 0),
                        'captured exact ordered DAD scenario plan')
                kind, scenario, trial = plan[phase]
                flags, preferred, valid = struct.unpack_from('!III', frame, 24)
                target, stamp = frame[36:52], int.from_bytes(frame[52:60], 'big')
                require(stamp > 0, 'actual guest monotonic observation in every DAD control')
                if kind in (2, 3):
                    expected = 0x140 if scenario == 4 else 0xc0 if scenario == 5 else 0x940
                    lifetimes = (0xffffffff, 0xffffffff) if scenario == 5 else (30, 60)
                    require(flags == expected and (preferred, valid) == lifetimes and
                            target[:8] == prefixes[scenario][:8],
                            'captured exact tentative flags and inherited configured lifetimes')
                    observations[scenario, trial] = dict(row=row, target=target, flags=flags,
                        preferred=preferred, valid=valid, guest_monotonic_ns=stamp)
                else:
                    require(frame[24:52] == bytes(28), 'no invented metadata in non-address DAD controls')
                requests.append(row)
                active = True
            else:
                require(frame[:12] == guest + control and phase == len(replies) and
                        frame[20:] == b'\x01' + bytes(39), 'captured exact ordered DAD acknowledgements')
                replies.append(row)
            timed.append(row)
            continue
        if not active:
            require(len(prelude) < 256, 'bounded original firmware prelude')
            prelude.append(hashlib.sha256(frame).hexdigest())
            continue
        require(len(frame) >= 62 and frame[12:14] == b'\x86\xdd' and frame[14] >> 4 == 6,
                'complete captured IPv6 DAD frame')
        length, protocol, hops = struct.unpack_from('!HBB', frame, 18)
        require(len(frame) == 54 + length, 'exact captured IPv6 DAD payload length')
        source, destination, body = frame[22:38], frame[38:54], frame[54:]
        outgoing = frame[6:12] == guest
        require(outgoing or frame[6:12] == peer, 'captured actual adapter MAC ownership')
        if protocol == 0:
            require((native or linux_vm) and outgoing and hops == 1 and len(body) >= 16 and
                    body[:2] == bytes([58, 0]) and body[8] in (131, 132, 143) and
                    not checksum(source + destination + struct.pack('!I3xB', len(body) - 8, 58) + body[8:]),
                    'complete captured native multicast report')
            mld.append(index)
            continue
        timed.append(row)
        require(protocol in (17, 58) and not checksum(source + destination +
                struct.pack('!I3xB', len(body), protocol) + body), 'captured complete DAD upper-layer checksum')
        if protocol == 17:
            require(len(body) == 24 and body[8:13] == b'DADC' + bytes([lane]) and
                    frame[:6] == (peer if outgoing else guest) and hops == 64 and body[6:8] != bytes(2),
                    'captured complete recovered unicast UDP destination, checksum and data')
            scenario = body[13]
            require(scenario in (1, 6) and body[14:] == bytes(scenario * 7 + at for at in range(6, 16)),
                    'captured exact recovered UDP payload')
            datagrams.append(dict(row=row, scenario=scenario, outgoing=outgoing,
                source=source, destination=destination, ports=struct.unpack_from('!HHH', body)))
            continue
        require(hops == 255 and body[1] == 0, 'captured exact neighbor discovery hops and code')
        if body[0] == 134:
            require(not outgoing and source == router and destination == all_nodes and
                    frame[:6] == b'\x33\x33\0\0\0\1' and len(body) == 64 and
                    body[4:16] == bytes([64, 0]) + bytes(10) and body[16:24] == b'\x01\x01' + peer and
                    body[56:] == struct.pack('!BBHI', 5, 1, 0, 1500), 'captured complete valid DAD advertisement')
            pio = body[24:56]
            scenario = int.from_bytes(pio[22:24], 'big')
            require(scenario in (1, 2, 3, 4, 6) and pio == struct.pack('!BBBBIII16s', 3, 4, 64,
                    0x40 if scenario == 2 else 0xc0, 60, 30, 0, prefixes[scenario]),
                    'captured exact independent autonomous and on-link PIO flags')
            advertisements.append((scenario, row))
            continue
        require(body[0] in (135, 136) and len(body) == 32,
                'captured complete expected solicitation or advertisement')
        target = body[8:24]
        if body[0] == 135:
            require(outgoing and not any(body[4:8]) and
                    destination == b'\xff\x02' + bytes(9) + b'\x01\xff' + target[-3:] and
                    frame[:6] == b'\x33\x33\xff' + target[-3:], 'captured exact solicited-node destinations')
            if source == bytes(16):
                require(body[24:26] == b'\x0e\x01', 'captured complete enhanced DAD nonce')
                if ipaddress.IPv6Address(target).is_link_local:
                    link.append((target, row))
                else:
                    probes.setdefault(target, []).append(row)
            else:
                require(body[24:] == b'\x01\x01' + guest, 'captured actual neighbor-query source MAC')
                neighbors.append(dict(outgoing=True, row=row, target=target, source=source, destination=destination))
        else:
            require(not outgoing and body[24:] == b'\x02\x01' + peer, 'captured actual conflict source MAC')
            if int.from_bytes(body[4:8], 'big') == 0x20000000:
                require(source == router and destination == all_nodes and frame[:6] == b'\x33\x33\0\0\0\1' and
                        target not in conflicts, 'one complete valid conflict per selected candidate')
                conflicts[target] = row
            else:
                require(int.from_bytes(body[4:8], 'big') == 0x60000000 and source == target and
                        frame[:6] == guest, 'captured solicited recovered-neighbor answer')
                neighbors.append(dict(outgoing=False, row=row, target=target, source=source, destination=destination))
    clock = bind_native_clock(path, timed, statistics) if native else None
    stamp = microseconds
    require(len(requests) == len(replies) == 31 and len(observations) == 14 and len(link) == 2,
            'complete independent DAD controls, observations and initial link-local probe')
    require(all(a['index'] < b['index'] and (position == 30 or b['index'] < requests[position + 1]['index'])
                for position, (a, b) in enumerate(zip(requests, replies))), 'complete causal DAD barrier ordering')
    require([scenario for scenario, _ in advertisements] == [1, 2, 3, 4, 6], 'all five exact original advertisements')
    identifier = bytes([guest[0] ^ 2]) + guest[1:3] + b'\xff\xfe' + guest[3:]
    eui = ipaddress.IPv6Address('fe80::').packed[:8] + identifier
    mode_change = next(row for row in requests if row['frame'][20:23] == bytes([6, 4, 0]))
    plain_start = next(row for row in requests if row['frame'][20:23] == bytes([1, 4, 0]))
    require(link[0][0] != eui and link[1][0] == eui and
            requests[0]['index'] < link[0][1]['index'] < requests[1]['index'] and
            mode_change['index'] < link[1][1]['index'] < plain_start['index'],
            'actual stable and EUI-64 link-local generation follows explicit mode controls')
    require(len(probes) == 14 and sum(map(len, probes.values())) == 18 and len(conflicts) == 12,
            'complete actual distinct DAD attempts, retransmissions and conflicts')
    require(len({value['target'] for value in observations.values()}) == 14 and
            set(probes) == {value['target'] for value in observations.values()},
            'every distinct actual DAD candidate has exactly one queried observation')
    inherited, retry_gaps = [], []
    for (scenario, trial), observed in observations.items():
        target, metadata = observed['target'], observed['row']
        packets = probes.get(target, [])
        require(len(packets) == (3 if scenario == 6 else 1), 'configured complete DAD probe count')
        generated = prefixes[scenario][:8] + identifier
        require(target == generated if scenario == 4 else
                target == prefixes[5][:-2] + b'\xab\xcd' if scenario == 5 else target != generated,
                'actual configured target or selected address generation algorithm')
        if scenario == 6:
            require(all(900000 <= stamp(b) - stamp(a) <= 1100000 for a, b in zip(packets, packets[1:])),
                    'original one-second DAD retransmission interval')
            require(all(packet['frame'][78:86] == packets[0]['frame'][78:86] for packet in packets),
                    'one complete unchanged enhanced nonce throughout each DAD cycle')
        conflict = conflicts.get(target)
        if scenario in (1, 6) and trial == 1:
            require(conflict is None, 'recovery candidate receives no synthesized conflict')
        else:
            require(conflict is not None and conflict['index'] > max(metadata['index'], packets[-1]['index']),
                    'actual conflict follows both tentative metadata and every required DAD probe')
        if trial:
            previous = observations[scenario, trial - 1]['target']
            require(target != previous and previous in conflicts, 'stable candidate counter advances after conflict')
            gap = stamp(packets[0]) - stamp(conflicts[previous])
            require(1000000 <= gap <= 2100000, 'full real stable retry delay and bounded start jitter')
            retry_gaps.append(dict(scenario=scenario, trial=trial, microseconds=gap))
            inherited.append(dict(scenario=scenario, trial=trial, preferred=observed['preferred'], valid=observed['valid']))
        if scenario in (2, 3, 4, 5) and trial == (3 if scenario in (2, 3) else 0):
            finish = next(row for row in requests if row['frame'][20:23] == bytes([4, scenario, 0]))
            require(stamp(finish) - stamp(conflict) >= 3000000,
                    'full independent three-second final exhausted or permanent observation')
    address_rows = re.findall(r'^IPV6_DAD_ADDRESS lane=' + str(lane) +
        r' scenario=(\d+) trial=(\d+) address=(\S+) flags=([0-9a-f]+) preferred=(\d+) valid=(\d+)\r?$', text, re.M)
    require(len(address_rows) == 14, 'complete original queried tentative address inventory')
    for scenario, trial, address, flags, preferred, valid in address_rows:
        value = observations[int(scenario), int(trial)]
        require((ipaddress.IPv6Address(address).packed, int(flags, 16), int(preferred), int(valid)) ==
                (value['target'], value['flags'], value['preferred'], value['valid']),
                'queried address inventory equals the actual wire observation')
    control_rows = re.findall(r'^IPV6_DAD_CONTROL lane=' + str(lane) +
        r' phase=(\d+) kind=(\d+) scenario=(\d+) trial=(\d+) observed_ns=(\d+)\r?$', text, re.M)
    require(len(control_rows) == 31, 'all actual client monotonic controls are retained')
    for expected, row in enumerate(control_rows):
        frame = requests[expected]['frame']
        require(tuple(map(int, row)) == (expected, *plan[expected], int.from_bytes(frame[52:60], 'big')),
                'every original client control agrees with its exact wire fields and monotonic observation')
    link_rows = re.findall(r'^IPV6_DAD_LINK lane=' + str(lane) +
        r' stage=(\d+) address=(\S+) flags=([0-9a-f]+) preferred=(\d+) valid=(\d+)\r?$', text, re.M)
    require(len(link_rows) == 5, 'actual link-local inventories before and after both generation mode changes')
    for stage in (0, 4, 5):
        found = [row for row in link_rows if int(row[0]) == stage]
        expected = {link[0][0]} if stage == 0 else {link[0][0], eui}
        require({ipaddress.IPv6Address(row[1]).packed for row in found} == expected and
                all(int(row[2], 16) == (0x80 if ipaddress.IPv6Address(row[1]).packed == eui else 0x880) and
                    int(row[3]) == int(row[4]) == 0xffffffff for row in found),
                'generation modes preserve both actual permanent link-local owners and lifetimes')
    final_rows = re.findall(r'^IPV6_DAD_FINISH lane=' + str(lane) +
        r' scenario=(\d+) count=(\d+) flags=([0-9a-f]+) preferred=(\d+) valid=(\d+) prefix_routes=(\d+) expires=(-?\d+) observed_ns=(\d+)\r?$', text, re.M)
    require([int(row[0]) for row in final_rows] == list(range(1, 7)), 'six complete final address inventories')
    route_rows = re.findall(r'^IPV6_DAD_ROUTE lane=' + str(lane) +
        r' scenario=(\d+) destination=(\S+)/64 gateway=(\S+) metric=(\d+) protocol=(\d+) expires=(-?\d+)\r?$', text, re.M)
    require(len(route_rows) == (5 if retain_routes else 3), 'complete actual surviving prefix route inventory')
    for scenario, count, flags, preferred, valid, routes, expires, final_stamp in final_rows:
        scenario, count, flags = int(scenario), int(count), int(flags, 16)
        require(count == (1 if scenario in (1, 5, 6) else 0) and
                flags == (0x900 if scenario in (1, 6) else 0xc8 if scenario == 5 else 0),
                'native-compatible final usable, failed permanent or removed automatic address')
        require(count or (int(preferred), int(valid)) == (0, 0),
                'removed address inventory has no fabricated cache lifetimes')
        expected_routes = 0 if scenario == 2 else int(retain_routes) if scenario in (3, 4) else 1
        require(int(routes) == expected_routes,
                'source-pinned exhausted prefix cleanup and independent surviving on-link ownership')
        require(expected_routes or int(expires) == 0, 'removed prefix has no fabricated route lifetime')
        matching = [row for row in route_rows if int(row[0]) == scenario]
        require(len(matching) == expected_routes and all(
            ipaddress.IPv6Address(row[1]).packed == prefixes[scenario] and
            ipaddress.IPv6Address(row[2]).packed == bytes(16) and
            (int(row[3]), int(row[4]), int(row[5])) == (256, 2, int(expires)) for row in matching),
            'exact original connected prefix, gateway, metric, protocol and expiry')
        if scenario == 5:
            require(int(preferred) == int(valid) == 0xffffffff and int(expires) == 0,
                    'failed configured permanent address and connected route remain infinite')
        elif count:
            trial = 1
            first = observations[scenario, trial]
            elapsed = int(final_stamp) - first['guest_monotonic_ns']
            require(elapsed >= 0 and 0 < int(preferred) <= 30 and int(valid) == int(preferred) + 30 and
                    max(0, 30 - (elapsed + 999999999) // 1000000000 - 1) <= int(preferred) <=
                    min(30, 30 - elapsed // 1000000000 + 1),
                    'finite regenerated cache lifetimes naturally age after the exact first observation')
        if scenario == 6:
            require(0 < int(expires) < 5800, 'original on-link route deadline does not restart with address regeneration')
    require(len(datagrams) == len(neighbors) == 4, 'two complete actual recovered UDP and neighbor exchanges')
    for scenario in (1, 6):
        target = observations[scenario, 1]['target']
        remote = prefixes[scenario][:-1] + b'\x42'
        sent = [row for row in datagrams if row['scenario'] == scenario and row['outgoing']]
        received = [row for row in datagrams if row['scenario'] == scenario and not row['outgoing']]
        require(len(sent) == len(received) == 1 and sent[0]['source'] == received[0]['destination'] == target and
                sent[0]['destination'] == received[0]['source'] == remote and
                sent[0]['ports'] == (48000 + lane, 48010 + scenario, 24) and
                received[0]['ports'] == (48010 + scenario, 48000 + lane, 24) and
                sent[0]['row']['index'] < received[0]['row']['index'], 'exact recovered-source UDP request and reply')
        queries = [row for row in neighbors if row['outgoing'] and row['target'] == remote]
        answers = [row for row in neighbors if not row['outgoing'] and row['target'] == remote]
        require(len(queries) == len(answers) == 1 and queries[0]['source'] in (target, link[0][0], eui) and
                answers[0]['destination'] == queries[0]['source'] and
                queries[0]['row']['index'] < answers[0]['row']['index'] < sent[0]['row']['index'],
                'complete causal neighbor resolution on the recovered actual adapter')
    return dict(passed=True, lane=lane, actual_frames=len(rows), DAD_probes=20, conflicts=12,
        tentative_inventories=14, scenarios=6, retry_gaps=retry_gaps, inherited_lifetimes=inherited,
        recovered_UDP=2, final_inventory=final_rows, original_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        native_clock=clock, original_packet_times_not_rescaled=True, firmware_sha256=prelude,
        retained_exhausted_prefix_policy=retain_routes, native_kernel_release=native_kernel_release,
        native_multicast_reports=len(mld), full_F12_complete=False)
