# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen route and address transitions for held IPv4 output selections."""
import struct

from ipv4_receive_wire_records import inventory, require


def prefix(lane):
    return 0xc6120102 + lane * 256


def mode(case):
    return divmod(case - 50, 3)


def retired(case):
    selected, mutation = mode(case)
    return selected < 4 and mutation != 0


def address(lane, case):
    return (prefix(lane) & ~255) + case + 1


def read_inventory(rows, at, lane, case, indices):
    selected, mutation = mode(case)
    primary = lambda number: 0x0a4d0102 + number * 256
    for phase in (0, 2) if mutation == 0 else (0, 1, 2):
        for routes in (1, 0):
            messages = []
            while at < len(rows) and rows[at].get('kind') == 'inventory':
                messages.append(rows[at])
                at += 1
            require(messages and at < len(rows), 'complete lifetime inventory and observed state')
            state = rows[at]
            at += 1
            require(all(row.keys() == {'kind', 'lane', 'case', 'phase', 'routes', 'hex'} and
                    (row['lane'], row['case'], row['phase'], row['routes']) == (lane, case, phase, routes)
                    for row in messages), 'lifetime dump belongs to this actual transition')
            decoded = inventory(messages, bool(routes))
            if routes:
                wanted = {(indices[n], value & ~255, 24, 2, 253, 0, value)
                          for n in range(2) for value in (primary(n), prefix(n))}
                if selected >= 4 or (phase == 1 and mutation == 1 and selected >= 2):
                    wanted.discard((indices[lane], prefix(lane) & ~255, 24, 2, 253, 0, prefix(lane)))
                if selected < 2 and not (phase == 1 or (phase == 2 and mutation == 2)):
                    wanted.add((indices[lane], address(lane, case), 32, 4, 253, 10, 0))
                if phase == 1 and mutation == 2:
                    wanted = {value for value in wanted if value[0] != indices[lane]}
                if phase == 2 and mutation in (1, 2) and selected >= 4:
                    wanted.add((indices[lane], prefix(lane) & ~255, 24, 2, 253, 0, prefix(lane)))
                if phase == 2 and mutation == 0:
                    wanted.add((indices[lane ^ 1], address(lane, case), 32, 4, 253, 1, 0))
                physical = [row for row in decoded if row['table'] == 254 and row['index'] in indices]
                require(all(row['type'] == 1 and row['scope'] == 253 and 5 not in row['attrs'] and
                            len(row['attrs'].get(6, bytes(4))) == 4 for row in physical),
                        'actual direct main-table lifetime route grammar')
                observed = [(row['index'], row['destination'], row['prefix'], row['protocol'], row['scope'],
                             int.from_bytes(row['attrs'].get(6, bytes(4)), 'little'),
                             int.from_bytes(row['attrs'].get(7, bytes(4)), 'big')) for row in physical]
                require(len(observed) == len(set(observed)) and set(observed) == wanted,
                        'independent complete lifetime route presence and preferred-source metadata')
                target, length = (address(lane, case), 32) if selected < 2 else (prefix(lane) & ~255, 24)
                matching = [value for value in wanted if value[1:3] == (target, length)]
                chosen = min(matching, key=lambda value: value[5])[0] if matching else 0
                found = len(matching)
            else:
                wanted = {(indices[n], value, 24) for n in range(2)
                          for value in (primary(n), primary(n) + 40, prefix(n))}
                if phase == 1 and mutation == 1 and selected >= 4:
                    wanted.remove((indices[lane], prefix(lane), 24))
                observed = [(row['index'], row['address'], row['prefix']) for row in decoded if row['index'] in indices]
                require(len(observed) == len(set(observed)) and set(observed) == wanted,
                        'independent complete lifetime source-address withdrawal and restoration')
                target = prefix(lane)
                found = int((indices[lane], target, 24) in wanted)
                chosen = indices[lane] if found else 0
            require(state == dict(kind='state', lane=lane, case=case, phase=phase, routes=routes,
                                  target=f'{target:08x}', found=found, index=chosen),
                    'actual lifetime state agrees with independently decoded complete dump')
    return at


def controls(lane, selected, indices):
    result = bytearray()
    for option, data in ((2, struct.pack('<i', 37)), (1, struct.pack('<i', 184)),
                         (8, struct.pack('<I', indices[lane] if selected == 4 else 0) +
                          struct.pack('!II', 0, 0xdeadbeef))):
        length = 16 + len(data)
        result.extend(struct.pack('<Qii', length, 0, option) + data + bytes(-length % 8))
    return result


def validate(named, lane, case, indices, fills):
    selected, mutation = mode(case)
    row = named['LIFETIME_INPUT', lane, case]
    require(set(row) == {'lane', 'case', 'mode', 'mutation', 'connected', 'bound', 'fill_index', 'length', 'control'} and
            all(int(row[name]) == value for name, value in dict(mode=selected, mutation=mutation,
                connected=selected & 1, bound=int(selected == 5), fill_index=indices[lane ^ 1], length=1100).items()) and
            bytes.fromhex(row['control']) == controls(lane, selected, indices),
            'actual connected/named/FIB/fallback controls and independent fill adapter')
    row = named['SLEEP', lane, case]
    tid = int(row['tid'])
    status = bytes.fromhex(row['status']).decode()
    require(set(row) == {'lane', 'case', 'tid', 'monotonic_ns', 'status'} and tid > 0 and
            '\nState:\tS (sleeping)\n' in '\n' + status and f'\nPid:\t{tid}\n' in '\n' + status,
            'actual lifetime worker sleeping inside sendmsg')
    sleeping = int(row['monotonic_ns'])
    row = named['LIFETIME', lane, case]
    require(set(row) == {'lane', 'case', 'mode', 'mutation', 'fills', 'result', 'error', 'socket_error', 'began_ns', 'finished_ns'} and
            all(int(row[name]) == value for name, value in dict(mode=selected, mutation=mutation,
                fills=fills, result=1100, error=0, socket_error=0).items()) and
            0 <= int(row['began_ns']) <= sleeping <= int(row['finished_ns']) and
            int(row['finished_ns']) - int(row['began_ns']) <= 6000000000,
            'actual retained lifetime syscall and zero post-transition socket error')
    if retired(case):
        window = named['LIFETIME_WINDOW', lane, case]
        require(set(window) == {'lane', 'case', 'began_ns', 'finished_ns'} and
                int(window['began_ns']) >= int(row['finished_ns']) and
                int(window['finished_ns']) - int(window['began_ns']) >= 3000000000,
                'original full three-second lifetime retirement observation')
    if mutation == 2:
        link = named['LIFETIME_LINK', lane, case]
        require(set(link) == {'lane', 'case', 'before', 'down', 'up'} and
                int(link['before'], 16) & 1 and not int(link['down'], 16) & 1 and int(link['up'], 16) & 1,
                'actual interface administration is withdrawn then restored')
