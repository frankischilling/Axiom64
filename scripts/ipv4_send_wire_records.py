# SPDX-License-Identifier: GPL-3.0-or-later
"""Decode complete syscall, sleeping-task and actual route/address observations."""
import json
import struct
from ipv4_receive_wire_records import inventory, require, unique
from ipv4_send_wire_lifetime import read_inventory, validate as lifetime, retired as lifetime_retired

WAITING = (*range(36,42), *range(44,50))


def waiting_scenario(case):
    return case - (36 if case < 42 else 44)


def primary(lane):
    return 0x0a4d0102 + lane * 256


def target(lane, case):
    if case >= 50:
        return 0xc6120101 + lane * 256 + case
    return 0xcb007101 + lane * 64 + case


def controls(lane, scenario, indices, waiting=False):
    result = bytearray()
    def append(option, data):
        length = 16 + len(data)
        result.extend(struct.pack('<Qii', length, 0, option) + data + bytes(-length % 8))
    append(2, struct.pack('<i', 37))
    append(1, struct.pack('<i', 184))
    index, source = 0, primary(lane) + 40 if waiting and scenario == 1 else 0
    if not waiting:
        index = indices[lane ^ 1 if scenario in (2, 3, 5) else lane]
        if scenario in (1, 3, 5):
            source = primary(lane) + 40
        elif scenario == 4:
            source = primary(lane ^ 1) + 40
    append(8, struct.pack('<I', index) + struct.pack('!II', source, 0xdeadbeef))
    if not waiting and scenario == 5:
        append(8, bytes(12))
    return bytes(result)


def read(text, native, firmware):
    lines = text.splitlines()
    require(lines.count('IPV4_SEND_WIRE_DONE lanes=2 cases_each=68') == 1 and
            not any(item in text for item in ('IPV4_SEND_WIRE_FAIL', 'PANIC:', 'FAULT pid=')),
            'complete actual Ethernet output application')
    if not native:
        require(lines.count('AXIOM64_TESTS_PASS') == lines.count('AXIOM64_EXIT status=0') == 1 and
                lines.count('Firmware: ' + firmware.upper()) == 1 and
                sum(lines.count('Firmware: '+value) for value in ('BIOS', 'UEFI')) == 1,
                'actual complete boot and firmware')
    rows = [json.loads(line, object_pairs_hook=unique) for line in lines if line.startswith('{')]
    identity, links = rows[0], rows[1:3]
    require(identity.keys() == {'kind', 'sysname', 'release'} and identity['kind'] == 'kernel' and
            identity['sysname'] == ('Linux' if native else 'Axiom64') and identity['release'], 'actual executing kernel')
    require(len(links) == 2 and all(row.keys() == {'kind','lane','index','mac'} and row['kind'] == 'link' and
        row['lane'] == lane and type(row['index']) is int and row['index'] > 0 and
        row['mac'] == f'52540012341{lane}' for lane,row in enumerate(links)), 'actual distinct physical interfaces')
    indices = [row['index'] for row in links]
    require(indices[0] != indices[1], 'separate interface identities')
    at = 3
    for lane in range(2):
        for case in (*WAITING, *range(50, 68)):
            if case >= 50:
                at = read_inventory(rows, at, lane, case, indices)
                continue
            for routes in (1,0) if waiting_scenario(case) == 1 else (1,):
                messages = []
                while at < len(rows) and rows[at].get('kind') == 'inventory':
                    messages.append(rows[at]);at += 1
                require(messages and at < len(rows), 'original mutation dump and state')
                state = rows[at];at += 1
                address = target(lane,case) if routes else primary(lane)+40
                require(state == dict(kind='state',lane=lane,case=case,phase=1,routes=routes,
                    target=f'{address:08x}',found=(2 if case>=44 else 1) if routes else 0,index=indices[lane^1] if routes else 0),
                    'actual replacement-route or removed-alias state')
                require(all(row.keys() == {'kind','lane','case','phase','routes','hex'} and
                    (row['lane'],row['case'],row['phase'],row['routes']) == (lane,case,1,routes)
                    for row in messages), 'original inventory ownership')
                decoded = inventory(messages,bool(routes))
                if routes:
                    selected = [row for row in decoded if row['destination'] == address and row['prefix'] == 32]
                    wanted = {(indices[lane^1], 1), (indices[lane], 10)} if case>=44 else {(indices[lane^1],0)}
                    require(len(selected) == len(wanted) and all(all(row[name] == value for name,value in
                        dict(table=254,protocol=4,scope=253,type=1).items()) and 5 not in row['attrs'] for row in selected) and
                        all(len(row['attrs'].get(6,bytes(4))) == 4 for row in selected) and
                        {(row['index'],int.from_bytes(row['attrs'].get(6,bytes(4)),'little')) for row in selected} == wanted,
                        'independently decoded retired or surviving original route and new preference')
                else:
                    actual = {(row['index'],row['address'],row['prefix']) for row in decoded if row['index'] in indices}
                    wanted = {(indices[n],value,24) for n in range(2) for value in
                        (primary(n),primary(n)+40,0xc6120102+n*256)}
                    wanted.remove((indices[lane],address,24))
                    require(actual == wanted, 'complete independently decoded alias withdrawal')
    require(at == len(rows), 'no extra mutation summaries')
    named = {}
    prefixes = ('OUTPUT','WAIT_INPUT','PRESSURE','SLEEP','WAIT','RAW_PRESSURE','RAW_ORDER','RETIRED_WINDOW',
                'LIFETIME_INPUT','LIFETIME','LIFETIME_LINK','LIFETIME_WINDOW')
    for line in lines:
        if not line.startswith('IPV4_SEND_WIRE_') or line.startswith('IPV4_SEND_WIRE_DONE'):
            continue
        head,*fields = line.split()
        name = head.removeprefix('IPV4_SEND_WIRE_')
        require(name in prefixes and all('=' in field for field in fields), 'known complete syscall record')
        row = dict(field.split('=',1) for field in fields)
        require(len(row) == len(fields), 'unique syscall fields')
        key = (name,int(row['lane']),int(row['case']))
        require(key not in named, 'unique syscall observation')
        named[key] = row
    expected = {(name,lane,case) for lane in range(2) for name,cases in (
        ('OUTPUT',range(36)),('WAIT_INPUT',WAITING),('PRESSURE',range(36,68)),
        ('SLEEP',(*WAITING,*range(50,68))),('WAIT',WAITING),('RAW_PRESSURE',range(42,44)),('RAW_ORDER',range(42,44)),
        ('RETIRED_WINDOW',range(36,42)),('LIFETIME_INPUT',range(50,68)),('LIFETIME',range(50,68)),
        ('LIFETIME_LINK',[case for case in range(50,68) if (case-50)%3==2]),
        ('LIFETIME_WINDOW',[case for case in range(50,68) if lifetime_retired(case)])) for case in cases}
    require(set(named) == expected, 'every original output, memory, sleeping and completion observation')
    fills = {}
    for lane in range(2):
        for case in range(68):
            if case < 36:
                row = named['OUTPUT',lane,case]
                kind,named_address,scenario = case//12,case//6%2,case%6
                require(set(row) == {'lane','case','kind','named','scenario','result','error','mtu_before','mtu_after','control'} and
                    all(int(row[name]) == value for name,value in dict(kind=kind,named=named_address,scenario=scenario,
                        result=64 if not kind else 72,error=0,mtu_before=-107 if named_address else 1200 if lane else 1400,
                        mtu_after=-107 if named_address else 1200 if lane else 1400).items()) and
                    bytes.fromhex(row['control']) == (controls(lane,scenario,indices) if scenario else b''),
                    'actual selected ancillary bytes and unchanged connected MTU')
                continue
            row = named['PRESSURE',lane,case]
            kind = case-41 if case in (42,43) else 0
            require(set(row) == {'lane','case','kind','fills','buffer','error'} and int(row['kind']) == kind and
                    0 < int(row['fills']) < 64 and 2048 <= int(row['buffer']) <= 65536 and
                    int(row['error']) == (105 if kind else 11), 'actual bounded memory pressure and refusal class')
            fills[lane,case] = int(row['fills'])
            if case >= 50:
                lifetime(named,lane,case,indices,fills[lane,case])
                continue
            if case in (42,43):
                for name,error in (('RAW_PRESSURE',105),('RAW_ORDER',22)):
                    row = named[name,lane,case]
                    require(set(row) == {'lane','case','kind','result','error'} and
                        (int(row['kind']),int(row['result']),int(row['error'])) == (kind,-1,error),
                        'raw memory refusal and control-before-payload admission')
                continue
            row = named['WAIT_INPUT',lane,case]
            require(set(row) == {'lane','case','length','control'} and int(row['length']) == 1100 and
                bytes.fromhex(row['control']) == controls(lane,waiting_scenario(case),indices,True), 'original controls before actual wait')
            sleeping = named['SLEEP',lane,case]
            status = bytes.fromhex(sleeping['status']).decode()
            tid = int(sleeping['tid'])
            require(set(sleeping) == {'lane','case','tid','monotonic_ns','status'} and tid > 0 and
                '\nState:\tS (sleeping)\n' in '\n'+status and f'\nPid:\t{tid}\n' in '\n'+status,
                'actual selected worker sleeping inside sendmsg')
            row = named['WAIT',lane,case]
            error = 14 if waiting_scenario(case) == 3 else 4 if waiting_scenario(case) == 5 else 0
            require(set(row) == {'lane','case','scenario','fills','result','error','began_ns','finished_ns','signals'} and
                all(int(row[name]) == value for name,value in dict(scenario=waiting_scenario(case),fills=fills[lane,case],
                    result=-1 if error else 1100,error=error,signals=2*lane+int(case>=41)+int(case==49)).items()) and
                0 <= int(row['began_ns']) <= int(sleeping['monotonic_ns']) <= int(row['finished_ns']) and
                int(row['finished_ns'])-int(row['began_ns']) <= 6000000000,
                'actual completed retained request, payload fault or interruption')
            if case < 42:
                window = named['RETIRED_WINDOW',lane,case]
                require(set(window) == {'lane','case','began_ns','finished_ns'} and
                    int(row['finished_ns']) <= int(window['began_ns']) and
                    int(window['finished_ns'])-int(window['began_ns']) >= 3000000000,
                    'complete actual three-second retired-output observation after worker completion')
    return dict(identity=identity,indices=indices,fills=fills,output_cases=72,waiting_cases=60,
                raw_pressure_cases=4,address_route_states=220,lifetime_cases=36,lifetime_retired_cases=16)
