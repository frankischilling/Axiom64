# SPDX-License-Identifier: GPL-3.0-or-later
"""Check every original IPv4 send-control input, result and packet byte."""
import re
import socket
import struct

def require(accepted, reason):
    if not accepted:
        raise ValueError(reason)

def checksum(data):
    value = sum(int.from_bytes(data[at:at+2], 'big') for at in range(0, len(data), 2))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return value == 65535

def control(variant, loopback, actual):
    result = bytearray()
    def append(level, option, data):
        size = 16 + len(data)
        result.extend(struct.pack('<Qii', size, level, option) + data + bytes(-size % 8))
    integer = lambda value: struct.pack('<i', value)
    if variant in (1,4,5,6,7,8,12,27,28,29,30,31,32,56,57,63):
        value = {6:0,7:-1,8:256,56:0}.get(variant,37)
        append(0,2,integer(value)[:1 if variant == 12 else 4])
    if variant in (2,4,9,10,11,63):
        value = {9:-1,10:256,11:254}.get(variant,184)
        append(0,1,integer(value)[:1 if variant == 11 else 4])
    if variant in (3,4,13,14,15,16,17,18,52,53,54,55,59,61,62,63):
        index = 999999 if variant in (16,17,55) else 0 if variant == 62 else loopback
        source = '203.0.113.8' if variant in (15,17,52,53,54) else '0.0.0.0' if variant == 61 else '127.0.0.2'
        data = struct.pack('<I',index) + socket.inet_aton(source) + socket.inet_aton('222.173.190.239')
        append(0,8,(data + b'\0')[:11 if variant == 13 else 13 if variant == 14 else 12])
    if variant == 5:
        append(0,2,integer(41))
    if variant == 18:
        append(0,8,bytes(12))
    if 19 <= variant <= 25:
        level = 0 if variant == 19 else 777 if variant == 20 else 1 if variant <= 23 else 17
        option = 1 if variant == 21 else 2 if variant == 22 else 103 if variant == 25 else 999
        data = bytes(12 if variant == 22 else 2 if variant == 25 else 4)
        if variant == 21:
            descriptor = struct.unpack('<i', actual[16:20])[0]
            require(0 <= descriptor < 1024, 'actual rights descriptor')
            data = integer(descriptor)
        append(level,option,data)
    if variant == 26:
        append(0,2,b'')
    if variant == 27:
        result = result[:15]
    if variant in (28,29,30):
        result[:8] = struct.pack('<Q',{28:15,29:17,30:200}[variant])
    if variant in (31,32):
        result.extend(bytes(1 if variant == 31 else 16))
    return bytes(result)

def expected_error(kind, named, variant):
    errors = {6:22,7:22,8:22,9:22,10:22,12:22,13:22,14:22,15:101,16:19,17:101,
        19:22,23:22,26:22,28:22,29:22,30:22,32:22,34:14,35:14,36:105,
        39:97,40:22,41:14,42:22,44:14,45:90,46:14,47:22,48:90,
        49:14,50:14,51:14,54:101,56:22,57:14,58:14}
    if variant == 24:
        return 22 if kind == 0 else 0
    if variant in (37,38):
        return 89 if named else 0
    if variant in (52,53):
        return 14 if kind == 2 else 101
    if variant == 55:
        return 14 if kind == 2 else 19
    return errors.get(variant,0)

def verify(text):
    begin = re.findall(r'^IPV4_SEND_CONTROLS_BEGIN loopback=(\d+)$', text, re.M)
    require(len(begin) == 1 and 0 < int(begin[0]) < 2**31, 'actual loopback identity')
    loopback = int(begin[0])
    require(text.splitlines().count('IPV4_SEND_CONTROLS_DONE cases=384 observations=768') == 1,
        'complete original case count')
    require('IPV4_SEND_CONTROLS_FAIL' not in text, 'actual client refusal')
    inputs, rows = {}, {}
    for line in text.splitlines():
        if line.startswith('IPV4_SEND_INPUT '):
            fields = dict(item.split('=',1) for item in line.split()[1:])
            key = tuple(int(fields[name]) for name in ('kind','named','variant'))
            require(key not in inputs,'unique original input')
            actual = bytes.fromhex(fields['control']) if fields['control'] != '-' else b''
            require(actual == control(key[2],loopback,actual), 'complete original ancillary bytes')
            require(int(fields['vector_count']) == (1025 if key[2] in (45,46,47,48) else 1), 'vector admission input')
            require(int(fields['body_length']) == (24 if key[0] == 0 else 32), 'original payload length')
            inputs[key] = fields
        if line.startswith('IPV4_SEND_CASE '):
            fields = dict(item.split('=',1) for item in line.split()[1:])
            key = tuple(int(fields[name]) for name in ('kind','named','variant','baseline'))
            require(key not in rows, 'unique observation')
            rows[key] = fields
    wanted = {(kind,named,variant) for kind in range(3) for named in range(2) for variant in range(64)}
    require(set(inputs) == wanted and set(rows) == {(*key,base) for key in wanted for base in (0,1)},
        'all input/selected/baseline records')
    preimport = {34,35,36,41,42,44,45,46,47,48,57,58}
    for key, row in rows.items():
        kind,named,variant,base = key
        error = 0 if base else expected_error(kind,named,variant)
        require(int(row['error']) == error and int(row['result']) == (-1 if error else 24 if kind == 0 else 32),
            'native-compatible result and error priority: '+str(key))
        require(row['unchanged'] == '1' and row['ttl'] == '63' and row['tos'] == '34', 'original inputs and shared defaults')
        before, after = [row[name].split(':') for name in ('before','after')]
        address = '00000000' if named else '7f000001'
        require(before[0] == after[0] == address, 'shared local source unchanged')
        before_port,after_port = int(before[1]),int(after[1])
        if kind:
            require(before_port == after_port == (1 if kind == 2 else 17), 'actual raw protocol identity')
        else:
            selected_bound = not named or variant not in preimport
            require(bool(before_port) == (selected_bound if base else not named), 'binding before actual call')
            require(bool(after_port) == (True if base else selected_bound), 'automatic binding admission point')
            require(not before_port or before_port == after_port, 'retained UDP port')
            if base:
                selected = rows[(kind,named,variant,0)]['after'].split(':')
                require(before == selected, 'same description between selected and baseline sends')
        token = bytearray((at*19+7)&255 for at in range(24))
        token[:4] = b'SCTL';token[4:7] = bytes((kind,variant,base))
        if error:
            require(row['packet'] == '-' and row['body'] == '-' and int(row['delivery']) == -1,
                'rejected send emits no owned packet or delivery')
            continue
        packet = bytes.fromhex(row['packet'])
        require(len(packet) == 52 and packet[0] == 0x45 and checksum(packet[:20]), 'complete valid IP header')
        require(int.from_bytes(packet[2:4],'big') == len(packet) and packet[9] == (1 if kind == 2 else 17), 'actual IP length/protocol')
        require(packet[28:] == token, 'actual full owned payload identity')
        ttl = 63 if base else 37 if variant in (1,4,31,63) else 41 if variant == 5 else 63
        tos = 34 if base else 184 if variant in (2,4,63) else 254 if variant == 11 else 34
        source = '127.0.0.2' if not base and variant in (3,4,59,62,63) else '127.0.0.1'
        destination = '127.0.0.2' if not base and variant == 59 else '127.0.0.1'
        require(packet[8] == ttl and packet[1] == tos and packet[12:16] == socket.inet_aton(source) and
            packet[16:20] == socket.inet_aton(destination), 'actual selected IP source/destination/TTL/TOS: '+str(key))
        if kind == 2:
            require(packet[20:22] == b'\xfd\0' and checksum(packet[20:]), 'complete ICMP bytes/checksum')
            require(int(row['delivery']) == -1 and row['body'] == '-' and int(row['delivery_error']) == 0, 'raw ICMP has no UDP sink')
        else:
            require(int.from_bytes(packet[22:24],'big') == 55100 and int.from_bytes(packet[24:26],'big') == 32,
                'actual UDP destination and transport length')
            require(int.from_bytes(packet[20:22],'big') == (55101 if kind else after_port), 'actual UDP source port')
            require(row['body'] == token.hex() and int(row['delivery']) == 24 and int(row['delivery_error']) == 0,
                'actual complete UDP application delivery')
    return dict(inputs=len(inputs),observations=len(rows),original_cases=384,actual_headers_and_payloads=True,
        default_sockets_and_auto_binding=True)

