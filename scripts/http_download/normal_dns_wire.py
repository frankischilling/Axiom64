# SPDX-License-Identifier: GPL-3.0-or-later
"""Read actual DHCP leases and DNS query/reply bytes independently from PCAP."""
from pathlib import Path
import struct

from tcp_capture import checksum
from tcp_fault_capture import require


def verify(capture, lane):
    data = Path(capture).read_bytes()
    require(len(data) >= 24 and data[:4] in (bytes.fromhex('d4c3b2a1'), bytes.fromhex('a1b2c3d4')),
            'normal PCAP header')
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    major, minor, _, _, snap, link = struct.unpack_from(endian+'HHIIII', data, 4)
    require((major, minor, link) == (2, 4, 1) and snap >= 1514, 'normal Ethernet PCAP format')
    queries, answers, leases = [], [], []
    at = 24
    while at < len(data):
        require(at+16 <= len(data), 'normal complete PCAP record')
        _, micros, length, original = struct.unpack_from(endian+'IIII', data, at)
        at += 16
        require(micros < 1000000 and length == original and 14 <= length <= snap and at+length <= len(data),
                'normal PCAP packet bounds')
        frame = data[at:at+length]
        at += length
        if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
            continue
        header, total = (frame[14] & 15)*4, int.from_bytes(frame[16:18], 'big')
        require(frame[14] >> 4 == 4 and 20 <= header and header+8 <= total <= len(frame)-14 and
                not checksum(frame[14:14+header]) and not int.from_bytes(frame[20:22], 'big') & 0x3fff,
                'normal actual UDP IPv4 checksum, bounds and fragmentation')
        ip = frame[14:14+total]
        udp = ip[header:]
        source, target, size, check = struct.unpack_from('!HHHH', udp)
        require(size == len(udp) and (not check or not checksum(ip[12:20]+struct.pack('!BBH',0,17,size)+udp)),
                'normal actual UDP length and checksum')
        payload = udp[8:]
        if 53 in (source, target):
            guest, resolver = bytes((10,23,lane+1,2)), bytes((10,23,lane+1,3))
            outgoing = target == 53
            require(check and (ip[12:16],ip[16:20]) == ((guest,resolver) if outgoing else (resolver,guest)),
                    'actual normal DNS address tuple and nonzero checksum')
            require(len(payload) >= 17, 'normal complete DNS header and question')
            (queries if outgoing else answers).append(payload.hex())
        elif (source,target) == (67,68):
            require(len(payload) >= 240 and payload[:3] == b'\x02\x01\x06' and
                    payload[236:240] == bytes.fromhex('63825363'), 'actual BOOTP DHCP reply')
            options = {}
            pos = 240
            while pos < len(payload):
                kind = payload[pos]
                pos += 1
                if kind == 255:
                    break
                if kind == 0:
                    continue
                require(pos < len(payload), 'complete DHCP option length')
                length = payload[pos]
                pos += 1
                require(pos+length <= len(payload) and kind not in options, 'bounded unique DHCP option')
                options[kind] = payload[pos:pos+length]
                pos += length
            if options.get(53) == b'\x05':
                address, resolver = bytes((10,23,lane+1,2)), bytes((10,23,lane+1,3))
                require(payload[16:20] == address and payload[28:34] == bytes((0x52,0x54,0,0x65,0,lane)) and
                        options.get(1) == bytes((255,255,255,0)) and options.get(6) == resolver and
                        options.get(3) == bytes((10,23,lane+1,1)),
                        'actual production DHCP lease, adapter, mask, route and resolver')
                leases.append(dict(address=address.hex(), resolver=resolver.hex(), transaction=payload[4:8].hex()))
    require(len(leases) == 1, 'one actual normal DHCP ACK per fresh kernel and adapter')
    return dict(passed=True, queries=queries, answers=answers, leases=leases)
