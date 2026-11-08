# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict Ethernet/IPv4 transport fields for the lifetime peer and offline readers."""
import struct

from ipv4_lifetimes.reader import require


def definitions():
    result = []
    for lane in (0, 1):
        source = 0xc6124002 + lane * 0x1000
        for transport in range(3):
            for survival in range(4):
                number = len(result)
                result.append(dict(case=number, lane=lane, transport=transport, survival=survival,
                                   source=source, peer=(source & 0xffffff00) | (16 + number % 12),
                                   guard=(source & 0xffffff00) | 254, port=39000 + 2 * number,
                                   retained=survival in (1, 3)))
    return result


def payload(number, tag):
    result = bytearray((number * 29 + tag * 71 + at * 17 + 11) & 255 for at in range(64))
    result[:8] = b'AXLIFE01'
    result[8:10] = bytes((number, tag))
    return bytes(result)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + str(len(data) // 2) + 'H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def hardware(lane, peer=False):
    return bytes((2, 0, 0, 0, int(peer), lane + 1))


def ipv4(frame):
    require(len(frame) >= 34 and frame[12:14] == b'\x08\x00', 'complete Ethernet IPv4 frame')
    packet = frame[14:]
    length = int.from_bytes(packet[2:4], 'big')
    header = (packet[0] & 15) * 4
    require(packet[0] >> 4 == 4 and 20 <= header <= 60 and header <= length <= len(packet) and
            checksum(packet[:header]) == 0 and packet[8] > 0 and not int.from_bytes(packet[6:8], 'big') & 0xbfff,
            'complete unfragmented IPv4 packet and header checksum')
    packet = packet[:length]
    source, destination = struct.unpack_from('!II', packet, 12)
    protocol = packet[9]
    data = packet[header:]
    result = dict(source=source, destination=destination, protocol=protocol, ttl=packet[8],
                  header_bytes=header, total_bytes=length, transport=data)
    if protocol in (6, 17):
        pseudo = packet[12:20] + bytes((0, protocol)) + len(data).to_bytes(2, 'big')
        require(len(data) >= (20 if protocol == 6 else 8) and checksum(pseudo + data) == 0,
                'complete software transport checksum including original IPv4 pseudo-header')
        result['source_port'], result['destination_port'] = struct.unpack_from('!HH', data)
        if protocol == 17:
            require(int.from_bytes(data[4:6], 'big') == len(data) and data[6:8] != bytes(2),
                    'complete UDP length and transmitted checksum')
            result['payload'] = data[8:]
        else:
            size = (data[12] >> 4) * 4
            require(20 <= size <= len(data), 'complete TCP header and options')
            result.update(sequence=int.from_bytes(data[4:8], 'big'),
                          acknowledgement=int.from_bytes(data[8:12], 'big'), flags=data[13],
                          window=int.from_bytes(data[14:16], 'big'), payload=data[size:])
    else:
        result['payload'] = data
    return result


def packet(lane, source, destination, protocol, body, identifier=0):
    # RFC 791 header checksum and RFC 768/9293 transport pseudo-headers.
    header = bytearray(struct.pack('!BBHHHBBHII', 0x45, 0, 20 + len(body), identifier, 0x4000,
                                  64, protocol, 0, source, destination))
    struct.pack_into('!H', header, 10, checksum(bytes(header)))
    frame = hardware(lane) + hardware(lane, True) + b'\x08\x00' + header + body
    return bytes(frame) + bytes(max(0, 60 - len(frame)))


def tcp(spec, sequence, acknowledgement, flags, data=b'', syn=False):
    options = b'\2\4\5\xb4' if syn else b''
    header = struct.pack('!HHIIBBHHH', 44732, spec['port'], sequence & 0xffffffff,
                         acknowledgement & 0xffffffff, ((20 + len(options)) // 4) << 4,
                         flags, 65535, 0, 0) + options + data
    pseudo = struct.pack('!IIBBH', spec['peer'], spec['source'], 0, 6, len(header))
    result = bytearray(header)
    struct.pack_into('!H', result, 16, checksum(pseudo + header))
    return packet(spec['lane'], spec['peer'], spec['source'], 6, result)


def arp_reply(lane, frame):
    require(len(frame) >= 42 and frame[12:22] == b'\x08\x06' + struct.pack('!HHBBH', 1, 0x800, 6, 4, 1),
            'complete Ethernet/IPv4 ARP request')
    require(frame[6:12] == frame[22:28] == hardware(lane), 'actual ARP sender hardware')
    peer = hardware(lane, True)
    result = hardware(lane) + peer + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x800, 6, 4, 2)
    result += peer + frame[38:42] + hardware(lane) + frame[28:32]
    return result + bytes(60 - len(result))
