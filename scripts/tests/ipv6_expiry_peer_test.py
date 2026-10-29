# SPDX-License-Identifier: GPL-3.0-or-later
"""A packet barrier can overtake IPv6 datagrams awaiting neighbor resolution."""
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_expiry_peer import Peer, application
from ipv6_host_peer import checksum


def barrier(peer, phase):
    return peer.control + peer.guest + b'\x88\xbcIP6X' + bytes([peer.lane, phase]) + bytes(40)


def datagram(peer, number):
    source = peer.link if number % 8 >= 4 else peer.local
    destination = source[:-1] + bytes([32 + number])
    protocol = 17 if number < 8 else 58
    body = bytearray(application(peer.lane, number, 0, 1440))
    if protocol == 17:
        body = bytearray(struct.pack('!HHHH', 49000 + number, 50000 + number, 1448, 0)) + body
    offset = 6 if protocol == 17 else 2
    body[offset:offset + 2] = checksum(source + destination + struct.pack('!I3xB', len(body), protocol) + body).to_bytes(2, 'big')
    return peer.mac + peer.guest + b'\x86\xdd' + struct.pack('!IHBB', 6 << 28, len(body), protocol, 64) + source + destination + body


def main():
    for lane in range(2):
        peer = Peer(lane, native=True)
        peer.receive(barrier(peer, 0))
        peer.receive(barrier(peer, 1))
        peer.outgoing.clear()
        originals = [datagram(peer, number) for number in range(16)]
        for frame in originals[:-1]:
            peer.receive(frame)
        peer.receive(barrier(peer, 2))
        peer.tick()
        assert not peer.outgoing and not peer.hints, 'do not acknowledge or quote a missing actual datagram'
        peer.receive(originals[-1])
        peer.tick()
        assert len(peer.outgoing) == 8 and len(peer.hints) == 8
        assert {frame[62:] for frame in peer.outgoing} == {
            frame[14:62] for number, frame in enumerate(originals) if number % 4 < 2}
    print('IPV6_EXPIRY_PEER_PASS delayed_actual_datagram=2')


if __name__ == '__main__':
    main()
