# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe original IPv6 datagrams and inject owned extended-error quotes."""
from ipv6_pmtu_peer import Peer as PathPeer
from ipv6_error_metadata_peer import Peer as MetadataPeer


class Peer(PathPeer):
    barrier_protocol = b'\x88\xbc'
    barrier_magic = b'IP6E'
    quote_length = 96

    def __init__(self, lane, native=False):
        super().__init__(lane, native)
        self.metadata = MetadataPeer(lane, native)
        self.metadata.outgoing = self.outgoing

    def receive(self, frame):
        if frame[12:14] == b'\x88\xbe' or self.metadata.ready:
            self.metadata.receive(frame)
        else:
            super().receive(frame)

    @property
    def passed(self):
        return super().passed and self.metadata.passed

    def result(self):
        result = super().result()
        result['metadata'] = self.metadata.result()
        return result
