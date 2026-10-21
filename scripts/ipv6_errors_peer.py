# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe original IPv6 datagrams and inject owned extended-error quotes."""
from ipv6_pmtu_peer import Peer as PathPeer


class Peer(PathPeer):
    barrier_protocol = b'\x88\xbc'
    barrier_magic = b'IP6E'
    quote_length = 96
