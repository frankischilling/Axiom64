# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise identical link-local TCP tuples on two independent interface zones."""
import ipaddress
from tcp6.peer import Peer as LossPeer


class Peer(LossPeer):
    def __init__(self, lane, minimum_fin_ms=850, native=False):
        super().__init__(lane, minimum_fin_ms, native)
        self.ip = ipaddress.IPv6Address('fe80::1').packed
        self.address = ipaddress.IPv6Address('fe80::2').packed
        for flow in self.flows:
            flow.local_port = 45000 if flow.role else 44000
            flow.guest_port = 44010 if flow.role else 44020
