# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare actual physical output and waiting IPv4 sends on Linux and Axiom64."""
from ipv4_receive_wire_test import main
from ipv4_send_wire_peer import peers

if __name__ == '__main__':
    raise SystemExit(main(dict(program='ipv4-send-wire', entrypoint=__file__, peers=peers, stable_native_peers=True,
        sources=['userspace/tests/net/ipv4_send_wire.c', 'userspace/tests/net/ipv4_receive_wire_fixture.c'],
        flags=['-pthread'], completion='IPV4_SEND_WIRE_DONE lanes=2 cases_each=68')))
