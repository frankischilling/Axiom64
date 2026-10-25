# SPDX-License-Identifier: GPL-3.0-or-later
"""Select a complete TCP6 workload without duplicating native or boot ownership."""


def definition(suite):
    if suite == 'loss':
        from tcp6.peer import Peer
        from tcp6.capture import verify
        return dict(program='tcp6-fault', source='userspace/tests/net/tcp_fault.c',
                    flags=['-DTCP_IPV6'], marker='TCP6_FAULT_PASS flows=4 bytes_each=65536',
                    peer=Peer, verify=verify)
    if suite == 'pmtu':
        from tcp6.pmtu_peer import Peer
        from tcp6.pmtu_capture import verify
        return dict(program='tcp6-pmtu', source='userspace/tests/net/tcp6/pmtu.c',
                    flags=[], marker='TCP6_PMTU_PASS lanes=2 cases_each=22 bytes_each=4096',
                    peer=Peer, verify=verify)
    raise ValueError('unknown TCP6 runtime suite')
