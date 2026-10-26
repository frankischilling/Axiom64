# SPDX-License-Identifier: GPL-3.0-or-later
"""Select a complete TCP6 workload without duplicating native or boot ownership."""


def definition(suite):
    if suite == 'isolation':
        from tcp6.isolation_peer import Peer
        from tcp6.isolation_capture import verify
        return dict(program='tcp6-isolation', source='userspace/tests/net/tcp6/isolation.c',
                    flags=[], marker='TCP6_ISOLATION_PASS rounds=4 zones=2 bytes_each=32 quiet_ms=50',
                    peer=Peer, verify=verify)
    if suite == 'replies':
        from tcp6.replies_peer import Peer
        from tcp6.replies_capture import verify
        return dict(program='tcp6-replies', source='userspace/tests/net/tcp6/replies.c',
                    flags=[], marker='TCP6_REPLIES_PASS lanes=2 cases_each=20 quiet_ms=50',
                    peer=Peer, verify=verify)
    if suite == 'scoped':
        from functools import partial
        from tcp6.scoped_peer import Peer
        from tcp6.capture import verify
        return dict(program='tcp6-scoped', source='userspace/tests/net/tcp_fault.c',
                    flags=['-DTCP_IPV6', '-DTCP_IPV6_LINK_LOCAL'],
                    marker='TCP6_SCOPED_FAULT_PASS flows=4 bytes_each=65536',
                    peer=Peer, verify=partial(verify, scoped=True))
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
    if suite == 'errors':
        from tcp6.errors_peer import Peer
        from tcp6.errors_capture import verify
        return dict(program='tcp6-errors', source='userspace/tests/net/tcp6/errors.c',
                    flags=[], marker='TCP6_ERRORS_PASS lanes=2 cases_each=62',
                    peer=Peer, verify=verify)
    raise ValueError('unknown TCP6 runtime suite')
