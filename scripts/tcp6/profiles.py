# SPDX-License-Identifier: GPL-3.0-or-later
"""Select a complete TCP6 workload without duplicating native or boot ownership."""


def definition(suite):
    if suite in ('controls-ipv6', 'controls-mapped', 'controls-ipv4'):
        from functools import partial
        from tcp6.control_peer import Peer, marker
        from tcp6.control_capture import verify, damaged
        family = suite.removeprefix('controls-')
        number = ('ipv6', 'mapped', 'ipv4').index(family)
        return dict(program='tcp6-' + suite, source='userspace/tests/net/tcp6/control_wire.c',
                    flags=['-Iuserspace/tests/net', '-DWIRE_FAMILY=' + str(number)],
                    marker=marker(family), peer=partial(Peer, family=family),
                    verify=partial(verify, family=family), damaged=partial(damaged, family=family),
                    router_hop_control=True)
    if suite == 'pending-source':
        from tcp6.pending_peer import Peer,MARKER
        from tcp6.pending_capture import verify,damaged
        return dict(program='tcp6-pending-source',source='userspace/tests/net/tcp6/pending_source.c',
                    flags=['-Iuserspace/tests/net'],marker=MARKER,peer=Peer,verify=verify,damaged=damaged)
    if suite == 'source-lifetime':
        from tcp6.source_peer import Peer,MARKER
        from tcp6.source_capture import verify,damaged
        return dict(program='tcp6-source-lifetime',source='userspace/tests/net/tcp6/source_lifetime.c',
                    flags=['-Iuserspace/tests/net'],marker=MARKER,peer=Peer,verify=verify,damaged=damaged)
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
