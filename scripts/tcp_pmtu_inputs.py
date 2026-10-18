# SPDX-License-Identifier: GPL-3.0-or-later
"""Fingerprint PMTU clients, providers, kernel and independent fixture sources."""
from tcp_icmp_inputs import record as record_inputs
from tcp_icmp_inputs import IPV4_MODULES

SOURCES = ('Makefile', 'scripts/tcp_capture_profiles.py', 'scripts/tcp_capture_clock.py', 'scripts/tests/tcp_clock_mutations.py', 'userspace/tests/net/tcp_pmtu.c', 'userspace/tests/net/packet.c',
           'scripts/tcp_pmtu_peer.py', 'scripts/tcp_pmtu_inputs.py',
           'scripts/tcp_pmtu_capture.py', 'scripts/tcp_icmp_inputs.py',
           'scripts/tcp_icmp_capture.py', 'scripts/tcp_fault_peer.py',
           'scripts/tcp_fault_test.py', 'scripts/tcp_fault_native.py',
           'kernel/io/io.cpp',
           'kernel/net/tcp/icmp.cpp', 'kernel/include/net/tcp/icmp.hpp',
           'kernel/net/tcp/connection.cpp', 'kernel/include/net/tcp/connection.hpp',
           'kernel/net/tcp/sender.cpp', 'kernel/include/net/tcp/sender.hpp',
           'kernel/net/tcp/socket.cpp', 'kernel/include/net/tcp/socket.hpp',
           'kernel/net/ipv4/core.cpp', 'kernel/net/ipv4/socket.cpp', 'kernel/net/ipv4/socket.hpp',
           'kernel/include/net/ipv4.hpp', 'kernel/include/net/inet.hpp',
           'kernel/net/packet.cpp', 'kernel/include/net/packet.hpp',
           'kernel/net/ethernet.cpp', 'kernel/tests/net/tcp_pmtu.cpp',
           'scripts/packet_buffer_native.py', 'scripts/tests/tcp_pmtu_capture_test.py')
SOURCES = tuple(dict.fromkeys(SOURCES + IPV4_MODULES))


def record(linkage, native=False, image=None, label=None):
    return record_inputs(linkage, native=native, image=image, label=label,
                         program='tcp-pmtu', sources=SOURCES)
