# SPDX-License-Identifier: GPL-3.0-or-later
"""Fingerprint the clients, providers and kernel ownership used by pressure tests."""
from tcp_icmp_inputs import record as record_inputs
from tcp_icmp_inputs import IPV4_MODULES

SOURCES = ('Makefile', 'scripts/tcp_capture_link.py', 'scripts/tests/tcp_packet_observer_test.py', 'scripts/tests/tcp_capture_link_test.py', 'scripts/tcp_capture_profiles.py', 'scripts/tcp_capture_clock.py', 'scripts/tests/tcp_clock_mutations.py', 'userspace/tests/net/tcp_pressure.c', 'scripts/tcp_pressure_peer.py',
           'scripts/tcp_pressure_inputs.py', 'scripts/tcp_pressure_capture.py',
           'scripts/tcp_pressure_test.py', 'scripts/tcp_icmp_inputs.py', 'scripts/tcp_icmp_capture.py',
           'scripts/tcp_fault_peer.py', 'scripts/tcp_fault_test.py', 'scripts/tcp_fault_native.py',
           'kernel/io/io.cpp',
           'kernel/net/tcp/socket.cpp', 'kernel/include/net/tcp/socket.hpp',
           'kernel/net/tcp/connection.cpp', 'kernel/include/net/tcp/connection.hpp',
           'kernel/net/tcp/time_wait.cpp', 'kernel/include/net/tcp/time_wait.hpp',
           'kernel/net/ipv4/socket.cpp', 'kernel/net/ipv4/socket.hpp',
           'kernel/net/ipv4/core.cpp', 'kernel/include/net/ipv4.hpp',
           'kernel/net/packet.cpp', 'kernel/include/net/packet.hpp',
           'kernel/net/ethernet.cpp', 'kernel/include/net/inet.hpp',
           'kernel/core/time.cpp', 'kernel/include/core/time.hpp', 'kernel/arch/x86_64/clock.cpp')
SOURCES = tuple(dict.fromkeys(SOURCES + IPV4_MODULES))


def record(linkage, native=False, image=None, label=None):
    return record_inputs(linkage, native=native, image=image, label=label,
                         program='tcp-pressure', sources=SOURCES)
