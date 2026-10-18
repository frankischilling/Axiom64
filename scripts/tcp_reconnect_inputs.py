# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind reconnect observations to actual clients, protocol state and retained I/O."""
from tcp_icmp_inputs import record as record_inputs
from tcp_icmp_inputs import IPV4_MODULES

SOURCES = ('Makefile', 'scripts/tcp_capture_clock.py', 'scripts/tests/tcp_clock_mutations.py', 'userspace/tests/net/tcp_reconnect.c', 'scripts/tcp_reconnect_peer.py',
           'scripts/tcp_reconnect_inputs.py', 'scripts/tcp_icmp_inputs.py',
           'scripts/tcp_reconnect_fault.py', 'scripts/tcp_reconnect_queued.py',
           'scripts/tcp_reconnect_capture.py', 'scripts/tcp_reconnect_queued_capture.py',
           'scripts/tests/tcp_reconnect_capture_test.py',
           'scripts/tests/tcp_reconnect_queued_controls.py',
           'scripts/tests/tcp_reconnect_observer_test.py',
           'scripts/tests/tcp_reconnect_clock_test.py',
           'scripts/tcp_fault_peer.py', 'scripts/tcp_fault_test.py', 'scripts/tcp_fault_native.py',
           'kernel/io/io.cpp', 'kernel/net/tcp/socket.cpp', 'kernel/include/net/tcp/socket.hpp',
           'kernel/net/tcp/connection.cpp', 'kernel/include/net/tcp/connection.hpp',
           'kernel/net/tcp/time_wait.cpp', 'kernel/include/net/tcp/time_wait.hpp',
           'kernel/net/tcp/isn.cpp', 'kernel/include/net/tcp/isn.hpp',
           'kernel/net/ipv4/socket.cpp', 'kernel/net/ipv4/socket.hpp',
           'kernel/net/ipv4/core.cpp', 'kernel/include/net/ipv4.hpp')
SOURCES = tuple(dict.fromkeys(SOURCES + IPV4_MODULES))


def record(linkage, native=False, image=None, label=None):
    return record_inputs(linkage, native=native, image=image, label=label,
                         program='tcp-reconnect', sources=SOURCES)
