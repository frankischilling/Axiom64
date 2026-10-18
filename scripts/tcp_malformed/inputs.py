# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind malformed TCP observations to real sources, clients and runtime bytes."""
from tcp_icmp_inputs import record as record_inputs

SOURCES = ('Makefile', 'userspace/tests/net/tcp_malformed.c',
           'scripts/tcp_malformed/peer.py', 'scripts/tcp_malformed/capture.py',
           'scripts/tcp_malformed/inputs.py', 'scripts/tcp_icmp_inputs.py',
           'scripts/tests/tcp_malformed_capture_test.py',
           'scripts/tcp_fault_peer.py', 'scripts/tcp_fault_test.py',
           'scripts/tcp_fault_native.py', 'scripts/tcp_capture_clock.py',
           'kernel/net/tcp/wire.cpp', 'kernel/include/net/tcp/wire.hpp',
           'kernel/net/tcp/socket.cpp', 'kernel/include/net/tcp/socket.hpp',
           'kernel/net/tcp/connection.cpp', 'kernel/include/net/tcp/connection.hpp')


def record(linkage, native=False, image=None, label=None):
    return record_inputs(linkage, native=native, image=image, label=label,
                         program='tcp-malformed', sources=SOURCES)
