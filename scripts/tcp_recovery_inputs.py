# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind interface-recovery observations to actual clients and network ownership."""
from tcp_icmp_inputs import record as record_inputs

SOURCES = ('Makefile', 'scripts/tcp_capture_clock.py', 'scripts/tests/tcp_clock_mutations.py', 'userspace/tests/net/tcp_recovery.c', 'scripts/tcp_recovery_peer.py',
           'scripts/tcp_recovery_inputs.py', 'scripts/tcp_icmp_inputs.py',
           'scripts/tcp_recovery_fault.py', 'scripts/tcp_recovery_carrier.py', 'scripts/qmp.py',
           'scripts/tcp_recovery_capture.py', 'scripts/tests/tcp_recovery_capture_test.py',
           'kernel/net/ethernet.cpp',
           'kernel/include/net/ethernet.hpp',
           'kernel/drivers/net/virtio.cpp', 'kernel/drivers/net/e1000.cpp',
           'scripts/tcp_fault_peer.py', 'scripts/tcp_fault_test.py', 'scripts/tcp_fault_native.py',
           'kernel/io/io.cpp', 'kernel/net/tcp/socket.cpp', 'kernel/include/net/tcp/socket.hpp',
           'kernel/net/tcp/connection.cpp', 'kernel/include/net/tcp/connection.hpp',
           'kernel/net/tcp/time_wait.cpp', 'kernel/include/net/tcp/time_wait.hpp',
           'kernel/net/tcp/isn.cpp', 'kernel/include/net/tcp/isn.hpp',
           'kernel/net/ipv4/socket.cpp', 'kernel/net/ipv4/socket.hpp',
           'kernel/net/ipv4/core.cpp', 'kernel/include/net/ipv4.hpp')


def record(linkage, native=False, image=None, label=None):
    return record_inputs(linkage, native=native, image=image, label=label,
                         program='tcp-recovery', sources=SOURCES)
