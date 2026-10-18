# SPDX-License-Identifier: GPL-3.0-or-later
"""Record actual inputs for both ACK-gated congestion observations."""
from tcp_icmp_inputs import record as record_inputs

SOURCES = ('Makefile', 'userspace/tests/net/tcp_window.c',
           'scripts/tcp_congestion/window_peer.py', 'scripts/tcp_congestion/fast_peer.py',
           'scripts/tcp_congestion/window_capture.py', 'scripts/tcp_congestion/fast_capture.py',
           'scripts/tcp_congestion/capture.py', 'scripts/tcp_congestion/inputs.py',
           'scripts/tcp_fixture_inputs.py', 'scripts/tcp_icmp_inputs.py',
           'scripts/tests/tcp_window_capture_test.py', 'scripts/tests/tcp_fast_capture_test.py',
           'scripts/tests/tcp_congestion_controls.py', 'scripts/tests/tcp_malformed_capture_test.py',
           'scripts/tcp_malformed/capture.py', 'scripts/tcp_fault_peer.py',
           'scripts/tcp_fault_test.py', 'scripts/tcp_fault_native.py', 'scripts/tcp_capture_clock.py',
           'kernel/net/tcp/sender.cpp', 'kernel/include/net/tcp/sender.hpp',
           'kernel/net/tcp/connection.cpp', 'kernel/include/net/tcp/connection.hpp',
           'kernel/net/tcp/socket.cpp', 'kernel/include/net/tcp/socket.hpp')


def record(linkage, wire, native=False, image=None):
    if wire not in ('window', 'fast'):
        raise ValueError('known captured congestion profile')
    label = f'tcp-{wire}-linux-{linkage}' if native else f'tcp-{wire}-{linkage}'
    return record_inputs(linkage, native=native, image=image, label=label,
                         program='tcp-window', sources=SOURCES)
