# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain the actual clients and runtime inputs used for device-loss acceptance."""
from tcp_icmp_inputs import record as record_inputs
from tcp_icmp_inputs import IPV4_MODULES

SOURCES = ('Makefile', 'userspace/tests/net/tcp_device.c',
           'scripts/tcp_device/__init__.py', 'scripts/tcp_device/run.py',
           'scripts/tcp_device/native.py', 'scripts/tcp_device/guest.py',
           'scripts/tcp_device/physical.py', 'scripts/tcp_device/peer.py',
           'scripts/tcp_device/inputs.py', 'scripts/tcp_device/capture.py',
           'scripts/tests/tcp_device_capture_test.py',
           'scripts/tests/tcp_device_native_cleanup_test.py',
           'scripts/tests/tcp_device_observation_test.py',
           'scripts/tests/tcp_malformed_capture_test.py',
           'scripts/tcp_malformed/capture.py',
           'scripts/tcp_fault_native.py', 'scripts/tcp_fault_test.py',
           'scripts/tcp_fault_peer.py', 'scripts/tcp_fault_capture.py',
           'scripts/tcp_capture_clock.py', 'scripts/tcp_icmp_inputs.py',
           'scripts/tcp_icmp_capture.py', 'scripts/tcp_fixture_inputs.py',
           'scripts/tcp_native_inputs.py', 'scripts/manager_link_hardware.py',
           'scripts/qmp.py', 'scripts/normal_manager_test.py',
           'kernel/net/ipv4/core.cpp', 'kernel/net/tcp/connection.cpp',
           'kernel/include/net/tcp/connection.hpp', 'kernel/net/tcp/socket.cpp',
           'kernel/include/net/tcp/socket.hpp')
SOURCES = tuple(dict.fromkeys(SOURCES + IPV4_MODULES))


def record(linkage, affected, native=False, image=None):
    label = f'tcp-device-{affected}-' + ('linux-' if native else '') + linkage
    return record_inputs(linkage, native=native, image=image, label=label,
                         program='tcp-device', sources=SOURCES)
