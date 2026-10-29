# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe native interface cycles from paired devices in a separate namespace."""
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess

from tcp_fault_native import Capture


class NativePeerLinks:
    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.client = os.open('/proc/self/ns/net', os.O_RDONLY | os.O_CLOEXEC)
        self.peer = -1
        self.features = []
        self.peer_sysctls = []
        if self.libc.unshare(0x40000000):
            raise OSError(ctypes.get_errno(), 'create private peer network namespace')
        try:
            self.peer = os.open('/proc/self/ns/net', os.O_RDONLY | os.O_CLOEXEC)
            self.command('ip', 'link', 'set', 'lo', 'up')
        finally:
            self.enter(self.client)

    @staticmethod
    def command(*arguments):
        return subprocess.check_output(list(arguments), stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    def enter(self, descriptor):
        if self.libc.setns(descriptor, 0x40000000):
            raise OSError(ctypes.get_errno(), 'select private network namespace')

    @contextmanager
    def peer_context(self):
        self.enter(self.peer)
        try:
            yield
        finally:
            self.enter(self.client)

    def disable_offloads(self, device, role):
        before = self.command('ethtool', '-k', device)
        self.command('ethtool', '-K', device, 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
        after = self.command('ethtool', '-k', device)
        for field in ('tx-checksumming', 'tcp-segmentation-offload', 'generic-segmentation-offload', 'generic-receive-offload'):
            if not any(line.strip().startswith(field + ': off') for line in after.splitlines()):
                raise ValueError('native observer requires complete software wire checksums: ' + field)
        self.features.append(dict(device=device, role=role, before=before, after=after))

    def create(self, lane, mac, directory):
        device, peer = 'eth' + str(lane), 'peer' + str(lane)
        self.command('ip', 'link', 'add', device, 'type', 'veth', 'peer', 'name', peer)
        self.disable_offloads(device, 'client')
        self.command('ip', 'link', 'set', peer, 'netns', f'/proc/{os.getpid()}/fd/{self.peer}')
        with self.peer_context():
            self.command('ip', 'link', 'set', peer, 'address', mac.hex(':'))
            path = Path('/proc/sys/net/ipv6/conf') / peer / 'disable_ipv6'
            before = path.read_text()
            path.write_text('1\n')
            self.peer_sysctls.append(dict(path=str(path), before=before, configured=path.read_text()))
            self.disable_offloads(peer, 'peer')
            self.command('ip', 'link', 'set', peer, 'up')
            channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            channel.setsockopt(263, 23, 1)  # PACKET_IGNORE_OUTGOING.
            channel.bind((peer, 0))
            channel.setblocking(False)
            capture = Capture(peer, directory / ('lane' + str(lane) + '.pcap'))
        return channel, capture

    def snapshot(self):
        with self.peer_context():
            interfaces = json.loads(self.command('ip', '-json', 'link', 'show'))
            addresses = json.loads(self.command('ip', '-json', '-4', 'address', 'show'))
        return dict(kind='veth', client_namespace_inode=os.fstat(self.client).st_ino,
                    peer_namespace_inode=os.fstat(self.peer).st_ino, interfaces=interfaces,
                    addresses=addresses, peer_sysctls=self.peer_sysctls, features=self.features)

    def close(self):
        for name in ('peer', 'client'):
            descriptor = getattr(self, name)
            if descriptor >= 0:
                os.close(descriptor)
                setattr(self, name, -1)
