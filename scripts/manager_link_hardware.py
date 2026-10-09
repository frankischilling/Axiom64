# SPDX-License-Identifier: GPL-3.0-or-later
"""Control emulator link state and prove physical PCI removal through I/O."""
import socket
import time
from dhcp_peer import check


class Hardware:
    def __init__(self, monitor, path, affected, transport):
        self.monitor, self.affected, self.transport = monitor, affected, transport
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(5)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile('rwb')
        self.records = []

    def io(self, request):
        # No clock manipulation is part of this fixture.
        check(request.startswith(('outl ', 'inl ')), 'only hardware port I/O is permitted')
        self.stream.write(request.encode() + b'\n')
        self.stream.flush()
        response = self.stream.readline().decode().strip()
        check(response.startswith('OK'), 'QTest port request completed')
        self.records.append(dict(request=request, response=response))
        return response

    def expected(self, lane):
        return 0x100e8086 if lane else 0x10411af4 if self.transport == 'modern' else 0x10001af4

    def identity(self, lane):
        self.io(f'outl 0xcf8 {0x80000000 | ((lane + 4) << 11):#x}')
        response = self.io('inl 0xcfc').split()
        check(len(response) == 2, 'complete vendor/device port response')
        return int(response[1], 0)

    def carrier(self, up):
        self.monitor.command('set_link', dict(name=f'nic{self.affected}', up=up))
        self.records.append(dict(operation='carrier', up=up, lane=self.affected,
                                 host_monotonic=time.monotonic()))

    def remove(self):
        # CF8 is shared with the guest's PCI access; stop it for this short I/O
        # sequence and resume it afterward. Its clock is never advanced by us.
        self.monitor.command('stop')
        try:
            before = [self.identity(lane) for lane in (0, 1)]
            check(before == [self.expected(lane) for lane in (0, 1)],
                  'both real PCI identities match the configured adapters')
            self.monitor.command('device_del', dict(id=f'nic{self.affected}'))
            pending = self.identity(self.affected)
            check(pending == before[self.affected], 'unacknowledged PCI deletion remains pending')
            self.io('outl 0xae0c 0')
            self.io(f'outl 0xae08 {1 << (self.affected + 4):#x}')
            after = [self.identity(lane) for lane in (0, 1)]
            check(after[self.affected] == 0xffffffff and
                  after[1 - self.affected] == before[1 - self.affected],
                  'only the selected physical PCI adapter disappears')
            pci = self.monitor.command('query-pci')
            slots = [device['slot'] for bus in pci for device in bus['devices']]
            check(self.affected + 4 not in slots and 5 - self.affected in slots,
                  'QMP enumeration confirms removal and the healthy adapter remains')
            self.records.append(dict(operation='remove', lane=self.affected, before=before,
                                     pending=pending, after=after, pci=pci,
                                     host_monotonic=time.monotonic()))
        finally:
            self.monitor.command('cont')

    def close(self):
        self.stream.close()
        self.socket.close()
