# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/isa_pnp_fixture.py
# @brief   Model ISA PnP configuration registers for the QEMU test.
# @author  frankischilling
# @date    2026-11-21
#
# Emulates configuration transfers while leaving device I/O to QEMU.
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.

"""Provide ISA PnP configuration input through GDB for two real QEMU devices."""
import json
from pathlib import Path

import gdb


KEY = bytes.fromhex('6a b5 da ed f6 fb 7d be df 6f 37 1b 0d 86 c3 61 '
                    'b0 58 2c 16 8b 45 a2 d1 e8 74 3a 9d ce e7 73 39')
SERIAL = bytes.fromhex('41 d0 80 01 01 02 03 04 c0')
PORTS = (0x2f8, 0x278)
WIDTHS = (8, 3)


def configuration_bytes(inactive, valid):
    data = bytearray()
    for kind, revision, base, width, irq in zip((5, 4), (1, 0), PORTS, WIDTHS, (3, 5)):
        data.extend((0x15, 0x41, 0xd0, kind, revision, 2 if inactive else 1))
        data.extend((0x4b, base & 255, base >> 8, width))
        if inactive:
            data.extend((0x22, 1 << irq, 0))
    data.append(0x79)
    data.append((-sum(data) % 256) ^ (0 if valid else 1))
    return bytes(data)


class ConfigBus:
    def __init__(self, output, scenario):
        self.output = Path(output)
        self.scenario = scenario
        self.inactive = scenario in ('activate', 'range-conflict', 'probe-failure')
        self.resources = configuration_bytes(self.inactive, scenario != 'bad-checksum')
        self.bases = [0x3e8, 0x3bc] if self.inactive else list(PORTS)
        self.enabled = [not self.inactive] * 2
        self.irq = [3, 5]
        self.checks = [0, 1] if self.inactive else [0, 0]
        self.programming = []
        self.check_reads = []
        self.address = 0
        self.key_bytes = 0
        self.unlocked = False
        self.isolating = False
        self.isolation_half = 0
        self.isolation_reads = 0
        self.serial_exhausted = False
        self.status_polled = False
        self.card_number = 0
        self.card_writes = []
        self.reset_count = 0
        self.offset = 0
        self.function = None
        self.function_writes = []
        self.read_port = 0

    def read(self, port):
        assert self.unlocked and self.read_port == 0x213
        if port != self.read_port:
            assert self.inactive and self.function in (0, 1)
            function = self.function
            mode = self.checks[function]
            assert PORTS[function] <= port < PORTS[function] + WIDTHS[function]
            value = 0xff
            if mode & 2 and self.bases[function] == PORTS[function]:
                value = 0x55 if mode & 1 else 0xaa
                if self.scenario == 'range-conflict' and mode == 2:
                    value = 0xff
            self.check_reads.append([function, port, mode, value])
            return value
        register = self.address
        if register == 1:
            assert self.isolation_half < 144
            index = self.isolation_half
            self.isolation_half += 1
            self.isolation_reads += 1
            if not self.isolating:
                self.serial_exhausted |= self.isolation_half == 144
                return 0xff
            if SERIAL[index // 16] & (1 << ((index // 2) % 8)):
                return 0xaa if index & 1 else 0x55
            return 0xff

        assert self.card_number == 1
        if register == 5:
            assert self.offset < len(self.resources)
            self.status_polled = True
            return 1
        if register == 4:
            assert self.status_polled
            self.status_polled = False
            value = self.resources[self.offset]
            self.offset += 1
            return value
        if register == 6:
            return self.card_number
        assert self.function in (0, 1)
        function = self.function
        base = self.bases[function]
        return {7: function, 0x30: int(self.enabled[function]), 0x31: self.checks[function],
                0x60: base >> 8, 0x61: base & 255, 0x70: self.irq[function]}[register]

    def write(self, port, value):
        if port == 0x279:
            if self.unlocked:
                self.address = value
            elif self.key_bytes or value == KEY[0]:
                assert value == KEY[self.key_bytes]
                self.key_bytes += 1
                if self.key_bytes == len(KEY):
                    self.unlocked, self.key_bytes = True, 0
            return
        assert port == 0xa79
        if not self.unlocked:
            return
        if self.address == 0:
            self.read_port = 4 * value + 3
        elif self.address == 2:
            if value == 4:
                self.reset_count += 1
                self.card_number = 0
            else:
                assert value == 2
                self.unlocked = False
                if self.serial_exhausted:
                    self.output.write_text(json.dumps({
                        'serial_reads': self.isolation_reads,
                        'resource_bytes': self.offset,
                        'card_numbers': self.card_writes,
                        'logical_devices': self.function_writes,
                        'card_number_resets': self.reset_count,
                        'programming': self.programming,
                        'range_reads': self.check_reads,
                        'bases': self.bases,
                        'active': self.enabled,
                        'checks': self.checks,
                        'irq': self.irq,
                    }) + '\n', encoding='utf-8')
        elif self.address == 3:
            assert value in (0, self.card_number)
            self.isolating = value == 0 and self.card_number == 0
            self.isolation_half = 0
        elif self.address == 6:
            assert value == 1 and self.isolating and self.isolation_half == 144
            self.card_number = value
            self.card_writes.append(value)
        elif self.address == 7:
            assert self.card_number == 1 and self.offset == len(self.resources)
            self.function = value
            self.function_writes.append(value)
        else:
            assert self.inactive and self.function in (0, 1)
            function = self.function
            self.programming.append([function, self.address, value])
            if self.address == 0x30:
                assert value in (0, 1) and not (self.checks[function] & 2)
                self.enabled[function] = bool(value)
                return
            assert not self.enabled[function]
            if self.address == 0x31:
                assert value <= 3
                self.checks[function] = value
            elif self.address == 0x60:
                self.bases[function] = (value << 8) | (self.bases[function] & 255)
            elif self.address == 0x61:
                self.bases[function] = (self.bases[function] & 0xff00) | value
            elif self.address == 0x70:
                self.irq[function] = value
            else:
                raise ValueError(f'unexpected ISA PnP register write {self.address:#x}')


def register(name):
    return int(gdb.parse_and_eval(name))


def port_transfer(bus, reading):
    # These entry breakpoints replace only the configuration-port callbacks.
    # Read the real return address before returning to the kernel's bus logic.
    port = register('$rsi') & 0xffff
    if reading:
        gdb.execute(f'set $rax = {bus.read(port)}')
    else:
        bus.write(port, register('$rdx') & 0xff)
    address = register('*(unsigned long long *)$rsp')
    gdb.execute('set $rsp = $rsp + 8')
    gdb.execute(f'set $rip = {address:#x}')
