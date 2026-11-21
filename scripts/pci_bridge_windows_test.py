#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/pci_bridge_windows_test.py
# @brief   Checks that PCI drivers skip endpoints with blocked bridge windows.
# @author  frankischilling
# @date    2026-11-21
#
# Changes Q35 bridge registers after firmware setup and watches for any
# attempt to map the blocked endpoint BAR before userspace starts.
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
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from fetch import ROOT
from network_test import fixture


DEBUG_SCRIPT = r'''
import gdb
import re

def config(bus, slot, offset, read_width='w', value=None):
    selector = 0x80000000 | bus << 16 | slot << 11 | offset
    gdb.execute(f"monitor o /w 0xcf8 {selector:#x}")
    if value is not None:
        gdb.execute(f"monitor o /{read_width} 0xcfc {value:#x}")
    report = gdb.execute(f"monitor i /{read_width} 0xcfc", to_string=True)
    return int(re.search(r"= (0x[0-9a-f]+)", report).group(1), 16)

outer = config(0, 6, 0x18)
inner_bus = (outer >> 8) & 0xff
inner = config(inner_bus, 0, 0x18)
endpoint_bus = (inner >> 8) & 0xff
assert 0 < inner_bus < endpoint_bus <= ((outer >> 16) & 0xff)
assert config(endpoint_bus, 5, 0) == 0x100e8086
bar = config(endpoint_bus, 5, 0x10)
assert bar != 0 and not (bar & 15)

if fault == "command":
    target = (0, 6, 4, "h")
    before = config(*target)
    assert before & 2
    changed = before & ~2
else:
    target = (inner_bus, 0, 0x20, "w")
    before = config(*target)
    base = (before & 0xfff0) << 16
    limit = (before & 0xfff00000) | 0xfffff
    assert base <= bar <= limit < 0xffefffff
    changed = before & 0xffff0000 | ((limit + 1) >> 16)
assert config(*target, value=changed) == changed
print(f"BRIDGE_REGISTER_CHANGED before={before:#x} after={changed:#x} bar={bar:#x}")

blocked = gdb.Breakpoint("ax::map_mmio", type=gdb.BP_HARDWARE_BREAKPOINT)
blocked.condition = f"$rdi == {bar:#x}"
userspace = gdb.Breakpoint("ax::start_init", type=gdb.BP_HARDWARE_BREAKPOINT)
gdb.execute("continue")
assert blocked.hit_count == 0, f"kernel tried to map blocked BAR {bar:#x}"
assert userspace.hit_count == 1
assert config(*target) == changed
assert config(endpoint_bus, 5, 0x10) == bar
print(f"BRIDGE_BAR_UNMAPPED bus={endpoint_bus} bar={bar:#x}")
'''


def run(firmware, fault, image, output):
    with tempfile.TemporaryDirectory(prefix='axiom-pci-') as directory:
        endpoint = Path(directory) / 'gdb'
        script = output / 'observe.gdb'
        script.write_text(f'''set pagination off
set confirm off
file {ROOT / 'build/axiom64.elf'}
target remote {endpoint}
hbreak ax::firmware_configure_pci_interrupts
continue
delete 1
python
fault = {fault!r}
{DEBUG_SCRIPT}
end
delete
detach
''')
        serial = output / 'serial.log'
        command = ['qemu-system-x86_64', '-machine', 'q35', '-m', '2G',
                   '-cdrom', str(image), '-nic', 'none', '-display', 'none', '-monitor', 'none',
                   '-serial', f'file:{serial}', '-no-reboot', '-S',
                   '-chardev', f'socket,id=debug,path={endpoint},server=on,wait=off',
                   '-gdb', 'chardev:debug', '-device', 'isa-debug-exit,iobase=0xf4,iosize=4',
                   '-device', 'pcie-root-port,id=upstream,bus=pcie.0,addr=6,slot=6',
                   '-device', 'pcie-pci-bridge,id=legacy,bus=upstream,addr=0',
                   '-netdev', 'user,id=virtio,restrict=on',
                   '-device', 'virtio-net-pci,netdev=virtio,addr=4,disable-legacy=on',
                   '-netdev', 'user,id=intel,restrict=on',
                   '-device', 'e1000,netdev=intel,bus=legacy,addr=5']
        if firmware == 'uefi':
            variables = output / 'OVMF_VARS.fd'
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                        '-drive', f'if=pflash,format=raw,file={variables}']
        with (output / 'qemu.log').open('wb') as qemu_log:
            process = subprocess.Popen(command, stdout=qemu_log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 5
                while not endpoint.is_socket():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(f'QEMU debugger socket unavailable. See {output}')
                    time.sleep(.02)
                with (output / 'gdb.log').open('wb') as debugger:
                    subprocess.run(['gdb', '-q', '-batch', '-x', str(script)],
                                   stdout=debugger, stderr=subprocess.STDOUT, check=True, timeout=75)
                status = process.wait(timeout=30)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        debug = (output / 'gdb.log').read_text(errors='replace')
        trace = serial.read_text(errors='replace')
        match = re.search(r'^BRIDGE_BAR_UNMAPPED bus=(\d+) bar=', debug, re.M)
        markers = ('BRIDGE_REGISTER_CHANGED', 'BRIDGE_BAR_UNMAPPED')
        if not match or any(debug.count(marker) != 1 for marker in markers):
            raise RuntimeError(f'Missing bridge register or mapping observation. See {output}')
        expected = f'PCI BAR: bridge window rejects segment=0 bus={match[1]} slot=5 function=0 BAR=0'
        required = (expected, 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0')
        lines = trace.splitlines()
        if status != 1 or any(lines.count(line) != 1 for line in required) or 'e1000: index=' in trace:
            raise RuntimeError(f'Bridge rejection was not verified. See {output}')
        print(f'PCI_BRIDGE_GUEST_PASS firmware={firmware} fault={fault}', flush=True)


def main():
    output = ROOT / 'build/pci-bridge-windows'
    output.mkdir(exist_ok=True)
    fixture(program='udp-tests', script='userspace/tests/net/pci_bridge_windows.sh')
    for firmware in ('bios', 'uefi'):
        image = ROOT / f'build/pci-bridge-{firmware}.iso'
        command = [sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                   '--output-name', image.name]
        # Observe discovery with and without the ACPI interrupt-routing pass.
        if firmware == 'uefi':
            command += ['--kernel-option', 'irq=pic']
        subprocess.run(command, cwd=ROOT, check=True)
        for fault in ('command', 'window'):
            case = output / f'{firmware}-{fault}'
            case.mkdir(exist_ok=True)
            run(firmware, fault, image, case)


if __name__ == '__main__':
    main()
