# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/guest_storage_boot.py
# @brief   Fresh QEMU boots for storage tests.
# @author  frankischilling
# @date    2026-11-20
#
# Starts an isolated firmware session each time and verifies its serial result.
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

import shutil
from signal import SIGKILL
import subprocess
import time


def boot(directory, iso, disks, firmware, transport, markers, success=True, *, hardware_readonly=False):
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "256M",
               "-boot", "order=d", "-cdrom", str(iso), "-display", "none", "-serial", "stdio",
               "-monitor", "none", "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    mode = "disable-legacy=on" if transport == "modern" else "disable-modern=on"
    access = ",readonly=on" if hardware_readonly else ""
    for index, path in enumerate(disks):
        command += ["-drive", f"if=none,id=d{index},format=raw,file={path}{access}",
                    "-device", f"virtio-blk-pci,drive=d{index},{mode},addr={5 + index}"]
    if firmware == "uefi":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    logfile = directory / (iso.stem + ".log")
    with logfile.open("wb") as log:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, timeout=70)
    output = logfile.read_text(errors="replace")
    lines = {line.strip() for line in output.splitlines()}
    expected = [f"Firmware: {firmware.upper()}", f"AXIOM64_EXIT status={int(not success)}", *markers]
    failures = ["FAULT ", "PANIC:", "FILESYSTEM_SHUTDOWN_FAIL"]
    failures.extend(["BOOT_ROOT_FAIL", "PARTITIONS_FAIL"] if success else ["VFS_ROOT_PASS", "Entering userspace"])
    if (result.returncode != (1 if success else 3) or any(line not in lines for line in expected) or
            any(token in output for token in failures)):
        raise RuntimeError(f"{logfile}:\n" + "\n".join(output.splitlines()[-35:]))
    return output


def cut_after_write_fault(directory, iso, disk, sector, marker):
    rule = directory / "home.conf"
    rule.write_text('[inject-error]\nevent = "write_aio"\niotype = "write"\n'
                    f'sector = "{sector}"\nerrno = "5"\nonce = "on"\n')
    serial = directory / "home-fault.log"
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "256M",
               "-boot", "order=d", "-cdrom", str(iso), "-display", "none", "-serial", "stdio",
               "-monitor", "none", "-no-reboot", "-nic", "none",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
               "-drive", f"if=none,id=d0,format=raw,file=blkdebug:{rule}:{disk},cache=writethrough,werror=report",
               "-device", "virtio-blk-pci,drive=d0,disable-legacy=on,addr=5"]
    with serial.open("wb") as log, subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT) as vm:
        try:
            deadline = time.monotonic() + 70
            while time.monotonic() < deadline and vm.poll() is None:
                if marker.encode() in serial.read_bytes().splitlines():
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError(f"{serial}: guest did not report the home write fault")
        finally:
            if vm.poll() is None:
                vm.kill()
                vm.wait()
        if vm.returncode != -SIGKILL:
            raise RuntimeError(f"{serial}: expected an abrupt VM stop, got {vm.returncode}")
