#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/nvme_reset_test.py
# @brief   Verify recovery after disabling a live NVMe controller in QEMU.
# @author  frankischilling
# @date    2026-11-21
#
# Pauses one sector read and disables the emulated controller through qtest.
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

"""Force a controller disable during the NVMe guest data check."""
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import time

from fetch import ROOT
from nvme_test import DATA_PASS, SECTOR, SECTORS, digest, disk, primary_disk, verify_data


def run(firmware, sockets):
    name = "pc-" + firmware
    original_case = ROOT / "build/nvme-test" / (name + "-data")
    output = ROOT / "build" / ("forced-reset-" + firmware)
    output.mkdir()
    command = json.loads((original_case / "command.json").read_text())
    assert command[0] == "qemu-system-x86_64"
    source = original_case.parent
    primary = primary_disk(output / "primary.raw")
    original = primary.read_bytes()
    other = {item: disk(output / (item + ".raw"), SECTORS * SECTOR)
             for item in ("secondary", "other", "4k", "zoned")}
    replacements = {str(source / f"{name}-primary.raw"): str(primary)}
    replacements.update({str(source / f"{name}-{item}.raw"): str(path)
                         for item, path in other.items()})
    if firmware == "uefi":
        variables = output / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        replacements[str(original_case / "VARS.fd")] = str(variables)
    for old, new in replacements.items():
        assert sum(old in arg for arg in command) == 1, old
        command = [arg.replace(old, new) for arg in command]
    socket = sockets / f"{firmware}-gdb.sock"
    qtest = sockets / f"{firmware}-qtest.sock"
    command += ["-S", "-gdb", f"unix:{socket},server=on,wait=off",
                "-qtest", f"unix:{qtest},server=on,wait=off"]
    (output / "command.json").write_text(json.dumps(command, indent=2))
    elf = ROOT / "build/axiom64.elf"
    debugger = output / "reset.gdb"
    debugger.write_text(
        "set pagination off\nset confirm off\n"
        f'file "{elf}"\ntarget remote {socket}\n'
        "hbreak *ax::nvme_transfer if $rdi == 0 && $rsi == 3131\n"
        "continue\n"
        "set $regs = 'nvme.cpp'::'ax::(anonymous namespace)::controllers'[0].registers\n"
        'printf "NVME_FORCED_RESET before=%x status=%x\\n", $regs[5], $regs[7]\n'
        "python\n"
        "import socket\n"
        "address = int(gdb.parse_and_eval('(unsigned long)($regs + 5) - ax::direct_map'))\n"
        "with socket.socket(socket.AF_UNIX) as bus:\n"
        f"    bus.connect({str(qtest)!r})\n"
        "    bus.sendall(f'writel {address:#x} 0\\n'.encode())\n"
        "    reply = bus.makefile('rb').readline()\n"
        "    if reply.strip() != b'OK':\n"
        "        raise RuntimeError(reply)\n"
        "end\n"
        'printf "NVME_FORCED_RESET after=%x status=%x\\n", $regs[5], $regs[7]\n'
        "delete 1\ndetach\n"
    )
    serial_path = output / "serial.log"
    debugger_path = output / "gdb.log"
    with serial_path.open("wb") as serial, debugger_path.open("wb") as debug:
        vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=serial,
                              stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while not socket.exists() and vm.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert socket.is_socket() and vm.poll() is None
            subprocess.run(["gdb", "-q", "-nx", "-batch", "-x", debugger],
                           stdin=subprocess.DEVNULL, stdout=debug, stderr=subprocess.STDOUT,
                           timeout=60, check=True)
            assert vm.wait(timeout=60) == 1
        finally:
            if vm.poll() is None:
                vm.terminate()
                try:
                    vm.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    vm.kill()
                    vm.wait()
    text = serial_path.read_text()
    assert text.count("nvme: controller=0 queue recovery=ready") == 1
    assert "nvme: controller=1 queue recovery=" not in text
    assert DATA_PASS in text and "AXIOM64_EXIT status=0" in text
    debug = debugger_path.read_text()
    assert "NVME_FORCED_RESET before=460001 status=1" in debug
    assert "NVME_FORCED_RESET after=0 status=0" in debug
    verify_data(primary, original, ((other["secondary"], 128), (other["other"], 256)),
                (other["4k"], other["zoned"]))
    return {"firmware": firmware, "kernel_sha256": digest(elf),
            "serial_sha256": digest(serial_path), "gdb_sha256": digest(debugger_path)}


def main():
    with TemporaryDirectory(prefix="axiom64-nvme-") as temporary:
        rows = [run(mode, Path(temporary)) for mode in ("bios", "uefi")]
    text = json.dumps(rows, indent=2)
    (ROOT / "build/nvme-reset-results.json").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
