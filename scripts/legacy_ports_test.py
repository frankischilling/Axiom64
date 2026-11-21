#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/legacy_ports_test.py
# @brief   Verify fixed ISA device binding under QEMU.
# @author  frankischilling
# @date    2026-11-21
#
# Exercises guest device nodes and verifies bytes delivered to host chardevs.
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

"""Check fixed ISA UART and LPT output in real QEMU guests."""
import argparse
from itertools import product
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from account_normal_test import write_cpio
from boot_media_test import digest
from fetch import ROOT


def exchange_serial(command, serial):
    deadline = time.monotonic() + 55
    with serial.open("wb") as output, subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT) as guest:
        try:
            while b"LEGACY_UART_READY\r\n" not in serial.read_bytes():
                if guest.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"UART prompt missing, see {serial}")
                time.sleep(0.03)
            guest.communicate(b"legacy-port-input\n", timeout=max(0.1, deadline - time.monotonic()))
            return guest.returncode
        finally:
            if guest.poll() is None:
                guest.kill()


def boot(case, firmware, machine, image, uart, printer):
    port = case / "printer.bin"
    serial = case / "serial.log"
    command = ["qemu-system-x86_64", "-machine", machine, "-cpu", "max", "-m", "256M",
               "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
               "-serial", "stdio" if uart else "none",
               "-parallel", f"file:{port}" if printer else "none",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=4", "-cdrom", image]
    if firmware == "uefi":
        variables = case / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    if uart:
        status = exchange_serial(command, serial)
        log = serial.read_bytes()
        clock = "Clock: calibrated TSC" if "hpet=off" in machine else "Clock: HPET"
        if clock.encode() not in log:
            raise RuntimeError(f"{case.name}: missing {clock!r}, see {serial}")
        for marker in (f"Firmware: {firmware.upper()}", "LEGACY_UART_PAYLOAD",
                       f"LEGACY_PORTS_PASS uart={int(uart)} printer={int(printer)}",
                       "AXIOM64_EXIT status=0"):
            if (marker + "\r\n").encode() not in log:
                raise RuntimeError(f"{case.name}: missing {marker!r}, see {serial}")
    else:
        with serial.open("wb") as output:
            status = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=55).returncode
    if status != 1:
        raise RuntimeError(f"{case.name}: guest exited {status}, see {serial}")
    if printer and port.read_bytes() != b"A\0\xff\n\r\x7fB":
        raise RuntimeError(f"{case.name}: wrong printer bytes, see {port}")
    return {"case": case.name, "iso_sha256": digest(image), "serial_sha256": digest(serial),
            "printer_sha256": digest(port) if printer else None, "exit": status}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/legacy-ports")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    kernel = ROOT / "build/axiom64.elf"
    init = output / "init"
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    subprocess.run(["musl-gcc", "-static", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/io/legacy-ports.c", "-o", init], check=True)
    images = {}
    for uart, printer in product((False, True), repeat=2):
        name = f"uart{int(uart)}-lp{int(printer)}"
        initramfs = output / f"{name}.cpio"
        image = output / f"{name}.iso"
        write_cpio(initramfs, {"dev": (0o40755, b""), "sbin": (0o40755, b""),
                               "sbin/init": (0o100755, init.read_bytes()),
                               "legacy-ports": (0o100444, f"{int(uart)}{int(printer)}".encode())})
        subprocess.run([sys.executable, ROOT / "scripts/image.py", "--test", "--initramfs",
                        initramfs, "--output-directory", output, "--output-name", image.name],
                       check=True)
        images[uart, printer] = image

    cases = []
    for firmware, (board, machine), (uart, printer) in product(
            ("bios", "uefi"), (("i440fx-tsc", "pc,hpet=off"), ("q35-hpet", "q35")), images):
        image = images[uart, printer]
        case = output / f"{firmware}-{board}-{image.stem}"
        case.mkdir()
        cases.append(boot(case, firmware, machine, image, uart, printer))
        print(f"{case.name}: passed", flush=True)
    (output / "results.json").write_text(json.dumps(
        {"kernel_sha256": digest(kernel), "cases": cases}, indent=2) + "\n")


if __name__ == "__main__":
    main()
