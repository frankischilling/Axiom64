#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/legacy_ports_test.py
# @brief   Verify ISA UART and printer binding under QEMU.
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

"""Check fixed and firmware-assigned ISA UART and printer I/O in QEMU."""
import argparse
from contextlib import ExitStack, contextmanager
from itertools import product
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tempfile

from account_normal_test import write_cpio
from boot_media_test import digest
from fetch import ROOT


def exchange_serial(command, serial, debugger=None):
    deadline = time.monotonic() + 55
    with ExitStack() as stack:
        output = stack.enter_context(serial.open("wb"))
        guest = stack.enter_context(subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT))
        try:
            if debugger:
                stack.enter_context(debugger(guest))
            while b"LEGACY_UART_READY\r\n" not in serial.read_bytes():
                if guest.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"UART prompt missing, see {serial}")
                time.sleep(0.03)
            guest.communicate(b"legacy-port-input\n", timeout=max(0.1, deadline - time.monotonic()))
            return guest.returncode
        finally:
            if guest.poll() is None:
                guest.kill()


def add_firmware(command, case, firmware):
    if firmware != "uefi":
        return
    variables = case / "VARS.fd"
    shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
    command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                "-drive", f"if=pflash,format=raw,file={variables}"]


def boot(case, firmware, machine, image, uart, printer):
    port = case / "printer.bin"
    serial = case / "serial.log"
    command = ["qemu-system-x86_64", "-machine", machine, "-cpu", "max", "-m", "256M",
               "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
               "-serial", "stdio" if uart else "none",
               "-parallel", f"file:{port}" if printer else "none",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=4", "-cdrom", image]
    add_firmware(command, case, firmware)
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


@contextmanager
def attach_fixture(guest, socket, script, transcript):
    deadline = time.monotonic() + 5
    while not socket.is_socket():
        if guest.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError("QEMU GDB socket did not become available")
        time.sleep(0.01)
    with transcript.open("wb") as log, subprocess.Popen(
            ["gdb", "-q", "-batch", "-x", script], stdout=log, stderr=subprocess.STDOUT) as debugger:
        try:
            yield
        finally:
            if debugger.poll() is None:
                debugger.terminate()


def check_configuration(observations, scenario):
    inactive = scenario in ("activate", "range-conflict", "probe-failure")
    success = scenario == "activate"
    stored = scenario == "probe-failure"
    checks = [0, 1] if inactive else [0, 0]
    original = [0x3e8, 0x3bc]
    ports = [0x2f8, 0x278]
    original_irq = [3, 5]
    writes, reads = [], []
    if inactive:
        for function, (base, width, saved) in enumerate(zip(ports, (8, 3), checks)):
            for mode, value in ((saved, 0xff), (3, 0x55), (2, 0xaa), (saved, 0xff)):
                if mode == 2 and scenario == "range-conflict":
                    reads.append([function, base + width - 1, mode, 0xff])
                    break
                reads.extend([function, port, mode, value] for port in reversed(range(base, base + width)))
            writes.extend([function, register, value] for register, value in (
                (0x60, base >> 8), (0x61, base & 255), (0x31, 3), (0x31, 2), (0x31, saved)))
            if success or stored:
                writes.extend(([function, 0x70, 0], [function, 0x30, 1]))
            if stored:
                writes.extend(([function, 0x30, 0], [function, 0x70, original_irq[function]]))
            if not success:
                writes.extend(([function, 0x60, original[function] >> 8],
                               [function, 0x61, original[function] & 255]))
    expected = {
        "serial_reads": 288, "resource_bytes": 28 if inactive else 22, "card_numbers": [1],
        "logical_devices": [0, 1, 0, 1] if inactive else ([] if scenario == "bad-checksum" else [0, 1]),
        "card_number_resets": 1, "programming": writes, "range_reads": reads,
        "bases": original if inactive and not success else ports,
        "active": [success or not inactive] * 2,
        "checks": checks, "irq": [0, 0] if success else original_irq,
    }
    if observations != expected:
        fields = [field for field, value in expected.items() if observations.get(field) != value]
        raise RuntimeError(f"{scenario}: unexpected configuration fields: {fields}")


def boot_pnp(case, firmware, machine, image, kernel, scenario):
    port = case / "printer.bin"
    serial = case / "serial.log"
    receipt = case / "config.json"
    script = case / "fixture.gdb"
    fixture = ROOT / "scripts/isa_pnp_fixture.py"
    symbols = subprocess.check_output(["nm", "-C", kernel], text=True).splitlines()
    callbacks = []
    for name in ("pnp_port_read", "pnp_port_write"):
        matches = [row.split()[0] for row in symbols if f"::{name}(" in row]
        if len(matches) != 1:
            raise RuntimeError(f"one guest callback required: {name}")
        callbacks.append(matches[0])
    with tempfile.TemporaryDirectory(prefix="axiom64-pnp-gdb-") as temporary:
        socket = Path(temporary) / "gdb.sock"
        script.write_text(f'''
set pagination off
set confirm off
target remote {socket}
python
exec(compile(open({str(fixture)!r}, "rb").read(), {str(fixture)!r}, "exec"))
bus = ConfigBus({str(receipt)!r}, {scenario!r})
end
hbreak *0x{callbacks[0]}
commands
silent
python port_transfer(bus, True)
continue
end
hbreak *0x{callbacks[1]}
commands
silent
python port_transfer(bus, False)
continue
end
continue
''', encoding="utf-8")
        command = ["qemu-system-x86_64", "-machine", machine, "-cpu", "max", "-m", "256M",
                   "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
                   "-serial", "none", "-parallel", "none",
                   "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
                   "-S", "-chardev", f"socket,id=debug,path={socket},server=on,wait=off",
                   "-gdb", "chardev:debug", "-cdrom", image]
        if scenario == "probe-failure":
            port.touch()
        else:
            command += ["-chardev", "stdio,id=uart,signal=off",
                        "-device", "isa-serial,chardev=uart,index=1,iobase=0x2f8,irq=3",
                        "-chardev", f"file,id=printer,path={port}",
                        "-device", "isa-parallel,chardev=printer,index=1,iobase=0x278,irq=5"]
        add_firmware(command, case, firmware)
        (case / "command.json").write_text(json.dumps(command, default=str, indent=2) + "\n")
        valid = scenario in ("active", "activate")
        if valid:
            status = exchange_serial(command, serial,
                                     lambda guest: attach_fixture(guest, socket, script, case / "gdb.log"))
        else:
            with serial.open("wb") as output, subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT) as guest:
                try:
                    with attach_fixture(guest, socket, script, case / "gdb.log"):
                        status = guest.wait(timeout=55)
                finally:
                    if guest.poll() is None:
                        guest.kill()
    log = serial.read_bytes()
    if valid:
        for marker in (b"ISA PnP: 1 cards, 0 malformed, UART=2f8 printer=278",
                       b"ISA: parallel printer at 0x278", b"LEGACY_UART_PAYLOAD",
                       b"LEGACY_PORTS_PASS uart=1 printer=1", b"AXIOM64_EXIT status=0"):
            if marker + b"\r\n" not in log:
                raise RuntimeError(f"{case.name}: missing {marker!r}, see {serial}")
        activated = b"ISA PnP: 2 devices activated for polling\r\n" in log
        if activated != (scenario == "activate"):
            raise RuntimeError(f"{case.name}: incorrect activation marker, see {serial}")
    elif b"LEGACY_UART_PAYLOAD" in log:
        raise RuntimeError(f"{case.name}: invalid resources bound a UART")
    expected = b"A\0\xff\n\r\x7fB" if valid else b""
    if status != 1 or port.read_bytes() != expected:
        raise RuntimeError(f"{case.name}: device transfer failed, see {serial}")
    observations = json.loads(receipt.read_text())
    check_configuration(observations, scenario)
    return {"case": case.name, "iso_sha256": digest(image), "serial_sha256": digest(serial),
            "printer_sha256": digest(port), "config_sha256": digest(receipt), "exit": status}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/legacy-ports")
    parser.add_argument("--pnp-only", action="store_true", help="run just the alternate-port fixture")
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
        if args.pnp_only and uart != printer:
            continue
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
    for firmware, (board, machine) in product(
            ("bios", "uefi"), (("i440fx-tsc", "pc,hpet=off"), ("q35-hpet", "q35"))):
        if not args.pnp_only:
            for (uart, printer), image in images.items():
                case = output / f"{firmware}-{board}-{image.stem}"
                case.mkdir()
                cases.append(boot(case, firmware, machine, image, uart, printer))
                print(f"{case.name}: passed", flush=True)
        for scenario in ("active", "bad-checksum", "activate", "range-conflict", "probe-failure"):
            valid = scenario in ("active", "activate")
            suffix = "pnp" if scenario == "active" else f"pnp-{scenario}"
            case = output / f"{firmware}-{board}-{suffix}"
            case.mkdir()
            cases.append(boot_pnp(case, firmware, machine, images[valid, valid], kernel, scenario))
            print(f"{case.name}: passed", flush=True)
    (output / "results.json").write_text(json.dumps(
        {"kernel_sha256": digest(kernel), "cases": cases}, indent=2) + "\n")


if __name__ == "__main__":
    main()
