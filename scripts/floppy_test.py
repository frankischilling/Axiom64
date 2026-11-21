#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/floppy_test.py
# @brief   Verify ISA floppy I/O in QEMU.
# @author  frankischilling
# @date    2026-11-21
#
# Checks write protection, sector bytes, absent devices, and ext2 across reboot.
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

"""Exercise floppy DMA through QEMU and compare the resulting disk bytes."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from account_normal_test import write_cpio
from boot_media_test import digest
from fetch import ROOT
from qmp import Qmp


SIZE = 1440 * 1024
PAYLOAD = b"FD persistence\n\0"


def disk(path, size=SIZE):
    with path.open("xb") as stream:
        stream.truncate(size)
    return path


def change_media(command, serial, replacement):
    deadline = time.monotonic() + 90
    with tempfile.TemporaryDirectory(prefix="axiom-floppy-") as temporary, serial.open("wb") as output:
        control = Path(temporary) / "qmp"
        with subprocess.Popen([*command, "-qmp", f"unix:{control},server=on,wait=off"],
                              stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT) as guest:
            try:
                while b"FLOPPY_CHANGE_READY\r\n" not in serial.read_bytes():
                    if guest.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(f"guest did not reach media-change handshake: {serial}")
                    time.sleep(0.03)
                monitor = Qmp(control)
                try:
                    drive = next(device["device"] for device in monitor.command("query-block")
                                 if device["device"] == "floppy0")
                    monitor.command("blockdev-change-medium",
                                    {"device": drive, "filename": str(replacement), "format": "raw"})
                    records = monitor.command("query-block")
                    if not any(item["device"] == drive and
                               item.get("inserted", {}).get("file") == str(replacement) for item in records):
                        raise RuntimeError("replacement floppy was not inserted")
                    (serial.parent / "block-after-change.json").write_text(json.dumps(records, indent=2))
                finally:
                    monitor.close()
                guest.communicate(b"y\n", timeout=max(0.1, deadline - time.monotonic()))
                return guest.returncode
            finally:
                if guest.poll() is None:
                    guest.kill()


def boot(directory, firmware, iso, phase, media=(), *, replacement=None):
    directory.mkdir()
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "256M",
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
               "-nic", "none", "-boot", "order=d,strict=on",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=4", "-cdrom", iso]
    for unit, (path, readonly) in enumerate(media):
        command += ["-drive", f"if=floppy,index={unit},format=raw,cache=writethrough,"
                              f"readonly={'on' if readonly else 'off'},file={path}"]
    if firmware == "uefi":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    serial = directory / "serial.log"
    if replacement is not None:
        status = change_media(command, serial, replacement)
    else:
        with serial.open("wb") as output:
            status = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=90).returncode
    text = serial.read_text(errors="replace")
    expected = {f"Firmware: {firmware.upper()}", f"FLOPPY_CHECK_PASS phase={phase}",
                "AXIOM64_EXIT status=0"}
    if status != 1 or not expected <= set(text.splitlines()):
        raise RuntimeError(f"{directory.name}: unexpected result {status}, see {serial}")
    addresses = [int(value, 16) for value in
                 re.findall(r"^floppy: fd\d sectors=2880 readonly=\d DMA=([0-9a-f]+)$",
                            text, re.MULTILINE)]
    if len(addresses) != (0 if phase == "N" else 2 if phase == "D" else 1) or any(
            address < 4096 or address + 512 > (1 << 24) or address % 4096 or
            address % 65536 + 512 > 65536 for address in addresses):
        raise RuntimeError(f"{directory.name}: invalid floppy DMA addresses {addresses}")
    print(f"{directory.name}: passed", flush=True)
    return {"name": directory.name, "serial_sha256": digest(serial), "dma_addresses": addresses}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/floppy-test")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    kernel = ROOT / "build/axiom64.elf"
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    init = output / "init"
    subprocess.run(["musl-gcc", "-std=c11", "-static", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/fs/floppy.c", "-o", init], check=True)
    images = {}
    for phase in "NDFMWR":
        cpio = output / f"{phase}.cpio"
        iso = output / f"{phase}.iso"
        write_cpio(cpio, {"dev": (0o40755, b""), "sbin": (0o40755, b""),
                         "data": (0o40755, b""), "sbin/init": (0o100755, init.read_bytes()),
                         "phase": (0o100444, phase.encode())})
        subprocess.run([sys.executable, ROOT / "scripts/image.py", "--test", "--initramfs", cpio,
                        "--output-directory", output, "--output-name", iso.name], check=True)
        images[phase] = iso
    results = []
    for firmware in ("bios", "uefi"):
        device = disk(output / f"{firmware}-write.raw")
        protected = disk(output / f"{firmware}-readonly.raw")
        with device.open("r+b") as stream:
            stream.seek(SIZE - 8)
            stream.write(b"LASTSECT")
        with protected.open("r+b") as stream:
            stream.write(b"READONLY")
        before = digest(protected)
        results.append(boot(output / f"{firmware}-absent", firmware, images["N"], "N"))
        small = disk(output / f"{firmware}-unsupported.raw", SIZE // 2)
        results.append(boot(output / f"{firmware}-unsupported", firmware, images["N"], "N",
                            ((small, False),)))
        if small.read_bytes() != bytes(SIZE // 2):
            raise RuntimeError(f"{firmware}: unsupported media changed")
        results.append(boot(output / f"{firmware}-raw", firmware, images["D"], "D",
                            ((device, False), (protected, True))))
        after = device.read_bytes()
        start = 36 * 512 - 4
        expected = bytearray(SIZE)
        expected[start:start + len(PAYLOAD)] = PAYLOAD
        expected[-8:] = b"LASTSECT"
        if after != expected or digest(protected) != before:
            raise RuntimeError(f"{firmware}: floppy data or write-protected image changed unexpectedly")

        faulted = disk(output / f"{firmware}-fault.raw")
        fault = output / "write-error.conf"
        fault.write_text('[inject-error]\nevent = "write_aio"\niotype = "write"\n'
                         'sector = "120"\nerrno = "5"\nonce = "off"\n')
        results.append(boot(output / f"{firmware}-write-error", firmware, images["F"], "F",
                            ((f"blkdebug:{fault}:{faulted}", False),)))
        expected = bytearray(SIZE)
        expected[121 * 512:121 * 512 + len(PAYLOAD)] = PAYLOAD
        if faulted.read_bytes() != expected:
            raise RuntimeError(f"{firmware}: rejected floppy write changed data")

        original = disk(output / f"{firmware}-original.raw")
        replacement = disk(output / f"{firmware}-replacement.raw")
        for path, marker in ((original, b"ORIGINAL"), (replacement, b"REPLACED")):
            with path.open("r+b") as stream:
                stream.write(marker)
        hashes = [digest(path) for path in (original, replacement)]
        results.append(boot(output / f"{firmware}-media-change", firmware, images["M"], "M",
                            ((original, False),), replacement=replacement))
        if hashes != [digest(path) for path in (original, replacement)]:
            raise RuntimeError(f"{firmware}: media change altered disk bytes")

        ext2 = disk(output / f"{firmware}-ext2.raw")
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2", "-I", "128",
                        "-O", "none,filetype,sparse_super", ext2], check=True)
        for phase in "WR":
            results.append(boot(output / f"{firmware}-ext2-{phase}", firmware, images[phase],
                                phase, ((ext2, False),)))
        subprocess.run(["e2fsck", "-fn", ext2], check=True)
        if subprocess.check_output(["debugfs", "-R", "cat /persist", ext2]) != PAYLOAD:
            raise RuntimeError(f"{firmware}: wrong ext2 file after warm boot")
    (output / "results.json").write_text(json.dumps(
        {"kernel_sha256": digest(kernel), "cases": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
