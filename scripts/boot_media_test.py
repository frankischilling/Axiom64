#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/boot_media_test.py
# @brief   Verify secondary boot media in QEMU.
# @author  frankischilling
# @date    2026-11-21
#
# Checks the boot payload, firmware handoff, Ring 3 execution, and invalid root arguments.
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

"""Boot disk, PXE, and optical media with the same kernel and Ring 3 probe."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

from account_normal_test import write_cpio
from boot_media import ESP_START, SECTOR, build_medium
from fetch import ROOT


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inspect_disk(directory, image, kernel, initramfs):
    subprocess.run(["sfdisk", "--verify", image], check=True)
    for name, source in (("axiom64.elf", kernel), ("rootfs.cpio", initramfs)):
        copy = directory / f"disk-{name}"
        subprocess.run(["mcopy", "-i", f"{image}@@{ESP_START * SECTOR}", f"::/boot/{name}", copy], check=True)
        if digest(copy) != digest(source):
            raise RuntimeError(f"disk readback differs: {name}")


def run_guest(directory, kind, firmware, medium, marker, module_bytes, *, invalid=False):
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "256M",
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=4"]
    if firmware == "uefi":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    if kind == "disk":
        command += ["-nic", "none", "-boot", "order=c,strict=on",
                    "-drive", f"file={medium},format=raw,if=ide,snapshot=on"]
    elif kind == "pxe":
        loader = "limine-bios-pxe.bin" if firmware == "bios" else "BOOTX64.EFI"
        command += ["-boot", "order=n,strict=on", "-device", "e1000,netdev=pxe",
                    "-netdev", f"user,id=pxe,restrict=on,tftp={medium},bootfile={loader}",
                    "-object", f"filter-dump,id=capture,netdev=pxe,file={directory / 'pxe.pcap'}"]
    else:
        command += ["-nic", "none", "-boot", "order=d,strict=on", "-cdrom", medium]
    log = directory / "serial.log"
    with log.open("wb") as output:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.STDOUT, timeout=90)
    text = log.read_text(errors="replace")
    lines = set(text.splitlines())
    expected = {f"Firmware: {firmware.upper()}", marker, f"AXIOM64_EXIT status={int(invalid)}",
                f"Boot modules: count=1 initramfs_bytes={module_bytes}"}
    entered = "Entering userspace in Ring 3" in lines
    if (result.returncode != (3 if invalid else 1) or not expected <= lines or entered == invalid or
            any(token in text for token in ("PANIC:", "FAULT pid=", "FILESYSTEM_SHUTDOWN_FAIL"))):
        raise RuntimeError(f"unexpected guest result in {log}: " + "\n".join(text.splitlines()[-15:]))
    return {"medium": kind, "firmware": firmware, "invalid": invalid, "serial_sha256": digest(log)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/boot-media-test")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    kernel = ROOT / "build/axiom64.elf"
    init = output / "init"
    subprocess.run(["musl-gcc", "-static", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/fs/boot-media.c", "-o", init], check=True)
    token = secrets.token_hex(16)
    initramfs = output / "rootfs.cpio"
    init_payload = init.read_bytes()
    alternate = "/sbin/media-init"
    write_cpio(initramfs, {"dev": (0o40755, b""), "proc": (0o40755, b""), "sbin": (0o40755, b""),
                         "sbin/init": (0o100755, init_payload), alternate.lstrip("/"): (0o100755, init_payload),
                         "boot-proof": (0o100444, token.encode())})
    disk, pxe, iso = (output / name for name in ("boot.raw", "pxe", "boot-media.iso"))
    for kind, medium in (("disk", disk), ("pxe", pxe)):
        command = [sys.executable, ROOT / "scripts/boot_media.py", kind, medium, "--kernel", kernel,
                   "--initramfs", initramfs, "--init-path", alternate, "--kernel-option", "test"]
        subprocess.run(command, check=True)
        original = medium if kind == "disk" else medium / "limine.conf"
        before = digest(original)
        duplicate = subprocess.run(command, capture_output=True, text=True)
        if duplicate.returncode != 2 or "output already exists" not in duplicate.stderr or digest(original) != before:
            raise RuntimeError(f"{kind} builder failed to preserve an existing output")
    inspect_disk(output, disk, kernel, initramfs)
    if digest(pxe / "boot/axiom64.elf") != digest(kernel):
        raise RuntimeError("PXE kernel differs from the original")
    with gzip.open(pxe / "boot/rootfs.cpio.gz", "rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest(initramfs):
            raise RuntimeError("PXE initramfs differs after decompression")
    subprocess.run([sys.executable, ROOT / "scripts/image.py", "--test", "--initramfs", initramfs,
                    "--output-directory", output, "--output-name", iso.name], cwd=ROOT, check=True)
    bad_disk = output / "invalid-root.raw"
    build_medium("disk", bad_disk, kernel, initramfs, " test root=ramfs rootflags=ro")
    bad_pxe = output / "invalid-pxe"
    build_medium("pxe", bad_pxe, kernel, initramfs, " test init=/sbin/other", init=alternate)
    cases = (("disk", disk, f"BOOT_MEDIA_PASS {alternate} {token}", False),
             ("pxe", pxe, f"BOOT_MEDIA_PASS {alternate} {token}", False),
             ("iso", iso, f"BOOT_MEDIA_PASS /sbin/init {token}", False),
             ("disk", bad_disk, "BOOT_ROOT_FAIL stage=configuration errno=22", True),
             ("pxe", bad_pxe, "BOOT_INIT_FAIL stage=configuration errno=22", True))
    results = []
    for firmware in ("bios", "uefi"):
        for kind, medium, marker, invalid in cases:
            case = output / f"{firmware}-{kind}{'-invalid' if invalid else ''}"
            case.mkdir()
            results.append(run_guest(case, kind, firmware, medium, marker, initramfs.stat().st_size, invalid=invalid))
            print(f"{case.name}: passed", flush=True)
    (output / "results.json").write_text(json.dumps({"kernel_sha256": digest(kernel),
        "initramfs_sha256": digest(initramfs), "boots": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
