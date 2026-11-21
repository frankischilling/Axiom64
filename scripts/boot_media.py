#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/boot_media.py
# @brief   Build raw boot disks and network boot trees.
# @author  frankischilling
# @date    2026-11-21
#
# Packages the shared Limine payload for BIOS, UEFI, and PXE.
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

"""Package Axiom64 as a bootable raw disk or a PXE directory."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from boot_assets import copy_limine_notices, init_path, limine_files, stage_payload
from fetch import ROOT


SECTOR = 512
ALIGNMENT = 2048
ESP_START = 2 * ALIGNMENT
BIOS_TYPE = "21686148-6449-6E6F-744E-656564454649"
ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def make_disk(work, payload, limine):
    esp = work / "esp.fat"
    image = work / "boot.raw"
    payload_bytes = sum(path.stat().st_size for path in payload.rglob("*") if path.is_file())
    mib = 1024 * 1024
    esp_size = max(64, (payload_bytes + mib - 1) // mib + 8) * mib
    with esp.open("xb") as stream:
        stream.truncate(esp_size)
    subprocess.run(["mkfs.fat", "-F", "32", "-h", str(ESP_START), "-n", "AXIOM64", esp], check=True)
    subprocess.run(["mcopy", "-s", "-i", esp, payload / "boot", payload / "EFI", "::/"], check=True)
    with image.open("xb") as disk:
        disk.truncate((ESP_START + ALIGNMENT) * SECTOR + esp_size)
    layout = (f"label: gpt\nsector-size: {SECTOR}\n"
              f"start={ALIGNMENT},size={ALIGNMENT},type={BIOS_TYPE},name=BIOS\n"
              f"start={ESP_START},size={esp_size // SECTOR},type={ESP_TYPE},name=AXIOM64\n")
    subprocess.run(["sfdisk", "--quiet", image], input=layout, text=True, check=True)
    with image.open("r+b") as disk, esp.open("rb") as volume:
        disk.seek(ESP_START * SECTOR)
        shutil.copyfileobj(volume, disk)
    subprocess.run([limine / "limine", "bios-install", image, "1"], check=True)
    return image


def build_medium(kind, output, kernel, initramfs, options="", *, init="/sbin/init"):
    if os.path.lexists(output):
        raise FileExistsError(output)
    limine = limine_files()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".boot-media-", dir=output.parent) as temporary:
        work = Path(temporary)
        payload = work / "payload"
        config = stage_payload(payload, kernel, initramfs, options, init=init, compress=True)
        if kind == "disk":
            loader = payload / "boot/limine"
            efi = payload / "EFI/BOOT"
            loader.mkdir()
            efi.mkdir(parents=True)
            shutil.copy2(limine / "BOOTX64.EFI", efi)
        else:
            loader = payload
            shutil.copy2(limine / "limine-bios-pxe.bin", loader)
            shutil.copy2(limine / "BOOTX64.EFI", loader)
        shutil.copy2(limine / "limine-bios.sys", loader)
        copy_limine_notices(limine, loader)
        (loader / "limine.conf").write_text(config)
        if kind == "disk":
            os.link(make_disk(work, payload, limine), output)
        else:
            output.mkdir()
            try:
                payload.rename(output)
            except OSError:
                output.rmdir()
                raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("disk", "pxe"))
    parser.add_argument("output", type=Path, help="new raw image path or TFTP directory")
    parser.add_argument("--kernel", type=Path, default=ROOT / "build/axiom64.elf")
    parser.add_argument("--initramfs", type=Path, default=ROOT / "build/rootfs.cpio")
    parser.add_argument("--init-path", type=init_path, default="/sbin/init", help="absolute guest PID 1 path")
    parser.add_argument("--kernel-option", action="append", default=[], help="one additional boot argument")
    args = parser.parse_args()
    if any(not token or any(char.isspace() for char in token) for token in args.kernel_option):
        parser.error("--kernel-option must be a nonempty token without whitespace")
    for source in (args.kernel, args.initramfs):
        if not source.is_file():
            parser.error(f"missing boot input {source}; run make image first")
    try:
        options = "".join(f" {token}" for token in args.kernel_option)
        build_medium(args.kind, args.output, args.kernel, args.initramfs, options, init=args.init_path)
    except FileExistsError:
        parser.error(f"output already exists: {args.output}")
    print(f"Boot media: {args.output}")


if __name__ == "__main__":
    main()
