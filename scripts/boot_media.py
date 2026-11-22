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
from uuid import UUID, uuid4

from boot_assets import copy_limine_notices, init_path, limine_files, stage_payload
from disk_root import bootstrap as build_bootstrap, build as build_root_volume
from fetch import ROOT


SECTOR = 512
ALIGNMENT = 2048
ESP_START = 2 * ALIGNMENT
BIOS_TYPE = "21686148-6449-6E6F-744E-656564454649"
ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
LINUX_FS_TYPE = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"


def copy_volume(source, disk):
    # The destination is a new, zero-filled image. Preserve holes in empty volumes.
    while chunk := source.read(1024 * 1024):
        if chunk.count(0) == len(chunk):
            disk.seek(len(chunk), os.SEEK_CUR)
        else:
            disk.write(chunk)


def make_disk(work, payload, limine, root_volume=None, root_id=None, *, disk_bytes=None):
    esp = work / "esp.fat"
    image = work / "boot.raw"
    payload_bytes = sum(path.stat().st_size for path in payload.rglob("*") if path.is_file())
    mib = 1024 * 1024
    esp_size = max(64, (payload_bytes + mib - 1) // mib + 8) * mib
    with esp.open("xb") as stream:
        stream.truncate(esp_size)
    subprocess.run(["mkfs.fat", "-F", "32", "-h", str(ESP_START), "-n", "AXIOM64", esp], check=True)
    subprocess.run(["mcopy", "-s", "-i", esp, payload / "boot", payload / "EFI", "::/"], check=True)
    layout = (f"label: gpt\nsector-size: {SECTOR}\n"
              f"start={ALIGNMENT},size={ALIGNMENT},type={BIOS_TYPE},name=BIOS\n"
              f"start={ESP_START},size={esp_size // SECTOR},type={ESP_TYPE},name=AXIOM64\n")
    end = ESP_START + esp_size // SECTOR
    if root_volume is not None:
        root_start = (end + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT
        root_sectors = root_volume.stat().st_size // SECTOR
        layout += (f"start={root_start},size={root_sectors},type={LINUX_FS_TYPE},"
                   f"uuid={root_id},name=AXIOM64_ROOT\n")
        end = root_start + root_sectors
    required_bytes = (end + ALIGNMENT) * SECTOR
    if disk_bytes is not None and disk_bytes < required_bytes:
        raise ValueError(f"the partition layout needs at least {required_bytes} disk bytes")
    with image.open("xb") as disk:
        disk.truncate(disk_bytes if disk_bytes is not None else required_bytes)
    subprocess.run(["sfdisk", "--quiet", image], input=layout, text=True, check=True)
    with image.open("r+b") as disk, esp.open("rb") as volume:
        disk.seek(ESP_START * SECTOR)
        copy_volume(volume, disk)
        if root_volume is not None:
            disk.seek(root_start * SECTOR)
            with root_volume.open("rb") as root:
                copy_volume(root, disk)
    subprocess.run([limine / "limine", "bios-install", image, "1"], check=True)
    return image


def build_medium(kind, output, kernel, initramfs, options="", *, init="/sbin/init", installed=False,
                 disk_bytes=None, root_mib=None, root_partuuid=None):
    has_root = any(token.startswith(("root=", "rootfstype=")) for token in options.split())
    if installed and (kind != "disk" or has_root):
        raise ValueError("the installed disk requires its own root device and filesystem")
    if root_partuuid is not None:
        if kind != "pxe" or initramfs is not None or has_root:
            raise ValueError("PXE disk root requires its own bootstrap archive and root options")
        root_partuuid = UUID(str(root_partuuid))
    if disk_bytes is not None and (kind != "disk" or not 0 < disk_bytes < (1 << 63) or
                                   disk_bytes % SECTOR):
        raise ValueError("disk bytes require a disk image and a positive multiple of 512")
    if root_mib is not None and (not installed or root_mib <= 0):
        raise ValueError("root MiB require an installed disk and a positive size")
    root_bytes = root_mib * 1024 * 1024 if root_mib is not None else None
    if root_bytes is not None and disk_bytes is not None and root_bytes >= disk_bytes:
        raise ValueError("the root partition must fit alongside the boot partitions")
    if os.path.lexists(output):
        raise FileExistsError(output)
    limine = limine_files()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".boot-media-", dir=output.parent) as temporary:
        work = Path(temporary)
        payload = work / "payload"
        root_volume = None
        root_id = None
        if installed or root_partuuid is not None:
            root_id = uuid4() if installed else root_partuuid
            bootstrap = work / "bootstrap.cpio"
            if installed:
                root_volume = work / "root.ext2"
                build_root_volume(source=initramfs, destination=root_volume, bootstrap_destination=bootstrap,
                                  capacity_bytes=root_bytes)
            else:
                build_bootstrap(bootstrap)
            initramfs = bootstrap
            options += f" root=PARTUUID={root_id} rootfstype=ext2"
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
            os.link(make_disk(work, payload, limine, root_volume, root_id, disk_bytes=disk_bytes), output)
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
    parser.add_argument("--initramfs", type=Path,
                        help="guest archive to boot, or to install when using --installed")
    parser.add_argument("--installed", action="store_true",
                        help="populate a writable ext2 system partition on a new raw disk image")
    parser.add_argument("--disk-bytes", type=int, help="exact capacity of the raw disk image in bytes")
    parser.add_argument("--root-mib", type=int, help="capacity of the installed ext2 root in MiB")
    parser.add_argument("--root-partuuid", type=UUID, help="PXE boot to an existing ext2 root with this GPT ID")
    parser.add_argument("--init-path", type=init_path, default="/sbin/init", help="absolute guest PID 1 path")
    parser.add_argument("--kernel-option", action="append", default=[], help="one additional boot argument")
    args = parser.parse_args()
    if any(not token or any(char.isspace() for char in token) for token in args.kernel_option):
        parser.error("--kernel-option must be a nonempty token without whitespace")
    if args.initramfs is None and args.root_partuuid is None:
        args.initramfs = ROOT / "build/rootfs.cpio"
    for source in (args.kernel, args.initramfs):
        if source is not None and not source.is_file():
            parser.error(f"missing boot input {source}; run make image first")
    try:
        options = "".join(f" {token}" for token in args.kernel_option)
        build_medium(args.kind, args.output, args.kernel, args.initramfs, options,
                     init=args.init_path, installed=args.installed,
                     disk_bytes=args.disk_bytes, root_mib=args.root_mib, root_partuuid=args.root_partuuid)
    except FileExistsError:
        parser.error(f"output already exists: {args.output}")
    except ValueError as error:
        parser.error(str(error))
    print(f"Boot media: {args.output}")


if __name__ == "__main__":
    main()
