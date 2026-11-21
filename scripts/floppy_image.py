#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/floppy_image.py
# @brief   Package a BIOS-bootable Axiom64 floppy image.
# @author  frankischilling
# @date    2026-11-21
#
# Embeds an installed GRUB BIOS loader and stores the compressed kernel and
# early filesystem in a FAT12 partition on a new 1,474,560-byte image.
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

"""Create a 1,474,560-byte BIOS floppy image with a Multiboot 2 payload."""

import argparse
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

from boot_assets import init_path
from boot_media import SECTOR
from disk_root import bootstrap
from fetch import ROOT


GRUB_PC = Path("/usr/lib/grub/i386-pc")
SECTORS = 2880
MBR_BOOT_CODE_SIZE = 440


def compress(source, destination, limit):
    encoder = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    with source.open("rb") as original, destination.open("xb") as output:
        for block in iter(lambda: original.read(64 * 1024), b""):
            output.write(encoder.compress(block))
            if output.tell() > limit:
                raise ValueError(f"{source.name} does not fit on the floppy")
        output.write(encoder.flush())
        if output.tell() > limit:
            raise ValueError(f"{source.name} does not fit on the floppy")
        return output.tell()


def boot_code(work, arguments):
    config = work / "embedded.cfg"
    tokens = " ".join(f"'{arg}'" for arg in arguments)
    config.write_text(
        "serial --unit=0 --speed=115200\n"
        "terminal_output serial\n"
        "set root=(fd0,msdos1)\n"
        f"multiboot2 /kernel.gz {tokens}\n"
        "module2 /rootfs.gz\n"
        "boot\n",
        encoding="ascii",
    )
    core_path = work / "core.img"
    subprocess.run(["grub-mkimage", "-d", GRUB_PC, "-O", "i386-pc", "-o", core_path,
                    "-c", config, "-p", "(fd0,msdos1)/boot/grub", "biosdisk", "part_msdos",
                    "fat", "gzio", "multiboot2", "boot", "serial", "terminal"], check=True)
    mbr = (GRUB_PC / "boot.img").read_bytes()
    core = core_path.read_bytes()
    core_sectors = (len(core) + SECTOR - 1) // SECTOR
    # The uninstalled GRUB MBR points to sector 1. grub-mkimage fills in
    # diskboot's default extent at the end of that sector for a contiguous core.
    if (len(mbr) != SECTOR or mbr[510:] != b"\x55\xaa"
            or struct.unpack_from("<QB", mbr, 0x5C) != (1, 0xFF)
            or core_sectors < 2 or struct.unpack_from("<QHH", core, 500)
            != (2, core_sectors - 1, 0x820)):
        raise ValueError("unsupported GRUB BIOS boot image layout")
    return mbr[:MBR_BOOT_CODE_SIZE], core, core_sectors


def build_floppy(output, kernel, initramfs, arguments):
    if os.path.lexists(output):
        raise FileExistsError(output)
    for argument in arguments:
        if not argument or any(not 0x21 <= ord(char) <= 0x7E or char == "'" for char in argument):
            raise ValueError("kernel options must be printable ASCII tokens without spaces or quotes")
    subprocess.run(["grub-file", "--is-x86-multiboot2", kernel], check=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".floppy-", dir=output.parent) as temporary:
        work = Path(temporary)
        if initramfs is None:
            initramfs = work / "bootstrap.cpio"
            bootstrap(initramfs)
        with initramfs.open("rb") as stream:
            if stream.read(6) not in (b"070701", b"070702"):
                raise ValueError("expected an uncompressed newc initramfs")

        mbr, core, core_sectors = boot_code(work, arguments)
        partition_start = ((1 + core_sectors + 17) // 18) * 18
        limit = (SECTORS - partition_start) * SECTOR
        if limit <= 0:
            raise ValueError("GRUB BIOS core does not fit on the floppy")
        kernel_file, root_file = work / "kernel.gz", work / "rootfs.gz"
        kernel_size = compress(kernel, kernel_file, limit)
        compress(initramfs, root_file, limit - kernel_size)

        image = work / "axiom64.raw"
        with image.open("xb") as stream:
            stream.truncate(SECTORS * SECTOR)
        layout = (f"label: dos\nlabel-id: 0x4158494f\nunit: sectors\n"
                  f"start={partition_start},size={SECTORS - partition_start},type=1,bootable\n")
        subprocess.run(["sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", image],
                       input=layout, text=True, check=True)
        subprocess.run(["mkfs.fat", "-F", "12", "-h", str(partition_start), "-n", "AXIOM64",
                        f"--offset={partition_start}", image], check=True)
        subprocess.run(["mcopy", "-i", f"{image}@@{partition_start * SECTOR}",
                        kernel_file, root_file, "::/"], check=True)
        with image.open("r+b") as stream:
            stream.write(mbr)
            stream.seek(SECTOR)
            stream.write(core)
        os.link(image, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new raw image path")
    parser.add_argument("--kernel", type=Path, default=ROOT / "build/axiom64-multiboot.elf")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--initramfs", type=Path, help="small uncompressed initramfs")
    source.add_argument("--root-device", help="boot a separate disk with a minimal initramfs")
    parser.add_argument("--init-path", type=init_path, default="/sbin/init")
    parser.add_argument("--kernel-option", action="append", default=[])
    args = parser.parse_args()
    arguments = [*args.kernel_option, f"init={args.init_path}"]
    if args.root_device is not None:
        if not args.root_device:
            parser.error("--root-device requires a device or disk identifier")
        arguments.append(f"root={args.root_device}")
    try:
        build_floppy(args.output, args.kernel, args.initramfs, arguments)
    except FileExistsError:
        parser.error(f"output already exists: {args.output}")
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print(f"Boot floppy: {args.output}")


if __name__ == "__main__":
    main()
