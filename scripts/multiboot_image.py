#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/multiboot_image.py
# @brief   Package the native kernel as a Multiboot ELF image.
# @author  frankischilling
# @date    2026-11-21
#
# Extracts the linked kernel's loadable bytes and page permissions for the
# 32-bit bootstrap that enters its 64-bit entry point.
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

"""Build a Multiboot wrapper without changing the kernel's link addresses."""

import argparse
from pathlib import Path
import struct
import subprocess
import tempfile


ARCH = Path(__file__).resolve().parents[1] / "kernel" / "arch" / "x86_64"
KERNEL_BASE = 0xFFFFFFFF80000000
PAGE_SIZE = 4096


def kernel_layout(kernel):
    elf = kernel.read_bytes()
    if len(elf) < 64 or elf[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected a little-endian ELF64 kernel")
    kind, machine, version, _, phoff = struct.unpack_from("<HHIQQ", elf, 16)
    phsize, phnum = struct.unpack_from("<HH", elf, 54)
    program = struct.Struct("<IIQQQQQQ")
    if (kind, machine, version) != (2, 62, 1) or phsize != program.size:
        raise ValueError("expected a linked x86-64 executable")
    if not phnum or phoff > len(elf) or phnum * phsize > len(elf) - phoff:
        raise ValueError("invalid program-header table")

    segments = []
    for index in range(phnum):
        kind, flags, offset, start, _, filesz, memsz, _ = program.unpack_from(
            elf, phoff + index * phsize
        )
        if kind != 1 or not memsz:
            continue
        if (start < KERNEL_BASE or start % PAGE_SIZE or start + memsz > KERNEL_BASE + (1 << 30)
                or flags not in (4, 5, 6) or filesz > memsz
                or offset > len(elf) or filesz > len(elf) - offset):
            raise ValueError("unsupported kernel load segment")
        segments.append((start - KERNEL_BASE, memsz, flags, elf[offset:offset + filesz]))
    segments.sort()
    if not segments or segments[0][0] != 0:
        raise ValueError("missing first load segment at the kernel link base")

    payload = bytearray()
    permissions = bytearray()
    for start, memsz, flags, data in segments:
        first_page = start // PAGE_SIZE
        if first_page < len(permissions):
            raise ValueError("overlapping kernel load segments")
        permissions.extend(bytes(first_page - len(permissions)))
        permissions.extend(bytes([1 | (flags & 2) | (0 if flags & 1 else 4)])
                           * ((memsz + PAGE_SIZE - 1) // PAGE_SIZE))
        if data:
            payload.extend(bytes(start - len(payload)))
            payload.extend(data)
    return payload, permissions


def build_image(kernel, output, nasm):
    payload, permissions = kernel_layout(kernel)
    symbols = subprocess.check_output(["nm", "-P", kernel], text=True).splitlines()
    entries = [line.split()[2] for line in symbols if line.startswith("multiboot_entry T ")]
    if len(entries) != 1:
        raise ValueError("expected one multiboot_entry symbol")
    entry = int(entries[0], 16)
    offset = entry - KERNEL_BASE
    if not 0 <= offset < len(payload) or permissions[offset // PAGE_SIZE] != 1:
        raise ValueError("Multiboot entry is outside the executable kernel image")

    with tempfile.TemporaryDirectory(prefix=".multiboot-", dir=output.parent) as temporary:
        directory = Path(temporary)
        (directory / "kernel-payload.bin").write_bytes(payload)
        (directory / "kernel-flags.bin").write_bytes(permissions)
        subprocess.run([nasm, "-f", "elf32", "-o", "bootstrap.o", ARCH / "multiboot.asm"],
                       cwd=directory, check=True)
        subprocess.run(["ld", "-m", "elf_i386", "--oformat=elf32-i386", "-z", "max-page-size=0x1000",
                        f"--defsym=kernel_image_size={len(permissions) * PAGE_SIZE}",
                        f"--defsym=kernel_entry_low={entry & 0xFFFFFFFF}",
                        f"--defsym=kernel_page_count={len(permissions)}",
                        f"--defsym=kernel_directory_count={(len(permissions) + 511) // 512}",
                        "-T", ARCH / "multiboot.ld", "-o", "multiboot.elf", "bootstrap.o",
                        "-b", "binary", "kernel-flags.bin", "kernel-payload.bin"],
                       cwd=directory, check=True)
        (directory / "multiboot.elf").replace(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--nasm", default="nasm")
    args = parser.parse_args()
    try:
        build_image(args.kernel, args.output, args.nasm)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Multiboot image: {error}\n")


if __name__ == "__main__":
    main()
