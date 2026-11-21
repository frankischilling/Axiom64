#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/partition_test.py
# @brief   Test partition decoding and ext2 persistence.
# @author  frankischilling
# @date    2026-11-20
#
# Creates disposable disk tables and checks production I/O in QEMU.
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

"""Check partition decoding and persistence on disposable virtio disks."""
import argparse
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib

from disk_root import bootstrap, populate
from fetch import ROOT
from guest_storage_boot import boot

SECTOR = 512
SECTORS = 72000
ROOT_START, DATA_START, FS_SECTORS = 2048, 36000, 32768
RAW_START, RAW_SECTORS = 69000, 1000
ROOT_ID = "01234567-89ab-cdef-0123-456789abcdef"
ROOT_LABEL = "root-☃"
PAYLOAD = b"Axiom64 partition persistence\n\0"


def mbr(entries, signature=0x13572468):
    sector = bytearray(SECTOR)
    struct.pack_into("<I", sector, 440, signature)
    for number, kind, start, length in entries:
        struct.pack_into("<B3xII", sector, 446 + (number - 1) * 16 + 4, kind, start, length)
    sector[510:] = b"\x55\xaa"
    return bytes(sector)


def gpt(overlap=False, overflow=False):
    entries = bytearray(128 * 128)
    for number, start, length, name, identifier in (
        (1, ROOT_START, FS_SECTORS, ROOT_LABEL, ROOT_ID),
        (17, ROOT_START if overlap else DATA_START, FS_SECTORS, "data", str(uuid.UUID(int=17))),
        (3, RAW_START, RAW_SECTORS, "", str(uuid.UUID(int=3))),
    ):
        index = (number - 1) * 128
        end = (1 << 64) - 1 if overflow and number == 3 else start + length - 1
        struct.pack_into("<16s16sQQQ72s", entries, index,
                         uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le,
                         uuid.UUID(identifier).bytes_le, start, end, 0, name.encode("utf-16le"))
    result = {0: mbr([(1, 0xEE, 1, SECTORS - 1)], signature=0)}
    last = SECTORS - 1
    for here, other, array in [(1, last, 2), (last, 1, last - 32)]:
        header = bytearray(SECTOR)
        struct.pack_into("<8s4I4Q16sQ3I", header, 0, b"EFI PART", 0x10000, 92, 0, 0,
                         here, other, 34, last - 33, uuid.UUID(int=1).bytes_le,
                         array, 128, 128, zlib.crc32(entries))
        struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
        result[here] = header
        result[array] = entries
    return result


def bsd(relative, damaged=False):
    label = bytearray(SECTOR)
    at = 64
    struct.pack_into("<I", label, at, 0x82564557)
    struct.pack_into("<I", label, at + 40, SECTOR)
    struct.pack_into("<IHH", label, at + 132, 0x82564557, 0, 3)
    struct.pack_into("<IIIB", label, at + 148, FS_SECTORS, 2 if relative else ROOT_START, 0, 7)
    struct.pack_into("<II", label, at + 148 + 32, FS_SECTORS + 2, 0)
    checksum = 0
    for word, in struct.iter_unpack("<H", label[at:at + 148 + 48]):
        checksum ^= word
    struct.pack_into("<H", label, at + 136, checksum ^ int(damaged))
    return label


MBR_COMMON = [(2, 0x83, DATA_START, FS_SECTORS), (3, 0x83, RAW_START, RAW_SECTORS)]
MBR_EXTENDED = mbr([(1, 0x0F, ROOT_START - 1, FS_SECTORS + 1), *MBR_COMMON])
BSD_PARENT = mbr([(1, 0xA5, ROOT_START - 2, FS_SECTORS + 2), *MBR_COMMON])
BSD_NESTED = {0: BSD_PARENT, ROOT_START - 1: bsd(True)}
DOS = {0: MBR_EXTENDED, ROOT_START - 1: mbr([(1, 0x83, 1, FS_SECTORS)], signature=0)}


def drive(path, metadata, files=()):
    with path.open("wb") as output:
        output.truncate(SECTORS * SECTOR)
        for sector, content in [*metadata.items(), *files]:
            output.seek(sector * SECTOR)
            output.write(content)


def native(directory):
    binary = directory / "partition-native"
    subprocess.run(["g++", "-std=c++20", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fno-pie",
                    "-no-pie", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "-Ikernel/include", "kernel/tests/drivers/partition.cpp",
                    "kernel/drivers/block/partition.cpp", "-o", binary], cwd=ROOT, check=True)
    good_gpt = gpt()
    gpt_expected = [
        (1, ROOT_START, FS_SECTORS, ROOT_ID), (17, DATA_START, FS_SECTORS, str(uuid.UUID(int=17))),
        (3, RAW_START, RAW_SECTORS, str(uuid.UUID(int=3))),
    ]
    mbr_expected = [(n, start, length, f"13572468-{n:02x}") for n, _, start, length in MBR_COMMON]
    cases = [
        ("gpt-primary", good_gpt, 0, gpt_expected),
        ("gpt-backup-header", {**good_gpt, 1: b"bad header"}, 0, gpt_expected),
        ("gpt-backup-array", {**good_gpt, 2: b"bad array"}, 0, gpt_expected),
        ("gpt-no-valid-crc", {**good_gpt, 2: b"bad array", SECTORS - 33: b"bad array"}, -22, []),
        ("gpt-overlap", gpt(overlap=True), -22, []),
        ("gpt-overflow", gpt(overflow=True), -22, []),
        ("gpt-short-protective", {**good_gpt, 0: mbr([(1, 0xEE, 1, 255)])}, -22, []),
        ("mbr-logical", DOS, 0, [*mbr_expected, (5, ROOT_START, FS_SECTORS, "13572468-05")]),
        ("mbr-overrun", {0: mbr([(1, 0x83, SECTORS - 10, 11)])}, -22, []),
        ("mbr-overlap", {0: mbr([(1, 0x83, 1, 10), (2, 0x83, 5, 2)])}, -22, []),
        ("ebr-cycle", {0: MBR_EXTENDED, ROOT_START - 1: mbr([(2, 0x0F, 0, 1)])}, -22, []),
        ("ebr-escape", {0: MBR_EXTENDED, ROOT_START - 1: mbr([(1, 0x83, 2, FS_SECTORS)])}, -22, []),
        ("bsd-standalone", {1: bsd(False)}, 0, [(1, ROOT_START, FS_SECTORS, "")]),
        ("bsd-nested", BSD_NESTED, 0, [*mbr_expected, (1, ROOT_START - 2, FS_SECTORS + 2,
                                                      "13572468-01"), (5, ROOT_START, FS_SECTORS, "")]),
        ("bsd-bad-checksum", {1: bsd(False, True)}, -22, []),
        ("bsd-nested-reject", {0: BSD_PARENT, ROOT_START - 1: bsd(True, True)},
         0, [*mbr_expected, (1, ROOT_START - 2, FS_SECTORS + 2, "13572468-01")]),
        ("unpartitioned", {}, 0, []),
    ]
    for name, metadata, error, expected in [*cases, ("read-error", {}, -5, [])]:
        path = directory / "decoder.raw"
        drive(path, metadata)
        fail = 0 if name == "read-error" else (1 << 64) - 1
        subprocess.run([binary, path, str(SECTORS), str(fail), str(error),
                        *[str(value) for entry in expected for value in entry]], check=True)
        print(f"PARTITION_DECODER_PASS {name}", flush=True)
    path.unlink()


def ext2(path, stage):
    with path.open("wb") as output:
        output.truncate(FS_SECTORS * SECTOR)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2", "-b", "4096", "-I", "128",
                    "-O", "none,filetype,sparse_super,large_file", "-E", "root_owner=0:0",
                    "-d", stage, path], check=True, stdout=subprocess.DEVNULL)


def fixture(directory, probe, sibling, first, root, data, parent, shifted=False):
    disk = "/dev/vdb" if shifted else "/dev/vda"
    major, minor = (259, int(shifted) * 128 + data - 16) if data >= 16 else (252, data)
    paths = [disk, f"{disk}{root}", f"{disk}{data}", f"{disk}3", f"{disk}{parent}" if parent else "-"]
    layout = (" ".join([*paths, str(major), str(minor)]) + "\n").encode()
    regular = stat.S_IFREG | 0o755
    files = {name: (stat.S_IFDIR | 0o755, b"") for name in
             ("bin", "dev", "lib", "mnt", "other", "proc", "run", "sbin", "sys", "tmp")}
    files["sbin/init"] = regular, probe
    files["bin/busybox"] = regular, probe
    files["lib/ld-musl-x86_64.so.1"] = regular, probe
    files["layout"] = stat.S_IFREG | 0o644, layout
    with tempfile.TemporaryDirectory(prefix="root-", dir=directory) as staging:
        stage = Path(staging)
        populate(stage, files)
        ext2(first, stage)
    empty = directory / "empty"
    empty.mkdir(exist_ok=True)
    if not sibling.exists():
        ext2(sibling, empty)


def image(directory, name, root):
    path = directory / (name + ".iso")
    subprocess.run([sys.executable, "-B", "scripts/image.py", "--test", "--suite", "root",
                    "--root-device", root, "--output-name", path.name,
                    "--output-directory", directory], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return path


def partition_boot(directory, iso, disks, firmware, transport, markers, success):
    boot(directory, iso, disks, firmware, transport, markers, success)
    print(f"PARTITION_BOOT_PASS {directory.name} {iso.stem}", flush=True)


def check_disk(directory, disk, original, phase):
    data = disk.read_bytes()
    for name, start in [("root-check", ROOT_START), ("data-check", DATA_START)]:
        view = directory / (name + ".ext2")
        view.write_bytes(data[start * SECTOR:(start + FS_SECTORS) * SECTOR])
        with (directory / f"{name}-{phase}.log").open("wb") as log:
            subprocess.run(["e2fsck", "-fn", view], check=True, stdout=log, stderr=subprocess.STDOUT)
        result = subprocess.run(["debugfs", "-R", "cat /persisted", view],
                                check=True, capture_output=True)
        if result.stdout != PAYLOAD:
            raise RuntimeError(f"{disk}: persisted bytes differ in {name}")
        view.unlink()
    raw_byte = (RAW_START + RAW_SECTORS) * SECTOR - 1
    gap = slice((ROOT_START + FS_SECTORS) * SECTOR, DATA_START * SECTOR)
    suffix = (DATA_START + FS_SECTORS) * SECTOR
    if (data[:ROOT_START * SECTOR] != original[:ROOT_START * SECTOR] or
            data[gap] != original[gap] or
            data[suffix:] != original[suffix:raw_byte] + b"p" + original[raw_byte + 1:]):
        raise RuntimeError(f"{disk}: unexpected write outside either ext2 partition")


def guest(directory, firmware, transport):
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    binary = directory / "partition-guest"
    subprocess.run(["musl-gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                    "userspace/tests/fs/partitions.c", "-o", binary], cwd=ROOT, check=True)
    bootstrap(ROOT / "build/rootfs-bootstrap.cpio")
    common = directory / "fixtures"
    common.mkdir(exist_ok=True)
    data = common / "data.raw"
    blank = common / "blank.raw"
    drive(blank, {})
    selections = [
        ("gpt", gpt(), "PARTUUID=" + ROOT_ID.upper(), "PARTLABEL=" + ROOT_LABEL, 1, 17, 0, True),
        ("mbr", DOS, "PARTUUID=13572468-05", "/dev/vda5", 5, 2, 0, False),
        ("bsd", BSD_NESTED, "/dev/vda5", "/dev/vda5", 5, 2, 1, False),
    ]
    for name, metadata, first_root, second_root, root_number, sibling_number, parent, shifted in selections:
        first = common / "root.raw"
        fixture(common, binary.read_bytes(), data, first, root_number, sibling_number, parent, shifted)
        files = [(ROOT_START, first.read_bytes()), (DATA_START, data.read_bytes())]
        for fw in firmware:
            for bus in transport:
                work = directory / f"{name}-{fw}-{bus}"
                work.mkdir(exist_ok=True)
                disk = work / "disk.raw"
                drive(disk, metadata, files)
                seed = disk.read_bytes()
                disks = [blank, disk] if shifted else [disk]
                for phase, root in [("write", first_root), ("reboot", second_root)]:
                    iso = image(work, f"{work.name}-{phase}", root)
                    partition_boot(work, iso, disks, fw, bus,
                                   [f"VFS_ROOT_PASS filesystem=ext2 device={root} readonly=0",
                                    f"PARTITIONS_{phase.upper()}_PASS"], True)
                    check_disk(work, disk, seed, phase)
                if name == "gpt":
                    bad = work / "bad.raw"
                    drive(bad, {**metadata, 2: b"bad array", SECTORS - 33: b"bad array"})
                    for case, selected, attached, err in [
                        ("corrupt", "/dev/vda1", [bad], "/dev/vda1 errno=19"),
                        ("ambiguous", first_root, [disk, shutil.copyfile(disk, work / "clone.raw")],
                         "root-device errno=76"),
                    ]:
                        iso = image(work, f"{work.name}-{case}", selected)
                        partition_boot(work, iso, attached, fw, bus, [f"BOOT_ROOT_FAIL stage={err}"], False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/partitions")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--firmware", choices=("bios", "uefi", "both"), default="both")
    parser.add_argument("--transport", choices=("modern", "legacy", "both"), default="both")
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    native(directory)
    if not args.native_only:
        guest(directory, ("bios", "uefi") if args.firmware == "both" else (args.firmware,),
              ("modern", "legacy") if args.transport == "both" else (args.transport,))


if __name__ == "__main__":
    main()
