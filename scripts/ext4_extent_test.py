#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext4_extent_test.py
# @brief   Test native and guest-authored extent trees across QEMU boots.
# @author  frankischilling
# @date    2026-11-20
#
# Builds isolated volumes with e2fsprogs and checks guest outputs independently.
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

"""Check writable ext4 extent trees with e2fsprogs and real guest operations."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

from account_normal_test import write_cpio
from ext2_index_test import debug, digest
from fetch import ROOT
from guest_storage_boot import boot

NATIVE = 96
SPARSE = 400
PROFILES = (
    (1024, "bios", "modern", True),
    (2048, "uefi", "modern", False),
    (4096, "bios", "legacy", False),
    (4096, "uefi", "legacy", True),
)
LAST_LOGICAL = 2**32 - 2


def fsck(disk, logpath):
    with logpath.open("wb") as log:
        subprocess.run(["e2fsck", "-fn", disk], check=True, stdout=log, stderr=subprocess.STDOUT)


def native_file(block):
    data = bytearray((2 * NATIVE + 1) * block)
    for i in range(NATIVE):
        offset = (2 + 2 * i) * block
        data[offset:offset + block] = bytes((ord("A") + i % 26,)) * block
    return data


def fixture(directory, disk, block, journal, binaries=()):
    prefix = "/mnt" if binaries else ""
    with tempfile.TemporaryDirectory(prefix="ext4-extents-") as source:
        root = Path(source)
        store = root
        if binaries:
            for name in ("bin", "dev", "lib", "mnt", "proc", "run", "sbin", "sys", "tmp"):
                (root / name).mkdir()
            for binary, name in zip(binaries, ("sbin/init", "bin/busybox", "lib/ld-musl-x86_64.so.1"),
                                    strict=True):
                shutil.copyfile(binary, root / name)
                (root / name).chmod(0o755)
            store = root / "mnt"
        (store / "native").write_bytes(native_file(block))
        (store / "preallocated").touch()
        (store / "empty-reserved").touch()
        with disk.open("wb") as output:
            output.truncate(48 * 1024 * 1024)
        features = "none,filetype,sparse_super,large_file,extent,dir_index"
        if journal:
            features += ",has_journal"
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", str(block), "-I", "128",
                        "-O", features, "-E", "root_owner=0:0", "-d", root, disk], check=True)
    path = prefix + "/preallocated"
    debug(disk, f"fallocate {path} 4 19", write=True)
    debug(disk, f"set_inode_field {path} size {14 * block}", write=True)
    debug(disk, f"fallocate {prefix}/empty-reserved 2 5", write=True)
    prealloc = [debug(disk, f"bmap {path} {logical}").split() for logical in range(4, 20)]
    with disk.open("r+b") as output:
        for row in prealloc:
            if len(row) != 2 or row[1] != b"(uninit)" or not int(row[0]):
                raise RuntimeError("native preallocation did not create an unwritten extent")
            output.seek(int(row[0]) * block)
            output.write(b"\xa5" * block)
    fsck(disk, directory / "before-fsck.log")
    (directory / "native-extents.log").write_bytes(debug(disk, f"extents {prefix}/native"))


def image(directory, archive, phase):
    name = f"ext4-extent-{phase}.iso"
    args = ["--kernel-option", "root=/dev/vda", "--kernel-option", "rootfstype=ext4"] if phase == "root" else []
    guest_phase = {"root": "io", "unsupported": "error"}.get(phase, phase)
    with (directory / f"image-{phase}.log").open("wb") as log:
        subprocess.run([sys.executable, "-B", "scripts/image.py", "--test", "--suite", "storage",
                        "--phase", guest_phase, "--kernel", ROOT / "build/axiom64.elf",
                        "--initramfs", archive, "--output-directory", directory,
                        "--output-name", name, *args], cwd=ROOT, check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    return directory / name


def inode_offset(disk, path, block):
    fields = re.search(rb"located at block (\d+), offset (0x[\da-f]+)", debug(disk, f"imap {path}"))
    return int(fields[1]) * block + int(fields[2], 16)


def rejected(directory, seed, boot_images):
    block = 1024
    native = inode_offset(seed, "/native", block) + 40
    with seed.open("rb") as source:
        source.seek(native)
        header = source.read(24)
        magic, entries, capacity, depth = struct.unpack_from("<4H", header)
        if magic != 0xf30a or not entries or depth != 1:
            raise RuntimeError("malformed control requires an external native leaf")
        leaf = struct.unpack_from("<I", header, 16)[0] * block
        source.seek(leaf + 20)
        duplicate = source.read(4)
    controls = (
        ("magic", native, b"\0\0", "invalid"),
        ("count", native + 2, struct.pack("<H", capacity + 1), "invalid"),
        ("subtree-key", leaf + 12, struct.pack("<I", 1), "invalid"),
        ("physical-overlap", leaf + 32, duplicate, "invalid"),
        ("physical-outside", leaf + 20, struct.pack("<I", 2**32 - 1), "invalid"),
        ("metadata-checksum", 1024 + 100, struct.pack("<I", 0x403), "unsupported"),
    )
    for name, offset, payload, phase in controls:
        case = directory / name
        case.mkdir()
        disk = case / "disk.raw"
        subprocess.run(["cp", "--sparse=always", "--", seed, disk], check=True)
        with disk.open("r+b") as output:
            output.seek(offset)
            output.write(payload)
        before = digest(disk)
        boot(case, boot_images[phase], [disk], "bios", "modern", ["EXT4_EXTENT_REJECTION_PASS"])
        if digest(disk) != before:
            raise RuntimeError(f"rejected extent volume changed bytes: {name}")


def split_file():
    data = bytearray(7 * 1024)
    for i in range(4):
        offset = i * 2048
        data[offset:offset + 1024] = bytes((ord("a") + i,)) * 1024
    return data


def full_volume(directory, iso):
    directory.mkdir()
    disk = directory / "disk.raw"
    with tempfile.TemporaryDirectory(prefix="ext4-full-") as scratch:
        root = Path(scratch)
        (root / "split").write_bytes(split_file())
        (root / "filler").touch()
        with disk.open("wb") as output:
            output.truncate(4 * 1024 * 1024)
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", "1024", "-I", "128", "-d", root,
                        "-O", "none,filetype,extent,sparse_super,large_file", disk], check=True)
    block_count = re.search(rb"Free blocks:\s+(\d+)", debug(disk, "stats"))
    debug(disk, f"fallocate /filler 0 {int(block_count[1]) - 2}", write=True)
    if not re.search(rb"Free blocks:\s+1\b", debug(disk, "stats")):
        raise RuntimeError("full-disk fixture must leave exactly one free block")
    fsck(disk, directory / "before-fsck.log")
    boot(directory, iso, [disk], "bios", "modern", ["EXT4_EXTENT_FULL_PASS"])
    fsck(disk, directory / "after-fsck.log")
    if debug(disk, "cat /split") != split_file() or debug(disk, "cat /last-block") != b"z":
        raise RuntimeError("full-disk rollback changed file bytes")


def verify_host(directory, disk, block, prefix=""):
    fsck(disk, directory / "after-fsck.log")
    native = native_file(block)
    native[0] = ord("a")
    native[3 * block + 5] = ord("b")
    prealloc = bytearray(11 * block)
    prealloc[9 * block + 127:9 * block + 129] = b"UV"
    sparse = bytearray((SPARSE - 1) * 2 * block + 8)
    for i in range(SPARSE):
        sparse[i * 2 * block + 7] = ord("a") + i % 26
    expected = {"native": native, "preallocated": prealloc, "renamed/sparse": sparse,
                "trimmed": b"T" * (block + 73) + bytes(3 * block - 73)}
    with tempfile.TemporaryDirectory(prefix="ext4-extent-export-") as scratch:
        target = Path(scratch) / "file"
        for name, contents in expected.items():
            debug(disk, f"dump {prefix}/{name} {target}")
            if target.read_bytes() != contents:
                raise RuntimeError(f"host export differs for {name}")
            target.unlink()
    tree = debug(disk, f"extents {prefix}/renamed/sparse")
    (directory / "guest-extents.log").write_bytes(tree)
    depth = max(int(match[1]) for match in re.finditer(rb"\d+/\s*(\d+)\s+\d+/", tree))
    if block == 1024 and depth < 2:
        raise RuntimeError("guest file did not grow a second extent tree level")
    trimmed = debug(disk, f"extents {prefix}/trimmed")
    if not re.search(rb"0/\s*0\s+1/\s*1\s+0\s*-\s*1\b", trimmed):
        raise RuntimeError("guest truncation did not collapse the extent tree to one inline extent")
    wide = debug(disk, f"stat {prefix}/wide")
    if not re.search(rb"Size:\s+" + str((LAST_LOGICAL + 1) * block).encode() + rb"\b", wide):
        raise RuntimeError("host wide file size differs")
    physical = int(debug(disk, f"bmap {prefix}/wide {LAST_LOGICAL}"))
    with disk.open("rb") as source:
        source.seek(physical * block)
        if not physical or source.read(block) != bytes(block - 1) + b"W":
            raise RuntimeError("host wide file block differs")
    return depth


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext4-extents")
    parser.add_argument("--profile", type=int, choices=range(len(PROFILES)))
    parser.add_argument("--root-tools", type=Path, nargs=2, metavar=("BUSYBOX", "MUSL_LOADER"),
                        help="test a direct ext4 root boot with the supplied guest tools")
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to((ROOT / "build").resolve()):
        parser.error("--directory must be under build/")
    directory.mkdir(parents=True, exist_ok=False)
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    client = directory / "ext4-extents"
    subprocess.run(["musl-gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                    "userspace/tests/fs/ext4-extents.c", "-o", client], cwd=ROOT, check=True)
    archive = directory / "initramfs.cpio"
    files = {name: (0o40755, b"") for name in ("dev", "proc", "run", "sbin", "sys", "tmp")}
    files["sbin/init"] = 0o100755, client.read_bytes()
    write_cpio(archive, files)
    phases = ["write", "verify", "invalid", "unsupported", "full"]
    if args.root_tools:
        phases.append("root")
    boot_images = {phase: image(directory, archive, phase) for phase in phases}
    rows = []
    selected = range(len(PROFILES)) if args.profile is None else (args.profile,)
    for profile in selected:
        block, firmware, transport, journal = PROFILES[profile]
        case = directory / f"profile-{profile}"
        case.mkdir()
        disk = case / "disk.raw"
        fixture(case, disk, block, journal)
        if profile == 0:
            rejected(case, disk, boot_images)
            full_volume(case / "full", boot_images["full"])
        boot(case, boot_images["write"], [disk], firmware, transport, ["EXT4_EXTENT_MUTATION_PASS"])
        depth = verify_host(case, disk, block)
        written = digest(disk)
        boot(case, boot_images["verify"], [disk], firmware, transport, ["EXT4_EXTENT_REBOOT_PASS"])
        if digest(disk) != written:
            raise RuntimeError("read-only ext4 reboot changed disk bytes")
        row = dict(profile=profile, block_size=block, firmware=firmware, transport=transport,
                   journal=journal, tree_depth=depth, disk_sha256=written)
        if args.root_tools:
            root = case / "root"
            root.mkdir()
            rootdisk = root / "disk.raw"
            fixture(root, rootdisk, block, journal, (client, *args.root_tools))
            boot(root, boot_images["root"], [rootdisk], firmware, transport,
                 ["VFS_ROOT_PASS filesystem=ext4 device=/dev/vda readonly=0",
                  "EXT4_EXTENT_MUTATION_PASS"])
            verify_host(root, rootdisk, block, "/mnt")
            row["root_disk_sha256"] = digest(rootdisk)
        rows.append(row)
        (directory / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"EXT4_EXTENT_PROFILE_PASS {profile} {firmware}/{transport}", flush=True)


if __name__ == "__main__":
    main()
