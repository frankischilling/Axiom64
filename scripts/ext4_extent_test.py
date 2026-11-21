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
import ctypes
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
from fixture_archive import archive_fixture, sparse_copy_fixture
from guest_storage_boot import boot, cut_after_write_fault

NATIVE = 96
SPARSE = 400
PROFILES = (
    (1024, "bios", "modern", True, ""),
    (2048, "uefi", "modern", False, ""),
    (4096, "bios", "legacy", False, ""),
    (4096, "uefi", "legacy", True, ""),
    (1024, "bios", "modern", True, "metadata_csum"),
    (4096, "uefi", "legacy", True, "metadata_csum,metadata_csum_seed"),
    (4096, "uefi", "modern", True, "metadata_csum,64bit"),
    (1024, "bios", "modern", True, "metadata_csum,64bit,flex_bg"),
    (1024, "uefi", "legacy", True, "metadata_csum,flex_bg"),
    (2048, "bios", "legacy", False, "64bit,flex_bg"),
    (4096, "uefi", "modern", True,
     "metadata_csum,64bit,flex_bg,huge_file,dir_nlink,extra_isize,resize_inode"),
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


def crc32c(seed, data):
    crc = ctypes.CDLL("libext2fs.so.2").ext2fs_crc32c_le
    crc.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t]
    crc.restype = ctypes.c_uint32
    return crc(seed, bytes(data), len(data))


def checksummed_journal(disk, block):
    physical = int(debug(disk, "bmap <8> 0"))
    with disk.open("r+b") as raw:
        raw.seek(physical * block)
        header = bytearray(raw.read(1024))
        if struct.unpack_from(">II", header) != (0xc03b3998, 4):
            raise RuntimeError("native image did not create an internal JBD2 journal")
        struct.pack_into(">I", header, 40, 19)
        header[80] = 4
        struct.pack_into(">I", header, 252, crc32c(0xffffffff, header))
        raw.seek(physical * block)
        raw.write(header)


def fixture(directory, disk, block, journal, binaries=(), features_extra=""):
    prefix = "/mnt" if binaries else ""
    feature_set = set(features_extra.split(","))
    checksums = "metadata_csum" in feature_set
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
        if "huge_file" in feature_set:
            (store / "native-inode").write_bytes(b"N")
        if checksums:
            (store / "attribute").touch()
            if block == 1024:
                (store / "lazy").touch()
        with disk.open("wb") as output:
            output.truncate(48 * 1024 * 1024)
        features = "none,filetype,sparse_super,large_file,extent,dir_index"
        if journal:
            features += ",has_journal"
        if features_extra:
            features += "," + features_extra
        if checksums:
            features += ",ext_attr"
        inode_size = "256" if checksums and block == 4096 else "128"
        layout = ["-G", "4", "-g", "2048"] if "flex_bg" in feature_set else []
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", str(block), "-I", inode_size, *layout,
                        "-O", features, "-E", "root_owner=0:0", "-d", root, disk], check=True)
        if "huge_file" in feature_set:
            debug(disk, f"set_inode_field {prefix}/native-inode flags 0xc0000", write=True)
            debug(disk, f"set_inode_field {prefix}/native-inode blocks 1", write=True)
            debug(disk, "set_super_value want_extra_isize 48", write=True)
        if checksums:
            value = root / "attribute-value"
            value.write_bytes(b"A" * 600)
            debug(disk, f"ea_set -f {value} {prefix}/attribute user.original", write=True)
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
    if checksums and journal:
        checksummed_journal(disk, block)
    fsck(disk, directory / "before-fsck.log")
    (directory / "native-extents.log").write_bytes(debug(disk, f"extents {prefix}/native"))


def image(directory, archive, phase):
    name = f"ext4-extent-{phase}.iso"
    args = ["--kernel-option", "root=/dev/vda", "--kernel-option", "rootfstype=ext4"] if phase == "root" else []
    guest_phase = {"root": "io", "unsupported": "error", "link-counts": "queue",
                   "link-counts-verify": "readonly"}.get(phase, phase)
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


def checksum_rejections(directory, seed, iso):
    block = 1024
    with seed.open("rb") as raw:
        raw.seek(1024 + 104)
        seed_crc = crc32c(0xffffffff, raw.read(16))
        raw.seek(inode_offset(seed, "/native", block) + 56)
        node, = struct.unpack("<I", raw.read(4))
        raw.seek(node * block + 4)
        entries, = struct.unpack("<H", raw.read(2))
    directory_block = int(debug(seed, "bmap / 0"))
    attribute = int(re.search(rb"File ACL: (\d+)", debug(seed, "stat /attribute"))[1])
    if not all((node, entries, directory_block, attribute)):
        raise RuntimeError("could not locate the native checksum regions")
    cases = {"superblock": 1024 + 1020, "group": 2 * block + 30,
             "block-bitmap": 2 * block + 24, "inode-bitmap": 2 * block + 26,
             "inode": inode_offset(seed, "/native", block) + 124,
             "extent": node * block + 12 + entries * 12,
             "directory": (directory_block + 1) * block - 4,
             "xattr": attribute * block + 16}
    for name, where in cases.items():
        case = directory / ("checksum-" + name)
        case.mkdir()
        disk = case / "disk.raw"
        subprocess.run(["cp", "--sparse=always", "--", seed, disk], check=True)
        with disk.open("r+b") as raw:
            raw.seek(where)
            old = raw.read(1)
            raw.seek(where)
            raw.write(bytes([old[0] ^ 1]))
            if name.endswith("-bitmap"):
                # Keep the descriptor valid so this can only fail the bitmap check.
                raw.seek(2 * block)
                desc = bytearray(raw.read(32))
                struct.pack_into("<H", desc, 30, 0)
                checksum = crc32c(seed_crc, bytes(4) + desc) & 0xffff
                raw.seek(2 * block + 30)
                raw.write(struct.pack("<H", checksum))
        digest_before = digest(disk)
        boot(case, iso, [disk], "bios", "modern", ["EXT4_EXTENT_REJECTION_PASS"])
        if digest(disk) != digest_before:
            raise RuntimeError(f"rejected metadata checksum wrote to the disk: {name}")


def group_layout(disk):
    with disk.open("rb") as raw:
        raw.seek(1024)
        header = raw.read(1024)
    first, block_shift, _, per_group = struct.unpack_from("<4I", header, 20)
    block = 1024 << block_shift
    incompatible, = struct.unpack_from("<I", header, 96)
    width = struct.unpack_from("<H", header, 254)[0] if incompatible & 0x80 else 32
    return header, (first + 1) * block, width, first + per_group


def lazy_flags(disk):
    _, table, width, _ = group_layout(disk)
    with disk.open("rb") as raw:
        raw.seek(table + width + 18)
        return struct.unpack("<H", raw.read(2))[0]


def verify_flex_placement(disk, block, wide):
    header, table, width, group1_first = group_layout(disk)
    with disk.open("rb") as raw:
        raw.seek(table + width)
        addresses = struct.unpack("<3I", raw.read(12))
    if width != (64 if wide else 32) or any(address >= group1_first for address in addresses):
        raise RuntimeError("native fixture did not relocate all three group 1 metadata regions")
    if wide and block == 1024:
        blocks, = struct.unpack_from("<I", header, 4)
        per_group = group1_first - 1
        groups = (blocks - 1 + per_group - 1) // per_group
        if groups * width <= block:
            raise RuntimeError("native fixture did not span more than one wide descriptor table block")
    return addresses


def wide_descriptor_rejections(directory, seed, images):
    header, table, width, _ = group_layout(seed)
    seed_crc = crc32c(0xffffffff, header[104:120])
    with seed.open("rb") as raw:
        raw.seek(table)
        first_bitmap = raw.read(4)
    cases = (
        ("block-bitmap-crc-high", 0, 56, None, "invalid"),
        ("inode-bitmap-crc-high", 0, 58, None, "invalid"),
        ("block-bitmap-address-high", 1, 32, struct.pack("<I", 1), "invalid"),
        ("overlapping-block-bitmaps", 1, 0, first_bitmap, "invalid"),
        ("descriptor-width", None, 254, struct.pack("<H", 96), "unsupported"),
        ("block-count-high", None, 336, struct.pack("<I", 1), "unsupported"),
    )
    for name, group, offset, payload, phase in cases:
        case = directory / name
        case.mkdir()
        disk = case / "disk.raw"
        sparse_copy_fixture(seed, disk)
        with disk.open("r+b") as raw:
            start = 1024 if group is None else table + group * width
            raw.seek(start)
            record = bytearray(raw.read(1024 if group is None else width))
            if payload is None:
                record[offset] ^= 1
            else:
                record[offset:offset + len(payload)] = payload
            if group is None:
                struct.pack_into("<I", record, 1020, crc32c(0xffffffff, record[:1020]))
            else:
                struct.pack_into("<H", record, 30, 0)
                checksum = crc32c(seed_crc, struct.pack("<I", group) + record) & 0xffff
                struct.pack_into("<H", record, 30, checksum)
            raw.seek(start)
            raw.write(record)
        before = digest(disk)
        boot(case, images[phase], [disk], "bios", "modern", ["EXT4_EXTENT_REJECTION_PASS"])
        if digest(disk) != before:
            raise RuntimeError(f"rejected wide descriptor fixture changed bytes: {name}")


def verify_cut(directory, seed, images):
    directory.mkdir()
    block = 1024
    disk = directory / "disk.raw"
    sparse_copy_fixture(seed, disk)
    with seed.open("rb") as raw:
        raw.seek(2 * block)
        desc = raw.read(block)
        bitmap, = struct.unpack_from("<I", desc)
        raw.seek(bitmap * block)
        bits = raw.read(block)
    journal = int(debug(seed, "bmap <8> 0"))
    cut_after_write_fault(directory, images["pressure"], disk, 4,
                          "EXT4_METADATA_HOME_WRITE_FAULT")
    with disk.open("rb") as raw:
        raw.seek(2 * block)
        if raw.read(block) != desc:
            raise RuntimeError("fault did not leave the home descriptor untouched")
        raw.seek(bitmap * block)
        if raw.read(block) == bits:
            raise RuntimeError("expected a newer home bitmap than the descriptor checksum")
        raw.seek(journal * block + 28)
        if not struct.unpack(">I", raw.read(4))[0]:
            raise RuntimeError("metadata write fault did not leave a committed journal")
    recovered, oracle = (directory / name for name in ("guest", "checker"))
    for path in (recovered, oracle):
        path.mkdir()
        sparse_copy_fixture(disk, path / "disk.raw")
    with (oracle / "replay.log").open("wb") as log:
        run = subprocess.run(["e2fsck", "-fy", oracle / "disk.raw"], stdout=log,
                             stderr=subprocess.STDOUT)
    if run.returncode not in (0, 1) or b"recovering journal" not in (oracle / "replay.log").read_bytes():
        raise RuntimeError("native checker did not replay the interrupted metadata update")
    boot(recovered, images["recovery"], [recovered / "disk.raw"], "bios", "modern",
         ["EXT4_METADATA_RECOVERY_PASS"])
    for path in (recovered, oracle):
        image = path / "disk.raw"
        fsck(image, path / "fsck.log")
        if debug(image, "cat /attribute") != b"metadata cut\0":
            raise RuntimeError("metadata recovery did not preserve the committed file")
    return {name: archive_fixture(path / "disk.raw", remove=True) for name, path in
            (("interrupted", directory), ("checker", oracle), ("guest", recovered))}


def verify_metadata(disk, block, prefix=""):
    with tempfile.TemporaryDirectory(prefix="ext4-metadata-export-") as scratch:
        data = Path(scratch) / "file"
        for attr, expected in (("original", b"A" * 600), ("updated", b"X" * 133)):
            debug(disk, f"ea_get -f {data} {prefix}/attribute user.{attr}")
            if data.read_bytes() != expected:
                raise RuntimeError(f"metadata checksum fixture lost user.{attr} bytes")
            data.unlink()
        if block == 1024:
            debug(disk, f"dump {prefix}/lazy {data}")
            if lazy_flags(disk) & 2 or data.read_bytes() != b"Z" * (9 * 1024 * 1024):
                raise RuntimeError("lazy block allocation did not persist")


def verify_native_inodes(disk, block, prefix=""):
    with disk.open("rb") as raw:
        raw.seek(inode_offset(disk, f"{prefix}/native-inode", block))
        native = raw.read(256)
        raw.seek(inode_offset(disk, f"{prefix}/time-probe", block))
        timed = raw.read(256)
    if struct.unpack_from("<II", native, 28) != (2 * block // 512, 0x80000):
        raise RuntimeError("guest mutation did not normalize the imported block count")
    if struct.unpack_from("<H", timed, 128)[0] != 48 or not struct.unpack_from("<I", timed, 144)[0]:
        raise RuntimeError("guest creation did not reserve the desired inode fields")
    for offset, extra, seconds, nsec in ((8, 140, -42, 987654321), (16, 136, 13569465600, 123456789)):
        low, = struct.unpack_from("<i", timed, offset)
        encoded, = struct.unpack_from("<I", timed, extra)
        if (low + ((encoded & 3) << 32), encoded >> 2) != (seconds, nsec):
            raise RuntimeError("host inode bytes differ from the guest timestamps")


def reject_inode_features(directory, seed, images):
    cases = (
        ("oversized-extra-isize", "set_super_value want_extra_isize 132", "invalid"),
        ("unindexed-dir-nlink", "set_inode_field /lost+found links_count 1", "invalid"),
        ("inconsistent-wide-block-count", "set_inode_field /native-inode blocks 4294967297", "invalid"),
    )
    for name, damage, phase in cases:
        case = directory / name
        case.mkdir()
        disk = case / "disk.raw"
        sparse_copy_fixture(seed, disk)
        debug(disk, damage, write=True)
        before = digest(disk)
        boot(case, images[phase], [disk], "bios", "modern", ["EXT4_EXTENT_REJECTION_PASS"])
        if digest(disk) != before:
            raise RuntimeError(f"rejected inode feature fixture changed bytes: {name}")


def link_count_rollover(directory, images):
    directory.mkdir()
    disk = directory / "disk.raw"
    with tempfile.TemporaryDirectory(prefix="ext4-directory-links-") as source:
        crowded = Path(source) / "crowded"
        crowded.mkdir()
        for i in range(64998):
            (crowded / f"d{i:05}").mkdir()
        with disk.open("wb") as raw:
            raw.truncate(128 * 1024 ** 2)
        features = "none,filetype,sparse_super,large_file,dir_index,extent,has_journal,dir_nlink,metadata_csum"
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", "1024", "-I", "128", "-N", "73728",
                        "-O", features, "-d", source, disk], check=True)
    with (directory / "index-build.log").open("wb") as log:
        result = subprocess.run(["e2fsck", "-fyD", disk], stdout=log, stderr=subprocess.STDOUT)
    if result.returncode not in (0, 1):
        raise RuntimeError("native directory index construction failed")
    before = debug(disk, "stat /crowded")
    if not re.search(rb"Links:\s+65000\b", before) or not re.search(rb"Flags: 0x81000\b", before):
        raise RuntimeError("native indexed directory did not start at the ext4 link limit")
    fsck(disk, directory / "before-fsck.log")
    boot(directory, images["link-counts"], [disk], "bios", "modern", ["EXT4_DIRECTORY_LINK_ROLLOVER_PASS"])
    fsck(disk, directory / "after-fsck.log")
    if not re.search(rb"Links:\s+1\b", debug(disk, "stat /crowded")):
        raise RuntimeError("native inspection did not find the directory link overflow marker")
    before = digest(disk)
    boot(directory, images["link-counts-verify"], [disk], "bios", "modern", ["EXT4_DIRECTORY_LINK_REBOOT_PASS"])
    if digest(disk) != before:
        raise RuntimeError("read-only directory rollover reboot changed disk bytes")
    return before


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
    phases = ["write", "verify", "invalid", "unsupported", "full", "pressure", "recovery",
              "link-counts", "link-counts-verify"]
    if args.root_tools:
        phases.append("root")
    boot_images = {phase: image(directory, archive, phase) for phase in phases}
    rows = []
    selected = range(len(PROFILES)) if args.profile is None else (args.profile,)
    for profile in selected:
        block, firmware, transport, journal, features_extra = PROFILES[profile]
        feature_set = set(features_extra.split(","))
        checksums = "metadata_csum" in feature_set
        case = directory / f"profile-{profile}"
        case.mkdir()
        disk = case / "disk.raw"
        fixture(case, disk, block, journal, features_extra=features_extra)
        relocated = None
        if "flex_bg" in feature_set:
            relocated = verify_flex_placement(disk, block, "64bit" in feature_set)
        cut = None
        if profile == 0:
            rejected(case, disk, boot_images)
            full_volume(case / "full", boot_images["full"])
        if checksums and block == 1024:
            if not lazy_flags(disk) & 2:
                raise RuntimeError("native seed did not have a lazy block group")
        if profile == 4:
            checksum_rejections(case, disk, boot_images["invalid"])
        if profile == 7:
            wide_descriptor_rejections(case, disk, boot_images)
        if "huge_file" in feature_set:
            reject_inode_features(case, disk, boot_images)
        if profile in (4, 7):
            cut = verify_cut(case / "metadata-cut", disk, boot_images)
        boot(case, boot_images["write"], [disk], firmware, transport, ["EXT4_EXTENT_MUTATION_PASS"])
        depth = verify_host(case, disk, block)
        if checksums:
            verify_metadata(disk, block)
        if "huge_file" in feature_set:
            verify_native_inodes(disk, block)
        written = digest(disk)
        boot(case, boot_images["verify"], [disk], firmware, transport, ["EXT4_EXTENT_REBOOT_PASS"])
        if digest(disk) != written:
            raise RuntimeError("read-only ext4 reboot changed disk bytes")
        row = dict(profile=profile, block_size=block, firmware=firmware, transport=transport,
                   journal=journal, features=features_extra, tree_depth=depth, disk_sha256=written)
        if relocated:
            row["group1_metadata_blocks"] = relocated
        if "dir_nlink" in feature_set:
            row["directory_link_rollover_sha256"] = link_count_rollover(case / "directory-links", boot_images)
        if cut:
            row["metadata_cut"] = cut
        if args.root_tools:
            root = case / "root"
            root.mkdir()
            rootdisk = root / "disk.raw"
            fixture(root, rootdisk, block, journal, (client, *args.root_tools), features_extra)
            boot(root, boot_images["root"], [rootdisk], firmware, transport,
                 ["VFS_ROOT_PASS filesystem=ext4 device=/dev/vda readonly=0",
                  "EXT4_EXTENT_MUTATION_PASS"])
            verify_host(root, rootdisk, block, "/mnt")
            if checksums:
                verify_metadata(rootdisk, block, "/mnt")
            if "huge_file" in feature_set:
                verify_native_inodes(rootdisk, block, "/mnt")
            row["root_disk_sha256"] = digest(rootdisk)
        rows.append(row)
        (directory / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"EXT4_EXTENT_PROFILE_PASS {profile} {firmware}/{transport}", flush=True)


if __name__ == "__main__":
    main()
