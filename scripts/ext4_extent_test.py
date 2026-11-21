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


def fixture(directory, disk, block, journal, binaries=(), checksums=""):
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
        if checksums:
            (store / "attribute").touch()
            if block == 1024:
                (store / "lazy").touch()
        with disk.open("wb") as output:
            output.truncate(48 * 1024 * 1024)
        features = "none,filetype,sparse_super,large_file,extent,dir_index"
        if journal:
            features += ",has_journal"
        if checksums:
            features += ",ext_attr," + checksums
        inode_size = "256" if checksums and block == 4096 else "128"
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", str(block), "-I", inode_size,
                        "-O", features, "-E", "root_owner=0:0", "-d", root, disk], check=True)
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


def lazy_flags(disk):
    with disk.open("rb") as raw:
        raw.seek(2048 + 32 + 18)
        return struct.unpack("<H", raw.read(2))[0]


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
    phases = ["write", "verify", "invalid", "unsupported", "full", "pressure", "recovery"]
    if args.root_tools:
        phases.append("root")
    boot_images = {phase: image(directory, archive, phase) for phase in phases}
    rows = []
    selected = range(len(PROFILES)) if args.profile is None else (args.profile,)
    for profile in selected:
        block, firmware, transport, journal, checksums = PROFILES[profile]
        case = directory / f"profile-{profile}"
        case.mkdir()
        disk = case / "disk.raw"
        fixture(case, disk, block, journal, checksums=checksums)
        cut = None
        if profile == 0:
            rejected(case, disk, boot_images)
            full_volume(case / "full", boot_images["full"])
        if profile == 4:
            if not lazy_flags(disk) & 2:
                raise RuntimeError("native seed did not have a lazy block group")
            checksum_rejections(case, disk, boot_images["invalid"])
            cut = verify_cut(case / "metadata-cut", disk, boot_images)
        boot(case, boot_images["write"], [disk], firmware, transport, ["EXT4_EXTENT_MUTATION_PASS"])
        depth = verify_host(case, disk, block)
        if checksums:
            verify_metadata(disk, block)
        written = digest(disk)
        boot(case, boot_images["verify"], [disk], firmware, transport, ["EXT4_EXTENT_REBOOT_PASS"])
        if digest(disk) != written:
            raise RuntimeError("read-only ext4 reboot changed disk bytes")
        row = dict(profile=profile, block_size=block, firmware=firmware, transport=transport,
                   journal=journal, metadata_checksums=checksums, tree_depth=depth, disk_sha256=written)
        if cut:
            row["metadata_cut"] = cut
        if args.root_tools:
            root = case / "root"
            root.mkdir()
            rootdisk = root / "disk.raw"
            fixture(root, rootdisk, block, journal, (client, *args.root_tools), checksums)
            boot(root, boot_images["root"], [rootdisk], firmware, transport,
                 ["VFS_ROOT_PASS filesystem=ext4 device=/dev/vda readonly=0",
                  "EXT4_EXTENT_MUTATION_PASS"])
            verify_host(root, rootdisk, block, "/mnt")
            if checksums:
                verify_metadata(rootdisk, block, "/mnt")
            row["root_disk_sha256"] = digest(rootdisk)
        rows.append(row)
        (directory / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"EXT4_EXTENT_PROFILE_PASS {profile} {firmware}/{transport}", flush=True)


if __name__ == "__main__":
    main()
