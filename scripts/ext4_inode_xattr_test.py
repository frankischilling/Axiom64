#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext4_inode_xattr_test.py
# @brief   Boot native ext4 images with inode-body extended attributes.
# @author  frankischilling
# @date    2026-11-21
#
# Checks native readback and rejects malformed attributes with valid inode checksums.
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

"""Check inode-body xattrs with mixed native storage and strict host fsck."""
import argparse
import json
from pathlib import Path
from shlex import quote
import struct
import subprocess

from ext4_extent_test import crc32c, debug, digest, fsck, inode_offset
from ext4_orphan_batches_test import clean_oracle, journal_state
from ext4_orphan_test import field, images
from fetch import ROOT
from fixture_archive import sparse_copy_fixture
from guest_storage_boot import boot, cut_after_write_fault

CLIENT = "userspace/tests/fs/ext4-inode-xattrs.c"
MAGIC = struct.pack("<I", 0xea020000)
FEATURES = "none,ext_attr,filetype,sparse_super,large_file,has_journal,extent,extra_isize"


def inode(disk, block):
    offset = inode_offset(disk, "/native", block)
    with disk.open("rb") as raw:
        raw.seek(offset)
        return offset, bytearray(raw.read(256))


def fixture(directory, block, checksums):
    directory.mkdir()
    source = directory / "source"
    source.mkdir()
    (source / "native").write_bytes(b"native ext4 file\n")
    values = directory / "attribute"
    values.write_bytes(bytes(range(240)))
    empty = directory / "empty"
    empty.touch()
    disk = directory / "seed.raw"
    with disk.open("xb") as raw:
        raw.truncate(32 * 1024 * 1024)
    features = FEATURES + (",metadata_csum" if checksums else "")
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", str(block), "-I", "256",
                    "-O", features, "-d", source, disk], check=True)
    debug(disk, "ea_set /native user.small inline", write=True)
    debug(disk, f"ea_set -f {quote(str(empty))} /native user.kept", write=True)
    debug(disk, f"ea_set -f {quote(str(values))} /native user.large", write=True)
    fsck(disk, directory / "seed-fsck.log")
    _, raw = inode(disk, block)
    start = 128 + struct.unpack_from("<H", raw, 128)[0]
    assert raw[start:start + 4] == MAGIC
    entries = {}
    offset = start + 4
    while raw[offset:offset + 4] != b"\0" * 4:
        length, index = raw[offset:offset + 2]
        assert index == 1 and 16 + length <= len(raw) - offset
        entries[bytes(raw[offset + 16:offset + 16 + length])] = offset
        offset += (16 + length + 3) & ~3
    assert set(entries) == {b"small", b"kept"}
    external = field(disk, "stat /native", rb"File ACL:\s+(\d+)")
    with disk.open("rb") as image:
        image.seek(external * block)
        attributes = image.read(block)
    assert external and attributes[:4] == MAGIC and attributes[48:53] == b"large"
    return disk, entries[b"small"]


def seal_inode(raw, disk, number):
    with disk.open("rb") as image:
        image.seek(1024 + 104)
        seed = crc32c(0xffffffff, image.read(16))
    original = struct.unpack_from("<H", raw, 124)[0] | (struct.unpack_from("<H", raw, 130)[0] << 16)
    struct.pack_into("<H", raw, 124, 0)
    struct.pack_into("<H", raw, 130, 0)
    value = crc32c(crc32c(crc32c(seed, struct.pack("<I", number)), raw[100:104]), raw)
    struct.pack_into("<H", raw, 124, value & 0xffff)
    struct.pack_into("<H", raw, 130, value >> 16)
    return original == value


def reject_layouts(directory, seed, entry, block, iso, firmware, transport):
    number = field(seed, "stat /native", rb"Inode:\s+(\d+)")
    disk_offset, expected = inode(seed, block)
    assert seal_inode(expected, seed, number)
    placements = (
        ("long-name", entry, b"\xff"),
        ("value-overlaps-entries", entry + 2, struct.pack("<H", 4)),
        ("duplicate-external-name", entry + 16, b"large"),
    )
    results = {}
    for label, offset, value in placements:
        case = directory / label
        case.mkdir()
        disk = case / "bad.raw"
        sparse_copy_fixture(seed, disk)
        image = expected.copy()
        image[offset:offset + len(value)] = value
        assert not seal_inode(image, disk, number)
        with disk.open("r+b") as output:
            output.seek(disk_offset)
            output.write(image)
        before = digest(disk)
        boot(case, iso, [disk], firmware, transport, ["EXT4_INODE_XATTR_REJECTION_PASS"])
        assert digest(disk) == before
        results[label] = before
    return results


def recover_relocation(directory, seed, block, boots):
    directory.mkdir()
    target = field(seed, "stat /native", rb"File ACL:\s+(\d+)")
    cut = directory / "interrupted.raw"
    sparse_copy_fixture(seed, cut)
    cut_after_write_fault(directory, boots["pressure"], cut, target * (block // 512),
                          "EXT4_INODE_XATTR_FAULT_ARMED")
    assert journal_state(cut)[1]
    with cut.open("rb") as current, seed.open("rb") as initial:
        for disk in (current, initial):
            disk.seek(target * block)
        assert current.read(block) == initial.read(block)

    native = clean_oracle(directory, cut)
    guest = directory / "guest.raw"
    sparse_copy_fixture(cut, guest)
    marker = "EXT4_INODE_XATTR_RECOVERY_PASS"
    boot(directory, boots["recovery"], [guest], "bios", "modern", [marker])
    for disk in (native, guest):
        fsck(disk, directory / f"{disk.stem}-fsck.log")
        assert debug(disk, "cat /native") == b"native ext4 file\n"
        for name, length in (("user.small", 480), ("user.large", 240), ("user.kept", 0)):
            value = directory / f"{disk.stem}-{name}"
            debug(disk, f"ea_get -f {quote(str(value))} /native {name}")
            assert value.read_bytes() == bytes(i & 255 for i in range(length))
    before = digest(guest)
    reboot = directory / "reboot"
    reboot.mkdir()
    boot(reboot, boots["recovery"], [guest], "bios", "modern", [marker])
    assert digest(guest) == before
    return {"interrupted_sha256": digest(cut), "native_sha256": digest(native),
            "guest_sha256": before, "failed_block": target}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext4-inode-xattrs")
    args = parser.parse_args()
    out = args.directory.resolve()
    if not out.is_relative_to((ROOT / "build").resolve()):
        parser.error("output must be under build/")
    out.mkdir(parents=True, exist_ok=False)
    boots, _ = images(out, False, prefix="ext4-inode-xattrs", source=CLIENT,
                      base_phases=("write", "verify", "invalid", "pressure", "recovery"))
    rows = []
    for block, checksums, firmware, transport in ((1024, True, "bios", "modern"),
                                                   (4096, False, "uefi", "legacy")):
        directory = out / str(block)
        seed, entry = fixture(directory, block, checksums)
        disk = directory / "disk.raw"
        sparse_copy_fixture(seed, disk)
        boot(directory, boots["write"], [disk], firmware, transport, ["EXT4_INODE_XATTR_PASS"])
        fsck(disk, directory / "guest-fsck.log")
        assert debug(disk, "cat /native") == b"native ext4 file\n"
        value = directory / "readback"
        debug(disk, f"ea_get -f {quote(str(value))} /native user.small")
        assert value.read_bytes() == bytes(i & 255 for i in range(480))
        kept = directory / "kept"
        debug(disk, f"ea_get -f {quote(str(kept))} /native user.kept")
        assert kept.read_bytes() == b"kept"
        assert b"user.large" not in debug(disk, "ea_list /native")
        before = digest(disk)
        boot(directory, boots["verify"], [disk], firmware, transport, ["EXT4_INODE_XATTR_PASS"])
        assert digest(disk) == before
        row = {"block_size": block, "firmware": firmware, "transport": transport, "disk_sha256": before}
        if checksums:
            row["rejections"] = reject_layouts(directory, seed, entry, block, boots["invalid"],
                                               firmware, transport)
            row["recovery"] = recover_relocation(directory / "relocation-cut", seed, block, boots)
        rows.append(row)
    (out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    print("EXT4_INODE_XATTR_MATRIX_PASS", flush=True)


if __name__ == "__main__":
    main()
