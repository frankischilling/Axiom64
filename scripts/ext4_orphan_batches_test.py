#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext4_orphan_batches_test.py
# @brief   Exercise ext4 orphan cleanup across journal transactions.
# @author  frankischilling
# @date    2026-11-21
#
# Reopens durable interrupted batches and compares recovery with e2fsprogs.
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

"""Reopen interrupted ext4 cleanup on a small internal journal."""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from ext4_extent_test import debug, digest, fsck, group_layout, inode_offset
from ext4_orphan_test import CONTENTS, field, images, reject, set_inode, set_super, slot_block
from fetch import ROOT
from fixture_archive import sparse_copy_fixture
from guest_storage_boot import boot, cut_after_write_fault

ORPHANS = 4100
BLOCK = 1024
SLOT_COUNT = (BLOCK - 8) // 4


def debug_commands(directory, disk, name, commands, write=False):
    source = directory / f"{name}.debugfs"
    source.write_text("".join(f"{command}\n" for command in commands))
    result = subprocess.run(["debugfs", *(["-w"] if write else []), "-f", source, disk],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    (directory / f"{name}.log").write_bytes(result.stdout)
    return result.stdout


def mkfs(disk, source, features, size, *options):
    with disk.open("wb") as raw:
        raw.truncate(size * 1024 ** 2)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", str(BLOCK), "-J", "size=1",
                    "-O", "none,filetype,sparse_super,has_journal," + features,
                    "-d", source, *options, disk], check=True)


def arm(disk, orphan_file=False, head=0):
    header = group_layout(disk)[0]
    incompat, readonly = struct.unpack_from("<II", header, 96)
    set_super(disk, "feature_incompat", incompat | 4)
    if orphan_file:
        set_super(disk, "feature_ro_compat", readonly | 0x10000)
    if head:
        set_super(disk, "last_orphan", head)


def make_list(directory, file_format):
    disk = directory / "pending.raw"
    with tempfile.TemporaryDirectory(prefix="ext4-orphan-batches-") as scratch:
        source = Path(scratch)
        detached = source / "retired"
        detached.mkdir()
        for i in range(ORPHANS):
            (detached / f"n{i:05}").touch()
        features = "extent,metadata_csum"
        if file_format:
            features += ",orphan_file"
        mkfs(disk, source, features, 48, "-I", "256", "-N", "8192")
    fsck(disk, directory / "before-fsck.log")
    entries = sorted((int(number), name.decode()) for number, name in re.findall(
        rb"^/(\d+)/[^/]+/[^/]+/[^/]+/(n\d{5})/", debug(disk, "ls -p /retired"), re.M))
    if len(entries) != ORPHANS:
        raise RuntimeError("incorrect native orphan allocation count")
    commands = []
    numbers = []
    for number, name in entries:
        commands += [f"unlink /retired/{name}", f"set_inode_field <{number}> links_count 0"]
        numbers.append(number)
    if not file_format:
        commands += [f"set_inode_field <{number}> dtime {following}"
                     for number, following in zip(numbers, numbers[1:])]
    debug_commands(directory, disk, "unlink", commands, write=True)
    if file_format:
        orphan = field(disk, "stats", rb"Orphan file inode:\s+(\d+)")
        for logical, start in enumerate(range(0, ORPHANS, SLOT_COUNT)):
            values = numbers[start:start + SLOT_COUNT]
            slot_block(disk, orphan,
                       lambda data: struct.pack_into(f"<{len(values)}I", data, 0, *values),
                       offset=logical)
        arm(disk, orphan_file=True)
    else:
        orphan = 0
        arm(disk, head=numbers[0])
    # Linux can have newer allocated bits and group counts than the primary superblock.
    free_blocks, free_inodes = struct.unpack_from("<II", group_layout(disk)[0], 12)
    set_super(disk, "free_blocks_count", free_blocks + 17)
    set_super(disk, "free_inodes_count", free_inodes + 29)
    return disk, numbers, orphan


def journal_state(disk, physical=None):
    if physical is None:
        physical = int(debug(disk, "bmap <8> 0"))
    with disk.open("rb") as raw:
        raw.seek(physical * BLOCK + 24)
        return struct.unpack(">II", raw.read(8))


def crash_at_inode(directory, seed, inode, pressure):
    directory.mkdir()
    disk = directory / "interrupted.raw"
    sparse_copy_fixture(seed, disk)
    journal = int(debug(seed, "bmap <8> 0"))
    _, start = journal_state(disk, journal)
    if start:
        raise RuntimeError("cleanup input already has a live journal")
    table = inode_offset(disk, f"<{inode}>", BLOCK) // BLOCK
    with disk.open("rb") as raw:
        raw.seek(table * BLOCK)
        prior = raw.read(BLOCK)
    cut_after_write_fault(directory, pressure, disk, table * 2, "EXT4_ORPHAN_HOME_WRITE_FAULT")
    with disk.open("rb") as raw:
        raw.seek(table * BLOCK)
        if raw.read(BLOCK) != prior:
            raise RuntimeError("target home inode table changed before the fault")
    sequence, start = journal_state(disk, journal)
    if not start:
        raise RuntimeError("fault did not retain a committed cleanup journal")
    return disk, sequence


def replay_only(directory, original, name):
    repaired = directory / name
    sparse_copy_fixture(original, repaired)
    with (directory / (name + ".log")).open("wb") as log:
        subprocess.run(["debugfs", "-n", "-w", "-R", "journal_run", repaired], check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    if journal_state(repaired)[1]:
        raise RuntimeError(f"native journal reader did not checkpoint {name}")
    return repaired


def clean_oracle(directory, original):
    repaired = directory / "checker.raw"
    sparse_copy_fixture(original, repaired)
    with (directory / "checker.raw.log").open("wb") as log:
        result = subprocess.run(["e2fsck", "-fy", repaired], stdout=log,
                                stderr=subprocess.STDOUT)
    if result.returncode not in (0, 1):
        raise RuntimeError("native orphan recovery failed")
    return repaired


def resume(directory, disk, image):
    guest = directory / "guest.raw"
    sparse_copy_fixture(disk, guest)
    boot(directory, image, [guest], "bios", "modern", ["EXT4_ORPHAN_RECOVERY_PASS"])
    fsck(guest, directory / "guest-fsck.log")
    before = digest(guest)
    reboot = directory / "reboot"
    reboot.mkdir()
    boot(reboot, image, [guest], "bios", "modern", ["EXT4_ORPHAN_RECOVERY_PASS"])
    if digest(guest) != before:
        raise RuntimeError("clean read-only reboot changed disk bytes")
    return guest


def check_empty_records(disk):
    header = group_layout(disk)[0]
    if struct.unpack_from("<I", header, 232)[0] or struct.unpack_from("<I", header, 100)[0] & 0x10000:
        raise RuntimeError("orphan records remain in the superblock")


def damage_group_count(disk):
    _, descriptors, _, _ = group_layout(disk)
    with disk.open("rb") as raw:
        raw.seek(descriptors + 12)
        free, = struct.unpack("<H", raw.read(2))
    debug(disk, f"set_block_group 0 free_blocks_count {free + 1}", write=True)
    debug(disk, "set_block_group 0 checksum calc", write=True)


def verify_many(directory, images, file_format):
    directory.mkdir()
    seed, numbers, orphan = make_list(directory, file_format)
    if orphan:
        last, slot = divmod(ORPHANS - 1, SLOT_COUNT)
        reject(directory / "invalid-last", seed, images["invalid"],
               lambda disk: slot_block(disk, orphan,
                                       lambda data: struct.pack_into("<I", data, 4 * slot, numbers[0]),
                                       offset=last))
        reject(directory / "invalid-group-count", seed, images["invalid"], damage_group_count)
    initial, _ = journal_state(seed)
    fault = directory / "cut"
    interrupted, sequence = crash_at_inode(fault, seed, numbers[-1], images["pressure"])
    # One transaction refreshes the stale totals before the cleanup batches.
    first_offset = inode_offset(seed, f"<{numbers[0]}>", BLOCK)
    with interrupted.open("rb") as raw:
        raw.seek(first_offset)
        early_inode_mode = raw.read(2)
    if sequence <= initial + 1 or early_inode_mode != b"\0\0":
        raise RuntimeError("fault occurred before any cleanup batch was checkpointed")
    inspected = replay_only(fault, interrupted, "between-batches.raw")
    session = debug_commands(fault, inspected, "between-first-last",
                             [f"testi <{numbers[0]}>", f"testi <{numbers[-1]}>"])
    if session.count(b"not in use") != 2:
        # A late batch need not be the last one, but it already removed its target.
        raise RuntimeError("committed batches did not release the first and last tested inode")
    checker = clean_oracle(fault, interrupted)
    fsck(checker, fault / "checker-fsck.log")
    guest = resume(fault, interrupted, images["queue"])
    for name, disk in (("guest", guest), ("native", checker)):
        check_empty_records(disk)
        records = debug_commands(fault, disk, f"{name}-allocation",
                                 [f"testi <{number}>" for number in numbers])
        if records.count(b"not in use") != ORPHANS:
            raise RuntimeError(f"{name} still has an allocated orphan")
    return {"orphan_count": ORPHANS, "committed_sequence": sequence,
            "initial_sequence": initial, "interrupted_sha256": digest(interrupted),
            "guest_sha256": digest(guest)}


def make_large_file(directory, extent, name, *, orphan_file=False):
    disk = directory / name
    with tempfile.TemporaryDirectory(prefix="ext4-orphan-truncate-") as scratch:
        source = Path(scratch)
        (source / "shrink").write_bytes(CONTENTS)
        (source / "independent").write_bytes(b"unchanged\n")
        features = "large_file,metadata_csum" + (",extent" if extent else "")
        options = ["-g", "256", "-I", "128"]
        if orphan_file:
            features += ",orphan_file"
            options += ["-E", "orphan_file_size=1k"]
        mkfs(disk, source, features, 300, *options)
    inode = field(disk, "stat /shrink", rb"Inode:\s+(\d+)")
    debug(disk, "fallocate /shrink 18 275000", write=True)
    allocated = debug(disk, f"blocks <{inode}>").split()
    groups = {(int(item) - 1) // 256 for item in allocated}
    if len(groups) < 1050:
        raise RuntimeError(f"native allocation reached only {len(groups)} block groups")
    return disk, inode, len(groups)


def make_truncate(directory, extent):
    disk, inode, groups = make_large_file(directory, extent, "pending.raw")
    set_inode(disk, "/shrink", "size", 5000)
    arm(disk, head=inode)
    return disk, inode, groups


def count_blocks(disk):
    return field(disk, "stat /shrink", rb"Blockcount:\s+(\d+)")


def verify_partial(directory, images, extent):
    directory.mkdir()
    seed, number, groups = make_truncate(directory, extent)
    before = count_blocks(seed)
    fault = directory / "cut"
    interrupted, sequence = crash_at_inode(fault, seed, number, images["pressure"])
    inspected = replay_only(fault, interrupted, "partial.raw")
    partial = count_blocks(inspected)
    header = group_layout(inspected)[0]
    if struct.unpack_from("<I", header, 232)[0] != number or not 10 < partial < before:
        raise RuntimeError("partial transaction lost its orphan or made no block progress")
    if debug(inspected, "cat /shrink") != CONTENTS[:5000]:
        raise RuntimeError("partial transaction changed bytes inside the stored length")
    checker = clean_oracle(fault, interrupted)
    fsck(checker, fault / "checker-fsck.log")
    guest = resume(fault, interrupted, images["verify"])
    for disk in (checker, guest):
        check_empty_records(disk)
        if count_blocks(disk) != 10 or debug(disk, "cat /shrink") != CONTENTS[:5000]:
            raise RuntimeError("final linked truncation differs from expected bytes or blocks")
    return {"groups": groups, "sectors_before": before, "sectors_in_partial": partial,
            "committed_sequence": sequence, "interrupted_sha256": digest(interrupted),
            "guest_sha256": digest(guest)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext4-orphan-batches")
    parser.add_argument("--profile", choices=("file-list", "legacy-list", "extents", "indirect"))
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to((ROOT / "build").resolve()):
        parser.error("output must be under build/")
    directory.mkdir(parents=True, exist_ok=False)
    boot_images, _ = images(directory, False, ("queue",), "ext4-orphan-batches")
    scenarios = (("file-list", verify_many, True), ("legacy-list", verify_many, False),
                 ("extents", verify_partial, True), ("indirect", verify_partial, False))
    rows = []
    for name, run, value in scenarios:
        if args.profile and args.profile != name:
            continue
        result = run(directory / name, boot_images, value)
        rows.append({"profile": name, **result})
        (directory / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"EXT4_ORPHAN_BATCH_PROFILE_PASS {name}", flush=True)


if __name__ == "__main__":
    main()
