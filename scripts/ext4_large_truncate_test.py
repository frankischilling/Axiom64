#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext4_large_truncate_test.py
# @brief   Check journaled shrinking that spans multiple ext4 transactions.
# @author  frankischilling
# @date    2026-11-21
#
# Compares committed shrink records, block counts and data with native recovery.
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

"""Exercise large linked and open-unlinked truncation in an Axiom64 guest."""
import argparse
import json
from pathlib import Path
import struct

from ext4_extent_test import debug, digest, fsck, group_layout
from ext4_orphan_batches_test import clean_oracle, debug_commands, journal_state, make_large_file, replay_only
from ext4_orphan_test import CONTENTS, field, images, set_inode
from ext4_orphan_writer_test import BLOCK, inode_record, read_block, records
from fetch import ROOT
from fixture_archive import sparse_copy_fixture
from guest_storage_boot import boot, cut_after_write_fault, with_write_fault

PASS = "EXT4_TRUNCATE_PASS"
LENGTH = 5000
ORIGINAL_BLOCKS = 275001
FAULT_OPTIONS = ",cache=writethrough,werror=report"


def fixture(directory, extent, orphan_file):
    seed, number, groups = make_large_file(directory, extent, "seed.raw", orphan_file=orphan_file)
    set_inode(seed, "/shrink", "size", ORIGINAL_BLOCKS * BLOCK)
    fsck(seed, directory / "seed-fsck.log")
    orphan = field(seed, "stats", rb"Orphan file inode:\s+(\d+)") if orphan_file else 0
    return seed, number, groups, orphan


def check_file(disk, number, size, sectors):
    inode = inode_record(disk, number)
    assert struct.unpack_from("<H", inode, 26)[0] == 1
    assert struct.unpack_from("<I", inode, 4)[0] == size
    assert struct.unpack_from("<I", inode, 28)[0] == sectors
    assert field(disk, "stat /shrink", rb"Inode:\s+(\d+)") == number
    assert debug(disk, "cat /shrink") == CONTENTS[:size]
    if size:
        physical = int(debug(disk, f"bmap <{number}> {size // BLOCK}"))
        assert physical
        assert not any(read_block(disk, physical)[size % BLOCK:])


def check_clean(directory, disk, number, orphan, mode, label):
    fsck(disk, directory / f"{label}-fsck.log")
    assert records(disk, orphan) == ([], [], False)
    assert debug(disk, "cat /independent") == b"unchanged\n"
    if mode == "unlinked":
        results = debug_commands(directory, disk, label, [f"testi <{number}>", "stat /shrink"])
        assert b"not in use" in results and b"File not found" in results
    else:
        check_file(disk, number, 0 if mode == "open" else LENGTH, 0 if mode == "open" else 10)


def tail_bitmap(disk, number):
    physical = int(debug(disk, f"bmap <{number}> {ORIGINAL_BLOCKS - 1}").split()[0])
    header, descriptors, width, _ = group_layout(disk)
    first = struct.unpack_from("<I", header, 20)[0]
    per_group = struct.unpack_from("<I", header, 32)[0]
    with disk.open("rb") as raw:
        raw.seek(descriptors + ((physical - first) // per_group) * width)
        return struct.unpack("<I", raw.read(4))[0]


def normal(directory, seed, number, orphan, boots, mode, spec, block=None):
    directory.mkdir()
    disk = directory / "disk.raw"
    sparse_copy_fixture(seed, disk)
    if block is None:
        boot(directory, boots[mode], [disk], *spec, [PASS])
    else:
        device = with_write_fault(directory, disk, block * (BLOCK // 512))
        boot(directory, boots[mode], [device], *spec, [PASS], disk_options=FAULT_OPTIONS)
    check_clean(directory, disk, number, orphan, mode, "guest")
    return digest(disk)


def cut(directory, seed, number, orphan, boots, block, initial):
    directory.mkdir()
    disk = directory / "cut.raw"
    sparse_copy_fixture(seed, disk)
    original_sectors = field(seed, "stat /shrink", rb"Blockcount:\s+(\d+)")
    cut_after_write_fault(directory, boots["cut"], disk, block * (BLOCK // 512),
                          "EXT4_TRUNCATE_HOME_FAULT")
    assert read_block(disk, block) == read_block(seed, block)
    journal = int(debug(seed, "bmap <8> 0"))
    sequence, start = journal_state(disk, journal)
    assert start
    observed = replay_only(directory, disk, "journal-only.raw")
    expected = ([], [number], True) if orphan else ([number], [], False)
    assert records(observed, orphan) == expected
    remaining = field(observed, "stat /shrink", rb"Blockcount:\s+(\d+)")
    if initial:
        assert remaining == original_sectors
    else:
        assert 10 < remaining < original_sectors
    check_file(observed, number, LENGTH, remaining)
    checker = clean_oracle(directory, disk)
    check_clean(directory, checker, number, orphan, "verify", "native")
    guest = directory / "guest.raw"
    sparse_copy_fixture(disk, guest)
    boot(directory, boots["verify"], [guest], "bios", "modern", [PASS])
    check_clean(directory, guest, number, orphan, "verify", "guest")
    checked = digest(guest)
    reboot = directory / "reboot"
    reboot.mkdir()
    boot(reboot, boots["verify"], [guest], "bios", "modern", [PASS])
    assert digest(guest) == checked
    return {"sequence": sequence, "original_sectors": original_sectors,
            "remaining_sectors": remaining, "failed_home_block": block,
            "interrupted_sha256": digest(disk), "guest_sha256": checked}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext4-large-truncate")
    parser.add_argument("--profile", choices=("indirect", "extent-orphan-file"))
    args = parser.parse_args()
    output = args.directory.resolve()
    if not output.is_relative_to((ROOT / "build").resolve()):
        parser.error("output must be under build/")
    output.mkdir(parents=True, exist_ok=False)
    phases = {"fd": "write", "path": "io", "open": "cache", "unlinked": "cond",
              "retry": "recovery", "cut": "pressure", "verify": "verify"}
    iso, _ = images(output, False, prefix="ext4-large-truncate", base_phases=phases.values(),
                    source="userspace/tests/fs/ext4-large-truncate.c")
    boots = {mode: iso[phase] for mode, phase in phases.items()}
    results = []
    for profile, extent, spec in (("indirect", False, ("bios", "modern")),
                                  ("extent-orphan-file", True, ("uefi", "legacy"))):
        if args.profile and args.profile != profile:
            continue
        directory = output / profile
        directory.mkdir()
        seed, number, groups, orphan = fixture(directory, extent, extent)
        row = {"profile": profile, "inode": number, "groups": groups}
        for mode in ("fd", "path", "open", "unlinked"):
            row[mode] = normal(directory / mode, seed, number, orphan, boots, mode, spec)
        bitmap = tail_bitmap(seed, number)
        row["partial"] = cut(directory / "partial", seed, number, orphan, boots, bitmap, False)
        row["retry"] = normal(directory / "retry", seed, number, orphan, boots, "retry", spec, bitmap)
        if orphan:
            slot = int(debug(seed, f"bmap <{orphan}> 0"))
            row["publication"] = cut(directory / "publication", seed, number, orphan, boots, slot, True)
        results.append(row)
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"EXT4_LARGE_TRUNCATE_PROFILE_PASS {profile}", flush=True)


if __name__ == "__main__":
    main()
