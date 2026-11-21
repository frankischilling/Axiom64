#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext4_orphan_writer_test.py
# @brief   Check native orphan records written by an Axiom64 guest.
# @author  frankischilling
# @date    2026-11-21
#
# Observes live orphan records, interrupted commits and independent recovery.
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

"""Check QEMU-written ext4 orphan records, interruption and clean shutdown."""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from ext4_extent_test import checksummed_journal, crc32c, debug, digest, fsck, group_layout, inode_offset
from ext4_orphan_batches_test import clean_oracle, debug_commands, journal_state, make_large_file, replay_only
from ext4_orphan_test import field, images, set_inode
from fetch import ROOT
from fixture_archive import sparse_copy_fixture
from guest_storage_boot import boot, cut_after_write_fault, stop_at_marker

BLOCK = 1024
SLOTS = (BLOCK - 8) // 4
ARMED = "EXT4_ORPHAN_WRITER_ARMED"
PASS = "EXT4_ORPHAN_WRITER_PASS"


def fixture(directory, file_format):
    seed = directory / "seed.raw"
    with seed.open("xb") as raw:
        raw.truncate(32 * 1024 * 1024)
    source = directory / "source"
    source.mkdir()
    (source / "victim").write_bytes(b"victim\n")
    (source / "replacement").write_bytes(b"replacement\n")
    (source / "independent").write_bytes(b"unrelated\n")
    options = ["-O", "orphan_file", "-E", "orphan_file_size=1k"] if file_format else []
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", str(BLOCK), "-d", source,
                    *options, seed], check=True)
    checksummed_journal(seed, BLOCK)
    fsck(seed, directory / "seed-fsck.log")
    orphan = field(seed, "stats", rb"Orphan file inode:\s+(\d+)") if file_format else 0
    return seed, orphan


def inode_record(disk, number):
    offset = inode_offset(disk, f"<{number}>", BLOCK)
    with disk.open("rb") as raw:
        raw.seek(offset)
        return raw.read(128)


def read_block(disk, block):
    with disk.open("rb") as raw:
        raw.seek(block * BLOCK)
        return raw.read(BLOCK)


def records(disk, orphan):
    header = group_layout(disk)[0]
    next_inode = struct.unpack_from("<I", header, 232)[0]
    chain = []
    while next_inode:
        assert next_inode not in chain, "orphan chain cycle"
        chain.append(next_inode)
        next_inode = struct.unpack_from("<I", inode_record(disk, next_inode), 20)[0]
    present = bool(struct.unpack_from("<I", header, 100)[0] & 0x10000)
    if not orphan:
        assert not present
        return chain, [], False
    assert field(disk, f"stat <{orphan}>", rb"Size:\s+(\d+)") == BLOCK
    physical = int(debug(disk, f"bmap <{orphan}> 0"))
    data = read_block(disk, physical)
    magic, stored = struct.unpack_from("<II", data, BLOCK - 8)
    assert magic == 0x0b10ca04
    generation = inode_record(disk, orphan)[100:104]
    incompat = struct.unpack_from("<I", header, 96)[0]
    seed = (struct.unpack_from("<I", header, 624)[0] if incompat & 0x2000 else
            crc32c(0xffffffff, header[104:120]))
    checksum = crc32c(seed, struct.pack("<I", orphan) + generation + struct.pack("<Q", physical))
    assert stored == crc32c(checksum, data[:-8]), "orphan block checksum mismatch"
    slots = list(filter(None, struct.unpack(f"<{SLOTS}I", data[:-8])))
    assert not slots or present
    assert len(chain) + len(slots) == len(set(chain + slots))
    return chain, slots, present


def check_inodes(directory, disk, numbers, allocated, name):
    commands = [f"testi <{number}>" for number in numbers]
    output = debug_commands(directory, disk, name, commands)
    expected = b"marked in use" if allocated else b"not in use"
    assert output.count(expected) == len(numbers), (name, numbers)
    if allocated:
        for number in numbers:
            inode = inode_record(disk, number)
            assert struct.unpack_from("<H", inode, 26)[0] == 0


def check_clean(directory, disk, orphan, numbers, name, fault):
    fsck(disk, directory / f"{name}-fsck.log")
    assert records(disk, orphan) == ([], [], False)
    check_inodes(directory, disk, numbers, False, name)
    assert debug(disk, "cat /independent") == b"unrelated\n"
    if fault:
        assert b"File not found" in debug_commands(directory, disk, f"{name}-namespace",
                                                    ["stat /victim"])
    else:
        assert debug(disk, "cat /victim") == b"replacement\n"


def resume(directory, disk, orphan, numbers, verify, spec, fault=False):
    firmware, transport = spec
    oracle = clean_oracle(directory, disk)
    check_clean(directory, oracle, orphan, numbers, "native", fault)
    guest = directory / "guest.raw"
    sparse_copy_fixture(disk, guest)
    boot(directory, verify, [guest], firmware, transport, [PASS])
    check_clean(directory, guest, orphan, numbers, "guest", fault)
    before = digest(guest)
    reboot = directory / "reboot"
    reboot.mkdir()
    boot(reboot, verify, [guest], firmware, transport, [PASS])
    assert digest(guest) == before
    return {"input_sha256": digest(disk), "guest_sha256": before, "native_sha256": digest(oracle)}


def hold(directory, seed, orphan, boot_images, name, spec):
    directory.mkdir()
    disk = directory / "cut.raw"
    sparse_copy_fixture(seed, disk)
    output = stop_at_marker(directory, boot_images[name], disk, *spec, ARMED)
    match = re.search(r"^EXT4_ORPHAN_WRITER_INODES (\d+) (\d+) (\d+)$", output, re.M)
    assert match
    first, middle, last = map(int, match.groups())
    chain, slots, present = records(disk, orphan)
    if name == "full":
        assert chain == [last, first] and len(slots) == SLOTS and present
    elif orphan:
        assert not chain and slots == [first, last] and present
    else:
        assert chain == [last, first] and not slots and not present
    assert not journal_state(disk)[1]
    check_inodes(directory, disk, chain + slots, True, "held")
    check_inodes(directory, disk, [middle], False, "closed")
    return {"chain": chain, "slots": slots, "closed": middle,
            **resume(directory, disk, orphan, chain + slots + [middle], boot_images["verify"], spec)}


def fault(directory, seed, orphan, boot_images):
    directory.mkdir()
    disk = directory / "cut.raw"
    sparse_copy_fixture(seed, disk)
    victim = field(seed, "stat /victim", rb"Inode:\s+(\d+)")
    block = int(debug(seed, f"bmap <{orphan}> 0"))
    cut_after_write_fault(directory, boot_images["fault"], disk, block * (BLOCK // 512),
                          "EXT4_ORPHAN_WRITER_HOME_FAULT")
    journal = int(debug(seed, "bmap <8> 0"))
    assert read_block(disk, block) == read_block(seed, block) and journal_state(disk, journal)[1]
    inspected = replay_only(directory, disk, "journal-only.raw")
    assert records(inspected, orphan) == ([], [victim], True)
    assert b"File not found" in debug_commands(directory, inspected, "journal-namespace",
                                                ["stat /victim"])
    check_inodes(directory, inspected, [victim], True, "journal-only")
    return {"committed_inode": victim, "failed_home_block": block,
            **resume(directory, disk, orphan, [victim], boot_images["verify-fault"],
                     ("bios", "modern"), fault=True)}


def clean(directory, seed, orphan, boot_images, mode, spec):
    directory.mkdir()
    disk = directory / "disk.raw"
    sparse_copy_fixture(seed, disk)
    output = boot(directory, boot_images[mode], [disk], *spec, [PASS])
    match = re.search(r"^EXT4_ORPHAN_WRITER_INODES (\d+) (\d+) (\d+)$", output, re.M)
    assert match
    numbers = list(map(int, match.groups()))
    check_clean(directory, disk, orphan, numbers, mode, fault=False)
    return {"inodes": numbers, "clean_sha256": digest(disk)}


def verify_large(directory, disk, number, renamed=False):
    fsck(disk, directory / "guest-fsck.log")
    assert records(disk, 0) == ([], [], False)
    check_inodes(directory, disk, [number], False, "guest")
    if renamed:
        assert debug(disk, "cat /shrink") == b"new"
    else:
        assert b"File not found" in debug_commands(directory, disk, "namespace", ["stat /shrink"])
    assert debug(disk, "cat /independent") == b"unchanged\n"


def large_cut(directory, seed, number, boot_images):
    directory.mkdir()
    disk = directory / "cut.raw"
    sparse_copy_fixture(seed, disk)
    last_block = int(debug(seed, f"bmap <{number}> 275000").split()[0])
    header, descriptors, descriptor_size, _ = group_layout(seed)
    first = struct.unpack_from("<I", header, 20)[0]
    per_group = struct.unpack_from("<I", header, 32)[0]
    with seed.open("rb") as raw:
        raw.seek(descriptors + ((last_block - first) // per_group) * descriptor_size)
        bitmap, = struct.unpack("<I", raw.read(4))
    cut_after_write_fault(directory, boot_images["large-fault"], disk, bitmap * (BLOCK // 512),
                          "EXT4_ORPHAN_WRITER_LARGE_ARMED")
    journal = int(debug(seed, "bmap <8> 0"))
    assert read_block(disk, bitmap) == read_block(seed, bitmap) and journal_state(disk, journal)[1]
    inspected = replay_only(directory, disk, "journal-only.raw")
    assert records(inspected, 0) == ([number], [], False)
    check_inodes(directory, inspected, [number], True, "partial")
    sectors = field(inspected, f"stat <{number}>", rb"Blockcount:\s+(\d+)")
    assert 0 < sectors < field(seed, f"stat <{number}>", rb"Blockcount:\s+(\d+)")
    assert b"File not found" in debug_commands(directory, inspected, "partial-namespace",
                                                ["stat /shrink"])
    oracle = clean_oracle(directory, disk)
    native = directory / "native"
    native.mkdir()
    verify_large(native, oracle, number)
    guest = directory / "guest.raw"
    sparse_copy_fixture(disk, guest)
    boot(directory, boot_images["large-verify"], [guest], "bios", "modern", [PASS])
    verify_large(directory, guest, number)
    return {"orphan": number, "failed_home_block": bitmap, "remaining_sectors": sectors,
            "input_sha256": digest(disk), "guest_sha256": digest(guest)}


def large(directory, boot_images, extent):
    directory.mkdir()
    seed, number, groups = make_large_file(directory, extent, "seed.raw")
    set_inode(seed, "/shrink", "size", 275001 * BLOCK)
    fsck(seed, directory / "seed-fsck.log")
    mode = "large-held" if extent else "large-closed"
    result = {"inode": number, "groups": groups}
    for operation in (mode, "large-rename"):
        tested = directory / operation
        tested.mkdir()
        disk = tested / "disk.raw"
        sparse_copy_fixture(seed, disk)
        boot(tested, boot_images[operation], [disk], "bios", "modern", [PASS])
        verify_large(tested, disk, number, renamed=operation == "large-rename")
        result[operation] = digest(disk)
    if extent:
        result["cut"] = large_cut(directory / "cut", seed, number, boot_images)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext4-orphan-writer")
    parser.add_argument("--profile", choices=("legacy", "file", "large"))
    args = parser.parse_args()
    output = args.directory.resolve()
    if not output.is_relative_to((ROOT / "build").resolve()):
        parser.error("output must be under build/")
    output.mkdir(parents=True, exist_ok=False)
    phases = {"hold": "write", "full": "full", "clean": "io", "shutdown": "recovery",
              "fault": "pressure", "verify": "verify", "verify-fault": "readonly",
              "large-closed": "cache", "large-held": "queue", "large-rename": "cond",
              "large-fault": "invalid", "large-verify": "error"}
    iso, _ = images(output, False, prefix="ext4-orphan-writer", base_phases=phases.values(),
                    source="userspace/tests/fs/ext4-orphan-writer.c")
    boot_images = {mode: iso[phase] for mode, phase in phases.items()}
    rows = []
    for layout, spec in (("legacy", ("uefi", "legacy")), ("file", ("bios", "modern"))):
        if args.profile and args.profile != layout:
            continue
        directory = output / layout
        directory.mkdir()
        seed, orphan = fixture(directory, layout == "file")
        data = {"hold": hold(directory / "hold", seed, orphan, boot_images, "hold", spec)}
        for mode in ("clean", "shutdown"):
            data[mode] = clean(directory / mode, seed, orphan, boot_images, mode, spec)
        if orphan:
            data["full"] = hold(directory / "full", seed, orphan, boot_images, "full", spec)
            data["fault"] = fault(directory / "fault", seed, orphan, boot_images)
        rows.append({"profile": layout, **data})
        (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"EXT4_ORPHAN_WRITER_PROFILE_PASS {layout}", flush=True)
    if args.profile in (None, "large"):
        for label, extent in (("indirect", False), ("extents", True)):
            rows.append({"profile": label, **large(output / label, boot_images, extent)})
            (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
            print(f"EXT4_ORPHAN_WRITER_PROFILE_PASS {label}", flush=True)


if __name__ == "__main__":
    main()
