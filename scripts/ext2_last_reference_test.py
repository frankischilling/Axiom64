#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext2_last_reference_test.py
# @brief   Check reclamation when the last filesystem reference drops.
# @author  frankischilling
# @date    2026-11-21
#
# Checks guest and native free counts, journal retry, and recovery around the final reference.
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

"""Verify ext-family inode reclamation at the last reference and after a cut."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

from ext4_extent_test import checksummed_journal, debug, digest, fsck, group_layout
from ext4_orphan_batches_test import clean_oracle, journal_state, replay_only
from ext4_orphan_test import field, images
from ext4_orphan_writer_test import BLOCK, check_inodes, read_block, records
from fetch import ROOT
from fixture_archive import sparse_copy_fixture
from guest_storage_boot import boot, cut_after_write_fault, stop_at_marker, with_write_fault

PASS = "EXT2_LAST_REFERENCE_PASS"
CLIENT = "userspace/tests/fs/ext2-last-reference.c"
PROFILES = (
    ("ext2", "ext2", ("bios", "legacy")),
    ("ext3", "ext3", ("bios", "modern")),
    ("orphan-file", "ext4", ("uefi", "legacy")),
)


def fixture(directory, binary, filesystem):
    directory.mkdir()
    source = directory / "source"
    source.mkdir()
    shutil.copyfile(binary, source / "release-child")
    (source / "release-child").chmod(0o755)
    (source / "victim").write_bytes(b"retained through close\n")
    (source / "independent").write_bytes(b"independent\n")
    disk = directory / "seed.raw"
    with disk.open("xb") as raw:
        raw.truncate(32 * 1024 * 1024)
    options = ["-O", "orphan_file", "-E", "orphan_file_size=1k"] if filesystem == "ext4" else []
    subprocess.run(["mke2fs", "-q", "-F", "-t", filesystem, "-b", str(BLOCK), "-d", source,
                    *options, disk], check=True)
    if filesystem == "ext4":
        checksummed_journal(disk, BLOCK)
    fsck(disk, directory / "seed-fsck.log")
    return disk


def data_bitmap(disk):
    block = int(debug(disk, "bmap /victim 0"))
    header, descriptors, width, _ = group_layout(disk)
    first = struct.unpack_from("<I", header, 20)[0]
    group_size = struct.unpack_from("<I", header, 32)[0]
    with disk.open("rb") as raw:
        raw.seek(descriptors + ((block - first) // group_size) * width)
        return struct.unpack("<I", raw.read(4))[0]


def check_volume(directory, disk, number, orphan, label):
    fsck(disk, directory / f"{label}-fsck.log")
    assert records(disk, orphan) == ([], [], False)
    assert debug(disk, "cat /independent") == b"independent\n"
    check_inodes(directory, disk, [number], False, label)


def recover_pair(directory, disk, number, orphan, iso, firmware, transport):
    checker = clean_oracle(directory, disk)
    check_volume(directory, checker, number, orphan, "native")
    guest = directory / "guest.raw"
    sparse_copy_fixture(disk, guest)
    boot(directory, iso, [guest], firmware, transport, [PASS])
    check_volume(directory, guest, number, orphan, "guest")
    before = digest(guest)
    reboot = directory / "reboot"
    reboot.mkdir()
    boot(reboot, iso, [guest], firmware, transport, [PASS])
    assert digest(guest) == before
    return {"native_sha256": digest(checker), "guest_sha256": before}


def mapped_cut(directory, seed, boot_images, orphan, firmware, transport):
    directory.mkdir()
    number = field(seed, "stat /victim", rb"Inode:\s+(\d+)")
    disk = directory / "cut.raw"
    sparse_copy_fixture(seed, disk)
    stop_at_marker(directory, boot_images["mapping-held"], disk, firmware, transport,
                   "EXT2_LAST_REFERENCE_MAPPING_HELD")
    assert records(disk, orphan) == (([], [number], True) if orphan else ([number], [], False))
    check_inodes(directory, disk, [number], True, "mapped")
    block = int(debug(seed, "bmap /victim 0"))
    assert read_block(disk, block) == read_block(seed, block)
    observed = recover_pair(directory, disk, number, orphan, boot_images["verify"], firmware, transport)
    return {"inode": number, "interrupted_sha256": digest(disk), **observed}


def fault(directory, seed, boot_images, orphan):
    directory.mkdir()
    number = field(seed, "stat /victim", rb"Inode:\s+(\d+)")
    block = data_bitmap(seed)
    sector = block * (BLOCK // 512)
    disk = directory / "cut.raw"
    sparse_copy_fixture(seed, disk)
    cut_after_write_fault(directory, boot_images["pressure"], disk, sector,
                          "EXT2_LAST_REFERENCE_FAULT_ARMED")
    journal = int(debug(seed, "bmap <8> 0"))
    sequence, start = journal_state(disk, journal)
    assert start and read_block(disk, block) == read_block(seed, block)
    observed = replay_only(directory, disk, "journal-only.raw")
    assert records(observed, orphan) == ([], [], bool(orphan))
    check_inodes(directory, observed, [number], False, "journal-only")
    recovered = recover_pair(directory, disk, number, orphan, boot_images["verify"], "bios", "modern")

    retry = directory / "retry"
    retry.mkdir()
    resumed = retry / "disk.raw"
    sparse_copy_fixture(seed, resumed)
    device = with_write_fault(retry, resumed, sector)
    boot(retry, boot_images["recovery"], [device], "bios", "modern", [PASS],
         disk_options=",cache=writethrough,werror=report")
    check_volume(retry, resumed, number, orphan, "same-mount")
    return {"inode": number, "checkpoint_sequence": sequence, "failed_home_block": block,
            "interrupted_sha256": digest(disk), "retry_sha256": digest(resumed), **recovered}


def native_comparison(directory):
    directory.mkdir()
    client = directory / "client"
    disk = directory / "disk.raw"
    with tempfile.TemporaryDirectory(prefix="ax-lastref-") as mount:
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                        "-DNATIVE_TEST", f'-DTOP="{mount}"', CLIENT, "-o", client], check=True)
        seed = fixture(directory / "fixture", client, "ext3")
        sparse_copy_fixture(seed, disk)
        device = subprocess.check_output(["losetup", "--find", "--show", disk], text=True).strip()
        try:
            subprocess.run(["mount", "-t", "ext4", device, mount], check=True)
            try:
                with (directory / "native.log").open("wb") as log:
                    subprocess.run([client], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
            finally:
                subprocess.run(["umount", mount], check=True)
        finally:
            subprocess.run(["losetup", "-d", device], check=True)
        assert not subprocess.check_output(["losetup", "-j", disk])
    assert PASS in (directory / "native.log").read_text().splitlines()
    fsck(disk, directory / "native-fsck.log")
    return {"kernel": subprocess.check_output(["uname", "-r"], text=True).strip(),
            "disk_sha256": digest(disk), "client_sha256": digest(client)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext2-last-reference")
    parser.add_argument("--profile", choices=[name for name, _, _ in PROFILES])
    parser.add_argument("--native", action="store_true", help="run the same checks on a private Linux loop mount")
    args = parser.parse_args()
    out = args.directory.resolve()
    if not out.is_relative_to((ROOT / "build").resolve()):
        parser.error("output must be under build/")
    out.mkdir(parents=True, exist_ok=False)
    boot_images, client = images(out, False, prefix="ext2-last-reference", source=CLIENT,
                                 base_phases=("write", "verify", "pressure", "recovery", "mapping-held"))
    rows = []
    for name, filesystem, (firmware, transport) in PROFILES:
        if args.profile and name != args.profile:
            continue
        directory = out / name
        seed = fixture(directory, client, filesystem)
        orphan = field(seed, "stats", rb"Orphan file inode:\s+(\d+)") if filesystem == "ext4" else 0
        child = field(seed, "stat /release-child", rb"Inode:\s+(\d+)")
        disk = directory / "disk.raw"
        sparse_copy_fixture(seed, disk)
        boot(directory, boot_images["write"], [disk], firmware, transport, [PASS])
        check_volume(directory, disk, child, orphan, "guest")
        row = dict(profile=name, firmware=firmware, transport=transport, sha256=digest(disk))
        if filesystem != "ext2":
            row["mapped_cut"] = mapped_cut(directory / "mapped-cut", seed, boot_images, orphan,
                                           firmware, transport)
            row["fault"] = fault(directory / "fault", seed, boot_images, orphan)
        rows.append(row)
        (out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"EXT2_LAST_REFERENCE_PROFILE_PASS {name}", flush=True)
    if args.native:
        evidence = native_comparison(out / "linux")
        (out / "linux.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print("EXT2_LAST_REFERENCE_NATIVE_PASS", flush=True)


if __name__ == "__main__":
    main()
