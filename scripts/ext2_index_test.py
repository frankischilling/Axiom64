#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext2_index_test.py
# @brief   Verify Linux-compatible indexed ext directories across guest boots.
# @author  frankischilling
# @date    2026-11-20
#
# Builds native trees and checks guest mutations with independent filesystem tools.
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

"""Exercise real indexed ext2 and ext3 directories with independent host checks."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

from account_normal_test import write_cpio
from fetch import ROOT
from guest_storage_boot import boot

SEEDS = 270
NEW = 660
CONVERTED = 50
COLLISION_NAMES = (1, 3, 41574, 59571, 0)
HASH_VERSIONS = {"legacy": 0, "half_md4": 1, "tea": 2}
PROFILES = (
    ("legacy", False, 1024, "bios", "modern", False),
    ("half_md4", True, 1024, "uefi", "modern", True),
    ("tea", False, 2048, "bios", "legacy", False),
    ("tea", True, 4096, "uefi", "legacy", True),
    ("legacy", True, 2048, "bios", "modern", False),
    ("half_md4", False, 4096, "uefi", "modern", True),
)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def name(prefix, index):
    start = ("é" if index % 7 == 0 else "") + f"{prefix}{index:04d}-"
    return start + chr(ord("a") + index * 7 % 26) * (237 + index % 11 - len(start.encode()))


def debug(disk, command, write=False):
    return subprocess.check_output(["debugfs", *(["-w"] if write else []), "-R", command, disk],
                                   stderr=subprocess.PIPE)


def fixture(directory, disk, block_size, algorithm, unsigned, journal):
    with tempfile.TemporaryDirectory(prefix="ext2-index-") as source:
        root = Path(source)
        (root / "index").mkdir()
        (root / "target").mkdir()
        for i in range(SEEDS):
            (root / "index" / name("s", i)).write_bytes(b"s")
        with disk.open("wb") as output:
            output.truncate(48 * 1024 * 1024)
        features = "none,filetype,sparse_super,large_file,dir_index"
        if journal:
            features += ",has_journal"
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext3" if journal else "ext2",
                        "-b", str(block_size), "-I", "128", "-N", "4096", "-O", features,
                        "-E", "hash_seed=01234567-89ab-cdef-0123-456789abcdef,root_owner=0:0",
                        "-d", root, disk], check=True)
    debug(disk, f"set_super_value def_hash_version {algorithm}", write=True)
    debug(disk, f"set_super_value flags {2 if unsigned else 1}", write=True)
    with disk.open("rb") as source:
        source.seek(1024 + 252)
        if source.read(1) != bytes([HASH_VERSIONS[algorithm]]):
            raise RuntimeError(f"{disk}: wrong default directory hash")
        source.seek(1024 + 352)
        if struct.unpack("<I", source.read(4))[0] & 3 != (2 if unsigned else 1):
            raise RuntimeError(f"{disk}: wrong directory hash signedness")
    with (directory / "native-index-build.log").open("wb") as log:
        result = subprocess.run(["e2fsck", "-fyD", disk], stdout=log, stderr=subprocess.STDOUT)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"{disk}: native index construction failed")
    return inspect_index(disk, "/index", directory / "native-index.log", algorithm)


def inspect_index(disk, path, logfile, algorithm):
    data = debug(disk, "htree_dump " + path)
    logfile.write_bytes(data)
    levels = re.search(rb"Indirect levels: (\d+)", data)
    count = re.search(rb"Number of entries \(count\): (\d+)", data)
    version = re.search(rb"Hash Version: (\d+)", data)
    if not levels or not count or not version or int(version[1]) != HASH_VERSIONS[algorithm]:
        raise RuntimeError(f"{disk}: missing indexed directory at {path}")
    return int(levels[1]), int(count[1])


def images(directory, kernel, archive):
    result = {}
    for phase in ("write", "verify", "invalid"):
        name = f"ext2-index-{phase}.iso"
        with (directory / f"{phase}-image.log").open("wb") as log:
            subprocess.run([sys.executable, "-B", "scripts/image.py", "--test", "--suite", "storage",
                            "--phase", phase, "--kernel", kernel, "--initramfs", archive,
                            "--output-directory", directory, "--output-name", name],
                           cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
        result[phase] = directory / name
    return result


def verify_host(directory, disk):
    with (directory / "host-fsck.log").open("wb") as log:
        subprocess.run(["e2fsck", "-fn", disk], check=True, stdout=log, stderr=subprocess.STDOUT)
    with tempfile.TemporaryDirectory(prefix="ext2-index-export-") as source:
        debug(disk, f"rdump /target/index {source}")
        debug(disk, f"rdump /target/converted {source}")
        debug(disk, f"rdump /target/collision {source}")
        result = {p.name: p.read_bytes() for p in (Path(source) / "index").iterdir()}
        converted = {p.name: p.read_bytes() for p in (Path(source) / "converted").iterdir()}
        collision = {p.name: p.read_bytes() for p in (Path(source) / "collision").iterdir()}
    expected = {name("s", i): b"s" for i in range(SEEDS) if i != 1}
    expected.update({name("n", i): b"n" for i in range(1, NEW)})
    expected["alias"] = b"s"
    if result != expected or converted != {name("c", i): b"c" for i in range(CONVERTED)}:
        raise RuntimeError(f"{disk}: host export differs")
    if collision != {f"x{index:07}-" + "z" * 231: str(i).encode()
                     for i, index in enumerate(COLLISION_NAMES)}:
        raise RuntimeError(f"{disk}: host collision directory export differs")


def damaged(directory, seed, iso):
    physical = int(debug(seed, "bmap /index 0").strip())
    for case, offset, payload in (
            ("count", 34, struct.pack("<H", 0xffff)),
            ("duplicate", 44, None),
            ("range", 40, struct.pack("<I", 2))):
        work = directory / case
        work.mkdir()
        disk = work / "disk.raw"
        shutil.copyfile(seed, disk)
        with disk.open("r+b") as output:
            base = physical * 1024
            if payload is None:
                output.seek(base + 36)
                payload = output.read(4)
            output.seek(base + offset)
            output.write(payload)
        before = digest(disk)
        boot(work, iso, [disk], "bios", "modern", ["EXT2_INDEX_REJECT_PASS"])
        if digest(disk) != before:
            raise RuntimeError(f"{disk}: rejected mount wrote to the disk")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext2-index")
    parser.add_argument("--profile", type=int, choices=range(len(PROFILES)))
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to((ROOT / "build").resolve()):
        parser.error("--directory must be under build/")
    directory.mkdir(parents=True)
    kernel = ROOT / "build/axiom64.elf"
    client = directory / "ext2-index"
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    subprocess.run(["musl-gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                    "userspace/tests/fs/ext2-index.c", "-o", client], cwd=ROOT, check=True)
    archive = directory / "initramfs.cpio"
    files = {n: (0o40755, b"") for n in ("dev", "proc", "run", "sbin", "sys", "tmp")}
    files["sbin/init"] = 0o100755, client.read_bytes()
    write_cpio(archive, files)
    boot_images = images(directory, kernel, archive)
    rows = []
    selected = range(len(PROFILES)) if args.profile is None else (args.profile,)
    for profile in selected:
        algorithm, unsigned, block_size, firmware, transport, journal = PROFILES[profile]
        case = directory / f"{profile}-{algorithm}"
        case.mkdir()
        disk = case / "disk.raw"
        before, _ = fixture(case, disk, block_size, algorithm, unsigned, journal)
        if profile == 0:
            if before:
                raise RuntimeError("root promotion fixture already has indirect index nodes")
            damaged(case, disk, boot_images["invalid"])
        boot(case, boot_images["write"], [disk], firmware, transport, ["EXT2_INDEX_MUTATE_PASS"])
        after, root_entries = inspect_index(disk, "/target/index", case / "guest-index.log",
                                            algorithm)
        inspect_index(disk, "/target/converted", case / "converted-index.log", algorithm)
        if profile == 0 and (after != 1 or root_entries < 2):
            raise RuntimeError("guest growth did not promote the index root and split a child")
        if profile == 0:
            collision = debug(disk, "htree_dump /target/collision")
            (case / "collision-index.log").write_bytes(collision)
            # The two equal legacy hashes straddle the split. Its low bit signals continuation.
            if b"Entry #1: Hash 0x43155c7b, block " not in collision:
                raise RuntimeError("guest split did not create the expected collision boundary")
        verify_host(case, disk)
        written = digest(disk)
        boot(case, boot_images["verify"], [disk], firmware, transport, ["EXT2_INDEX_REBOOT_PASS"])
        if digest(disk) != written:
            raise RuntimeError("read-only reboot changed filesystem bytes")
        rows.append(dict(profile=profile, hash=algorithm, unsigned=unsigned, journal=journal,
                         block_size=block_size, firmware=firmware, transport=transport,
                         initial_depth=before, final_depth=after, root_entries=root_entries,
                         disk_sha256=written))
        (directory / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"EXT2_INDEX_PROFILE_PASS {profile} {firmware}/{transport}", flush=True)


if __name__ == "__main__":
    main()
