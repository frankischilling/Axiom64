#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext4_orphan_test.py
# @brief   Verify native ext4 orphan recovery in QEMU.
# @author  frankischilling
# @date    2026-11-20
#
# Checks journaled removal and truncation against independent e2fsprogs copies.
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

"""Compare native ext4 orphan recovery with QEMU guest mounts."""
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
from ext4_extent_test import checksummed_journal, crc32c, debug, digest, fsck, group_layout, inode_offset
from fetch import ROOT
from fixture_archive import sparse_copy_fixture
from guest_storage_boot import boot, cut_after_write_fault

CONTENTS = bytes(i % 251 + 1 for i in range(18000))
PROFILES = (
    ("legacy-indirect", 1024, "bios", "modern", False, False, False),
    ("legacy-extents", 4096, "uefi", "modern", True, True, False),
    ("orphan-file", 1024, "uefi", "legacy", True, True, True),
    ("orphan-file-plain", 2048, "bios", "legacy", True, False, True),
)


def field(disk, command, pattern):
    match = re.search(pattern, debug(disk, command))
    if not match:
        raise RuntimeError(f"{disk}: missing expected field in {command}")
    return int(match[1])


def set_super(disk, name, value):
    debug(disk, f"set_super_value {name} {value}", write=True)


def set_inode(disk, path, name, value):
    debug(disk, f"set_inode_field {path} {name} {value}", write=True)


def slot_block(disk, number, transform, offset=0, seal=True):
    header, _, _, _ = group_layout(disk)
    block = 1024 << struct.unpack_from("<I", header, 24)[0]
    physical = int(debug(disk, f"bmap <{number}> {offset}"))
    inode = inode_offset(disk, f"<{number}>", block)
    with disk.open("r+b") as raw:
        raw.seek(inode + 100)
        generation = raw.read(4)
        raw.seek(physical * block)
        data = bytearray(raw.read(block))
        if struct.unpack_from("<I", data, block - 8)[0] != 0x0b10ca04:
            raise RuntimeError("missing native orphan-file tail")
        transform(data)
        incompatible, readonly = struct.unpack_from("<II", header, 96)
        if seal and readonly & 0x400:
            seed = (struct.unpack_from("<I", header, 624)[0] if incompatible & 0x2000 else
                    crc32c(0xffffffff, header[104:120]))
            checksum = crc32c(seed, struct.pack("<I", number) + generation + struct.pack("<Q", physical))
            struct.pack_into("<I", data, block - 4, crc32c(checksum, data[:-8]))
        raw.seek(physical * block)
        raw.write(data)
    return physical


def fixture(directory, profile, binaries=(), mixed=False):
    directory.mkdir()
    _, block, _, _, extents, checksums, orphan_file = profile
    clean = directory / "clean.raw"
    disk = directory / "pending.raw"
    prefix = "/mnt" if binaries else ""
    with tempfile.TemporaryDirectory(prefix="ext4-orphan-") as scratch:
        root = Path(scratch)
        data = root
        if binaries:
            for subdir in ("bin", "dev", "lib", "mnt", "proc", "run", "sbin", "sys", "tmp"):
                (root / subdir).mkdir()
            for binary, path in zip(binaries, ("sbin/init", "bin/busybox", "lib/ld-musl-x86_64.so.1"),
                                    strict=True):
                shutil.copyfile(binary, root / path)
                (root / path).chmod(0o755)
            data = root / "mnt"
        (data / "retired-dir").mkdir()
        (data / "retire").write_bytes(b"old-" * 4096)
        (data / "shrink").write_bytes(CONTENTS)
        (data / "independent").write_bytes(b"unchanged\n")
        with clean.open("wb") as raw:
            raw.truncate(32 * 1024 * 1024)
        features = ["none", "filetype", "sparse_super", "large_file", "has_journal"]
        if extents:
            features.append("extent")
        if checksums:
            features += ["64bit", "flex_bg", "metadata_csum"]
        if orphan_file:
            features.append("orphan_file")
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", str(block),
                        "-I", "256" if checksums else "128", "-O", ",".join(features),
                        "-d", root, clean], check=True)
    if checksums:
        checksummed_journal(clean, block)
    fsck(clean, directory / "clean-fsck.log")
    sparse_copy_fixture(clean, disk)
    targets = {path: field(clean, f"stat {prefix}/{path}", rb"Inode:\s+(\d+)")
               for path in ("retired-dir", "retire", "shrink")}
    parent = prefix or "/"
    links = field(clean, f"stat {parent}", rb"Links:\s+(\d+)")
    for path in ("retired-dir", "retire"):
        debug(disk, f"unlink {prefix}/{path}", write=True)
        set_inode(disk, f"<{targets[path]}>", "links_count", 0)
    set_inode(disk, parent, "links_count", links - 1)
    set_inode(disk, f"<{targets['retired-dir']}>", "size", 0)
    set_inode(disk, f"{prefix}/shrink", "size", 5000)
    header, _, _, _ = group_layout(clean)
    incompatible, readonly = struct.unpack_from("<II", header, 96)
    # Journal replay may publish a newer 64-bit lifetime write counter.
    previous = struct.unpack_from("<Q", header, 376)[0]
    set_super(disk, "kbytes_written", previous + (1 << 32) + 2048)
    set_super(disk, "feature_incompat", incompatible | 4)
    orphan = 0
    if orphan_file:
        orphan = field(disk, "stats", rb"Orphan file inode:\s+(\d+)")
        slot_block(disk, orphan, lambda data: struct.pack_into("<2I", data, 0,
                                                               targets["retire"], targets["shrink"]))
        if mixed:
            set_super(disk, "last_orphan", targets["retired-dir"])
        else:
            slot_block(disk, orphan, lambda data: struct.pack_into("<I", data, block - 12,
                                                                   targets["retired-dir"]), offset=1)
        set_super(disk, "feature_ro_compat", readonly | 0x10000)
    else:
        set_inode(disk, f"<{targets['retired-dir']}>", "dtime", targets["retire"])
        set_inode(disk, f"<{targets['retire']}>", "dtime", targets["shrink"])
        set_super(disk, "last_orphan", targets["retired-dir"])
    return clean, disk, targets, orphan


def journal_pending_image(directory, clean, pending, block, target):
    blocks = []
    payload = directory / "replay.bin"
    with clean.open("rb") as before, pending.open("rb") as after, payload.open("wb") as out:
        for number in range(clean.stat().st_size // block):
            original, updated = before.read(block), after.read(block)
            if original != updated:
                blocks.append(number)
                out.write(updated)
    if not blocks:
        raise RuntimeError("empty staged orphan transaction")
    commands = directory / "replay.debugfs"
    commands.write_text("journal_open\njournal_write -b " + ",".join(map(str, blocks)) +
                        f" {payload}\njournal_close\n")
    sparse_copy_fixture(clean, target)
    result = subprocess.run(["debugfs", "-w", "-f", commands, target], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (directory / "replay-debugfs.log").write_bytes(result.stdout)
    journal = int(debug(target, "bmap <8> 0"))
    with target.open("rb") as raw:
        raw.seek(journal * block + 28)
        if not struct.unpack(">I", raw.read(4))[0]:
            raise RuntimeError("no committed native JBD2 record")


def valid_volume(directory, disk, targets, orphan, prefix=""):
    fsck(disk, directory / "after-fsck.log")
    if debug(disk, f"cat {prefix}/shrink") != CONTENTS[:5000]:
        raise RuntimeError("retained truncation bytes differ")
    if debug(disk, f"cat {prefix}/independent") != b"unchanged\n":
        raise RuntimeError("unrelated file changed")
    for path in ("retired-dir", "retire"):
        if b"not in use" not in debug(disk, f"testi <{targets[path]}>"):
            raise RuntimeError(f"{path} still allocated")
    header, _, _, _ = group_layout(disk)
    if struct.unpack_from("<I", header, 232)[0] or struct.unpack_from("<I", header, 100)[0] & 0x10000:
        raise RuntimeError("orphan state still set")
    if orphan:
        block = 1024 << struct.unpack_from("<I", header, 24)[0]
        length = field(disk, f"stat <{orphan}>", rb"Size:\s+(\d+)")
        # Inspect without rewriting the independently checked orphan file.
        with disk.open("rb") as raw:
            for index in range(length // block):
                physical = int(debug(disk, f"bmap <{orphan}> {index}"))
                raw.seek(physical * block)
                if any(raw.read(block)[:-8]):
                    raise RuntimeError("orphan slots still allocated")


def oracle(directory, seed, targets, orphan, prefix=""):
    directory.mkdir()
    disk = directory / "disk.raw"
    sparse_copy_fixture(seed, disk)
    with (directory / "replay.log").open("wb") as log:
        checked = subprocess.run(["e2fsck", "-fy", disk], stdout=log, stderr=subprocess.STDOUT)
    if checked.returncode not in (0, 1):
        raise RuntimeError("native orphan recovery failed")
    valid_volume(directory, disk, targets, orphan, prefix)


def reject(directory, seed, image, change, hardware=False):
    directory.mkdir()
    disk = directory / "disk.raw"
    sparse_copy_fixture(seed, disk)
    change(disk)
    before = digest(disk)
    boot(directory, image, [disk], "bios", "modern", ["EXT4_ORPHAN_REJECT_PASS"],
         hardware_readonly=hardware)
    if digest(disk) != before:
        raise RuntimeError(f"rejected image changed: {directory.name}")


def reject_controls(directory, seed, images, targets, orphan):
    reject(directory / "hardware-readonly", seed, images["error"], lambda disk: None, hardware=True)
    invalid = images["invalid"]
    if not orphan:
        victim = f"<{targets['retire']}>"
        reject(directory / "cycle", seed, invalid,
               lambda disk: set_inode(disk, victim, "dtime", targets["retired-dir"]))
        reject(directory / "reserved-target", seed, invalid,
               lambda disk: set_super(disk, "last_orphan", 8))
        reject(directory / "invalid-linked-count", seed, invalid,
               lambda disk: set_inode(disk, "/shrink", "links_count", 0))
        return
    reject(directory / "duplicate-slot", seed, invalid,
           lambda disk: slot_block(disk, orphan, lambda data: struct.pack_into("<I", data, 4, targets["retire"])))
    reject(directory / "metadata-slot", seed, invalid,
           lambda disk: slot_block(disk, orphan, lambda data: struct.pack_into("<I", data, 4, orphan)))
    reject(directory / "unadvertised-slots", seed, invalid,
           lambda disk: set_super(disk, "feature_ro_compat",
                                  struct.unpack_from("<I", group_layout(disk)[0], 100)[0] & ~0x10000))
    if struct.unpack_from("<I", group_layout(seed)[0], 100)[0] & 0x400:
        reject(directory / "bad-orphan-file-checksum", seed, invalid,
               lambda disk: slot_block(disk, orphan, lambda data: data.__setitem__(-1, data[-1] ^ 1),
                                       seal=False))


def cut_recovery(directory, seed, target_block, block, images, targets, orphan):
    directory.mkdir()
    disk = directory / "interrupted.raw"
    sparse_copy_fixture(seed, disk)
    with disk.open("rb") as raw:
        raw.seek(target_block * block)
        original = raw.read(block)
    cut_after_write_fault(directory, images["pressure"], disk, target_block * block // 512,
                          "EXT4_ORPHAN_HOME_WRITE_FAULT")
    journal = int(debug(seed, "bmap <8> 0"))
    with disk.open("rb") as raw:
        raw.seek(target_block * block)
        if raw.read(block) != original:
            raise RuntimeError("fault did not leave the target home block unchanged")
        raw.seek(journal * block + 28)
        if not struct.unpack(">I", raw.read(4))[0]:
            raise RuntimeError("interruption lost the committed cleanup transaction")
    oracle(directory / "checker", disk, targets, orphan)
    recovered = directory / "disk.raw"
    sparse_copy_fixture(disk, recovered)
    boot(directory, images["verify"], [recovered], "bios", "modern", ["EXT4_ORPHAN_RECOVERY_PASS"])
    valid_volume(directory, recovered, targets, orphan)


def images(directory, root_test, extra_phases=(), prefix="ext4-orphan", *,
           base_phases=("write", "verify", "invalid", "error", "pressure"),
           source="userspace/tests/fs/ext4-orphan.c"):
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    client = directory / "ext4-orphan"
    subprocess.run(["musl-gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                    source, "-o", client], cwd=ROOT, check=True)
    archive = directory / "initramfs.cpio"
    files = {name: (0o40755, b"") for name in ("dev", "proc", "run", "sbin", "sys", "tmp")}
    files["sbin/init"] = 0o100755, client.read_bytes()
    write_cpio(archive, files)
    result = {}
    phases = list(base_phases)
    if root_test:
        phases.append("root")
    phases.extend(extra_phases)
    for phase in phases:
        name = f"{prefix}-{phase}.iso"
        options = ["--kernel-option", "root=/dev/vda", "--kernel-option", "rootfstype=ext4"] if phase == "root" else []
        with (directory / f"image-{phase}.log").open("wb") as log:
            subprocess.run([sys.executable, "-B", "scripts/image.py", "--test", "--suite", "storage",
                            "--phase", "io" if phase == "root" else phase,
                            "--kernel", ROOT / "build/axiom64.elf", "--initramfs", archive,
                            "--output-directory", directory, "--output-name", name, *options],
                           cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
        result[phase] = directory / name
    return result, client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext4-orphans")
    parser.add_argument("--profile", choices=[profile[0] for profile in PROFILES])
    parser.add_argument("--root-tools", type=Path, nargs=2, metavar=("BUSYBOX", "MUSL_LOADER"),
                        help="boot the orphan fixture as root with the supplied guest tools")
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to((ROOT / "build").resolve()):
        parser.error("output must be under build/")
    directory.mkdir(parents=True, exist_ok=False)
    boot_images, client = images(directory, args.root_tools)
    rows = []
    for profile in PROFILES:
        name, block, firmware, transport, _, checksums, has_orphan_file = profile
        if args.profile and name != args.profile:
            continue
        case = directory / name
        clean, seed, targets, orphan = fixture(case, profile)
        reject_controls(case, seed, boot_images, targets, orphan)
        seed_sha = digest(seed)
        if name in ("legacy-extents", "orphan-file"):
            # Exercise home metadata that has yet to receive the orphan records.
            recovery = case / "staged.raw"
            journal_pending_image(case, clean, seed, block, recovery)
        else:
            recovery = case / "staged.raw"
            sparse_copy_fixture(seed, recovery)
        oracle(case / "checker", recovery, targets, orphan)
        phase = "write" if name in ("legacy-indirect", "orphan-file-plain") else "verify"
        boot(case, boot_images[phase], [recovery], firmware, transport, ["EXT4_ORPHAN_RECOVERY_PASS"])
        valid_volume(case, recovery, targets, orphan)
        after = digest(recovery)
        reboot = case / "reboot"
        reboot.mkdir()
        boot(reboot, boot_images["verify"], [recovery], firmware, transport, ["EXT4_ORPHAN_RECOVERY_PASS"])
        if digest(recovery) != after or digest(seed) != seed_sha:
            raise RuntimeError("recovery verifier or read-only reboot changed input bytes")
        row = {"profile": name, "firmware": firmware, "device": transport, "block_size": block,
               "recovered_sha256": after}
        if has_orphan_file and checksums:
            phys = int(debug(seed, f"bmap <{orphan}> 0"))
            cut_recovery(case / "cut", seed, phys, block, boot_images, targets, orphan)
        if has_orphan_file and checksums and args.root_tools:
            root = case / "root"
            _, root_disk, root_targets, root_orphan = fixture(root, profile, (client, *args.root_tools),
                                                             mixed=True)
            oracle(root / "checker", root_disk, root_targets, root_orphan, "/mnt")
            boot(root, boot_images["root"], [root_disk], firmware, transport,
                 ["VFS_ROOT_PASS filesystem=ext4 device=/dev/vda readonly=0", "EXT4_ORPHAN_RECOVERY_PASS"])
            valid_volume(root, root_disk, root_targets, root_orphan, "/mnt")
            row["root_sha256"] = digest(root_disk)
        rows.append(row)
        (directory / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"EXT4_ORPHAN_PROFILE_PASS {name}", flush=True)


if __name__ == "__main__":
    main()
