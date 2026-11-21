#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/ext2_journal_checksums_test.py
# @brief   Verify checksummed JBD2 replay and persistence in QEMU.
# @author  frankischilling
# @date    2026-11-20
#
# Compares independent native journal producers and filesystem-checker copies.
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

"""Replay JBD2 transactions from native and Axiom64 writers inside the guest."""
import argparse
import ctypes
import gzip
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

from account_normal_test import write_cpio
from ext2_index_test import debug, digest
from fetch import ROOT
from fixture_archive import archive_fixture, sparse_copy_fixture
from guest_storage_boot import boot

MAGIC = 0xc03b3998
PROFILES = (("v1", "bios", "modern"), ("v2", "uefi", "modern"),
            ("v2-wide", "bios", "legacy"), ("v3", "uefi", "legacy"),
            ("v3-wide", "bios", "modern"), ("wide", "uefi", "modern"))


def export(disk, size, mode, directory):
    old = bytes((i * 31 + 17) & 255 for i in range(9 * size - 128))
    appended = bytes((i * 13 + 9) & 255 for i in range(448))
    additional = bytes((i * 7 + 3) & 255 for i in range(2 * size + 37))
    expected = old if mode == "discard" else old + appended
    if mode in ("write", "append"):
        expected += additional
    with (directory / "fsck.log").open("wb") as log:
        subprocess.run(["e2fsck", "-fn", disk], check=True, stdout=log,
                       stderr=subprocess.STDOUT)
    target = directory / "seed.bin"
    debug(disk, f"dump /seed {target}")
    if target.read_bytes() != expected:
        raise RuntimeError(f"{disk}: native export differs from the expected seed bytes")
    if mode == "write":
        created = directory / "final.bin"
        debug(disk, f"dump /work/final {created}")
        if created.read_bytes() != expected[:size + 97]:
            raise RuntimeError(f"{disk}: guest-created file differs")


def restore(directory, native, row, name):
    record = row["archives"][name]
    source = native / f"{name}.raw.gz"
    if digest(source) != record["compressed"]["sha256"]:
        raise RuntimeError(f"{source}: compressed fixture digest mismatch")
    target = directory / "disk.raw"
    with gzip.open(source, "rb") as packed, target.open("xb") as output:
        shutil.copyfileobj(packed, output)
    if digest(target) != record["original"]["sha256"]:
        raise RuntimeError(f"{target}: restored fixture digest mismatch")
    return target


def native_transaction(directory, source, row):
    disk = restore(directory, source, row, "base")
    size = row["block_size"]
    transaction = (source / "transaction.bin").read_bytes()
    count, = struct.unpack_from("<I", transaction)
    assert count == 6 and len(transaction) == 4 + count * (4 + size)
    blocks, payload = [], bytearray()
    for i in range(count):
        start = 4 + i * (4 + size)
        blocks.append(struct.unpack_from("<I", transaction, start)[0])
        payload += transaction[start + 4:start + 4 + size]
    data = directory / "transaction-payload.bin"
    data.write_bytes(payload)
    stale = directory / "revoked-payload.bin"
    stale.write_bytes(b"\xa5" * size)
    victim = int(debug(disk, "bmap /seed 0"))
    assert victim and victim not in blocks
    commands = "\n".join(("journal_open", f"journal_write -b {victim} {stale}",
                          f"journal_write -r {victim} /dev/null",
                          f"journal_write -b {','.join(map(str, blocks))} {data}",
                          "journal_close", ""))
    with (directory / "debugfs-writer.log").open("wb") as log:
        subprocess.run(["debugfs", "-w", "-f", "-", disk], input=commands.encode(),
                       check=True, stdout=log, stderr=subprocess.STDOUT)
    oracle_directory = directory / "oracle"
    oracle_directory.mkdir()
    oracle = oracle_directory / "disk.raw"
    sparse_copy_fixture(disk, oracle)
    replay_log = oracle_directory / "replay.log"
    with replay_log.open("wb") as log:
        result = subprocess.run(["e2fsck", "-fy", oracle], stdout=log, stderr=subprocess.STDOUT)
    if result.returncode not in (0, 1) or b"recovering journal" not in replay_log.read_bytes():
        raise RuntimeError(f"{oracle}: independent checker did not replay the native transaction")
    export(oracle, size, "read", oracle_directory)
    archive_fixture(oracle, remove=True)
    return disk


def control_offsets(disk, source, size):
    mapping = [item[0] for item in struct.iter_unpack("<I", (source / "journal-map.bin").read_bytes())]
    with disk.open("rb") as raw:
        raw.seek(mapping[0] * size)
        header = raw.read(size)
        sequence, start = struct.unpack_from(">II", header, 24)
        if not start or struct.unpack_from(">I", header, 40)[0] != 19:
            raise RuntimeError("control fixture requires a pending 64-bit checksum v3 journal")
        records = {}
        for logical in range(1, len(mapping)):
            raw.seek(mapping[logical] * size)
            magic, kind, tid = struct.unpack(">III", raw.read(12))
            if magic == MAGIC:
                records[kind, tid] = logical
    descriptor = records[1, sequence + 2]
    return header, {name: mapping[logical] * size for name, logical in (
        ("superblock", 0), ("descriptor", descriptor), ("payload", descriptor + 1),
        ("revoke", records[5, sequence + 1]), ("commit", records[2, sequence + 2]))}


def controls(directory, source, disk, size, images):
    header, offsets = control_offsets(disk, source, size)
    crc = ctypes.CDLL("libext2fs.so.2").ext2fs_crc32c_le
    crc.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t]
    crc.restype = ctypes.c_uint32
    seed = crc(0xffffffff, header[48:64], 16)
    cases = (("superblock", 252), ("descriptor", size - 4), ("payload", 56),
             ("revoke", size - 4), ("commit", 16), ("wide-target", 20),
             ("uncommitted", 0))
    results = {}
    for name, delta in cases:
        case = directory / name
        case.mkdir()
        damaged = case / "disk.raw"
        sparse_copy_fixture(disk, damaged)
        with damaged.open("r+b") as raw:
            if name == "wide-target":
                raw.seek(offsets["descriptor"])
                descriptor = bytearray(raw.read(size))
                struct.pack_into(">I", descriptor, delta, 1)  # Nonzero high target word.
                struct.pack_into(">I", descriptor, size - 4, 0)
                struct.pack_into(">I", descriptor, size - 4, crc(seed, bytes(descriptor), size))
                raw.seek(offsets["descriptor"])
                raw.write(descriptor)
            elif name == "uncommitted":
                raw.seek(offsets["commit"])
                raw.write(bytes(size))
                raw.seek(offsets["payload"])
                raw.write(b"partial")
            else:
                offset = offsets[name] + delta
                raw.seek(offset)
                byte = raw.read(1)
                raw.seek(offset)
                raw.write(bytes((byte[0] ^ 1,)))
        before = digest(damaged)
        if name == "uncommitted":
            marker = f"EXT2_JOURNAL_PASS mode=recovery block_size={size} historical_bytes={9 * size - 128}"
            boot(case, images["recovery"], [damaged], "bios", "modern", [marker])
            export(damaged, size, "discard", case)
        else:
            boot(case, images["invalid"], [damaged], "bios", "modern",
                 ["EXT2_JOURNAL_CHECKSUM_REJECT_PASS"])
            if digest(damaged) != before:
                raise RuntimeError(f"{damaged}: rejected journal changed disk bytes")
        results[name] = {"input_sha256": before, "output": archive_fixture(damaged, remove=True)}
    return results


def power_cut(directory, source, size, images):
    directory.mkdir()
    disk = directory / "disk.raw"
    # The oracle has the native transaction checkpointed and the old file intact.
    with gzip.open(directory.parent / "oracle/disk.raw.gz", "rb") as packed, disk.open("xb") as out:
        shutil.copyfileobj(packed, out)
    tail = int(debug(disk, "bmap /seed 9"))
    assert tail
    with disk.open("rb") as raw:
        raw.seek(tail * size)
        historical_tail = raw.read(size)
    rule = directory / "home.conf"
    rule.write_text('[inject-error]\nevent = "write_aio"\niotype = "write"\n'
                    f'sector = "{tail * (size // 512)}"\nerrno = "5"\nonce = "on"\n')
    serial = directory / "home-fault.log"
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "256M",
               "-boot", "order=d", "-cdrom", str(images["error"]), "-display", "none",
               "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
               "-drive", f"if=none,id=d0,format=raw,file=blkdebug:{rule}:{disk},cache=writethrough,werror=report",
               "-device", "virtio-blk-pci,drive=d0,disable-legacy=on,addr=5"]
    with serial.open("wb") as log, subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT) as vm:
        try:
            deadline = time.monotonic() + 70
            while time.monotonic() < deadline and vm.poll() is None:
                if b"EXT2_JOURNAL_HOME_WRITE_FAULT" in serial.read_bytes().splitlines():
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError(f"{serial}: guest did not report the home write fault")
        finally:
            if vm.poll() is None:
                vm.kill()
                vm.wait()
    mapping = (source / "journal-map.bin").read_bytes()
    superblock, = struct.unpack_from("<I", mapping)
    with disk.open("rb") as raw:
        raw.seek(tail * size)
        if raw.read(size) != historical_tail:
            raise RuntimeError("home write reached disk despite the injected error")
        raw.seek(superblock * size + 28)
        if not struct.unpack(">I", raw.read(4))[0]:
            raise RuntimeError("failed home write left no pending journal")
    recovered = directory / "guest"
    oracle = directory / "oracle"
    for path in (recovered, oracle):
        path.mkdir()
        sparse_copy_fixture(disk, path / "disk.raw")
    with (oracle / "replay.log").open("wb") as log:
        result = subprocess.run(["e2fsck", "-fy", oracle / "disk.raw"], stdout=log,
                                stderr=subprocess.STDOUT)
    if result.returncode not in (0, 1) or b"recovering journal" not in (oracle / "replay.log").read_bytes():
        raise RuntimeError("native tools did not recover the guest's pending journal")
    export(oracle / "disk.raw", size, "append", oracle)
    marker = f"EXT2_JOURNAL_PASS mode=readonly block_size={size} historical_bytes={9 * size - 128}"
    boot(recovered, images["readonly"], [recovered / "disk.raw"], "bios", "modern", [marker])
    export(recovered / "disk.raw", size, "append", recovered)
    return {name: archive_fixture(path / "disk.raw", remove=True) for name, path in
            (("interrupted", directory), ("native_recovery", oracle), ("guest_recovery", recovered))}


def images(directory):
    client, archive = directory / "ext2-journal", directory / "initramfs.cpio"
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    subprocess.run(["musl-gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                    "userspace/tests/fs/ext2-journal.c", "-o", client], cwd=ROOT, check=True)
    files = {name: (0o40755, b"") for name in ("dev", "proc", "run", "sbin", "sys", "tmp")}
    files["sbin/init"] = 0o100755, client.read_bytes()
    write_cpio(archive, files)
    result = {}
    for phase in ("write", "verify", "invalid", "recovery", "error", "readonly"):
        name = f"ext2-jbd2-checksums-{phase}.iso"
        with (directory / f"{phase}-image.log").open("wb") as log:
            subprocess.run([sys.executable, "-B", "scripts/image.py", "--test", "--suite", "storage",
                            "--phase", phase, "--kernel", ROOT / "build/axiom64.elf",
                            "--initramfs", archive, "--output-directory", directory,
                            "--output-name", name], cwd=ROOT, check=True, stdout=log,
                           stderr=subprocess.STDOUT)
        result[phase] = directory / name
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/ext2-jbd2-checksums")
    parser.add_argument("--native-directory", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    native = (args.native_directory or directory / "native").resolve()
    if any(not path.is_relative_to((ROOT / "build").resolve()) for path in (directory, native)):
        parser.error("result directories must be under build/")
    directory.mkdir(parents=True, exist_ok=False)
    if not args.native_directory:
        subprocess.run([sys.executable, "-B", "scripts/ext2_journal_native_test.py",
                        "--directory", native], cwd=ROOT, check=True)
    receipt = json.loads((native / "receipt.json").read_text())
    if not receipt["passed"] or not receipt["terminal"] or not all(
            digest(ROOT / path) == sha for path, sha in receipt["source_inputs"].items()):
        raise RuntimeError("native fixtures do not match the current source")
    profiles = {row["layout"]: row for row in json.loads((native / "results.json").read_text())}
    boot_images = images(directory)
    results = []
    for label, firmware, transport in PROFILES:
        row, source = profiles[label], native / label
        if (digest(source / "journal-map.bin") != row["inputs"]["mapping"] or
                digest(source / "transaction.bin") != row["inputs"]["transaction"]):
            raise RuntimeError(f"{source}: native journal inputs changed")
        size = row["block_size"]
        case = directory / label
        case.mkdir()
        producer = "debugfs" if label.startswith(("v2", "v3")) else "axiom64"
        disk = native_transaction(case, source, row) if producer == "debugfs" \
            else restore(case, source, row, "crashed")
        evidence = {"format": label, "firmware": firmware, "transport": transport,
                    "producer": producer, "input": digest(disk)}
        if label == "v3-wide":
            evidence["controls"] = controls(case, source, disk, size, boot_images)
            evidence["power_cut"] = power_cut(case / "home-interruption", source, size, boot_images)
        for phase in ("write", "verify"):
            marker = f"EXT2_JOURNAL_PASS mode={phase} block_size={size} historical_bytes={9 * size - 128}"
            boot(case, boot_images[phase], [disk], firmware, transport, [marker])
            if phase == "write":
                export(disk, size, phase, case)
                written = digest(disk)
            elif digest(disk) != written:
                raise RuntimeError(f"{disk}: read-only reboot changed disk bytes")
        evidence["output"] = archive_fixture(disk, remove=True)
        results.append(evidence)
        (directory / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"EXT2_JOURNAL_CHECKSUM_PROFILE_PASS {label} {firmware}/{transport}", flush=True)


if __name__ == "__main__":
    main()
