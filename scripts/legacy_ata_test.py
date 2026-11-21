#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/legacy_ata_test.py
# @brief   Verify legacy ATA I/O in QEMU.
# @author  frankischilling
# @date    2026-11-21
#
# Boots PCI compatibility disks and checks on-disk bytes outside the guest.
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

"""Exercise legacy ATA compatibility channels and an ext2 root."""
import argparse
from pathlib import Path
import json
import shutil
import struct
import subprocess
import sys

from account_normal_test import write_cpio
from boot_media_test import digest
from disk_root import bootstrap
from fetch import ROOT


SECTOR = 512
BOUNDARY = (1 << 28) * SECTOR
PAYLOAD = b"ATA persisted\n\0"


def disk(path, size, seed=b"", offset=0):
    with path.open("xb") as stream:
        stream.truncate(size)
        stream.seek(offset)
        stream.write(seed)
    return path


def primary_disk(path):
    mbr = bytearray(SECTOR)
    struct.pack_into("<I", mbr, 440, 0x68ce920d)
    struct.pack_into("<B3xB3xII", mbr, 446, 0, 0x83, 2048, 4096)
    mbr[510:] = b"\x55\xaa"
    disk(path, 8192 * SECTOR, mbr)
    with path.open("r+b") as stream:
        stream.seek(3132 * SECTOR)
        stream.write(b"ATA-READ")
        stream.seek(2048 * SECTOR)
        stream.write(b"ATA-SEED")
        stream.seek(6144 * SECTOR)
        stream.write(b"outside-partition")
    return path


def image(output, initramfs, root=None, *, name="ata-data.iso"):
    iso = output / name
    args = ["--root-device", root] if root else ["--initramfs", initramfs]
    subprocess.run([sys.executable, ROOT / "scripts/image.py", "--test",
                    "--output-directory", output, "--output-name", iso.name, *args],
                   check=True)
    return iso


def run(directory, firmware, iso, drives, marker, root_marker=None, *, virtio=None):
    directory.mkdir()
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "384M",
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
               "-nic", "none", "-boot", "order=d,strict=on",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=4", "-cdrom", iso]
    for slot, path in drives.items():
        command += ["-drive", f"if=none,id=ata{slot},format=raw,cache=writeback,file={path}",
                    "-device", f"ide-hd,drive=ata{slot},bus=ide.{slot // 2},unit={slot % 2},"
                               "rerror=report,werror=report"]
    if virtio:
        command += ["-drive", f"if=none,id=virtio,format=raw,file={virtio}",
                    "-device", "virtio-blk-pci,drive=virtio,disable-legacy=on"]
    if firmware == "uefi":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    log = directory / "serial.log"
    with log.open("wb") as serial:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=serial,
                                stderr=subprocess.STDOUT, timeout=90)
    lines = set(log.read_text(errors="replace").splitlines())
    expected = {f"Firmware: {firmware.upper()}", marker, "AXIOM64_EXIT status=0"}
    if root_marker:
        expected.add(root_marker)
    if result.returncode != 1 or not expected <= lines:
        raise RuntimeError(f"{directory.name} failed: missing {expected - lines}, see {log}")
    print(f"{directory.name}: passed", flush=True)
    return {"name": directory.name, "serial_sha256": digest(log)}


def compare(path, offset, data):
    with path.open("rb") as stream:
        stream.seek(offset)
        if stream.read(len(data)) != data:
            raise RuntimeError(f"{path}: wrong bytes at offset {offset}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/legacy-ata")
    opts = parser.parse_args()
    output = opts.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    init = output / "init"
    subprocess.run(["musl-gcc", "-static", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/fs/legacy-ata.c", "-o", init], check=True)
    cpio = output / "data.cpio"
    write_cpio(cpio, {"dev": (0o40755, b""), "sbin": (0o40755, b""),
                     "sbin/init": (0o100755, init.read_bytes())})
    data_iso = image(output, cpio)

    seed = output / "seed"
    seed.mkdir()
    for name in ("bin", "dev", "lib", "proc", "run", "sbin", "sys", "tmp"):
        (seed / name).mkdir()
    (seed / "ata-root").touch()
    shutil.copy2(init, seed / "sbin/init")
    shutil.copy2(shutil.which("busybox"), seed / "bin/busybox")
    shutil.copy2("/lib/ld-musl-x86_64.so.1", seed / "lib/ld-musl-x86_64.so.1")
    root_image = disk(output / "root.ext2", 16 * 1024 * 1024)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2", "-O", "none,filetype,sparse_super",
                    "-d", seed, root_image], check=True)
    bootstrap(ROOT / "build/rootfs-bootstrap.cpio")
    root_iso = image(output, None, root="/dev/sda", name="ata-root.iso")
    identified = "PARTUUID=68ce920d-01"
    partition_iso = image(output, None, root=identified, name="ata-partition.iso")

    cases = []
    faults = output / "faults.conf"
    faults.write_text(''.join(f'[inject-error]\nevent = "{direction}_aio"\niotype = "{direction}"\n'
                              f'sector = "{sector}"\nerrno = "5"\nonce = "off"\n\n'
                              for direction, sector in (("read", 3131), ("write", 3133))))
    for firmware in ("bios", "uefi"):
        primary = primary_disk(output / f"{firmware}-primary.raw")
        slave = disk(output / f"{firmware}-slave.raw", BOUNDARY + 64 * SECTOR)
        secondary = disk(output / f"{firmware}-secondary.raw", 4096 * SECTOR, b"ATA-SEC2")
        virtio = disk(output / f"{firmware}-virtio.raw", 4096 * SECTOR, b"VIO-SEED")
        cases.append(run(output / f"{firmware}-data", firmware, data_iso,
                         {0: f"blkdebug:{faults}:{primary}", 1: slave, 3: secondary},
                         "ATA_BLOCK_PASS", virtio=virtio))
        compare(primary, 3133 * SECTOR, bytes(SECTOR))
        compare(primary, 3134 * SECTOR, PAYLOAD)
        compare(primary, 2048 * SECTOR, b"ATA" + PAYLOAD)
        compare(primary, 6144 * SECTOR - 3, PAYLOAD[:3] + b"outside-partition")
        compare(slave, BOUNDARY - 2 * SECTOR, bytes(SECTOR) + b"\xa5" * SECTOR +
                b"\x6b" * SECTOR + bytes(SECTOR))
        root = output / f"{firmware}-root.ext2"
        shutil.copyfile(root_image, root)
        mounted = "VFS_ROOT_PASS filesystem=ext2 device=/dev/sda readonly=0"
        for phase, marker in (("write", "ATA_ROOT_WRITE_PASS"), ("reboot", "ATA_ROOT_REBOOT_PASS")):
            cases.append(run(output / f"{firmware}-root-{phase}", firmware, root_iso, {0: root},
                             marker, mounted))
        subprocess.run(["e2fsck", "-fn", root], check=True)
        contents = subprocess.check_output(["debugfs", "-R", "cat /ata-written", root])
        if contents != PAYLOAD:
            raise RuntimeError(f"{root}: wrong data after reboot")

        partition = output / f"{firmware}-partition.raw"
        with primary.open("rb") as stream:
            mbr = bytearray(stream.read(SECTOR))
        root_bytes = root.read_bytes()
        struct.pack_into("<I", mbr, 458, len(root_bytes) // SECTOR)
        disk(partition, 2048 * SECTOR + len(root_bytes), mbr)
        with partition.open("r+b") as stream:
            stream.seek(2048 * SECTOR)
            stream.write(root_bytes)
        mounted = f"VFS_ROOT_PASS filesystem=ext2 device={identified} readonly=0"
        cases.append(run(output / f"{firmware}-partition-root", firmware, partition_iso,
                         {1: partition}, "ATA_ROOT_REBOOT_PASS", mounted))
    (output / "results.json").write_text(json.dumps(
        {"kernel_sha256": digest(ROOT / "build/axiom64.elf"), "cases": cases}, indent=2) + "\n")


if __name__ == "__main__":
    main()
