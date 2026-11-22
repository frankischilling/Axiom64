#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/nvme_test.py
# @brief   Boot and verify NVMe disks on QEMU.
# @author  frankischilling
# @date    2026-11-21
#
# Checks the independent disk bytes and filesystems after guest I/O and reboot.
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

"""Verify PCI NVMe namespaces, I/O errors, and persistent ext2 root boot."""
import argparse
from itertools import product
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

from account_normal_test import write_cpio
from boot_media import build_medium
from boot_media_test import digest
from disk_root import bootstrap
from fetch import ROOT
from legacy_ata_test import SECTOR, disk, image, primary_disk

PAYLOAD = b"NVMe persisted\n\0"
SECTORS = 8192
PARTUUID = "PARTUUID=68ce920d-01"
DATA_PASS = "NVME_DATA_PASS sparse_ids two_controllers io_errors queue_wrap transfer_boundaries"


def run(directory, machine, firmware, iso, namespaces, markers, *, dual=False, zoned=(), pxe=None):
    directory.mkdir()
    command = [
        "qemu-system-x86_64", "-machine", machine, "-cpu", "max", "-m", "384M",
        "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
    ]
    if iso is not None:
        command += ["-boot", "order=d,strict=on", "-cdrom", str(iso),
                    "-device", "nvme,id=nv0,serial=AXNVME0,mdts=2,max_ioqpairs=1,addr=5"]
    else:
        command += ["-device", "nvme,id=nv0,serial=AXNVME0"]
    if pxe is not None:
        loader = "BOOTX64.EFI" if firmware == "uefi" else "limine-bios-pxe.bin"
        capture = directory / "pxe.pcap"
        command += ["-boot", "strict=on", "-device", "e1000,netdev=pxe,bootindex=1",
                    "-netdev", f"user,id=pxe,restrict=on,tftp={pxe},bootfile={loader}",
                    "-object", f"filter-dump,id=capture,netdev=pxe,file={capture}"]
    if dual:
        command += ["-device", "nvme,id=nv1,serial=AXNVME1,mdts=1,max_ioqpairs=1,addr=6"]
    for controller, nsid, path, logical in namespaces:
        label = f"drive{controller}_{nsid}"
        zones = ",zoned=on,zoned.zone_size=1M" if (controller, nsid) in zoned else ""
        boot = ",bootindex=1" if iso is None and pxe is None else ""
        command += ["-drive", f"if=none,id={label},format=raw,cache=writeback,file={path}",
                    "-device", f"nvme-ns,drive={label},bus=nv{controller},nsid={nsid},"
                               f"logical_block_size={logical},physical_block_size={logical}{zones}{boot}"]
    if firmware == "uefi":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    log = directory / "serial.log"
    with log.open("wb") as serial:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=serial,
                                stderr=subprocess.STDOUT, timeout=90)
    text = log.read_text(errors="replace")
    required = {f"Firmware: {firmware.upper()}", "AXIOM64_EXIT status=0",
                "nvme: controller=0 reset complete depth=16 transfer_sectors=32",
                "nvme: controller=0 shutdown complete", *markers}
    if dual:
        required |= {"nvme: controller=1 reset complete depth=16 transfer_sectors=16",
                     "nvme: controller=1 shutdown complete"}
    missing = required.difference(text.splitlines())
    if result.returncode != 1 or missing or "PANIC:" in text or "FAULT pid=" in text:
        raise RuntimeError(f"{directory.name}: status {result.returncode}, missing {missing}; see {log}")
    if dual and any(f"controller=0 nsid={nsid} " in text for nsid in (3, 9)):
        raise RuntimeError("An unsupported namespace was published")
    if pxe is not None:
        traffic = capture.read_bytes()
        if not all(name.encode() + b"\0" in traffic
                   for name in (loader, "boot/axiom64.elf", "boot/rootfs.cpio.gz")):
            raise RuntimeError(f"expected TFTP boot paths missing in {capture}")
    print(f"{directory.name}: passed", flush=True)
    return {"name": directory.name, "serial_sha256": digest(log), "iso_sha256": digest(iso) if iso else None}


def verify_data(primary, original, others, unsupported):
    expected = bytearray(original)
    for offset, content in ((3134 * SECTOR, PAYLOAD), (2048 * SECTOR + 3, PAYLOAD),
                            (6144 * SECTOR - 3, PAYLOAD[:3])):
        expected[offset:offset + len(content)] = content
    if primary.read_bytes() != expected:
        raise RuntimeError(f"{primary}: wrong disk bytes after error and partition writes")
    for path, first in others:
        expected = bytearray(SECTORS * SECTOR)
        for i, sectors in enumerate((8, 16, 24, 33)):
            offset = (first + i * 64) * SECTOR
            size = sectors * SECTOR
            expected[offset:offset + size] = bytes((j * 17 + first + i) & 255 for j in range(size))
        if path.read_bytes() != expected:
            raise RuntimeError(f"{path}: wrong transfer or namespace isolation")
    for path in unsupported:
        if any(path.read_bytes()):
            raise RuntimeError(f"{path}: unsupported disk was changed")


def verify_fs(path):
    subprocess.run(["e2fsck", "-fn", path], check=True, capture_output=True)
    observed = subprocess.check_output(["debugfs", "-R", "cat /nvme-written", path],
                                       stderr=subprocess.DEVNULL)
    if observed != PAYLOAD:
        raise RuntimeError(f"{path}: wrong ext2 file contents")


def boot_installed_disk(output, seed):
    archive = output / "installed.cpio"
    files = {path.name: (0o40755, b"") for path in seed.iterdir() if path.is_dir()}
    for name in ("sbin/init", "bin/busybox", "lib/ld-musl-x86_64.so.1", "nvme-root"):
        path = seed / name
        files[name] = (path.stat().st_mode, path.read_bytes())
    write_cpio(archive, files)
    installed = output / "installed.raw"
    size = 1536 * 1024 * 1024
    root_mib = 512
    build_medium("disk", installed, ROOT / "build/axiom64.elf", archive, " test", installed=True,
                 disk_bytes=size, root_mib=root_mib)
    if installed.stat().st_size != size:
        raise RuntimeError("installed disk has the wrong capacity")
    subprocess.run(["sfdisk", "--verify", installed], check=True)
    table = json.loads(subprocess.check_output(["sfdisk", "--json", installed]))["partitiontable"]
    layout = table["partitions"]
    if len(layout) != 3 or layout[2]["name"] != "AXIOM64_ROOT":
        raise RuntimeError("installed disk has an unexpected GPT layout")
    root = layout[2]
    if root["size"] * SECTOR != root_mib * 1024 * 1024:
        raise RuntimeError("installed ext2 partition has the wrong capacity")
    with installed.open("rb") as disk:
        disk.seek(-SECTOR, os.SEEK_END)
        if disk.read(8) != b"EFI PART":
            raise RuntimeError("backup GPT header is missing from the last sector")
    selector = f"PARTUUID={root['uuid'].lower()}"
    results = []
    for phase, marker in (("write", "NVME_ROOT_WRITE_PASS"), ("reboot", "NVME_ROOT_REBOOT_PASS")):
        disk_sha256 = digest(installed)
        result = run(output / f"installed-uefi-{phase}", "q35", "uefi", None,
                     [(0, 1, installed, 512)],
                     [marker, f"VFS_ROOT_PASS filesystem=ext2 device={selector} readonly=0"])
        results.append(dict(result, boot_disk_sha256=disk_sha256))
    pxe = output / "installed-pxe"
    build_medium("pxe", pxe, ROOT / "build/axiom64.elf", None, " test",
                 root_partuuid=root['uuid'])
    for firmware in ("bios", "uefi"):
        results.append(run(output / f"installed-{firmware}-pxe", "q35", firmware, None,
                           [(0, 1, installed, 512)],
                           ["NVME_ROOT_REBOOT_PASS", f"VFS_ROOT_PASS filesystem=ext2 device={selector} readonly=0"],
                           pxe=pxe))
    extracted = output / "installed-check.ext2"
    with installed.open("rb") as disk, extracted.open("xb") as volume:
        disk.seek(root["start"] * SECTOR)
        remaining = root["size"] * SECTOR
        while remaining:
            block = disk.read(min(remaining, 1024 * 1024))
            if not block:
                raise RuntimeError("installed root is truncated")
            volume.write(block)
            remaining -= len(block)
    verify_fs(extracted)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/nvme-test")
    options = parser.parse_args()
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    init = output / "init"
    subprocess.run(["musl-gcc", "-static", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/fs/nvme.c", "-o", init], check=True)
    cpio = output / "data.cpio"
    write_cpio(cpio, {"dev": (0o40755, b""), "sbin": (0o40755, b""),
                     "sbin/init": (0o100755, init.read_bytes())})
    data_image = image(output, cpio, name="nvme-data.iso")
    seed = output / "seed"
    seed.mkdir()
    for directory in ("bin", "dev", "lib", "proc", "run", "sbin", "sys", "tmp"):
        (seed / directory).mkdir()
    (seed / "nvme-root").touch()
    shutil.copy2(init, seed / "sbin/init")
    shutil.copy2(shutil.which("busybox"), seed / "bin/busybox")
    shutil.copy2("/lib/ld-musl-x86_64.so.1", seed / "lib/ld-musl-x86_64.so.1")
    root_image = disk(output / "seed.ext2", 16 * 1024 * 1024)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2", "-O", "none,filetype,sparse_super",
                    "-d", seed, root_image], check=True)
    bootstrap(ROOT / "build/rootfs-bootstrap.cpio")
    root_images = {selector: image(output, None, root=selector, name=f"nvme-{name}.iso")
                   for selector, name in (("/dev/nvme0n7", "root"), ("/dev/nvme0n7p1", "partition"),
                                          (PARTUUID, "partuuid"))}
    faults = output / "faults.conf"
    faults.write_text(''.join(f'[inject-error]\nevent = "{direction}_aio"\niotype = "{direction}"\n'
                              f'sector = "{number}"\nerrno = "5"\nonce = "off"\n\n'
                              for direction, number in (("read", 3131), ("write", 3133))))
    cases = boot_installed_disk(output, seed)
    for machine, firmware in product(("pc", "q35"), ("bios", "uefi")):
        prefix = f"{machine}-{firmware}"
        primary = primary_disk(output / f"{prefix}-primary.raw")
        original = primary.read_bytes()
        sparse = disk(output / f"{prefix}-secondary.raw", SECTORS * SECTOR)
        other = disk(output / f"{prefix}-other.raw", SECTORS * SECTOR)
        unsupported = disk(output / f"{prefix}-4k.raw", SECTORS * SECTOR)
        zoned = disk(output / f"{prefix}-zoned.raw", SECTORS * SECTOR)
        cases.append(run(output / f"{prefix}-data", machine, firmware, data_image,
                         [(0, 1, f"blkdebug:{faults}:{primary}", 512), (0, 7, sparse, 512),
                          (0, 3, unsupported, 4096), (0, 9, zoned, 512), (1, 5, other, 512)],
                         [DATA_PASS], dual=True, zoned=((0, 9),)))
        verify_data(primary, original, ((sparse, 128), (other, 256)), (unsupported, zoned))
        root = output / f"{prefix}-root.ext2"
        shutil.copyfile(root_image, root)
        for phase, marker in (("write", "NVME_ROOT_WRITE_PASS"), ("reboot", "NVME_ROOT_REBOOT_PASS")):
            selector = "/dev/nvme0n7"
            cases.append(run(output / f"{prefix}-root-{phase}", machine, firmware, root_images[selector],
                             [(0, 7, root, 512)],
                             [marker, f"VFS_ROOT_PASS filesystem=ext2 device={selector} readonly=0"]))
        verify_fs(root)
        partition = output / f"{prefix}-partition.raw"
        mbr = bytearray(original[:SECTOR])
        struct.pack_into("<I", mbr, 458, root.stat().st_size // SECTOR)
        disk(partition, 2048 * SECTOR + root.stat().st_size, mbr)
        with partition.open("r+b") as stream, root.open("rb") as filesystem:
            stream.seek(2048 * SECTOR)
            shutil.copyfileobj(filesystem, stream)
        for name, selector in (("partition", "/dev/nvme0n7p1"), ("partuuid", PARTUUID)):
            cases.append(run(output / f"{prefix}-{name}", machine, firmware, root_images[selector],
                             [(0, 7, partition, 512)], ["NVME_ROOT_REBOOT_PASS",
                              f"VFS_ROOT_PASS filesystem=ext2 device={selector} readonly=0"]))
        extracted = output / f"{prefix}-partition.ext2"
        with partition.open("rb") as stream, extracted.open("wb") as filesystem:
            stream.seek(2048 * SECTOR)
            shutil.copyfileobj(stream, filesystem)
        verify_fs(extracted)
    (output / "results.json").write_text(json.dumps(
        {"kernel_sha256": digest(ROOT / "build/axiom64.elf"), "cases": cases}, indent=2) + "\n")


if __name__ == "__main__":
    main()
