#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/image.py
# @brief   Assemble BIOS and UEFI boot images.
# @author  frankischilling
# @date    2026-11-21
#
# Packages the kernel and initramfs with the configured bootloader and test options.
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

"""Build an ISO that boots through the same Limine protocol on BIOS and UEFI."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
from boot_assets import copy_limine_notices, init_path, limine_files, stage_payload
from fetch import ROOT

parser = argparse.ArgumentParser()
parser.add_argument("--test", action="store_true")
parser.add_argument("--trace", action="store_true")
parser.add_argument("--suite", choices=["full", "abi", "desktop", "storage", "ext2", "threads", "root", "network"], default="full")
parser.add_argument("--phase", choices=["write", "verify", "readonly", "error", "recovery", "queue",
                                       "invalid", "full", "all", "cond", "io", "pressure", "cache",
                                       "mapping-held"], default="verify")
parser.add_argument("--output-name", help="ISO filename under build/ for an isolated test run")
parser.add_argument("--output-directory", type=Path, help="directory for the completed ISO")
parser.add_argument("--initramfs", type=Path, help="explicit initramfs for an isolated fixture")
parser.add_argument("--kernel", type=Path, help="explicit kernel ELF for an isolated fixture")
parser.add_argument("--init-path", type=init_path, default="/sbin/init", help="absolute guest PID 1 path")
parser.add_argument("--root-device", help="disk or partition device, PARTUUID=, or PARTLABEL=")
parser.add_argument("--root-readonly", action="store_true")
parser.add_argument("--root-recovery", action="store_true", help="validate a structurally consistent dirty ext2 root")
parser.add_argument("--kernel-option", action="append", default=[], help="one additional kernel command-line token")
args = parser.parse_args()
if args.root_device is not None:
    device = re.fullmatch(r"/dev/(?:vd[a-h]|sd[a-l])([1-9][0-9]{0,2})?", args.root_device)
    nvme = re.fullmatch(r"/dev/nvme[0-3]n([1-9][0-9]{0,9})(?:p([1-9][0-9]{0,2}))?",
                        args.root_device)
    uuid = re.fullmatch(r"PARTUUID=(?:[\da-fA-F]{8}-[\da-fA-F]{2}|"
                        r"[\da-fA-F]{8}(?:-[\da-fA-F]{4}){3}-[\da-fA-F]{12})",
                        args.root_device, re.ASCII)
    label = (args.root_device.startswith("PARTLABEL=") and 10 < len(args.root_device.encode()) < 119
             and not any(character.isspace() for character in args.root_device))
    if not (uuid or label or (device and int(device[1] or "0") <= 128) or
            (nvme and int(nvme[1]) < 0xffffffff and int(nvme[2] or "0") <= 128)):
        parser.error("--root-device must name a virtio, ATA, or NVMe disk or partition, PARTUUID, or PARTLABEL")
if args.root_readonly and not args.root_device:
    parser.error("--root-readonly requires --root-device")
if args.root_recovery and not args.root_device:
    parser.error("--root-recovery requires --root-device")
if args.initramfs and args.root_device:
    parser.error("--initramfs cannot replace the disk-root bootstrap")
if args.initramfs:
    args.initramfs = args.initramfs.resolve()
    if not args.initramfs.is_file():
        parser.error("--initramfs must name an existing file")
if any(not token or any(character.isspace() for character in token) for token in args.kernel_option):
    parser.error("--kernel-option must be a nonempty token without whitespace")
if args.output_name and (Path(args.output_name).name != args.output_name or
                         not args.output_name.endswith(".iso") or "\\" in args.output_name):
    parser.error("--output-name must be an ISO filename without directory components")
limine = limine_files()
disk_suite = args.test and args.suite in ["storage", "ext2", "root"]
staging = ROOT / "build" / ("iso-" + args.output_name[:-4] if args.output_name else
                            "iso-" + args.suite + "-" + args.phase if disk_suite else "iso")
(staging / "boot" / "limine").mkdir(parents=True, exist_ok=True)
(staging / "EFI" / "BOOT").mkdir(parents=True, exist_ok=True)
desktop_profile = args.suite not in ["full", "threads"] or (args.suite == "threads" and args.phase in ["cond", "io"])
kernel = args.kernel or ROOT / "build/axiom64.elf"
initramfs = ROOT / "build" / ("rootfs-desktop.cpio" if args.test and desktop_profile else "rootfs.cpio")
if args.test and args.suite == "network":
    initramfs = ROOT / "build/rootfs-network.cpio"
if args.initramfs:
    initramfs = args.initramfs
if args.root_device:
    initramfs = ROOT / "build/rootfs-bootstrap.cpio"
for filename in ["limine-bios.sys", "limine-bios-cd.bin", "limine-uefi-cd.bin"]:
    shutil.copy2(limine / filename, staging / "boot" / "limine" / filename)
shutil.copy2(limine / "BOOTX64.EFI", staging / "EFI" / "BOOT" / "BOOTX64.EFI")
copy_limine_notices(limine, staging / "boot" / "limine")
options = (" test" if args.test else "") + (" trace" if args.trace else "")
if args.test:
    options += " suite=" + args.suite
    if disk_suite or args.suite in ["threads", "network"]:
        options += " phase=" + args.phase
if args.root_device:
    options += " root=" + args.root_device + " rootfstype=ext2 rootflags=" + ("ro" if args.root_readonly else "rw")
    if args.root_recovery:
        options += ",recovery=check"
for token in args.kernel_option:
    options += " " + token
config = stage_payload(staging, kernel, initramfs, options, init=args.init_path)
(staging / "boot" / "limine" / "limine.conf").write_text(config)
output_directory = (args.output_directory.resolve() if args.output_directory else ROOT / "build")
output_directory.mkdir(parents=True, exist_ok=True)
destination = output_directory / (args.output_name if args.output_name else
                                  args.suite + "-" + args.phase + ".iso" if disk_suite else
                                  "axiom64-test.iso" if args.test else "axiom64.iso")
command = ["xorriso", "-as", "mkisofs", "-quiet", "-R", "-J", "-b", "boot/limine/limine-bios-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", "boot/limine/limine-uefi-cd.bin", "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", str(staging), "-o", str(destination)]
subprocess.run(command, check=True)
subprocess.run([str(limine / "limine"), "bios-install", str(destination)], check=True)
print(f"Boot image: {destination}")
