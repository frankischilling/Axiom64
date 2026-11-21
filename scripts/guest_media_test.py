#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/guest_media_test.py
# @brief   Verify guest-owned ext2 disk images across restarts.
# @author  frankischilling
# @date    2026-11-20
#
# Reattaches the exact image exported from the guest and validates it independently.
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

"""Create an ext2 disk image in Axiom64 and use it on subsequent boots."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys

from account_normal_test import write_cpio
from fetch import LOCK, ROOT
from guest_storage_boot import boot

IMAGE_BYTES = 32 * 1024 * 1024
PAYLOAD = b"formatted inside Axiom64\n"
PHASE_MARKERS = {
    "write": "GUEST_EXT2_MEDIA_CREATED",
    "verify": "GUEST_EXT2_MEDIA_MOUNTED",
    "readonly": "GUEST_EXT2_MEDIA_REBOOT_PASS",
}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def fsck(path, logfile):
    with logfile.open("wb") as log:
        subprocess.run(["e2fsck", "-fn", path], check=True, stdout=log, stderr=subprocess.STDOUT)


def images(directory, busybox, init):
    archive = directory / "initramfs.cpio"
    files = {name: (0o40755, b"") for name in
             ("bin", "dev", "etc", "mnt", "mnt/media", "proc", "run", "sbin", "sys", "tmp")}
    files["bin/busybox"] = 0o100755, busybox.read_bytes()
    files["sbin/init"] = 0o100755, init.read_bytes()
    files["etc/storage-test.sh"] = 0o100755, (ROOT / "userspace/tests/storage/media.sh").read_bytes()
    write_cpio(archive, files)
    results = {}
    for phase in PHASE_MARKERS:
        iso = directory / f"guest-media-{phase}.iso"
        with iso.with_suffix(".image.log").open("wb") as log:
            subprocess.run([sys.executable, "-B", "scripts/image.py", "--test", "--suite", "storage",
                            "--phase", phase, "--initramfs", archive, "--output-name", iso.name,
                            "--output-directory", directory],
                           cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
        results[phase] = iso
    return results


def test(directory, boot_images, firmware, transport):
    directory.mkdir(exist_ok=True)
    carrier, media = directory / "carrier.raw", directory / "guest.ext2"
    with carrier.open("wb") as output:
        output.truncate(2 * IMAGE_BYTES)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2", "-b", "4096", "-I", "128",
                    "-O", "none,filetype,sparse_super,large_file", carrier], check=True)
    serial = boot(directory, boot_images["write"], [carrier], firmware, transport,
                  [PHASE_MARKERS["write"]])
    fsck(carrier, directory / "carrier-fsck.log")
    with media.open("wb") as output, (directory / "export.log").open("wb") as log:
        subprocess.run(["debugfs", "-R", "cat /guest.ext2", carrier], check=True,
                       stdout=output, stderr=log)
    matches = re.findall(r"^([0-9a-f]{64})  /mnt/media/guest\.ext2\r?$", serial, re.MULTILINE)
    if media.stat().st_size != IMAGE_BYTES or matches != [digest(media)]:
        raise RuntimeError(f"{directory}: exported bytes differ from the guest image")
    (directory / "formatted.sha256").write_text(matches[0] + "\n")
    fsck(media, directory / "formatted-fsck.log")

    boot(directory, boot_images["verify"], [media], firmware, transport, [PHASE_MARKERS["verify"]])
    fsck(media, directory / "mounted-fsck.log")
    persisted = subprocess.run(["debugfs", "-R", "cat /proof.txt", media],
                               check=True, capture_output=True)
    if persisted.stdout != PAYLOAD:
        raise RuntimeError(f"{directory}: persisted file differs")
    before = digest(media)
    boot(directory, boot_images["readonly"], [media], firmware, transport, [PHASE_MARKERS["readonly"]])
    if digest(media) != before:
        raise RuntimeError(f"{directory}: read-only boot changed the image")
    print(f"GUEST_MEDIA_PASS {firmware}/{transport} sha256={before}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/guest-media")
    parser.add_argument("--busybox", type=Path, help="use an already built Axiom64 BusyBox")
    parser.add_argument("--init", type=Path, help="use an already built Axiom64 init")
    parser.add_argument("--firmware", choices=("bios", "uefi", "both"), default="both")
    parser.add_argument("--transport", choices=("modern", "legacy", "both"), default="both")
    args = parser.parse_args()
    if (args.busybox is None) != (args.init is None):
        parser.error("--busybox and --init must be supplied together")
    targets = ["build/axiom64.elf"]
    if args.busybox is None:
        targets += ["build/init", "busybox"]
    subprocess.run(["make", "-j2", *targets], cwd=ROOT, check=True)
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    busybox = args.busybox or ROOT / "build" / f"busybox-{LOCK['busybox']['version']}" / "busybox"
    boot_images = images(directory, busybox, args.init or ROOT / "build/init")
    fw = ("bios", "uefi") if args.firmware == "both" else (args.firmware,)
    bus = ("modern", "legacy") if args.transport == "both" else (args.transport,)
    for firmware in fw:
        for transport in bus:
            test(directory / f"{firmware}-{transport}", boot_images, firmware, transport)


if __name__ == "__main__":
    main()
