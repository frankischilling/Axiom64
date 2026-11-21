#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/boot_assets.py
# @brief   Share pinned Limine files and payload staging.
# @author  frankischilling
# @date    2026-11-21
#
# Prepares the bootloader and stages the kernel and initramfs for each medium.
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

"""Common Limine payload and release files for boot media."""
import argparse
import fcntl
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from fetch import ROOT, fetch


def limine_files():
    downloads = ROOT / "downloads"
    downloads.mkdir(exist_ok=True)
    directory = downloads / "limine"
    with (downloads / "limine-build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        archive = fetch("limine")
        if not directory.exists():
            with tempfile.TemporaryDirectory(dir=downloads) as temporary:
                with tarfile.open(archive) as source:
                    source.extractall(temporary, filter="data")
                (Path(temporary) / "limine-binary").rename(directory)
        subprocess.run(["make", "-C", str(directory)], check=True, stdout=subprocess.DEVNULL)
    return directory


def copy_limine_notices(limine, directory):
    for name in ("LICENSE", "3RDPARTY.md"):
        shutil.copy2(limine / name, directory)


def init_path(value):
    if not value.startswith("/") or len(value.encode()) >= 1024 or any(char.isspace() for char in value):
        raise argparse.ArgumentTypeError("init must be an absolute path under 1024 bytes without whitespace")
    return value


def stage_payload(directory, kernel, initramfs, options, *, init="/sbin/init", network=False):
    boot = directory / "boot"
    boot.mkdir(parents=True, exist_ok=True)
    if network:
        shutil.copy2(kernel, boot / "axiom64.elf")
        with initramfs.open("rb") as stream, (boot / "rootfs.cpio.gz").open("wb") as compressed:
            with gzip.GzipFile(filename="", mode="wb", fileobj=compressed,
                               compresslevel=1, mtime=0) as output:
                shutil.copyfileobj(stream, output)
    else:
        for source, target in ((kernel, boot / "axiom64.elf"), (initramfs, boot / "rootfs.cpio")):
            target.unlink(missing_ok=True)
            try:
                os.link(source, target)
            except OSError:
                shutil.copy2(source, target)
    config = (ROOT / "boot/limine.conf").read_text()
    if network:
        config = config.replace("module_path: boot():/boot/rootfs.cpio",
                                "module_path: $boot():/boot/rootfs.cpio.gz")
    return config.replace("cmdline: init=/sbin/init", f"cmdline: init={init}{options}")
