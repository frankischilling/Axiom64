#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/firefox_lab.py
# @brief   Build an installed Firefox ESR fixture for offline guest testing.
# @author  frankischilling
# @date    2026-11-24
#
# Copyright (C) 2026 frankischilling

"""Add the pinned Firefox ESR port and its notices to an installed desktop archive."""

import argparse
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile

from disk_root import archive_entries
from fetch import ROOT
from newc import write_cpio
from ports import LOCKFILE, locked_package, overlay_tar
from sources import SOURCE_LOCK, notices, port_sources


def add_browser(files, package):
    browser = {}
    with tarfile.open(locked_package(package), "r:gz", ignore_zeros=True) as stream:
        overlay_tar(browser, stream)
    for name in ("usr/bin/firefox-esr", "usr/lib/firefox-esr/libxul.so"):
        if name not in browser:
            raise RuntimeError(f"Firefox package is missing {name}")
    for name, value in browser.items():
        if name in files and files[name] != value:
            if stat.S_ISDIR(files[name][0]) and stat.S_ISDIR(value[0]):
                continue
            raise RuntimeError(f"Firefox package conflicts with installed file {name}")
        files[name] = value


def build(base, output):
    if os.path.lexists(output):
        raise FileExistsError(output)
    package = json.loads(LOCKFILE.read_text())["firefox_lab"]
    source = json.loads(SOURCE_LOCK.read_text())["firefox_lab"]
    if (package["origin"], package["source_commit"]) != (source["origin"], source["commit"]):
        raise RuntimeError("Firefox package and source recipes do not match")
    origin, inputs = port_sources(source)
    files = archive_entries(base)
    if "usr/libexec/axiom64-plasma-session" not in files:
        raise RuntimeError("Firefox needs the installed desktop archive")
    add_browser(files, package)

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".firefox-lab-", dir=output.parent) as temporary:
        stage = Path(temporary)
        notices(origin, inputs, notice_root=stage)
        license_dir = f"usr/share/licenses/{origin}"
        files[license_dir] = (0o40755, b"")
        license_files = sorted((stage / origin).iterdir())
        if not license_files:
            raise RuntimeError("The Firefox source has no license notices")
        for notice in license_files:
            files[f"{license_dir}/{notice.name}"] = (0o100644, notice.read_bytes())
        archive = stage / "rootfs.cpio"
        write_cpio(archive, files)
        os.link(archive, output)
    print(f"Firefox {package['version']} offline test archive: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new offline-test root filesystem archive")
    parser.add_argument("--base", type=Path, default=ROOT / "build/rootfs-installed-desktop.cpio",
                        help="installed desktop root filesystem archive")
    args = parser.parse_args()
    build(args.base, args.output)
