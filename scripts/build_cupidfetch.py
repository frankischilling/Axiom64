#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/build_cupidfetch.py
# @brief   Build the pinned CupidFetch port for the desktop image.
# @author  frankischilling
# @date    2026-11-21
#
# Compiles an Axiom64 userspace executable from its verified source archive
# and retains the upstream license in the installed root.
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

"""Compile CupidFetch against the pinned build libc and Linux UAPI."""
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile

from build_musl import compiler_args
from fetch import LOCK, ROOT
from linux_uapi import headers as uapi_headers
from ports import download


def source_inputs():
    pin = LOCK["cupidfetch"]
    archive = download(pin["url"], ROOT / "downloads" / pin["archive"], expected_sha256=pin["sha256"])
    return "cupidfetch", [archive]


def runtime_files():
    pin = LOCK["cupidfetch"]
    _, (archive,) = source_inputs()
    headers, _ = uapi_headers()
    compiler = shlex.join(compiler_args("build"))
    with tempfile.TemporaryDirectory(prefix="axiom64-cupidfetch-") as directory:
        with tarfile.open(archive) as source:
            source.extractall(directory, filter="data")
        root = Path(directory) / f"cupidfetch-{pin['revision']}"
        subprocess.run(["make", "cupidfetch", f"CC={compiler}",
                        f"CFLAGS=-isystem {shlex.quote(str(headers))}", "LDFLAGS=-static -s"],
                       cwd=root, check=True)
        return {
            "usr/bin/cupidfetch": (0o100755, (root / "cupidfetch").read_bytes()),
            "usr/share/licenses/cupidfetch/LICENSE": (0o100644, (root / "LICENSE").read_bytes()),
        }
