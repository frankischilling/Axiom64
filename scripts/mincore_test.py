#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/mincore_test.py
# @brief   Boot memory residency tests from an installed NVMe disk.
# @author  frankischilling
# @date    2026-11-23

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
"""Boot the static and dynamic mincore probes under BIOS and UEFI."""
import argparse
from pathlib import Path
import shutil
import subprocess

from boot_media import build_medium
from build_musl import compiler_args, loader
from fetch import LOCK, ROOT
from newc import write_cpio


def build_fixture(output):
    files = {name: (0o40755, b"") for name in ("bin", "lib", "sbin", "tmp")}
    busybox = ROOT / "build" / ("busybox-" + LOCK["busybox"]["version"]) / "busybox"
    files["bin/busybox"] = (0o100755, busybox.read_bytes())
    files["bin/sh"] = (0o120777, b"busybox")
    files["lib/ld-musl-x86_64.so.1"] = (0o100755, loader().read_bytes())
    files["lib/libc.so"] = (0o120777, b"ld-musl-x86_64.so.1")
    files["sbin/init"] = (0o100755, b"""#!/bin/sh
cd /mnt/data || exec /bin/busybox poweroff -f
for linkage in static dynamic; do
    echo "MINCORE_LINKAGE $linkage"
    "/bin/mincore-$linkage" || exec /bin/busybox poweroff -f
done
exec /bin/busybox poweroff -f
""")
    compiler = [*compiler_args(), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    source = ROOT / "userspace/tests/abi/mincore.c"
    for linkage in ("static", "dynamic"):
        binary = output / f"mincore-{linkage}"
        flags = ["-static"] if linkage == "static" else []
        subprocess.run([*compiler, *flags, source, "-o", binary], check=True)
        files[f"bin/{binary.name}"] = (0o100755, binary.read_bytes())
    archive = output / "rootfs.cpio"
    write_cpio(archive, files)
    disk = output / "nvme.raw"
    build_medium("disk", disk, ROOT / "build/axiom64.elf", archive, " test", installed=True)
    return disk


def run_guest(output, disk, firmware):
    command = ["qemu-system-x86_64", "-machine", "q35", "-cpu", "max", "-m", "512M",
               "-display", "none", "-monitor", "none", "-serial", "stdio",
               "-nic", "none", "-no-reboot",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
               "-drive", f"if=none,id=root,format=raw,file={disk},snapshot=on",
               "-device", "nvme,drive=root,serial=AXMINCORE,bootindex=0"]
    if firmware == "uefi":
        variables = output / "OVMF_VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    log = output / f"{firmware}.log"
    with log.open("wb") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, timeout=90)
    data = log.read_text(errors="replace")
    markers = ("MINCORE_ANONYMOUS_PASS", "MINCORE_LONG_VECTOR_PASS", "MINCORE_MEMFD_PASS",
               "MINCORE_FILE_PRIVACY_PASS", "MINCORE_FILE_PASS", "MINCORE_PASS")
    if (result.returncode != 1 or "VFS_ROOT_PASS filesystem=ext2 device=PARTUUID=" not in data or
            "nvme: controller=0 nsid=1" not in data or "MINCORE_FAIL" in data or
            any(data.splitlines().count(marker) != 2 for marker in markers)):
        raise RuntimeError(f"{firmware} mincore test failed. See {log}.")
    print(f"MINCORE_NVME_PASS {firmware}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/mincore-test")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    disk = build_fixture(output)
    for firmware in ("bios", "uefi"):
        run_guest(output, disk, firmware)


if __name__ == "__main__":
    main()
