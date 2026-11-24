#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/tmpfs_test.py
# @brief   Test tmpfs mount and quota behavior in BIOS and UEFI.

"""Exercise a bounded per-user runtime filesystem in disposable guests."""
import argparse
import json
from pathlib import Path
import subprocess

from boot_media_test import build_medium, digest, run_guest, write_cpio
from fetch import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/tmpfs")
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True)
    subprocess.run(["make", "-j4", "build/axiom64.elf"], cwd=ROOT, check=True)
    kernel = ROOT / "build/axiom64.elf"
    init = out / "tmpfs-workload"
    subprocess.run(["musl-gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/abi/tmpfs.c", "-o", init], check=True)
    rootfs = out / "tmpfs.cpio"
    write_cpio(rootfs, {"dev": (0o40755, b""), "sbin": (0o40755, b""),
                       "ram": (0o40755, b""), "sbin/init": (0o100755, init.read_bytes())})
    image = out / "boot.raw"
    build_medium("disk", image, kernel, rootfs, " test")
    cases = []
    for firmware in ("bios", "uefi"):
        case = out / firmware
        case.mkdir()
        cases.append(run_guest(case, "disk", firmware, image, "TMPFS_PASS",
                               rootfs.stat().st_size))
    (out / "results.json").write_text(json.dumps({
        "kernel_sha256": digest(kernel), "workload_sha256": digest(init), "boots": cases,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
