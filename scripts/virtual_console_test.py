#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/virtual_console_test.py
# @brief   Verify the foreground virtual console in BIOS and UEFI guests.

"""Exercise the console identity required by desktop session managers."""
import argparse
import json
from pathlib import Path
import subprocess

from boot_media_test import build_medium, digest, run_guest, write_cpio
from fetch import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/virtual-console")
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True)
    subprocess.run(["make", "-j4", "build/axiom64.elf"], cwd=ROOT, check=True)
    kernel = ROOT / "build/axiom64.elf"
    init = out / "virtual-console-workload"
    subprocess.run([
        "python3", "scripts/compile_uapi_client.py", "--compiler", "musl-gcc",
        "--output", init, "--", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
        "userspace/tests/abi/virtual-console.c",
    ], cwd=ROOT, check=True)
    rootfs = out / "virtual-console.cpio"
    write_cpio(rootfs, {"dev": (0o40755, b""), "sbin": (0o40755, b""),
                       "sbin/init": (0o100755, init.read_bytes())})
    image = out / "boot.raw"
    build_medium("disk", image, kernel, rootfs, " test")
    cases = []
    for firmware in ("bios", "uefi"):
        case = out / firmware
        case.mkdir()
        cases.append(run_guest(case, "disk", firmware, image, "FOREGROUND_CONSOLE_PASS",
                               rootfs.stat().st_size))
    (out / "results.json").write_text(json.dumps({
        "kernel_sha256": digest(kernel), "workload_sha256": digest(init), "boots": cases,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
