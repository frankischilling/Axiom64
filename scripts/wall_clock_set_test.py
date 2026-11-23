#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/wall_clock_set_test.py
# @brief   Check guest realtime changes and clock sleeps in BIOS and UEFI.

"""Compare Linux clock sleeps and test realtime changes in disposable guests."""
import argparse
import json
from pathlib import Path
import subprocess

from boot_media_test import build_medium, digest, run_guest, write_cpio
from build_musl import compiler_args, loader
from fetch import ROOT


def boot_workload(out, init, marker, *, dynamic=False):
    out.mkdir()
    kernel = ROOT / "build/axiom64.elf"
    files = {"dev": (0o40755, b""), "sbin": (0o40755, b""),
             "sbin/init": (0o100755, init.read_bytes())}
    if dynamic:
        interpreter = loader()
        files["lib"] = (0o40755, b"")
        files["lib/ld-musl-x86_64.so.1"] = (0o100755, interpreter.read_bytes())
    rootfs = out / "clock.cpio"
    write_cpio(rootfs, files)
    image = out / "boot.raw"
    build_medium("disk", image, kernel, rootfs, " test")
    cases = []
    for firmware in ("bios", "uefi"):
        case = out / firmware
        case.mkdir()
        cases.append(run_guest(case, "disk", firmware, image, marker, rootfs.stat().st_size))
    return cases


def test_sleep(out):
    source = ROOT / "userspace/tests/abi/clock-sleep.c"
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    native = out / "clock-sleep-native"
    subprocess.run(["gcc", *flags, source, "-o", native], check=True)
    reference = subprocess.check_output([native], text=True, timeout=15)
    (out / "sleep-native.log").write_text(reference)
    if reference.splitlines().count("CLOCK_SLEEP_PASS") != 1:
        raise RuntimeError("native clock sleep reference did not pass")

    results = {"native_sha256": digest(native), "workloads": {}}
    for linkage in ("static", "dynamic"):
        program = out / f"clock-sleep-{linkage}"
        options = ["-static"] if linkage == "static" else []
        subprocess.run([*compiler_args(), *flags, *options, source, "-o", program], check=True)
        cases = boot_workload(out / linkage, program, "CLOCK_SLEEP_PASS",
                              dynamic=linkage == "dynamic")
        results["workloads"][linkage] = {"sha256": digest(program), "boots": cases}
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/wall-clock-set")
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True)
    subprocess.run(["make", "-j4", "build/axiom64.elf"], cwd=ROOT, check=True)

    kernel = ROOT / "build/axiom64.elf"
    init = out / "clock-workload"
    source = ROOT / "userspace/tests/abi/wall-clock-set.c"
    subprocess.run(["musl-gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                    source, "-o", init], check=True)
    cases = boot_workload(out / "wall-clock", init, "WALL_CLOCK_SET_PASS")
    sleep = test_sleep(out)
    (out / "results.json").write_text(json.dumps({
        "kernel_sha256": digest(kernel), "workload_sha256": digest(init), "boots": cases,
        "clock_sleep": sleep,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
