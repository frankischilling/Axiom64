#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build and run the native toolchain examples from an installed NVMe desktop."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
from time import monotonic, sleep

from boot_media import build_medium
from boot_media_test import digest
from fetch import ROOT
from legacy_ports_test import add_firmware

SAMPLES = ("Makefile", "arithmetic.asm", "broken.c", "hello.c", "hello.cpp",
           "library.cpp", "shared.cpp", "threads.cpp")


def verify(disk, output, firmware, samples):
    log = output / f"{firmware}.log"
    command = ["qemu-system-x86_64", "-machine", "q35", "-m", "2048",
               "-display", "none", "-monitor", "none", "-serial", "stdio",
               "-nic", "none", "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
               "-drive", f"if=none,id=root,format=raw,file={disk},snapshot=on",
               "-device", "nvme,drive=root,serial=AXDEVTOOLS,bootindex=0"]
    command += (["-accel", "kvm", "-cpu", "host"] if os.access("/dev/kvm", os.R_OK | os.W_OK)
                else ["-cpu", "max"])
    add_firmware(command, output, firmware)
    password = "dev-toolchain-guest26"
    with log.open("wb") as stream, subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=stream, stderr=subprocess.STDOUT) as vm:
        cursor = 0

        def wait(marker, timeout=120):
            nonlocal cursor
            until = monotonic() + timeout
            while monotonic() < until:
                found = log.read_bytes().find(marker, cursor)
                if found >= 0:
                    cursor = found + len(marker)
                    return
                if vm.poll() is not None:
                    break
                sleep(0.1)
            raise RuntimeError(f"{firmware} did not report {marker!r}. See {log}")

        def send(line):
            vm.stdin.write(line.encode() + b"\n")
            vm.stdin.flush()

        def run(line, number, timeout=120):
            marker = f"INSTALLED_TOOLCHAIN_STEP_{number}"
            # Split the marker so the echoed command cannot satisfy the wait.
            send(f"{line} && printf '%s\\n' 'INSTALLED_TOOLCHAIN_''STEP_{number}'")
            wait(marker.encode(), timeout)

        try:
            for marker, answer in (
                (b"Administrator name: ", "devcheck"),
                (b"New password: ", password),
                (b"Confirm password: ", password),
                (b"login: ", "devcheck"),
                (b"Password: ", password),
            ):
                wait(marker)
                send(answer)
            wait(b"$ ")
            run("test \"$(id -u)\" = 1000 && mkdir \"$HOME/toolchain\" && cd \"$HOME/toolchain\"", 0)
            for index, name in enumerate(SAMPLES, 1):
                encoded = base64.b64encode(samples[name]).decode()
                run(f"printf '%s' {encoded} | base64 -d > {name}", index)
            run("make -j2 test", 9, timeout=300)
            run("ar rcs libnative.a /tmp/native-arithmetic.o && nm libnative.a | "
                "grep -w native_asm_add && readelf -h /tmp/native-cpp | grep -q ELF64", 10)
            send("sudo /bin/busybox poweroff -f")
            wait(b"Password: ")
            send(password)
            vm.wait(timeout=40)
        finally:
            if vm.poll() is None:
                vm.kill()
                vm.wait()
    text = log.read_text(errors="replace")
    required = (f"Firmware: {firmware.upper()}", "VFS_ROOT_PASS filesystem=ext2 device=PARTUUID=",
                "nvme: controller=0 nsid=1", "NATIVE_C_PASS", "NATIVE_ASSEMBLER_PASS",
                "NATIVE_CPP_PASS", "NATIVE_THREADS_PASS", "NATIVE_SHARED_CPP_PASS",
                "NATIVE_DIAGNOSTICS_PASS", "AXIOM64_EXIT status=0")
    if vm.returncode != 1 or any(marker not in text for marker in required):
        raise RuntimeError(f"Installed toolchain checks failed. See {log}")
    print(f"INSTALLED_TOOLCHAIN_NVME_PASS {firmware}", flush=True)
    return dict(firmware=firmware, serial_sha256=digest(log))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/installed-toolchain-test")
    args = parser.parse_args()
    result = args.output.resolve()
    result.mkdir(parents=True, exist_ok=False)
    kernel = ROOT / "build/axiom64.elf"
    archive = ROOT / "build/rootfs-installed-desktop.cpio"
    examples = ROOT / "userspace/tests/toolchain"
    samples = {name: (examples / name).read_bytes() for name in SAMPLES}
    disk = result / "installed.raw"
    build_medium("disk", disk, kernel, archive, " console.text", installed=True)
    record = dict(kernel_sha256=digest(kernel), archive_sha256=digest(archive), boots=[])
    for firmware in ("bios", "uefi"):
        record["boots"].append(verify(disk, result, firmware, samples))
        (result / "results.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
