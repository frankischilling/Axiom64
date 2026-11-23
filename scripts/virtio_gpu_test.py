#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/virtio_gpu_test.py
# @brief   Verify real Virtio GPU scanout in QEMU.
# @author  frankischilling
# @date    2026-11-23
#
# Captures two guest-drawn frames, and checks firmware fallback without a GPU.
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

"""Check host-visible pixels from a guest using the Virtio GPU."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from boot_media import build_medium
from fetch import ROOT
from newc import write_cpio
from qmp import Qmp, await_serial


COLORS = (b"\xff\x00\x00", b"\x00\xff\x00", b"\x00\x00\xff", b"\xff\xff\xff")


def match_frame(path, frame, width, height):
    if not path.is_file():
        return False
    magic, dimensions, levels, data = path.read_bytes().split(b"\n", 3)
    if magic != b"P6" or dimensions != f"{width} {height}".encode() or levels != b"255":
        return False
    if len(data) != width * height * 3:
        return False
    points = ((100, 100), (width - 100, 100), (100, height - 100),
              (width - 100, height - 100))
    for index, (x, y) in enumerate(points):
        offset = (y * width + x) * 3
        if data[offset:offset + 3] != COLORS[(index + frame) % 4]:
            return False
    return True


def capture(monitor, directory, frame, width, height):
    path = directory / f"frame-{frame + 1}.ppm"
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        monitor.command("screendump", {"filename": str(path), "format": "ppm"})
        if match_frame(path, frame, width, height):
            return
        time.sleep(.15)
    raise RuntimeError(f"Guest frame {frame + 1} did not appear in {path}")


def boot(directory, firmware, fallback, init, drm=False):
    directory.mkdir()
    archive = directory / "rootfs.cpio"
    files = {path: (0o40755, b"") for path in ("dev", "proc", "sys", "sbin")}
    files["sbin/init"] = (0o100755, init.read_bytes())
    if fallback and not drm:
        files["gpu-fallback"] = (0o100444, b"")
    write_cpio(archive, files)
    disk = directory / "boot.raw"
    options = " virtio.gpu=2d" + (" drm.scanout" if drm else "")
    build_medium("disk", disk, ROOT / "build/axiom64.elf", archive, options)
    command = ["qemu-system-x86_64", "-machine", "q35", "-cpu", "max", "-m", "256M",
               "-nic", "none", "-display", "none", "-monitor", "none", "-serial", "stdio",
               "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
               "-drive", f"file={disk},if=ide,format=raw,snapshot=on"]
    if fallback:
        command += ["-vga", "std"]
    else:
        command += ["-vga", "none", "-device", "virtio-gpu-pci,id=scanout,xres=800,yres=600"]
    if firmware == "uefi":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    log = directory / "serial.log"
    prefix = "DRM_SCANOUT" if drm else "VIRTIO_GPU"
    frames = tuple(f"{prefix}_FRAME_{label}".encode() for label in ("ONE", "TWO"))
    dimensions = (1024, 768) if fallback else (800, 600)
    with tempfile.TemporaryDirectory(prefix="axiom64-gpu-qmp-", dir="/tmp") as temporary:
        qmp = Path(temporary) / "qmp"
        command += ["-qmp", f"unix:{qmp},server=on,wait=off"]
        with log.open("wb") as output, subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output,
                                                       stderr=subprocess.STDOUT) as guest:
            try:
                if drm or not fallback:
                    await_serial(guest, log, frames[:1], 55)
                    control = Qmp(qmp)
                    try:
                        for frame, ready in enumerate(frames):
                            await_serial(guest, log, (ready,), 12)
                            capture(control, directory, frame, *dimensions)
                            guest.stdin.write(b"\n")
                            guest.stdin.flush()
                    finally:
                        control.close()
                result = guest.wait(timeout=60)
            finally:
                if guest.poll() is None:
                    guest.kill()
                    guest.wait()
    lines = log.read_text(errors="replace").splitlines()
    expected = {"AXIOM64_EXIT status=0", f"Firmware: {firmware.upper()}"}
    if drm:
        expected.add("DRM_SCANOUT_GUEST_PASS")
    elif fallback:
        expected.add("VIRTIO_GPU_FIRMWARE_FALLBACK")
    else:
        expected.add("VIRTIO_GPU_GUEST_PASS")
    if not fallback:
        expected.add("virtio-gpu: scanout=0 800x600 pitch=3200")
    if result != 1 or not expected.issubset(lines):
        raise RuntimeError(f"{prefix} test failed for {directory.name}. See {log}")
    print(f"{prefix} passed for {directory.name}.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--drm", action="store_true")
    args = parser.parse_args()
    if args.directory is None:
        prefix = "drm-scanout-" if args.drm else "virtio-gpu-"
        directory = Path(tempfile.mkdtemp(prefix=prefix, dir=ROOT / "build"))
    else:
        directory = args.directory
        directory.mkdir(parents=True, exist_ok=False)
    init = directory / "init"
    source = "drm-scanout.c" if args.drm else "virtio-gpu.c"
    subprocess.run(["musl-gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-idirafter", "/usr/include", "-idirafter", "/usr/include/x86_64-linux-gnu",
                    ROOT / "userspace/tests/desktop" / source, "-o", init], check=True)
    boot(directory / "bios-scanout", "bios", False, init, args.drm)
    boot(directory / "uefi-scanout", "uefi", False, init, args.drm)
    boot(directory / "uefi-firmware-fallback", "uefi", True, init, args.drm)


if __name__ == "__main__":
    main()
