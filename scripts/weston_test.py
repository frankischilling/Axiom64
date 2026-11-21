#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/weston_test.py
# @brief   Verify Weston rendering and physical keyboard input in Axiom64.
# @author  frankischilling
# @date    2026-11-21
#
# Boots the installed desktop payload and drives the nested compositor in QEMU.
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
"""Verify CPU-composited Wayland pixels and physical input on both firmware paths."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

from account_normal_test import write_cpio
from boot_media_test import digest
from disk_root import archive_entries
from doom_test import await_serial, screenshot
from fetch import ROOT
from legacy_ata_test import image
from qmp import Qmp


def fixture(rootfs, destination):
    files = archive_entries(rootfs)
    launcher = "weston-nested.desktop"
    menu = files["usr/share/applications/" + launcher]
    shortcut = files["etc/skel/Desktop/" + launcher]
    if (menu[0] != 0o100644 or shortcut[0] != 0o100755 or menu[1] != shortcut[1] or
            b"Exec=/usr/bin/weston-nested\n" not in menu[1]):
        raise RuntimeError("The Weston application entries differ from the launcher.")
    accounts = {
        "etc/passwd": (0o100644, b"root:x:0:0:root:/root:/bin/sh\n"
                               b"player:x:1000:1000:Player:/tmp/player:/bin/sh\n"
                               b"other:x:1001:1001:Other:/tmp:/bin/sh\n"),
        "etc/group": (0o100644, b"root:x:0:\nplayer:x:1000:\nother:x:1001:\n"),
    }
    program = ROOT / "userspace/tests/desktop/weston.sh"
    write_cpio(destination, {**files, **accounts, "etc/boot-test.sh": (0o100755, program.read_bytes())})


def keyboard(qmp, keys):
    for key in keys:
        qmp.command("send-key", {"keys": [{"type": "qcode", "data": key}], "hold-time": 80})
        time.sleep(0.12)


def frame_pixels(path):
    header, geometry, maximum, data = path.read_bytes().split(b"\n", 3)
    width, height = map(int, geometry.split())
    if header != b"P6" or maximum != b"255" or len(data) != width * height * 3:
        raise RuntimeError(f"Malformed screen capture {path}")
    return width, data


def demo_pixels(image, width):
    # In the outer part of simple-shm's test pattern, each next column
    # advances the 24-bit pixel value by this constant. Match long spans to
    # distinguish the actual client from wallpaper and startup fades.
    matched = set()
    for start in range(0, len(image), width * 3):
        row = image[start:start + width * 3]
        run = 0
        previous = -1
        for column, (red, green, blue) in enumerate(struct.iter_unpack("BBB", row)):
            pixel = (red << 16) | (green << 8) | blue
            if previous >= 0 and pixel == (previous + 0x080401) & 0xffffff:
                run += 1
                if run == 15:
                    matched.update(range(start + 3 * (column - run), start + 3 * column, 3))
                if run >= 15:
                    matched.add(start + 3 * column)
            else:
                run = 0
            previous = pixel
    return matched


def observe_animation(case, qmp):
    before = None
    reference = set()
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        name = "shm.ppm" if before is None else "shm-later.ppm"
        screenshot(qmp, case / name)
        width, frame = frame_pixels(case / name)
        pattern = demo_pixels(frame, width)
        if len(pattern) >= 3000:
            if before is None:
                before = frame
                reference = pattern
            else:
                changed = sum(before[index:index + 3] != frame[index:index + 3]
                              for index in reference & pattern)
                if changed >= 2000:
                    return len(pattern), changed
        time.sleep(0.5)
    raise RuntimeError(f"Expected animated shared-memory pixels in {case}")


def boot(case, iso, firmware):
    with tempfile.TemporaryDirectory(prefix="axiom64-weston-qmp-") as directory:
        socket = Path(directory) / "monitor.sock"
        command = [
            "qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "1024M",
            "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none",
            "-qmp", f"unix:{socket},server=on,wait=off", "-cdrom", str(iso),
            "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
        ]
        if firmware == "uefi":
            variables = case / "OVMF_VARS.fd"
            shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
            command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                        "-drive", f"if=pflash,format=raw,file={variables}"]
        log = case / "serial.log"
        with log.open("wb") as serial:
            vm = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=serial,
                                  stderr=subprocess.STDOUT)
            try:
                await_serial(vm, log, (b"WESTON_SHM_READY",), 120)
                qmp = Qmp(socket)
                try:
                    pattern, changed = observe_animation(case, qmp)
                    vm.stdin.write(b"terminal\n")
                    vm.stdin.flush()
                    await_serial(vm, log, (b"WESTON_KEYBOARD_READY",), 45)
                    screenshot(qmp, case / "terminal.ppm")
                    keyboard(qmp, [*"touch", "spc", *"input", "minus", *"ok", "ret"])
                    await_serial(vm, log, (b"WESTON_KEYBOARD_PASS",), 15)
                finally:
                    qmp.close()
                await_serial(vm, log, (b"WESTON_TEST_PASS",), 30)
                if vm.wait(timeout=20) != 1:
                    raise RuntimeError(f"Guest failed shutdown. See {log}")
            finally:
                if vm.poll() is None:
                    vm.kill()
                    vm.wait()
    lines = log.read_text().splitlines()
    for marker in (f"Firmware: {firmware.upper()}", "WESTON_FOREIGN_DENIED", "WESTON_RUNTIME_RETIRED",
                   "WESTON_KEYBOARD_PASS", "AXIOM64_EXIT status=0"):
        if marker not in lines:
            raise RuntimeError(f"Missing {marker!r}. See {log}")
    if not any("Using Pixman renderer" in line for line in lines):
        raise RuntimeError("Weston did not use its CPU renderer.")
    return dict(firmware=firmware, pattern_pixels=pattern, changed_pattern_pixels=changed,
                serial_sha256=digest(log),
                image_sha256=digest(iso), screen_sha256={
                    name: digest(case / name) for name in ("shm.ppm", "shm-later.ppm", "terminal.ppm")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initramfs", type=Path, default=ROOT / "build/rootfs-desktop.cpio")
    parser.add_argument("--output", type=Path, default=ROOT / "build/weston-test")
    parser.add_argument("--firmware", choices=("bios", "uefi", "both"), default="both")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cpio = output / "root.cpio"
    fixture(args.initramfs, cpio)
    iso = image(output, cpio, name="weston-test.iso")
    firmwares = ("bios", "uefi") if args.firmware == "both" else (args.firmware,)
    cases = []
    for firmware in firmwares:
        case = output / firmware
        case.mkdir()
        cases.append(boot(case, iso, firmware))
        print(f"{firmware}: Weston rendering, keyboard, isolation and shutdown passed", flush=True)
    report = dict(installed_root_sha256=digest(args.initramfs), fixture_root_sha256=digest(cpio),
                  kernel_sha256=digest(ROOT / "build/axiom64.elf"), cases=cases)
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
