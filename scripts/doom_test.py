#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/doom_test.py
# @brief   Check the installed Freedoom campaigns in the guest.
# @author  frankischilling
# @date    2026-11-21
#
# Verifies launch entries, physical input, frame changes, and captured audio.
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

"""Check the installed Freedoom launchers and game in QEMU."""
import argparse
import configparser
from pathlib import Path
import json
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import wave

from account_normal_test import write_cpio
from boot_media import build_medium
from boot_media_test import digest
from build_doom import WADS, verify_engine
from disk_root import archive_entries
from fetch import ROOT
from legacy_ata_test import image
from qmp import Qmp


def installed_applications(files, output):
    manifest = json.loads(files["usr/share/licenses/chocolate-doom/manifest.json"][1])
    engine = output / "installed-chocolate-doom"
    mode, contents = files["usr/bin/chocolate-doom"]
    if mode != 0o100755:
        raise RuntimeError("Installed Chocolate Doom is not executable")
    engine.write_bytes(contents)
    verify_engine(engine)
    if digest(engine) != manifest["products"]["chocolate-doom"]:
        raise RuntimeError("Installed Chocolate Doom differs from the build")
    if any(name.startswith("usr/include/SDL2/") for name in files):
        raise RuntimeError("Build-only SDL2 headers leaked into the desktop image")
    commands = []
    for phase, name in enumerate(WADS, 1):
        wad = output / name
        mode, contents = files["usr/share/games/doom/" + name]
        wad.write_bytes(contents)
        if mode != 0o100644 or contents[:4] != b"IWAD" or digest(wad) != manifest["products"][name]:
            raise RuntimeError("Installed Freedoom IWAD differs from the checked release")
        launcher = f"freedoom-phase-{phase}.desktop"
        menu_mode, menu = files["usr/share/applications/" + launcher]
        shortcut_mode, shortcut = files["etc/skel/Desktop/" + launcher]
        desktop = configparser.ConfigParser(interpolation=None)
        desktop.read_string(menu.decode())
        entry = desktop["Desktop Entry"]
        command = shlex.split(entry["Exec"])
        if (menu_mode != 0o100644 or shortcut_mode != 0o100755 or menu != shortcut or
                entry["Type"] != "Application" or "Game;" not in entry["Categories"] or
                command != ["/usr/bin/freedoom", str(phase)]):
            raise RuntimeError(f"Incorrect desktop registration for phase {phase}")
        commands.append(command)
    return commands


def fixture(files, path, command, phase):
    arguments = ["-nogui", "-nograbmouse", "-nomonsters", "-warp"]
    arguments.extend(["1", "1"] if phase == 1 else ["01"])
    script = """#!/bin/sh
export PATH=/usr/bin:/bin:/sbin:/usr/sbin HOME=/tmp/player
mkdir -p "$HOME" || exit 1
chown 1000:29 "$HOME" || exit 1
. /etc/x11-session.sh
x11_server || exit 1
setuidgid player /etc/desktop-client-session.sh &
desktop=$!
for attempt in $(seq 1 80); do
    test -f "$HOME/.local/share/axiom64/desktop-shortcuts" && break
    kill -0 "$desktop" || exit 1
    sleep .1
done
for phase in 1 2; do
    name=freedoom-phase-$phase.desktop
    cmp "/usr/share/applications/$name" "$HOME/Desktop/$name" || exit 1
    setuidgid player /bin/busybox test -x "$HOME/Desktop/$name" || exit 1
done
echo DOOM_SHORTCUTS_READY
export SDL_VIDEODRIVER=x11
setuidgid player GAME_COMMAND &
game=$!
for attempt in $(seq 1 160); do
    if /bin/x11-probe --focus-title Freedoom; then echo DOOM_INPUT_READY; break; fi
    sleep .2
done
(
    for attempt in $(seq 1 240); do
        kill -0 "$game" 2>/dev/null || exit 0
        if /bin/x11-probe --focus-title-exact 'Chocolate Doom 3.1.1'; then
            echo DOOM_END_READY
            exit 0
        fi
        sleep .25
    done
) &
observer=$!
wait "$game"
status=$?
kill "$observer" 2>/dev/null || true
wait "$observer" 2>/dev/null || true
echo "DOOM_EXIT status=$status"
kill "$desktop" 2>/dev/null || true
x11_stop
/bin/busybox poweroff -f
""".replace("GAME_COMMAND", shlex.join(command + arguments))
    accounts = {
        "etc/passwd": (0o100644, b"root:x:0:0:root:/root:/bin/sh\n"
                               b"player:x:1000:29:Player:/tmp/player:/bin/sh\n"),
        "etc/group": (0o100644, b"root:x:0:\naudio:x:29:player\n"),
    }
    write_cpio(path, {**files, **accounts, "sbin/init": (0o100755, script.encode())})


def await_serial(vm, log, markers, timeout):
    deadline = time.monotonic() + timeout
    while True:
        data = log.read_bytes()
        for marker in markers:
            if marker in data:
                return marker
        if time.monotonic() >= deadline or vm.poll() is not None:
            raise RuntimeError(f"Missing {markers!r}. See {log}")
        time.sleep(0.1)


def screenshot(qmp, path):
    qmp.command("screendump", {"filename": str(path), "format": "ppm"})


def picture(path):
    header, geometry, maximum, data = path.read_bytes().split(b"\n", 3)
    width, height = map(int, geometry.split())
    if header != b"P6" or maximum != b"255" or len(data) != width * height * 3:
        raise RuntimeError(f"Malformed screen capture {path}")
    x0, y0, span, rows = (width - 640) // 2, (height - 420) // 2, 640, 420
    if x0 < 0 or y0 < 0:
        raise RuntimeError(f"Display fixture is too small: {path}")
    return b"".join(data[(y * width + x0) * 3:(y * width + x0 + span) * 3]
                    for y in range(y0, y0 + rows))


def verify_play(output):
    before = picture(output / "level.ppm")
    after = picture(output / "moved.ppm")
    colors = len(set(struct.iter_unpack("BBB", before)))
    changed = sum(left != right for left, right in zip(before, after))
    if colors < 32 or changed < 30000:
        raise RuntimeError(f"Rendered scene or movement missing in {output}")
    with wave.open(str(output / "audio.wav"), "rb") as wav:
        if (wav.getnchannels(), wav.getsampwidth()) != (2, 2):
            raise RuntimeError("Unexpected playback recording format")
        samples = wav.readframes(wav.getnframes())
    audible = sum(abs(value) >= 32 for value, in struct.iter_unpack("<h", samples))
    if audible < 18000:
        raise RuntimeError(f"Game audio missing in {output}")
    return dict(scene_colors=colors, changed_components=changed, audible_samples=audible)


def boot(output, medium, firmware, phase, *, nvme=False):
    with tempfile.TemporaryDirectory(prefix="axiom64-doom-qmp-") as directory:
        socket = Path(directory) / "monitor.sock"
        machine = "pc" if firmware == "bios" else "q35"
        controller = "intel-hda" if machine == "pc" else "ich9-intel-hda"
        command = [
            "qemu-system-x86_64", "-machine", machine, "-cpu", "max", "-m", "1024M",
            "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none",
            "-qmp", f"unix:{socket},server=on,wait=off",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
            "-audiodev", f"wav,id=doom,path={output / 'audio.wav'},out.frequency=44100",
            "-device", f"{controller},id=hda", "-device", "hda-output,bus=hda.0,audiodev=doom",
        ]
        if nvme:
            command += ["-drive", f"if=none,id=installed,format=raw,file={medium}",
                        "-device", "nvme,drive=installed,serial=AXIOM64,bootindex=1"]
        else:
            command += ["-cdrom", str(medium)]
        if firmware == "uefi":
            variables = output / "OVMF_VARS.fd"
            shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
            command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                        "-drive", f"if=pflash,format=raw,file={variables}"]
        log = output / "serial.log"
        with log.open("wb") as serial:
            vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=serial,
                                  stderr=subprocess.STDOUT)
            try:
                await_serial(vm, log, (b"DOOM_SHORTCUTS_READY",), 90)
                await_serial(vm, log, (b"DOOM_INPUT_READY",), 120)
                time.sleep(3)
                qmp = Qmp(socket)
                try:
                    screenshot(qmp, output / "level.ppm")
                    for key, hold, delay in (("up", 1800, 2.5), ("f10", 100, 2.0),
                                              ("y", 100, 0.0)):
                        qmp.command("send-key", {"keys": [{"type": "qcode", "data": key}],
                                                "hold-time": hold})
                        time.sleep(delay)
                        if key == "up":
                            screenshot(qmp, output / "moved.ppm")
                    exit_status = b"DOOM_EXIT status=0"
                    if await_serial(vm, log, (exit_status, b"DOOM_END_READY"), 20) != exit_status:
                        screenshot(qmp, output / "end.ppm")
                        qmp.command("send-key", {"keys": [{"type": "qcode", "data": "ret"}],
                                                "hold-time": 100})
                finally:
                    qmp.close()
                await_serial(vm, log, (b"DOOM_EXIT status=0",), 30)
                if vm.wait(timeout=20) != 1:
                    raise RuntimeError(f"Guest failed shutdown. See {log}")
            finally:
                if vm.poll() is None:
                    vm.kill()
                    vm.wait()
    data = log.read_text()
    markers = [f"Firmware: {firmware.upper()}", f"Freedoom: Phase {phase}",
               "OPL_Init: Using driver 'SDL'.", "AXIOM64_EXIT status=0"]
    if nvme:
        markers += ["VFS_ROOT_PASS filesystem=ext2 device=PARTUUID=", "nvme: controller=0 shutdown complete"]
    for marker in markers:
        if marker not in data:
            raise RuntimeError(f"Missing {marker!r}. See {log}")
    return dict(firmware=firmware, phase=phase, medium="nvme" if nvme else "iso", serial_sha256=digest(log),
                wav_sha256=digest(output / "audio.wav"), **verify_play(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initramfs", type=Path, default=ROOT / "build/rootfs-desktop.cpio")
    parser.add_argument("--output", type=Path, default=ROOT / "build/doom-test")
    parser.add_argument("--verify-image", action="store_true")
    parser.add_argument("--nvme", action="store_true", help="cold-boot both campaigns from standalone NVMe disks")
    options = parser.parse_args()
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    files = archive_entries(options.initramfs)
    applications = installed_applications(files, output)
    print(f"DOOM_IMAGE_PASS launchers={len(applications)}")
    if options.verify_image:
        return
    cases = []
    configurations = (("uefi", 1), ("uefi", 2)) if options.nvme else (("bios", 1), ("uefi", 2))
    for firmware, phase in configurations:
        cell = output / f"{firmware}-phase-{phase}"
        cell.mkdir()
        cpio = cell / "root.cpio"
        fixture(files, cpio, applications[phase - 1], phase)
        if options.nvme:
            medium = cell / "freedoom.raw"
            build_medium("disk", medium, ROOT / "build/axiom64.elf", cpio, " test", installed=True)
        else:
            medium = image(cell, cpio, name="freedoom.iso")
        cases.append(boot(cell, medium, firmware, phase, nvme=options.nvme))
        print(f"{cell.name}: passed", flush=True)
    report = dict(root_sha256=digest(options.initramfs),
                  kernel_sha256=digest(ROOT / "build/axiom64.elf"), cases=cases)
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
