#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/kitty_test.py
# @brief   Exercise the installed kitty session on an NVMe boot.
# @author  frankischilling
# @date    2026-11-21
#
# Logs in through the normal account tools and sends keyboard input through QEMU.
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

"""Boot the installed desktop and type a command into kitty as a regular user."""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from boot_media import build_medium
from fetch import ROOT
from normal_login import ConsoleLogin
from qmp import Qmp


def type_command(qmp):
    codes = {" ": "spc", "/": "slash", "-": "minus", "\n": "ret"}
    for character in "touch /tmp/kitty-input-pass\n":
        qmp.command("send-key", {"keys": [{"type": "qcode", "data": codes.get(character, character)}],
                                 "hold-time": 30})
        time.sleep(0.07)


def verify_desktop(guest, serial_path, socket_path, output, timeout):
    def send(data):
        guest.stdin.write(data)
        guest.stdin.flush()

    login = ConsoleLogin(send)
    display = "DISPLAY=:0 XAUTHORITY=/run/axiom64-seat/client.auth"
    probe = f"{display} /bin/x11-probe --focus-title-exact 'Axiom64 - Terminal'"
    deadline = time.monotonic() + timeout
    focus_requested = input_sent = shutdown_requested = False
    while guest.poll() is None and time.monotonic() < deadline:
        log = serial_path.read_bytes()
        lines = {line.strip() for line in log.splitlines()}
        login.consume(log)
        if login.ready and not focus_requested:
            login.command("for attempt in $(seq 1 450); do "
                          f"if test -x \"$HOME/Desktop/kitty.desktop\" && {probe}; then "
                          "printf '%s%s\\n' KITTY_WINDOW_ READY; break; fi; "
                          f"sleep .2; done")
            focus_requested = True
        if b"KITTY_WINDOW_READY" in lines and not input_sent:
            terminal = re.search(rb"(?m)^exec pid=(\d+) /usr/libexec/desktop-terminal ", log)
            if terminal is None or (b"exec pid=" + terminal[1] + b" /bin/bash ") not in log:
                time.sleep(0.1)
                continue
            control = Qmp(socket_path)
            try:
                type_command(control)
            finally:
                control.close()
            login.command("for attempt in $(seq 1 250); do "
                          "if test -f /tmp/kitty-input-pass; then break; fi; sleep .2; done; "
                          "test \"$(stat -c %u /tmp/kitty-input-pass)\" = 1000 && "
                          "printf '%s%s\\n' KITTY_INPUT_ PASS")
            input_sent = True
        if b"KITTY_INPUT_PASS" in lines and not shutdown_requested:
            control = Qmp(socket_path)
            try:
                control.command("screendump", {"filename": str(output / "kitty.png"), "format": "png"})
            finally:
                control.close()
            login.elevate("/bin/busybox poweroff -f")
            shutdown_requested = True
        time.sleep(0.1)
    log = serial_path.read_text(errors="replace")
    required = ("Firmware: UEFI", "VFS_ROOT_PASS filesystem=ext2 device=PARTUUID=",
                "exec pid=", "/usr/bin/kitty (dynamic musl)", "KITTY_INPUT_PASS",
                "nvme: controller=0 shutdown complete", "AXIOM64_EXIT status=0")
    if (guest.poll() != 1 or not shutdown_requested or
            not all(marker in log for marker in required)):
        raise RuntimeError(f"Installed kitty test failed. See {serial_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accel", choices=("tcg", "kvm"), default="tcg")
    parser.add_argument("--timeout", type=int, default=500)
    args = parser.parse_args()
    build = ROOT / "build"
    output = Path(tempfile.mkdtemp(prefix="kitty-nvme-", dir=build))
    disk = output / "installed.raw"
    build_medium("disk", disk, build / "axiom64.elf", build / "rootfs-installed-desktop.cpio",
                 installed=True)
    variables = output / "VARS.fd"
    shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
    serial = output / "serial.log"
    with tempfile.TemporaryDirectory(prefix="axiom64-kitty-qmp-") as monitor:
        socket_path = Path(monitor) / "qmp.sock"
        command = ["qemu-system-x86_64", "-machine", "q35", "-accel", args.accel,
                   "-cpu", "host" if args.accel == "kvm" else "max", "-m", "2G",
                   "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
                   "-nic", "none", "-qmp", f"unix:{socket_path},server=on,wait=off",
                   "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                   "-drive", f"if=pflash,format=raw,file={variables}",
                   "-drive", f"if=none,id=disk,format=raw,file={disk}",
                   "-device", "nvme,drive=disk,serial=AXIOM64,bootindex=1",
                   "-device", "isa-debug-exit,iobase=0xf4,iosize=4"]
        with serial.open("wb") as stream, subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=stream, stderr=subprocess.STDOUT) as guest:
            try:
                verify_desktop(guest, serial, socket_path, output, args.timeout)
            finally:
                if guest.poll() is None:
                    guest.kill()
    print(f"KITTY_NVME_PASS artifacts={output}")


if __name__ == "__main__":
    main()
