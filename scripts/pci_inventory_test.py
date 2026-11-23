#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/pci_inventory_test.py
# @brief   Verify the guest PCI inventory in QEMU.
# @author  frankischilling
# @date    2026-11-23
#
# Checks discovery paths, configuration headers, and ordinary-user permissions.
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

"""Exercise real PCI functions and bridge paths through guest userspace."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

from boot_media import build_medium
from fetch import LOCK, ROOT
from newc import write_cpio


INIT = b"""#!/bin/sh
set -eux
bb=/bin/busybox
base=/sys/bus/pci/devices
trap 'printf "PCI_INVENTORY_TEST_FAIL\\n"; /bin/busybox poweroff -f' EXIT

check_device() {
    path=$1
    test -L "$path"
    test "$($bb readlink -f "$path/subsystem")" = /sys/bus/pci
    test "$($bb stat -c %a "$path/config")" = 444
    test "$($bb wc -c < "$path/config")" -eq 64
}

$bb printf 'PCI_INVENTORY_SCANNING\\n'
case "$($bb cat /etc/pci-test-layout)" in
    headless)
        for path in "$base"/*; do
            test -r "$path/class"
            case "$($bb cat "$path/class")" in 0x03*) exit 1;; esac
        done
        ;;
    *)
        vga=$base/0000:00:05.0
        check_device "$vga"
        test "$($bb readlink -f "$vga")" = /sys/devices/pci0000:00/0000:00:05.0
        test "$($bb cat "$vga/vendor")" = 0x1234
        test "$($bb cat "$vga/device")" = 0x1111
        test "$($bb cat "$vga/class")" = 0x030000
        test "$($bb od -An -v -t x1 -N 4 "$vga/config" | $bb tr -d ' \\n')" = 34121111

        gpu=
        for path in "$base"/*; do
            if test "$($bb cat "$path/vendor")" = 0x1af4 && test "$($bb cat "$path/device")" = 0x1050; then
                test -z "$gpu"
                gpu="$path"
            fi
        done
        test -n "$gpu"
        check_device "$gpu"
        case "$($bb readlink -f "$gpu")" in
            /sys/devices/pci0000:00/0000:00:06.0/"$(basename "$gpu")") ;;
            *) exit 1;;
        esac
        test "$($bb cat "$gpu/class")" = 0x038000
        test "$($bb cat "$gpu/subsystem_vendor")" = 0x1af4
        test "$($bb cat "$gpu/subsystem_device")" = 0x1100
        case "$($bb cat "$gpu/modalias")" in pci:v00001AF4d00001050sv00001AF4sd00001100bc03sc80i00) ;; *) exit 1;; esac
        test "$($bb od -An -v -t x1 -N 4 "$gpu/config" | $bb tr -d ' \\n')" = f41a5010
        test "$($bb od -An -v -t x1 -j 9 -N 3 "$gpu/config" | $bb tr -d ' \\n')" = 008003
        test "$($bb od -An -v -t x1 -j 44 -N 4 "$gpu/config" | $bb tr -d ' \\n')" = f41a0011
        $bb chpst -u observer /bin/sh -c '
            test "$(/bin/busybox id -u)" = 1000 &&
            test -r "$1" && test ! -w "$1" &&
            ! (printf fake > "$1")
        ' sh "$gpu/config"
        $bb printf 'PCI_INVENTORY_DUAL_GRAPHICS %s %s\\n' "$vga" "$gpu"
        ;;
esac
trap - EXIT
$bb printf 'PCI_INVENTORY_TEST_PASS\\n'
exec $bb poweroff -f
"""


def image_for(directory, layout, installed):
    files = {path: (0o40755, b"") for path in ("bin", "sbin", "dev", "etc", "proc", "sys", "tmp", "run", "lib")}
    loader = (ROOT / "build" / f"busybox-{LOCK['busybox']['version']}" / "busybox").read_bytes()
    files.update({
        "bin/busybox": (0o100755, loader),
        "bin/sh": (0o120777, b"/bin/busybox"),
        "bin/basename": (0o120777, b"/bin/busybox"),
        "etc/passwd": (0o100644, b"observer:x:1000:1000:Observer:/:/bin/sh\n"),
        "etc/group": (0o100644, b"observer:x:1000:\n"),
        "etc/pci-test-layout": (0o100644, layout.encode() + b"\n"),
        "sbin/init": (0o100755, INIT),
    })
    if installed:
        # The installed-root bootstrap requires an interpreter path even for this static fixture.
        files["lib/ld-musl-x86_64.so.1"] = (0o120777, b"/bin/busybox")
    archive = directory / "rootfs.cpio"
    write_cpio(archive, files)
    image = directory / "system.raw"
    build_medium("disk", image, ROOT / "build/axiom64.elf", archive, installed=installed)
    return image


def check(directory, firmware, layout, installed=False):
    directory.mkdir()
    image = image_for(directory, layout, installed)
    command = ["qemu-system-x86_64", "-machine", "pc" if firmware == "bios" else "q35",
               "-cpu", "max", "-m", "256M", "-nic", "none", "-display", "none", "-monitor", "none",
               "-no-reboot", "-serial", "stdio", "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
               "-drive", f"file={image},if=ide,format=raw,snapshot=on"]
    if layout == "headless":
        command += ["-vga", "none"]
    else:
        bridge = ("pci-bridge,chassis_nr=1" if firmware == "bios"
                  else "pcie-root-port,port=1,chassis=1,slot=1")
        command += ["-vga", "none", "-device", "VGA,addr=0x05",
                    "-device", f"{bridge},id=graphics-port,addr=0x06",
                    "-device", "virtio-gpu-pci,bus=graphics-port,addr=0"]
    if firmware == "uefi":
        variables = directory / "OVMF_VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    log = directory / "serial.log"
    with log.open("wb") as output:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=80)
    text = log.read_text(errors="replace")
    markers = {f"Firmware: {firmware.upper()}", "PCI_INVENTORY_TEST_PASS", "AXIOM64_EXIT status=0"}
    lines = text.splitlines()
    if (result.returncode != 1 or not markers.issubset(lines)
            or (installed and not any(line.startswith("VFS_ROOT_PASS filesystem=ext2 ") for line in lines))
            or (layout == "dual" and not any(line.startswith("PCI_INVENTORY_DUAL_GRAPHICS ") for line in lines))
            or "PCI_INVENTORY_TEST_FAIL" in lines
            or "incomplete)" in text or "PANIC:" in text):
        raise RuntimeError(f"PCI inventory failed for {directory.name}. See {log}")
    print(f"PCI inventory passed for {directory.name}.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    directory = args.directory
    if directory is None:
        directory = Path(tempfile.mkdtemp(prefix="pci-inventory-", dir=ROOT / "build"))
    else:
        directory.mkdir(parents=True, exist_ok=False)
    check(directory / "bios-dual", "bios", "dual")
    check(directory / "uefi-dual-installed", "uefi", "dual", installed=True)
    check(directory / "uefi-headless", "uefi", "headless")


if __name__ == "__main__":
    main()
