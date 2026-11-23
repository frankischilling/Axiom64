#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/boot_media_test.py
# @brief   Verify secondary boot media in QEMU.
# @author  frankischilling
# @date    2026-11-21
#
# Checks the boot payload, firmware handoff, Ring 3 execution, and invalid root arguments.
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

"""Boot disk, PXE, and optical media with the same kernel and Ring 3 probe."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

from account_normal_test import write_cpio
from boot_media import ESP_START, SECTOR, build_medium
from fetch import ROOT
from qmp import Qmp, await_serial


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_initramfs(compressed, original):
    with gzip.open(compressed, "rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest(original):
            raise RuntimeError(f"{compressed}: initramfs differs after decompression")


def inspect_disk(directory, image, kernel, initramfs):
    subprocess.run(["sfdisk", "--verify", image], check=True)
    for name in ("axiom64.elf", "rootfs.cpio.gz"):
        subprocess.run(["mcopy", "-i", f"{image}@@{ESP_START * SECTOR}", f"::/boot/{name}",
                        directory / f"disk-{name}"], check=True)
    if digest(directory / "disk-axiom64.elf") != digest(kernel):
        raise RuntimeError("disk kernel differs from the original")
    verify_initramfs(directory / "disk-rootfs.cpio.gz", initramfs)


def send_usb_input(monitor, guest, log, empty_controller):
    mouse_bus = "xhci-second" if empty_controller else "xhci"
    if empty_controller:
        monitor.command("device_add", {"driver": "usb-mouse", "bus": mouse_bus + ".0",
                                       "port": "3", "id": "boot-mouse"})
        # On qemu-xhci the USB 2 root ports follow the four SuperSpeed ports.
        await_serial(guest, log, (b"xhci-mouse-active: port=7",), 8)
    for display, key in (("usb-video-a", "a"), ("usb-video-b", "b")):
        for down in (True, False):
            monitor.command("input-send-event", {"device": display, "events": [
                {"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": key}}}
            ]})
    monitor.command("input-send-event", {"events": [
        {"type": "rel", "data": {"axis": "x", "value": 31}},
        {"type": "rel", "data": {"axis": "y", "value": -19}},
        {"type": "btn", "data": {"button": "left", "down": True}}
    ]})
    await_serial(guest, log, (b"BOOT_USB_MOUSE_PRESSED",), 8)
    monitor.command("device_del", {"id": "boot-mouse"})
    await_serial(guest, log, (b"BOOT_USB_MOUSE_RELEASED",), 8)
    monitor.command("device_add", {"driver": "usb-mouse", "bus": mouse_bus + ".0",
                                   "port": "4", "id": "hotplug-mouse"})
    await_serial(guest, log, (b"xhci-mouse-active: port=8",), 8)
    monitor.command("input-send-event", {"events": [
        {"type": "rel", "data": {"axis": "x", "value": -12}},
        {"type": "rel", "data": {"axis": "y", "value": 7}},
        {"type": "btn", "data": {"button": "left", "down": True}},
    ]})
    await_serial(guest, log, (b"BOOT_USB_HOTPLUG_MOUSE_PRESSED",), 8)
    monitor.command("input-send-event", {"events": [
        {"type": "btn", "data": {"button": "left", "down": False}},
    ]})
    monitor.command("device_del", {"id": "boot-kbd-b"})
    await_serial(guest, log, (b"xhci-keyboard-stopped: port=6",), 8)
    monitor.command("device_add", {"driver": "usb-kbd", "bus": "xhci.0", "port": "3",
                                   "display": "usb-video-b", "id": "hotplug-kbd"})
    await_serial(guest, log, (b"xhci-keyboard-active: port=7",), 8)
    for down in (True, False):
        monitor.command("input-send-event", {"device": "usb-video-b", "events": [
            {"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": "c"}}}
        ]})


def run_keyboard_guest(command, log, output, runtime_input, empty_controller=False):
    with tempfile.TemporaryDirectory(prefix="axiom64-xhci-qmp-", dir="/tmp") as temporary:
        socket = Path(temporary) / "monitor"
        with subprocess.Popen(command + ["-qmp", f"unix:{socket},server=on,wait=off"],
                              stdin=subprocess.DEVNULL, stdout=output,
                              stderr=subprocess.STDOUT) as guest:
            try:
                ready = b"BOOT_USB_INPUT_READY" if runtime_input else b"xhci-keyboard-ready:"
                await_serial(guest, log, (ready,), 60)
                monitor = Qmp(socket)
                try:
                    if runtime_input:
                        send_usb_input(monitor, guest, log, empty_controller)
                    else:
                        monitor.command("send-key", {"keys": [{"type": "qcode", "data": "a"}],
                                                     "hold-time": 350})
                finally:
                    monitor.close()
                return guest.wait(timeout=15)
            finally:
                if guest.poll() is None:
                    guest.kill()


def run_guest(directory, kind, firmware, medium, marker, module_bytes, *, invalid=False, xhci=None,
              smp=None, no_hpet=False):
    runtime_input = xhci in ("input", "input-two-controllers")
    machine = "pc,i8042=off" if runtime_input else "pc"
    if no_hpet:
        machine += ",hpet=off"
    command = ["qemu-system-x86_64", "-machine", machine, "-cpu", "max", "-m", "256M",
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=4"]
    if firmware == "uefi":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    if kind == "disk":
        command += ["-nic", "none", "-boot", "order=c,strict=on",
                    "-drive", f"file={medium},format=raw,if=ide,snapshot=on"]
    elif kind == "pxe":
        loader = "limine-bios-pxe.bin" if firmware == "bios" else "BOOTX64.EFI"
        command += ["-boot", "order=n,strict=on", "-device", "e1000,netdev=pxe",
                    "-netdev", f"user,id=pxe,restrict=on,tftp={medium},bootfile={loader}",
                    "-object", f"filter-dump,id=capture,netdev=pxe,file={directory / 'pxe.pcap'}"]
    else:
        command += ["-nic", "none", "-boot", "order=d,strict=on", "-cdrom", medium]
    if xhci == "keyboard":
        command += ["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0"]
    if runtime_input:
        command += ["-vga", "none", "-device", "VGA,id=usb-video-a",
                    "-device", "secondary-vga,id=usb-video-b", "-device", "qemu-xhci,id=xhci",
                    "-device", "usb-kbd,bus=xhci.0,port=1,display=usb-video-a",
                    "-device", "usb-kbd,bus=xhci.0,port=2,display=usb-video-b,id=boot-kbd-b"]
        if xhci == "input-two-controllers":
            command += ["-device", "qemu-xhci,id=xhci-second"]
        else:
            command += ["-device", "usb-mouse,bus=xhci.0,port=3,id=boot-mouse"]
    if smp is not None:
        threads = 2 if smp > 1 else 1
        command += ["-smp", f"cpus={smp},sockets=1,cores={smp // threads},threads={threads}"]
    log = directory / "serial.log"
    with log.open("wb") as output:
        if xhci == "keyboard" or runtime_input:
            returncode = run_keyboard_guest(command, log, output, runtime_input,
                                             xhci == "input-two-controllers")
        else:
            returncode = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=subprocess.STDOUT, timeout=90).returncode
    text = log.read_text(errors="replace")
    lines = set(text.splitlines())
    expected = {f"Firmware: {firmware.upper()}", marker, f"AXIOM64_EXIT status={int(invalid)}",
                f"Boot modules: count=1 initramfs_bytes={module_bytes}"}
    entered = "Entering userspace in Ring 3" in lines
    if (returncode != (3 if invalid else 1) or not expected <= lines or entered == invalid or
            any(token in text for token in ("PANIC:", "FAULT pid=", "FILESYSTEM_SHUTDOWN_FAIL"))):
        raise RuntimeError(f"unexpected guest result in {log}: " + "\n".join(text.splitlines()[-15:]))
    if no_hpet and "Clock: ACPI PM timer, 24-bit counter, 100 Hz accounting" not in lines:
        raise RuntimeError(f"scheduler did not select the ACPI PM timer in {log}")
    probes = [line for line in text.splitlines() if line.startswith("xhci:")]
    devices = [line for line in text.splitlines() if line.startswith("xhci-device:")]
    keyboards = [line for line in text.splitlines() if line.startswith("xhci-keyboard:")]
    keys = [line for line in text.splitlines() if line.startswith("xhci-key:")]
    if xhci == "keyboard" and (len(probes) != 1 or not re.fullmatch(
            r"xhci: pci=[0-9a-f]+:[0-9a-f]+\.[0-7] commands=130 ports=8 connected=1 stopped=1",
            probes[0])):
        raise RuntimeError(f"xHCI did not complete both rings in {log}: {probes}")
    if xhci == "keyboard" and (len(devices) != 1 or not re.fullmatch(
            r"xhci-device: port=[1-8] speed=[1-5] vendor=627 product=1 configurations=1",
            devices[0])):
        raise RuntimeError(f"xHCI did not read the keyboard descriptor in {log}: {devices}")
    if xhci == "keyboard" and (len(keyboards) != 1 or not re.fullmatch(
            r"xhci-keyboard: port=[1-8] configuration=1 interface=0 endpoint=81 packet=8 interval=[1-9][0-9]*",
            keyboards[0])):
        raise RuntimeError(f"xHCI did not configure the keyboard in {log}: {keyboards}")
    if xhci == "keyboard":
        port = devices[0].split()[1]
        if keys != [f"xhci-key: {port} usage=4 pressed=1", f"xhci-key: {port} usage=4 pressed=0"]:
            raise RuntimeError(f"xHCI did not read the key press and release in {log}: {keys}")
    if xhci == "none" and (probes or devices or keyboards or keys):
        raise RuntimeError(f"xHCI reported a controller in the absent-device case: {probes}")
    if runtime_input:
        if (sum(line.startswith("xhci-keyboard-active:") for line in lines) != 3 or
                sum(line.startswith("xhci-keyboard-stopped:") for line in lines) != 1 or
                sum(line.startswith("xhci-mouse-active:") for line in lines) != 2 or
                sum(line.startswith("xhci-mouse-stopped:") for line in lines) != 1 or
                "BOOT_USB_HOTPLUG_MOUSE_PRESSED" not in lines or
                "BOOT_USB_INPUT_PASS" not in lines):
            raise RuntimeError(f"xHCI did not deliver input from all devices in {log}")
    if smp is not None:
        summaries = re.findall(r"^SMP: present=(\d+) bsp=(\d+) application_processors=(\d+)$",
                               text, re.MULTILINE)
        entered = re.findall(r"^SMP: application processor apic=(\d+) entered$", text, re.MULTILINE)
        tables = re.findall(
            r"^SMP: application processor apic=(\d+) stack, TSS, IDT and syscall entry ready$",
            text, re.MULTILINE)
        wakeups = re.findall(
            r"^SMP: application processor apic=(\d+) wake interrupts=(\d+)$",
            text, re.MULTILINE)
        timers = re.findall(
            r"^SMP: application processor apic=(\d+) local timer interrupts=(\d+)$",
            text, re.MULTILINE)
        task_slots = re.findall(r"^SMP: application processor apic=(\d+) idle task slot ready$",
                                text, re.MULTILINE)
        shootdowns = re.findall(
            r"^SMP: application processor apic=(\d+) remote page invalidation verified$",
            text, re.MULTILINE)
        translation_targets = re.findall(r"^SMP: translation targets=(\d+) other=(\d+)$",
                                         text, re.MULTILINE)
        if (len(summaries) != 1 or summaries[0][0] != str(smp) or summaries[0][2] != str(smp - 1) or
                len(entered) != smp - 1 or len(set(entered)) != len(entered) or summaries[0][1] in entered or
                sorted(entered) != sorted(tables)):
            raise RuntimeError(f"SMP processor entry failed in {log}: {summaries} {entered} {tables}")
        if sorted(wakeups) != sorted((apic_id, "2") for apic_id in entered):
            raise RuntimeError(f"SMP targeted wake interrupts failed in {log}: {wakeups}")
        if sorted(timers) != sorted((apic_id, "2") for apic_id in entered):
            raise RuntimeError(f"SMP local timer interrupts failed in {log}: {timers}")
        if sorted(task_slots) != sorted(entered):
            raise RuntimeError(f"SMP CPU-local task slots failed in {log}: {task_slots}")
        if sorted(shootdowns) != sorted(entered):
            raise RuntimeError(f"SMP remote page invalidation failed in {log}: {shootdowns}")
        if translation_targets != ([(str(smp - 1), "0")] if smp > 1 else []):
            raise RuntimeError(f"SMP translation target selection failed in {log}: {translation_targets}")
    return {"medium": kind, "firmware": firmware, "invalid": invalid, "xhci": xhci,
            "smp": smp, "serial_sha256": digest(log)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/boot-media-test")
    parser.add_argument("--xhci", action="store_true", help="include xHCI and USB keyboard checks")
    parser.add_argument("--smp", action="store_true", help="check processor entry, IPIs and local timers")
    parser.add_argument("--scheduler", action="store_true", help="run userspace on twelve logical CPUs")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    kernel = ROOT / "build/axiom64.elf"
    init = output / "init"
    subprocess.run(["musl-gcc", "-static", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/fs/boot-media.c", "-o", init], check=True)
    token = secrets.token_hex(16)
    initramfs = output / "rootfs.cpio"
    init_payload = init.read_bytes()
    alternate = "/sbin/media-init"
    write_cpio(initramfs, {"dev": (0o40755, b""), "proc": (0o40755, b""), "sbin": (0o40755, b""),
                         "sbin/init": (0o100755, init_payload), alternate.lstrip("/"): (0o100755, init_payload),
                         "boot-proof": (0o100444, token.encode())})
    disk, pxe, iso = (output / name for name in ("boot.raw", "pxe", "boot-media.iso"))
    for kind, medium in (("disk", disk), ("pxe", pxe)):
        command = [sys.executable, ROOT / "scripts/boot_media.py", kind, medium, "--kernel", kernel,
                   "--initramfs", initramfs, "--init-path", alternate, "--kernel-option", "test"]
        subprocess.run(command, check=True)
        original = medium if kind == "disk" else medium / "limine.conf"
        before = digest(original)
        duplicate = subprocess.run(command, capture_output=True, text=True)
        if duplicate.returncode != 2 or "output already exists" not in duplicate.stderr or digest(original) != before:
            raise RuntimeError(f"{kind} builder failed to preserve an existing output")
    inspect_disk(output, disk, kernel, initramfs)
    if digest(pxe / "boot/axiom64.elf") != digest(kernel):
        raise RuntimeError("PXE kernel differs from the original")
    verify_initramfs(pxe / "boot/rootfs.cpio.gz", initramfs)
    subprocess.run([sys.executable, ROOT / "scripts/image.py", "--test", "--initramfs", initramfs,
                    "--output-directory", output, "--output-name", iso.name], cwd=ROOT, check=True)
    bad_disk = output / "invalid-root.raw"
    build_medium("disk", bad_disk, kernel, initramfs, " test root=ramfs rootflags=ro")
    bad_pxe = output / "invalid-pxe"
    build_medium("pxe", bad_pxe, kernel, initramfs, " test init=/sbin/other", init=alternate)
    cases = (("disk", disk, f"BOOT_MEDIA_PASS {alternate} {token}", False),
             ("pxe", pxe, f"BOOT_MEDIA_PASS {alternate} {token}", False),
             ("iso", iso, f"BOOT_MEDIA_PASS /sbin/init {token}", False),
             ("disk", bad_disk, "BOOT_ROOT_FAIL stage=configuration errno=22", True),
             ("pxe", bad_pxe, "BOOT_INIT_FAIL stage=configuration errno=22", True))
    results = []
    for firmware in ("bios", "uefi"):
        for kind, medium, marker, invalid in cases:
            case = output / f"{firmware}-{kind}{'-invalid' if invalid else ''}"
            case.mkdir()
            results.append(run_guest(case, kind, firmware, medium, marker, initramfs.stat().st_size, invalid=invalid))
            print(f"{case.name}: passed", flush=True)
    if args.xhci:
        target = output / "xhci-probe.raw"
        build_medium("disk", target, kernel, initramfs, " test usb.xhci=keyboard-probe", init=alternate)
        for firmware in ("bios", "uefi"):
            for device in ("none", "keyboard"):
                case = output / f"{firmware}-xhci-{device}"
                case.mkdir()
                results.append(run_guest(case, "disk", firmware, target,
                                         f"BOOT_MEDIA_PASS {alternate} {token}", initramfs.stat().st_size,
                                         xhci=device))
                print(f"{case.name}: passed", flush=True)
        input_ramfs = output / "usb-input.cpio"
        write_cpio(input_ramfs, {
            "dev": (0o40755, b""), "proc": (0o40755, b""), "sbin": (0o40755, b""),
            "sbin/init": (0o100755, init_payload), "boot-proof": (0o100444, token.encode()),
            "boot-usb-input": (0o100444, b""),
        })
        target = output / "xhci-input.raw"
        build_medium("disk", target, kernel, input_ramfs, " test usb.xhci=keyboard")
        for firmware in ("bios", "uefi"):
            for device in ("input", "input-two-controllers"):
                case = output / f"{firmware}-xhci-{device}"
                case.mkdir()
                results.append(run_guest(case, "disk", firmware, target, f"BOOT_MEDIA_PASS /sbin/init {token}",
                                         input_ramfs.stat().st_size, xhci=device))
                print(f"{case.name}: passed", flush=True)
    if args.smp:
        target = output / "smp-probe.raw"
        build_medium("disk", target, kernel, initramfs, " test smp.probe", init=alternate)
        for firmware in ("bios", "uefi"):
            for count in (1, 12):
                case = output / f"{firmware}-smp-{count}"
                case.mkdir()
                results.append(run_guest(case, "disk", firmware, target,
                                         f"BOOT_MEDIA_PASS {alternate} {token}", initramfs.stat().st_size,
                                         smp=count))
                print(f"{case.name}: passed", flush=True)
    if args.scheduler:
        worker = output / "scheduler-init"
        subprocess.run(["musl-gcc", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
                        "-pthread", ROOT / "userspace/tests/process/smp-scheduler.c",
                        "-o", worker], check=True)
        worker_ramfs = output / "scheduler.cpio"
        write_cpio(worker_ramfs, {"dev": (0o40755, b""), "proc": (0o40755, b""),
                                 "sbin": (0o40755, b""),
                                 "sbin/init": (0o100755, worker.read_bytes())})
        target = output / "scheduler.raw"
        build_medium("disk", target, kernel, worker_ramfs, " test smp.scheduler")
        for firmware in ("bios", "uefi"):
            for no_hpet in (False, True):
                suffix = "-without-hpet" if no_hpet else ""
                case = output / f"{firmware}-scheduler{suffix}"
                case.mkdir()
                results.append(run_guest(case, "disk", firmware, target, "SMP_SCHED_RUNTIME_PASS",
                                         worker_ramfs.stat().st_size, smp=12, no_hpet=no_hpet))
                print(f"{case.name}: passed", flush=True)
    (output / "results.json").write_text(json.dumps({"kernel_sha256": digest(kernel),
        "initramfs_sha256": digest(initramfs), "boots": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
