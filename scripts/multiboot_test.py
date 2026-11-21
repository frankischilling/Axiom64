#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/multiboot_test.py
# @brief   Verify the Multiboot loader and direct QEMU boot.
# @author  frankischilling
# @date    2026-11-21
#
# Exercises BIOS and UEFI handoffs, framebuffer access, and an initramfs
# or virtio disk root with a real PID 1.
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

"""Boot the Multiboot image in QEMU and compare its firmware handoffs."""

import argparse
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

from account_normal_test import write_cpio
from boot_media_test import SECTOR, digest, verify_initramfs
from fetch import ROOT


BOOT_ARGUMENTS = "test init=/sbin/media-init"
DISK_ARGUMENTS = "root=/dev/vda rootfstype=ext2 rootflags=ro"


def grub_config(protocol, *, include_module=True):
    module = "module2" if protocol == "multiboot2" else "module"
    module_line = f"    {module} /boot/rootfs.cpio\n" if include_module else ""
    return (
        "insmod all_video\nset gfxmode=auto\nset timeout=0\n"
        'menuentry "Axiom64" {\n'
        f"    {protocol} /boot/kernel.elf {BOOT_ARGUMENTS}\n"
        f"{module_line}    boot\n}}\n"
    )


def build_iso(output, kernel, initramfs, protocol, *, include_module=True):
    tree = output.with_suffix("")
    config = tree / "boot/grub/grub.cfg"
    config.parent.mkdir(parents=True)
    config.write_text(grub_config(protocol, include_module=include_module), encoding="ascii")
    shutil.copyfile(kernel, tree / "boot/kernel.elf")
    if include_module:
        shutil.copyfile(initramfs, tree / "boot/rootfs.cpio")
    with output.with_suffix(".log").open("wb") as log:
        subprocess.run(["grub-mkrescue", "-o", output, tree], check=True,
                       stdout=log, stderr=subprocess.STDOUT)


def run_guest(directory, machine, firmware, protocol, load, expected=(), *, failure=False,
              framebuffer=False, disk=None):
    directory.mkdir()
    command = ["qemu-system-x86_64", "-machine", machine, "-cpu", "max", "-m", "256M",
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
               "-nic", "none", "-device", "isa-debug-exit,iobase=0xf4,iosize=4", *load]
    if firmware == "UEFI":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    if disk:
        command += ["-drive", f"if=none,id=root,readonly=on,format=raw,file={disk}",
                    "-device", "virtio-blk-pci,drive=root,disable-legacy=on"]

    log_path = directory / "serial.log"
    with log_path.open("wb") as log:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, timeout=90)
    text = log_path.read_text(errors="replace")
    lines = set(text.splitlines())
    if failure:
        required = {"PANIC: Multiboot requires an initramfs module"}
        forbidden = ("Entering userspace in Ring 3", "BOOT_MEDIA_PASS")
        prefixes = ()
    else:
        required = {f"Boot protocol: Multiboot {protocol}", f"Firmware: {firmware}",
                    "Entering userspace in Ring 3", "AXIOM64_EXIT status=0", *expected}
        forbidden = ("PANIC:", "FAULT pid=", "FILESYSTEM_SHUTDOWN_FAIL")
        prefixes = ("ACPI MADT:", "Interrupts: xAPIC I/O APIC PIT", "PCI:")
        if machine == "q35":
            prefixes += ("PCI ECAM:",)
        if framebuffer:
            required.update({"BOOT_MEDIA_FRAMEBUFFER_PASS", "Framebuffer: 1024x768 pitch=4096 bpp=32"})
    if (result.returncode != (255 if failure else 1) or not required <= lines
            or any(item in text for item in forbidden)
            or any(not any(line.startswith(prefix) for line in lines) for prefix in prefixes)):
        raise RuntimeError(f"{directory.name} failed with status {result.returncode}\n"
                           + "\n".join(text.splitlines()[-35:]))
    print(f"{directory.name}: passed", flush=True)
    return {"case": directory.name, "serial_sha256": digest(log_path)}


def floppy_cases(output, kernel, initramfs, disk, in_ram, disk_token):
    command = [sys.executable, "-B", ROOT / "scripts/floppy_image.py", "--kernel", kernel,
               "--init-path", "/sbin/media-init", "--kernel-option", "test"]
    disk_image = output / "floppy-disk.raw"
    ram_image = output / "floppy-ram.raw"
    build_ram = [*command, ram_image, "--initramfs", initramfs]
    subprocess.run(build_ram, check=True)
    subprocess.run([*command, disk_image, "--root-device", "/dev/vda",
                    "--kernel-option", "rootfstype=ext2", "--kernel-option", "rootflags=ro"], check=True)
    for image in (ram_image, disk_image):
        subprocess.run(["sfdisk", "--verify", image], check=True)
        if image.stat().st_size != 1_474_560:
            raise RuntimeError(f"wrong floppy size: {image}")
    layout = json.loads(subprocess.check_output(["sfdisk", "--json", ram_image]))
    volume = layout["partitiontable"]["partitions"][0]["start"] * SECTOR
    kernel_gz, ram_gz = output / "floppy-kernel.gz", output / "floppy-rootfs.gz"
    for name, product in (("kernel.gz", kernel_gz), ("rootfs.gz", ram_gz)):
        subprocess.run(["mcopy", "-i", f"{ram_image}@@{volume}", f"::/{name}", product], check=True)
    verify_initramfs(kernel_gz, kernel)
    verify_initramfs(ram_gz, initramfs)

    original = digest(ram_image)
    duplicate = subprocess.run(build_ram, capture_output=True, text=True)
    if duplicate.returncode != 2 or "output already exists" not in duplicate.stderr or digest(ram_image) != original:
        raise RuntimeError("the floppy builder changed an existing image")
    oversized = output / "oversized.cpio"
    write_cpio(oversized, {"large-file": (0o100644, secrets.token_bytes(2 * 1024 * 1024))})
    rejected = output / "oversized.raw"
    too_large = subprocess.run([*command, rejected, "--initramfs", oversized],
                               capture_output=True, text=True)
    if too_large.returncode != 2 or "does not fit" not in too_large.stderr or rejected.exists():
        raise RuntimeError("the floppy builder published an oversized image")

    results = []
    for kind, image, expected, drive in (
        ("ram", ram_image, in_ram, None),
        ("disk", disk_image, (f"BOOT_MEDIA_PASS /sbin/media-init {disk_token}",), disk),
    ):
        load = ["-drive", f"if=floppy,format=raw,readonly=on,file={image}", "-boot", "order=a,strict=on"]
        results.append(run_guest(output / f"floppy-{kind}", "pc", "BIOS", 2, load, expected, disk=drive))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/multiboot-test")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["make", "-j2", "build/axiom64-multiboot.elf"], cwd=ROOT, check=True)
    kernel = ROOT / "build/axiom64-multiboot.elf"
    for probe in ("--is-x86-multiboot", "--is-x86-multiboot2"):
        subprocess.run(["grub-file", probe, kernel], check=True)

    seed = output / "root"
    init = seed / "sbin/media-init"
    init.parent.mkdir(parents=True)
    for name in ("bin", "dev", "lib", "proc", "run", "sys", "tmp"):
        (seed / name).mkdir()
    subprocess.run(["musl-gcc", "-static", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/fs/boot-media.c", "-o", init], check=True)
    token = secrets.token_hex(16)
    disk_token = secrets.token_hex(16)
    initramfs = output / "rootfs.cpio"
    write_cpio(initramfs, {"dev": (0o40755, b""), "proc": (0o40755, b""),
                          "sbin": (0o40755, b""), "sbin/media-init": (0o100755, init.read_bytes()),
                          "boot-proof": (0o100444, token.encode("ascii"))})
    (seed / "boot-proof").write_text(disk_token, encoding="ascii")
    busybox = shutil.which("busybox")
    if not busybox:
        parser.error("install busybox-static for the disk-root fixture")
    shutil.copy2(busybox, seed / "bin/busybox")
    shutil.copy2("/lib/ld-musl-x86_64.so.1", seed / "lib/ld-musl-x86_64.so.1")
    disk = output / "virtio.ext2"
    with disk.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2", "-O", "none,filetype,sparse_super",
                    "-d", seed, disk], check=True)
    disk_digest = digest(disk)
    module_line = f"Boot modules: count=1 initramfs_bytes={initramfs.stat().st_size}"
    in_ram = (f"BOOT_MEDIA_PASS /sbin/media-init {token}", module_line)

    iso = output / "grub.iso"
    iso_v1 = output / "grub-v1.iso"
    iso_missing = output / "grub-missing.iso"
    build_iso(iso, kernel, initramfs, "multiboot2")
    build_iso(iso_v1, kernel, initramfs, "multiboot")
    build_iso(iso_missing, kernel, initramfs, "multiboot2", include_module=False)
    direct = ["-kernel", kernel, "-initrd", initramfs]
    results = []
    for machine in ("pc", "q35"):
        results.append(run_guest(output / f"{machine}-direct", machine, "BIOS", 1,
                                 [*direct, "-append", BOOT_ARGUMENTS], in_ram))
        for firmware in ("BIOS", "UEFI"):
            results.append(run_guest(output / f"{machine}-grub-{firmware.lower()}", machine,
                                     firmware, 2, ["-cdrom", iso, "-boot", "d"], in_ram,
                                     framebuffer=True))
    results.append(run_guest(output / "grub-v1-bios", "pc", "BIOS", 1,
                             ["-cdrom", iso_v1, "-boot", "d"], in_ram))
    results.append(run_guest(output / "direct-disk-root", "q35", "BIOS", 1,
                             [*direct, "-append", f"{BOOT_ARGUMENTS} {DISK_ARGUMENTS}"],
                             (f"BOOT_MEDIA_PASS /sbin/media-init {disk_token}", module_line), disk=disk))
    results.append(run_guest(output / "direct-missing-module", "pc", "BIOS", 1,
                             ["-kernel", kernel, "-append", BOOT_ARGUMENTS], failure=True))
    results.append(run_guest(output / "grub-missing-module", "q35", "UEFI", 2,
                             ["-cdrom", iso_missing, "-boot", "d"], failure=True))
    results.extend(floppy_cases(output, kernel, initramfs, disk, in_ram, disk_token))
    if digest(disk) != disk_digest:
        raise RuntimeError("read-only virtio disk changed")
    (output / "results.json").write_text(json.dumps({
        "kernel_sha256": digest(ROOT / "build/axiom64.elf"),
        "wrapper_sha256": digest(kernel),
        "initramfs_sha256": digest(initramfs),
        "disk_sha256": disk_digest,
        "boots": results,
    }, indent=2) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
