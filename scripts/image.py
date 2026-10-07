#!/usr/bin/env python3
"""Build an ISO that boots through the same Limine protocol on BIOS and UEFI."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from fetch import ROOT, fetch

parser = argparse.ArgumentParser()
parser.add_argument("--test", action="store_true")
parser.add_argument("--trace", action="store_true")
parser.add_argument("--suite", choices=["full", "abi", "desktop", "storage"], default="full")
parser.add_argument("--phase", choices=["write", "verify", "readonly", "error"], default="verify")
args = parser.parse_args()
archive = fetch("limine")
limine = ROOT / "downloads" / "limine"
if not (limine / "limine.c").exists():
    with tarfile.open(archive) as source:
        source.extractall(limine.parent, filter="data")
    extracted = limine.parent / "limine-binary"
    if extracted.exists() and extracted != limine:
        extracted.rename(limine)
subprocess.run(["make", "-C", str(limine)], check=True, stdout=subprocess.DEVNULL)
storage = args.test and args.suite == "storage"
staging = ROOT / "build" / ("iso-storage-" + args.phase if storage else "iso")
(staging / "boot" / "limine").mkdir(parents=True, exist_ok=True)
(staging / "EFI" / "BOOT").mkdir(parents=True, exist_ok=True)
for filename in ["axiom64.elf", "rootfs.cpio"]:
    source = ROOT / "build" / ("rootfs-desktop.cpio" if filename == "rootfs.cpio" and args.test and args.suite != "full" else filename)
    target = staging / "boot" / filename
    if target.exists():
        target.unlink()
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)
for filename in ["limine-bios.sys", "limine-bios-cd.bin", "limine-uefi-cd.bin"]:
    shutil.copy2(limine / filename, staging / "boot" / "limine" / filename)
shutil.copy2(limine / "BOOTX64.EFI", staging / "EFI" / "BOOT" / "BOOTX64.EFI")
shutil.copy2(limine / "LICENSE", staging / "boot" / "limine" / "LICENSE")
config = (ROOT / "boot" / "limine.conf").read_text()
options = (" test" if args.test else "") + (" trace" if args.trace else "")
if args.test:
    options += " suite=" + args.suite
    if args.suite == "storage":
        options += " phase=" + args.phase
config = config.replace("cmdline: init=/sbin/init", "cmdline: init=/sbin/init" + options)
(staging / "boot" / "limine" / "limine.conf").write_text(config)
destination = ROOT / "build" / ("storage-" + args.phase + ".iso" if storage else
                                  "axiom64-test.iso" if args.test else "axiom64.iso")
command = ["xorriso", "-as", "mkisofs", "-quiet", "-R", "-J", "-b", "boot/limine/limine-bios-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", "boot/limine/limine-uefi-cd.bin", "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", str(staging), "-o", str(destination)]
subprocess.run(command, check=True)
subprocess.run([str(limine / "limine"), "bios-install", str(destination)], check=True)
print(f"Boot image: {destination}")
