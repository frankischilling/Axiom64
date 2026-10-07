#!/usr/bin/env python3
"""Build an ISO that boots through the same Limine protocol on BIOS and UEFI."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tarfile
from fetch import ROOT, fetch

parser = argparse.ArgumentParser()
parser.add_argument("--test", action="store_true")
parser.add_argument("--trace", action="store_true")
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
staging = ROOT / "build" / "iso"
(staging / "boot" / "limine").mkdir(parents=True, exist_ok=True)
(staging / "EFI" / "BOOT").mkdir(parents=True, exist_ok=True)
shutil.copy2(ROOT / "build" / "axiom64.elf", staging / "boot" / "axiom64.elf")
shutil.copy2(ROOT / "build" / "rootfs.cpio", staging / "boot" / "rootfs.cpio")
for filename in ["limine-bios.sys", "limine-bios-cd.bin", "limine-uefi-cd.bin"]:
    shutil.copy2(limine / filename, staging / "boot" / "limine" / filename)
shutil.copy2(limine / "BOOTX64.EFI", staging / "EFI" / "BOOT" / "BOOTX64.EFI")
shutil.copy2(limine / "LICENSE", staging / "boot" / "limine" / "LICENSE")
config = (ROOT / "boot" / "limine.conf").read_text()
options = (" test" if args.test else "") + (" trace" if args.trace else "")
config = config.replace("cmdline: init=/sbin/init", "cmdline: init=/sbin/init" + options)
(staging / "boot" / "limine" / "limine.conf").write_text(config)
destination = ROOT / "build" / ("axiom64-test.iso" if args.test else "axiom64.iso")
command = ["xorriso", "-as", "mkisofs", "-quiet", "-R", "-J", "-b", "boot/limine/limine-bios-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", "boot/limine/limine-uefi-cd.bin", "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", str(staging), "-o", str(destination)]
subprocess.run(command, check=True)
subprocess.run([str(limine / "limine"), "bios-install", str(destination)], check=True)
print(f"Boot image: {destination}")
