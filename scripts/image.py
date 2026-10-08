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
parser.add_argument("--suite", choices=["full", "abi", "desktop", "storage", "ext2", "threads", "root", "network"], default="full")
parser.add_argument("--phase", choices=["write", "verify", "readonly", "error", "queue", "invalid", "full", "all", "cond", "io", "pressure"], default="verify")
parser.add_argument("--output-name", help="ISO filename under build/ for an isolated test run")
parser.add_argument("--root-device", choices=[f"/dev/vd{letter}" for letter in "abcdefgh"])
parser.add_argument("--root-readonly", action="store_true")
parser.add_argument("--kernel-option", action="append", default=[], help="one additional kernel command-line token")
args = parser.parse_args()
if args.root_readonly and not args.root_device:
    parser.error("--root-readonly requires --root-device")
if any(not token or any(character.isspace() for character in token) for token in args.kernel_option):
    parser.error("--kernel-option must be a nonempty token without whitespace")
if args.output_name and (Path(args.output_name).name != args.output_name or
                         not args.output_name.endswith(".iso") or "\\" in args.output_name):
    parser.error("--output-name must be an ISO filename without directory components")
archive = fetch("limine")
limine = ROOT / "downloads" / "limine"
if not (limine / "limine.c").exists():
    with tarfile.open(archive) as source:
        source.extractall(limine.parent, filter="data")
    extracted = limine.parent / "limine-binary"
    if extracted.exists() and extracted != limine:
        extracted.rename(limine)
subprocess.run(["make", "-C", str(limine)], check=True, stdout=subprocess.DEVNULL)
disk_suite = args.test and args.suite in ["storage", "ext2", "root"]
staging = ROOT / "build" / ("iso-" + args.output_name[:-4] if args.output_name else
                            "iso-" + args.suite + "-" + args.phase if disk_suite else "iso")
(staging / "boot" / "limine").mkdir(parents=True, exist_ok=True)
(staging / "EFI" / "BOOT").mkdir(parents=True, exist_ok=True)
for filename in ["axiom64.elf", "rootfs.cpio"]:
    desktop_profile = args.suite not in ["full", "threads"] or (args.suite == "threads" and args.phase in ["cond", "io"])
    source = ROOT / "build" / ("rootfs-desktop.cpio" if filename == "rootfs.cpio" and args.test and desktop_profile else filename)
    if filename == 'rootfs.cpio' and args.test and args.suite == 'network':
        source = ROOT / 'build/rootfs-network.cpio'
    if filename == "rootfs.cpio" and args.root_device:
        source = ROOT / "build/rootfs-bootstrap.cpio"
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
    if disk_suite or args.suite in ["threads", "network"]:
        options += " phase=" + args.phase
if args.root_device:
    options += " root=" + args.root_device + " rootfstype=ext2 rootflags=" + ("ro" if args.root_readonly else "rw")
for token in args.kernel_option:
    options += " " + token
config = config.replace("cmdline: init=/sbin/init", "cmdline: init=/sbin/init" + options)
(staging / "boot" / "limine" / "limine.conf").write_text(config)
destination = ROOT / "build" / (args.output_name if args.output_name else
                                  args.suite + "-" + args.phase + ".iso" if disk_suite else
                                  "axiom64-test.iso" if args.test else "axiom64.iso")
command = ["xorriso", "-as", "mkisofs", "-quiet", "-R", "-J", "-b", "boot/limine/limine-bios-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", "boot/limine/limine-uefi-cd.bin", "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", str(staging), "-o", str(destination)]
subprocess.run(command, check=True)
subprocess.run([str(limine / "limine"), "bios-install", str(destination)], check=True)
print(f"Boot image: {destination}")
