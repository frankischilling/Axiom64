#!/usr/bin/env python3
"""Create a deterministic newc initramfs without privileged filesystem tools."""
import os
from pathlib import Path
import struct
import subprocess
from fetch import ROOT, LOCK

files = {}


def directory(path):
    files[path] = (0o40755, b"")


def regular(path, source, mode=0o100755):
    files[path] = (mode, Path(source).read_bytes())


for path in ["bin", "sbin", "lib", "etc", "dev", "proc", "tmp", "run", "root", "usr", "usr/bin", "usr/share", "usr/share/licenses", "usr/share/licenses/Axiom64", "usr/share/licenses/BusyBox", "usr/share/licenses/musl"]:
    directory(path)
busybox_dir = ROOT / "build" / f"busybox-{LOCK['busybox']['version']}"
busybox = busybox_dir / "busybox"
regular("bin/busybox", busybox)
for applet in subprocess.check_output([str(busybox), "--list"], text=True).splitlines():
    if applet != "busybox":
        files[f"bin/{applet}"] = (0o120777, b"/bin/busybox")
files["bin/sh"] = (0o120777, b"/bin/busybox")
regular("bin/abi-static", ROOT / "build" / "abi-static")
regular("bin/abi-dynamic", ROOT / "build" / "abi-dynamic")
regular("sbin/init", ROOT / "build" / "init")
regular("etc/boot-test.sh", ROOT / "userspace" / "boot-test.sh")
regular("lib/ld-musl-x86_64.so.1", Path("/lib/ld-musl-x86_64.so.1").resolve())
files["lib/libc.so"] = (0o120777, b"/lib/ld-musl-x86_64.so.1")
regular("usr/share/licenses/Axiom64/LICENSE", ROOT / "LICENSE", 0o100644)
regular("usr/share/licenses/BusyBox/LICENSE", busybox_dir / "LICENSE", 0o100644)
regular("usr/share/licenses/musl/copyright", "/usr/share/doc/musl/copyright", 0o100644)


def entry(stream, path, mode, data, inode):
    name = path.encode() + b"\0"
    values = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in values)
    stream.write(header + name)
    stream.write(b"\0" * (-stream.tell() % 4))
    stream.write(data)
    stream.write(b"\0" * (-stream.tell() % 4))


destination = ROOT / "build" / "rootfs.cpio"
with destination.open("wb") as stream:
    for inode, (path, (mode, data)) in enumerate(sorted(files.items()), start=1):
        entry(stream, path, mode, data, inode)
    entry(stream, "TRAILER!!!", 0, b"", len(files) + 1)
print(f"Initramfs: {len(files)} entries, {destination.stat().st_size} bytes")
