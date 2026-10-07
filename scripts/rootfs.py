#!/usr/bin/env python3
"""Create a deterministic newc initramfs without privileged filesystem tools."""
from pathlib import Path
import subprocess
from fetch import ROOT, LOCK
from ports import packages
import tarfile
import argparse
import tempfile
import json

parser = argparse.ArgumentParser()
parser.add_argument("--profile", choices=["full", "desktop"], default="full")
args = parser.parse_args()
expected_musl = json.loads((ROOT / "sources.lock.json").read_text())["build_musl"]["version"]
build_musl = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", "musl-dev"], text=True)
if build_musl != expected_musl:
    raise RuntimeError(f"build musl must be {expected_musl}; found {build_musl}")

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
regular("bin/ipc-tests", ROOT / "build" / "ipc-tests")
regular("bin/signal-tests", ROOT / "build" / "signal-tests")
regular("sbin/init", ROOT / "build" / "init")
regular("etc/boot-test.sh", ROOT / "userspace" / "boot-test.sh")
regular("etc/desktop-test.sh", ROOT / "userspace" / "desktop-test.sh")
regular("etc/x11-session.sh", ROOT / "userspace" / "x11-session.sh")
regular("usr/bin/startx", ROOT / "userspace" / "startx.sh")
regular("lib/ld-musl-x86_64.so.1", Path("/lib/ld-musl-x86_64.so.1").resolve())
files["lib/libc.so"] = (0o120777, b"/lib/ld-musl-x86_64.so.1")
regular("usr/share/licenses/Axiom64/LICENSE", ROOT / "LICENSE", 0o100644)
regular("usr/share/licenses/BusyBox/LICENSE", busybox_dir / "LICENSE", 0o100644)
regular("usr/share/licenses/musl/copyright", "/usr/share/doc/musl/copyright", 0o100644)
for notice in sorted((ROOT / "build" / "licenses").rglob("*")):
    if notice.name.startswith("."):
        continue
    path = "usr/share/licenses/ports/" + notice.relative_to(ROOT / "build" / "licenses").as_posix()
    for parent in reversed(Path(path).parents):
        if str(parent) != ".":
            files.setdefault(str(parent), (0o40755, b""))
    if notice.is_file():
        regular(path, notice, 0o100644)
    else:
        directory(path)

# Packages are data inputs. Their install hooks never run on the host or guest.
for package, archive in packages():
    # This image uses fbdev with GLX disabled; no Mesa or LLVM payload is needed.
    if package["name"] in {"mesa", "llvm20-libs", "spirv-tools"}:
        continue
    if args.profile == "desktop" and package["name"] in {
        "gcc", "g++", "binutils", "musl-dev", "linux-headers", "libstdc++-dev",
        "make", "isl25", "mpfr4", "gmp", "libgomp"
    }:
        continue
    with tarfile.open(archive, "r:gz", ignore_zeros=True) as stream:
        for member in stream:
            path = member.name.rstrip("/")
            if not path or path.startswith("."):
                continue
            if path.startswith("/") or ".." in Path(path).parts:
                raise RuntimeError(f"unsafe package path: {path}")
            for parent in reversed(Path(path).parents):
                if str(parent) != ".":
                    files.setdefault(str(parent), (0o40755, b""))
            if member.isdir():
                files[path] = (0o40000 | member.mode, b"")
            elif member.issym():
                files[path] = (0o120000 | member.mode, member.linkname.encode())
            elif member.isfile():
                files[path] = (0o100000 | member.mode, stream.extractfile(member).read())
            elif member.islnk():
                target = member.linkname.rstrip("/")
                if target not in files:
                    raise RuntimeError(f"unresolved package hard link: {path} -> {target}")
                files[path] = files[target]

# Keep the shell built from our pinned upstream source after importing packages.
regular("bin/busybox", busybox)
files["bin/sh"] = (0o120777, b"/bin/busybox")
for filename in ["xorg.conf", "system.twmrc"]:
    regular(f"etc/X11/{filename}", ROOT / "userspace" / filename, 0o100644)
regular("etc/xterm-session.sh", ROOT / "userspace" / "xterm-session.sh")
regular("bin/x11-probe", ROOT / "build" / "x11-probe")
for path in ["etc/X11", "tmp/.X11-unix", "var", "var/log", "var/lib", "var/lib/xkb", "usr/share/licenses/Xorg"]:
    directory(path)
files["tmp"] = (0o41777, b"")
files["tmp/.X11-unix"] = (0o41777, b"")

# APK font hooks are not executed. Generate the required index explicitly.
font_path = "usr/share/fonts/misc"
with tempfile.TemporaryDirectory(prefix="axiom64-fonts-") as temporary:
    font_stage = Path(temporary)
    for path, (mode, data) in files.items():
        if path.startswith(font_path + "/") and path.endswith(".pcf.gz"):
            (font_stage / Path(path).name).write_bytes(data)
    subprocess.run(["mkfontscale", "-b", "-s", "-l", str(font_stage)], check=True)
    regular(font_path + "/fonts.dir", font_stage / "fonts.dir", 0o100644)
directory("root/toolchain-test")
for filename in ["hello.c", "hello.cpp", "broken.c", "Makefile"]:
    regular(f"root/toolchain-test/{filename}", ROOT / "userspace" / "toolchain-test" / filename, 0o100644)


def entry(stream, path, mode, data, inode):
    name = path.encode() + b"\0"
    values = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in values)
    stream.write(header + name)
    stream.write(b"\0" * (-stream.tell() % 4))
    stream.write(data)
    stream.write(b"\0" * (-stream.tell() % 4))


destination = ROOT / "build" / ("rootfs-desktop.cpio" if args.profile == "desktop" else "rootfs.cpio")
with destination.open("wb") as stream:
    for inode, (path, (mode, data)) in enumerate(sorted(files.items()), start=1):
        entry(stream, path, mode, data, inode)
    entry(stream, "TRAILER!!!", 0, b"", len(files) + 1)
print(f"Initramfs: {len(files)} entries, {destination.stat().st_size} bytes")
