#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/rootfs.py
# @brief   Build the boot image's root filesystem.
# @author  frankischilling
# @date    2026-11-21
#
# Assembles the pinned ports and first-party guest programs into a newc archive.
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

"""Create a deterministic newc initramfs without privileged filesystem tools."""
from pathlib import Path
import subprocess
from fetch import ROOT, LOCK
from newc import write_cpio
from ports import overlay_tar, packages
from build_musl import loader, runtime_files
from build_libcap import runtime_files as capability_files
from build_openssl import runtime_files as crypto_files
from build_curl import runtime_files as download_files
from ca_bundle import runtime_files as trust_files
from build_libxcrypt import runtime_files as password_files
from build_accounts import runtime_files as account_files
from build_doom import runtime_files as doom_files
from build_cupidfetch import runtime_files as cupidfetch_files
import tarfile
import argparse
import tempfile
import json

parser = argparse.ArgumentParser()
root_archives = {
    "full": "rootfs.cpio",
    "desktop": "rootfs-desktop.cpio",
    "installed-desktop": "rootfs-installed-desktop.cpio",
}
parser.add_argument("--profile", choices=root_archives, default="full")
args = parser.parse_args()
installed_desktop = args.profile == "installed-desktop"
expected_musl = json.loads((ROOT / "sources.lock.json").read_text())["build_musl"]["version"]
build_musl = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", "musl-dev"], text=True)
if build_musl != expected_musl:
    raise RuntimeError(f"build musl must be {expected_musl}; found {build_musl}")

files = {}


def directory(path):
    files[path] = (0o40755, b"")


def regular(path, source, mode=0o100755):
    files[path] = (mode, Path(source).read_bytes())


def compile_desktop_data():
    schema_dir = Path("usr/share/glib-2.0/schemas")
    mime_dir = Path("usr/share/mime")
    with tempfile.TemporaryDirectory(prefix="axiom64-desktop-data-") as temporary:
        stage = Path(temporary)
        for name, (mode, payload) in files.items():
            path = Path(name)
            if mode & 0o170000 == 0o100000 and path.parent in (schema_dir, mime_dir / "packages"):
                target = stage / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
        subprocess.run(["glib-compile-schemas", "--strict", stage / schema_dir], check=True)
        subprocess.run(["update-mime-database", stage / mime_dir], check=True)
        for target in sorted(stage.rglob("*")):
            name = target.relative_to(stage).as_posix()
            if name not in files:
                if target.is_dir():
                    directory(name)
                elif target.is_file():
                    regular(name, target, 0o100644)


for path in ["bin", "sbin", "lib", "etc", "dev", "proc", "sys", "tmp", "run", "root", "usr", "usr/bin", "usr/share", "usr/share/licenses", "usr/share/licenses/Axiom64", "usr/share/licenses/BusyBox", "usr/share/licenses/musl"]:
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
regular("bin/storage-tests", ROOT / "build" / "storage-tests")
regular("bin/vfs-tests", ROOT / "build" / "vfs-tests")
regular("bin/ext2-tests", ROOT / "build" / "ext2-tests")
regular("bin/root-tests", ROOT / "build" / "root-tests")
regular("bin/net-tests", ROOT / "build" / "net-tests")
regular("bin/ipv4-tests", ROOT / "build" / "ipv4-tests")
regular("bin/udp-tests", ROOT / "build" / "udp-tests")
regular("bin/thread-static", ROOT / "build" / "thread-static")
regular("bin/thread-dynamic", ROOT / "build" / "thread-dynamic")
regular("bin/thread-io-static", ROOT / "build" / "thread-io-static")
regular("bin/thread-io-dynamic", ROOT / "build" / "thread-io-dynamic")
regular("bin/futex-static", ROOT / "build" / "futex-static")
regular("bin/futex-dynamic", ROOT / "build" / "futex-dynamic")
regular("bin/lifecycle-static", ROOT / "build" / "lifecycle-static")
regular("bin/lifecycle-dynamic", ROOT / "build" / "lifecycle-dynamic")
regular("sbin/init", ROOT / "build" / "init")
regular("sbin/network-manager", ROOT / "build" / "network-manager")
regular("sbin/random-seed", ROOT / "build" / "random-seed-static")
regular("etc/boot-test.sh", ROOT / "userspace/tests/boot.sh")
regular("etc/desktop-test.sh", ROOT / "userspace/tests/desktop/run.sh")
regular("etc/storage-test.sh", ROOT / "userspace/tests/storage/block.sh")
regular("etc/ext2-test.sh", ROOT / "userspace/tests/fs/ext2.sh")
regular("etc/root-test.sh", ROOT / "userspace/tests/fs/root.sh")
regular("etc/net-test.sh", ROOT / "userspace/tests/net/run.sh")
regular("etc/ipv4-test.sh", ROOT / "userspace/tests/net/ipv4.sh")
regular("etc/udp-test.sh", ROOT / "userspace/tests/net/udp.sh")
regular("etc/thread-test.sh", ROOT / "userspace/tests/threads/run.sh")
regular("etc/x11-session.sh", ROOT / "userspace/desktop/x11-session.sh")
regular("usr/bin/startx", ROOT / "userspace/desktop/startx.sh")
regular("lib/ld-musl-x86_64.so.1", loader())
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
# Select Weston's CPU-rendered X11 backend and desktop shell. The Alpine
# packages also contain modules for transports and renderers that need separate
# kernel interfaces and dependencies.
package_payloads = {
    "weston": (
        "usr/bin/weston", "usr/lib/weston/libexec_weston.so.0*",
        "usr/libexec/weston-desktop-shell", "usr/libexec/weston-keyboard",
        "usr/libexec/weston-simple-im", "usr/share/weston/*",
    ),
    "libweston": ("usr/lib/libweston-14.so.0*",),
    "weston-backend-x11": ("usr/lib/libweston-14/x11-backend.so",),
    "weston-shell-desktop": ("usr/lib/weston/desktop-shell.so",),
    "weston-clients": ("usr/bin/weston-simple-shm",),
    "openssh-server-common": (),  # The installed server requires a local configuration.
}
installed_libraries = {'gmp', 'libgomp'} if installed_desktop else set()
for package, archive in packages(include_installed=installed_desktop):
    if package.get("build_only", False):
        continue
    if args.profile != "full" and package["name"] not in installed_libraries and package["name"] in {
        "gcc", "g++", "binutils", "bison", "flex", "m4", "musl-dev", "linux-headers", "libstdc++-dev",
        "make", "nasm", "isl25", "mpfr4", "gmp", "libgomp", "acl-libs", "libburn", "libedit",
        "libisoburn", "libisofs", "xorriso"
    }:
        continue
    with tarfile.open(archive, "r:gz", ignore_zeros=True) as stream:
        overlay_tar(files, stream, include=package_payloads.get(package["name"]))

# Override both the installed interpreter and native development libc after APK imports.
for path, value in {**runtime_files(), **capability_files(), **crypto_files(), **download_files(),
                    **trust_files(), **password_files(), **account_files(), **doom_files(),
                    **cupidfetch_files()}.items():
    for parent in reversed(Path(path).parents):
        if str(parent) != '.':
            files.setdefault(str(parent), (0o40755, b''))
    files[path] = value

# Saved profiles use the manager's private directory policy.
files["etc/network"] = (0o40700, b"")
# Keep the shell built from our pinned upstream source after importing packages.
regular("bin/busybox", busybox)
files["bin/sh"] = (0o120777, b"/bin/busybox")
for filename in ["xorg.conf", "system.twmrc"]:
    regular(f"etc/X11/{filename}", ROOT / "userspace/desktop" / filename, 0o100644)
# Package shell-registration hooks are not run. Supply the conventional list
# explicitly so clients using getusershell retain the authenticated shell.
shells = [path for path in ('/bin/sh', '/bin/ash', '/bin/bash', '/bin/zsh',
                           '/bin/ksh', '/bin/mksh', '/bin/dash', '/bin/csh', '/bin/tcsh')
          if path.lstrip('/') in files]
files['etc/shells'] = (0o100644, ('\n'.join(shells) + '\n').encode())
regular("etc/xterm-session.sh", ROOT / "userspace/desktop/xterm-session.sh")
regular("usr/bin/freedoom", ROOT / "userspace/desktop/freedoom.sh")
regular("usr/bin/weston-nested", ROOT / "userspace/desktop/weston-nested.sh")
for path in ("usr/share/applications", "etc/skel", "etc/skel/Desktop"):
    files.setdefault(path, (0o40755, b""))
for entry in sorted((ROOT / "userspace/desktop/launchers").glob("*.desktop")):
    regular("usr/share/applications/" + entry.name, entry, 0o100644)
    regular("etc/skel/Desktop/" + entry.name, entry, 0o100755)
if installed_desktop:
    for name in ("btop.desktop", "kitty.desktop", "thunar.desktop"):
        files[f"etc/skel/Desktop/{name}"] = (0o100755, files[f"usr/share/applications/{name}"][1])
    files.setdefault("etc/xdg", (0o40755, b""))
    files["etc/xdg/mimeapps.list"] = (
        0o100644, b"[Default Applications]\ninode/directory=thunar.desktop;\n"
    )
    compile_desktop_data()
    directory("etc/ssh")
    directory("var/empty")
    regular("etc/ssh/sshd_config.example", ROOT / "userspace/services/sshd_config", 0o100644)
regular('usr/libexec/desktop-terminal', ROOT / 'build/desktop-terminal')
regular('usr/libexec/axiom64-session-bus', ROOT / 'build/desktop-session-bus')
regular('usr/libexec/axiom64-system-bus', ROOT / 'userspace/services/system-bus.sh')
files['var/lib/dbus/machine-id'] = (0o120777, b'/etc/machine-id')
for filename in ('desktop-client-session.sh', 'desktop-console-session.sh'):
    regular('etc/' + filename, ROOT / 'userspace/desktop' / filename)
if installed_desktop:
    regular('usr/libexec/axiom64-plasma-session', ROOT / 'userspace/desktop/plasma-session.sh')
    regular('usr/libexec/axiom64-plasma-shell', ROOT / 'userspace/desktop/plasma-shell.sh')
    files.setdefault('etc/pam.d', (0o40755, b''))
    regular('etc/pam.d/kde', ROOT / 'userspace/desktop/kde.pam', 0o100644)
    autostart = 'etc/xdg/autostart/org.kde.plasmashell.desktop'
    mode, desktop = files[autostart]
    command = b'\nExec=/usr/bin/plasmashell\n'
    if desktop.count(command) != 1:
        raise ValueError(f'{autostart} does not have the expected Plasma shell command')
    files[autostart] = mode, desktop.replace(command, b'\nExec=/usr/libexec/axiom64-plasma-shell\n')
regular("bin/x11-probe", ROOT / "build" / "x11-probe")
for path in ["etc/X11", "tmp/.X11-unix", "var", "var/log", "var/lib", "var/lib/xkb", "usr/share/licenses/Xorg"]:
    directory(path)
for path in ('home', 'etc/axiom64', 'etc/axiom64/accounts', 'var/log/axiom64', 'var/log/axiom64/login'):
    directory(path)
directory("var/lib/axiom64")
files["var/lib/axiom64/random"] = (0o40700, b"")
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
for filename in ["hello.c", "hello.cpp", "broken.c", "threads.cpp", "library.cpp", "shared.cpp",
                 "arithmetic.asm", "Makefile"]:
    regular(f"root/toolchain-test/{filename}", ROOT / "userspace/tests/toolchain" / filename, 0o100644)


destination = ROOT / "build" / root_archives[args.profile]
write_cpio(destination, files)
print(f"Initramfs: {len(files)} entries, {destination.stat().st_size} bytes")
