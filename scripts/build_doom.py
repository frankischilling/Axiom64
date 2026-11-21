#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/build_doom.py
# @brief   Build the Chocolate Doom guest port.
# @author  frankischilling
# @date    2026-11-21
#
# Checks pinned code, SDL2 packages, and signed Freedoom release data.
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

"""Build Chocolate Doom for the guest and stage upstream Freedoom data."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from build_musl import compiler_args, ensure as musl
from fetch import LOCK, ROOT
from ports import download, locked_package

PATCH_DIRECTORY = ROOT / "vendor/chocolate-doom"
PORTS = ("sdl2", "sdl2_mixer", "sdl2_net")
PACKAGE_NAMES = frozenset((*PORTS, *(name + "-dev" for name in PORTS)))
WADS = ("freedoom1.wad", "freedoom2.wad")
NOTICES = ("COPYING.txt", "CREDITS.txt", "CREDITS-MUSIC.txt")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def pinned(info):
    return download(info["url"], ROOT / "downloads" / info["archive"],
                    expected_sha256=info["sha256"])


def source_inputs():
    doom = LOCK["chocolate_doom"]
    freedoom = LOCK["freedoom"]
    patches = []
    for name, sha256 in doom["patches"].items():
        if Path(name).name != name:
            raise RuntimeError("Invalid Chocolate Doom patch filename")
        patch = PATCH_DIRECTORY / name
        if digest(patch) != sha256:
            raise RuntimeError(f"Chocolate Doom patch checksum differs: {name}")
        patches.append(patch)
    binary = pinned(freedoom)
    checksum = pinned(freedoom["checksum"])
    key = pinned(freedoom["release_key"])
    with tempfile.TemporaryDirectory(prefix="axiom64-freedoom-signature-") as directory:
        keyring = Path(directory) / "release.gpg"
        subprocess.run(["gpg", "--no-options", "--batch", "--homedir", directory, "--dearmor",
                        "--output", keyring, key], check=True, capture_output=True)
        result = subprocess.run(["gpgv", "--homedir", directory, "--keyring", keyring,
                                 "--status-fd", "1", checksum], check=True, capture_output=True)
    signatures = [line.split() for line in result.stdout.decode().splitlines()
                  if line.startswith("[GNUPG:] VALIDSIG ")]
    if (len(signatures) != 1 or signatures[0][-1] != freedoom["release_fingerprint"] or
            f"SHA256 ({binary.name}) = {freedoom['sha256']}" not in checksum.read_text().splitlines()):
        raise RuntimeError("The signed Freedoom manifest does not name the pinned release")
    return [("chocolate-doom", [pinned(doom), *patches]),
            ("freedoom", [pinned(freedoom["source"]), binary, checksum, key])]


def input_packages():
    packages = json.loads((ROOT / "ports.lock.json").read_text())["packages"]
    selected = {entry["name"]: entry for entry in packages if entry["name"] in PACKAGE_NAMES}
    if set(selected) != PACKAGE_NAMES:
        raise RuntimeError("Chocolate Doom SDL2 input closure is incomplete")
    for name in sorted(selected):
        package = selected[name]
        if package.get("build_only", False) != name.endswith("-dev"):
            raise RuntimeError(f"{name}: incorrect build-only package policy")
        yield package, locked_package(package)


def build():
    (doom_source, *patches), (_, data, _, _) = (paths for _, paths in source_inputs())
    inputs = list(input_packages())
    compiler = compiler_args("build")
    executable = shutil.which(os.environ.get("CMAKE", "cmake"))
    if not executable:
        raise RuntimeError("CMake is required to build the Chocolate Doom port")
    identity = dict(locks=[LOCK["chocolate_doom"], LOCK["freedoom"]],
                    recipe=digest(Path(__file__)), packages=[entry for entry, _ in inputs],
                    compiler_specs=digest(Path(compiler[1].removeprefix("-specs="))),
                    compiler_version=subprocess.check_output([compiler[0], "-dumpfullversion"],
                                                             text=True).strip(),
                    cmake=subprocess.check_output([executable, "--version"],
                                                  text=True).splitlines()[0])
    parent = ROOT / "build/chocolate-doom"
    parent.mkdir(parents=True, exist_ok=True)
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    destination = parent / fingerprint
    with (parent / ".lock").open("a") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if destination.exists():
            verify_build(destination, identity)
            return destination
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            work = Path(temporary)
            sysroot = work / "target"
            sysroot.mkdir()
            for _, archive in inputs:
                with tarfile.open(archive, "r:gz", ignore_zeros=True) as stream:
                    stream.extractall(sysroot, filter="data")
            library_path = sysroot / "usr/lib"
            (library_path / "libc.musl-x86_64.so.1").symlink_to(
                musl("build") / "sysroot/usr/lib/libc.so")
            with tarfile.open(doom_source) as archive:
                archive.extractall(work, filter="data")
            source = work / ("chocolate-doom-" + LOCK["chocolate_doom"]["revision"])
            for patch in patches:
                subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", patch],
                               cwd=source, check=True)
            environment = os.environ.copy()
            for key in ("CFLAGS", "CPPFLAGS", "LDFLAGS", "CMAKE_PREFIX_PATH", "CPATH",
                        "C_INCLUDE_PATH", "LIBRARY_PATH", "PKG_CONFIG_PATH"):
                environment.pop(key, None)
            environment["CC"] = shlex.join(compiler)
            environment["CFLAGS"] = shlex.quote(f"-ffile-prefix-map={source}=/usr/src/chocolate-doom")
            environment["PKG_CONFIG_LIBDIR"] = str(sysroot / "usr/lib/pkgconfig")
            environment["PKG_CONFIG_SYSROOT_DIR"] = str(sysroot)
            configured = work / "compile"
            subprocess.run([executable, "-S", source, "-B", configured, "-DCMAKE_BUILD_TYPE=Release",
                            "-DCMAKE_SYSTEM_NAME=Linux", "-DCMAKE_SYSTEM_PROCESSOR=x86_64",
                            "-DCMAKE_FIND_ROOT_PATH=" + str(sysroot),
                            "-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY",
                            "-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY",
                            "-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY",
                            "-DCMAKE_PREFIX_PATH=" + str(sysroot / "usr"),
                            "-DCMAKE_EXE_LINKER_FLAGS=-Wl,-rpath-link," + str(library_path),
                            "-DCMAKE_INSTALL_PREFIX=/usr", "-DCMAKE_SKIP_RPATH=ON"],
                           env=environment, check=True)
            subprocess.run([executable, "--build", configured, "--target", "chocolate-doom",
                            "--parallel", str(min(12, os.cpu_count() or 1))],
                           env=environment, check=True)
            product = work / "products"
            product.mkdir()
            engine = product / "chocolate-doom"
            shutil.copy2(configured / "src/chocolate-doom", engine)
            verify_engine(engine)
            if os.fsencode(work) in engine.read_bytes():
                raise RuntimeError("Chocolate Doom retains its temporary build path")
            shutil.copyfile(source / "COPYING.md", product / "COPYING.md")
            prefix = "freedoom-" + LOCK["freedoom"]["version"] + "/"
            with zipfile.ZipFile(data) as archive:
                for name in (*WADS, *NOTICES):
                    (product / name).write_bytes(archive.read(prefix + name))
            receipt = dict(inputs=identity, products={p.name: digest(p) for p in product.iterdir()})
            (product / "manifest.json").write_text(json.dumps(receipt, indent=2) + "\n")
            product.rename(destination)
    return destination


def verify_engine(engine):
    report = subprocess.check_output(["readelf", "-l", "-d", engine], text=True)
    dependencies = set(re.findall(r"\(NEEDED\).*Shared library: \[([^]]+)\]", report))
    expected = {"libSDL2-2.0.so.0", "libSDL2_mixer-2.0.so.0", "libSDL2_net-2.0.so.0", "libc.so"}
    if (dependencies != expected or "Requesting program interpreter: /lib/ld-musl-x86_64.so.1" not in report
            or any(tag in report for tag in ("(RPATH)", "(RUNPATH)"))):
        raise RuntimeError(f"Chocolate Doom interpreter or dependencies differ: {dependencies}")


def verify_build(destination, identity):
    receipt = json.loads((destination / "manifest.json").read_text())
    expected = {"chocolate-doom", "COPYING.md", *WADS, *NOTICES}
    if (receipt["inputs"] != identity or set(receipt["products"]) != expected or
            any(digest(destination / name) != receipt["products"][name] for name in expected)):
        raise RuntimeError("Cached Chocolate Doom build differs from its receipt")
    verify_engine(destination / "chocolate-doom")


def runtime_files():
    product = build()
    files = {"usr/bin/chocolate-doom": (0o100755, (product / "chocolate-doom").read_bytes())}
    for name in WADS:
        files["usr/share/games/doom/" + name] = (0o100644, (product / name).read_bytes())
    license_path = "usr/share/licenses/"
    files[license_path + "chocolate-doom/COPYING.md"] = (0o100644,
                                                       (product / "COPYING.md").read_bytes())
    for name in NOTICES:
        files[license_path + "freedoom/" + name] = (0o100644, (product / name).read_bytes())
    files[license_path + "chocolate-doom/manifest.json"] = (0o100644,
                                                          (product / "manifest.json").read_bytes())
    return files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help="build and verify the guest engine")
    options = parser.parse_args()
    if options.build:
        print(build())
    else:
        for origin, paths in source_inputs():
            print(origin, ": ", ", ".join(path.name for path in paths), sep="")
