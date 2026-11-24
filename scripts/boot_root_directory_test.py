#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/boot_root_directory_test.py
# @brief   Verify disk installation selection in BIOS, UEFI and PXE guests.
# @author  frankischilling
# @date    2026-11-24
#
# Copyright (C) 2026 frankischilling

"""Boot an alternate installation and check the selected root boundary."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import tempfile

from boot_media import build_medium
from boot_media_test import digest, run_guest
from disk_root import bootstrap
from fetch import ROOT
from newc import write_cpio
from nvme_test import run as run_nvme


def installation(busybox, check):
    paths = ("bin", "sbin", "lib", "dev", "proc", "sys", "run", "tmp")
    files = dict.fromkeys(paths, (0o40755, b""))
    files["bin/busybox"] = 0o100755, busybox
    # The fixture runs a static interpreter and needs no dynamic libraries.
    files["lib/ld-musl-x86_64.so.1"] = 0o120777, b"/bin/busybox"
    files["sbin/init"] = 0o100755, f"""#!/bin/busybox sh
set -eu
test -c /dev/console
{check}
exec /bin/busybox poweroff -f
""".encode()
    return files


def fixture(busybox):
    files = installation(busybox, "test -f /base-marker\necho BASE_INSTALLATION_PASS")
    files["base-marker"] = 0o100644, b"outside\n"
    files["outer-init"] = files["sbin/init"]
    files["alias"] = 0o120777, b"/trial"
    files["writable"] = 0o40775, b""
    files["launch-outside"] = 0o40755, b""
    files["launch-outside/sbin"] = 0o40755, b""
    files["launch-outside/sbin/init"] = 0o120777, b"/../outer-init"
    files["trial"] = 0o40755, b""
    files["trial/local-marker"] = 0o100644, b"inside\n"
    files["trial/local-alias"] = 0o120777, b"/local-marker"
    files["trial/outer-alias"] = 0o120777, b"../base-marker"
    trial = installation(busybox, """test -f /local-alias
test ! -e /base-marker
test ! -e /../base-marker
test ! -e /outer-alias
test ! -e /trial
test -f /proc/1/root/local-marker
echo ready >/run/ready
if /bin/busybox grep -q ' / ext2 ro ' /proc/mounts; then
    if /bin/busybox touch /test-write; then exit 9; fi
    echo READONLY_INSTALLATION_PASS
else
    /bin/busybox grep -q ' / ext2 rw ' /proc/mounts
    echo ready >/test-write
    test -f /test-write
    echo ALTERNATE_INSTALLATION_PASS
fi""")
    files.update({f"trial/{name}": value for name, value in trial.items()})
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/root-directory-test")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    kernel = ROOT / "build/axiom64.elf"
    busybox = ROOT / "build/busybox-1.37.0/busybox"
    with tempfile.TemporaryDirectory(prefix="axiom64-root-directory-") as temporary:
        work = Path(temporary)
        archive = work / "root.cpio"
        write_cpio(archive, fixture(busybox.read_bytes()))
        initial = work / "bootstrap.cpio"
        bootstrap(initial)
        cases = [
            ("base", "", "BASE_INSTALLATION_PASS", None),
            ("trial", " rootdir=trial", "ALTERNATE_INSTALLATION_PASS", None),
            ("readonly", " rootdir=trial rootflags=ro", "READONLY_INSTALLATION_PASS", None),
            ("escape", " rootdir=../trial", "rootdir errno=22", None),
            ("alias", " rootdir=alias", "rootdir errno=20", None),
            ("writable", " rootdir=writable", "rootdir errno=13", None),
            ("missing", " rootdir=absent", "rootdir errno=2", None),
            ("outside-init", " rootdir=launch-outside", "/sbin/init errno=2", None),
            ("duplicate", " rootdir=trial rootdir=trial", "configuration errno=22", None),
            ("ramfs", " rootdir=trial", "configuration errno=22", archive),
        ]

        def verify(case):
            firmware, (name, options, marker, ramfs) = case
            path = output / f"{firmware}-{name}"
            path.mkdir()
            disk = work / f"{path.name}.raw"
            build_medium("disk", disk, kernel, archive, options, installed=ramfs is None)
            invalid = not marker.endswith("_PASS")
            if invalid:
                marker = "BOOT_ROOT_FAIL stage=" + marker
            return run_guest(path, "disk", firmware, disk, marker,
                             (ramfs or initial).stat().st_size, invalid=invalid)

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(verify, ((fw, case) for fw in ("bios", "uefi")
                                                 for case in cases)))
        disk = work / "nvme.raw"
        build_medium("disk", disk, kernel, archive, installed=True)
        layout = json.loads(subprocess.check_output(["sfdisk", "--json", disk]))
        root, = [part for part in layout["partitiontable"]["partitions"]
                 if part.get("name") == "AXIOM64_ROOT"]
        pxe = work / "pxe"
        build_medium("pxe", pxe, kernel, None, " rootdir=trial",
                     root_partuuid=root["uuid"])
        pxe_result = run_nvme(output / "uefi-pxe-nvme", "q35", "uefi", None,
                              [(0, 1, disk, 512)], ["VFS_ROOT_DIRECTORY name=trial",
                                                    "ALTERNATE_INSTALLATION_PASS"], pxe=pxe)
        (output / "results.json").write_text(json.dumps({
            "kernel_sha256": digest(kernel),
            "archive_sha256": digest(archive),
            "boots": results,
            "pxe": pxe_result,
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()
