#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/vm_journal_test.py
# @brief   Verify journaled production VM roots across power loss.
# @author  frankischilling
# @date    2026-11-20
#
# Drives the normal serial login and checks the retained guest disk independently.
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

"""Test a normal root first boot, abrupt VM stop, and authenticated recovery."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import time

from build_accounts import digest
from console_prompt import shell_prompt_end
from fetch import ROOT

PASSWORD = b"Fixture-vm-root-journal-only-2026"
PAYLOAD = b"durable journaled root file\n"


def journal_state(path):
    with path.open("rb") as source:
        source.seek(1024)
        header = source.read(1024)
    if struct.unpack_from("<H", header, 56)[0] != 0xef53:
        raise RuntimeError(f"{path}: missing ext filesystem superblock")
    compatible, incompatible = struct.unpack_from("<II", header, 92)
    return {"journal": bool(compatible & 4), "needs_recovery": bool(incompatible & 4)}


def verify_retained_state(launcher, disk):
    before = digest(disk), digest(disk.parent / "created.json")
    result = subprocess.run([*launcher, "--prepare-only"], cwd=ROOT,
                            check=True, capture_output=True, text=True)
    if json.loads(result.stdout) != {"disk": str(disk), "created": False}:
        raise RuntimeError(f"{disk}: launcher did not reuse its root")
    if before != (digest(disk), digest(disk.parent / "created.json")):
        raise RuntimeError(f"{disk}: reopening the state wrote to it")


def boot(launcher, logfile, firmware, cut):
    with logfile.open("wb") as log, subprocess.Popen(
            launcher, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True) as process:
        text = bytearray()
        cursor = 0
        deadline = time.monotonic() + 180

        def send(line):
            process.stdin.write(line + b"\n")
            process.stdin.flush()

        def until(marker):
            nonlocal cursor
            while time.monotonic() < deadline:
                if marker == b"$ ":
                    end = shell_prompt_end(text, cursor)
                else:
                    at = text.find(marker, cursor)
                    end = at + len(marker) if at >= 0 else None
                if end is not None:
                    cursor = end
                    return
                readable, _, _ = select.select([process.stdout], [], [], 1)
                if readable:
                    more = os.read(process.stdout.fileno(), 65536)
                    if not more:
                        break
                    text.extend(more)
                    log.write(more)
                    log.flush()
                    if PASSWORD in text:
                        raise RuntimeError("guest exposed the disposable test password")
            raise RuntimeError(f"{logfile}: guest failed to reach {marker!r}")

        try:
            if cut:
                until(b"Administrator name: ")
                send(b"admin")
                until(b"New password: ")
                send(PASSWORD)
                until(b"Confirm password: ")
                send(PASSWORD)
                until(b"Administrator created. Please log in.")
            until(b"login: ")
            send(b"admin")
            until(b"Password: ")
            send(PASSWORD)
            until(b"$ ")
            if cut:
                send(b"printf '%s\\n' 'durable journaled root file' > \"$HOME/journal-proof\""
                     b" && sync && printf '%s%s\\n' VM_JOURNAL_ CUT_READY")
                until(b"VM_JOURNAL_CUT_READY")
                os.killpg(process.pid, signal.SIGKILL)
                if process.wait(timeout=15) != -signal.SIGKILL:
                    raise RuntimeError("launcher unexpectedly survived the VM power cut")
                remaining, _ = process.communicate(timeout=15)
                text.extend(remaining)
                log.write(remaining)
            else:
                send(b"test \"$(cat \"$HOME/journal-proof\")\" = 'durable journaled root file'"
                     b" && printf '%s%s\\n' VM_JOURNAL_ FILE_RECOVERED")
                until(b"VM_JOURNAL_FILE_RECOVERED")
                until(b"$ ")
                send(b"sudo /bin/busybox poweroff -f")
                until(b"Password: ")
                send(PASSWORD)
                remaining, _ = process.communicate(timeout=30)
                text.extend(remaining)
                log.write(remaining)
                if process.returncode != 0:
                    raise RuntimeError(f"{logfile}: launcher did not power off cleanly")
            markers = (b"Firmware: " + firmware.upper().encode(),
                       b"VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0")
            if (any(marker not in text for marker in markers) or
                    text.count(b"Administrator created. Please log in.") != int(cut) or
                    any(marker in text for marker in (PASSWORD, b"PANIC:", b"FAULT pid=",
                                              b"FILESYSTEM_SHUTDOWN_FAIL", b"BOOT_ROOT_FAIL"))):
                raise RuntimeError(f"{logfile}: incorrect boot or shutdown evidence")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def check_legacy(directory):
    directory.mkdir()
    disk = directory / "root.ext2"
    with disk.open("wb") as output:
        output.truncate(8 * 1024 * 1024)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext2", disk], check=True)
    record = {"version": 1, "disk": disk.name, "disk_bytes": disk.stat().st_size,
              "initial_disk_sha256": digest(disk)}
    (directory / "created.json").write_text(json.dumps(record))
    launcher = [sys.executable, "-B", "scripts/vm.py", "--state-directory", str(directory), "--serial"]
    verify_retained_state(launcher, disk)
    if journal_state(disk) != {"journal": False, "needs_recovery": False}:
        raise RuntimeError("existing ext2 disk format changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "build/vm-journal")
    parser.add_argument("--firmware", choices=("bios", "uefi", "both"), default="both")
    parser.add_argument("--prepared", action="store_true", help="use the current prepared build inputs")
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to((ROOT / "build").resolve()):
        parser.error("--directory must be under build/")
    directory.mkdir(parents=True, exist_ok=False)
    if not args.prepared:
        subprocess.run(["make", "-j2", "build/axiom64.elf", "build/rootfs.cpio"],
                       cwd=ROOT, check=True)
    inputs = ["scripts/vm.py", "scripts/vm_journal_test.py", "build/axiom64.elf", "build/rootfs.cpio"]
    hashes = {name: digest(ROOT / name) for name in inputs}
    (directory / "inputs.json").write_text(json.dumps(hashes, indent=2) + "\n")
    check_legacy(directory / "legacy")
    rows = []
    for firmware in ("bios", "uefi") if args.firmware == "both" else (args.firmware,):
        state = directory / firmware
        disk = state / "root.ext2"
        launcher = [sys.executable, "-B", "scripts/vm.py", "--state-directory", str(state),
                    "--serial", "--firmware", firmware]
        boot(launcher, directory / f"{firmware}-cut.log", firmware, cut=True)
        dirty = journal_state(disk)
        if dirty != {"journal": True, "needs_recovery": True}:
            raise RuntimeError(f"{disk}: missing journal or crash recovery flag")
        metadata = json.loads((state / "created.json").read_text())
        if metadata.get("filesystem") != "ext3":
            raise RuntimeError(f"{disk}: launcher did not record the journaled format")
        verify_retained_state(launcher, disk)
        boot(launcher, directory / f"{firmware}-recover.log", firmware, cut=False)
        clean = journal_state(disk)
        if clean != {"journal": True, "needs_recovery": False}:
            raise RuntimeError(f"{disk}: clean boot failed to clear the recovery flag")
        inode = subprocess.run(["debugfs", "-R", "stat <8>", disk], check=True,
                               capture_output=True, text=True)
        match = re.search(r"\bSize:\s*(\d+)", inode.stdout)
        if not match or int(match[1]) != 32 * 1024 * 1024:
            raise RuntimeError(f"{disk}: unexpected journal size")
        with (directory / f"{firmware}-fsck.log").open("wb") as output:
            subprocess.run(["e2fsck", "-fn", disk], check=True, stdout=output, stderr=subprocess.STDOUT)
        file = subprocess.run(["debugfs", "-R", "cat /home/admin/journal-proof", disk],
                              check=True, capture_output=True)
        if file.stdout != PAYLOAD:
            raise RuntimeError(f"{disk}: recovered file bytes differ")
        rows.append({"firmware": firmware, "dirty": dirty, "clean": clean,
                     "journal_bytes": int(match[1]), "disk_sha256": digest(disk)})
        (directory / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"VM_JOURNAL_RECOVERY_PASS {firmware}", flush=True)
    if hashes != {name: digest(ROOT / name) for name in inputs}:
        raise RuntimeError("VM test inputs changed")


if __name__ == "__main__":
    main()
