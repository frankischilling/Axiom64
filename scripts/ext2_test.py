#!/usr/bin/env python3
"""Boot real ext2 volumes, verify persistence, and check them with host filesystem tools."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
from fetch import ROOT

CAPACITY = 16 * 1024 * 1024
SEED = b"host-created seed\n"
FORMATS = [(1024, 128, "default"), (2048, 256, "default"),
           (4096, 256, "default"), (1024, 128, "original")]


def debugfs(disk, command, write=False):
    result = subprocess.run(["debugfs", *(["-w"] if write else []), "-R", command, str(disk)],
                            check=True, capture_output=True, text=True)
    return result.stdout


def create_volume(disk, block_size=1024, inode_size=128, features="default", capacity=CAPACITY, inodes=None):
    with disk.open("wb") as output:
        output.truncate(capacity)
    command = ["mke2fs", "-q", "-F", "-t", "ext2", "-b", str(block_size), "-I", str(inode_size)]
    if features == "original":
        command += ["-r", "0", "-O", "none"]
    if inodes:
        command += ["-N", str(inodes)]
    subprocess.run(command + [str(disk)], check=True, capture_output=True)
    seed = disk.with_suffix(".seed")
    seed.write_bytes(SEED)
    debugfs(disk, f"write {seed} /seed.txt", write=True)


def check_fs(disk, label):
    result = subprocess.run(["e2fsck", "-f", "-n", str(disk)], capture_output=True, text=True)
    logfile = ROOT / "build" / f"{label}-fsck.log"
    logfile.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"e2fsck rejected {disk.name}:\n{result.stdout}{result.stderr}")
    return logfile.name


def dump(disk, filename, label):
    output = ROOT / "build" / f"{label}-{filename.lstrip('/').replace('/', '-')}.dump"
    output.unlink(missing_ok=True)
    debugfs(disk, f"dump {filename} {output}")
    return output.read_bytes()


def host_verify(disk, block_size, label):
    length = (12 + block_size // 4 + 3) * block_size + 713
    payload = bytes((i * 31 + 17) & 255 for i in range(length))
    expected = {"seed.txt": SEED, "cli.txt": b"command-line-mount\n", "final": b"linked-data", "pattern": bytes(37) + payload,
                "pruned": b"tiny", "old-time": b"dated", "trim": payload[:12 * block_size + 37] +
                bytes(length - (12 * block_size + 37)),
                "program-static": (ROOT / "build" / "abi-static").read_bytes(),
                "program-dynamic": (ROOT / "build" / "abi-dynamic").read_bytes()}
    for filename, data in expected.items():
        if dump(disk, "/" + filename, label) != data:
            raise RuntimeError(f"host file bytes differ: {filename}")
    stat = debugfs(disk, "stat /final")
    if "Mode:  0640" not in stat or "Links: 1" not in stat:
        raise RuntimeError("host inode mode/link count differs")
    n = block_size // 4
    logical = 12 + n + n * n
    triple = int(debugfs(disk, f"bmap /sparse {logical}").strip())
    with disk.open("rb") as source:
        source.seek(triple * block_size + 29)
        if source.read(8) != b"triples!":
            raise RuntimeError("host triple-indirect data differs")
    stat = debugfs(disk, "stat /sparse")
    if f"Size: {logical * block_size + 37}" not in stat or f"Blockcount: {4 * block_size // 512}" not in stat:
        raise RuntimeError("host sparse size/allocation count differs")
    return check_fs(disk, label)


def boot(firmware, transport, phase, disks, images, label, timeout, readonly=False, rules=None):
    logfile = ROOT / "build" / f"{label}.log"
    mode = "disable-legacy=on" if transport == "modern" else "disable-modern=on"
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "512M",
               "-cdrom", str(images[phase]), "-display", "none", "-serial", "stdio", "-monitor", "none",
               "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    for index, disk in enumerate(disks):
        backend = f"blkdebug:{rules[index]}:{disk}" if rules and rules[index] else str(disk)
        command += ["-drive", f"if=none,id=data{index},format=raw,cache=writeback,file={backend},readonly={'on' if readonly else 'off'}",
                    "-device", f"virtio-blk-pci,drive=data{index},{mode},rerror=report,werror=report,addr={5 + index:x}"]
    if firmware == "uefi":
        variables = ROOT / "build" / f"{label}-VARS.fd"
        shutil.copy2("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    marker = {"write": "EXT2_WRITE_PASS", "verify": "EXT2_REBOOT_PASS", "readonly": "EXT2_READONLY_PASS",
              "full": "EXT2_FULL_VOLUME_PASS", "error": "EXT2_BACKEND_ERROR_PASS"}.get(phase)
    markers = [f"Firmware: {firmware.upper()}", "AXIOM64_EXIT status=0", f"EXT2_PHASE_PASS phase={phase}"]
    if marker:
        markers.append(marker)
    if phase == "write":
        markers.append("EXT2_COMMANDS_PASS")
    if phase == "invalid":
        markers.append(f"EXT2_REJECT_PASS volumes={len(disks)}")
    for index, disk in enumerate(disks):
        markers.append(f"virtio-blk: disk={index} transport={transport} sectors={disk.stat().st_size // 512} readonly={int(readonly)} flush=1")
    started = time.monotonic()
    timed_out = False
    with logfile.open("w") as output:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=timeout)
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, None
    text = logfile.read_text(errors="replace")
    lines = {line.strip() for line in text.splitlines()}
    missing = [value for value in markers if value not in lines]
    failed = any(value in text for value in ["EXT2_FAIL", "PANIC:", "FAULT pid=", "initialization failed"])
    report = {"firmware": firmware, "transport": transport, "phase": phase, "label": label,
              "passed": not timed_out and not missing and not failed and returncode == 1,
              "returncode": returncode, "timed_out": timed_out, "missing": missing,
              "seconds": round(time.monotonic() - started, 2), "log": logfile.name}
    print(json.dumps(report), flush=True)
    if not report["passed"]:
        print("\n".join(text.splitlines()[-26:]), flush=True)
    return report


def inode_offset(data, number):
    block_size = 1024 << struct.unpack_from("<I", data, 1024 + 24)[0]
    per_group = struct.unpack_from("<I", data, 1024 + 40)[0]
    inode_size = struct.unpack_from("<H", data, 1024 + 88)[0]
    group, index = divmod(number - 1, per_group)
    first = struct.unpack_from("<I", data, 1024 + 20)[0]
    table = struct.unpack_from("<I", data, (first + 1) * block_size + group * 32 + 8)[0]
    return table * block_size + index * inode_size


def invalid_volumes(prefix):
    base = Path(str(prefix) + "-base.raw")
    create_volume(base)
    original = base.read_bytes()
    variants = [("magic", 22), ("capacity", 117), ("bitmap-location", 117),
                ("free-count", 117), ("metadata-bit", 117), ("duplicate-block", 117),
                ("directory-record", 117), ("directory-inode", 117), ("extents", 95),
                ("journal", 95), ("checksum", 95), ("inode-flags", 95), ("acl", 95),
                ("block-size", 95), ("inode-size", 95), ("duplicate-name", 117),
                ("directory-parent", 117), ("entry-type", 117), ("links", 117),
                ("beyond-eof", 117), ("zero-links", 117), ("resize-pointer", 117)]
    seed_number = int(re.search(r"Inode:\s+(\d+)", debugfs(base, "stat /seed.txt"))[1])
    for name, expected in variants:
        data = bytearray(original)
        if name == "magic": struct.pack_into("<H", data, 1024 + 56, 0)
        elif name == "capacity": struct.pack_into("<I", data, 1024 + 4, CAPACITY // 1024 + 1)
        elif name == "bitmap-location": struct.pack_into("<I", data, 2048, CAPACITY // 1024 + 1)
        elif name == "free-count": struct.pack_into("<I", data, 1024 + 12, 0)
        elif name == "metadata-bit":
            bitmap = struct.unpack_from("<I", data, 2048)[0]
            index = bitmap - 1
            data[bitmap * 1024 + index // 8] &= ~(1 << (index % 8))
        elif name == "duplicate-block":
            root = inode_offset(data, 2)
            root_block = struct.unpack_from("<I", data, root + 40)[0]
            struct.pack_into("<I", data, inode_offset(data, seed_number) + 40, root_block)
        elif name in ["directory-record", "directory-inode"]:
            root_block = struct.unpack_from("<I", data, inode_offset(data, 2) + 40)[0]
            struct.pack_into("<H" if name == "directory-record" else "<I", data,
                             root_block * 1024 + (4 if name == "directory-record" else 0),
                             7 if name == "directory-record" else 0xffffffff)
        elif name == "extents": struct.pack_into("<I", data, 1024 + 96, 0x42)
        elif name == "journal": struct.pack_into("<I", data, 1024 + 92, 0x3c)
        elif name == "checksum": struct.pack_into("<I", data, 1024 + 100, 0x403)
        elif name == "inode-flags": struct.pack_into("<I", data, inode_offset(data, seed_number) + 32, 0x80000)
        elif name == "acl": struct.pack_into("<I", data, inode_offset(data, seed_number) + 104, 400)
        elif name == "block-size": struct.pack_into("<I", data, 1024 + 24, 3)
        elif name == "inode-size": struct.pack_into("<H", data, 1024 + 88, 512)
        elif name in ["duplicate-name", "entry-type"]:
            root_block = struct.unpack_from("<I", data, inode_offset(data, 2) + 40)[0]
            offset = root_block * 1024
            while data[offset + 8:offset + 16] != b"seed.txt":
                offset += struct.unpack_from("<H", data, offset + 4)[0]
            if name == "entry-type": data[offset + 7] = 2
            else:
                data[offset + 6] = 10
                data[offset + 8:offset + 18] = b"lost+found"
        elif name == "directory-parent":
            folder = inode_offset(data, 11)
            block = struct.unpack_from("<I", data, folder + 40)[0]
            struct.pack_into("<I", data, block * 1024 + 12, 11)
            struct.pack_into("<H", data, inode_offset(data, 2) + 26, 2)
            struct.pack_into("<H", data, folder + 26, 3)
        elif name == "links": struct.pack_into("<H", data, inode_offset(data, seed_number) + 26, 2)
        elif name == "beyond-eof": struct.pack_into("<I", data, inode_offset(data, seed_number) + 4, 0)
        elif name == "zero-links": struct.pack_into("<H", data, inode_offset(data, seed_number) + 26, 0)
        elif name == "resize-pointer":
            bitmap = struct.unpack_from("<I", data, 2048)[0]
            struct.pack_into("<I", data, inode_offset(data, 7) + 92, bitmap)
        marker = f"AXIOM64_EXT2_EXPECT={expected}\n".encode()
        data[:len(marker)] = marker
        disk = Path(str(prefix) + "-" + name + ".raw")
        disk.write_bytes(data)
        yield disk


def error_volumes(prefix):
    blob = Path(str(prefix) + "-blob")
    blob.write_bytes(b"\x6e" * 1024)
    disks, rules = [], []
    for kind in ["read", "write", "flush", "dirty", "mount-read"]:
        disk = Path(str(prefix) + "-" + kind + ".raw")
        create_volume(disk)
        debugfs(disk, f"write {blob} /error-blob", write=True)
        sector = int(debugfs(disk, "bmap /error-blob 0").strip()) * 2
        rule = Path(str(prefix) + "-" + kind + ".conf")
        if kind == "dirty":
            data = bytearray(disk.read_bytes())
            struct.pack_into("<H", data, 1024 + 58, 0)
            disk.write_bytes(data)
            disks.append(disk)
            rules.append(None)
            continue
        if kind == "mount-read":
            bitmap = struct.unpack_from("<I", disk.read_bytes(), 2048)[0]
            text = ('[inject-error]\nevent = "read_aio"\niotype = "read"\n'
                    f'sector = "{bitmap * 2}"\nerrno = "5"\nonce = "off"\n')
        elif kind == "flush":
            # The first flush commits the writable mount marker; fail the next one.
            text = ('[set-state]\nevent = "flush_to_disk"\nstate = "1"\nnew_state = "2"\n\n'
                    '[inject-error]\nevent = "flush_to_disk"\nstate = "2"\n'
                    'iotype = "flush"\nerrno = "5"\nonce = "on"\n')
        else:
            text = (f'[inject-error]\nevent = "{kind}_aio"\niotype = "{kind}"\n'
                    f'sector = "{sector}"\nerrno = "5"\nonce = "on"\n')
        rule.write_text(text)
        disks.append(disk)
        rules.append(rule)
    return disks, rules


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", choices=["bios", "uefi", "both"], default="both")
    parser.add_argument("--transport", choices=["modern", "legacy", "both"], default="both")
    parser.add_argument("--quick", action="store_true", help="Run only the first format's write/reboot checks")
    parser.add_argument("--checks", choices=["all", "files", "invalid", "errors", "full"], default="all")
    parser.add_argument("--tag", help="Distinct label for generated images and results")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    if args.tag and not re.fullmatch(r"[a-z0-9-]+", args.tag):
        parser.error("--tag must contain only lowercase letters, digits, and hyphens")
    suite_label = "ext2" + ("-" + args.tag if args.tag else "")
    subprocess.run(["make", "-j2", "build/axiom64.elf", "build/rootfs-desktop.cpio"], cwd=ROOT, check=True)
    checks = "files" if args.quick else args.checks
    phases = ["write", "verify"] if args.quick else {
        "all": ["write", "verify", "readonly", "invalid", "error", "full"],
        "files": ["write", "verify", "readonly"], "invalid": ["invalid"],
        "errors": ["error"], "full": ["full"]}[checks]
    images = {}
    for phase in phases:
        with (ROOT / "build" / f"{suite_label}-image-{phase}.log").open("w") as output:
            subprocess.run([sys.executable, str(ROOT / "scripts" / "image.py"), "--test", "--suite", "ext2",
                            "--phase", phase, "--output-name", f"{suite_label}-{phase}.iso"],
                           check=True, stdout=output, stderr=subprocess.STDOUT)
        images[phase] = ROOT / "build" / f"{suite_label}-{phase}.iso"
    firmwares = ["bios", "uefi"] if args.firmware == "both" else [args.firmware]
    transports = ["modern", "legacy"] if args.transport == "both" else [args.transport]
    reports = []

    def run(firmware, transport, phase, disks, label, **kwargs):
        report = boot(firmware, transport, phase, disks, images, label, args.timeout, **kwargs)
        reports.append(report)
        if not report["passed"]:
            raise RuntimeError(f"ext2 boot failed: {label}")
        return report

    try:
        for firmware in firmwares:
            for transport in transports:
                prefix = ROOT / "build" / f"{suite_label}-{firmware}-{transport}"
                formats = (FORMATS[:1] if args.quick else FORMATS) if checks in ["all", "files"] else []
                for block_size, inode_size, features in formats:
                    label = f"{prefix.name}-{block_size}-{inode_size}-{features}"
                    disk = ROOT / "build" / f"{label}.raw"
                    create_volume(disk, block_size, inode_size, features)
                    report = run(firmware, transport, "write", [disk], label + "-write")
                    report["fsck"] = host_verify(disk, block_size, label)
                    report["host_verified"] = True
                    expected = disk.read_bytes()
                    print(f"HOST_EXT2_FILES_PASS {label}", flush=True)
                    for phase in ["verify"] if args.quick else ["verify", "readonly"]:
                        report = run(firmware, transport, phase, [disk], label + "-" + phase, readonly=phase == "readonly")
                        if disk.read_bytes() != expected:
                            raise RuntimeError(f"read-only mount changed disk bytes: {label}/{phase}")
                        report.update(host_verified=True, disk_sha256=hashlib.sha256(expected).hexdigest())
                        print(f"HOST_EXT2_UNCHANGED_PASS {label}/{phase}", flush=True)
                if args.quick:
                    continue
                invalid = list(invalid_volumes(Path(str(prefix) + "-invalid"))) if checks in ["all", "invalid"] else []
                for batch in range(0, len(invalid), 8):
                    disks = invalid[batch:batch + 8]
                    hashes = [hashlib.sha256(disk.read_bytes()).hexdigest() for disk in disks]
                    report = run(firmware, transport, "invalid", disks, f"{prefix.name}-invalid-{batch // 8}")
                    if hashes != [hashlib.sha256(disk.read_bytes()).hexdigest() for disk in disks]:
                        raise RuntimeError("rejected mount changed a disk")
                    report.update(host_verified=True, rejected=[disk.name for disk in disks])
                    print(f"HOST_EXT2_REJECT_UNCHANGED_PASS {prefix.name}/{batch // 8}", flush=True)
                if checks in ["all", "errors"]:
                    disks, rules = error_volumes(Path(str(prefix) + "-error"))
                    expected = [hashlib.sha256(disk.read_bytes()).hexdigest() for disk in disks]
                    report = run(firmware, transport, "error", disks, prefix.name + "-error", rules=rules)
                    for index, disk in enumerate(disks):
                        if index not in [1, 2] and hashlib.sha256(disk.read_bytes()).hexdigest() != expected[index]:
                            raise RuntimeError("read-only or rejected volume changed during an error test")
                        report.setdefault("fsck", []).append(check_fs(disk, disk.stem))
                        blob = dump(disk, "/error-blob", disk.stem)
                        expected_blob = b"\x6e" * 5 + b"X" + b"\x6e" * 1018 if index in [1, 2] else b"\x6e" * 1024
                        if blob != expected_blob:
                            raise RuntimeError("I/O retry file bytes differ")
                    report["host_verified"] = True
                    print(f"HOST_EXT2_RETRY_PASS {prefix.name}", flush=True)
                if checks in ["all", "full"]:
                    disks = [Path(str(prefix) + "-full.raw"), Path(str(prefix) + "-inodes.raw")]
                    create_volume(disks[0], capacity=4 * 1024 * 1024)
                    create_volume(disks[1], capacity=4 * 1024 * 1024, inodes=32)
                    report = run(firmware, transport, "full", disks, prefix.name + "-full")
                    for disk in disks:
                        report.setdefault("fsck", []).append(check_fs(disk, disk.stem))
                        if dump(disk, "/seed.txt", disk.stem) != SEED:
                            raise RuntimeError("full-volume test changed the seed")
                    report["host_verified"] = True
                    print(f"HOST_EXT2_FULL_VOLUME_PASS {prefix.name}", flush=True)
    except Exception as error:
        if reports:
            reports[-1].update(passed=False, host_error=str(error))
        raise
    finally:
        (ROOT / "build" / f"{suite_label}-results.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(f"EXT2_MATRIX_PASS boots={len(reports)}", flush=True)


if __name__ == "__main__":
    main()
