#!/usr/bin/env python3
"""Verify real virtio disks across fresh QEMU boots and inspect their bytes on the host."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from fetch import ROOT

CAPACITY = 8 * 1024 * 1024
START, LENGTH = 8192 + 37, 16384 + 713
ERROR_READ, ERROR_WRITE = 12328, 12348
PAYLOAD = bytes((i * 31 + 17) & 255 for i in range(LENGTH))


def fixture(capacity, value, marker):
    data = bytearray([value]) * capacity
    data[:len(marker)] = marker
    return data


def check_image(path, expected):
    actual = path.read_bytes()
    if actual != expected:
        mismatch = next((i for i, pair in enumerate(zip(actual, expected))
                         if pair[0] != pair[1]), min(len(actual), len(expected)))
        raise RuntimeError(f"{path.name}: unexpected disk byte at {mismatch}")
    return hashlib.sha256(actual).hexdigest()


def boot(firmware, transport, phase, disk, second, image, timeout, *, configuration=None):
    label = f"storage-{firmware}-{transport}-{phase}"
    properties = ""
    if configuration:
        label += f"-q{configuration['size']}"
        properties = (f",queue-size={configuration['size']},num-queues={configuration['queues']},"
                      f"event_idx={configuration['features']},indirect_desc={configuration['features']},"
                      f"packed={configuration['packed']}")
    logfile = ROOT / "build" / f"{label}.log"
    mode = "disable-legacy=on" if transport == "modern" else "disable-modern=on"
    readonly = phase == "readonly"
    backend = str(disk)
    if phase == "error":
        rules = ROOT / "build" / f"{label}.conf"
        # Firmware probes the beginning and end of each disk before the kernel starts.
        rules.write_text('[inject-error]\nevent = "read_aio"\niotype = "read"\nerrno = "5"\n'
                         f'sector = "{ERROR_READ}"\nonce = "on"\n\n'
                         '[inject-error]\nevent = "write_aio"\niotype = "write"\nerrno = "5"\n'
                         f'sector = "{ERROR_WRITE}"\nonce = "on"\n\n'
                         '[inject-error]\nevent = "flush_to_disk"\nerrno = "5"\n'
                         'iotype = "flush"\nonce = "on"\n')
        backend = f"blkdebug:{rules}:{disk}"
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "512M",
               "-cdrom", str(image), "-display", "none", "-serial", "stdio", "-monitor", "none",
               "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
               "-drive", f"if=none,id=data,format=raw,cache=writeback,file={backend},readonly={'on' if readonly else 'off'}",
               "-device", f"virtio-blk-pci,drive=data,{mode},rerror=report,werror=report,addr=5{properties}",
               "-drive", f"if=none,id=second,format=raw,readonly=on,file={second}",
               "-device", f"virtio-blk-pci,drive=second,{mode},addr=6{properties}"]
    if phase == "error":
        command += ["-trace", f"enable=virtio_blk_handle_read,file={ROOT / 'build' / (label + '.trace')}"]
    if firmware == "uefi":
        variables = ROOT / "build" / f"{label}-VARS.fd"
        shutil.copy2("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    markers = [f"Firmware: {firmware.upper()}", "AXIOM64_EXIT status=0",
               f"virtio-blk: disk=0 transport={transport} sectors={CAPACITY // 512} readonly={int(readonly)} flush=1",
               f"virtio-blk: disk=1 transport={transport} sectors={CAPACITY // 1024} readonly=1 flush=1",
               f"STORAGE_PHASE_PASS phase={phase}"]
    markers += {"write": ["STORAGE_WRITE_PASS", "STORAGE_RING_WRAP_PASS requests=65540"],
                "queue": ["STORAGE_WRITE_PASS", "STORAGE_QUEUE_WRAP_PASS requests=2052"],
                "verify": ["STORAGE_REBOOT_PASS"], "readonly": ["STORAGE_READONLY_PASS"],
                "error": ["STORAGE_BACKEND_ERROR_PASS"]}[phase]
    if configuration:
        selected = min(256, configuration["size"]) if transport == "modern" else configuration["size"]
        markers += [f"virtio-queue: disk={disk_number} id=0 size={selected}" for disk_number in [0, 1]]
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
    missing = [marker for marker in markers if marker not in lines]
    failed = any(marker in text for marker in ["STORAGE_FAIL", "PANIC:", "FAULT pid=", "initialization failed"])
    passed = not timed_out and not missing and not failed and returncode == 1
    report = {"firmware": firmware, "transport": transport, "phase": phase, "passed": passed,
              "returncode": returncode, "timed_out": timed_out, "missing": missing,
              "seconds": round(time.monotonic() - started, 2), "log": logfile.name}
    if configuration:
        report.update(configuration=configuration, selected_size=selected)
    print(json.dumps(report), flush=True)
    if not passed:
        print("\n".join(text.splitlines()[-24:]), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", choices=["bios", "uefi", "both"], default="both")
    parser.add_argument("--transport", choices=["modern", "legacy", "both"], default="both")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    subprocess.run(["make", "-j2", "build/axiom64.elf", "build/rootfs-desktop.cpio"], cwd=ROOT, check=True)
    images = {}
    for phase in ["write", "verify", "readonly", "error"]:
        image_log = ROOT / "build" / f"storage-image-{phase}.log"
        with image_log.open("w") as output:
            subprocess.run([sys.executable, str(ROOT / "scripts" / "image.py"), "--test", "--suite", "storage",
                            "--phase", phase], check=True, stdout=output, stderr=subprocess.STDOUT)
        images[phase] = ROOT / "build" / f"storage-{phase}.iso"
    firmwares = ["bios", "uefi"] if args.firmware == "both" else [args.firmware]
    transports = ["modern", "legacy"] if args.transport == "both" else [args.transport]
    reports = []
    try:
        for firmware in firmwares:
            for transport in transports:
                prefix = ROOT / "build" / f"storage-{firmware}-{transport}"
                disk, second = Path(str(prefix) + ".raw"), Path(str(prefix) + "-second.raw")
                expected = fixture(CAPACITY, 0xa5, b"AXIOM64-DISK-FIRST\n")
                second_expected = fixture(CAPACITY // 2, 0x3c, b"AXIOM64-DISK-SECOND\n")
                disk.write_bytes(expected)
                second.write_bytes(second_expected)
                for phase in ["write", "verify", "readonly", "error"]:
                    if phase == "error":
                        disk = Path(str(prefix) + "-error.raw")
                        expected = fixture(CAPACITY, 0xa5, b"AXIOM64-DISK-FIRST\n")
                        disk.write_bytes(expected)
                    report = boot(firmware, transport, phase, disk, second, images[phase], args.timeout)
                    reports.append(report)
                    if not report["passed"]:
                        raise RuntimeError(f"storage boot failed: {firmware}/{transport}/{phase}")
                    if phase == "write":
                        expected[START:START + LENGTH] = PAYLOAD
                        expected[-257:] = PAYLOAD[:257]
                    elif phase == "error":
                        expected[ERROR_WRITE * 512:(ERROR_WRITE + 1) * 512] = b"\x6e" * 512
                    try:
                        report["disk_sha256"] = check_image(disk, expected)
                        report["second_sha256"] = check_image(second, second_expected)
                    except RuntimeError as error:
                        report.update(passed=False, host_verified=False, host_error=str(error))
                        raise
                    report["host_verified"] = True
                    print(f"HOST_DISK_BYTES_PASS {firmware}/{transport}/{phase}", flush=True)
    finally:
        (ROOT / "build" / "storage-results.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(f"STORAGE_MATRIX_PASS boots={len(reports)}", flush=True)


if __name__ == "__main__":
    main()
