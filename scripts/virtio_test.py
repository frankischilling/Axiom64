#!/usr/bin/env python3
"""Check split-ring geometry and optional device features with real disk I/O."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from fetch import ROOT
from storage_test import CAPACITY, START, LENGTH, PAYLOAD, fixture, check_image, boot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", choices=["bios", "uefi", "both"], default="both")
    parser.add_argument("--transport", choices=["modern", "legacy", "both"], default="both")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    subprocess.run(["make", "-j2", "build/axiom64.elf", "build/rootfs-desktop.cpio"], cwd=ROOT, check=True)
    images = {}
    for phase in ["queue", "verify"]:
        name = f"virtio-{phase}.iso"
        with (ROOT / "build" / f"virtio-image-{phase}.log").open("w") as output:
            subprocess.run([sys.executable, str(ROOT / "scripts" / "image.py"), "--test", "--suite", "storage",
                            "--phase", phase, "--output-name", name], check=True, stdout=output, stderr=subprocess.STDOUT)
        images[phase] = ROOT / "build" / name
    configurations = [
        {"size": 4, "queues": 1, "features": "off", "packed": "off"},
        {"size": 128, "queues": 2, "features": "on", "packed": "on"},
        {"size": 1024, "queues": 1, "features": "off", "packed": "off"},
    ]
    firmwares = ["bios", "uefi"] if args.firmware == "both" else [args.firmware]
    transports = ["modern", "legacy"] if args.transport == "both" else [args.transport]
    reports = []
    try:
        for firmware in firmwares:
            for transport in transports:
                for configuration in configurations:
                    prefix = ROOT / "build" / f"virtio-{firmware}-{transport}-q{configuration['size']}"
                    disk, second = Path(str(prefix) + ".raw"), Path(str(prefix) + "-second.raw")
                    expected = fixture(CAPACITY, 0xa5, b"AXIOM64-DISK-FIRST\n")
                    other = fixture(CAPACITY // 2, 0x3c, b"AXIOM64-DISK-SECOND\n")
                    disk.write_bytes(expected)
                    second.write_bytes(other)
                    for phase in ["queue", "verify"]:
                        report = boot(firmware, transport, phase, disk, second, images[phase], args.timeout,
                                      configuration=configuration)
                        reports.append(report)
                        if not report["passed"]:
                            raise RuntimeError(f"virtio configuration failed: {firmware}/{transport}/{configuration['size']}/{phase}")
                        if phase == "queue":
                            expected[START:START + LENGTH] = PAYLOAD
                            expected[-257:] = PAYLOAD[:257]
                        try:
                            report["disk_sha256"] = check_image(disk, expected)
                            report["second_sha256"] = check_image(second, other)
                        except RuntimeError as error:
                            report.update(passed=False, host_verified=False, host_error=str(error))
                            raise
                        report["host_verified"] = True
                        print(f"HOST_VIRTIO_BYTES_PASS {firmware}/{transport}/q{configuration['size']}/{phase}", flush=True)
    finally:
        (ROOT / "build" / "virtio-results.json").write_text(json.dumps(reports, indent=2) + "\n")
    print(f"VIRTIO_MATRIX_PASS boots={len(reports)}", flush=True)


if __name__ == "__main__":
    main()
