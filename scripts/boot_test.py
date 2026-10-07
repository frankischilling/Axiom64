#!/usr/bin/env python3
"""Require userspace test markers, the expected firmware, and clean guest exit."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
from fetch import ROOT

parser = argparse.ArgumentParser()
parser.add_argument("--firmware", choices=["bios", "uefi", "both"], default="both")
parser.add_argument("--timeout", type=int, default=90)
parser.add_argument("--trace", action="store_true")
args = parser.parse_args()
subprocess.run([sys.executable, str(ROOT / "scripts" / "image.py"), "--test"] + (["--trace"] if args.trace else []), check=True)
firmwares = ["bios", "uefi"] if args.firmware == "both" else [args.firmware]
results = []
for firmware in firmwares:
    logfile = ROOT / "build" / f"boot-{firmware}.log"
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "512M", "-cdrom", str(ROOT / "build" / "axiom64-test.iso"), "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    if firmware == "uefi":
        code = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
        variables = ROOT / "build" / "OVMF_VARS.fd"
        shutil.copy2("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command.extend(["-drive", f"if=pflash,format=raw,readonly=on,file={code}", "-drive", f"if=pflash,format=raw,file={variables}"])
    timed_out = False
    with logfile.open("w") as output:
        try:
            run = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=args.timeout)
            returncode = run.returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, None
    text = logfile.read_text(errors="replace")
    required = [f"Firmware: {firmware.upper()}", "ABI_TESTS_PASS linkage=static", "ABI_TESTS_PASS linkage=dynamic", "BUSYBOX_SHELL_PASS", "AXIOM64_TESTS_PASS", "AXIOM64_EXIT status=0"]
    missing = [marker for marker in required if marker not in text]
    passed = not timed_out and returncode == 1 and not missing and "PANIC:" not in text and "FAULT " not in text and "ABI_FAIL" not in text
    results.append({"firmware": firmware, "passed": passed, "returncode": returncode, "timed_out": timed_out, "missing_markers": missing, "log": str(logfile)})
    print(f"{firmware}: {'PASS' if passed else 'FAIL'}; log: {logfile}", flush=True)
    if not passed:
        print("\n".join(text.splitlines()[-60:]), flush=True)
(ROOT / "build" / "boot-results.json").write_text(json.dumps(results, indent=2) + "\n")
sys.exit(0 if all(result["passed"] for result in results) else 1)
