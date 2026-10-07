#!/usr/bin/env python3
"""Boot the actual kernel, check guest tests, and capture the X11 desktop."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from fetch import ROOT
from qmp import Qmp


parser = argparse.ArgumentParser()
parser.add_argument("--firmware", choices=["bios", "uefi", "both"], default="both")
parser.add_argument("--suite", choices=["full", "abi", "desktop"], default="full")
parser.add_argument("--timeout", type=int, default=600)
parser.add_argument("--trace", action="store_true")
parser.add_argument("--gdb", action="store_true")
parser.add_argument("--interactive", action="store_true", help="check the normal desktop image and serial shell")
args = parser.parse_args()
if args.interactive and args.suite != "full":
    parser.error("--interactive uses the full image")
subprocess.run(["make", "-j2", "build/axiom64.elf",
                "build/rootfs-desktop.cpio" if args.suite != "full" else "build/rootfs.cpio"],
               cwd=ROOT, check=True)
subprocess.run([sys.executable, str(ROOT / "scripts" / "image.py")]
               + ([] if args.interactive else ["--test", "--suite", args.suite])
               + (["--trace"] if args.trace else []), check=True)
firmwares = ["bios", "uefi"] if args.firmware == "both" else [args.firmware]
results = []
for firmware in firmwares:
    started = time.monotonic()
    logfile = ROOT / "build" / f"{'interactive' if args.interactive else 'boot'}-{firmware}.log"
    control = Path("/tmp") / f"axiom64-qmp-{os.getpid()}-{firmware}.sock"
    screenshot = ROOT / "build" / f"{'interactive' if args.interactive else 'desktop'}-{firmware}.png"
    control.unlink(missing_ok=True)
    screenshot.unlink(missing_ok=True)
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "2G",
               "-cdrom", str(ROOT / "build" / ("axiom64.iso" if args.interactive else "axiom64-test.iso")), "-display", "none",
               "-serial", "stdio", "-monitor", "none", "-no-reboot", "-qmp",
               f"unix:{control},server=on,wait=off",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    if args.gdb:
        command += ["-gdb", "tcp:127.0.0.1:1234"]
    if firmware == "uefi":
        variables = ROOT / "build" / "OVMF_VARS.fd"
        shutil.copy2("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command.extend(["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                        "-drive", f"if=pflash,format=raw,file={variables}"])
    timed_out, capture_error, qmp = False, None, None
    input_sent = False
    serial_sent = False
    with logfile.open("w") as output:
        process = subprocess.Popen(command, stdin=subprocess.PIPE if args.interactive else subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                if time.monotonic() - started > args.timeout:
                    timed_out = True
                    process.kill()
                    break
                if args.suite != "abi":
                    with logfile.open("rb") as log:
                        log.seek(max(0, logfile.stat().st_size - 16384))
                        tail = log.read()
                    lines = {line.strip() for line in tail.splitlines()}
                    if args.interactive and not serial_sent and b"Starting Xorg" in tail:
                        process.stdin.write(b"while ! test -f /tmp/xterm-ready; do sleep .1; done; "
                            b"/bin/x11-probe --desktop && echo DESKTOP_INPUT_READY; "
                            b"while ! test -f /tmp/x11-input-pass; do sleep .1; done; "
                            b"echo X11_KEYBOARD_PASS; echo DESKTOP_CAPTURE_READY; "
                            b"sleep 2; echo NORMAL_BOOT_PASS\n")
                        process.stdin.flush()
                        serial_sent = True
                    if b"DESKTOP_INPUT_READY" in lines and not input_sent:
                        qmp = Qmp(control)
                        qmp.command("input-send-event", {"events": [
                            {"type": "rel", "data": {"axis": "x", "value": 4}},
                            {"type": "rel", "data": {"axis": "y", "value": 4}},
                            {"type": "btn", "data": {"button": "left", "down": True}}]})
                        qmp.command("input-send-event", {"events": [
                            {"type": "btn", "data": {"button": "left", "down": False}}]})
                        key_names = {" ": "spc", "/": "slash", "-": "minus", "\n": "ret"}
                        for character in "touch /tmp/x11-input-pass\n":
                            qmp.command("send-key", {"keys": [{"type": "qcode", "data":
                                key_names.get(character, character)}], "hold-time": 30})
                            time.sleep(0.07)
                        qmp.close()
                        qmp = None
                        input_sent = True
                    if b"DESKTOP_CAPTURE_READY" in lines and not screenshot.exists():
                        qmp = Qmp(control)
                        qmp.command("screendump", {"filename": str(screenshot), "format": "png"})
                        qmp.close()
                        qmp = None
                    if args.interactive and b"NORMAL_BOOT_PASS" in lines:
                        qmp = Qmp(control)
                        qmp.command("quit")
                        qmp.close()
                        qmp = None
                time.sleep(0.1)
        except Exception as error:
            capture_error = str(error)
            process.kill()
        finally:
            if qmp:
                qmp.close()
            returncode = process.wait()
            if process.stdin:
                process.stdin.close()
            control.unlink(missing_ok=True)
    text = logfile.read_text(errors="replace")
    required = [f"Firmware: {firmware.upper()}"]
    if args.interactive:
        required += ["NORMAL_BOOT_PASS", "WINDOW_MANAGER_PASS", "XTERM_WINDOW_PASS", "X11_KEYBOARD_PASS"]
    else:
        required += ["AXIOM64_TESTS_PASS", "AXIOM64_EXIT status=0"]
    if args.suite != "desktop" and not args.interactive:
        required += ["ABI_TESTS_PASS linkage=static", "ABI_TESTS_PASS linkage=dynamic",
                     "IPC_TESTS_PASS", "SIGNAL_TESTS_PASS", "VFS_TESTS_PASS", "BUSYBOX_SHELL_PASS"]
    if args.suite == "full" and not args.interactive:
        required += ["NATIVE_C_PASS", "NATIVE_CPP_PASS", "NATIVE_DIAGNOSTICS_PASS", "NATIVE_TOOLCHAIN_PASS"]
    if args.suite != "abi" and not args.interactive:
        required += ["BASH_SHELL_PASS", "ZSH_SHELL_PASS", "XORG_SERVER_PASS",
                     "X11_PROTOCOL_PIXELS_PASS", "XTERM_BASH_PASS", "WINDOW_MANAGER_PASS",
                     "XTERM_WINDOW_PASS", "X11_KEYBOARD_PASS", "X11_DESKTOP_PASS"]
    missing = [marker for marker in required if marker not in {line.strip() for line in text.splitlines()}]
    if args.suite != "abi" and not screenshot.exists():
        missing.append("desktop screenshot")
    passed = not timed_out and not capture_error and returncode == (0 if args.interactive else 1) and not missing
    passed &= not any(marker in text for marker in ["PANIC:", "FAULT ", "ABI_FAIL", "IPC_FAIL", "SIGNAL_FAIL", "VFS_FAIL", "X11_FAIL"])
    results.append({"firmware": firmware, "suite": "interactive" if args.interactive else args.suite, "passed": passed,
                    "returncode": returncode, "timed_out": timed_out, "capture_error": capture_error,
                    "elapsed_seconds": round(time.monotonic() - started, 2), "missing_markers": missing,
                    "log": str(logfile), "screenshot": str(screenshot) if screenshot.exists() else None})
    print(f"{firmware}: {'PASS' if passed else 'FAIL'}; log: {logfile}", flush=True)
    if not passed:
        print("\n".join(text.splitlines()[-100:]), flush=True)
        if capture_error:
            print("Capture failed:", capture_error, flush=True)
(ROOT / "build" / ("interactive-results.json" if args.interactive else "boot-results.json")).write_text(json.dumps(results, indent=2) + "\n")
sys.exit(0 if all(result["passed"] for result in results) else 1)
