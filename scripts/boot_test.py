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
from desktop_console import desktop_complete, desktop_test_command
from normal_login import ConsoleLogin, install_observer
from account_normal_test import save, write_cpio
from build_accounts import digest
from fixture_archive import archive_fixture


parser = argparse.ArgumentParser()
parser.add_argument("--firmware", choices=["bios", "uefi", "both"], default="both")
parser.add_argument("--suite", choices=["full", "abi", "desktop", "threads"], default="full")
parser.add_argument("--phase", choices=["all", "cond", "io"], default="all", help="threads test selection")
parser.add_argument("--timeout", type=int, default=600)
parser.add_argument("--trace", action="store_true")
parser.add_argument("--gdb", action="store_true")
parser.add_argument("--interactive", action="store_true", help="check the normal desktop image and serial shell")
parser.add_argument("--disk-root", action="store_true", help="boot the generated ext2 root fixture")
parser.add_argument("--transport", choices=["modern", "legacy"], default="modern")
args = parser.parse_args()
if args.interactive and args.suite != "full":
    parser.error("--interactive uses the full image")
desktop_checks = args.suite in ["full", "desktop"]
subprocess.run(["make", "-j2", "build/axiom64.elf",
                "build/rootfs-desktop.cpio" if args.suite not in ["full", "threads"] or
                    (args.suite == "threads" and args.phase in ["cond", "io"]) else "build/rootfs.cpio"],
               cwd=ROOT, check=True)
interactive_cpio = None
login_inputs = None
if args.interactive:
    from disk_root import archive_entries
    login_directory = ROOT / 'build' / ('interactive-login-' + str(os.getpid()))
    login_directory.mkdir(exist_ok=False)
    original_cpio = ROOT / 'build/rootfs.cpio'
    original_digest = digest(original_cpio)
    files = archive_entries(original_cpio)
    login_inputs = install_observer(files, login_directory)
    interactive_cpio = login_directory / 'root.cpio'
    write_cpio(interactive_cpio, files)
    login_inputs.update(original_cpio_sha256=original_digest, root_cpio_sha256=digest(interactive_cpio),
                        kernel_sha256=digest(ROOT / 'build/axiom64.elf'),
                        source_sha256={name: digest(ROOT / name) for name in
                            ('scripts/boot_test.py', 'scripts/desktop_console.py', 'scripts/normal_login.py',
                             'scripts/account_normal_test.py', 'scripts/disk_root.py',
                             'scripts/fixture_archive.py',
                             'userspace/tests/security/account-normal-observe.c')})
    save(login_directory / 'inputs.json', login_inputs)
    if digest(original_cpio) != original_digest:
        raise RuntimeError('normal login fixture changed the installed root archive')
if args.disk_root:
    from disk_root import build
    from ext2_test import check_fs
    disk_profile = "desktop" if args.suite not in ["full", "threads"] or (
        args.suite == "threads" and args.phase in ["cond", "io"]) else "full"
    root_seed = build(disk_profile, source=interactive_cpio)
image_name = (f"threads-{args.phase}.iso" if args.suite == "threads" else
              "axiom64.iso" if args.interactive else "axiom64-test.iso")
if args.disk_root:
    image_name = f"disk-root-{args.transport}-" + image_name
subprocess.run([sys.executable, str(ROOT / "scripts" / "image.py")]
               + ([] if args.interactive else ["--test", "--suite", args.suite])
               + (["--phase", args.phase] if args.suite == "threads" else [])
               + (["--output-name", image_name])
               + (["--root-device", "/dev/vda"] if args.disk_root else [])
               + (["--initramfs", str(interactive_cpio)] if interactive_cpio and not args.disk_root else [])
               + (["--trace"] if args.trace else []), check=True)
firmwares = ["bios", "uefi"] if args.firmware == "both" else [args.firmware]
results = []
for firmware in firmwares:
    started = time.monotonic()
    prefix = f"threads-{args.phase}" if args.suite == "threads" else "interactive" if args.interactive else "boot"
    if args.disk_root:
        prefix = f"disk-root-{args.transport}-" + prefix
    logfile = ROOT / "build" / f"{prefix}-{firmware}.log"
    control = Path("/tmp") / f"axiom64-qmp-{os.getpid()}-{firmware}.sock"
    screenshot = ROOT / "build" / (f"{prefix}-{firmware}.png" if args.disk_root else
                                  f"{'interactive' if args.interactive else 'desktop'}-{firmware}.png")
    control.unlink(missing_ok=True)
    if desktop_checks:
        screenshot.unlink(missing_ok=True)
    command = ["qemu-system-x86_64", "-machine", "pc", "-cpu", "max", "-m", "2G",
               "-cdrom", str(ROOT / "build" / image_name), "-display", "none",
               "-serial", "stdio", "-monitor", "none", "-no-reboot", "-qmp",
               f"unix:{control},server=on,wait=off"]
    if not (args.interactive and args.disk_root):
        command += ["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    if args.disk_root:
        disk = ROOT / "build" / f"{prefix}-{firmware}.raw"
        shutil.copyfile(root_seed, disk)
        transport = "disable-legacy=on" if args.transport == "modern" else "disable-modern=on"
        command += ["-drive", f"if=none,id=root,format=raw,cache=writeback,file={disk}",
                    "-device", f"virtio-blk-pci,drive=root,{transport},rerror=report,werror=report,addr=5"]
    if args.gdb:
        command += ["-gdb", "tcp:127.0.0.1:1234"]
    if firmware == "uefi":
        variables = ROOT / "build" / f"{prefix}-OVMF_VARS.fd"
        shutil.copy2("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command.extend(["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                        "-drive", f"if=pflash,format=raw,file={variables}"])
    timed_out, capture_error, qmp = False, None, None
    input_sent = False
    serial_sent = False
    shutdown_sent = False
    with logfile.open("w") as output:
        process = subprocess.Popen(command, stdin=subprocess.PIPE if args.interactive else subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        def console_write(value):
            process.stdin.write(value)
            process.stdin.flush()
        login = ConsoleLogin(console_write) if args.interactive else None
        try:
            while process.poll() is None:
                if time.monotonic() - started > args.timeout:
                    timed_out = True
                    process.kill()
                    break
                if desktop_checks:
                    with logfile.open("rb") as log:
                        log.seek(max(0, logfile.stat().st_size - 16384))
                        tail = log.read()
                    lines = {line.strip() for line in tail.splitlines()}
                    if args.interactive:
                        login.consume(logfile.read_bytes())
                    if args.interactive and not serial_sent and login.ready:
                        login.command(desktop_test_command(authenticated=True))
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
                    if args.interactive and desktop_complete(lines, input_sent, screenshot.exists()):
                        if args.disk_root:
                            if not shutdown_sent:
                                login.elevate('/bin/busybox poweroff -f')
                                shutdown_sent = True
                        else:
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
    if args.disk_root:
        required += ["VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0", "AXIOM64_EXIT status=0"]
    if args.interactive:
        required += ["NORMAL_BOOT_PASS", "WINDOW_MANAGER_PASS", "XTERM_WINDOW_PASS",
                     "X11_KEYBOARD_PASS", "DESKTOP_CAPTURE_READY"]
        if args.disk_root:
            required += ["PLATFORM_POWEROFF method=piix4"]
    else:
        required += ["AXIOM64_TESTS_PASS", "AXIOM64_EXIT status=0"]
    if args.suite in ["full", "abi"] and not args.interactive:
        required += ["ABI_TESTS_PASS linkage=static", "ABI_TESTS_PASS linkage=dynamic",
                     "IPC_TESTS_PASS", "SIGNAL_TESTS_PASS", "VFS_TESTS_PASS", "BUSYBOX_SHELL_PASS",
                     "THREAD_TESTS_PASS linkage=static", "THREAD_TESTS_PASS linkage=dynamic",
                     "FUTEX_TESTS_PASS linkage=static", "FUTEX_TESTS_PASS linkage=dynamic",
                     "THREAD_LIFECYCLE_PASS linkage=static", "THREAD_LIFECYCLE_PASS linkage=dynamic",
                     "THREAD_IO_TESTS_PASS linkage=static", "THREAD_IO_TESTS_PASS linkage=dynamic"]
    if args.suite == "full" and not args.interactive:
        required += ["NATIVE_C_PASS", "NATIVE_CPP_PASS", "NATIVE_THREADS_PASS",
                     "NATIVE_DIAGNOSTICS_PASS", "NATIVE_TOOLCHAIN_PASS"]
    if not args.interactive and (args.suite in ["full", "abi"] or
                                (args.suite == "threads" and args.phase != "cond")):
        required += [f"THREAD_IO_TIMEOUTS_PASS linkage={linkage} operations=10 signals=4 families=4 cycles=300"
                     for linkage in ["static", "dynamic"]]
        required += [f"THREAD_IO_TIMEOUTS_UNMAPPED_PASS linkage={linkage} operations=8 readable_faults=2"
                     for linkage in ["static", "dynamic"]]
    if args.suite == "threads":
        required += (["THREAD_MUTEX_COND_PASS"] if args.phase == "cond" else
                     ["THREAD_IO_TESTS_PASS linkage=static", "THREAD_IO_TESTS_PASS linkage=dynamic"] if args.phase == "io" else
                     ["THREAD_TESTS_PASS linkage=static", "THREAD_TESTS_PASS linkage=dynamic",
                      "FUTEX_TESTS_PASS linkage=static", "FUTEX_TESTS_PASS linkage=dynamic",
                      "THREAD_LIFECYCLE_PASS linkage=static", "THREAD_LIFECYCLE_PASS linkage=dynamic",
                      "THREAD_IO_TESTS_PASS linkage=static", "THREAD_IO_TESTS_PASS linkage=dynamic",
                      "NATIVE_THREADS_PASS"])
    if desktop_checks and not args.interactive:
        required += ["BASH_SHELL_PASS", "ZSH_SHELL_PASS", "XORG_SERVER_PASS",
                     "X11_PROTOCOL_PIXELS_PASS", "XTERM_BASH_PASS", "WINDOW_MANAGER_PASS",
                     "XTERM_WINDOW_PASS", "X11_KEYBOARD_PASS", "X11_DESKTOP_PASS"]
    missing = [marker for marker in required if marker not in {line.strip() for line in text.splitlines()}]
    if desktop_checks and not screenshot.exists():
        missing.append("desktop screenshot")
    passed = not timed_out and not capture_error and returncode == (0 if args.interactive else 1) and not missing
    passed &= not any(marker in text for marker in ["PANIC:", "FAULT ", "ABI_FAIL", "IPC_FAIL", "SIGNAL_FAIL", "VFS_FAIL", "THREAD_FAIL", "THREAD_IO_FAIL", "FUTEX_FAIL", "LIFECYCLE_FAIL", "X11_FAIL", "BOOT_ROOT_FAIL", "FILESYSTEM_SHUTDOWN_FAIL", "ACCOUNT_NORMAL_FAIL"])
    if args.interactive:
        passed &= login.ready and 'ACCOUNT_NORMAL_IDENTITY_PASS uid=1000 gid=1000 groups=2 ' in text
    if args.disk_root and passed:
        try:
            fsck = check_fs(disk, f"{prefix}-{firmware}")
        except Exception as error:
            capture_error, passed = str(error), False
    row = {"firmware": firmware, "suite": "interactive" if args.interactive else args.suite, "passed": passed,
                    "root": "ext2" if args.disk_root else "ramfs",
                    "transport": args.transport if args.disk_root else None,
                    "returncode": returncode, "timed_out": timed_out, "capture_error": capture_error,
                    "elapsed_seconds": round(time.monotonic() - started, 2), "missing_markers": missing,
                    "log": str(logfile), "screenshot": str(screenshot) if desktop_checks and screenshot.exists() else None,
                    "login_events": login.events if login else None, "login_inputs": login_inputs}
    results.append(row)
    if args.interactive:
        retained = login_directory / firmware
        retained.mkdir(exist_ok=False)
        shutil.copyfile(logfile, retained / 'serial.log')
        if screenshot.exists():
            shutil.copyfile(screenshot, retained / 'desktop.png')
        if not (login_directory / 'image.iso').exists():
            shutil.copyfile(ROOT / 'build' / image_name, login_directory / 'image.iso')
        login_inputs['image_sha256'] = digest(login_directory / 'image.iso')
        if args.disk_root and passed:
            shutil.copyfile(ROOT / 'build' / fsck, retained / 'fsck.log')
            archived = archive_fixture(disk, remove=True)
            shutil.move(archived['path'], retained / 'root.raw.gz')
            archived['path'] = str(retained / 'root.raw.gz')
            row['retained_disk'] = archived
        save(retained / 'result.json', row)
        save(login_directory / 'inputs.json', login_inputs)
    print(f"{firmware}: {'PASS' if passed else 'FAIL'}; log: {logfile}", flush=True)
    if not passed:
        print("\n".join(text.splitlines()[-100:]), flush=True)
        if capture_error:
            print("Capture failed:", capture_error, flush=True)
result_name = (f"threads-{args.phase}-results.json" if args.suite == "threads" else
               "interactive-results.json" if args.interactive else "boot-results.json")
if args.disk_root:
    result_name = f"disk-root-{args.transport}-" + result_name
(ROOT / "build" / result_name).write_text(json.dumps(results, indent=2) + "\n")
if args.interactive:
    expected = {**login_inputs['source_sha256'], **login_inputs['observer_source_sha256']}
    if expected != {name: digest(ROOT / name) for name in expected}:
        raise RuntimeError('normal boot sources changed during acceptance')
sys.exit(0 if all(result["passed"] for result in results) else 1)
