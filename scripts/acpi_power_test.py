#!/usr/bin/env python3
"""Check ACPI power-supply discovery and sysfs in BIOS and UEFI guests."""
import argparse
from hashlib import file_digest
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import boot_media
import newc


FIXTURE = """DefinitionBlock ("", "SSDT", 2, "AXIOM", "PWRTEST", 1)
{
    Scope (\\_SB)
    {
        Device (BAT0)
        {
            Name (_HID, EisaId ("PNP0C0A"))
            Name (_STA, 0x1F)
            Method (_BIF, 0)
            {
                Return (Package (13)
                {
                    One, 4221, 4070, One, 11400, 100, 30, 1, 1,
                    "Test battery", "", "Li-I", "Fixture"
                })
            }
            Method (_BST, 0) { Return (Package (4) { 2, 520, 2741, 12028 }) }
        }
        Device (AC00)
        {
            Name (_HID, "ACPI0003")
            Method (_PSR, 0) { Return (One) }
        }
    }
}
"""

STATUS = "/sys/firmware/acpi/axiom64_power_status"
CHECK_SUPPLIES = f"""test "$(cat {STATUS})" = ready
battery=/sys/class/power_supply/BAT0
adapter=/sys/class/power_supply/AC00
test "$(cat "$battery/type")" = Battery
test "$(cat "$battery/present")" = 1
test "$(cat "$battery/capacity")" = 67
test "$(cat "$battery/charge_full")" = 4070000
test "$(cat "$battery/status")" = Charging
test "$(cat "$adapter/type")" = Mains
test "$(cat "$adapter/online")" = 1
grep -Fxq POWER_SUPPLY_CAPACITY=67 "$battery/uevent"
grep -Fxq POWER_SUPPLY_ONLINE=1 "$adapter/uevent"
"""
CHECK_NO_SUPPLIES = """test ! -e /sys/class/power_supply/BAT0
test ! -e /sys/class/power_supply/AC00
"""


def boot(work, firmware, acpi, kernel, busybox, power, check):
    archive = work / "root.cpio"
    init = ("#!/bin/busybox sh\nset -eu\n/bin/busybox --install -s /bin\n" +
            check + "echo ACPI_POWER_CLASS_PASS\nexec /bin/busybox poweroff -f\n")
    files = {name: (0o40755, b"") for name in ("bin", "dev", "proc", "sbin", "sys")}
    files["bin/busybox"] = (0o100755, busybox.read_bytes())
    files["sbin/init"] = (0o100755, init.encode())
    newc.write_cpio(archive, files)
    disk = work / "disk.raw"
    boot_media.build_medium("disk", disk, kernel, archive, " acpi.power" if power else "")
    command = [
        "qemu-system-x86_64", "-machine", "q35", "-m", "256", "-nic", "none",
        "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
        "-drive", f"if=ide,format=raw,snapshot=on,file={disk}",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
    ]
    if acpi:
        command += ["-acpitable", f"file={acpi}"]
    if firmware == "uefi":
        variables = work / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += [
            "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive", f"if=pflash,format=raw,file={variables}",
        ]
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iasl", default="iasl")
    parser.add_argument("--directory", type=Path, default=Path("build/acpi-power-test"))
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    kernel = Path("build/axiom64.elf").resolve()
    busybox = Path("build/busybox-1.37.0/busybox").resolve()
    with kernel.open("rb") as binary:
        results = {"kernel_sha256": file_digest(binary, "sha256").hexdigest()}
    with tempfile.TemporaryDirectory(prefix="axiom64-acpi-power-") as scratch:
        temp = Path(scratch)
        asl = temp / "battery.asl"
        asl.write_text(FIXTURE)
        aml = asl.with_suffix(".aml")
        subprocess.run([args.iasl, "-p", str(aml.with_suffix("")), str(asl)], check=True)
        cases = (
            ("bios", "bios", aml, True, CHECK_SUPPLIES),
            ("uefi", "uefi", aml, True, CHECK_SUPPLIES),
            ("uefi-disabled", "uefi", aml, False, CHECK_NO_SUPPLIES + f"test ! -e {STATUS}\n"),
            ("uefi-no-devices", "uefi", None, True,
             CHECK_NO_SUPPLIES + f'test "$(cat {STATUS})" = "no battery or adapter"\n'),
        )
        for name, firmware, acpi, power, check in cases:
            work = temp / name
            work.mkdir()
            serial = args.directory / f"{name}.log"
            try:
                result = boot(work, firmware, acpi, kernel, busybox, power, check)
            except subprocess.TimeoutExpired as failure:
                serial.write_bytes(failure.stdout or b"")
                raise SystemExit(f"{name} power-supply check timed out. See {serial}") from failure
            serial.write_bytes(result.stdout)
            lines = result.stdout.replace(b"\r", b"").splitlines()
            if (result.returncode != 1 or b"ACPI_POWER_CLASS_PASS" not in lines or
                    b"AXIOM64_EXIT status=0" not in lines):
                raise SystemExit(f"{name} power-supply check failed. See {serial}")
            with serial.open("rb") as transcript:
                results[name] = file_digest(transcript, "sha256").hexdigest()
            print(f"ACPI_POWER_CLASS_PASS {name}", flush=True)
    (args.directory / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
