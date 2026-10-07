#!/usr/bin/env python3
"""Build the upstream BusyBox release against the host's musl toolchain."""
import os
from pathlib import Path
import subprocess
from fetch import ROOT, LOCK, extract

version = LOCK["busybox"]["version"]
source = ROOT / "build" / f"busybox-{version}"
binary = source / "busybox"
if not binary.exists():
    if not source.exists():
        extract("busybox", ROOT / "build")
    uapi = ROOT / "build" / "uapi"
    uapi.mkdir(exist_ok=True)
    for name, target in {"linux": "/usr/include/linux", "asm-generic": "/usr/include/asm-generic", "asm": "/usr/include/x86_64-linux-gnu/asm", "mtd": "/usr/include/mtd"}.items():
        link = uapi / name
        if not link.exists():
            link.symlink_to(target, target_is_directory=True)
    logfile = ROOT / "build" / "busybox-build.log"
    with logfile.open("w") as output:
        def run(args):
            subprocess.run(args, cwd=source, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, check=True)
        run(["make", "defconfig"])
        config = source / ".config"
        lines = config.read_text().splitlines()
        settings = {"CONFIG_STATIC": "y", "CONFIG_TC": "n", "CONFIG_SELINUX": "n"}
        for key, value in settings.items():
            lines = [line for line in lines if not line.startswith(key + "=") and line != f"# {key} is not set"]
            lines.append(f"{key}=y" if value == "y" else f"# {key} is not set")
        config.write_text("\n".join(lines) + "\n")
        try:
            run(["make", "oldconfig"])
            run(["make", f"-j{min(os.cpu_count() or 2, 8)}", "CC=musl-gcc", "HOSTCC=gcc", f"EXTRA_CFLAGS=-I{uapi}"])
        except subprocess.CalledProcessError:
            output.flush()
            print("\n".join(logfile.read_text().splitlines()[-50:]))
            raise
print(f"BusyBox ready: {binary}")
