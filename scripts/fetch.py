#!/usr/bin/env python3
"""Fetch only the dependency versions and bytes recorded in the lock file."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "dependencies.json").read_text())


def fetch(name):
    dep = LOCK[name]
    dest = ROOT / "downloads" / dep["archive"]
    dest.parent.mkdir(exist_ok=True)
    if not dest.exists():
        temporary = dest.with_suffix(dest.suffix + ".part")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(dep["url"], timeout=60) as response:
                    with temporary.open("wb") as output:
                        while chunk := response.read(1024 * 1024):
                            output.write(chunk)
                temporary.replace(dest)
                break
            except OSError:
                if attempt == 2:
                    raise
                time.sleep(2)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    if digest != dep["sha256"]:
        raise RuntimeError(f"{dest.name}: SHA-256 mismatch: {digest}")
    return dest


def extract(name, destination):
    archive = fetch(name)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as stream:
        stream.extractall(destination, filter="data")


if __name__ == "__main__":
    for dependency in sys.argv[1:] or ["limine", "busybox"]:
        print(f"Verified {fetch(dependency).name}", flush=True)
