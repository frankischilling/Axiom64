#!/usr/bin/env python3
"""Fetch only the dependency versions and bytes recorded in the lock file."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "dependencies.json").read_text())


def verify_archive(path, expected):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise RuntimeError(f"{path.name}: SHA-256 mismatch: {digest}")


def fetch(name):
    dep = LOCK[name]
    dest = ROOT / "downloads" / dep["archive"]
    dest.parent.mkdir(exist_ok=True)
    if dest.exists():
        verify_archive(dest, dep["sha256"])
        return dest
    temporary = dest.with_suffix(dest.suffix + ".part")
    urls = (dep["url"], *dep.get("mirrors", ()))
    for attempt in range(3):
        try:
            url = urls[min(attempt, len(urls) - 1)]
            with urllib.request.urlopen(url, timeout=60) as response:
                with temporary.open("wb") as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
            verify_archive(temporary, dep["sha256"])
            temporary.replace(dest)
            return dest
        except OSError as error:
            print(f"{dep['archive']}: download from {url} failed: {error}",
                  file=sys.stderr, flush=True)
            if attempt == 2:
                raise
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            time.sleep(2)


def extract(name, destination):
    archive = fetch(name)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as stream:
        stream.extractall(destination, filter="data")


if __name__ == "__main__":
    for dependency in sys.argv[1:] or ["limine", "busybox"]:
        print(f"Verified {fetch(dependency).name}", flush=True)
