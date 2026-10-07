#!/usr/bin/env python3
"""Resolve and fetch musl packages for the guest; never execute package scripts."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request
from fetch import ROOT

BASE = "https://dl-cdn.alpinelinux.org/alpine/v3.22"
LOCKFILE = ROOT / "ports.lock.json"
TOOLCHAIN = ["gcc", "g++", "binutils", "musl-dev", "linux-headers", "make"]


def download(url, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        request = urllib.request.Request(url, headers={"User-Agent": "Axiom64-build"})
        with urllib.request.urlopen(request, timeout=60) as response:
            temporary = destination.with_suffix(destination.suffix + ".part")
            with temporary.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
            temporary.replace(destination)
    return destination


def resolve(names):
    index = {}
    providers = {}
    for repo in ["main", "community"]:
        with urllib.request.urlopen(f"{BASE}/{repo}/x86_64/APKINDEX.tar.gz", timeout=60) as response:
            with tarfile.open(fileobj=io.BytesIO(response.read()), mode="r:gz") as stream:
                text = stream.extractfile("APKINDEX").read().decode()
        for paragraph in text.split("\n\n"):
            fields = dict(line.split(":", 1) for line in paragraph.splitlines() if ":" in line)
            if "P" not in fields:
                continue
            fields["repo"] = repo
            index[fields["P"]] = fields
            for provided in [fields["P"]] + fields.get("p", "").split():
                providers.setdefault(provided.split("=", 1)[0], fields["P"])
    pending = list(names)
    selected = {}
    while pending:
        requirement = pending.pop(0)
        name = requirement.split("=", 1)[0].split(">", 1)[0].split("<", 1)[0].split("~", 1)[0]
        if name.startswith("!"):
            continue
        package = name if name in index else providers.get(name)
        if not package:
            raise RuntimeError(f"unresolved package dependency: {requirement}")
        if package in selected:
            continue
        fields = index[package]
        filename = f"{package}-{fields['V']}.apk"
        url = f"{BASE}/{fields['repo']}/x86_64/{filename}"
        archive = download(url, ROOT / "downloads" / "ports" / filename)
        with tarfile.open(archive, "r:gz", ignore_zeros=True) as stream:
            metadata = stream.extractfile(".PKGINFO").read().decode()
        info = dict(line.split(" = ", 1) for line in metadata.splitlines() if " = " in line)
        selected[package] = {"name": package, "version": fields["V"], "repository": fields["repo"], "url": url, "archive": filename, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "license": fields.get("L", ""), "upstream": fields.get("U", ""), "origin": info["origin"], "source_commit": info["commit"]}
        pending.extend(fields.get("D", "").split())
        print(f"Pinned {filename}", flush=True)
    return sorted(selected.values(), key=lambda package: package["name"])


def packages():
    lock = json.loads(LOCKFILE.read_text())
    for package in lock["packages"]:
        archive = download(package["url"], ROOT / "downloads" / "ports" / package["archive"])
        if hashlib.sha256(archive.read_bytes()).hexdigest() != package["sha256"]:
            raise RuntimeError(f"{package['archive']}: SHA-256 mismatch")
        yield package, archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["resolve", "fetch"])
    parser.add_argument("names", nargs="*")
    args = parser.parse_args()
    if args.command == "resolve":
        locked = resolve(args.names or TOOLCHAIN)
        LOCKFILE.write_text(json.dumps({"distribution": "Alpine Linux 3.22 x86_64", "packages": locked}, indent=2) + "\n")
    else:
        for package, archive in packages():
            print(f"Verified {archive.name}", flush=True)
