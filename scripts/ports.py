#!/usr/bin/env python3
"""Resolve and fetch musl packages for the guest; never execute package scripts."""
import argparse
import fcntl
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request
from fetch import ROOT, verify_archive

BASE = "https://dl-cdn.alpinelinux.org/alpine/v3.22"
LOCKFILE = ROOT / "ports.lock.json"
TOOLCHAIN = ["gcc", "g++", "binutils", "musl-dev", "linux-headers", "make", "nasm", "xorriso"]


def download(url, destination, *, expected_sha256=None):
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Parallel libc/client builds can request the same uncached archive. Keep
    # its existence check, partial file and publication under one owned lock.
    with destination.with_suffix(destination.suffix + ".lock").open("a") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if destination.exists():
            if expected_sha256 is not None:
                verify_archive(destination, expected_sha256)
        else:
            request = urllib.request.Request(url, headers={"User-Agent": "Axiom64-build"})
            with urllib.request.urlopen(request, timeout=60) as response:
                temporary = destination.with_suffix(destination.suffix + ".part")
                with temporary.open("wb") as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
                if expected_sha256 is not None:
                    verify_archive(temporary, expected_sha256)
                temporary.replace(destination)
    return destination


def locked_package(package):
    """Use the exact locked bytes, including a declared preserved package."""
    url = package["url"]
    if "vendored_archive" in package:
        name = package["vendored_archive"]
        if not isinstance(name, str) or "\\" in name:
            raise RuntimeError("invalid vendored package path")
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts or
                len(relative.parts) < 3 or relative.parts[:2] != ("vendor", "ports")):
            raise RuntimeError("vendored package must stay under vendor/ports")
        source = ROOT.joinpath(*relative.parts)
        if source.resolve(strict=True) != source.absolute() or not source.is_file():
            raise RuntimeError("vendored package must be a regular file without aliases")
        verify_archive(source, package["sha256"])
        url = source.as_uri()
    return download(url, ROOT / "downloads" / "ports" / package["archive"],
                    expected_sha256=package["sha256"])


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


def overlay_tar(files, stream):
    """Merge package file data without executing installation hooks."""
    for member in stream:
        path = member.name.rstrip("/")
        if not path or path.startswith("."):
            continue
        if path.startswith("/") or ".." in Path(path).parts:
            raise RuntimeError(f"unsafe package path: {path}")
        for parent in reversed(Path(path).parents):
            if str(parent) != ".":
                files.setdefault(str(parent), (0o40755, b""))
        if member.isdir():
            files[path] = (0o40000 | member.mode, b"")
        elif member.issym():
            files[path] = (0o120000 | member.mode, member.linkname.encode())
        elif member.isfile():
            files[path] = (0o100000 | member.mode, stream.extractfile(member).read())
        elif member.islnk():
            target = member.linkname.rstrip("/")
            if target not in files:
                raise RuntimeError(f"unresolved package hard link: {path} -> {target}")
            files[path] = files[target]


def packages():
    lock = json.loads(LOCKFILE.read_text())
    for package in lock["packages"]:
        yield package, locked_package(package)


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
