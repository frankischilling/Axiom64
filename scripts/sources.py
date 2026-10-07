#!/usr/bin/env python3
"""Fetch verified port sources, preserve notices, and bundle build recipes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import tarfile
import urllib.error
from fetch import ROOT, fetch
from ports import download

SOURCE_LOCK = ROOT / "sources.lock.json"
CACHE = ROOT / "downloads" / "sources"
NOTICES = ROOT / "build" / "licenses"


def verify(path, digest, algorithm):
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, algorithm).hexdigest()
    if actual != digest:
        raise RuntimeError(f"{path.name}: {algorithm} mismatch")
    return path


def resolve():
    previous = json.loads(SOURCE_LOCK.read_text()) if SOURCE_LOCK.exists() else {}
    origins = {}
    for package in json.loads((ROOT / "ports.lock.json").read_text())["packages"]:
        if "origin" not in package or package["name"] in {"mesa", "llvm20-libs", "spirv-tools"}:
            continue
        origins.setdefault(package["origin"], package)
    sources = []
    for origin, package in sorted(origins.items()):
        commit = package["source_commit"]
        base = f"https://raw.githubusercontent.com/alpinelinux/aports/{commit}/{package['repository']}/{origin}"
        recipe = download(base + "/APKBUILD", CACHE / origin / commit / "APKBUILD")
        checksums = re.search(r'sha512sums="(.*?)"', recipe.read_text(), re.S)
        if not checksums:
            raise RuntimeError(f"{origin}: missing source checksums")
        files = []
        for line in checksums[1].splitlines():
            if not line.strip():
                continue
            digest, name = line.split()
            if Path(name).name != name or len(digest) != 128:
                raise RuntimeError(f"{origin}: unsafe source name or checksum")
            files.append({"name": name, "sha512": digest, "urls": [
                f"https://distfiles.alpinelinux.org/distfiles/v3.22/{name}", base + "/" + name]})
        sources.append({"origin": origin, "commit": commit, "license": package["license"],
                        "recipe_url": base + "/APKBUILD",
                        "recipe_sha256": hashlib.sha256(recipe.read_bytes()).hexdigest(), "files": files})
    previous["ports"] = sources
    SOURCE_LOCK.write_text(json.dumps(previous, indent=2) + "\n")


def source_file(origin, item):
    destination = CACHE / origin / item["name"]
    if not destination.exists():
        for url in item["urls"]:
            try:
                download(url, destination)
                break
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    raise
        else:
            raise RuntimeError(f"{origin}/{item['name']}: source unavailable")
    return verify(destination, item["sha512"], "sha512")


def port_sources(port):
    origin = port["origin"]
    recipe = download(port["recipe_url"], CACHE / origin / port["commit"] / "APKBUILD")
    verify(recipe, port["recipe_sha256"], "sha256")
    result = [recipe]
    for item in port["files"]:
        result.append(source_file(origin, item))
    print(f"Sources verified: {origin}", flush=True)
    return origin, result


def notices(origin, paths):
    destination = NOTICES / origin
    destination.mkdir(parents=True, exist_ok=True)
    for path in paths:
        if not tarfile.is_tarfile(path):
            continue
        with tarfile.open(path) as archive:
            for member in archive:
                name = Path(member.name).name.upper()
                if (not member.isfile() or member.size > 1024 * 1024 or
                    not (name.startswith(("COPYING", "COPYRIGHT", "LICENSE", "NOTICE")) or
                         name in {"FTL.TXT", "GPLV2.TXT"})):
                    continue
                if Path(member.name).suffix.lower() in {".c", ".h", ".py", ".sh", ".in"}:
                    continue
                # Flatten paths so source archives cannot escape the notice directory.
                target = destination / member.name.replace("/", "__")
                target.write_bytes(archive.extractfile(member).read())


def prepare():
    lock = json.loads(SOURCE_LOCK.read_text())
    ports = lock["ports"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        inputs = list(pool.map(port_sources, ports))
    inputs += [("BusyBox-upstream", [fetch("busybox")]), ("Limine", [fetch("limine")])]
    musl = [verify(download(item["url"], CACHE / "build-musl" / item["name"]),
                   item["sha256"], "sha256") for item in lock["build_musl"]["files"]]
    inputs.append(("build-musl", musl))
    digest = hashlib.sha256(SOURCE_LOCK.read_bytes() + (ROOT / "dependencies.json").read_bytes()).hexdigest()
    stamp = NOTICES / ".stamp"
    if not stamp.exists() or stamp.read_text() != digest:
        for origin, paths in inputs:
            notices(origin, paths)
    manifest = NOTICES / "sources.lock.json"
    manifest.write_bytes(SOURCE_LOCK.read_bytes())
    (NOTICES / "ports.lock.json").write_bytes((ROOT / "ports.lock.json").read_bytes())
    stamp.write_text(digest)
    return inputs


def bundle(inputs):
    destination = ROOT / "build" / "axiom64-sources.tar"
    with tarfile.open(destination, "w") as archive:
        for origin, paths in inputs:
            for path in paths:
                archive.add(path, arcname=f"ports/{origin}/{path.name}")
        for path in ["sources.lock.json", "ports.lock.json", "dependencies.json", "LICENSE", "Makefile", "README.md", ".clang-format"]:
            archive.add(ROOT / path, arcname=f"Axiom64/{path}")
        for path in sorted((ROOT / "scripts").glob("*.py")):
            archive.add(path, arcname=f"Axiom64/scripts/{path.name}")
        archive.add(ROOT / "build" / "busybox-1.37.0" / ".config", arcname="Axiom64/BusyBox.config")
        for folder in ["kernel", "userspace", "boot", "vendor", "docs"]:
            archive.add(ROOT / folder, arcname=f"Axiom64/{folder}")
    print(f"Source bundle: {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["resolve", "prepare", "bundle"])
    args = parser.parse_args()
    if args.command == "resolve":
        resolve()
    else:
        inputs = prepare()
        if args.command == "bundle":
            bundle(inputs)
