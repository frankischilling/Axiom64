#!/usr/bin/env python3
"""Fetch verified port sources, preserve notices, and bundle build recipes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import urllib.error
from fetch import LOCK, ROOT, fetch
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
    for item in lock.get('musl_local_patches', []):
        patch = (ROOT / item['path']).resolve()
        if not patch.is_relative_to((ROOT / 'vendor/musl').resolve()):
            raise RuntimeError('local musl patch escapes its vendor folder')
        verify(patch, item['sha256'], 'sha256')
    ports = lock["ports"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        inputs = list(pool.map(port_sources, ports))
    inputs += [("BusyBox-upstream", [fetch("busybox")]), ("Limine", [fetch("limine")]),
               ("libcap-upstream", [fetch("libcap")])]
    crypto = LOCK['openssl']
    signature = verify(download(crypto['signature_url'], CACHE / 'OpenSSL-upstream' /
                                (crypto['archive'] + '.asc')),
                       crypto['signature_sha256'], 'sha256')
    inputs.append(('OpenSSL-upstream', [fetch('openssl'), signature]))
    from build_curl import source_inputs as curl_sources
    from ca_bundle import source_inputs as ca_sources
    inputs.extend((curl_sources(), ca_sources()))
    password = LOCK['libxcrypt']
    signature = verify(download(password['signature_url'], CACHE / 'libxcrypt-upstream' /
                                (password['archive'] + '.asc')), password['signature_sha256'], 'sha256')
    public_key = verify(download(password['public_key_url'], CACHE / 'libxcrypt-upstream' /
                                 'libxcrypt-gpgkey.asc'), password['public_key_sha256'], 'sha256')
    inputs.append(('libxcrypt-upstream', [fetch('libxcrypt'), signature, public_key]))
    musl = [verify(download(item["url"], CACHE / "build-musl" / item["name"]),
                   item["sha256"], "sha256") for item in lock["build_musl"]["files"]]
    inputs.append(("build-musl", musl))
    from build_gnu_utmp_reader import PIN as gnu_reader_pin, source_inputs as gnu_reader_sources
    inputs.append(gnu_reader_sources())
    digest = hashlib.sha256(SOURCE_LOCK.read_bytes() + (ROOT / "dependencies.json").read_bytes() +
                            Path(__file__).read_bytes() + gnu_reader_pin.read_bytes()).hexdigest()
    stamp = NOTICES / ".stamp"
    if not stamp.exists() or stamp.read_text() != digest:
        for origin, paths in inputs:
            notices(origin, paths)
            if origin == 'gnu-utmp-reader':
                for path in paths:
                    if path.parent == ROOT / 'vendor/gnu-utmp-reader' and path.name != 'inputs.json':
                        target = NOTICES / origin / path.name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(path.read_bytes())
    manifest = NOTICES / "sources.lock.json"
    manifest.write_bytes(SOURCE_LOCK.read_bytes())
    (NOTICES / "ports.lock.json").write_bytes((ROOT / "ports.lock.json").read_bytes())
    (NOTICES / 'musl' / 'Axiom64-patches.json').write_text(json.dumps(
        lock.get('musl_local_patches', []), indent=2) + '\n')
    stamp.write_text(digest)
    return inputs


def gnu_reader_kit(archive):
    """Publish the actual static reader inputs and a portable relinking kit."""
    from build_gnu_utmp_reader import digest, ensure
    directory, saved = ensure()
    names = {'application.c', 'application.o', 'application.d', 'compile.log',
             'linker-inputs.log', 'relink.sh', 'account-login-libc'}
    names.update('licenses/' + name for name in saved['notices'])
    names.update('sysroot/' + name for name in saved['source_inputs'])
    names.update('sysroot/usr/include/' + name for name in saved['linux_uapi_inputs'])
    linked = {str(Path(argument).relative_to(directory)) for argument in saved['commands'][-1]
              if argument.endswith(('.a', '.o'))}
    if not linked.issubset(names) or not names.issubset(saved['products']):
        raise RuntimeError('GNU reader public kit omits an actual input')
    # Original producer receipts stay untouched. Published commands, dependency
    # paths and traces describe paths relative to the exported kit instead.
    def portable(text):
        return text.replace(str(directory), '.').replace(str(ROOT), 'Axiom64')
    public = json.loads(portable(json.dumps(saved)))
    public['publication'] = dict(source_manifest_sha256=digest(directory / 'manifest.json'),
                               recipe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                               paths='Producer paths are relative to this kit; host tool paths identify recorded executables.',
                               contents='Actual application, header and linker inputs; complete packages and corresponding sources are under ports/gnu-utmp-reader.')
    public['products'] = {}
    public['symlinks'] = {}
    prefix = 'verification/gnu-utmp-reader/'
    for name in sorted(names):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('GNU reader public input is not a regular file: ' + name)
        if name in {'application.d', 'compile.log', 'linker-inputs.log'}:
            content = portable(path.read_text()).encode()
            info = archive.gettarinfo(str(path), arcname=prefix + name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
            public['products'][name] = hashlib.sha256(content).hexdigest()
        else:
            archive.add(path, arcname=prefix + name)
            public['products'][name] = saved['products'][name]
    content = (json.dumps(public, indent=2) + '\n').encode()
    info = tarfile.TarInfo(prefix + 'manifest.json')
    info.size = len(content)
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(content))


def bundle(inputs):
    destination = ROOT / "build" / "axiom64-sources.tar"
    with tarfile.open(destination, "w") as archive:
        members = set()
        for origin, paths in inputs:
            for path in paths:
                name = f"ports/{origin}/{path.name}"
                if name in members:
                    raise RuntimeError("duplicate source bundle input: " + name)
                members.add(name)
                archive.add(path, arcname=name)
        gnu_reader_kit(archive)
        for path in ["sources.lock.json", "ports.lock.json", "dependencies.json", "LICENSE", "Makefile", "README.md", ".clang-format", ".gitattributes"]:
            archive.add(ROOT / path, arcname=f"Axiom64/{path}")
        for path in sorted((ROOT / "scripts").rglob("*")):
            if path.is_file() and (path.suffix in (".py", ".sh") or
                                   path.is_relative_to(ROOT / "scripts" / "tests" / "fixtures")):
                archive.add(path, arcname=f"Axiom64/{path.relative_to(ROOT).as_posix()}")
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
