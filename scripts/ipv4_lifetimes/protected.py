# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen source-bound guest evidence from a separate export as root and UID 65534."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import zipfile

from fetch import ROOT
from ipv4_lifetimes import artifact_controls, controls, guest
from ipv4_lifetimes.reader import decode, require
from tcp6.inputs import digest, write


def inventory(directory):
    rows = {}
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'export contains no substituted symbolic links')
        if path.is_file():
            rows[path.relative_to(directory).as_posix()] = dict(bytes=path.stat().st_size, sha256=digest(path))
        else:
            require(path.is_dir(), 'only regular retained files and directories are exported')
    return rows


def worker(directory, destination, original, uid):
    require(os.getuid() == os.geteuid() == uid and uid in (0, 65534), 'actual requested reader identity')
    if uid == 65534:
        require(os.getgid() == os.getegid() == 65534 and os.getgroups() == [],
                'ordinary reader has no supplementary privileged groups')
        require(not os.access(original, os.R_OK | os.X_OK), 'ordinary reader cannot read original evidence directory')
    require(ROOT.is_relative_to(directory.parent / 'source-tree'), 'reader imports the separately exported source')
    proof = guest.verify(directory)
    rows = []
    for spec in guest.specifications():
        case = guest.name(spec)
        result = controls.run(directory / case / 'serial.log', destination / case)
        rows.append(dict(profile=spec, original_sha256=result['original_sha256'],
                         count=result['count'], controls=result['controls']))
    artifacts = artifact_controls.run(directory, destination / 'artifact-controls')
    result = dict(passed=True, uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), groups=os.getgroups(),
                  original_evidence_readable=os.access(original, os.R_OK | os.X_OK),
                  guest=proof, rejections=rows, controls=8 * len(controls.NAMES),
                  artifact_controls=artifacts, source_root=str(ROOT))
    write(destination / 'completed.json', result)
    return result


def produce(directory, destination):
    require(os.geteuid() == 0, 'protected export production requires actual root for identity isolation')
    require('GH_TOKEN' not in os.environ, 'artifact readers do not receive GitHub credentials')
    directory, destination = Path(directory).resolve(), Path(destination).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'retained original evidence is in build output')
    require(destination.parent == Path('/var/tmp') and destination.name.startswith('axiom-ipv4-lifetimes-'),
            'separate designated export directory')
    guest.verify(directory)
    before = inventory(directory)
    destination.mkdir(mode=0o755, exist_ok=False)
    exported = destination / 'artifacts'
    shutil.copytree(directory, exported)
    require(inventory(exported) == before, 'all exported original artifact bytes match')
    tree = destination / 'source-tree'
    tree.mkdir(mode=0o755)
    inputs = decode((exported / 'source/source-inputs.json').read_text())
    with zipfile.ZipFile(exported / 'source/source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) and set(archive.namelist()) == set(inputs),
                'one complete public source inventory for exported readers')
        for name in archive.namelist():
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and '\\' not in name,
                    'source member stays within the exported source tree')
        archive.extractall(tree)
    require(all(digest(tree / name) == expected for name, expected in inputs.items()), 'every exported source byte')
    for base in (tree, exported):
        for path in base.rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o444)
        base.chmod(0o755)
    environment = dict(os.environ, PYTHONPATH=str(tree / 'scripts'), PYTHONDONTWRITEBYTECODE='1')
    original_mode = stat.S_IMODE(directory.stat().st_mode)
    directory.chmod(0o700)
    try:
        rows = []
        for uid, name in ((0, 'root'), (65534, 'ordinary')):
            output = destination / name
            output.mkdir(mode=0o700)
            if uid:
                os.chown(output, uid, uid)
            command = [sys.executable, '-B', '-m', 'ipv4_lifetimes.protected', str(exported), str(output),
                       '--worker', '--original', str(directory), '--uid', str(uid)]
            if uid:
                command = ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', *command]
            with (destination / (name + '.log')).open('xb') as log:
                result = subprocess.run(command, cwd=tree, env=environment, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=subprocess.STDOUT, timeout=180)
            require(result.returncode == 0, 'exported ' + name + ' reader process success')
            saved = decode((output / 'completed.json').read_text())
            require(saved['passed'] is True and saved['uid'] == saved['euid'] == uid and
                    saved['guest']['profiles'] == 8 and saved['controls'] == 8 * len(controls.NAMES) and
                    saved['artifact_controls']['count'] == len(artifact_controls.NAMES),
                    'actual protected reader reopened every profile and rejected every control')
            rows.append(dict(identity=name, uid=uid, controls=saved['controls'],
                             artifact_controls=saved['artifact_controls']['count'],
                             log_sha256=digest(destination / (name + '.log'))))
    finally:
        directory.chmod(original_mode)
    require(inventory(directory) == inventory(exported) == before, 'both readers preserve every original artifact byte')
    result = dict(passed=True, artifacts=before, identities=rows, profiles_per_identity=8,
                  controls_per_identity=8 * len(controls.NAMES), ordinary_uid=65534,
                  original_permissions_restored=stat.S_IMODE(directory.stat().st_mode) == original_mode,
                  originals_unchanged=True, export=str(destination), native_or_wire_or_hosted_acceptance=False)
    write(destination / 'completed.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--original', type=Path)
    parser.add_argument('--uid', type=int)
    args = parser.parse_args()
    if args.worker:
        require(args.original is not None and args.uid in (0, 65534), 'explicit protected worker inputs')
        result = worker(args.directory.resolve(), args.destination.resolve(), args.original, args.uid)
    else:
        result = produce(args.directory, args.destination)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
