#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen changed IPv6 TCP control evidence and require semantic rejection."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp6.abi_evidence import audit
from tcp6.inputs import digest, write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/tcp6-abi')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/tcp6-abi-damaged')
    args = parser.parse_args()
    source, output = args.directory.resolve(), args.output.resolve()
    if not source.is_relative_to((ROOT / 'build').resolve()) or not output.is_relative_to((ROOT / 'build').resolve()):
        parser.error('source and fresh control output must stay below build/')
    audit(source)
    original = {path.relative_to(source).as_posix(): digest(path) for path in source.rglob('*') if path.is_file()}
    output.mkdir(parents=True, exist_ok=False)
    controls = []
    for profile in ('static', 'dynamic'):
        for environment in ('native', 'bios', 'uefi'):
            controls.append(('application-count-' + profile + '-' + environment,
                             'count', profile, environment))
            controls.append(('preexecution-deadline-' + profile + '-' + environment,
                             'deadline', profile, environment))
    controls += [('missing-profile', 'missing', None, None), ('repeated-profile', 'repeat', None, None),
                 ('program-source', 'source', 'static', None), ('program-image', 'program', 'static', None),
                 ('kernel-image', 'kernel', 'static', None), ('loader-image', 'loader', 'dynamic', None)]
    results = []
    for label, mutation, profile, environment in controls:
        candidate = output / label
        candidate.mkdir()
        for name in original:
            destination = candidate / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(source / name)
        changed = {}
        def save(name, data):
            path = candidate / name
            if path.is_symlink():
                path.unlink()
            path.write_bytes(data)
            changed[name] = data
        report = json.loads((source / 'results.json').read_text())
        if mutation == 'missing':
            report['results'].pop()
        elif mutation == 'repeat':
            report['results'][-1] = report['results'][0]
        elif mutation == 'count':
            name = profile + '/' + ('native.log' if environment == 'native' else environment + '.log')
            data = (source / name).read_bytes().replace(b'copy_cases=102', b'copy_cases=101')
            save(name, data)
            next(row for row in report['results'] if row['profile'] == profile and
                 row['environment'] == environment)['log_sha256'] = hashlib.sha256(data).hexdigest()
        elif mutation == 'deadline':
            name = profile + '/' + environment + '-before.json'
            value = json.loads((source / name).read_text())
            value['deadline_seconds'] -= 1
            save(name, (json.dumps(value, indent=2)+'\n').encode())
        elif mutation == 'source':
            name = profile + '/program.inputs.json'
            value = json.loads((source / name).read_text())
            value['sources']['userspace/tests/net/tcp6/abi.c'] = '0' * 64
            save(name, (json.dumps(value, indent=2)+'\n').encode())
        else:
            name = profile + '/' + {'program': 'program', 'kernel': 'kernel.elf', 'loader': 'loader'}[mutation]
            data = bytearray((source / name).read_bytes())
            data[-1] ^= 1
            save(name, bytes(data))
            if mutation == 'program':
                name = profile + '/program.inputs.json'
                value = json.loads((source / name).read_text())
                value['product']['sha256'] = hashlib.sha256(data).hexdigest()
                save(name, (json.dumps(value, indent=2)+'\n').encode())
        save('results.json', (json.dumps(report, indent=2)+'\n').encode())
        archive = candidate / 'changed.zip'
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
            for name, data in changed.items():
                bundle.writestr(name, data)
        for name in changed:
            (candidate / name).unlink()
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                (candidate / name).write_bytes(bundle.read(name))
        try:
            audit(candidate)
        except (ValueError, AssertionError) as failure:
            results.append(dict(label=label, rejected=True, reason=str(failure),
                changed_files={name: digest(candidate / name) for name in changed},
                reopened_archive_sha256=digest(archive)))
        else:
            raise AssertionError('changed IPv6 TCP control evidence accepted: ' + label)
    assert original == {path.relative_to(source).as_posix(): digest(path) for path in source.rglob('*') if path.is_file()}
    write(output / 'results.json', dict(passed=True, controls=results, originals_unchanged=True))
    print('TCP6_ABI_CONTROLS_PASS serialized_reopened=18 originals_unchanged=1')


if __name__ == '__main__':
    main()
