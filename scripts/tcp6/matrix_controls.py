#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen changed IPv6 TCP control evidence and require semantic rejection."""
import hashlib
import json
import re
from pathlib import Path
import shutil
import sys
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp6.inputs import digest, write


from tcp6.control_contract import ABI, STATE


def run_matrix_controls(source, output, suite, audit, log_mutation=None, *,
                        log_control_label='snapshot', log_failure=None):
    if suite not in (ABI, STATE):
        raise ValueError('unknown Internet stream control contract')
    source, output = Path(source).resolve(), Path(output).resolve()
    if (not source.is_relative_to((ROOT / 'build').resolve()) or
            not output.is_relative_to((ROOT / 'build').resolve()) or output.is_relative_to(source)):
        raise ValueError('source and fresh control output must stay separately below build/')
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
    if log_mutation is not None:
        controls.extend((log_control_label + '-' + profile + '-' + environment, 'log', profile, environment)
                        for profile in ('static', 'dynamic') for environment in ('native', 'bios', 'uefi'))
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
        elif mutation in ('count', 'log'):
            name = profile + '/' + ('native.log' if environment == 'native' else environment + '.log')
            data = (source / name).read_bytes()
            if mutation == 'log':
                data = log_mutation(data)
            else:
                damaged_marker = re.sub(r'copy_cases=(\d+)', lambda match: 'copy_cases=' + str(int(match[1])-1), suite.marker)
                data = data.replace(suite.marker.encode(), damaged_marker.encode())
            assert data != (source / name).read_bytes()
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
            value['sources'][suite.source] = '0' * 64
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
            if mutation == 'log' and log_failure is not None:
                assert str(failure) == log_failure
            results.append(dict(label=label, rejected=True, reason=str(failure),
                changed_files={name: digest(candidate / name) for name in changed},
                reopened_archive_sha256=digest(archive)))
        else:
            raise AssertionError('changed IPv6 TCP control evidence accepted: ' + label)
    assert original == {path.relative_to(source).as_posix(): digest(path) for path in source.rglob('*') if path.is_file()}
    report = dict(passed=True, controls=results, originals_unchanged=True)
    write(output / 'results.json', report)
    return report
