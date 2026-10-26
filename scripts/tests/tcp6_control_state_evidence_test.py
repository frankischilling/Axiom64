#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject reopened control-state mutations through the real evidence interface."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp6.control_contract import STATE
from tcp6.inputs import digest, write
from tcp6.matrix_controls import run_matrix_controls
from tcp6.matrix_evidence import require
from tcp6.state_evidence import audit, observations, PATTERN


def changed_snapshot(body):
    changed = re.sub(rb'\bhops=(-?\d+)',
                     lambda match: b'hops=' + str(int(match[1]) ^ 1).encode(), body, count=1)
    assert changed != body
    return changed


def profiles():
    return [('glibc', 'native', 'glibc/client.log', 'glibc/before.json')] + [
        (profile, environment, profile + '/' + ('native.log' if environment == 'native' else environment + '.log'),
         profile + '/' + environment + '-before.json')
        for profile in ('static', 'dynamic') for environment in ('native', 'bios', 'uefi')]


def glibc_full_control(source, output, original):
    with tempfile.TemporaryDirectory(prefix='state-glibc-control-', dir=output) as temporary:
        candidate = Path(temporary)
        for name in original:
            path = candidate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(source / name)
        body = changed_snapshot((source / 'glibc/client.log').read_bytes())
        result = json.loads((source / 'glibc/result.json').read_text())
        result['log_sha256'] = hashlib.sha256(body).hexdigest()
        changed = {'glibc/client.log': body, 'glibc/result.json': (json.dumps(result, indent=2)+'\n').encode()}
        path = output / 'glibc-snapshot.zip'
        with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED) as archive:
            for name, value in changed.items():
                archive.writestr(name, value)
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                target = candidate / name
                target.unlink()
                target.write_bytes(archive.read(name))
        try:
            audit(candidate)
        except ValueError as error:
            require(str(error) == 'native-derived control-state snapshots', 'glibc scalar reaches semantic rejection')
        else:
            raise AssertionError('reopened changed glibc state accepted')
        return dict(label='snapshot-glibc-native', rejected=True, archive_sha256=digest(path))


def snapshot_controls(source, output):
    report = json.loads((source / 'results.json').read_text())
    labels = []
    path = output / 'snapshot-controls.zip'
    with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED) as archive:
        for profile, environment, logname, before_name in profiles():
            body = (source / logname).read_bytes()
            observations(body)
            lines = body.decode().splitlines(keepends=True)
            selected = [(index, PATTERN.fullmatch(line.rstrip('\r\n'))) for index, line in enumerate(lines)
                        if PATTERN.fullmatch(line.rstrip('\r\n'))]
            require(len(selected) == 51, 'complete positive control-state snapshots')
            before = json.loads((source / before_name).read_text())
            compiled = json.loads((source / profile / 'program.inputs.json').read_text())
            execution = (json.loads((source / 'glibc/result.json').read_text()) if profile == 'glibc' else
                next(row for row in report['results'] if row['profile'] == profile and row['environment'] == environment))
            for position, (index, found) in enumerate(selected):
                fields = ('ttl', 'tos') if found[1] == 'ipv4' else ('hops', 'class', 'ttl', 'tos', 'only')
                for field in fields:
                    changed = list(lines)
                    changed[index] = re.sub(r'\b' + field + r'=(-?\d+)',
                        lambda match: field + '=' + str(int(match[1]) ^ 1), lines[index], count=1)
                    actual = ''.join(changed).encode()
                    context = dict(profile=profile, environment=environment, snapshot=position, field=field,
                        report=deepcopy(report), before=before, compiled=compiled, execution=deepcopy(execution))
                    context['execution']['log_sha256'] = hashlib.sha256(actual).hexdigest()
                    if profile != 'glibc':
                        next(row for row in context['report']['results'] if row['profile'] == profile and
                             row['environment'] == environment)['log_sha256'] = context['execution']['log_sha256']
                    label = f'{profile}-{environment}-{position:02d}-{field}'
                    archive.writestr(label+'/client.log', actual)
                    archive.writestr(label+'/context.json', json.dumps(context))
                    labels.append(label)
    require(len(labels) == 1428, 'every actual scalar snapshot receives independent damage')
    with zipfile.ZipFile(path) as archive:
        for label in labels:
            body = archive.read(label+'/client.log')
            context = json.loads(archive.read(label+'/context.json'))
            require(context['execution']['log_sha256'] == hashlib.sha256(body).hexdigest() and
                    context['before']['source'] == context['report']['source'] and
                    context['before']['program_sha256'] == context['execution']['program_sha256'] ==
                    context['compiled']['product']['sha256'], 'complete reopened candidate state metadata')
            if context['profile'] != 'glibc':
                row = next(row for row in context['report']['results'] if row['profile'] == context['profile'] and
                           row['environment'] == context['environment'])
                require(row == context['execution'], 'rebound full candidate execution row')
            try:
                observations(body)
            except ValueError as error:
                require(str(error) == 'native-derived control-state snapshots', 'snapshot reaches semantic rejection')
            else:
                raise AssertionError('reopened changed scalar accepted: ' + label)
    return dict(controls=len(labels), archive_sha256=digest(path), complete_candidate_metadata_serialized=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/tcp-control-state')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/tcp-control-state-damaged')
    args = parser.parse_args()
    source, output = args.directory.resolve(), args.output.resolve()
    matrix = run_matrix_controls(source, output, STATE, audit, changed_snapshot,
        log_failure='native-derived control-state snapshots')
    original = {path.relative_to(source).as_posix(): digest(path) for path in source.rglob('*') if path.is_file()}
    glibc = glibc_full_control(source, output, original)
    snapshots = snapshot_controls(source, output)
    require(original == {path.relative_to(source).as_posix(): digest(path) for path in source.rglob('*') if path.is_file()},
            'control-state originals remain unchanged')
    result = dict(passed=True, full_matrix_controls=matrix['controls'] + [glibc],
                  snapshot_controls=snapshots, originals_unchanged=True)
    write(output / 'results.json', result)
    print('TCP_CONTROL_STATE_CONTROLS_PASS matrix=25 snapshots=1428 serialized_reopened=1 originals_unchanged=1')


if __name__ == '__main__':
    main()
