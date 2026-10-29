# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen actual native client and collector CPU ownership without editing captures."""
import copy
import json
from pathlib import Path
import tempfile
import zipfile
from tcp6.capture import require
from tcp6.inputs import digest


def verify(directory, profile):
    before = json.loads((directory / 'preexecution.json').read_text())
    client = json.loads((directory / 'client-execution.json').read_text())
    receipt = json.loads((directory / 'receipt.json').read_text())
    cpu = before['packet_cpu']
    allowed, selected, tasks = cpu['before'], cpu['selected'], cpu['tasks']
    require(profile in ('native', 'static', 'dynamic') and before['profile'] == profile and
            isinstance(allowed, list) and 0 < len(allowed) <= 4096 and
            all(type(value) is int and value >= 0 for value in allowed) and
            allowed == sorted(set(allowed)) and type(selected) is int and
            selected == allowed[('native', 'static', 'dynamic').index(profile) % len(allowed)] and
            cpu['actual'] == [selected] and cpu['policy'] == 'client-and-capture-on-one-cpu',
            'native TCP client selects one recorded allowed CPU for its profile')
    require(before['namespace'] > 0 and before['parent_namespace'] > 0 and
            before['namespace'] != before['parent_namespace'] and
            cpu['network_namespace'] == client['namespace'] == before['namespace'] and
            client['kernel'] == before['kernel'], 'actual private native TCP execution namespace')
    require(len(tasks) == 3 and len({row['tid'] for row in tasks}) == 3 and
            cpu['process'] in {row['tid'] for row in tasks} and
            all(type(row['tid']) is int and row['tid'] > 0 and row['actual'] == [selected] for row in tasks) and
            cpu['wrapper']['pid'] == client['owner_pid'] > 0 and
            cpu['wrapper']['actual'] == client['actual'] == [selected] and
            client['pid'] > 0 and client['pid'] != client['owner_pid'] and
            client['owner_pid'] != cpu['process'],
            'actual client process, wrapper and both independent collectors own the selected CPU')
    command = client['command']
    invocation = before['command']
    require(len(invocation) == 9 and invocation[1:5] ==
            ['-B', 'scripts/tcp6_test.py', '--client', profile] and
            invocation[5] == '--output-directory' and invocation[7:] == ['--suite', receipt['suite']],
            'original native client wrapper command')
    execution_directory = Path(invocation[6])
    require(len(command) == (2 if profile == 'dynamic' else 1) + 1 and command[-1] == '--native' and
            Path(command[-2]).name == 'program' and
            (profile != 'dynamic' or Path(command[0]).name == 'loader') and
            execution_directory.is_absolute() and
            all(Path(name).parent == execution_directory for name in command[:-1]) and
            receipt['passed'] and receipt['native'] and receipt['profile'] == profile and
            receipt['returncode'] == client['returncode'] == 0 and
            before['deadline_seconds'] == 150 and
            receipt['start_monotonic_ns'] == before['start_monotonic_ns'] <=
            client['start_monotonic_ns'] <= client['end_monotonic_ns'] <= receipt['end_monotonic_ns'],
            'actual native executable command, successful exit and unchanged execution deadline')
    return dict(passed=True, selected=selected, client_pid=client['pid'], collectors=2,
                namespace=before['namespace'], original_capture_order_unchanged=True)


def damaged(directory, profile, destination):
    verify(directory, profile)
    names = ('preexecution.json', 'client-execution.json', 'receipt.json')
    originals = {name: json.loads((directory / name).read_text()) for name in names}
    variants = {}
    for label in ('client-cpu', 'collector-cpu', 'wrapper-cpu', 'parent-namespace',
                  'profile-selection', 'client-exit', 'client-owner'):
        value = copy.deepcopy(originals)
        cpu = value['preexecution.json']['packet_cpu']
        if label == 'client-cpu':
            value['client-execution.json']['actual'] = [cpu['selected'] + 4096]
        elif label == 'collector-cpu':
            cpu['tasks'][1]['actual'] = []
        elif label == 'wrapper-cpu':
            cpu['wrapper']['actual'] = []
        elif label == 'parent-namespace':
            value['preexecution.json']['parent_namespace'] = value['preexecution.json']['namespace']
        elif label == 'profile-selection':
            cpu['selected'] += 4096
        elif label == 'client-exit':
            value['client-execution.json']['returncode'] = 1
        else:
            value['client-execution.json']['owner_pid'] += 1
        variants[label] = value
    with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED) as archive:
        for label, files in variants.items():
            for name, value in files.items():
                archive.writestr(label + '/' + name, json.dumps(value))
    rejected = []
    with zipfile.ZipFile(destination) as archive, tempfile.TemporaryDirectory(prefix='axiom64-tcp6-cpu-') as temporary:
        scratch = Path(temporary)
        for label in variants:
            for name in names:
                value = json.loads(archive.read(label + '/' + name))
                (scratch / name).write_text(json.dumps(value))
            try:
                verify(scratch, profile)
            except (ValueError, KeyError, IndexError, TypeError):
                rejected.append(label)
            else:
                raise ValueError('reader accepted reopened damaged TCP CPU ownership: ' + label)
    return dict(rejected=rejected, archive_sha256=digest(destination))
