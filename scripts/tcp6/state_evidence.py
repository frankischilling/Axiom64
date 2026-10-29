# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen native-derived Internet stream control snapshots and actual products."""
import json
from pathlib import Path
import re
from tcp6.control_contract import STATE
from tcp6.inputs import digest
from tcp6.matrix_evidence import audit_matrix, require

MARKER = STATE.marker
POINTS = (
    ('fresh', 'listener', 64, 0, 64, 0), ('fresh', 'client', 64, 0, 64, 0),
    ('configured', 'listener', 37, 168, 77, 44), ('configured', 'client', 64, 236, 91, 84),
    ('connected', 'client', 64, 236, 91, 84), ('connected', 'accepted', 37, 168, 77, 44),
    ('listener-updated', 'listener', 55, 204, 79, 100),
    ('listener-updated', 'accepted', 37, 168, 77, 44),
    ('class-updated', 'client', 64, 24, 91, 84), ('class-sent', 'client', 64, 24, 91, 84),
    ('zero-hop', 'client', 0, 24, 91, 84), ('default-restored', 'client', 64, 24, 91, 84),
    ('tos-updated', 'client', 64, 24, 91, 108), ('ttl-updated', 'client', 64, 24, 93, 108),
    ('disconnected', 'client', 64, 24, 93, 108), ('reconnected', 'client', 64, 24, 93, 108),
    ('reconnected', 'accepted', 55, 204, 79, 100))
PATTERN = re.compile(r'TCP_CONTROL_STATE family=(ipv6|mapped|ipv4) phase=([a-z-]+) '
    r'role=(listener|client|accepted) hops=(-?\d+) class=(-?\d+) ttl=(\d+) tos=(\d+) only=(-?\d+)')


def expected_points():
    expected = []
    for family in ('ipv6', 'mapped', 'ipv4'):
        for phase, role, hops, traffic, ttl, tos in POINTS:
            only = int(family == 'ipv6' and (role == 'accepted' or
                       role == 'listener' and phase == 'listener-updated'))
            if family == 'ipv4':
                hops = traffic = only = -2
            expected.append((family, phase, role, hops, traffic, ttl, tos, only))
    return expected


def observations(body):
    lines = body.decode().replace('\r\n', '\n').replace('\r', '\n').splitlines()
    records = [line for line in lines if line.startswith('TCP_CONTROL_STATE')]
    require(len(records) == 52 and records[-1] == MARKER,
            'complete control-state application inventory')
    actual = []
    for line in records[:-1]:
        found = PATTERN.fullmatch(line)
        require(found is not None, 'complete native-derived control-state record')
        fields = found.groups()
        actual.append((*fields[:3], *(int(value) for value in fields[3:])))
    require(actual == expected_points(), 'native-derived control-state snapshots')
    return actual


def glibc_inputs(directory, sources, source):
    case = directory / 'glibc'
    before = json.loads((case / 'before.json').read_text())
    compiled = json.loads((case / 'program.inputs.json').read_text())
    result = json.loads((case / 'result.json').read_text())
    require(before['source'] == source and before['deadline_seconds'] == 60 and before['kernel'] and
            len(before['command']) == 1 and Path(before['command'][0]).name == 'program',
            'actual glibc control invocation and source')
    require(result['before_sha256'] == digest(case / 'before.json') and
            before['compiler_inputs_sha256'] == digest(case / 'program.inputs.json') and
            before['program_sha256'] == compiled['product']['sha256'] == result['program_sha256'] == digest(case / 'program') and
            result['passed'] is True and result['returncode'] == 0 and result['log_sha256'] == digest(case / 'client.log'),
            'actual glibc control executable and outcome')
    require(compiled['command'][:-2] == ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', STATE.source] and
            compiled['command'][-2] == '-o' and Path(compiled['command'][-1]).name == 'program' and
            compiled['sources'].get(STATE.source) == sources[STATE.source] and compiled['compiler_version'] and
            all(name in sources and sources[name] == value for name, value in compiled['sources'].items()),
            'all actual glibc control compiler source bindings')
    require(set(before['libraries']) == {'libc.so.6', 'ld-linux-x86-64.so.2'},
            'complete actual glibc runtime')
    for name, item in before['libraries'].items():
        path = Path(item['file'])
        require(path.parts == ('runtime', name) and (case / path).stat().st_size == item['bytes'] and
                digest(case / path) == item['sha256'] and (case / path).read_bytes()[:7] == b'\x7fELF\2\1\1',
                'retained actual glibc runtime bytes')


def audit(directory):
    directory = Path(directory)
    result = audit_matrix(directory, STATE)
    report = json.loads((directory / 'results.json').read_text())
    sources = json.loads((directory / 'source-inputs.json').read_text())
    glibc_inputs(directory, sources, report['source'])
    observations((directory / 'glibc/client.log').read_bytes())
    for profile in ('static', 'dynamic'):
        for environment in ('native', 'bios', 'uefi'):
            name = 'native.log' if environment == 'native' else environment + '.log'
            observations((directory / profile / name).read_bytes())
    result.update(profiles=7, native=3, guests=4, snapshots=357, scalar_queries=1652,
                  request_reply_exchanges=84, copy_cases=350, loopback_only=True,
                  wider_wire_and_route_lifetime_acceptance=False)
    return result
