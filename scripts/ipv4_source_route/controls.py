# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixed Linux control observations, independent of the guest implementation."""
import hashlib
import json
from pathlib import Path

CLIENT = 'userspace/tests/net/ipv4/source_route_controls.c'
SCRIPT = b'#!/bin/sh\nset -e\n/bin/ipv4-source-controls\necho AXIOM64_TESTS_PASS\n'


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'no duplicate JSON fields')
        result[key] = value
    return result


def decode(text):
    return json.loads(text, object_pairs_hook=unique)


def fixture():
    saved = decode(Path(__file__).with_name('controls.json').read_text())
    rows = saved['observations']
    require(saved['schema'] == 1 and len(rows) == 157 and
            [row['case'] for row in rows] == list(range(157)), 'complete fixed Linux observations')
    return saved


def observations(text, native):
    saved = fixture()
    lines = text.replace('\r\n', '\n').splitlines()
    rows = [decode(line) for line in lines if line.startswith('{')]
    # Equality alone accepts Python bool as an integer. Require the serialized
    # field types as well as every observed value and the exact ordered cases.
    require(len(rows) == 157, 'all source-route control observations')
    for actual, expected in zip(rows, saved['observations']):
        require(set(actual) == set(expected) and
                all(type(actual[key]) is type(value) for key, value in expected.items()) and
                isinstance(actual['values'], list) and
                all(type(value) is int for value in actual['values']) and actual == expected,
                'exact source-route syscall result, position and all seven values')
    markers = [line for line in lines if line.startswith('IPV4_SOURCE_CONTROLS_KERNEL ')]
    prefix = 'IPV4_SOURCE_CONTROLS_KERNEL sysname=' + ('Linux' if native else 'Axiom64') + ' release='
    require(len(markers) == 1 and markers[0].startswith(prefix) and len(markers[0]) > len(prefix),
            'one actual kernel identity')
    require(lines.count('IPV4_SOURCE_CONTROLS_PASS observations=157') == 1 and
            'IPV4_SOURCE_CONTROLS_FAIL' not in text, 'complete successful control process')
    if not native:
        require(lines.count('AXIOM64_TESTS_PASS') == 1 and lines.count('AXIOM64_EXIT status=0') == 1,
                'successful guest init and test process')
    return len(rows)


def client_binding(inputs):
    require(inputs.get(CLIENT) == fixture()['client_source_sha256'], 'same fixed native and guest client')
    require(inputs.get('scripts/ipv4_source_route/controls.json') ==
            fingerprint(Path(__file__).with_name('controls.json').read_bytes()), 'same fixed Linux fixture bytes')


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()
