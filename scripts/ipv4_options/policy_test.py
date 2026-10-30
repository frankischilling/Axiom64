# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep both complete observed Linux policies and reject ambiguous selection."""
import copy
import gzip
import json

from ipv4_options.fixtures import LEGACY_SOCKET, SOCKET
from ipv4_options.native_policy import verify_policy


def verify_retained_policies():
    legacy = json.loads(gzip.decompress(LEGACY_SOCKET.read_bytes()))
    current = json.loads(gzip.decompress(SOCKET.read_bytes()))
    if legacy['root'] != current['root'] or len(current['ordinary']) != 7110:
        raise ValueError('complete unchanged privileged source-route reference')
    differences = []
    for old, new in zip(legacy['ordinary'], current['ordinary'], strict=True):
        if old['name'] != new['name'] or old['input'] != new['input']:
            raise ValueError('both native policies retain every original vector in order')
        if old != new:
            if (old['result'] != 0 or new['result'] != -1 or new['output'] != '01010101' or
                    bytes.fromhex(new['input'])[0] not in (131, 137)):
                raise ValueError('only actual valid source-route capability results differ')
            differences.append(new)
    if len(differences) != 20:
        raise ValueError('all twenty observed ordinary source-route policy differences')
    probes = []
    for fixture, content in ((LEGACY_SOCKET, legacy), (SOCKET, current)):
        rows = []
        for kind in (131, 137):
            row = next(row for row in content['ordinary'] if row['name'] == f'type-{kind}-length-7')
            rows.append({key: row[key] for key in ('input', 'result', 'output')})
        proof = dict(schema=1, kernel='retained-native-policy', uid=65534, gid=65534,
                     effective_capabilities='0000000000000000', rows=rows, fixture=fixture.name)
        assert verify_policy(proof) == fixture
        probes.append(proof)
    controls = []
    for field, value in (('schema', True), ('uid', 0), ('effective_capabilities', '0000000000002000'),
                         ('fixture', LEGACY_SOCKET.name), ('rows', [])):
        damaged = copy.deepcopy(probes[1])
        damaged[field] = value
        controls.append(damaged)
    for field, value in (('input', '00'), ('result', -22), ('result', True), ('output', '')):
        damaged = copy.deepcopy(probes[1])
        damaged['rows'][0][field] = value
        controls.append(damaged)
    damaged = copy.deepcopy(probes[1])
    damaged['rows'][1] = probes[0]['rows'][1]
    controls.append(damaged)
    for damaged in controls:
        try:
            verify_policy(damaged)
        except ValueError:
            pass
        else:
            raise ValueError('damaged native policy proof accepted')
    print(f'IPV4_OPTIONS_POLICY_PASS observations_each=14220 differences=20 damaged_controls={len(controls)}')
