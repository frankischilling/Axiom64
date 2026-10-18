# SPDX-License-Identifier: GPL-3.0-or-later
"""Record and independently verify actual runtime inputs for legacy TCP peers."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from fetch import ROOT
from tcp_icmp_inputs import record as record_inputs
from tcp_icmp_capture import audit_inputs, require

CONTRACTS = {
    'loss': ('tcp-fault', 'tcp-fault', 'tcp_fault.c', 'tcp_fault_peer.py', 'tcp_fault_capture.py'),
    'reordering': ('tcp-fault', 'tcp-reordering', 'tcp_fault.c', 'tcp_reordering_peer.py', 'tcp_reordering_capture.py'),
    'persist': ('tcp-fault', 'tcp-persist', 'tcp_fault.c', 'tcp_persist_peer.py', 'tcp_persist_capture.py'),
    'timeout': ('tcp-timeout', 'tcp-timeout', 'tcp_timeout.c', 'tcp_timeout_peer.py', 'tcp_timeout_capture.py'),
    'old-ack': ('tcp-fault', 'tcp-old-ack', 'tcp_fault.c', 'tcp_old_ack_peer.py', 'tcp_old_ack_capture.py'),
    'challenge': ('tcp-challenge', 'tcp-challenge', 'tcp_fault.c', 'tcp_challenge_peer.py', 'tcp_challenge_capture.py'),
    'lifetime': ('tcp-lifetime', 'tcp-lifetime', 'tcp_lifetime.c', 'tcp_lifetime/peer.py', 'tcp_lifetime/capture.py'),
}
SOURCES = ('Makefile', 'scripts/tcp_native_inputs.py', 'scripts/tcp_icmp_inputs.py',
           'scripts/tests/tcp_native_inputs_test.py',
           'scripts/tcp_icmp_capture.py', 'scripts/tcp_fault_native.py', 'scripts/tcp_fault_test.py',
           'scripts/tcp_fault_peer.py', 'scripts/tcp_fault_capture.py', 'scripts/tcp_capture.py',
           'scripts/tcp_capture_clock.py', 'scripts/build_musl.py', 'sources.lock.json')


def sources(wire):
    require(wire in CONTRACTS, 'known legacy native TCP profile')
    _, _, client, peer, capture = CONTRACTS[wire]
    return tuple(dict.fromkeys((*SOURCES, 'userspace/tests/net/' + client,
                                'scripts/' + peer, 'scripts/' + capture)))


def record(wire, linkage):
    require(wire in CONTRACTS, 'known native runtime input profile')
    program, prefix, *_ = CONTRACTS[wire]
    return record_inputs(linkage, native=True, label=f'{prefix}-linux-{linkage}',
                         program=program, sources=sources(wire))


def provider_root(inputs, provider):
    value = inputs['providers'][provider]
    identity = value.get('identity')
    require(value.get('provider') == provider and isinstance(identity, str) and
            re.fullmatch('[0-9a-f]{64}', identity), 'actual bounded musl provider identity')
    return f'build/musl/{provider}/{identity}'


def audit(report, input_root=None):
    input_root = input_root or ROOT
    rows = json.loads(report.read_text())
    require(len(rows) == 3 and {row['linkage'] for row in rows} == {'native', 'static', 'dynamic'},
            'all three unique native runtime input profiles')
    wires = {row['wire'] for row in rows}
    require(len(wires) == 1 and wires <= CONTRACTS.keys(), 'one known complete native wire cohort')
    wire = next(iter(wires))
    program, prefix, *_ = CONTRACTS[wire]
    checked = []
    for row in rows:
        require(row['passed'] and not row['error'] and not row['missing'] and row['returncode'] == 0 and
                len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3,
                'actual isolated native client and peer completed successfully')
        name = f'{prefix}-linux-{row["linkage"]}-inputs.json'
        require(row.get('inputs') == name, 'native report names its actual pre-execution runtime inputs')
        input_path = report.parent / name
        inputs = json.loads(input_path.read_text())
        require(inputs['native'] is True and inputs['linkage'] == row['linkage'] and
                set(inputs['sources']) == set(sources(wire)) and
                f'build/{program}-{row["linkage"]}' in inputs['products'],
                'native client, source and runtime input contract')
        if row['linkage'] == 'native':
            require(set(inputs['host_libraries']) == {'libc.so.6', 'ld-linux-x86-64.so.2'} and
                    all('retained' in library and library['retained'] in inputs['products']
                        for library in inputs['host_libraries'].values()),
                    'both native shared libraries must be actual retained products')
        else:
            require(set(inputs['providers']) == {'build', 'runtime'} and all(
                f'{provider_root(inputs, provider)}/{product}' in inputs['products']
                for provider in ('build', 'runtime')
                for product in ('manifest.json', 'COPYRIGHT', 'sysroot/lib/ld-musl-x86_64.so.1',
                                'sysroot/usr/lib/libc.a')),
                'both musl providers retain their actual loader and static library')
        audit_inputs(inputs, input_root=input_root)
        for provider, metadata in inputs['providers'].items():
            provider_manifest = input_root / provider_root(inputs, provider) / 'manifest.json'
            require(json.loads(provider_manifest.read_text()) == metadata, 'actual musl metadata matches its retained manifest')
        checked.append(dict(linkage=row['linkage'], inputs=name,
            sha256=hashlib.sha256(input_path.read_bytes()).hexdigest(),
            retained_host_libraries=inputs['host_libraries'], providers=inputs['providers']))
    return dict(passed=True, wire=wire, native_profiles=3, inputs=checked,
                report_sha256=hashlib.sha256(report.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--input-root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = audit(args.report, args.input_root)
    destination = args.output or args.report.with_name(args.report.stem.replace('-results', '') + '-inputs-results.json')
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print(f'TCP_NATIVE_INPUTS_PASS wire={result["wire"]} native_profiles=3 exact_retained_runtime=1')


if __name__ == '__main__':
    main()
