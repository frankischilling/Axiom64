# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit all actual RTO and duplicate-ACK congestion cohorts and boot images."""
import argparse
from collections import Counter, defaultdict, deque
import itertools
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_congestion.inputs import SOURCES
from tcp_congestion.window_capture import reconstruct as window_reconstruct, digest
from tcp_congestion.fast_capture import reconstruct as fast_reconstruct
from tcp_fault_capture import packets, decode, require
from tcp_fixture_inputs import audit_image
from tcp_icmp_capture import audit_inputs


def bounded(root, name):
    require(isinstance(name, str) and name and Path(name).name == name and
            '/' not in name and '\\' not in name, 'bounded congestion evidence name')
    return root / name


def verify(path, lane, evidence, wire, native=False, statistics=None):
    require(not native or statistics is not None, 'native congestion capture retains independent clocks')
    rows = packets(path, lane, (49500 + lane,), statistics=statistics if native else None)
    require(evidence['lane'] == lane, 'actual congestion peer lane identity')
    reported, clocks = Counter(), defaultdict(deque)
    for item in evidence['frames']:
        row = decode(bytes.fromhex(item['frame']), lane, (49500 + lane,))
        if row is not None:
            require(item['direction'] in ('send', 'receive') and
                    row['outgoing'] == (item['direction'] == 'receive'), 'actual congestion peer direction')
            reported[row['frame']] += 1
            clocks[row['frame']].append(item['ms'])
    require(reported == Counter(row['frame'] for row in rows), 'every original congestion peer frame matches capture bytes')
    for row in rows:
        row['peer_ms'] = clocks[row['frame']].popleft()
    reconstruct = window_reconstruct if wire == 'window' else fast_reconstruct
    result = reconstruct(rows, lane, native)
    result.update(file=path.name, sha256=digest(path), lane=lane, native=native)
    return result


def check_results(directory, wire, input_root=None):
    require(wire in ('window', 'fast'), 'known complete congestion profile')
    input_root = input_root or ROOT
    checked, images = [], {}
    for native in (True, False):
        report = directory / (f'tcp-{wire}-native-results.json' if native else f'tcp-{wire}-results.json')
        rows = json.loads(report.read_text())
        if native:
            require(len(rows) == 3 and {row['linkage'] for row in rows} == {'native', 'static', 'dynamic'},
                    'all three native congestion libc profiles')
        else:
            expected = set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
            require(len(rows) == 8 and {(row['linkage'], row['firmware'], row['transport']) for row in rows} == expected,
                    'all eight actual guest congestion profiles')
        for row in rows:
            require(row['wire'] == wire and row['passed'] and not row['error'] and not row['missing'] and
                    row['returncode'] == (0 if native else 1), 'actual congestion socket client and peer succeed')
            if native:
                require(len({row[key] for key in ('parent_namespace', 'peer_namespace', 'client_namespace')}) == 3 and
                        len(row['capture_statistics']) == 2, 'isolated congestion client, peer and both native observers')
            inputs = json.loads(bounded(directory, row['inputs']).read_text())
            require(inputs['linkage'] == row['linkage'] and inputs['native'] == native and
                    set(inputs['sources']) == set(SOURCES) and
                    f'build/tcp-window-{row["linkage"]}' in inputs['products'], 'complete actual congestion inputs')
            audit_inputs(inputs, input_root)
            text = bounded(directory, row['log']).read_text()
            require(text.count('TCP_WINDOW_PASS nics=2 bytes_each=65536') == 1 and
                    set(re.findall(r'TCP_WINDOW_LANE_PASS lane=(\d) bytes=65536 elapsed_ms=\d+', text)) == {'0', '1'} and
                    not any(word in text for word in ('TCP_WINDOW_FAIL', 'PANIC:', 'FAULT pid=')),
                    'both real congestion socket streams finish exact bytes and close')
            if not native:
                require(all(marker in text for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                        f'Firmware: {row["firmware"].upper()}', f'virtio-net: index=1 transport={row["transport"]}',
                        'e1000: index=2 model=82540EM')), 'actual congestion firmware and both NIC drivers')
                if row['linkage'] not in images:
                    images[row['linkage']] = audit_image(inputs, input_root, 'tcp-window', f'tcp-{wire}')
            peers = json.loads(bounded(directory, row['peer']).read_text())
            require(len(peers) == len(row['captures']) == 2, 'both original congestion adapter captures')
            for lane, name in enumerate(row['captures']):
                checked.append(verify(bounded(directory, name), lane, peers[lane], wire, native,
                               row['capture_statistics'][lane] if native else None))
    require(len(checked) == 22 and len(images) == 2, 'complete congestion captures and actual boot images')
    result = dict(passed=True, wire=wire, captures=checked, images=images)
    (directory / f'tcp-{wire}-capture-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'TCP_CONGESTION_CAPTURE_PASS wire={wire} captures=22 streams=22 actual_images=2 exact_bytes')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wire', choices=('window', 'fast', 'both'), default='both')
    args = parser.parse_args()
    for wire in ('window', 'fast') if args.wire == 'both' else (args.wire,):
        check_results(ROOT / 'build', wire)
