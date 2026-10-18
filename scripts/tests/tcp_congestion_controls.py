# SPDX-License-Identifier: GPL-3.0-or-later
"""Run semantic congestion mutations on every original native and guest capture."""
from pathlib import Path
import json
from tcp_congestion.window_capture import packets, digest, require


def run(wire, controls, candidate, reconstruct):
    root = Path(__file__).resolve().parents[2] / 'build'
    out = root / f'tcp-{wire}-damaged'
    out.mkdir(exist_ok=True)
    originals, results = {}, []
    for native in (True, False):
        report = root / (f'tcp-{wire}-native-results.json' if native else f'tcp-{wire}-results.json')
        originals[report] = digest(report)
        for row in json.loads(report.read_text()):
            profile = 'linux-' + row['linkage'] if native else '-'.join(row[key] for key in
                       ('linkage', 'firmware', 'transport'))
            for lane, name in enumerate(row['captures']):
                path = root / name
                originals[path] = digest(path)
                statistics = row['capture_statistics'][lane] if native else None
                if native:
                    sidecar = root / statistics['monotonic_receipts']
                    originals[sidecar] = digest(sidecar)
                reconstruct(packets(path, lane, (49500 + lane,), statistics=statistics), lane, native)
                for label, expected in controls.items():
                    destination = out / f'{profile}-lane{lane}-{label}'
                    destination.mkdir(exist_ok=True)
                    changed, clocks = candidate(path, lane, statistics, label, destination, native)
                    try:
                        reconstruct(packets(changed, lane, (49500 + lane,), statistics=clocks), lane, native)
                    except ValueError as error:
                        require(expected in str(error), f'{profile} lane{lane} {label}: wrong semantic rejection: {error}')
                        results.append(dict(profile=profile, lane=lane, control=label, reason=str(error),
                            candidate=changed.relative_to(root).as_posix(), sha256=digest(changed)))
                    else:
                        raise AssertionError(f'{profile} lane{lane} {label}: damaged evidence was accepted')
    require(len(results) == 22 * len(controls), 'each congestion control rejects on all twenty-two actual captures')
    require(all(digest(path) == expected for path, expected in originals.items()),
            'congestion mutations preserve original reports, captures and clock receipts')
    (out / 'results.json').write_text(json.dumps(dict(passed=True, controls_rejected=len(results),
        originals_unchanged=True, candidates_only=True, results=results), indent=2) + '\n')
    print(f'TCP_CONGESTION_DAMAGE_PASS wire={wire} controls={len(results)} originals_unchanged=1')
