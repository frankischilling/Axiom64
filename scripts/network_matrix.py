#!/usr/bin/env python3
"""Run the complete Ethernet matrix without rebuilding between matching boots."""
import json
import subprocess
import sys
from fetch import ROOT
from network_test import fixture, run


def cases():
    for transport in ['modern', 'legacy']:
        for queue in [256, 512, 1024]:
            for firmware in ['bios', 'uefi']:
                yield dict(firmware=firmware, transport=transport, models=['virtio', 'e1000'], queue=queue)
        for firmware in ['bios', 'uefi']:
            common = dict(firmware=firmware, transport=transport, queue=512)
            yield dict(common, models=['virtio', 'e1000'] * 4)
            yield dict(common, models=['virtio', 'e1000'], wrap=True)
            yield dict(common, models=['virtio'], status=False)
            yield dict(common, models=['virtio', 'e1000'], mtu=9000)
            for fault in ['length', 'id']:
                yield dict(common, models=['virtio'], fault=fault)
            yield dict(common, models=['virtio'], pressure=True)
    for firmware in ['bios', 'uefi']:
        yield dict(firmware=firmware, transport='modern', models=['e1000'], queue=256, fault='length')
        yield dict(firmware=firmware, transport='modern', models=['virtio'], queue=256, mtu=1500)
        yield dict(firmware=firmware, transport='modern', models=['e1000'], queue=256, pressure=True)


def main():
    results = []
    image_key = None
    fixture_key = None
    try:
        for case in cases():
            status = case.get('status', True)
            phase = 'pressure' if case.get('pressure') else 'invalid' if case.get('fault') == 'id' else 'error' if case.get('fault') else \
                    'queue' if case.get('wrap') else 'verify'
            if fixture_key != status:
                fixture(status)
                fixture_key = status
            if image_key != (status, phase):
                subprocess.run([sys.executable, str(ROOT / 'scripts/image.py'), '--test',
                                '--suite', 'network', '--phase', phase,
                                '--output-name', 'network-test.iso'], check=True)
                image_key = (status, phase)
            options = dict(timeout=300 if case.get('wrap') else 45, wrap=False)
            options.update(case)
            result = run(**options)
            results.append(result)
            (ROOT / 'build/network-results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not result['passed']:
                return 1
    finally:
        (ROOT / 'build/network-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'NETWORK_MATRIX_PASS boots={len(results)}', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
